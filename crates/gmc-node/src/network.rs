//! Multi-node TCP peer-to-peer transport and two-phase BFT consensus driver (`BftClusterNode`).
//!
//! Implements bounded length-prefixed TCP framing (`<= 256 KiB` pre-allocation ceiling,
//! socket read/write timeouts) exchanging [`BftWireMessage`] (`Propose`, `Prevote`,
//! `Precommit`, `Commit`, `Equivocation`) across independent validator processes/threads.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use gmc_core::types::{ChainId, Decimal};

use crate::consensus::{
    BftStep, BlockProposal, BlockTransaction, EquivocationEvidence, QuorumCertificate,
    SignedConsensusVote, ValidatorSet, BFT_FINALITY_BUDGET_MS, VALIDATOR_REWARD,
};
use crate::crypto::{keypair_from_seed, ED25519_SEED_LEN};
use crate::error::{NodeError, NodeResult};
use crate::runtime::{NodeConfig, NodeRuntime};

/// 4-byte wire magic prefixing every BFT TCP frame (`"GMCB"`).
pub const BFT_WIRE_MAGIC: &[u8; 4] = b"GMCB";
/// Hard ceiling (`256 KiB`) on BFT peer-to-peer wire frames, enforced before allocation.
pub const MAX_BFT_FRAME_BYTES: usize = 256 * 1024;
/// Default TCP read/write socket timeout for peer messaging.
const PEER_IO_TIMEOUT: Duration = Duration::from_millis(750);

/// Peer-to-peer wire envelope exchanged over TCP between [`BftClusterNode`] validators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BftWireMessage {
    /// Phase 0: Round-robin proposer broadcasts signed candidate block.
    Propose(BlockProposal),
    /// Phase 1: Active validator broadcasts signed `Prevote`.
    Prevote(SignedConsensusVote),
    /// Phase 2: Active validator broadcasts signed `Precommit` after `>= (2*N)/3 + 1` prevotes.
    Precommit(SignedConsensusVote),
    /// Finalized commit carrying proposal + supermajority `QuorumCertificate`.
    Commit {
        proposal: BlockProposal,
        qc: QuorumCertificate,
    },
    /// Cryptographic double-signing proof triggering immediate non-monetary validator ejection.
    Equivocation(EquivocationEvidence),
}

/// Writes a bounded `GMCB` + `u32(len)` + JSON frame to `stream`.
pub fn write_bft_frame(stream: &mut TcpStream, msg: &BftWireMessage) -> NodeResult<()> {
    let payload = serde_json::to_vec(msg)
        .map_err(|e| NodeError::ConsensusInvalid(format!("wire serialize failed: {e}")))?;
    if payload.len() > MAX_BFT_FRAME_BYTES {
        return Err(NodeError::RequestTooLarge {
            max_bytes: MAX_BFT_FRAME_BYTES,
        });
    }
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(BFT_WIRE_MAGIC);
    header[4..8].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header)?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

/// Reads and validates a bounded `GMCB` + `u32(len)` + JSON frame from `stream`.
pub fn read_bft_frame(stream: &mut TcpStream) -> NodeResult<BftWireMessage> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header)?;
    if &header[..4] != BFT_WIRE_MAGIC {
        return Err(NodeError::ConsensusInvalid(
            "invalid BFT TCP frame magic".into(),
        ));
    }
    let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if len == 0 || len > MAX_BFT_FRAME_BYTES {
        return Err(NodeError::RequestTooLarge {
            max_bytes: MAX_BFT_FRAME_BYTES,
        });
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map_err(|e| NodeError::ConsensusInvalid(format!("invalid BFT wire JSON: {e}")))
}

type VoteSlotKey = (String, u64, u32, BftStep);
type TalliedVotes = BTreeMap<(u64, u32, [u8; 32]), BTreeMap<String, SignedConsensusVote>>;

struct ClusterInner {
    runtime: NodeRuntime,
    validator_id: String,
    seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
    peers: Vec<SocketAddr>,
    offline: bool,
    proposals: BTreeMap<(u64, u32), BlockProposal>,
    vote_book: BTreeMap<VoteSlotKey, SignedConsensusVote>,
    prevotes: TalliedVotes,
    precommits: TalliedVotes,
    sent_prevote: BTreeSet<(u64, u32)>,
    sent_precommit: BTreeSet<(u64, u32)>,
}

impl ClusterInner {
    fn is_self_active(&self) -> bool {
        self.runtime
            .validator_set()
            .get(&self.validator_id)
            .map(|v| v.active)
            .unwrap_or(false)
    }

    /// Checks a newly received vote against previously observed votes from the same validator
    /// at the same `(height, round, step)`. If conflicting valid signatures exist, immediately
    /// applies equivocation ejection and queues gossip broadcast.
    fn check_and_record_vote(
        &mut self,
        vote: &SignedConsensusVote,
        outbound: &mut Vec<BftWireMessage>,
    ) -> bool {
        let chain_id = self.runtime.config().chain_id.clone();
        let Some(vinfo) = self.runtime.validator_set().get(&vote.validator_id) else {
            return false;
        };
        if !vote.verify_signature(&vinfo.pubkey) || vote.chain_id != chain_id {
            return false;
        }

        let key = (
            vote.validator_id.clone(),
            vote.height,
            vote.round,
            vote.step,
        );
        if let Some(existing) = self.vote_book.get(&key).cloned() {
            if existing.block_hash != vote.block_hash {
                let evidence = EquivocationEvidence {
                    vote_a: existing,
                    vote_b: vote.clone(),
                };
                if self.runtime.apply_equivocation(&evidence).is_ok() {
                    outbound.push(BftWireMessage::Equivocation(evidence));
                }
                return false;
            }
            return true;
        }

        if !vinfo.active {
            return false;
        }
        self.vote_book.insert(key, vote.clone());
        true
    }

    fn handle_message(&mut self, msg: BftWireMessage) -> Vec<BftWireMessage> {
        if self.offline {
            return Vec::new();
        }
        let mut outbound = Vec::new();
        let chain_id = self.runtime.config().chain_id.clone();

        match msg {
            BftWireMessage::Propose(proposal) => {
                let propose_vote = proposal.to_propose_vote();
                if !self.check_and_record_vote(&propose_vote, &mut outbound) {
                    return outbound;
                }
                if proposal.height != self.runtime.block_height() + 1 {
                    return outbound;
                }
                if proposal
                    .verify(self.runtime.validator_set(), &chain_id)
                    .is_err()
                {
                    return outbound;
                }
                if proposal.parent_state_root != self.runtime.state_root() {
                    return outbound;
                }
                let Ok(computed_root) = self.runtime.preview_bft_state_root(
                    proposal.height,
                    proposal.timestamp_secs,
                    &proposal.transactions,
                ) else {
                    return outbound;
                };
                if computed_root != proposal.state_root {
                    // Reject forged/mismatched state_root without voting!
                    return outbound;
                }

                let h = proposal.height;
                let r = proposal.round;
                let bhash = proposal.block_hash;
                let sroot = proposal.state_root;
                self.proposals.insert((h, r), proposal);

                if self.is_self_active() && !self.sent_prevote.contains(&(h, r)) {
                    if let Ok(my_prevote) = SignedConsensusVote::sign(
                        &self.seed,
                        &self.validator_id,
                        &chain_id,
                        h,
                        r,
                        BftStep::Prevote,
                        bhash,
                        sroot,
                    ) {
                        self.sent_prevote.insert((h, r));
                        self.vote_book.insert(
                            (self.validator_id.clone(), h, r, BftStep::Prevote),
                            my_prevote.clone(),
                        );
                        self.prevotes
                            .entry((h, r, bhash))
                            .or_default()
                            .insert(self.validator_id.clone(), my_prevote.clone());
                        outbound.push(BftWireMessage::Prevote(my_prevote));
                    }
                }

                self.try_advance_round(h, r, bhash, &mut outbound);
            }
            BftWireMessage::Prevote(vote) => {
                if !self.check_and_record_vote(&vote, &mut outbound) {
                    return outbound;
                }
                let (h, r, bhash) = (vote.height, vote.round, vote.block_hash);
                self.prevotes
                    .entry((h, r, bhash))
                    .or_default()
                    .insert(vote.validator_id.clone(), vote);
                self.try_advance_round(h, r, bhash, &mut outbound);
            }
            BftWireMessage::Precommit(vote) => {
                if !self.check_and_record_vote(&vote, &mut outbound) {
                    return outbound;
                }
                let (h, r, bhash) = (vote.height, vote.round, vote.block_hash);
                self.precommits
                    .entry((h, r, bhash))
                    .or_default()
                    .insert(vote.validator_id.clone(), vote);
                self.try_advance_round(h, r, bhash, &mut outbound);
            }
            BftWireMessage::Commit { proposal, qc } => {
                if proposal.height == self.runtime.block_height() + 1 {
                    let _ = self.runtime.commit_bft_proposal(&proposal, &qc);
                }
            }
            BftWireMessage::Equivocation(evidence) => {
                let target_active = self
                    .runtime
                    .validator_set()
                    .get(&evidence.vote_a.validator_id)
                    .map(|v| v.active)
                    .unwrap_or(false);
                if target_active && self.runtime.apply_equivocation(&evidence).is_ok() {
                    outbound.push(BftWireMessage::Equivocation(evidence));
                }
            }
        }

        outbound
    }

    fn try_advance_round(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        outbound: &mut Vec<BftWireMessage>,
    ) {
        if height != self.runtime.block_height() + 1 {
            return;
        }
        let Some(proposal) = self.proposals.get(&(height, round)).cloned() else {
            return;
        };
        if proposal.block_hash != block_hash {
            return;
        }

        let quorum = self.runtime.validator_set().quorum_threshold();
        if quorum == 0 {
            return;
        }
        let chain_id = self.runtime.config().chain_id.clone();

        // Phase 1 -> Phase 2: Prevote supermajority unlocks Precommit!
        let prevote_count = self
            .prevotes
            .get(&(height, round, block_hash))
            .map(|m| {
                m.keys()
                    .filter(|vid| {
                        self.runtime
                            .validator_set()
                            .get(vid)
                            .map(|v| v.active)
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0);

        if prevote_count >= quorum
            && self.is_self_active()
            && !self.sent_precommit.contains(&(height, round))
        {
            if let Ok(my_precommit) = SignedConsensusVote::sign(
                &self.seed,
                &self.validator_id,
                &chain_id,
                height,
                round,
                BftStep::Precommit,
                block_hash,
                proposal.state_root,
            ) {
                self.sent_precommit.insert((height, round));
                self.vote_book.insert(
                    (self.validator_id.clone(), height, round, BftStep::Precommit),
                    my_precommit.clone(),
                );
                self.precommits
                    .entry((height, round, block_hash))
                    .or_default()
                    .insert(self.validator_id.clone(), my_precommit.clone());
                outbound.push(BftWireMessage::Precommit(my_precommit));
            }
        }

        // Phase 2 -> Commit: Precommit supermajority seals QuorumCertificate & commits block!
        let active_precommits: Vec<SignedConsensusVote> = self
            .precommits
            .get(&(height, round, block_hash))
            .map(|m| {
                m.values()
                    .filter(|v| {
                        self.runtime
                            .validator_set()
                            .get(&v.validator_id)
                            .map(|info| info.active)
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        if active_precommits.len() >= quorum && height == self.runtime.block_height() + 1 {
            let qc = QuorumCertificate {
                chain_id,
                height,
                round,
                step: BftStep::Precommit,
                block_hash,
                state_root: proposal.state_root,
                votes: active_precommits,
            };
            if self.runtime.commit_bft_proposal(&proposal, &qc).is_ok() {
                outbound.push(BftWireMessage::Commit { proposal, qc });
            }
        }
    }
}

/// Live validator node participating in a TCP peer-to-peer two-phase BFT cluster.
pub struct BftClusterNode {
    local_addr: SocketAddr,
    validator_id: String,
    inner: Arc<(Mutex<ClusterInner>, Condvar)>,
    stop_flag: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl BftClusterNode {
    /// Spawns a validator instance bound to `bind_addr` (e.g. `"127.0.0.1:0"`).
    pub fn spawn(
        config: NodeConfig,
        seed: [u8; ED25519_SEED_LEN],
        validator_id: String,
        validator_set: ValidatorSet,
        bind_addr: &str,
    ) -> NodeResult<Self> {
        let sock_addr: SocketAddr = bind_addr.parse().map_err(|e| {
            NodeError::ConfigInvalid(format!("invalid BFT bind_addr '{bind_addr}': {e}"))
        })?;
        let listener = TcpListener::bind(sock_addr)?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let runtime = NodeRuntime::init_with_validators(config, seed, validator_set)?;
        let inner = Arc::new((
            Mutex::new(ClusterInner {
                runtime,
                validator_id: validator_id.clone(),
                seed: Zeroizing::new(seed),
                peers: Vec::new(),
                offline: false,
                proposals: BTreeMap::new(),
                vote_book: BTreeMap::new(),
                prevotes: BTreeMap::new(),
                precommits: BTreeMap::new(),
                sent_prevote: BTreeSet::new(),
                sent_precommit: BTreeSet::new(),
            }),
            Condvar::new(),
        ));

        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);
        let thread_inner = Arc::clone(&inner);

        let join_handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        if thread_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(PEER_IO_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(PEER_IO_TIMEOUT));
                        if let Ok(msg) = read_bft_frame(&mut stream) {
                            process_and_gossip(&thread_inner, msg);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(BftClusterNode {
            local_addr,
            validator_id,
            inner,
            stop_flag,
            join_handle: Some(join_handle),
        })
    }

    /// Bound TCP listener address for peer mesh wiring.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Validator's accountable `FayID` (`ifay_`/`cofay_`/`org_`).
    pub fn validator_id(&self) -> &str {
        &self.validator_id
    }

    /// Configures peer TCP addresses for outbound gossip.
    pub fn set_peers(&self, peers: Vec<SocketAddr>) {
        if let Ok(mut guard) = self.inner.0.lock() {
            guard.peers = peers;
        }
    }

    /// Simulates an offline/silent validator when `offline == true`.
    pub fn set_offline(&self, offline: bool) {
        if let Ok(mut guard) = self.inner.0.lock() {
            guard.offline = offline;
        }
    }

    /// Read-only inspection helper over the underlying [`NodeRuntime`].
    pub fn with_runtime<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&NodeRuntime) -> R,
    {
        let guard = self.inner.0.lock().expect("cluster runtime lock");
        f(&guard.runtime)
    }

    /// Current committed block height.
    pub fn block_height(&self) -> u64 {
        self.with_runtime(|rt| rt.block_height())
    }

    /// Current canonical SHA-256 `StateRoot` hex.
    pub fn state_root_hex(&self) -> String {
        self.with_runtime(|rt| rt.state_root_hex())
    }

    /// Active validator count in this node's `ValidatorSet`.
    pub fn active_validator_count(&self) -> usize {
        self.with_runtime(|rt| rt.validator_set().active_count())
    }

    /// Latest committed [`QuorumCertificate`].
    pub fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.with_runtime(|rt| rt.latest_qc().cloned())
    }

    /// Builds and signs a candidate [`BlockProposal`] using deterministic local `StateRoot` preview.
    pub fn build_signed_proposal(
        &self,
        height: u64,
        round: u32,
        timestamp_secs: u64,
        transactions: Vec<BlockTransaction>,
    ) -> NodeResult<BlockProposal> {
        let guard = self
            .inner
            .0
            .lock()
            .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
        let parent_root = guard.runtime.state_root();
        let state_root = guard
            .runtime
            .preview_bft_state_root(height, timestamp_secs, &transactions)?;
        let chain_id = guard.runtime.config().chain_id.clone();
        BlockProposal::sign_new(
            &guard.seed,
            guard.validator_id.clone(),
            chain_id,
            height,
            round,
            timestamp_secs,
            parent_root,
            transactions,
            state_root,
        )
    }

    /// Sends an arbitrary [`BftWireMessage`] directly to all configured peers over TCP.
    pub fn broadcast_raw(&self, msg: BftWireMessage) -> NodeResult<()> {
        let peers = {
            let guard = self
                .inner
                .0
                .lock()
                .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
            guard.peers.clone()
        };
        send_to_peers(&peers, &msg);
        Ok(())
    }

    /// Drives a full two-phase BFT round (`Propose -> Prevote -> Precommit -> Commit`)
    /// from the designated round-robin proposer across TCP peers.
    pub fn propose_block(
        &self,
        height: u64,
        round: u32,
        timestamp_secs: u64,
        transactions: Vec<BlockTransaction>,
    ) -> NodeResult<BlockProposal> {
        let proposal = self.build_signed_proposal(height, round, timestamp_secs, transactions)?;
        let peers = {
            let guard = self
                .inner
                .0
                .lock()
                .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
            guard.peers.clone()
        };
        // First broadcast proposal to TCP peers, then process locally and gossip own Prevote!
        send_to_peers(&peers, &BftWireMessage::Propose(proposal.clone()));
        process_and_gossip(&self.inner, BftWireMessage::Propose(proposal.clone()));
        Ok(proposal)
    }

    /// Fault-injection helper: transmits two conflicting signed `Prevote` frames for distinct
    /// `block_hash`es at `(height, round)` over real TCP sockets to all peers so honest
    /// nodes detect the double-vote and eject this faulty validator.
    pub fn inject_equivocation_over_tcp(
        &self,
        height: u64,
        round: u32,
        block_hash_a: [u8; 32],
        block_hash_b: [u8; 32],
        state_root: [u8; 32],
    ) -> NodeResult<()> {
        let (vote_a, vote_b, peers) = {
            let guard = self
                .inner
                .0
                .lock()
                .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
            let chain_id = guard.runtime.config().chain_id.clone();
            let va = SignedConsensusVote::sign(
                &guard.seed,
                &guard.validator_id,
                &chain_id,
                height,
                round,
                BftStep::Prevote,
                block_hash_a,
                state_root,
            )?;
            let vb = SignedConsensusVote::sign(
                &guard.seed,
                &guard.validator_id,
                &chain_id,
                height,
                round,
                BftStep::Prevote,
                block_hash_b,
                state_root,
            )?;
            (va, vb, guard.peers.clone())
        };
        send_to_peers(&peers, &BftWireMessage::Prevote(vote_a));
        send_to_peers(&peers, &BftWireMessage::Prevote(vote_b));
        Ok(())
    }

    /// Blocks until `block_height >= target_height` or returns [`NodeError::FinalityTimeout`]
    /// if `timeout_ms` elapses.
    pub fn wait_for_height(&self, target_height: u64, timeout_ms: u64) -> NodeResult<()> {
        let start = Instant::now();
        let budget = Duration::from_millis(timeout_ms);
        let mut guard = self
            .inner
            .0
            .lock()
            .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
        while guard.runtime.block_height() < target_height {
            let elapsed = start.elapsed();
            if elapsed >= budget {
                return Err(NodeError::FinalityTimeout {
                    elapsed_ms: elapsed.as_millis() as u64,
                    budget_ms: timeout_ms,
                });
            }
            let wait_slice = (budget - elapsed).min(Duration::from_millis(20));
            let (next_guard, _) = self
                .inner
                .1
                .wait_timeout(guard, wait_slice)
                .map_err(|_| NodeError::Io("condvar poisoned".into()))?;
            guard = next_guard;
        }
        Ok(())
    }

    /// Blocks until `validator_id` has been marked `active == false` or times out.
    pub fn wait_for_ejection(&self, validator_id: &str, timeout_ms: u64) -> NodeResult<()> {
        let start = Instant::now();
        let budget = Duration::from_millis(timeout_ms);
        let mut guard = self
            .inner
            .0
            .lock()
            .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
        loop {
            let is_ejected = guard
                .runtime
                .validator_set()
                .get(validator_id)
                .map(|v| !v.active)
                .unwrap_or(false);
            if is_ejected {
                return Ok(());
            }
            let elapsed = start.elapsed();
            if elapsed >= budget {
                return Err(NodeError::FinalityTimeout {
                    elapsed_ms: elapsed.as_millis() as u64,
                    budget_ms: timeout_ms,
                });
            }
            let wait_slice = (budget - elapsed).min(Duration::from_millis(20));
            let (next_guard, _) = self
                .inner
                .1
                .wait_timeout(guard, wait_slice)
                .map_err(|_| NodeError::Io("condvar poisoned".into()))?;
            guard = next_guard;
        }
    }

    /// Stops the TCP listener thread and writes an atomic `snapshot.json` on disk.
    pub fn shutdown(mut self) -> NodeResult<[u8; 32]> {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(100));
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
        let mut guard = self
            .inner
            .0
            .lock()
            .map_err(|_| NodeError::Io("cluster mutex poisoned".into()))?;
        guard.runtime.shutdown()
    }
}

impl Drop for BftClusterNode {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(50));
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

fn process_and_gossip(shared: &Arc<(Mutex<ClusterInner>, Condvar)>, initial: BftWireMessage) {
    let (outbound, peers) = {
        let Ok(mut guard) = shared.0.lock() else {
            return;
        };
        let out = guard.handle_message(initial);
        let peers = guard.peers.clone();
        shared.1.notify_all();
        (out, peers)
    };

    for msg in outbound {
        send_to_peers(&peers, &msg);
    }
}

fn send_to_peers(peers: &[SocketAddr], msg: &BftWireMessage) {
    for peer in peers {
        if let Ok(mut stream) = TcpStream::connect_timeout(peer, PEER_IO_TIMEOUT) {
            let _ = stream.set_read_timeout(Some(PEER_IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(PEER_IO_TIMEOUT));
            let _ = write_bft_frame(&mut stream, msg);
        }
    }
}

/// Executes the end-to-end multi-validator TCP BFT `cluster-demo` showcase:
/// - Spawns `validator_count` (`>= 4`) independent TCP `BftClusterNode` instances on `127.0.0.1:0`;
/// - Height 1 (`N/N` online): settles `iFay` registration + L2 contribution with full supermajority QC;
/// - Height 2 (`N - 1` online, `1` faulty/offline validator): settles L2 contribution with `(N-1)/N`
///   quorum within `< 3,000 ms` AND detects + ejects a TCP double-vote equivocation;
/// - Asserts every honest node converges on the exact same canonical SHA-256 `StateRoot`.
pub fn run_cluster_demo(
    data_dir: &Path,
    validator_count: usize,
    chain_id: &str,
) -> NodeResult<Value> {
    if validator_count < 4 {
        return Err(NodeError::ConfigInvalid(
            "--validators must be >= 4 for Byzantine fault tolerance (N = 3f + 1)".into(),
        ));
    }

    let (members, vset) = ValidatorSet::deterministic_local_committee(validator_count)?;
    let mut nodes = Vec::with_capacity(validator_count);
    for (idx, (seed, info)) in members.iter().enumerate() {
        let sub_dir = data_dir.join(format!("validator-{}", idx + 1));
        let mut cfg = NodeConfig::new(&sub_dir);
        cfg.chain_id = chain_id.to_string();
        nodes.push(BftClusterNode::spawn(
            cfg,
            *seed,
            info.validator_id.clone(),
            vset.clone(),
            "127.0.0.1:0",
        )?);
    }

    let addrs: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr()).collect();
    for (idx, node) in nodes.iter().enumerate() {
        let peers = addrs
            .iter()
            .enumerate()
            .filter_map(|(j, a)| if j != idx { Some(*a) } else { None })
            .collect();
        node.set_peers(peers);
    }

    let (_alice_sk, alice_vk) = keypair_from_seed(&[0xA1u8; 32]);
    let alice_id = gmc_identity::identity_id::derive_identity_id(
        &nodes[0].with_runtime(|rt| rt.identities().registry.clone()),
        &gmc_identity::types::SchemeTag::ed25519(),
        &alice_vk,
    )?;

    // Height 1: all validators online
    let h1_leader_id = vset.proposer_for(1, 0)?.validator_id.clone();
    let h1_leader_idx = members
        .iter()
        .position(|(_, m)| m.validator_id == h1_leader_id)
        .unwrap_or(0);
    let h1_txs = vec![
        BlockTransaction::RegisterIfay {
            verifying_key_hex: hex::encode(alice_vk.as_bytes()),
            timestamp_secs: 1_700_000_010,
        },
        BlockTransaction::SubmitContribution {
            contributor_scheme_tag: alice_id.scheme_tag().as_str().to_string(),
            contributor_key_repr: alice_id.key_repr().to_string(),
            chain_id: ChainId::new("gmc-base").as_str().to_string(),
            merit_amount_raw: Decimal::from_int(30).raw(),
            influence_duration_raw: Decimal::from_int(86_400).raw(),
            timestamp_secs: 1_700_000_020,
        },
    ];

    let t1 = Instant::now();
    nodes[h1_leader_idx].propose_block(1, 0, 1_700_000_030, h1_txs)?;
    for node in &nodes {
        node.wait_for_height(1, BFT_FINALITY_BUDGET_MS)?;
    }
    let h1_ms = t1.elapsed().as_millis() as u64;
    let h1_root = nodes[0].state_root_hex();
    for node in &nodes {
        if node.state_root_hex() != h1_root {
            return Err(NodeError::ConsensusInvalid(
                "height 1 state_root divergence".into(),
            ));
        }
    }

    // Height 2: last validator goes offline & broadcasts conflicting Prevotes over TCP
    let faulty_idx = validator_count - 1;
    let faulty_id = members[faulty_idx].1.validator_id.clone();
    nodes[faulty_idx].set_offline(true);

    let round_h2 = (0..validator_count as u32)
        .find(|&r| {
            vset.proposer_for(2, r)
                .map(|p| p.validator_id != faulty_id)
                .unwrap_or(false)
        })
        .unwrap_or(0);
    let h2_leader_id = vset.proposer_for(2, round_h2)?.validator_id.clone();
    let h2_leader_idx = members
        .iter()
        .position(|(_, m)| m.validator_id == h2_leader_id)
        .unwrap_or(0);

    let h2_txs = vec![BlockTransaction::SubmitContribution {
        contributor_scheme_tag: alice_id.scheme_tag().as_str().to_string(),
        contributor_key_repr: alice_id.key_repr().to_string(),
        chain_id: ChainId::new("gmc-base").as_str().to_string(),
        merit_amount_raw: Decimal::from_int(50).raw(),
        influence_duration_raw: Decimal::from_int(86_400).raw(),
        timestamp_secs: 1_700_000_070,
    }];

    let t2 = Instant::now();
    nodes[h2_leader_idx].propose_block(2, round_h2, 1_700_000_090, h2_txs)?;
    for honest in &nodes[..faulty_idx] {
        honest.wait_for_height(2, BFT_FINALITY_BUDGET_MS)?;
    }
    let h2_ms = t2.elapsed().as_millis() as u64;

    nodes[faulty_idx].inject_equivocation_over_tcp(
        2,
        round_h2,
        [0xAA; 32],
        [0xBB; 32],
        [0xCC; 32],
    )?;
    for honest in &nodes[..faulty_idx] {
        honest.wait_for_ejection(&faulty_id, BFT_FINALITY_BUDGET_MS)?;
    }

    let h2_root = nodes[0].state_root_hex();
    for honest in &nodes[..faulty_idx] {
        if honest.state_root_hex() != h2_root {
            return Err(NodeError::ConsensusInvalid(
                "height 2 state_root divergence".into(),
            ));
        }
    }
    let latest_qc = nodes[0]
        .latest_qc()
        .map(|q| q.to_summary_json(vset.quorum_threshold()))
        .unwrap_or(Value::Null);
    let peer_addrs: Vec<String> = addrs.iter().map(ToString::to_string).collect();

    for node in nodes {
        node.shutdown()?;
    }

    Ok(json!({
        "cluster_demo": "ok",
        "chain_id": chain_id,
        "validators_total": validator_count,
        "quorum_threshold": vset.quorum_threshold(),
        "committed_height": 2,
        "height_1_state_root_hex": h1_root,
        "height_2_state_root_hex": h2_root,
        "height_1_finality_ms": h1_ms,
        "height_2_finality_ms": h2_ms,
        "finality_budget_ms": BFT_FINALITY_BUDGET_MS,
        "active_validators_after": validator_count - 1,
        "ejected_validators_count": 1,
        "ejected_validator_id": faulty_id,
        "peer_listen_addrs": peer_addrs,
        "latest_quorum_certificate": latest_qc,
        "node_transaction_fee": "0",
        "node_block_reward": "0",
        "validator_reward": VALIDATOR_REWARD.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bft_wire_message_roundtrip_and_mini_cluster() {
        let (_members, vset) = ValidatorSet::deterministic_local_committee(4).unwrap();
        let seed = [0x42u8; 32];
        let prop = BlockProposal::sign_new(
            &seed,
            vset.proposer_for(1, 0).unwrap().validator_id.clone(),
            "gmc-net-ut",
            1,
            0,
            100,
            [0x11; 32],
            Vec::new(),
            [0x22; 32],
        )
        .unwrap();
        let wire = BftWireMessage::Propose(prop);
        let bytes = serde_json::to_vec(&wire).expect("BftWireMessage serialize");
        let decoded: BftWireMessage = serde_json::from_slice(&bytes).expect("BftWireMessage deserialize");
        assert_eq!(wire, decoded);

        let dir = std::env::temp_dir().join(format!("gmc-net-ut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let res = run_cluster_demo(&dir, 4, "gmc-net-ut");
        let _ = std::fs::remove_dir_all(&dir);
        res.expect("cluster demo must succeed");
    }
}
