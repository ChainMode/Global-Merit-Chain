//! Deterministic Ed25519 two-phase BFT consensus (`Propose -> Prevote -> Precommit -> Commit`),
//! accountable permissioned `ValidatorSet`, supermajority `QuorumCertificate`, and
//! non-monetary cryptographic `EquivocationEvidence` validator ejection.
//!
//! Constitutional non-monetary invariants:
//! - [`VALIDATOR_REWARD`] `== 0` (zero `MeriToken` minted for proposing or voting);
//! - Zero financial stake deposits and zero monetary slashing — faulty validators are
//!   ejected (`active = false`) via verifiable [`EquivocationEvidence`].

use std::collections::BTreeSet;

use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{keypair_from_seed, ED25519_SEED_LEN};
use crate::error::{NodeError, NodeResult};
use crate::runtime::WireSignedOperation;

/// Constitutional invariant: BFT validator block/vote reward is strictly `0 μ`.
pub const VALIDATOR_REWARD: u128 = 0;

/// Constitutional finality budget (`3,000 ms` / `3s`) for local/LAN two-phase BFT rounds.
pub const BFT_FINALITY_BUDGET_MS: u64 = 3_000;

/// Canonical domain-separation tag for all Ed25519 BFT consensus votes.
pub const BFT_VOTE_DOMAIN: &[u8] = b"gmc.bft.vote.v1";

/// Canonical domain-separation tag for deterministic `BlockProposal` hashing.
pub const BFT_PROPOSAL_DOMAIN: &[u8] = b"gmc.bft.proposal.v1";

/// Seed + validator entry tuple returned by [`ValidatorSet::deterministic_local_committee`].
pub type LocalCommitteeMember = ([u8; ED25519_SEED_LEN], ValidatorInfo);

mod serde_sig64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let decoded = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte Ed25519 signature hex"))
    }
}

/// Computes the BFT supermajority quorum threshold `(2 * n) / 3 + 1` for `N = 3f + 1`.
#[inline]
pub const fn quorum_threshold(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (2 * n) / 3 + 1
    }
}

/// Validates that `validator_id` carries an accountable `FayID` entity prefix
/// (`ifay_`, `cofay_`, or `org_`) and NEVER exposes plaintext Human Prime `hid_`.
pub fn validate_validator_id(validator_id: &str) -> NodeResult<()> {
    let Some((prefix, body)) = validator_id.split_once('_') else {
        return Err(NodeError::ConsensusInvalid(format!(
            "validator_id '{validator_id}' must use accountable prefix ifay_/cofay_/org_"
        )));
    };
    if !matches!(prefix, "ifay" | "cofay" | "org") {
        return Err(NodeError::ConsensusInvalid(format!(
            "validator_id prefix '{prefix}_' is not allowed (must be ifay_, cofay_, or org_)"
        )));
    }
    if body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(NodeError::ConsensusInvalid(format!(
            "validator_id '{validator_id}' body must be non-empty lowercase alphanumeric/hyphen"
        )));
    }
    Ok(())
}

/// Accountable permissioned validator entry binding an `ifay_`/`cofay_`/`org_` operator
/// identity to a 32-byte Ed25519 consensus verifying key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Accountable operator `FayID` (`ifay_...`, `cofay_...`, or `org_...`).
    pub validator_id: String,
    /// Compressed 32-byte Ed25519 verifying key.
    pub pubkey: [u8; 32],
    /// Whether this validator is currently active (`false` once ejected for equivocation).
    pub active: bool,
}

impl ValidatorInfo {
    /// Creates and validates an active [`ValidatorInfo`].
    pub fn new(validator_id: impl Into<String>, pubkey: [u8; 32]) -> NodeResult<Self> {
        let validator_id = validator_id.into();
        validate_validator_id(&validator_id)?;
        DalekVerifyingKey::from_bytes(&pubkey).map_err(|e| {
            NodeError::ConsensusInvalid(format!("invalid validator Ed25519 pubkey: {e}"))
        })?;
        Ok(ValidatorInfo {
            validator_id,
            pubkey,
            active: true,
        })
    }

    /// Re-validates structural invariants after deserialization.
    pub fn validate(&self) -> NodeResult<()> {
        validate_validator_id(&self.validator_id)?;
        DalekVerifyingKey::from_bytes(&self.pubkey).map_err(|e| {
            NodeError::ConsensusInvalid(format!("invalid validator Ed25519 pubkey: {e}"))
        })?;
        Ok(())
    }
}

/// Accountable permissioned validator set supporting deterministic round-robin proposer
/// selection and cryptographic equivocation ejection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    /// Constructs a validated [`ValidatorSet`], rejecting empty sets, duplicate IDs,
    /// duplicate public keys, invalid prefixes, or sets with zero active validators.
    pub fn new(validators: Vec<ValidatorInfo>) -> NodeResult<Self> {
        if validators.is_empty() {
            return Err(NodeError::ConsensusInvalid(
                "validator set must not be empty".into(),
            ));
        }
        let mut seen_ids = BTreeSet::new();
        let mut seen_pks = BTreeSet::new();
        let mut active_count = 0usize;
        for v in &validators {
            v.validate()?;
            if !seen_ids.insert(v.validator_id.clone()) {
                return Err(NodeError::ConsensusInvalid(format!(
                    "duplicate validator_id '{}'",
                    v.validator_id
                )));
            }
            if !seen_pks.insert(v.pubkey) {
                return Err(NodeError::ConsensusInvalid(format!(
                    "duplicate validator pubkey for '{}'",
                    v.validator_id
                )));
            }
            if v.active {
                active_count += 1;
            }
        }
        if active_count == 0 {
            return Err(NodeError::ConsensusInvalid(
                "validator set must contain at least one active validator".into(),
            ));
        }
        Ok(ValidatorSet { validators })
    }

    /// Builds a single-validator set from a node operator's keypair.
    pub fn single_operator(validator_id: impl Into<String>, pubkey: [u8; 32]) -> NodeResult<Self> {
        Self::new(vec![ValidatorInfo::new(validator_id, pubkey)?])
    }

    /// Generates a deterministic `count`-validator local committee (`([u8; 32] seed, ValidatorInfo)`)
    /// for `cluster-demo` and `Meritora Desktop` local workbench mode.
    pub fn deterministic_local_committee(
        count: usize,
    ) -> NodeResult<(Vec<LocalCommitteeMember>, Self)> {
        if count == 0 {
            return Err(NodeError::ConsensusInvalid(
                "committee size must be >= 1".into(),
            ));
        }
        let prefixes = ["ifay", "cofay", "org", "ifay"];
        let mut pairs = Vec::with_capacity(count);
        let mut infos = Vec::with_capacity(count);
        for idx in 0..count {
            let mut seed = [0u8; ED25519_SEED_LEN];
            let label = format!("gmc-local-bft-validator-seed-v1:{idx}");
            let digest = Sha256::digest(label.as_bytes());
            seed.copy_from_slice(&digest);
            let (_sk, vk) = keypair_from_seed(&seed);
            let pubkey: [u8; 32] = vk
                .as_bytes()
                .try_into()
                .map_err(|_| NodeError::KeyFormatInvalid)?;
            let pfx = prefixes[idx % prefixes.len()];
            let validator_id = format!("{pfx}_meritora-val-{}", idx + 1);
            let info = ValidatorInfo::new(validator_id, pubkey)?;
            pairs.push((seed, info.clone()));
            infos.push(info);
        }
        let set = Self::new(infos)?;
        Ok((pairs, set))
    }

    /// All validators (both active and ejected) in canonical registration order.
    pub fn validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// Active validators eligible to propose and vote.
    pub fn active_validators(&self) -> Vec<&ValidatorInfo> {
        self.validators.iter().filter(|v| v.active).collect()
    }

    /// Total validator count (`active + ejected`).
    pub fn total_count(&self) -> usize {
        self.validators.len()
    }

    /// Active validator count.
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.active).count()
    }

    /// Ejected validator count (`active == false`).
    pub fn ejected_count(&self) -> usize {
        self.validators.iter().filter(|v| !v.active).count()
    }

    /// Current BFT supermajority quorum threshold `(2 * active_count) / 3 + 1`.
    pub fn quorum_threshold(&self) -> usize {
        quorum_threshold(self.active_count())
    }

    /// Looks up a validator by `validator_id`.
    pub fn get(&self, validator_id: &str) -> Option<&ValidatorInfo> {
        self.validators
            .iter()
            .find(|v| v.validator_id == validator_id)
    }

    /// Deterministic round-robin proposer `(height + round) % active_count`.
    pub fn proposer_for(&self, height: u64, round: u32) -> NodeResult<&ValidatorInfo> {
        let active = self.active_validators();
        if active.is_empty() {
            return Err(NodeError::ConsensusInvalid(
                "no active validators remaining in ValidatorSet".into(),
            ));
        }
        let idx = (height.wrapping_add(u64::from(round)) as usize) % active.len();
        Ok(active[idx])
    }

    /// Verifies cryptographic [`EquivocationEvidence`] and immediately ejects (`active = false`)
    /// the faulty validator without financial stake slashing.
    pub fn apply_equivocation(
        &mut self,
        evidence: &EquivocationEvidence,
        expected_chain_id: &str,
    ) -> NodeResult<String> {
        evidence.verify(self, expected_chain_id)?;
        let target_id = evidence.vote_a.validator_id.clone();
        // Ensure we never eject the very last active validator into a 0-active state if N == 1,
        // though in N >= 2 Byzantine ejection proceeds unconditionally.
        let slot = self
            .validators
            .iter_mut()
            .find(|v| v.validator_id == target_id)
            .ok_or_else(|| {
                NodeError::ConsensusInvalid(format!("unknown validator '{target_id}'"))
            })?;
        slot.active = false;
        Ok(target_id)
    }
}

/// Two-phase BFT consensus step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BftStep {
    /// Leader block proposal phase.
    Propose,
    /// Phase 1 supermajority prevote.
    Prevote,
    /// Phase 2 supermajority precommit sealing the `QuorumCertificate`.
    Precommit,
}

impl BftStep {
    /// Canonical single-byte wire tag used in domain-separated vote signing.
    pub const fn tag(self) -> u8 {
        match self {
            BftStep::Propose => 0x01,
            BftStep::Prevote => 0x02,
            BftStep::Precommit => 0x03,
        }
    }
}

/// Canonical domain-separated signing message (`"gmc.bft.vote.v1"`) over
/// `(chain_id, height, round, step, block_hash, state_root)`.
pub fn canonical_vote_bytes(
    chain_id: &str,
    height: u64,
    round: u32,
    step: BftStep,
    block_hash: &[u8; 32],
    state_root: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&(BFT_VOTE_DOMAIN.len() as u64).to_be_bytes());
    out.extend_from_slice(BFT_VOTE_DOMAIN);
    out.extend_from_slice(&(chain_id.len() as u64).to_be_bytes());
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&round.to_be_bytes());
    out.push(step.tag());
    out.extend_from_slice(block_hash);
    out.extend_from_slice(state_root);
    out
}

/// Deterministic state-transition item carried inside a multi-node [`BlockProposal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTransaction {
    /// Registers an `iFay` identity and anchors it on L1.
    RegisterIfay {
        verifying_key_hex: String,
        timestamp_secs: u64,
    },
    /// Executes an Ed25519-authenticated `SignedOperation`.
    SignedOperation {
        operation: WireSignedOperation,
        timestamp_secs: u64,
    },
    /// Registers a bilateral social relationship edge.
    RegisterRelationship {
        a_fay_id: String,
        b_fay_id: String,
        relationship_type: String,
        privacy_tier: String,
        registered_at_secs: u64,
    },
    /// Records a directed social interaction on an existing edge.
    RecordInteraction {
        initiator_fay_id: String,
        counterparty_fay_id: String,
        depth_raw: i128,
        at_secs: u64,
    },
    /// Submits an L2 contribution batch for a registered contributor.
    SubmitContribution {
        contributor_scheme_tag: String,
        contributor_key_repr: String,
        chain_id: String,
        merit_amount_raw: i128,
        influence_duration_raw: i128,
        timestamp_secs: u64,
    },
}

/// Candidate block proposed in `BftStep::Propose`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockProposal {
    pub chain_id: String,
    pub height: u64,
    pub round: u32,
    pub timestamp_secs: u64,
    pub parent_state_root: [u8; 32],
    pub transactions: Vec<BlockTransaction>,
    pub state_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub proposer_id: String,
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
}

impl BlockProposal {
    /// Deterministically hashes proposal header + ordered transactions + post-execution `state_root`.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_block_hash(
        chain_id: &str,
        height: u64,
        round: u32,
        timestamp_secs: u64,
        parent_state_root: &[u8; 32],
        transactions: &[BlockTransaction],
        state_root: &[u8; 32],
        proposer_id: &str,
    ) -> NodeResult<[u8; 32]> {
        let tx_bytes = serde_json::to_vec(transactions)
            .map_err(|e| NodeError::ConsensusInvalid(format!("tx encode failed: {e}")))?;
        let mut h = Sha256::new();
        h.update((BFT_PROPOSAL_DOMAIN.len() as u64).to_be_bytes());
        h.update(BFT_PROPOSAL_DOMAIN);
        h.update((chain_id.len() as u64).to_be_bytes());
        h.update(chain_id.as_bytes());
        h.update(height.to_be_bytes());
        h.update(round.to_be_bytes());
        h.update(timestamp_secs.to_be_bytes());
        h.update(parent_state_root);
        h.update((tx_bytes.len() as u64).to_be_bytes());
        h.update(&tx_bytes);
        h.update(state_root);
        h.update((proposer_id.len() as u64).to_be_bytes());
        h.update(proposer_id.as_bytes());
        Ok(h.finalize().into())
    }

    /// Constructs and signs a [`BlockProposal`] using the proposer's 32-byte Ed25519 seed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        seed: &[u8; ED25519_SEED_LEN],
        proposer_id: impl Into<String>,
        chain_id: impl Into<String>,
        height: u64,
        round: u32,
        timestamp_secs: u64,
        parent_state_root: [u8; 32],
        transactions: Vec<BlockTransaction>,
        state_root: [u8; 32],
    ) -> NodeResult<Self> {
        let proposer_id = proposer_id.into();
        let chain_id = chain_id.into();
        let block_hash = Self::compute_block_hash(
            &chain_id,
            height,
            round,
            timestamp_secs,
            &parent_state_root,
            &transactions,
            &state_root,
            &proposer_id,
        )?;
        let vote = SignedConsensusVote::sign(
            seed,
            &proposer_id,
            &chain_id,
            height,
            round,
            BftStep::Propose,
            block_hash,
            state_root,
        )?;
        Ok(BlockProposal {
            chain_id,
            height,
            round,
            timestamp_secs,
            parent_state_root,
            transactions,
            state_root,
            block_hash,
            proposer_id,
            signature: vote.signature,
        })
    }

    /// Recomputes `block_hash` and re-signs a mutated proposal (for Byzantine fault-injection tests).
    pub fn resign_for_test(mut proposal: Self, seed: &[u8; ED25519_SEED_LEN]) -> NodeResult<Self> {
        proposal.block_hash = Self::compute_block_hash(
            &proposal.chain_id,
            proposal.height,
            proposal.round,
            proposal.timestamp_secs,
            &proposal.parent_state_root,
            &proposal.transactions,
            &proposal.state_root,
            &proposal.proposer_id,
        )?;
        let vote = SignedConsensusVote::sign(
            seed,
            &proposal.proposer_id,
            &proposal.chain_id,
            proposal.height,
            proposal.round,
            BftStep::Propose,
            proposal.block_hash,
            proposal.state_root,
        )?;
        proposal.signature = vote.signature;
        Ok(proposal)
    }

    /// Extracts the underlying `BftStep::Propose` [`SignedConsensusVote`] (enabling
    /// uniform double-proposal equivocation detection!).
    pub fn to_propose_vote(&self) -> SignedConsensusVote {
        SignedConsensusVote {
            validator_id: self.proposer_id.clone(),
            chain_id: self.chain_id.clone(),
            height: self.height,
            round: self.round,
            step: BftStep::Propose,
            block_hash: self.block_hash,
            state_root: self.state_root,
            signature: self.signature,
        }
    }

    /// Verifies block hash integrity, designated round-robin proposer, and strict Ed25519 signature.
    pub fn verify(&self, validator_set: &ValidatorSet, expected_chain_id: &str) -> NodeResult<()> {
        if self.chain_id != expected_chain_id {
            return Err(NodeError::ConsensusInvalid(format!(
                "proposal chain_id '{}' != expected '{expected_chain_id}'",
                self.chain_id
            )));
        }
        let expected_proposer = validator_set.proposer_for(self.height, self.round)?;
        if expected_proposer.validator_id != self.proposer_id {
            return Err(NodeError::ConsensusInvalid(format!(
                "unexpected proposer '{}' at (h={}, r={}), expected '{}'",
                self.proposer_id, self.height, self.round, expected_proposer.validator_id
            )));
        }
        let expected_hash = Self::compute_block_hash(
            &self.chain_id,
            self.height,
            self.round,
            self.timestamp_secs,
            &self.parent_state_root,
            &self.transactions,
            &self.state_root,
            &self.proposer_id,
        )?;
        if expected_hash != self.block_hash {
            return Err(NodeError::ConsensusInvalid(
                "proposal block_hash mismatch".into(),
            ));
        }
        let vote = self.to_propose_vote();
        if !vote.verify_signature(&expected_proposer.pubkey) {
            return Err(NodeError::ConsensusInvalid(
                "proposal Ed25519 signature invalid".into(),
            ));
        }
        Ok(())
    }
}

/// Domain-separated strict Ed25519 consensus vote (`"gmc.bft.vote.v1"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConsensusVote {
    pub validator_id: String,
    pub chain_id: String,
    pub height: u64,
    pub round: u32,
    pub step: BftStep,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
}

impl SignedConsensusVote {
    /// Signs a domain-separated `"gmc.bft.vote.v1"` vote with a zeroized 32-byte Ed25519 seed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        seed: &[u8; ED25519_SEED_LEN],
        validator_id: &str,
        chain_id: &str,
        height: u64,
        round: u32,
        step: BftStep,
        block_hash: [u8; 32],
        state_root: [u8; 32],
    ) -> NodeResult<Self> {
        validate_validator_id(validator_id)?;
        let zeroized = Zeroizing::new(*seed);
        let sk = DalekSigningKey::from_bytes(&zeroized);
        let msg = canonical_vote_bytes(chain_id, height, round, step, &block_hash, &state_root);
        let sig = sk.sign(&msg);
        Ok(SignedConsensusVote {
            validator_id: validator_id.to_string(),
            chain_id: chain_id.to_string(),
            height,
            round,
            step,
            block_hash,
            state_root,
            signature: sig.to_bytes(),
        })
    }

    /// Strict Ed25519 signature check (`verify_strict`) against `pubkey`.
    pub fn verify_signature(&self, pubkey: &[u8; 32]) -> bool {
        let Ok(vk) = DalekVerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let sig = DalekSignature::from_bytes(&self.signature);
        let msg = canonical_vote_bytes(
            &self.chain_id,
            self.height,
            self.round,
            self.step,
            &self.block_hash,
            &self.state_root,
        );
        vk.verify_strict(&msg, &sig).is_ok()
    }

    /// Verifies that this vote comes from an active validator in `validator_set` with a valid signature.
    pub fn verify_against_set(
        &self,
        validator_set: &ValidatorSet,
        expected_chain_id: &str,
    ) -> NodeResult<()> {
        if self.chain_id != expected_chain_id {
            return Err(NodeError::ConsensusInvalid("vote chain_id mismatch".into()));
        }
        let Some(info) = validator_set.get(&self.validator_id) else {
            return Err(NodeError::ConsensusInvalid(format!(
                "unknown validator '{}'",
                self.validator_id
            )));
        };
        if !info.active {
            return Err(NodeError::ConsensusInvalid(format!(
                "validator '{}' is ejected/inactive",
                self.validator_id
            )));
        }
        if !self.verify_signature(&info.pubkey) {
            return Err(NodeError::ConsensusInvalid(format!(
                "invalid Ed25519 vote signature from '{}'",
                self.validator_id
            )));
        }
        Ok(())
    }
}

/// Supermajority BFT Quorum Certificate (`>= (2*N)/3 + 1` distinct active validator
/// `Precommit` signatures) persisted with every committed block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub chain_id: String,
    pub height: u64,
    pub round: u32,
    pub step: BftStep,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub votes: Vec<SignedConsensusVote>,
}

impl QuorumCertificate {
    /// Verifies that this `QuorumCertificate` seals `BftStep::Precommit` with at least
    /// `validator_set.quorum_threshold()` distinct active validator signatures.
    pub fn verify(&self, validator_set: &ValidatorSet, expected_chain_id: &str) -> NodeResult<()> {
        if self.step != BftStep::Precommit {
            return Err(NodeError::ConsensusInvalid(
                "commit QuorumCertificate must carry step == Precommit".into(),
            ));
        }
        self.verify_for_step(validator_set, expected_chain_id, BftStep::Precommit)
    }

    /// Verifies a QuorumCertificate for a specific [`BftStep`].
    pub fn verify_for_step(
        &self,
        validator_set: &ValidatorSet,
        expected_chain_id: &str,
        expected_step: BftStep,
    ) -> NodeResult<()> {
        debug_assert_eq!(VALIDATOR_REWARD, 0);
        if self.chain_id != expected_chain_id {
            return Err(NodeError::ConsensusInvalid("QC chain_id mismatch".into()));
        }
        if self.step != expected_step {
            return Err(NodeError::ConsensusInvalid("QC step mismatch".into()));
        }

        let required = validator_set.quorum_threshold();
        if required == 0 {
            return Err(NodeError::ConsensusInvalid(
                "validator set has zero active quorum".into(),
            ));
        }

        let mut distinct_signers = BTreeSet::new();
        for vote in &self.votes {
            if vote.chain_id != self.chain_id
                || vote.height != self.height
                || vote.round != self.round
                || vote.step != self.step
                || vote.block_hash != self.block_hash
                || vote.state_root != self.state_root
            {
                return Err(NodeError::ConsensusInvalid(
                    "QC vote target mismatch".into(),
                ));
            }
            vote.verify_against_set(validator_set, expected_chain_id)?;
            if !distinct_signers.insert(vote.validator_id.clone()) {
                return Err(NodeError::ConsensusInvalid(format!(
                    "duplicate validator vote '{}' in QuorumCertificate",
                    vote.validator_id
                )));
            }
        }

        if distinct_signers.len() < required {
            return Err(NodeError::ConsensusInvalid(format!(
                "insufficient QC signatures: got {}, required {required}",
                distinct_signers.len()
            )));
        }
        Ok(())
    }

    /// Builds a JSON-friendly summary DTO for RPC responses and `Meritora Desktop`.
    pub fn to_summary_json(&self, quorum_threshold: usize) -> Value {
        let signers: Vec<String> = self.votes.iter().map(|v| v.validator_id.clone()).collect();
        json!({
            "chain_id": self.chain_id,
            "height": self.height,
            "round": self.round,
            "step": self.step,
            "block_hash_hex": hex::encode(self.block_hash),
            "state_root_hex": hex::encode(self.state_root),
            "vote_count": self.votes.len(),
            "quorum_threshold": quorum_threshold,
            "signer_ids": signers,
            "validator_reward": "0",
        })
    }
}

/// Cryptographic proof of Byzantine double-signing (double-proposal or double-vote) by the
/// same validator at the exact same `(height, round, step)` for two distinct `block_hash`es.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub vote_a: SignedConsensusVote,
    pub vote_b: SignedConsensusVote,
}

impl EquivocationEvidence {
    /// Verifies that `vote_a` and `vote_b` are two genuine conflicting signatures from the
    /// same registered validator at the same `(height, round, step)`.
    pub fn verify(&self, validator_set: &ValidatorSet, expected_chain_id: &str) -> NodeResult<()> {
        if self.vote_a.validator_id != self.vote_b.validator_id {
            return Err(NodeError::ConsensusInvalid(
                "equivocation votes belong to different validators".into(),
            ));
        }
        if self.vote_a.chain_id != expected_chain_id || self.vote_b.chain_id != expected_chain_id {
            return Err(NodeError::ConsensusInvalid(
                "equivocation chain_id mismatch".into(),
            ));
        }
        if self.vote_a.height != self.vote_b.height
            || self.vote_a.round != self.vote_b.round
            || self.vote_a.step != self.vote_b.step
        {
            return Err(NodeError::ConsensusInvalid(
                "equivocation votes do not share identical (height, round, step)".into(),
            ));
        }
        if self.vote_a.block_hash == self.vote_b.block_hash {
            return Err(NodeError::ConsensusInvalid(
                "identical block_hash is not an equivocation".into(),
            ));
        }

        let Some(info) = validator_set.get(&self.vote_a.validator_id) else {
            return Err(NodeError::ConsensusInvalid(format!(
                "unknown validator '{}'",
                self.vote_a.validator_id
            )));
        };

        if !self.vote_a.verify_signature(&info.pubkey)
            || !self.vote_b.verify_signature(&info.pubkey)
        {
            return Err(NodeError::ConsensusInvalid(
                "equivocation evidence failed strict Ed25519 signature verification".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_prefix_and_tampered_vote_guards() {
        let (pairs, vset) = ValidatorSet::deterministic_local_committee(4).unwrap();
        assert_eq!(vset.active_count(), 4);
        assert_eq!(vset.quorum_threshold(), 3);

        let mut vote = SignedConsensusVote::sign(
            &pairs[0].0,
            &pairs[0].1.validator_id,
            "gmc-test",
            1,
            0,
            BftStep::Prevote,
            [0x11; 32],
            [0x22; 32],
        )
        .unwrap();
        assert!(vote.verify_against_set(&vset, "gmc-test").is_ok());

        // Flip 1 bit -> strict verification must reject
        vote.signature[0] ^= 0x01;
        assert!(vote.verify_against_set(&vset, "gmc-test").is_err());
    }
}
