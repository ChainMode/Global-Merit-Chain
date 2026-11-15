//! `L2_Rollup` — pure-logic model of the ZK Rollup L2 high-frequency layer.
//!
//! Per the design's *L1/L2 分层架构集成* section, the **L2_Rollup** layer is a ZK
//! Rollup responsible for high-frequency processing: contribution-record creation,
//! real-time MeriToken computation and intimacy updates, returning a computation
//! result within a 5-second SLA (Requirement 13.2). It batches that work and submits a
//! batch zero-knowledge proof to L1 whenever **1,000 records** accumulate **or 60
//! seconds** elapse since the last batch — whichever comes first (Requirement 13.3) —
//! the entry point being `Recording_Service.submitRollupBatch` (Requirement 9.7). The
//! L2 runs a BFT-class consensus with block finality ≤ 3 seconds (Requirement 13.7).
//!
//! ## Why this is a pure-logic abstraction (not a real ZK rollup)
//!
//! `gmc-core` is intentionally dependency-free (task 1.1): it must compile and be
//! testable without any Substrate / ZK / proving-system crates so the very same logic
//! can be reused by both the L1 pallet and the L2 rollup. Accordingly this module
//! models **the batch-trigger decision and the per-record processing seam** as a
//! deterministic, in-memory state machine ([`L2Rollup`]). The real ZK Rollup is a thin
//! wrapper that:
//!
//! - executes the actual `Scoring_Engine` + `Minting_Service` + intimacy update for
//!   each record (here modeled by [`L2Rollup::process_contribution`], which threads a
//!   pre-computed amount through and returns a [`ComputationResult`] synchronously);
//! - generates a real zero-knowledge proof over the batched state transition (here a
//!   [`BatchProof`] placeholder + a deterministic model [`BatchRoot`]);
//! - submits `(batch_root, proof)` to L1 for verification (here the decoupled
//!   [`L1ProofSink`] seam);
//! - runs a real BFT engine honouring the ≤ 3 s finality budget (here the
//!   [`L2Consensus`] marker).
//!
//! Where this module says "model" / "stand-in" / "budget", the production rollup
//! substitutes the corresponding real primitive; the **batch-trigger arithmetic**
//! ([`L2Rollup::should_submit_batch`] / [`L2Rollup::try_submit_batch`]) is, however,
//! the real protocol logic and is what Property 29 (task 19.3) verifies.
//!
//! ## Latency & finality budgets (Requirements 13.2, 13.7)
//!
//! These are documented **SLAs**, not something the pure-logic model can enforce by
//! itself (it returns immediately): [`COMPUTE_LATENCY_BUDGET_SECS`] = 5 s is the
//! deadline within which [`process_contribution`](L2Rollup::process_contribution) must
//! return a computation result on the real L2; [`L2Consensus::finality_budget_secs`]
//! = [`BFT_FINALITY_BUDGET_SECS`] = 3 s is the block-finality budget the real BFT
//! engine honours.
//!
//! ## Decoupling from the concurrently-edited L1 module (the [`L1ProofSink`] seam)
//!
//! The L2→L1 submission boundary is modeled with the [`L1ProofSink`] **trait defined
//! here**, so this module does **not** import the `l1_settlement` module (authored /
//! edited concurrently) nor any of its internals. [`try_submit_batch`] produces a
//! self-contained [`Batch`] value `{ records, batch_root, proof }`; the integration
//! task (20.1) implements [`L1ProofSink`] over the real `L1Settlement` (whose
//! `submit_batch_proof` guard — verify proof, update the state root on success, retain
//! the previous root on failure — is task 18.2, Requirement 13.8) and hands the batch
//! to it. [`L2Rollup::submit_batch_proof_to`] is the convenience that wires a produced
//! batch into any [`L1ProofSink`].
//!
//! ## Sharding scale-out & ZK voter privacy (task 19.2)
//!
//! Two further L2-layer concerns are modeled at the bottom of this module:
//!
//! - **Sharding scale-out (Requirement 13.5)** — when the network-wide submission rate
//!   stays above the in-use instances' combined rated throughput for > 60 s, parallel
//!   rollup instances are added until the total rated throughput covers the rate. The
//!   single-instance [`L2Rollup`] above models *one* shard's batching; the
//!   [`ShardController`] layered on top owns N parallel instances and captures the
//!   **scale-out decision arithmetic** ([`ShardController::observe_rate`] /
//!   [`required_instances`]). Real elastic provisioning is infrastructure; this module
//!   captures only the deterministic, unit-testable decision.
//! - **ZK voter privacy (Requirement 11.7)** — [`PublicVoteResult`] models the privacy
//!   property: from a private [`VoteTally`] only the *aggregate outcome* (pass/fail and
//!   approval ratio) is published; per-voter identities are never part of the public
//!   view. The real ZK proof attests the tally without revealing ballots.

use std::collections::VecDeque;

use crate::error::GmcResult;
use crate::types::{ChainId, Decimal, FayID, Ratio, Timestamp};

/// Maximum number of records buffered before a batch is submitted to L1
/// (Requirement 13.3). The 1,000th accumulated record since the last batch triggers a
/// record-threshold flush.
pub const BATCH_MAX_RECORDS: usize = 1_000;

/// Maximum number of seconds since the last batch before a batch is submitted to L1
/// (Requirement 13.3). Once this many seconds have elapsed since the previous batch
/// (and at least one record is buffered) a time-elapsed flush triggers.
pub const BATCH_MAX_INTERVAL_SECS: u64 = 60;

/// Per-record processing latency budget, in seconds (Requirement 13.2).
///
/// Documented SLA: the real L2 must return a [`ComputationResult`] from
/// [`L2Rollup::process_contribution`] within this many seconds of a contribution
/// submission. The pure-logic model returns immediately; this constant records the
/// deadline the production rollup honours.
pub const COMPUTE_LATENCY_BUDGET_SECS: u64 = 5;

/// L2 block-finality budget, in seconds (Requirement 13.7).
///
/// Documented SLA for the BFT-class consensus: a block must reach final confirmation
/// within this many seconds. Surfaced by [`L2Consensus::finality_budget_secs`].
pub const BFT_FINALITY_BUDGET_SECS: u64 = 3;

/// Rated sustained throughput of a single rollup instance, in records per second
/// (Requirement 13.5). This is the per-shard capacity used by the [`ShardController`]
/// scale-out arithmetic; the network-wide capacity is `instance_count *
/// PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC`.
pub const PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC: u64 = 1_000;

/// How long (in seconds) the submission rate must remain **strictly above** the in-use
/// instances' combined rated throughput before the [`ShardController`] scales out
/// (Requirement 13.5). The overload must be *sustained* for longer than this window.
pub const SUSTAINED_OVERLOAD_SECS: u64 = 60;

/// The L2 consensus configuration (Requirement 13.7).
///
/// Analogous to `l1_settlement::ConsensusConfig` (which records GRANDPA/BABE for L1),
/// this records the protocol decision for L2: a **BFT-class** consensus with block
/// finality ≤ [`BFT_FINALITY_BUDGET_SECS`] seconds. The pure-logic core only needs to
/// *record* the chosen consensus and its finality budget; the real BFT engine is the
/// rollup runtime's responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum L2Consensus {
    /// A BFT-class consensus with ≤ 3 s block finality (Requirement 13.7).
    #[default]
    Bft,
}

impl L2Consensus {
    /// The configured L2 consensus (always [`L2Consensus::Bft`]).
    pub const L2: L2Consensus = L2Consensus::Bft;

    /// A stable, human-readable label for the consensus family.
    pub const fn label(self) -> &'static str {
        match self {
            L2Consensus::Bft => "BFT",
        }
    }

    /// The block-finality budget in seconds: [`BFT_FINALITY_BUDGET_SECS`] (= 3).
    pub const fn finality_budget_secs(self) -> u64 {
        BFT_FINALITY_BUDGET_SECS
    }

    /// `true` if a BFT-class consensus is in use (always `true` for the L2 config).
    pub const fn is_bft(self) -> bool {
        matches!(self, L2Consensus::Bft)
    }
}

/// Opaque identifier of a contribution record created on L2.
///
/// Allocated by [`L2Rollup::process_contribution`] (`rollup-rec-<n>`, monotonically
/// increasing across the rollup's lifetime — it does **not** reset on a batch flush).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RollupRecordId(String);

impl RollupRecordId {
    /// Builds a [`RollupRecordId`] from any string-like value.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        RollupRecordId(id.into())
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for RollupRecordId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A contribution submission entering the L2 rollup for high-frequency processing.
///
/// In the real L2 the MeriToken `amount` is computed by `Scoring_Engine` +
/// `Minting_Service`. To keep `l2_rollup` decoupled from those modules, the amount is
/// modeled as an **input** here (`merit_amount`); the integration task (20.1) computes
/// it and passes it in. This module's responsibility is the contribution-record
/// creation, intimacy-update marking, buffering and batch-trigger decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionSubmission {
    /// The contributor the contribution belongs to.
    pub contributor_id: FayID,
    /// The merit chain the contribution was recorded against.
    pub chain_id: ChainId,
    /// The MeriToken amount computed for this contribution (modeled input; see above).
    pub merit_amount: Decimal,
}

impl ContributionSubmission {
    /// Builds a [`ContributionSubmission`] from its parts.
    pub fn new(contributor_id: FayID, chain_id: ChainId, merit_amount: Decimal) -> Self {
        ContributionSubmission {
            contributor_id,
            chain_id,
            merit_amount,
        }
    }
}

/// The synchronous result of processing one contribution on L2 (Requirement 13.2).
///
/// Bundles the three things the design says L2 does per record — contribution-record
/// creation, MeriToken computation and intimacy update — and is returned by
/// [`L2Rollup::process_contribution`] immediately (the real L2 returns it within the
/// [`COMPUTE_LATENCY_BUDGET_SECS`] SLA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputationResult {
    /// The id of the contribution record created for this submission.
    pub record_id: RollupRecordId,
    /// The contributor the result belongs to.
    pub contributor_id: FayID,
    /// The merit chain the contribution was recorded against.
    pub chain_id: ChainId,
    /// The MeriToken amount computed for this contribution.
    pub merit_amount: Decimal,
    /// Whether the contributor's intimacy graph was updated as part of processing.
    pub intimacy_updated: bool,
    /// The on-chain time the result was computed.
    pub computed_at: Timestamp,
}

/// A record buffered by the rollup awaiting inclusion in the next batch.
///
/// Produced from a [`ContributionSubmission`] by
/// [`L2Rollup::process_contribution`], or supplied directly via
/// [`L2Rollup::record_contribution`]. The integration task (20.1) maps a
/// `recording::ContributionRecord` into this lightweight, self-contained shape so
/// `l2_rollup` stays decoupled from the `recording` module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedRecord {
    /// The contribution record's id.
    pub record_id: RollupRecordId,
    /// The contributor the record belongs to.
    pub contributor_id: FayID,
    /// The merit chain the contribution was recorded against.
    pub chain_id: ChainId,
    /// The MeriToken amount computed for this contribution.
    pub merit_amount: Decimal,
    /// The on-chain time the record was ingested into the rollup buffer.
    pub ingested_at: Timestamp,
}

impl BufferedRecord {
    /// Builds a [`BufferedRecord`] from its parts.
    pub fn new(
        record_id: RollupRecordId,
        contributor_id: FayID,
        chain_id: ChainId,
        merit_amount: Decimal,
        ingested_at: Timestamp,
    ) -> Self {
        BufferedRecord {
            record_id,
            contributor_id,
            chain_id,
            merit_amount,
            ingested_at,
        }
    }
}

/// What caused a batch to be submitted (the "whichever comes first" winner of
/// Requirement 13.3 / Property 29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BatchTrigger {
    /// Accumulated records reached [`BATCH_MAX_RECORDS`] (1,000) since the last batch.
    RecordThreshold,
    /// [`BATCH_MAX_INTERVAL_SECS`] (60 s) elapsed since the last batch with ≥ 1 record.
    IntervalElapsed,
}

/// A model of the ZK batch **state root** the rollup commits to (Requirements 13.3,
/// 8.6, 13.8).
///
/// In the production rollup this is the real cryptographic root of the batched state
/// transition. Here it is a 32-byte **stand-in** derived deterministically from the
/// batch sequence and its record ids (an FNV-1a-style mix), so the surrounding flow —
/// "each batch produces a distinct root committed to L1" — is exercisable without a
/// hashing/crypto dependency. The byte width matches a typical 256-bit chain state
/// root, making the seam shape-compatible with `l1_settlement`'s `StateRoot`; task
/// 20.1 maps between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchRoot([u8; 32]);

impl BatchRoot {
    /// An all-zero root (no batch committed yet).
    pub const GENESIS: BatchRoot = BatchRoot([0u8; 32]);

    /// Builds a [`BatchRoot`] from explicit bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        BatchRoot(bytes)
    }

    /// Returns the underlying 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `true` if this is the all-zero [`GENESIS`](BatchRoot::GENESIS) root.
    pub fn is_genesis(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Deterministically derives a batch root from the batch `seq` and its records.
    ///
    /// **Stand-in**, not a cryptographic commitment: an FNV-1a-style mix over the
    /// sequence number and each record id. Determinism guarantees the L1 pallet and
    /// the L2 rollup agree on the model root; including the strictly-increasing `seq`
    /// keeps successive batch roots distinct. The production rollup replaces this with
    /// the real ZK state-transition root.
    fn derive(seq: u64, records: &VecDeque<BufferedRecord>) -> BatchRoot {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let mut h = FNV_OFFSET;
            h = (h ^ seq).wrapping_mul(FNV_PRIME);
            h = (h ^ i as u64).wrapping_mul(FNV_PRIME);
            h = (h ^ records.len() as u64).wrapping_mul(FNV_PRIME);
            for record in records {
                for &b in record.record_id.as_str().as_bytes() {
                    h = (h ^ b as u64).wrapping_mul(FNV_PRIME);
                }
            }
            *slot = (h ^ (h >> 32)) as u8;
        }
        BatchRoot(out)
    }
}

impl Default for BatchRoot {
    fn default() -> Self {
        BatchRoot::GENESIS
    }
}

/// A placeholder for the batch zero-knowledge proof submitted to L1 (Requirement 9.7).
///
/// `gmc-core` carries no proving-system dependency, so this is a **placeholder** that
/// records just enough to model the L2→L1 submission seam: the number of records the
/// batch proves and the [`BatchRoot`] it commits to. The production rollup replaces it
/// with a real succinct proof; L1's verification of that proof is task 18.2
/// (Requirement 13.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchProof {
    record_count: usize,
    committed_root: BatchRoot,
}

impl BatchProof {
    /// Builds a [`BatchProof`] from `record_count` and `committed_root`.
    pub const fn new(record_count: usize, committed_root: BatchRoot) -> Self {
        BatchProof {
            record_count,
            committed_root,
        }
    }

    /// The number of records this proof attests to.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// The batch root this proof commits to.
    pub fn committed_root(&self) -> BatchRoot {
        self.committed_root
    }
}

/// A batch of processed contribution records ready for L1 submission.
///
/// Produced by [`L2Rollup::try_submit_batch`] when the Requirement 13.3 trigger fires.
/// Self-contained so the integration task (20.1) can hand it to an [`L1ProofSink`]
/// (e.g. the real `L1Settlement::submit_batch_proof`) without `l2_rollup` depending on
/// the L1 module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// Monotonic batch sequence number (first batch = 1).
    pub seq: u64,
    /// The records included in this batch, in ingestion order.
    pub records: Vec<BufferedRecord>,
    /// The (model) state root this batch commits to.
    pub batch_root: BatchRoot,
    /// The (placeholder) zero-knowledge proof for this batch.
    pub proof: BatchProof,
    /// The on-chain time the batch was submitted.
    pub submitted_at: Timestamp,
    /// Which Requirement 13.3 condition triggered the submission.
    pub trigger: BatchTrigger,
}

impl Batch {
    /// Number of records in this batch.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` if the batch has no records (never produced by [`L2Rollup`], which only
    /// flushes non-empty buffers).
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// The L2→L1 batch-proof submission boundary (Requirement 9.7,
/// `Recording_Service.submitRollupBatch`).
///
/// Defined here so [`L2Rollup`] stays **decoupled** from the `l1_settlement` module.
/// The integration task (20.1) implements this trait over the real `L1Settlement`,
/// delegating to its `submit_batch_proof` guard (task 18.2): verify the proof, update
/// the confirmed state root to `batch_root` on success, or retain the previous root
/// and return [`GmcError::ProofVerificationFailed`](crate::error::GmcError::ProofVerificationFailed)
/// on failure (Requirement 13.8).
pub trait L1ProofSink {
    /// Submits a batch's `batch_root` and `proof` to L1 for verification.
    ///
    /// Returns `Ok(())` when L1 accepted the batch (proof verified, state root
    /// advanced to `batch_root`), or
    /// `Err(`[`GmcError::ProofVerificationFailed`](crate::error::GmcError::ProofVerificationFailed)`)`
    /// when verification failed and the previous confirmed root was retained.
    fn submit_batch_proof(&mut self, batch_root: BatchRoot, proof: &BatchProof) -> GmcResult<()>;
}

/// Pure-logic model of a single ZK Rollup L2 instance's high-frequency processing &
/// batching (Requirements 9.7, 13.2, 13.3, 13.7).
///
/// Construct with [`L2Rollup::new`] (anchoring the batch timer at a genesis time),
/// feed contributions via [`process_contribution`](L2Rollup::process_contribution) (or
/// buffer pre-built records via [`record_contribution`](L2Rollup::record_contribution)),
/// and flush to L1 with [`try_submit_batch`](L2Rollup::try_submit_batch) whenever the
/// Requirement 13.3 trigger fires.
///
/// The batch-trigger arithmetic is deterministic and is the real protocol logic that
/// Property 29 (task 19.3) verifies.
#[derive(Debug, Clone)]
pub struct L2Rollup {
    /// Records buffered since the last batch submission (ingestion order).
    buffer: VecDeque<BufferedRecord>,
    /// The on-chain time of the last batch submission (or the rollup genesis time).
    last_batch_at: Timestamp,
    /// Monotonic batch sequence number; the next batch will be `next_batch_seq`.
    next_batch_seq: u64,
    /// Monotonic record sequence used to allocate [`RollupRecordId`]s; never resets.
    next_record_seq: u64,
    /// The L2 consensus configuration (BFT, ≤ 3 s finality).
    consensus: L2Consensus,
}

impl L2Rollup {
    /// Creates an empty rollup whose batch timer is anchored at `genesis_time`.
    ///
    /// The first batch's "60 s since last batch" window is measured from
    /// `genesis_time`. Configured with [`L2Consensus::Bft`] (Requirement 13.7).
    pub fn new(genesis_time: Timestamp) -> Self {
        L2Rollup {
            buffer: VecDeque::new(),
            last_batch_at: genesis_time,
            next_batch_seq: 1,
            next_record_seq: 0,
            consensus: L2Consensus::L2,
        }
    }

    // --- Configuration markers (Requirement 13.7) --------------------------

    /// The L2 consensus configuration: BFT with ≤ 3 s finality (Requirement 13.7).
    pub const fn consensus(&self) -> L2Consensus {
        self.consensus
    }

    // --- Read accessors -----------------------------------------------------

    /// Number of records buffered since the last batch.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// `true` if no records are buffered since the last batch.
    pub fn is_buffer_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// The on-chain time of the last batch submission (or the genesis time).
    pub fn last_batch_at(&self) -> Timestamp {
        self.last_batch_at
    }

    /// The sequence number the next submitted batch will carry (first batch = 1).
    pub fn next_batch_seq(&self) -> u64 {
        self.next_batch_seq
    }

    /// Seconds elapsed since the last batch submission, given the current time `now`
    /// (saturating at zero if `now` precedes the last batch time).
    pub fn secs_since_last_batch(&self, now: Timestamp) -> u64 {
        now.saturating_elapsed_since(self.last_batch_at)
    }

    /// Iterates over the currently buffered records in ingestion order.
    pub fn buffered(&self) -> impl Iterator<Item = &BufferedRecord> {
        self.buffer.iter()
    }

    // --- Per-record processing (Requirement 13.2) --------------------------

    /// Processes one contribution submission and buffers it, returning the computation
    /// result synchronously (Requirement 13.2).
    ///
    /// Models the three things L2 does per record:
    ///
    /// 1. **contribution-record creation** — allocates a fresh [`RollupRecordId`];
    /// 2. **MeriToken computation** — threads the submission's `merit_amount` through
    ///    (the real L2 computes it via `Scoring_Engine` + `Minting_Service`);
    /// 3. **intimacy update** — marked performed in the returned result.
    ///
    /// The processed record is appended to the batch buffer via
    /// [`record_contribution`](L2Rollup::record_contribution). The real L2 must return
    /// this result within [`COMPUTE_LATENCY_BUDGET_SECS`] seconds; the model returns
    /// immediately.
    ///
    /// This does **not** itself submit a batch — call
    /// [`try_submit_batch`](L2Rollup::try_submit_batch) (typically after each ingest,
    /// or on a timer tick) to flush when the Requirement 13.3 trigger fires.
    pub fn process_contribution(
        &mut self,
        submission: ContributionSubmission,
        now: Timestamp,
    ) -> ComputationResult {
        let record_id = self.allocate_record_id();

        let result = ComputationResult {
            record_id: record_id.clone(),
            contributor_id: submission.contributor_id.clone(),
            chain_id: submission.chain_id.clone(),
            merit_amount: submission.merit_amount,
            intimacy_updated: true,
            computed_at: now,
        };

        self.record_contribution(BufferedRecord::new(
            record_id,
            submission.contributor_id,
            submission.chain_id,
            submission.merit_amount,
            now,
        ));

        result
    }

    /// Appends an already-processed [`BufferedRecord`] to the batch buffer.
    ///
    /// The low-level buffering primitive used by
    /// [`process_contribution`](L2Rollup::process_contribution); the integration task
    /// (20.1) may also call it directly when mapping `recording::ContributionRecord`s
    /// into the rollup. Buffering never itself triggers a submission.
    pub fn record_contribution(&mut self, record: BufferedRecord) {
        self.buffer.push_back(record);
    }

    // --- Batch-trigger decision (Requirement 13.3 / Property 29) -----------

    /// Determines which Requirement 13.3 condition (if any) currently warrants a batch
    /// submission, given the current time `now`.
    ///
    /// Returns:
    /// - `None` when the buffer is empty (there is nothing to prove — the 60 s timer is
    ///   only meaningful once at least one record has accumulated), or when neither
    ///   threshold is reached;
    /// - `Some(`[`BatchTrigger::RecordThreshold`]`)` when ≥ [`BATCH_MAX_RECORDS`]
    ///   records are buffered (this takes precedence — it is the "first" trigger when
    ///   both hold);
    /// - `Some(`[`BatchTrigger::IntervalElapsed`]`)` when fewer than
    ///   [`BATCH_MAX_RECORDS`] records are buffered but ≥ [`BATCH_MAX_INTERVAL_SECS`]
    ///   seconds have elapsed since the last batch.
    pub fn batch_trigger(&self, now: Timestamp) -> Option<BatchTrigger> {
        if self.buffer.is_empty() {
            return None;
        }
        if self.buffer.len() >= BATCH_MAX_RECORDS {
            Some(BatchTrigger::RecordThreshold)
        } else if self.secs_since_last_batch(now) >= BATCH_MAX_INTERVAL_SECS {
            Some(BatchTrigger::IntervalElapsed)
        } else {
            None
        }
    }

    /// Whether a batch should be submitted to L1 at time `now` (Requirement 13.3).
    ///
    /// Equivalent to `self.batch_trigger(now).is_some()`: `true` iff at least one
    /// record is buffered **and** either the 1,000-record threshold or the 60-second
    /// interval has been reached (whichever comes first).
    pub fn should_submit_batch(&self, now: Timestamp) -> bool {
        self.batch_trigger(now).is_some()
    }

    /// Submits a batch to L1 if the Requirement 13.3 trigger fires at time `now`.
    ///
    /// When [`batch_trigger`](L2Rollup::batch_trigger) yields a trigger, this drains
    /// the entire buffer into a [`Batch`] (records in ingestion order), derives the
    /// model [`BatchRoot`] and [`BatchProof`], stamps the batch with `now` and the
    /// winning [`BatchTrigger`], and **resets the per-batch state**: the buffer is
    /// emptied and `last_batch_at` is set to `now`, restarting the 60-second window;
    /// the batch sequence advances. Returns `Some(batch)`.
    ///
    /// When the trigger does not fire, returns `None` and leaves all state unchanged.
    pub fn try_submit_batch(&mut self, now: Timestamp) -> Option<Batch> {
        let trigger = self.batch_trigger(now)?;

        let seq = self.next_batch_seq;
        let batch_root = BatchRoot::derive(seq, &self.buffer);
        let records: Vec<BufferedRecord> = self.buffer.drain(..).collect();
        let proof = BatchProof {
            record_count: records.len(),
            committed_root: batch_root,
        };

        // Reset per-batch state: restart the interval window and advance the sequence.
        self.last_batch_at = now;
        self.next_batch_seq += 1;

        Some(Batch {
            seq,
            records,
            batch_root,
            proof,
            submitted_at: now,
            trigger,
        })
    }

    // --- L1 submission boundary (Requirement 9.7) --------------------------

    /// Submits a produced [`Batch`] to L1 through an [`L1ProofSink`]
    /// (`Recording_Service.submitRollupBatch`, Requirement 9.7).
    ///
    /// Convenience that hands `batch.batch_root` and `batch.proof` to the sink. The
    /// integration task (20.1) implements [`L1ProofSink`] over the real `L1Settlement`
    /// (task 18.2's `submit_batch_proof` guard, Requirement 13.8). Propagates the
    /// sink's `Ok(())` / [`GmcError::ProofVerificationFailed`](crate::error::GmcError::ProofVerificationFailed).
    pub fn submit_batch_proof_to(batch: &Batch, sink: &mut impl L1ProofSink) -> GmcResult<()> {
        sink.submit_batch_proof(batch.batch_root, &batch.proof)
    }

    /// Monotonic next record sequence counter (used for deterministic persistence).
    pub const fn next_record_seq(&self) -> u64 {
        self.next_record_seq
    }

    /// Restores an [`L2Rollup`] instance from persisted deterministic state.
    pub fn from_persisted_parts(
        buffer: VecDeque<BufferedRecord>,
        last_batch_at: Timestamp,
        next_batch_seq: u64,
        next_record_seq: u64,
    ) -> Self {
        L2Rollup {
            buffer,
            last_batch_at,
            next_batch_seq,
            next_record_seq,
            consensus: L2Consensus::L2,
        }
    }

    /// Builds the candidate [`Batch`] without draining the buffer yet, either only when
    /// [`batch_trigger`](L2Rollup::batch_trigger) fires (`force == false`) or whenever
    /// the buffer is non-empty (`force == true`, e.g. explicit block production).
    pub fn preview_batch(&self, now: Timestamp, force: bool) -> Option<Batch> {
        if self.buffer.is_empty() {
            return None;
        }
        let trigger = match self.batch_trigger(now) {
            Some(t) => t,
            None if force => BatchTrigger::IntervalElapsed,
            None => return None,
        };
        let seq = self.next_batch_seq;
        let batch_root = BatchRoot::derive(seq, &self.buffer);
        let records: Vec<BufferedRecord> = self.buffer.iter().cloned().collect();
        let proof = BatchProof {
            record_count: records.len(),
            committed_root: batch_root,
        };
        Some(Batch {
            seq,
            records,
            batch_root,
            proof,
            submitted_at: now,
            trigger,
        })
    }

    /// Commits a previewed batch after `L1ProofSink` verification succeeds, draining
    /// the buffer, advancing `next_batch_seq`, and resetting `last_batch_at = now`.
    pub fn commit_previewed_batch(&mut self, now: Timestamp) {
        self.buffer.clear();
        self.last_batch_at = now;
        self.next_batch_seq += 1;
    }

    // --- Internal helpers ---------------------------------------------------

    /// Allocates a fresh, deterministic [`RollupRecordId`] (`rollup-rec-<n>`), never
    /// resetting across batch flushes.
    fn allocate_record_id(&mut self) -> RollupRecordId {
        let id = RollupRecordId::new(format!("rollup-rec-{}", self.next_record_seq));
        self.next_record_seq += 1;
        id
    }
}

// =============================================================================
// Sharding scale-out (Requirement 13.5)
// =============================================================================

/// The minimum number of parallel rollup instances whose combined rated throughput
/// (`n * `[`PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC`]) covers `submission_rate_per_sec`
/// (Requirement 13.5).
///
/// This is the `ceil(rate / per_instance)` arithmetic, clamped to **at least one**
/// instance (a rollup always runs at least a single shard, even at a zero rate). It is
/// a pure, deterministic function so the scale-out decision is fully unit-testable.
///
/// # Examples
/// ```
/// use gmc_core::l2_rollup::{required_instances, PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC};
/// assert_eq!(PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC, 1_000);
/// assert_eq!(required_instances(0), 1);       // always at least one shard
/// assert_eq!(required_instances(1_000), 1);   // exactly one instance's capacity
/// assert_eq!(required_instances(1_001), 2);   // one over → needs a second shard
/// assert_eq!(required_instances(2_500), 3);   // ceil(2500 / 1000)
/// ```
pub fn required_instances(submission_rate_per_sec: u64) -> usize {
    let per_instance = PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC;
    // ceil(rate / per_instance), but never fewer than one instance.
    let ceil = submission_rate_per_sec.div_ceil(per_instance);
    ceil.max(1) as usize
}

/// The outcome of feeding an observed submission rate to a [`ShardController`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleDecision {
    /// The instance count in effect *after* this observation.
    pub instance_count: usize,
    /// `true` if this observation caused new parallel instances to be added.
    pub scaled_out: bool,
}

/// Pure-logic model of the L2 sharding scale-out controller (Requirement 13.5).
///
/// Owns a count of `N` parallel [`L2Rollup`] instances (each rated at
/// [`PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC`] records/sec) and tracks how long the
/// observed network-wide submission rate has stayed **strictly above** the in-use
/// instances' combined rated throughput. Once that overload has been *sustained* for
/// longer than [`SUSTAINED_OVERLOAD_SECS`] (60 s), it scales out to
/// [`required_instances`] so the total rated throughput covers the rate — exactly the
/// Requirement 13.5 rule.
///
/// ## What is and isn't modeled
///
/// Real elastic provisioning (spinning up machines, rebalancing shards) is
/// infrastructure outside this dependency-free core. [`ShardController`] models only
/// the **deterministic scale-out decision arithmetic**: when to add instances and how
/// many. Feed it observations with [`observe_rate`](ShardController::observe_rate); it
/// reports whether it scaled and the resulting instance count.
///
/// ## Overload tracking
///
/// The controller remembers the timestamp at which the *current* contiguous overload
/// began (`overload_since`). While the rate stays above current capacity, that anchor
/// is held; once `now - overload_since > SUSTAINED_OVERLOAD_SECS` it scales out and the
/// overload window is re-anchored against the *new* (larger) capacity. Any observation
/// at or below current capacity clears the overload anchor (the overload must be
/// *continuous* to count).
#[derive(Debug, Clone)]
pub struct ShardController {
    /// Number of parallel rollup instances currently in use (always ≥ 1).
    instance_count: usize,
    /// The time the current contiguous overload began, or `None` if not overloaded.
    overload_since: Option<Timestamp>,
}

impl Default for ShardController {
    fn default() -> Self {
        ShardController::new()
    }
}

impl ShardController {
    /// Creates a controller starting with a single rollup instance and no overload.
    pub fn new() -> Self {
        ShardController {
            instance_count: 1,
            overload_since: None,
        }
    }

    /// Creates a controller starting with `instance_count` instances (clamped to ≥ 1).
    pub fn with_instances(instance_count: usize) -> Self {
        ShardController {
            instance_count: instance_count.max(1),
            overload_since: None,
        }
    }

    /// The number of parallel rollup instances currently in use (always ≥ 1).
    pub fn instance_count(&self) -> usize {
        self.instance_count
    }

    /// The combined rated throughput of all in-use instances, in records/sec:
    /// `instance_count * `[`PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC`].
    pub fn rated_throughput_per_sec(&self) -> u64 {
        (self.instance_count as u64) * PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC
    }

    /// `true` if the controller is currently tracking a contiguous overload window.
    pub fn is_overloaded(&self) -> bool {
        self.overload_since.is_some()
    }

    /// The time the current contiguous overload began, if any.
    pub fn overload_since(&self) -> Option<Timestamp> {
        self.overload_since
    }

    /// Observes the network-wide submission `rate_per_sec` at time `now` and applies
    /// the Requirement 13.5 scale-out rule.
    ///
    /// Behavior:
    /// - If `rate_per_sec` is at or below the in-use instances' combined rated
    ///   throughput, the overload window is cleared and no scaling occurs.
    /// - If `rate_per_sec` is strictly above current capacity, the overload window is
    ///   started (anchored at `now`) if it was not already running. Once the overload
    ///   has been sustained for **more than** [`SUSTAINED_OVERLOAD_SECS`] seconds, the
    ///   controller scales out to [`required_instances`]`(rate_per_sec)` so the total
    ///   rated throughput is `≥ rate_per_sec`, then re-anchors the overload window at
    ///   `now` against the new capacity.
    ///
    /// Returns a [`ScaleDecision`] with the resulting instance count and whether this
    /// observation triggered a scale-out.
    pub fn observe_rate(&mut self, rate_per_sec: u64, now: Timestamp) -> ScaleDecision {
        // Not overloaded: capacity covers the rate. Clear any overload window.
        if rate_per_sec <= self.rated_throughput_per_sec() {
            self.overload_since = None;
            return ScaleDecision {
                instance_count: self.instance_count,
                scaled_out: false,
            };
        }

        // Overloaded. Anchor the window if this is the start of a contiguous overload.
        let since = *self.overload_since.get_or_insert(now);
        let sustained_secs = now.saturating_elapsed_since(since);

        // Only scale once the overload has persisted for *longer than* the window.
        if sustained_secs <= SUSTAINED_OVERLOAD_SECS {
            return ScaleDecision {
                instance_count: self.instance_count,
                scaled_out: false,
            };
        }

        // Scale out to cover the observed rate, then re-anchor against new capacity.
        let needed = required_instances(rate_per_sec);
        let scaled_out = needed > self.instance_count;
        if scaled_out {
            self.instance_count = needed;
        }
        self.overload_since = Some(now);

        ScaleDecision {
            instance_count: self.instance_count,
            scaled_out,
        }
    }
}

// =============================================================================
// ZK voter privacy (Requirement 11.7)
// =============================================================================

/// A **private** aggregate vote tally — the input to publishing a [`PublicVoteResult`].
///
/// Models the result of a governance / anti-fraud vote as nothing more than two
/// weighted aggregates: the approving weight and the total weight. Crucially it carries
/// **no per-voter identities or ballots** — the design keeps `l2_rollup` decoupled from
/// `governance` / `antifraud`, and the privacy property is that identities never reach
/// the public surface in the first place. In the production system the ZK proof attests
/// that these aggregates were computed correctly over real ballots without revealing
/// them (Requirement 11.7); here the aggregates are taken as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteTally {
    approve_weight: Decimal,
    total_weight: Decimal,
}

impl VoteTally {
    /// Builds a tally from the approving weight and the total weight.
    ///
    /// Returns `None` if `total_weight` is not strictly positive or if `approve_weight`
    /// is negative or exceeds `total_weight` (a tally that cannot be a valid aggregate).
    pub fn new(approve_weight: Decimal, total_weight: Decimal) -> Option<VoteTally> {
        if !total_weight.is_positive() {
            return None;
        }
        if approve_weight.is_negative() || approve_weight > total_weight {
            return None;
        }
        Some(VoteTally {
            approve_weight,
            total_weight,
        })
    }

    /// The approving weight component of the tally.
    pub fn approve_weight(&self) -> Decimal {
        self.approve_weight
    }

    /// The total weight component of the tally.
    pub fn total_weight(&self) -> Decimal {
        self.total_weight
    }

    /// The weighted approval ratio `approve_weight / total_weight`, in `[0, 1]`.
    pub fn approval_ratio(&self) -> Ratio {
        // total_weight > 0 (invariant) and 0 ≤ approve_weight ≤ total_weight, so the
        // quotient is well-defined and lands in [0, 1].
        let raw = self
            .approve_weight
            .checked_div(self.total_weight)
            .unwrap_or(Decimal::ZERO);
        Ratio::new(raw).unwrap_or(Ratio::ONE)
    }
}

/// The **public** view of a vote outcome (Requirement 11.7).
///
/// This is the *only* thing the L2 publishes about a vote: whether it passed and the
/// aggregate weighted-approval ratio. By construction it has **no field that could
/// carry a voter identity** — no `FayID`, no per-ballot list — so individual votes
/// cannot be recovered from it. The real ZK proof attests that `passed` /
/// `approval_ratio` follow from the underlying ballots without ever revealing them.
///
/// Produced from a private [`VoteTally`] via [`PublicVoteResult::from_tally`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicVoteResult {
    /// Whether the vote reached its passing threshold (the aggregate outcome).
    passed: bool,
    /// The aggregate weighted-approval ratio (`approve_weight / total_weight`).
    approval_ratio: Ratio,
}

impl PublicVoteResult {
    /// Derives the public result from a private [`VoteTally`] and a passing `threshold`.
    ///
    /// The vote `passed` iff the tally's [`approval_ratio`](VoteTally::approval_ratio)
    /// is greater than or equal to `threshold`. Only the aggregate outcome and ratio
    /// are retained; the tally's components are not stored, and no voter identity is
    /// ever part of the produced value (Requirement 11.7).
    pub fn from_tally(tally: &VoteTally, threshold: Ratio) -> PublicVoteResult {
        let approval_ratio = tally.approval_ratio();
        PublicVoteResult {
            passed: approval_ratio.value() >= threshold.value(),
            approval_ratio,
        }
    }

    /// Builds a public result directly from an aggregate outcome and approval ratio.
    pub fn new(passed: bool, approval_ratio: Ratio) -> PublicVoteResult {
        PublicVoteResult {
            passed,
            approval_ratio,
        }
    }

    /// Whether the vote passed (the published aggregate outcome).
    pub fn passed(&self) -> bool {
        self.passed
    }

    /// The published aggregate weighted-approval ratio.
    pub fn approval_ratio(&self) -> Ratio {
        self.approval_ratio
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GmcError;

    fn ts(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn submission(contributor: &str, chain: &str) -> ContributionSubmission {
        ContributionSubmission::new(
            FayID::new(contributor),
            ChainId::new(chain),
            Decimal::from_int(10),
        )
    }

    /// Feeds `n` contributions into the rollup at time `now` without flushing.
    fn ingest_n(rollup: &mut L2Rollup, n: usize, now: Timestamp) {
        for _ in 0..n {
            rollup.process_contribution(submission("alice", "academia"), now);
        }
    }

    // --- Requirement 13.3: record-threshold triggers at exactly the 1000th ----

    #[test]
    fn batch_flushes_exactly_at_the_1000th_record() {
        let mut rollup = L2Rollup::new(ts(0));
        // 999 records, still within the 60 s window → no flush yet.
        ingest_n(&mut rollup, BATCH_MAX_RECORDS - 1, ts(1));
        assert_eq!(rollup.buffered_len(), 999);
        assert!(!rollup.should_submit_batch(ts(1)));
        assert_eq!(rollup.batch_trigger(ts(1)), None);

        // The 1000th record triggers a record-threshold flush.
        ingest_n(&mut rollup, 1, ts(2));
        assert_eq!(rollup.buffered_len(), 1_000);
        assert_eq!(
            rollup.batch_trigger(ts(2)),
            Some(BatchTrigger::RecordThreshold)
        );

        let batch = rollup
            .try_submit_batch(ts(2))
            .expect("1000th record flushes");
        assert_eq!(batch.len(), 1_000);
        assert_eq!(batch.trigger, BatchTrigger::RecordThreshold);
    }

    // --- Requirement 13.3: time trigger fires with fewer than 1000 records ----

    #[test]
    fn batch_flushes_when_60s_elapse_with_fewer_records() {
        let mut rollup = L2Rollup::new(ts(100));
        ingest_n(&mut rollup, 5, ts(110));

        // Before 60 s: no flush despite buffered records.
        assert!(!rollup.should_submit_batch(ts(159)));
        // At exactly 60 s since last batch (genesis @100): time trigger fires.
        assert_eq!(
            rollup.batch_trigger(ts(160)),
            Some(BatchTrigger::IntervalElapsed)
        );

        let batch = rollup
            .try_submit_batch(ts(160))
            .expect("60 s elapsed flushes");
        assert_eq!(batch.len(), 5);
        assert_eq!(batch.trigger, BatchTrigger::IntervalElapsed);
    }

    // --- Requirement 13.3: whichever comes first ------------------------------

    #[test]
    fn record_trigger_wins_when_1000_reached_before_60s() {
        let mut rollup = L2Rollup::new(ts(0));
        // 1000 records accumulate well within the 60 s window.
        ingest_n(&mut rollup, BATCH_MAX_RECORDS, ts(10));
        assert!(rollup.secs_since_last_batch(ts(10)) < BATCH_MAX_INTERVAL_SECS);
        assert_eq!(
            rollup.batch_trigger(ts(10)),
            Some(BatchTrigger::RecordThreshold)
        );
        let batch = rollup.try_submit_batch(ts(10)).unwrap();
        assert_eq!(batch.trigger, BatchTrigger::RecordThreshold);
    }

    #[test]
    fn time_trigger_wins_when_60s_elapse_before_1000() {
        let mut rollup = L2Rollup::new(ts(0));
        // Only 5 records, but 60 s pass.
        ingest_n(&mut rollup, 5, ts(5));
        assert!(rollup.buffered_len() < BATCH_MAX_RECORDS);
        assert_eq!(
            rollup.batch_trigger(ts(60)),
            Some(BatchTrigger::IntervalElapsed)
        );
        let batch = rollup.try_submit_batch(ts(60)).unwrap();
        assert_eq!(batch.trigger, BatchTrigger::IntervalElapsed);
    }

    // --- Requirement 13.3: flush resets the counter and the interval window ---

    #[test]
    fn flush_resets_buffer_counter_and_last_batch_time() {
        let mut rollup = L2Rollup::new(ts(0));
        ingest_n(&mut rollup, 5, ts(10));
        assert_eq!(rollup.next_batch_seq(), 1);

        let batch = rollup.try_submit_batch(ts(60)).expect("flush at 60 s");
        assert_eq!(batch.seq, 1);

        // Buffer drained, interval window restarted at the flush time, seq advanced.
        assert!(rollup.is_buffer_empty());
        assert_eq!(rollup.buffered_len(), 0);
        assert_eq!(rollup.last_batch_at(), ts(60));
        assert_eq!(rollup.secs_since_last_batch(ts(60)), 0);
        assert_eq!(rollup.next_batch_seq(), 2);

        // A fresh window: 59 s after the flush is not enough, 60 s is.
        ingest_n(&mut rollup, 3, ts(70));
        assert!(!rollup.should_submit_batch(ts(119)));
        assert!(rollup.should_submit_batch(ts(120)));
    }

    #[test]
    fn two_consecutive_batches_are_independent_and_seqs_increase() {
        let mut rollup = L2Rollup::new(ts(0));
        ingest_n(&mut rollup, 2, ts(10));
        let b1 = rollup.try_submit_batch(ts(60)).unwrap();

        ingest_n(&mut rollup, 4, ts(70));
        let b2 = rollup.try_submit_batch(ts(120)).unwrap();

        assert_eq!(b1.seq, 1);
        assert_eq!(b2.seq, 2);
        assert_eq!(b1.len(), 2);
        assert_eq!(b2.len(), 4);
        // Distinct, non-genesis batch roots.
        assert_ne!(b1.batch_root, b2.batch_root);
        assert!(!b1.batch_root.is_genesis());
        assert!(!b2.batch_root.is_genesis());
    }

    // --- Requirement 13.3: neither condition → no flush -----------------------

    #[test]
    fn under_both_thresholds_does_not_flush() {
        let mut rollup = L2Rollup::new(ts(0));
        ingest_n(&mut rollup, 10, ts(5));
        // Fewer than 1000 records and fewer than 60 s elapsed.
        assert!(!rollup.should_submit_batch(ts(30)));
        assert_eq!(rollup.try_submit_batch(ts(30)), None);
        // Nothing was consumed.
        assert_eq!(rollup.buffered_len(), 10);
    }

    #[test]
    fn empty_buffer_never_triggers_even_after_long_idle() {
        let mut rollup = L2Rollup::new(ts(0));
        // No records ingested; far more than 60 s elapse.
        assert!(!rollup.should_submit_batch(ts(10_000)));
        assert_eq!(rollup.batch_trigger(ts(10_000)), None);
        assert_eq!(rollup.try_submit_batch(ts(10_000)), None);
    }

    // --- Interval boundary is inclusive at exactly 60 s -----------------------

    #[test]
    fn interval_boundary_is_inclusive_at_60s() {
        let mut rollup = L2Rollup::new(ts(1_000));
        ingest_n(&mut rollup, 1, ts(1_000));
        assert!(!rollup.should_submit_batch(ts(1_059))); // 59 s
        assert!(rollup.should_submit_batch(ts(1_060))); // exactly 60 s
    }

    // --- Requirement 13.2: process returns a result and buffers the record ----

    #[test]
    fn process_contribution_returns_result_and_buffers_record() {
        let mut rollup = L2Rollup::new(ts(0));
        let result = rollup.process_contribution(submission("bob", "charity"), ts(42));

        assert_eq!(result.contributor_id, FayID::new("bob"));
        assert_eq!(result.chain_id, ChainId::new("charity"));
        assert_eq!(result.merit_amount, Decimal::from_int(10));
        assert!(result.intimacy_updated);
        assert_eq!(result.computed_at, ts(42));
        assert_eq!(result.record_id, RollupRecordId::new("rollup-rec-0"));

        // The processed record is buffered for the next batch.
        assert_eq!(rollup.buffered_len(), 1);
        let buffered = rollup.buffered().next().unwrap();
        assert_eq!(buffered.record_id, result.record_id);
        assert_eq!(buffered.ingested_at, ts(42));
    }

    #[test]
    fn record_ids_are_monotonic_across_batch_flushes() {
        let mut rollup = L2Rollup::new(ts(0));
        let r0 = rollup.process_contribution(submission("a", "c"), ts(1));
        rollup.try_submit_batch(ts(60));
        let r1 = rollup.process_contribution(submission("a", "c"), ts(61));
        assert_eq!(r0.record_id, RollupRecordId::new("rollup-rec-0"));
        // Ids do not reset on flush.
        assert_eq!(r1.record_id, RollupRecordId::new("rollup-rec-1"));
    }

    // --- Batch carries its records and a proof committing to its root ---------

    #[test]
    fn batch_carries_records_and_a_consistent_proof() {
        let mut rollup = L2Rollup::new(ts(0));
        ingest_n(&mut rollup, 3, ts(10));
        let batch = rollup.try_submit_batch(ts(60)).unwrap();

        assert_eq!(batch.records.len(), 3);
        assert_eq!(batch.proof.record_count(), 3);
        assert_eq!(batch.proof.committed_root(), batch.batch_root);
        assert_eq!(batch.submitted_at, ts(60));
        assert!(!batch.batch_root.is_genesis());
        // Records preserved in ingestion order.
        assert_eq!(
            batch.records[0].record_id,
            RollupRecordId::new("rollup-rec-0")
        );
        assert_eq!(
            batch.records[2].record_id,
            RollupRecordId::new("rollup-rec-2")
        );
    }

    // --- Requirement 9.7: L1ProofSink submission boundary ---------------------

    /// Test double for [`L1ProofSink`] modeling L1 verification (task 18.2 / Req 13.8).
    struct StubSink {
        accept: bool,
        last_root: Option<BatchRoot>,
        submissions: usize,
    }

    impl StubSink {
        fn new(accept: bool) -> Self {
            StubSink {
                accept,
                last_root: None,
                submissions: 0,
            }
        }
    }

    impl L1ProofSink for StubSink {
        fn submit_batch_proof(
            &mut self,
            batch_root: BatchRoot,
            proof: &BatchProof,
        ) -> GmcResult<()> {
            self.submissions += 1;
            assert_eq!(proof.committed_root(), batch_root);
            if self.accept {
                self.last_root = Some(batch_root);
                Ok(())
            } else {
                Err(GmcError::ProofVerificationFailed)
            }
        }
    }

    #[test]
    fn submit_batch_proof_to_accepting_sink_succeeds() {
        let mut rollup = L2Rollup::new(ts(0));
        ingest_n(&mut rollup, 2, ts(10));
        let batch = rollup.try_submit_batch(ts(60)).unwrap();

        let mut sink = StubSink::new(true);
        L2Rollup::submit_batch_proof_to(&batch, &mut sink).expect("accepting sink");
        assert_eq!(sink.submissions, 1);
        assert_eq!(sink.last_root, Some(batch.batch_root));
    }

    #[test]
    fn submit_batch_proof_to_rejecting_sink_propagates_error() {
        let mut rollup = L2Rollup::new(ts(0));
        ingest_n(&mut rollup, 2, ts(10));
        let batch = rollup.try_submit_batch(ts(60)).unwrap();

        let mut sink = StubSink::new(false);
        let err = L2Rollup::submit_batch_proof_to(&batch, &mut sink)
            .expect_err("rejecting sink propagates error");
        assert_eq!(err, GmcError::ProofVerificationFailed);
        assert_eq!(sink.last_root, None);
    }

    // --- Requirements 13.2 / 13.7: documented budget constants ----------------

    #[test]
    fn batch_and_budget_constants_have_expected_values() {
        assert_eq!(BATCH_MAX_RECORDS, 1_000);
        assert_eq!(BATCH_MAX_INTERVAL_SECS, 60);
        assert_eq!(COMPUTE_LATENCY_BUDGET_SECS, 5);
        assert_eq!(BFT_FINALITY_BUDGET_SECS, 3);
    }

    #[test]
    fn l2_consensus_is_bft_with_3s_finality_budget() {
        let rollup = L2Rollup::new(ts(0));
        assert_eq!(rollup.consensus(), L2Consensus::Bft);
        assert!(rollup.consensus().is_bft());
        assert_eq!(rollup.consensus().label(), "BFT");
        assert_eq!(rollup.consensus().finality_budget_secs(), 3);
        assert_eq!(
            rollup.consensus().finality_budget_secs(),
            BFT_FINALITY_BUDGET_SECS
        );
    }

    // --- Batch root derivation is deterministic across instances --------------

    #[test]
    fn batch_root_is_deterministic_across_instances() {
        let mut a = L2Rollup::new(ts(0));
        let mut b = L2Rollup::new(ts(0));
        ingest_n(&mut a, 3, ts(10));
        ingest_n(&mut b, 3, ts(10));
        let ba = a.try_submit_batch(ts(60)).unwrap();
        let bb = b.try_submit_batch(ts(60)).unwrap();
        assert_eq!(ba.batch_root, bb.batch_root);
    }

    // =====================================================================
    // Sharding scale-out (Requirement 13.5, task 19.2)
    // =====================================================================

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    // --- required_instances arithmetic: ceil(rate / 1000), at least one -------

    #[test]
    fn required_instances_is_ceil_of_rate_over_per_instance() {
        assert_eq!(PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC, 1_000);
        // Zero rate still needs at least one shard.
        assert_eq!(required_instances(0), 1);
        // Exactly one instance's rated throughput.
        assert_eq!(required_instances(1), 1);
        assert_eq!(required_instances(1_000), 1);
        // One over a multiple rounds up.
        assert_eq!(required_instances(1_001), 2);
        assert_eq!(required_instances(2_000), 2);
        assert_eq!(required_instances(2_001), 3);
        assert_eq!(required_instances(2_500), 3);
    }

    #[test]
    fn required_instances_total_throughput_covers_rate() {
        // The chosen instance count's combined rated throughput always covers the rate.
        for rate in [0u64, 1, 999, 1_000, 1_001, 2_500, 9_999, 10_000, 10_001] {
            let n = required_instances(rate) as u64;
            assert!(
                n * PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC >= rate,
                "instances={n} must cover rate={rate}"
            );
            assert!(n >= 1, "at least one instance for rate={rate}");
        }
    }

    // --- Controller does NOT scale until overload sustained > 60 s ------------

    #[test]
    fn controller_does_not_scale_for_rate_within_capacity() {
        let mut ctrl = ShardController::new();
        assert_eq!(ctrl.instance_count(), 1);
        assert_eq!(ctrl.rated_throughput_per_sec(), 1_000);

        // Rate at capacity for a long time → never scales, never overloaded.
        let d = ctrl.observe_rate(1_000, ts(0));
        assert!(!d.scaled_out);
        assert!(!ctrl.is_overloaded());
        let d = ctrl.observe_rate(1_000, ts(10_000));
        assert!(!d.scaled_out);
        assert_eq!(ctrl.instance_count(), 1);
    }

    #[test]
    fn controller_does_not_scale_until_overload_sustained_beyond_60s() {
        let mut ctrl = ShardController::new();
        // Overload begins at t=0 (rate 1500 > 1000 capacity).
        let d = ctrl.observe_rate(1_500, ts(0));
        assert!(
            !d.scaled_out,
            "first overload observation only anchors the window"
        );
        assert!(ctrl.is_overloaded());
        assert_eq!(ctrl.overload_since(), Some(ts(0)));

        // Still within the 60 s window: no scale-out.
        let d = ctrl.observe_rate(1_500, ts(30));
        assert!(!d.scaled_out);
        assert_eq!(ctrl.instance_count(), 1);

        // At exactly 60 s the overload is not yet *beyond* the window: no scale-out.
        let d = ctrl.observe_rate(1_500, ts(60));
        assert!(!d.scaled_out);
        assert_eq!(ctrl.instance_count(), 1);

        // Beyond 60 s → scale out to cover 1500 (ceil(1500/1000) = 2 instances).
        let d = ctrl.observe_rate(1_500, ts(61));
        assert!(d.scaled_out);
        assert_eq!(d.instance_count, 2);
        assert_eq!(ctrl.instance_count(), 2);
    }

    #[test]
    fn sub_60s_overload_that_subsides_clears_the_window() {
        let mut ctrl = ShardController::new();
        ctrl.observe_rate(1_500, ts(0)); // overload starts
        assert!(ctrl.is_overloaded());
        // Rate drops back within capacity before 60 s → window cleared, no scaling.
        let d = ctrl.observe_rate(800, ts(30));
        assert!(!d.scaled_out);
        assert!(!ctrl.is_overloaded());
        // A later renewed overload restarts the clock; 40 s of new overload is < 60 s.
        ctrl.observe_rate(1_500, ts(100));
        let d = ctrl.observe_rate(1_500, ts(140));
        assert!(!d.scaled_out);
        assert_eq!(ctrl.instance_count(), 1);
    }

    // --- Once sustained > 60 s it scales to cover the rate --------------------

    #[test]
    fn controller_scales_to_cover_observed_rate() {
        let mut ctrl = ShardController::new();
        // A large sustained rate scales straight to the required instance count.
        ctrl.observe_rate(4_200, ts(0)); // anchor
        let d = ctrl.observe_rate(4_200, ts(61)); // beyond 60 s
        assert!(d.scaled_out);
        // ceil(4200 / 1000) = 5 instances.
        assert_eq!(d.instance_count, 5);
        // Total rated throughput now covers the rate.
        assert!(ctrl.rated_throughput_per_sec() >= 4_200);
        assert_eq!(ctrl.rated_throughput_per_sec(), 5_000);
    }

    #[test]
    fn controller_scales_again_when_rate_keeps_climbing() {
        let mut ctrl = ShardController::new();
        // First overload: scale 1 → 2 to cover 1500.
        ctrl.observe_rate(1_500, ts(0));
        let d = ctrl.observe_rate(1_500, ts(61));
        assert_eq!(d.instance_count, 2);
        assert!(ctrl.rated_throughput_per_sec() >= 1_500);

        // Now 2 instances (2000 capacity). A 2500 rate is a fresh overload.
        let d = ctrl.observe_rate(2_500, ts(100));
        assert!(
            !d.scaled_out,
            "new overload re-anchors at the scale-out time"
        );
        // Sustained beyond 60 s from the re-anchor (t=61) → scale 2 → 3 to cover 2500.
        let d = ctrl.observe_rate(2_500, ts(122));
        assert!(d.scaled_out);
        assert_eq!(d.instance_count, 3);
        assert!(ctrl.rated_throughput_per_sec() >= 2_500);
    }

    #[test]
    fn controller_does_not_shrink_when_rate_drops_after_scaling() {
        let mut ctrl = ShardController::with_instances(3);
        assert_eq!(ctrl.instance_count(), 3);
        // A rate within the 3-instance capacity neither scales out nor shrinks.
        let d = ctrl.observe_rate(2_500, ts(0));
        assert!(!d.scaled_out);
        assert_eq!(ctrl.instance_count(), 3);
    }

    // =====================================================================
    // ZK voter privacy (Requirement 11.7, task 19.2)
    // =====================================================================

    #[test]
    fn vote_tally_rejects_invalid_aggregates() {
        // total_weight must be strictly positive.
        assert_eq!(VoteTally::new(Decimal::ZERO, Decimal::ZERO), None);
        // approve_weight cannot exceed total_weight.
        assert_eq!(VoteTally::new(dec("2"), dec("1")), None);
        // approve_weight cannot be negative.
        assert_eq!(VoteTally::new(dec("-0.1"), dec("1")), None);
        // A valid aggregate is accepted.
        assert!(VoteTally::new(dec("0.7"), dec("1")).is_some());
    }

    #[test]
    fn vote_tally_approval_ratio_is_quotient() {
        let tally = VoteTally::new(dec("3"), dec("4")).unwrap();
        assert_eq!(tally.approval_ratio().value(), dec("0.75"));
    }

    #[test]
    fn public_result_passes_iff_ratio_meets_threshold() {
        let tally = VoteTally::new(dec("7"), dec("10")).unwrap(); // 0.70 approval
        let two_thirds = Ratio::new(dec("0.666666")).unwrap();
        let pass = PublicVoteResult::from_tally(&tally, two_thirds);
        assert!(pass.passed());
        assert_eq!(pass.approval_ratio().value(), dec("0.7"));

        // A stricter threshold fails the same tally.
        let strict = Ratio::new(dec("0.8")).unwrap();
        let fail = PublicVoteResult::from_tally(&tally, strict);
        assert!(!fail.passed());
        // Even a failing result exposes only the aggregate ratio, no ballots.
        assert_eq!(fail.approval_ratio().value(), dec("0.7"));
    }

    #[test]
    fn public_result_exposes_only_aggregate_outcome_not_identities() {
        // Two votes with completely different (private) voter sets but the same
        // aggregate tally produce identical public results — the public view cannot
        // distinguish *who* voted, only the outcome (Requirement 11.7).
        let tally_a = VoteTally::new(dec("6"), dec("9")).unwrap();
        let tally_b = VoteTally::new(dec("2"), dec("3")).unwrap();
        let threshold = Ratio::new(dec("0.5")).unwrap();

        let ra = PublicVoteResult::from_tally(&tally_a, threshold);
        let rb = PublicVoteResult::from_tally(&tally_b, threshold);

        // Same aggregate ratio (2/3) and outcome regardless of the underlying ballots.
        assert_eq!(ra, rb);
        assert!(ra.passed());

        // Structurally, the public result is exactly {passed, approval_ratio}; the
        // `Copy` bound documents it holds no owned identity data (no FayID/Vec).
        fn assert_copy<T: Copy>(_t: &T) {}
        assert_copy(&ra);
    }

    #[test]
    fn public_result_can_be_built_directly_from_aggregate() {
        let r = PublicVoteResult::new(true, Ratio::new(dec("0.9")).unwrap());
        assert!(r.passed());
        assert_eq!(r.approval_ratio().value(), dec("0.9"));
    }
}
