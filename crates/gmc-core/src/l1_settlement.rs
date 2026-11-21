//! `L1_Settlement` — pure-logic model of the Substrate L1 settlement layer.
//!
//! Per the design's *L1/L2 分层架构集成* section, the **L1_Settlement** layer is a
//! Substrate专用链 responsible for settlement & consensus. It stores the protocol's
//! low-frequency, strong-finality state and is the anchoring target for the seams
//! left across the pure-logic modules (registry, mechanism, scoring, minting,
//! retroactive, anti-fraud). This module is the **concrete home** for those seams.
//!
//! ## Why this is a pure-logic abstraction (not a Substrate pallet)
//!
//! `gmc-core` is intentionally dependency-free (task 1.1): it must compile and be
//! testable without any Substrate / FRAME runtime crates so the very same logic can be
//! reused by both the L1 pallet and the L2 rollup. Accordingly this module models
//! **what L1 stores and the anchoring operations it performs** as an in-memory data
//! structure ([`L1Settlement`]) with documented seams. The real Substrate pallet is a
//! thin wrapper: it persists this same record set into on-chain storage, charges no
//! transaction fee (Requirement 13.4), and runs GRANDPA/BABE consensus
//! (Requirement 13.6). Where this module says "model" / "stand-in", the production
//! pallet substitutes the corresponding chain primitive (real cryptographic state
//! root, real storage maps, real consensus engine).
//!
//! ## What L1 stores (Requirement 13.1)
//!
//! [`L1Settlement`] holds, exactly as the requirement enumerates:
//!
//! - **功勋链注册记录** — [`ChainRegistrationRecord`], keyed by [`ChainId`].
//! - **身份注册记录** — [`IdentityRegistrationRecord`], keyed by [`FayID`].
//! - **治理投票结果** — [`VoteResultRecord`], keyed by vote id.
//! - **惩罚记录** — an append-only log of [`PenaltyRecord`].
//! - **状态根** — the current [`StateRoot`] (a model stand-in; see that type).
//!
//! It additionally keeps an append-only [`AnchorEntry`] audit log so every anchoring
//! event (and the state root it produced) is traceable.
//!
//! ## Anchoring operations (锚定)
//!
//! "锚定" = commit a settled fact to L1. Two flavours:
//!
//! 1. **Record-anchoring** — store a record *and* advance the model state root
//!    (because the root commits to all L1 state): [`anchor_chain_creation`] (Req 2.6),
//!    [`anchor_mechanism_change`] (Req 3.8), [`anchor_inflation_index_change`]
//!    (Req 7.7), [`anchor_retroactive_outcome`] (Req 10.7),
//!    [`store_identity_registration`] (Req 13.1), [`record_penalty`] (Req 13.1).
//! 2. **Explicit-root anchoring** — set the state root to a caller-supplied value:
//!    [`anchor_derivation_state_root`] (Req 5.1, the `Chain_Registry` 派生关系状态根)
//!    and [`update_state_root`] (Req 8.6, the L2/ZK post-batch state root).
//!
//! [`anchor_chain_creation`]: L1Settlement::anchor_chain_creation
//! [`anchor_mechanism_change`]: L1Settlement::anchor_mechanism_change
//! [`anchor_inflation_index_change`]: L1Settlement::anchor_inflation_index_change
//! [`anchor_retroactive_outcome`]: L1Settlement::anchor_retroactive_outcome
//! [`store_identity_registration`]: L1Settlement::store_identity_registration
//! [`record_penalty`]: L1Settlement::record_penalty
//! [`anchor_derivation_state_root`]: L1Settlement::anchor_derivation_state_root
//! [`update_state_root`]: L1Settlement::update_state_root
//!
//! ## ZK proof verification guard (task 18.2 — Requirement 13.8)
//!
//! The ZK-proof **verification** guard — verify a batch proof, update the state root to
//! the batch root on success, and reject / retain the previous root on failure — is
//! implemented by [`submit_batch_proof`](L1Settlement::submit_batch_proof). It models a
//! batch proof with [`BatchProof`] and verifies it *above* the unconditional
//! [`update_state_root`](L1Settlement::update_state_root): on success it advances the
//! confirmed root to the batch root; on failure it returns
//! [`GmcError::ProofVerificationFailed`] and leaves the previous confirmed root unchanged
//! (Property 30).

use std::collections::BTreeMap;

use crate::error::{GmcError, GmcResult};
use crate::registry::OriginType;
use crate::types::{ChainId, Decimal, FayID, Timestamp};

/// The L1 consensus configuration (Requirement 13.6).
///
/// The pure-logic core only needs to *record* the chosen consensus; the real consensus
/// engine is the Substrate runtime's responsibility. The single variant documents the
/// protocol decision: Substrate's default GRANDPA (finality) + BABE (block production).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ConsensusConfig {
    /// Substrate's default consensus pairing: **BABE** block production with
    /// **GRANDPA** finality (Requirement 13.6).
    #[default]
    GrandpaBabe,
}

impl ConsensusConfig {
    /// The configured L1 consensus (always [`ConsensusConfig::GrandpaBabe`]).
    pub const L1: ConsensusConfig = ConsensusConfig::GrandpaBabe;

    /// A stable, human-readable label for the consensus pairing.
    pub const fn label(self) -> &'static str {
        match self {
            ConsensusConfig::GrandpaBabe => "GRANDPA/BABE",
        }
    }

    /// `true` if GRANDPA finality is in use (always `true` for the L1 config).
    pub const fn uses_grandpa(self) -> bool {
        matches!(self, ConsensusConfig::GrandpaBabe)
    }

    /// `true` if BABE block production is in use (always `true` for the L1 config).
    pub const fn uses_babe(self) -> bool {
        matches!(self, ConsensusConfig::GrandpaBabe)
    }
}

/// A model of the L1 cryptographic **state root** (Requirement 13.1).
///
/// In the production pallet this is the real Merkle/trie state root committing to all
/// L1 storage. Here it is a 32-byte **stand-in**: anchoring operations advance it via a
/// deterministic (non-cryptographic) mixing function so the surrounding flow — "every
/// settled change moves the root forward, and tests can observe that" — is exercisable
/// without pulling in a hashing/crypto dependency. The byte width matches a typical
/// 256-bit chain state root so the seam is shape-compatible with the real thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateRoot([u8; 32]);

impl StateRoot {
    /// The genesis state root: all zero bytes (no settled state yet).
    pub const GENESIS: StateRoot = StateRoot([0u8; 32]);

    /// Builds a [`StateRoot`] from explicit bytes (e.g. an L2 batch root, Req 8.6/13.8).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        StateRoot(bytes)
    }

    /// Returns the underlying 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Deterministically derives the next model state root from `self`, the new
    /// settlement `version`, and an event `tag`.
    ///
    /// This is a **stand-in**, not a cryptographic hash: it uses an FNV-1a-style mix so
    /// that (a) the result is fully deterministic across the L1 pallet and the L2
    /// rollup, and (b) including the strictly-increasing `version` guarantees the new
    /// root differs from the previous one on every settled change. The production
    /// pallet replaces this with the runtime's real state-root computation.
    fn advanced(self, version: u64, tag: &str) -> StateRoot {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let mut h = FNV_OFFSET;
            h = (h ^ self.0[i] as u64).wrapping_mul(FNV_PRIME);
            h = (h ^ version).wrapping_mul(FNV_PRIME);
            h = (h ^ i as u64).wrapping_mul(FNV_PRIME);
            for &b in tag.as_bytes() {
                h = (h ^ b as u64).wrapping_mul(FNV_PRIME);
            }
            *slot = (h ^ (h >> 32)) as u8;
        }
        StateRoot(out)
    }
}

impl Default for StateRoot {
    fn default() -> Self {
        StateRoot::GENESIS
    }
}

/// A model of an L2 batch's **zero-knowledge proof** submitted to L1 for verification
/// (Requirement 13.8).
///
/// In production this is a real ZK proof (e.g. a SNARK/STARK) that L1's on-chain
/// verifier checks cryptographically: a valid proof attests that applying the batch's
/// transactions to the previous state yields the claimed `batch_root`. `gmc-core` is
/// dependency-free (task 1.1), so this is a **deterministic stand-in** that captures the
/// two things the production verifier decides:
///
/// 1. whether the proof is itself valid ([`valid`](BatchProof::valid)), and
/// 2. which batch state root the proof commits to
///    ([`committed_root`](BatchProof::committed_root)).
///
/// [`verifies`](BatchProof::verifies) returns `true` only when **both** hold for the
/// submitted root: the proof is valid *and* it commits to exactly the `batch_root` being
/// submitted. This mirrors real ZK semantics — a valid proof for a *different* root must
/// not authorise this batch's root. The production pallet replaces this stand-in with the
/// runtime's real proof verifier; the guard behaviour around it ([`submit_batch_proof`])
/// is unchanged.
///
/// [`submit_batch_proof`]: L1Settlement::submit_batch_proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchProof {
    committed_root: StateRoot,
    valid: bool,
}

impl BatchProof {
    /// A proof that **verifies** for `batch_root`: it is valid and commits to that root.
    /// Submitting it via [`submit_batch_proof`](L1Settlement::submit_batch_proof) advances
    /// the confirmed state root to `batch_root`.
    pub const fn valid_for(batch_root: StateRoot) -> Self {
        BatchProof {
            committed_root: batch_root,
            valid: true,
        }
    }

    /// An **invalid** proof committing to `batch_root` (models a proof that fails the
    /// cryptographic check even though it claims `batch_root`). Verification fails and the
    /// previous confirmed root is retained.
    pub const fn invalid_for(batch_root: StateRoot) -> Self {
        BatchProof {
            committed_root: batch_root,
            valid: false,
        }
    }

    /// An **invalid** proof with no meaningful committed root (the genesis placeholder).
    /// Convenience constructor for the common "verification simply fails" test case.
    pub const fn invalid() -> Self {
        BatchProof {
            committed_root: StateRoot::GENESIS,
            valid: false,
        }
    }

    /// The batch state root this proof commits to.
    pub const fn committed_root(&self) -> StateRoot {
        self.committed_root
    }

    /// Whether the underlying proof is (modelled as) cryptographically valid.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// `true` iff this proof verifies for the submitted `batch_root`: it is valid **and**
    /// commits to exactly that root. A valid proof for a different root does not verify.
    pub fn verifies(&self, batch_root: StateRoot) -> bool {
        self.valid && self.committed_root == batch_root
    }
}

/// A merit-chain registration record as stored on L1 (Requirements 13.1, 2.6).
///
/// Mirrors the design's "锚定创建记录（链ID/父链/领域/Steward/发起方式/时间）".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRegistrationRecord {
    /// The newly created chain's id.
    pub chain_id: ChainId,
    /// The parent chain (`None` only for the `GMC_Base` root).
    pub parent_id: Option<ChainId>,
    /// The domain the chain owns.
    pub domain: String,
    /// A representative steward recorded with the creation (the chain carries ≥ 1).
    pub steward: FayID,
    /// How the chain was created (vote / steward / institution).
    pub origin: OriginType,
    /// On-chain creation time.
    pub created_at: Timestamp,
}

impl ChainRegistrationRecord {
    /// Builds a chain registration record from its parts.
    pub fn new(
        chain_id: ChainId,
        parent_id: Option<ChainId>,
        domain: impl Into<String>,
        steward: FayID,
        origin: OriginType,
        created_at: Timestamp,
    ) -> Self {
        ChainRegistrationRecord {
            chain_id,
            parent_id,
            domain: domain.into(),
            steward,
            origin,
            created_at,
        }
    }
}

/// An identity registration record as stored on L1 (Requirement 13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRegistrationRecord {
    /// The registered identity.
    pub fay_id: FayID,
    /// On-chain registration time.
    pub registered_at: Timestamp,
}

impl IdentityRegistrationRecord {
    /// Builds an identity registration record.
    pub fn new(fay_id: FayID, registered_at: Timestamp) -> Self {
        IdentityRegistrationRecord {
            fay_id,
            registered_at,
        }
    }
}

/// A governance vote *result* as stored on L1 (Requirement 13.1).
///
/// L1 stores the **outcome** of a vote (subject, pass/fail, the weighted approval and
/// threshold it was decided against), not the per-voter ballots — voter identities are
/// protected by ZK at L2 (Requirement 11.7). This is the settlement record produced by
/// anchoring a `Governance_Module` tally / a retroactive review outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteResultRecord {
    /// Opaque vote identifier (stringified so any vote-id flavour can be anchored).
    pub vote_id: String,
    /// Opaque subject the vote decided (mechanism change, retro declaration, …).
    pub subject: String,
    /// Whether the vote passed its threshold.
    pub passed: bool,
    /// When the result was anchored.
    pub anchored_at: Timestamp,
}

impl VoteResultRecord {
    /// Builds a vote result record.
    pub fn new(
        vote_id: impl Into<String>,
        subject: impl Into<String>,
        passed: bool,
        anchored_at: Timestamp,
    ) -> Self {
        VoteResultRecord {
            vote_id: vote_id.into(),
            subject: subject.into(),
            passed,
            anchored_at,
        }
    }
}

/// A penalty record as stored on L1 (Requirement 13.1).
///
/// Penalties are append-only: the anti-fraud engine's retroactive penalties
/// (Requirement 11.6) and any governance penalty land here as immutable settlement
/// facts. The model keeps the subject, a free-text reason and the time recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyRecord {
    /// The penalised identity.
    pub subject: FayID,
    /// Human-readable reason / category for the penalty.
    pub reason: String,
    /// When the penalty was recorded.
    pub recorded_at: Timestamp,
}

impl PenaltyRecord {
    /// Builds a penalty record.
    pub fn new(subject: FayID, reason: impl Into<String>, recorded_at: Timestamp) -> Self {
        PenaltyRecord {
            subject,
            reason: reason.into(),
            recorded_at,
        }
    }
}

/// The kind of settled event captured by an [`AnchorEntry`] audit-log row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnchorKind {
    /// A chain creation record was anchored (Requirement 2.6).
    ChainCreation,
    /// An evaluation-mechanism change took effect and was anchored (Requirement 3.8).
    MechanismChange,
    /// An inflation-index change took effect and was anchored (Requirement 7.7).
    InflationIndexChange,
    /// A retroactive review outcome was anchored (Requirement 10.7).
    RetroactiveOutcome,
    /// An identity registration was stored (Requirement 13.1).
    IdentityRegistration,
    /// A penalty was recorded (Requirement 13.1 / 11.6).
    Penalty,
    /// The `Chain_Registry` derivation-relationship state root was anchored (Req 5.1).
    DerivationStateRoot,
    /// An explicit state root (e.g. an L2/ZK post-batch root) was anchored (Req 8.6).
    StateRootUpdate,
    /// A submitted batch ZK proof **failed** verification and was rejected; the batch
    /// state update was refused and the previous confirmed root retained (Req 13.8).
    /// Recorded for audit only — it advances neither the version nor the state root.
    BatchProofRejected,
}

impl AnchorKind {
    /// A short, stable tag mixed into the model state root and useful for logging.
    pub const fn tag(self) -> &'static str {
        match self {
            AnchorKind::ChainCreation => "chain-creation",
            AnchorKind::MechanismChange => "mechanism-change",
            AnchorKind::InflationIndexChange => "inflation-index-change",
            AnchorKind::RetroactiveOutcome => "retroactive-outcome",
            AnchorKind::IdentityRegistration => "identity-registration",
            AnchorKind::Penalty => "penalty",
            AnchorKind::DerivationStateRoot => "derivation-state-root",
            AnchorKind::StateRootUpdate => "state-root-update",
            AnchorKind::BatchProofRejected => "batch-proof-rejected",
        }
    }
}

/// An append-only audit-log row recording one anchoring event and its resulting root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEntry {
    /// What kind of event was anchored.
    pub kind: AnchorKind,
    /// The chain the event pertains to, if any.
    pub chain_id: Option<ChainId>,
    /// The settlement version after this event (monotonically increasing).
    pub version: u64,
    /// The state root produced by this event.
    pub resulting_root: StateRoot,
}

/// In-memory model of the Substrate L1 settlement layer.
///
/// See the module docs for the full picture. Construct with [`L1Settlement::new`]
/// (genesis state root, empty stores), then anchor records / state roots as the
/// pure-logic modules complete settled actions. Every mutating operation advances the
/// settlement [`version`](L1Settlement::version) and appends an [`AnchorEntry`].
#[derive(Debug, Clone)]
pub struct L1Settlement {
    chain_registrations: BTreeMap<ChainId, ChainRegistrationRecord>,
    identity_registrations: BTreeMap<FayID, IdentityRegistrationRecord>,
    vote_results: BTreeMap<String, VoteResultRecord>,
    penalties: Vec<PenaltyRecord>,
    anchor_log: Vec<AnchorEntry>,
    state_root: StateRoot,
    version: u64,
    consensus: ConsensusConfig,
}

impl Default for L1Settlement {
    fn default() -> Self {
        L1Settlement::new()
    }
}

impl L1Settlement {
    /// The transaction fee L1 charges per on-chain transaction: **zero**
    /// (Requirement 13.4). L1_Settlement is configured fee-free.
    pub const TRANSACTION_FEE: Decimal = Decimal::ZERO;

    /// Creates an empty L1 settlement model at the genesis state root, configured
    /// fee-free (Req 13.4) with GRANDPA/BABE consensus (Req 13.6).
    pub fn new() -> Self {
        L1Settlement {
            chain_registrations: BTreeMap::new(),
            identity_registrations: BTreeMap::new(),
            vote_results: BTreeMap::new(),
            penalties: Vec::new(),
            anchor_log: Vec::new(),
            state_root: StateRoot::GENESIS,
            version: 0,
            consensus: ConsensusConfig::L1,
        }
    }

    // --- Configuration markers (Requirements 13.4, 13.6) -------------------

    /// The per-transaction fee charged by L1: always zero (Requirement 13.4).
    pub const fn transaction_fee(&self) -> Decimal {
        L1Settlement::TRANSACTION_FEE
    }

    /// `true` — L1 never charges a transaction fee (Requirement 13.4).
    pub fn is_fee_free(&self) -> bool {
        self.transaction_fee().is_zero()
    }

    /// The L1 consensus configuration: GRANDPA/BABE (Requirement 13.6).
    pub const fn consensus_config(&self) -> ConsensusConfig {
        self.consensus
    }

    // --- Read accessors over stored L1 state (Requirement 13.1) ------------

    /// The current confirmed state root.
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// The number of settled state transitions applied so far (genesis = 0).
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Looks up a stored chain registration record by id.
    pub fn chain_registration(&self, chain_id: &ChainId) -> Option<&ChainRegistrationRecord> {
        self.chain_registrations.get(chain_id)
    }

    /// Number of stored chain registration records.
    pub fn chain_registration_count(&self) -> usize {
        self.chain_registrations.len()
    }

    /// Looks up a stored identity registration record by id.
    pub fn identity_registration(&self, fay_id: &FayID) -> Option<&IdentityRegistrationRecord> {
        self.identity_registrations.get(fay_id)
    }

    /// Looks up a stored governance vote result by vote id.
    pub fn vote_result(&self, vote_id: &str) -> Option<&VoteResultRecord> {
        self.vote_results.get(vote_id)
    }

    /// All recorded penalties, in the order they were recorded (append-only).
    pub fn penalties(&self) -> &[PenaltyRecord] {
        &self.penalties
    }

    /// The append-only anchoring audit log.
    pub fn anchor_log(&self) -> &[AnchorEntry] {
        &self.anchor_log
    }

    /// Ordered iterator over all stored chain registration records.
    pub fn chain_registrations(
        &self,
    ) -> impl Iterator<Item = (&ChainId, &ChainRegistrationRecord)> {
        self.chain_registrations.iter()
    }

    /// Ordered iterator over all stored identity registration records.
    pub fn identity_registrations(
        &self,
    ) -> impl Iterator<Item = (&FayID, &IdentityRegistrationRecord)> {
        self.identity_registrations.iter()
    }

    /// Ordered iterator over all stored governance vote results.
    pub fn vote_results(&self) -> impl Iterator<Item = (&String, &VoteResultRecord)> {
        self.vote_results.iter()
    }

    /// Restores an [`L1Settlement`] instance from persisted deterministic state.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts(
        chain_registrations: BTreeMap<ChainId, ChainRegistrationRecord>,
        identity_registrations: BTreeMap<FayID, IdentityRegistrationRecord>,
        vote_results: BTreeMap<String, VoteResultRecord>,
        penalties: Vec<PenaltyRecord>,
        anchor_log: Vec<AnchorEntry>,
        state_root: StateRoot,
        version: u64,
    ) -> Self {
        L1Settlement {
            chain_registrations,
            identity_registrations,
            vote_results,
            penalties,
            anchor_log,
            state_root,
            version,
            consensus: ConsensusConfig::L1,
        }
    }

    // --- Record-anchoring operations ---------------------------------------

    /// Anchors a chain-creation record to L1 and advances the state root
    /// (_Requirement 2.6_). This is the concrete home for `Chain_Registry::derive`'s
    /// "anchor creation record" seam.
    ///
    /// Stores the record under its chain id and returns the new state root.
    pub fn anchor_chain_creation(&mut self, record: ChainRegistrationRecord) -> StateRoot {
        let chain_id = record.chain_id.clone();
        self.chain_registrations.insert(chain_id.clone(), record);
        self.advance(AnchorKind::ChainCreation, Some(chain_id))
    }

    /// Anchors an effective evaluation-mechanism change for `chain_id`
    /// (_Requirement 3.8_) and advances the state root. The concrete home for the
    /// `mechanism` module's `MechanismChangeReceipt` anchoring seam.
    pub fn anchor_mechanism_change(&mut self, chain_id: ChainId) -> StateRoot {
        self.advance(AnchorKind::MechanismChange, Some(chain_id))
    }

    /// Anchors an effective inflation-index change for `chain_id` (_Requirement 7.7_)
    /// and advances the state root. The concrete home for the `scoring` module's
    /// inflation-index anchoring seam.
    pub fn anchor_inflation_index_change(&mut self, chain_id: ChainId) -> StateRoot {
        self.advance(AnchorKind::InflationIndexChange, Some(chain_id))
    }

    /// Anchors a retroactive review outcome to L1 (_Requirement 10.7_) and advances the
    /// state root. Stores the associated vote result so the outcome is queryable. The
    /// concrete home for `Retroactive_Review_Module::anchor_outcome`.
    pub fn anchor_retroactive_outcome(&mut self, result: VoteResultRecord) -> StateRoot {
        self.vote_results.insert(result.vote_id.clone(), result);
        self.advance(AnchorKind::RetroactiveOutcome, None)
    }

    /// Stores an identity registration record (_Requirement 13.1_) and advances the
    /// state root.
    pub fn store_identity_registration(&mut self, record: IdentityRegistrationRecord) -> StateRoot {
        self.identity_registrations
            .insert(record.fay_id.clone(), record);
        self.advance(AnchorKind::IdentityRegistration, None)
    }

    /// Stores a governance vote result (_Requirement 13.1_) and advances the state
    /// root. Used to anchor any `Governance_Module` tally outcome to L1.
    pub fn store_vote_result(&mut self, result: VoteResultRecord) -> StateRoot {
        self.vote_results.insert(result.vote_id.clone(), result);
        self.advance(AnchorKind::RetroactiveOutcome, None)
    }

    /// Appends a penalty record (_Requirement 13.1_; anti-fraud retroactive penalties,
    /// Requirement 11.6) and advances the state root.
    pub fn record_penalty(&mut self, record: PenaltyRecord) -> StateRoot {
        self.penalties.push(record);
        self.advance(AnchorKind::Penalty, None)
    }

    // --- Explicit-root anchoring operations --------------------------------

    /// Anchors the `Chain_Registry` derivation-relationship state root
    /// (_Requirement 5.1_): sets the confirmed state root to the supplied value.
    ///
    /// Returns the (now confirmed) root.
    pub fn anchor_derivation_state_root(&mut self, root: StateRoot) -> StateRoot {
        self.set_root(root, AnchorKind::DerivationStateRoot)
    }

    /// Updates the confirmed state root to an explicit value (_Requirement 8.6_): the
    /// L2/ZK post-batch root anchored after a successful batch.
    ///
    /// Returns the (now confirmed) root.
    ///
    /// ## Task 18.2 seam (ZK proof verification, Requirement 13.8)
    ///
    /// This method performs **no** proof verification — it unconditionally sets the
    /// root. The verification guard lives in
    /// [`submit_batch_proof`](L1Settlement::submit_batch_proof), which verifies a
    /// [`BatchProof`] first and only calls `update_state_root(batch_root)` on success.
    /// Callers settling a *verified* L2 batch should prefer `submit_batch_proof`.
    pub fn update_state_root(&mut self, root: StateRoot) -> StateRoot {
        self.set_root(root, AnchorKind::StateRootUpdate)
    }

    /// Verifies an L2 batch ZK proof and, on success, settles the batch by advancing the
    /// confirmed state root to `batch_root` (_Requirement 13.8_, _Property 30_).
    ///
    /// This is the L1 verification guard around [`update_state_root`]:
    ///
    /// - **Proof verifies** (`proof.verifies(batch_root)`): the batch is accepted. The
    ///   confirmed state root is updated to `batch_root` via [`update_state_root`] (which
    ///   bumps the version and appends a [`AnchorKind::StateRootUpdate`] audit entry), and
    ///   the new confirmed root is returned as `Ok(batch_root)`.
    /// - **Proof fails verification**: the batch is **rejected**. The confirmed state root
    ///   is left **exactly as before** (the previous confirmed root is retained) and the
    ///   version is unchanged; a non-advancing [`AnchorKind::BatchProofRejected`] audit
    ///   entry is appended so the rejection is traceable, and
    ///   [`GmcError::ProofVerificationFailed`] is returned.
    ///
    /// The essential invariant (Property 30): the confirmed state root changes **only**
    /// when the proof verifies; a failed proof leaves `state_root()` and `version()`
    /// exactly as they were.
    ///
    /// In production the deterministic [`BatchProof`] stand-in is replaced by the
    /// runtime's real ZK verifier; this guard's accept/reject behaviour is unchanged.
    ///
    /// [`update_state_root`]: L1Settlement::update_state_root
    pub fn submit_batch_proof(
        &mut self,
        batch_root: StateRoot,
        proof: BatchProof,
    ) -> GmcResult<StateRoot> {
        if proof.verifies(batch_root) {
            Ok(self.update_state_root(batch_root))
        } else {
            // Reject: retain the previous confirmed root, do not bump the version, and
            // record a non-advancing audit entry referencing the retained root.
            self.anchor_log.push(AnchorEntry {
                kind: AnchorKind::BatchProofRejected,
                chain_id: None,
                version: self.version,
                resulting_root: self.state_root,
            });
            Err(GmcError::ProofVerificationFailed)
        }
    }

    // --- Internal state-root transitions -----------------------------------

    /// Advances the model state root for a record-anchoring event: bumps the version,
    /// derives the next model root, and appends an [`AnchorEntry`].
    fn advance(&mut self, kind: AnchorKind, chain_id: Option<ChainId>) -> StateRoot {
        self.version += 1;
        self.state_root = self.state_root.advanced(self.version, kind.tag());
        self.anchor_log.push(AnchorEntry {
            kind,
            chain_id,
            version: self.version,
            resulting_root: self.state_root,
        });
        self.state_root
    }

    /// Sets the confirmed state root to an explicit value: bumps the version and
    /// appends an [`AnchorEntry`].
    fn set_root(&mut self, root: StateRoot, kind: AnchorKind) -> StateRoot {
        self.version += 1;
        self.state_root = root;
        self.anchor_log.push(AnchorEntry {
            kind,
            chain_id: None,
            version: self.version,
            resulting_root: self.state_root,
        });
        self.state_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn chain_record(id: &str) -> ChainRegistrationRecord {
        ChainRegistrationRecord::new(
            ChainId::new(id),
            Some(ChainId::new("gmc-base")),
            "academic",
            FayID::new("steward-1"),
            OriginType::StewardInitiated,
            ts(1_000),
        )
    }

    // --- Requirement 13.1: chain registration storage + anchoring (2.6) -----

    #[test]
    fn anchor_chain_creation_stores_record_and_advances_root() {
        let mut l1 = L1Settlement::new();
        let before = l1.state_root();
        assert_eq!(before, StateRoot::GENESIS);

        let new_root = l1.anchor_chain_creation(chain_record("academic-chain"));

        // The record is stored and retrievable.
        let stored = l1
            .chain_registration(&ChainId::new("academic-chain"))
            .expect("anchored chain record is retrievable");
        assert_eq!(stored.domain, "academic");
        assert_eq!(stored.parent_id, Some(ChainId::new("gmc-base")));
        assert_eq!(stored.origin, OriginType::StewardInitiated);
        assert_eq!(l1.chain_registration_count(), 1);

        // The state root advanced (Requirement 2.6 anchoring updates settled state).
        assert_ne!(new_root, before);
        assert_eq!(l1.state_root(), new_root);
        assert_eq!(l1.version(), 1);

        // The anchoring event is in the audit log.
        let entry = l1.anchor_log().last().unwrap();
        assert_eq!(entry.kind, AnchorKind::ChainCreation);
        assert_eq!(entry.chain_id, Some(ChainId::new("academic-chain")));
        assert_eq!(entry.resulting_root, new_root);
    }

    // --- Requirement 13.1: identity registration storage -------------------

    #[test]
    fn store_identity_registration_is_retrievable() {
        let mut l1 = L1Settlement::new();
        l1.store_identity_registration(IdentityRegistrationRecord::new(
            FayID::new("fay-1"),
            ts(2_000),
        ));

        let stored = l1
            .identity_registration(&FayID::new("fay-1"))
            .expect("identity registration is retrievable");
        assert_eq!(stored.registered_at, ts(2_000));
        assert_eq!(l1.version(), 1);
    }

    // --- Requirement 13.1: governance vote result storage ------------------

    #[test]
    fn store_vote_result_is_retrievable() {
        let mut l1 = L1Settlement::new();
        l1.store_vote_result(VoteResultRecord::new(
            "vote-7",
            "mechanism-change:academic-chain",
            true,
            ts(3_000),
        ));

        let stored = l1
            .vote_result("vote-7")
            .expect("vote result is retrievable");
        assert!(stored.passed);
        assert_eq!(stored.subject, "mechanism-change:academic-chain");
    }

    // --- Requirement 13.1 / 11.6: penalty record ---------------------------

    #[test]
    fn record_penalty_appends_to_penalty_log() {
        let mut l1 = L1Settlement::new();
        assert!(l1.penalties().is_empty());

        l1.record_penalty(PenaltyRecord::new(
            FayID::new("fay-cheater"),
            "collusion-clawback",
            ts(4_000),
        ));

        assert_eq!(l1.penalties().len(), 1);
        assert_eq!(l1.penalties()[0].subject, FayID::new("fay-cheater"));
        assert_eq!(l1.penalties()[0].reason, "collusion-clawback");
    }

    // --- Requirement 8.6 / 5.1: state-root updates --------------------------

    #[test]
    fn update_state_root_sets_explicit_root() {
        let mut l1 = L1Settlement::new();
        let batch_root = StateRoot::from_bytes([7u8; 32]);

        let confirmed = l1.update_state_root(batch_root);

        assert_eq!(confirmed, batch_root);
        assert_eq!(l1.state_root(), batch_root);
        assert_eq!(l1.version(), 1);
        assert_eq!(
            l1.anchor_log().last().unwrap().kind,
            AnchorKind::StateRootUpdate
        );
    }

    #[test]
    fn anchor_derivation_state_root_sets_explicit_root() {
        let mut l1 = L1Settlement::new();
        let derivation_root = StateRoot::from_bytes([42u8; 32]);

        let confirmed = l1.anchor_derivation_state_root(derivation_root);

        assert_eq!(confirmed, derivation_root);
        assert_eq!(l1.state_root(), derivation_root);
        assert_eq!(
            l1.anchor_log().last().unwrap().kind,
            AnchorKind::DerivationStateRoot
        );
    }

    // --- Requirement 13.8 / Property 30: ZK batch-proof verification guard --

    #[test]
    fn valid_batch_proof_advances_confirmed_root_to_batch_root() {
        let mut l1 = L1Settlement::new();
        let before_root = l1.state_root();
        let before_version = l1.version();
        let batch_root = StateRoot::from_bytes([9u8; 32]);

        let confirmed = l1
            .submit_batch_proof(batch_root, BatchProof::valid_for(batch_root))
            .expect("a valid proof for the batch root verifies");

        // The confirmed root advanced to the batch root and the version moved forward.
        assert_eq!(confirmed, batch_root);
        assert_eq!(l1.state_root(), batch_root);
        assert_ne!(l1.state_root(), before_root);
        assert_eq!(l1.version(), before_version + 1);

        // The successful settlement is recorded as a state-root update.
        assert_eq!(
            l1.anchor_log().last().unwrap().kind,
            AnchorKind::StateRootUpdate
        );
    }

    #[test]
    fn invalid_batch_proof_is_rejected_and_retains_previous_root() {
        let mut l1 = L1Settlement::new();

        // Establish a non-genesis confirmed root via a first, valid batch.
        let confirmed_root = StateRoot::from_bytes([1u8; 32]);
        l1.submit_batch_proof(confirmed_root, BatchProof::valid_for(confirmed_root))
            .expect("first valid batch settles");
        let version_after_valid = l1.version();

        // A second batch arrives with an invalid proof.
        let rejected_root = StateRoot::from_bytes([2u8; 32]);
        let err = l1
            .submit_batch_proof(rejected_root, BatchProof::invalid_for(rejected_root))
            .expect_err("an invalid proof must be rejected");

        // The error is ProofVerificationFailed.
        assert_eq!(err, GmcError::ProofVerificationFailed);

        // The previous confirmed root is retained, unchanged; version does not advance.
        assert_eq!(l1.state_root(), confirmed_root);
        assert_ne!(l1.state_root(), rejected_root);
        assert_eq!(l1.version(), version_after_valid);

        // The rejection is traceable but did not advance state: the audit entry points
        // at the retained root and the unchanged version.
        let last = l1.anchor_log().last().unwrap();
        assert_eq!(last.kind, AnchorKind::BatchProofRejected);
        assert_eq!(last.resulting_root, confirmed_root);
        assert_eq!(last.version, version_after_valid);
    }

    #[test]
    fn valid_proof_committing_to_different_root_does_not_verify() {
        let mut l1 = L1Settlement::new();
        let batch_root = StateRoot::from_bytes([5u8; 32]);
        let other_root = StateRoot::from_bytes([6u8; 32]);

        // A proof that is "valid" but commits to a *different* root must not authorise
        // settling `batch_root` (mirrors real ZK semantics).
        let err = l1
            .submit_batch_proof(batch_root, BatchProof::valid_for(other_root))
            .expect_err("a proof for a different root must not verify this batch");

        assert_eq!(err, GmcError::ProofVerificationFailed);
        assert_eq!(l1.state_root(), StateRoot::GENESIS);
        assert_eq!(l1.version(), 0);
    }

    #[test]
    fn mixed_proof_sequence_only_advances_on_valid_submissions() {
        let mut l1 = L1Settlement::new();

        let r1 = StateRoot::from_bytes([10u8; 32]);
        let r2 = StateRoot::from_bytes([20u8; 32]);
        let r3 = StateRoot::from_bytes([30u8; 32]);

        // valid -> advances to r1
        assert_eq!(
            l1.submit_batch_proof(r1, BatchProof::valid_for(r1))
                .unwrap(),
            r1
        );
        assert_eq!(l1.state_root(), r1);
        assert_eq!(l1.version(), 1);

        // invalid -> rejected, root and version retained at r1 / 1
        assert_eq!(
            l1.submit_batch_proof(r2, BatchProof::invalid())
                .unwrap_err(),
            GmcError::ProofVerificationFailed
        );
        assert_eq!(l1.state_root(), r1, "failed proof retains the prior root");
        assert_eq!(l1.version(), 1, "failed proof does not advance the version");

        // valid -> advances to r3 (only the verified batches move the root)
        assert_eq!(
            l1.submit_batch_proof(r3, BatchProof::valid_for(r3))
                .unwrap(),
            r3
        );
        assert_eq!(l1.state_root(), r3);
        assert_eq!(l1.version(), 2);

        // The confirmed root only ever equalled the roots of the verified batches.
        assert_ne!(l1.state_root(), r2);
    }

    // --- Requirements 3.8 / 7.7 / 10.7: change & outcome anchoring ----------

    #[test]
    fn mechanism_inflation_and_retro_anchors_advance_distinct_roots() {
        let mut l1 = L1Settlement::new();
        let r0 = l1.state_root();

        let r1 = l1.anchor_mechanism_change(ChainId::new("academic-chain"));
        let r2 = l1.anchor_inflation_index_change(ChainId::new("academic-chain"));
        let r3 = l1.anchor_retroactive_outcome(VoteResultRecord::new(
            "retro-1",
            "retro:carbon-chain",
            false,
            ts(5_000),
        ));

        // Every anchoring advanced the root to a fresh value.
        let roots = [r0, r1, r2, r3];
        for (i, a) in roots.iter().enumerate() {
            for b in roots.iter().skip(i + 1) {
                assert_ne!(a, b, "each settled change must move the state root");
            }
        }
        assert_eq!(l1.version(), 3);

        // The retro outcome's vote result is stored.
        assert!(!l1.vote_result("retro-1").unwrap().passed);

        // The audit log records the kinds in order.
        let kinds: Vec<AnchorKind> = l1.anchor_log().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                AnchorKind::MechanismChange,
                AnchorKind::InflationIndexChange,
                AnchorKind::RetroactiveOutcome,
            ]
        );
    }

    // --- Requirement 13.4: fee-free -----------------------------------------

    #[test]
    fn transaction_fee_is_zero() {
        let l1 = L1Settlement::new();
        assert_eq!(l1.transaction_fee(), Decimal::ZERO);
        assert!(l1.transaction_fee().is_zero());
        assert!(l1.is_fee_free());
        assert_eq!(L1Settlement::TRANSACTION_FEE, Decimal::ZERO);
    }

    // --- Requirement 13.6: GRANDPA/BABE consensus ---------------------------

    #[test]
    fn consensus_config_is_grandpa_babe() {
        let l1 = L1Settlement::new();
        assert_eq!(l1.consensus_config(), ConsensusConfig::GrandpaBabe);
        assert_eq!(l1.consensus_config().label(), "GRANDPA/BABE");
        assert!(l1.consensus_config().uses_grandpa());
        assert!(l1.consensus_config().uses_babe());
    }

    // --- State-root model determinism ---------------------------------------

    #[test]
    fn state_root_advance_is_deterministic_across_instances() {
        let mut a = L1Settlement::new();
        let mut b = L1Settlement::new();
        a.anchor_chain_creation(chain_record("c1"));
        b.anchor_chain_creation(chain_record("c1"));
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(a.version(), b.version());
    }

    #[test]
    fn genesis_state_root_is_zero_and_default_matches_new() {
        let l1 = L1Settlement::default();
        assert_eq!(l1.state_root(), StateRoot::GENESIS);
        assert_eq!(l1.state_root().as_bytes(), &[0u8; 32]);
        assert_eq!(l1.version(), 0);
    }
}
