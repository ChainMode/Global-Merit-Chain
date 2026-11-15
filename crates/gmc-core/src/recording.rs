//! `Recording_Service` — contribution recording and registration matching.
//!
//! This module implements task 11.2: recording a concrete contribution behaviour
//! *after* a merit has been registered, and wiring the evaluation-result mark back
//! onto the stored record. It realises the design's `Recording_Service` interface
//! (`record` / `markEvaluationResult`) and the standard-flow state machine
//! `Registered → Recorded → Evaluating → Passed | Failed`.
//!
//! ## Requirements covered by task 11.2
//!
//! - **Requirement 9.3**: when a contribution is submitted *and* a matching **valid**
//!   registration exists (same `contributorId`, same `chainId`, registration status
//!   `Valid`), a [`ContributionRecord`] is created and **linked** to that
//!   registration (its [`ContributionRecord::registration_id`] is `Some`). The new
//!   record starts in [`EvaluationStatus::Pending`].
//! - **Requirement 9.4**: when no matching valid registration exists **and** the
//!   request is not flowing through the retroactive-declaration path, the record is
//!   rejected with [`GmcError::NotRegistered`] and nothing is written.
//! - **Requirement 9.6**: [`RecordingService::mark_evaluation_result`] with
//!   `passed = false` **retains** the record and marks it
//!   [`EvaluationStatus::Failed`] ("认定未通过"); it mints nothing. (Minting itself
//!   is owned by `Minting_Service`; this module only records the verdict.)
//!
//! ## Decoupling from `Registration_Service` (the `RegistrationLookup` seam)
//!
//! Whether a "matching valid registration exists" is a fact owned by the
//! `Registration_Service` (`src/registration.rs`, task 11.1). To keep this module
//! independently compilable and free of a cross-module dependency on a concurrently
//! authored file, `Recording_Service` does **not** import the concrete registration
//! types. Instead it depends on the [`RegistrationLookup`] **trait defined here**,
//! which it owns. The integration task (20.1) implements [`RegistrationLookup`] over
//! the real `RegistrationService` (its `findValidRegistration`) and passes it in.
//!
//! The trait's primary method returns the *id* of a matching valid registration
//! ([`RegistrationLookup::find_valid_registration`]) so the new record can be linked
//! to it (Requirement 9.3); the boolean convenience
//! [`RegistrationLookup::has_valid_registration`] is provided as a default on top.
//!
//! ## Retroactive path (Requirement 9.4, delegated to task 15.x)
//!
//! When `is_retroactive` is `true`, a missing registration is **not** an error: the
//! retroactive-declaration flow (`Retroactive_Review_Module`, task 15.x) is the
//! authority for such records, and the contribution record it produces is **not**
//! linked to a registration (its `registration_id` is `None`, matching the design
//! data model `registrationId: string | null`). Here we only allow such a record to
//! be created; the stricter retroactive evidence checks and voting live in task 15.x.
//!
//! ## L2 rollup batch seam (Requirement 9.7, task 19.1)
//!
//! Per the design, `Recording_Service` runs on L2 and submits a batched
//! zero-knowledge proof of recorded contributions to L1 (`submitRollupBatch`). That
//! ZK/L2 machinery is **not** implemented in this pure-logic core; it is wired by the
//! L2 integration task (19.1). The records stored here are the input that batching
//! will later consume — see [`RecordingService::iter`].

use std::collections::BTreeMap;

use crate::error::{GmcError, GmcResult};
use crate::types::{ChainId, DimensionWeights, FayID, Timestamp};

/// Opaque identifier of a stored [`ContributionRecord`].
///
/// Allocated by [`RecordingService`] when a record is created; callers use it to
/// later mark the evaluation verdict via [`RecordingService::mark_evaluation_result`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContributionId(String);

impl ContributionId {
    /// Builds a [`ContributionId`] from any string-like value.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        ContributionId(id.into())
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ContributionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Evaluation lifecycle state of a [`ContributionRecord`] (design `evaluationStatus`).
///
/// A freshly recorded contribution is [`Pending`](EvaluationStatus::Pending). Once the
/// chain's `Evaluation_Mechanism` reaches a verdict, the record transitions to
/// [`Passed`](EvaluationStatus::Passed) (the gate that lets `Minting_Service` mint,
/// task 11.3) or [`Failed`](EvaluationStatus::Failed) ("认定未通过", Requirement 9.6 —
/// the record is retained and nothing is minted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationStatus {
    /// Recorded but not yet evaluated.
    Pending,
    /// Passed the chain's `Evaluation_Mechanism` (Requirement 9.5; mint gate).
    Passed,
    /// Did not pass the chain's `Evaluation_Mechanism` (Requirement 9.6).
    Failed,
}

/// A minimal off-chain evidence reference (CID/hash) carried by a contribution record.
///
/// The design's full `EvidenceRef` (with replayability semantics used by the
/// retroactive-review module) is owned by task 15.x; this module needs only a
/// lightweight, self-contained reference so a recorded contribution can carry its
/// supporting evidence pointers without coupling to that module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    uri: String,
    hash: String,
}

impl EvidenceRef {
    /// Builds an evidence reference from its on-/off-chain locator and content hash.
    pub fn new(uri: impl Into<String>, hash: impl Into<String>) -> Self {
        EvidenceRef {
            uri: uri.into(),
            hash: hash.into(),
        }
    }

    /// The locator (on-chain reference, or external CID/URL).
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The content hash used for replayability/verification.
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

/// A recorded contribution behaviour (design data model `ContributionRecord`).
///
/// Created by [`RecordingService::record`]. Fields are private with read-only
/// accessors so the verdict can only move through the controlled
/// [`RecordingService::mark_evaluation_result`] entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionRecord {
    id: ContributionId,
    /// The linked valid registration's id (Requirement 9.3), or `None` for a record
    /// produced via the retroactive-declaration path (Requirement 9.4 / task 15.x).
    registration_id: Option<String>,
    contributor_id: FayID,
    chain_id: ChainId,
    evidence_refs: Vec<EvidenceRef>,
    /// Three-dimensional weights (design `dimensionWeights`); optional at this stage —
    /// the `Scoring_Engine` (task 8.x) populates it before minting.
    dimension_weights: Option<DimensionWeights>,
    evaluation_status: EvaluationStatus,
    recorded_at: Timestamp,
}

impl ContributionRecord {
    /// This record's identifier.
    pub fn id(&self) -> &ContributionId {
        &self.id
    }

    /// The linked registration id, or `None` for a retroactive (unlinked) record.
    pub fn registration_id(&self) -> Option<&str> {
        self.registration_id.as_deref()
    }

    /// `true` if this record is linked to a valid registration (standard flow);
    /// `false` if it was produced through the retroactive path.
    pub fn is_linked(&self) -> bool {
        self.registration_id.is_some()
    }

    /// The contributor this record belongs to.
    pub fn contributor_id(&self) -> &FayID {
        &self.contributor_id
    }

    /// The merit chain this contribution was recorded against.
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// The off-chain evidence references supporting this contribution.
    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }

    /// The three-dimensional weights, if scoring has been attached yet.
    pub fn dimension_weights(&self) -> Option<&DimensionWeights> {
        self.dimension_weights.as_ref()
    }

    /// Current evaluation status.
    pub fn evaluation_status(&self) -> EvaluationStatus {
        self.evaluation_status
    }

    /// On-chain time the contribution was recorded.
    pub fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }
}

/// Input to [`RecordingService::record`] — a request to record a contribution.
///
/// The `registration_id` link (Requirement 9.3) is **not** supplied by the caller: it
/// is resolved by `record` through the [`RegistrationLookup`] so a record can never be
/// linked to a non-existent or non-valid registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionRequest {
    /// The contributor submitting the contribution (matched against a registration).
    pub contributor_id: FayID,
    /// The merit chain the contribution belongs to (matched against a registration).
    pub chain_id: ChainId,
    /// Off-chain evidence references (CID/hash) supporting the contribution.
    pub evidence_refs: Vec<EvidenceRef>,
    /// On-chain time the contribution is being recorded.
    pub recorded_at: Timestamp,
}

impl ContributionRequest {
    /// Builds a [`ContributionRequest`] from its parts.
    pub fn new(
        contributor_id: FayID,
        chain_id: ChainId,
        evidence_refs: Vec<EvidenceRef>,
        recorded_at: Timestamp,
    ) -> Self {
        ContributionRequest {
            contributor_id,
            chain_id,
            evidence_refs,
            recorded_at,
        }
    }
}

/// Abstraction over the `Registration_Service`'s "valid registration" lookup.
///
/// `Recording_Service` owns this trait so it does **not** depend on the concrete
/// registration module (`src/registration.rs`, task 11.1, authored concurrently). The
/// integration task (20.1) implements this trait over the real `RegistrationService`
/// (delegating to its `findValidRegistration`).
///
/// A "matching valid registration" is one whose contributor id and chain id match the
/// request and whose status is `Valid` (Requirement 9.3).
pub trait RegistrationLookup {
    /// Returns the id of a matching **valid** registration for
    /// `(contributor_id, chain_id)`, or `None` if none exists.
    ///
    /// The returned id is what [`RecordingService::record`] links the new
    /// [`ContributionRecord`] to (Requirement 9.3).
    fn find_valid_registration(&self, contributor_id: &FayID, chain_id: &ChainId)
        -> Option<String>;

    /// Convenience predicate: whether a matching valid registration exists.
    ///
    /// Defaults to `find_valid_registration(...).is_some()`; implementors normally only
    /// need to implement [`find_valid_registration`](RegistrationLookup::find_valid_registration).
    fn has_valid_registration(&self, contributor_id: &FayID, chain_id: &ChainId) -> bool {
        self.find_valid_registration(contributor_id, chain_id)
            .is_some()
    }
}

/// The contribution-recording service (design `Recording_Service`).
///
/// Stores [`ContributionRecord`]s keyed by their [`ContributionId`] and allocates ids
/// deterministically (`contrib-<n>`). All mutating entry points are **atomic**:
/// validation runs before any write, so a rejected request leaves the store unchanged
/// (the design's "validate up front, fail atomically, state unchanged" principle).
///
/// > **L2 rollup seam (Requirement 9.7, task 19.1):** the stored records are the input
/// > a future L2 batch-proof submission (`submitRollupBatch`) consumes. That ZK/L2
/// > machinery is not implemented here; iterate via [`RecordingService::iter`].
#[derive(Debug, Clone, Default)]
pub struct RecordingService {
    /// Stored contribution records keyed by id (`BTreeMap` for deterministic order).
    records: BTreeMap<ContributionId, ContributionRecord>,
    /// Monotonic sequence used to allocate fresh [`ContributionId`]s.
    next_seq: u64,
}

impl RecordingService {
    /// Creates an empty recording service.
    pub fn new() -> Self {
        RecordingService {
            records: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Records a contribution, enforcing the registration-matching rule.
    ///
    /// Behaviour (Requirements 9.3, 9.4):
    ///
    /// - If a matching **valid** registration exists
    ///   ([`RegistrationLookup::find_valid_registration`] returns `Some(id)`), a new
    ///   [`ContributionRecord`] is created **linked** to that registration
    ///   (`registration_id = Some(id)`) with status [`EvaluationStatus::Pending`], and
    ///   its [`ContributionId`] is returned (Requirement 9.3). This holds regardless
    ///   of `is_retroactive` — an existing valid registration always takes the linked
    ///   standard path.
    /// - Otherwise, if `is_retroactive` is `false`, the request is rejected with
    ///   [`GmcError::NotRegistered`] and **nothing is written** (Requirement 9.4).
    /// - Otherwise (`is_retroactive == true` and no valid registration), an
    ///   **unlinked** record (`registration_id = None`) is created with status
    ///   [`EvaluationStatus::Pending`] — the retroactive path owned by task 15.x is
    ///   responsible for the stricter evidence/voting checks.
    ///
    /// On success the contribution-id counter advances; on the rejected path it does
    /// not (no side effects).
    pub fn record(
        &mut self,
        req: ContributionRequest,
        registrations: &impl RegistrationLookup,
        is_retroactive: bool,
    ) -> GmcResult<ContributionId> {
        // Resolve the matching valid registration up front (no mutation yet).
        let registration_id =
            registrations.find_valid_registration(&req.contributor_id, &req.chain_id);

        // Requirement 9.4: no valid registration and not a retroactive declaration →
        // reject with NotRegistered, leaving the store completely unchanged.
        if registration_id.is_none() && !is_retroactive {
            return Err(GmcError::NotRegistered);
        }

        // All checks passed: allocate an id and create the record (Requirement 9.3 for
        // the linked path; the retroactive unlinked path keeps registration_id = None).
        let id = self.allocate_id();
        let record = ContributionRecord {
            id: id.clone(),
            registration_id,
            contributor_id: req.contributor_id,
            chain_id: req.chain_id,
            evidence_refs: req.evidence_refs,
            dimension_weights: None,
            evaluation_status: EvaluationStatus::Pending,
            recorded_at: req.recorded_at,
        };
        self.records.insert(id.clone(), record);
        Ok(id)
    }

    /// Marks a stored record's evaluation verdict.
    ///
    /// - `passed = false`: the record is **retained** and marked
    ///   [`EvaluationStatus::Failed`] ("认定未通过"); no MeriToken is minted
    ///   (Requirement 9.6 — minting is owned by `Minting_Service`, which is never
    ///   invoked on this path).
    /// - `passed = true`: the record is marked [`EvaluationStatus::Passed`]. This only
    ///   records the verdict; the actual grant/mint is gated by the three-condition
    ///   guard `canGrant` (task 11.3) before `Minting_Service` runs.
    ///
    /// # Errors
    /// Returns [`GmcError::FieldValidation`] when `record_id` does not refer to a
    /// stored record; nothing is mutated. (The unified error vocabulary has no
    /// dedicated "record not found" code; an unknown id is treated as an invalid
    /// reference field.)
    pub fn mark_evaluation_result(
        &mut self,
        record_id: &ContributionId,
        passed: bool,
    ) -> GmcResult<()> {
        let record = self
            .records
            .get_mut(record_id)
            .ok_or(GmcError::FieldValidation)?;
        record.evaluation_status = if passed {
            EvaluationStatus::Passed
        } else {
            EvaluationStatus::Failed
        };
        Ok(())
    }

    /// Returns the stored record with `id`, if present.
    pub fn get(&self, id: &ContributionId) -> Option<&ContributionRecord> {
        self.records.get(id)
    }

    /// Number of contribution records currently stored.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` if no contribution records are stored.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterates over all stored records in deterministic id order.
    ///
    /// This is the input a future L2 batch-proof submission (Requirement 9.7,
    /// task 19.1) consumes.
    pub fn iter(&self) -> impl Iterator<Item = &ContributionRecord> {
        self.records.values()
    }

    /// Allocates a fresh, deterministic [`ContributionId`] (`contrib-<n>`).
    fn allocate_id(&mut self) -> ContributionId {
        let id = ContributionId::new(format!("contrib-{}", self.next_seq));
        self.next_seq += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Test double for [`RegistrationLookup`]: holds a set of `(contributor, chain)`
    /// pairs that have a matching valid registration, and the id it links them to.
    struct StubRegistrations {
        valid: BTreeSet<(String, String)>,
        linked_id: String,
    }

    impl StubRegistrations {
        fn new() -> Self {
            StubRegistrations {
                valid: BTreeSet::new(),
                linked_id: "reg-1".to_owned(),
            }
        }

        /// Marks `(contributor, chain)` as having a matching valid registration.
        fn with_valid(mut self, contributor: &str, chain: &str) -> Self {
            self.valid
                .insert((contributor.to_owned(), chain.to_owned()));
            self
        }
    }

    impl RegistrationLookup for StubRegistrations {
        fn find_valid_registration(
            &self,
            contributor_id: &FayID,
            chain_id: &ChainId,
        ) -> Option<String> {
            let key = (
                contributor_id.as_str().to_owned(),
                chain_id.as_str().to_owned(),
            );
            if self.valid.contains(&key) {
                Some(self.linked_id.clone())
            } else {
                None
            }
        }
    }

    fn request(contributor: &str, chain: &str) -> ContributionRequest {
        ContributionRequest::new(
            FayID::new(contributor),
            ChainId::new(chain),
            vec![EvidenceRef::new("ipfs://cid", "0xhash")],
            Timestamp::from_secs(1_000),
        )
    }

    // --- Requirement 9.3: matching valid registration → linked Pending record ---

    #[test]
    fn record_with_matching_valid_registration_creates_pending_linked_record() {
        let registrations = StubRegistrations::new().with_valid("alice", "academia");
        let mut service = RecordingService::new();

        let id = service
            .record(request("alice", "academia"), &registrations, false)
            .expect("a matching valid registration must allow recording");

        let record = service.get(&id).expect("record stored");
        assert_eq!(record.evaluation_status(), EvaluationStatus::Pending);
        assert!(record.is_linked());
        assert_eq!(record.registration_id(), Some("reg-1"));
        assert_eq!(record.contributor_id(), &FayID::new("alice"));
        assert_eq!(record.chain_id(), &ChainId::new("academia"));
        assert_eq!(service.len(), 1);
    }

    // --- Requirement 9.4: no valid registration + not retroactive → NotRegistered ---

    #[test]
    fn record_without_valid_registration_and_not_retroactive_is_rejected() {
        let registrations = StubRegistrations::new(); // no valid registrations at all
        let mut service = RecordingService::new();

        let err = service
            .record(request("bob", "academia"), &registrations, false)
            .expect_err("missing valid registration must be rejected");

        assert_eq!(err, GmcError::NotRegistered);
        // Atomic: nothing was written.
        assert!(service.is_empty());
    }

    #[test]
    fn record_rejected_when_chain_does_not_match_a_valid_registration() {
        // A valid registration exists for a *different* chain — must not match.
        let registrations = StubRegistrations::new().with_valid("alice", "academia");
        let mut service = RecordingService::new();

        let err = service
            .record(request("alice", "charity"), &registrations, false)
            .expect_err("mismatched chain must be rejected");

        assert_eq!(err, GmcError::NotRegistered);
        assert!(service.is_empty());
    }

    // --- Requirement 9.4: retroactive path allows an unlinked record ---

    #[test]
    fn record_without_valid_registration_via_retroactive_path_creates_unlinked_record() {
        let registrations = StubRegistrations::new();
        let mut service = RecordingService::new();

        let id = service
            .record(request("carol", "history"), &registrations, true)
            .expect("retroactive path allows recording without a registration");

        let record = service.get(&id).expect("record stored");
        assert_eq!(record.evaluation_status(), EvaluationStatus::Pending);
        assert!(!record.is_linked());
        assert_eq!(record.registration_id(), None);
        assert_eq!(service.len(), 1);
    }

    #[test]
    fn retroactive_flag_still_links_when_a_valid_registration_exists() {
        // An existing valid registration takes the linked standard path even if the
        // request is flagged retroactive.
        let registrations = StubRegistrations::new().with_valid("alice", "academia");
        let mut service = RecordingService::new();

        let id = service
            .record(request("alice", "academia"), &registrations, true)
            .expect("valid registration always links");

        assert!(service.get(&id).unwrap().is_linked());
    }

    // --- Requirement 9.6: failed evaluation retains record, marks Failed ---

    #[test]
    fn mark_evaluation_result_false_marks_failed_and_retains_record() {
        let registrations = StubRegistrations::new().with_valid("alice", "academia");
        let mut service = RecordingService::new();
        let id = service
            .record(request("alice", "academia"), &registrations, false)
            .unwrap();

        service
            .mark_evaluation_result(&id, false)
            .expect("marking a stored record must succeed");

        let record = service.get(&id).expect("record is retained, not removed");
        assert_eq!(record.evaluation_status(), EvaluationStatus::Failed);
        assert_eq!(service.len(), 1);
    }

    #[test]
    fn mark_evaluation_result_true_marks_passed() {
        let registrations = StubRegistrations::new().with_valid("alice", "academia");
        let mut service = RecordingService::new();
        let id = service
            .record(request("alice", "academia"), &registrations, false)
            .unwrap();

        service
            .mark_evaluation_result(&id, true)
            .expect("marking a stored record must succeed");

        assert_eq!(
            service.get(&id).unwrap().evaluation_status(),
            EvaluationStatus::Passed
        );
    }

    #[test]
    fn mark_evaluation_result_on_unknown_record_is_rejected() {
        let mut service = RecordingService::new();
        let err = service
            .mark_evaluation_result(&ContributionId::new("contrib-404"), true)
            .expect_err("unknown record id must be rejected");
        assert_eq!(err, GmcError::FieldValidation);
    }

    // --- id allocation is unique/deterministic across records ---

    #[test]
    fn distinct_records_get_distinct_ids() {
        let registrations = StubRegistrations::new()
            .with_valid("alice", "academia")
            .with_valid("bob", "academia");
        let mut service = RecordingService::new();

        let id1 = service
            .record(request("alice", "academia"), &registrations, false)
            .unwrap();
        let id2 = service
            .record(request("bob", "academia"), &registrations, false)
            .unwrap();

        assert_ne!(id1, id2);
        assert_eq!(service.len(), 2);
    }

    // --- has_valid_registration default method delegates correctly ---

    #[test]
    fn has_valid_registration_default_matches_find() {
        let registrations = StubRegistrations::new().with_valid("alice", "academia");
        assert!(
            registrations.has_valid_registration(&FayID::new("alice"), &ChainId::new("academia"))
        );
        assert!(
            !registrations.has_valid_registration(&FayID::new("alice"), &ChainId::new("charity"))
        );
    }
}
