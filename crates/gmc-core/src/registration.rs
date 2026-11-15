//! `Registration_Service` — merit registration and grant-trigger guards.
//!
//! This module implements the **standard "登记 → 记录 → 授予" intake stage**: a
//! contributor first *registers* an intended contribution on-chain before any
//! recording or minting happens (design's *Registration_Service* section, and the
//! *Data Models → 登记记录* record). It owns:
//!
//! - [`RegistrationStatus`] — the lifecycle of a registration (`Valid` / `Consumed`
//!   / `Revoked`), initialized to `Valid` on a successful application.
//! - [`Registration`] — the immutable登记记录 (`id / contributorId / chainId /
//!   description / registeredAt / status`).
//! - [`RegistrationApplication`] — the input to [`RegistrationService::register`].
//! - [`RegistrationService`] — the store of registrations plus the validating
//!   `register` entry point and the [`find_valid_registration`] lookup that the
//!   `Recording_Service` (task 11.2) relies on.
//!
//! ## Field validation (this task, 11.1 — Requirements 9.1, 9.2)
//!
//! [`RegistrationService::register`] accepts an application **iff** it carries a
//! non-empty contributor id, a non-empty chain id, and a description of at most
//! **2000 characters** (counted as Unicode *characters*, not bytes — "字" = chars).
//! The登记时间 (`registered_at`) is a value-typed [`Timestamp`] and so is always
//! present by construction. On success a [`Registration`] with `status = Valid` is
//! created, stored, and its [`RegistrationId`] returned. On **any** validation
//! failure the call returns [`GmcError::FieldValidation`] and creates **nothing**
//! (no partial write — the design's "validate up front, fail atomically, state
//! unchanged" principle).
//!
//! ## Lookup for the recording stage (Requirement 9.3 support)
//!
//! [`RegistrationService::find_valid_registration`] returns the registration whose
//! `contributorId` *and* `chainId` match the query *and* whose `status` is `Valid`.
//! `Recording_Service` (task 11.2) calls this to answer "is there a matching valid
//! registration?" without coupling to this module's internals.
//!
//! ## Grant three-condition guard (this task, 11.3 — Requirements 9.5, 9.8)
//!
//! The授予 (grant) guard fires minting **iff** all three conditions hold at once
//! (_Requirement 9.8_): a *matching valid registration* exists ∧ an *associated
//! contribution record* exists ∧ that record *passed evaluation*. This is realised by:
//!
//! - [`can_grant`] — the **pure three-condition predicate** (the design's `canGrant`).
//!   It takes the registration (as an `Option`, re-checking validity defensively) plus
//!   the two contribution-derived booleans, and returns `true` only when all three are
//!   true. This is the canonical AND that Property 20 (task 11.6) exercises across the
//!   full boolean truth table.
//! - [`GrantContext`] — a tiny trait **owned by this module** that abstracts the two
//!   contribution-derived facts (`has_linked_record` / `evaluation_passed`). It keeps
//!   `Registration_Service` decoupled from `recording.rs`'s concrete types (which are
//!   authored separately), mirroring how `Recording_Service` owns its
//!   `RegistrationLookup` trait rather than importing this module.
//! - [`RegistrationService::can_grant`] — the single integration entry point. It
//!   supplies condition 1 itself via [`find_valid_registration`] and combines it with
//!   the [`GrantContext`] facts, so the wiring task (20.1) calls one method.
//!
//! > **Minting wiring (_Requirement 9.5_).** This guard is only the *gate*: when
//! > [`RegistrationService::can_grant`] returns `true`, the integration layer (task
//! > 20.1) is responsible for invoking `Minting_Service.mint` (mint only once the
//! > record passes evaluation). The actual `Minting_Service` call is intentionally
//! > **not** made here, to keep this pure-logic core free of cross-module coupling.
//!
//! ## Seams left for later tasks
//!
//! - **L1 state-root anchoring (Requirement 9.1).** The登记状态根 must be anchored to
//!   `L1_Settlement`. Real anchoring is the infrastructure task 18.1; this module
//!   leaves the documented seam [`RegistrationService::anchor_registration_root`]
//!   (a pure-logic no-op placeholder) so the wiring point is explicit.
//! - **`GrantContext` implementation over real records (Requirement 9.8).** The
//!   integration task (20.1) implements [`GrantContext`] over the real
//!   `ContributionRecord` (`recording.rs`): `has_linked_record` ← `record.is_linked()`
//!   and `evaluation_passed` ← `record.evaluation_status() == Passed`.

use std::collections::BTreeMap;

use crate::error::{GmcError, GmcResult};
use crate::types::{ChainId, FayID, Timestamp};

/// Maximum length, in Unicode characters, of a registration's intended-contribution
/// description (_Requirements 9.1, 9.2_).
///
/// The bound is measured in characters ("字"), not bytes, so multi-byte scripts are
/// counted the way a human would count them.
pub const MAX_DESCRIPTION_CHARS: usize = 2000;

/// Lifecycle status of a [`Registration`] (design's登记记录 `status` field).
///
/// A registration is born [`Valid`](RegistrationStatus::Valid). The transitions to
/// [`Consumed`](RegistrationStatus::Consumed) (once its grant has fired) and
/// [`Revoked`](RegistrationStatus::Revoked) are driven by later tasks (recording /
/// grant / penalty paths); this task only establishes the initial `Valid` state and
/// the [`find_valid_registration`](RegistrationService::find_valid_registration)
/// predicate that keys off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RegistrationStatus {
    /// Active and eligible to back a contribution record (_Requirement 9.1_).
    #[default]
    Valid,
    /// The registration's grant has already fired; no longer matchable.
    Consumed,
    /// Administratively revoked; no longer matchable.
    Revoked,
}

impl RegistrationStatus {
    /// `true` only for [`RegistrationStatus::Valid`].
    ///
    /// Used by [`RegistrationService::find_valid_registration`] so the "status is
    /// valid" half of the matching rule (_Requirement 9.3_) is expressed in one place.
    #[inline]
    pub fn is_valid(self) -> bool {
        matches!(self, RegistrationStatus::Valid)
    }
}

/// Opaque identifier of a [`Registration`].
///
/// Backed by a `String` so it can carry either an externally-supplied id or one
/// generated by [`RegistrationService`]. Returned by
/// [`RegistrationService::register`] and surfaced on [`Registration::id`] for the
/// recording/grant stages to reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RegistrationId(String);

impl RegistrationId {
    /// Builds a `RegistrationId` from any string-like value.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        RegistrationId(id.into())
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for RegistrationId {
    fn from(value: String) -> Self {
        RegistrationId(value)
    }
}

impl From<&str> for RegistrationId {
    fn from(value: &str) -> Self {
        RegistrationId(value.to_owned())
    }
}

impl core::fmt::Display for RegistrationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An on-chain merit registration record (design's登记记录).
///
/// Created only via [`RegistrationService::register`], which enforces the field rules
/// of _Requirements 9.1 / 9.2_, so any `Registration` value in hand is, by
/// construction, well-formed (non-empty contributor & chain ids; description within
/// [`MAX_DESCRIPTION_CHARS`]). Fields are private with read-only accessors so the
/// validated invariants cannot be silently broken by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    id: RegistrationId,
    contributor_id: FayID,
    chain_id: ChainId,
    description: String,
    registered_at: Timestamp,
    status: RegistrationStatus,
}

impl Registration {
    /// This registration's identifier.
    #[inline]
    pub fn id(&self) -> &RegistrationId {
        &self.id
    }

    /// The contributor this registration belongs to (_Requirement 9.1_).
    #[inline]
    pub fn contributor_id(&self) -> &FayID {
        &self.contributor_id
    }

    /// The functioning merit chain this registration targets (_Requirement 9.1_).
    #[inline]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// The intended-contribution description (≤ [`MAX_DESCRIPTION_CHARS`] chars).
    #[inline]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// On-chain time the registration was filed (_Requirement 9.1_).
    #[inline]
    pub fn registered_at(&self) -> Timestamp {
        self.registered_at
    }

    /// Current lifecycle status (initialized to [`RegistrationStatus::Valid`]).
    #[inline]
    pub fn status(&self) -> RegistrationStatus {
        self.status
    }

    /// Convenience: `true` if this registration is currently `Valid`.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.status.is_valid()
    }
}

/// Input to [`RegistrationService::register`] (design's `RegistrationApplication`).
///
/// Mirrors the design fields a contributor submits: who is registering
/// (`contributor_id`), the target chain (`chain_id`), the intended-contribution
/// `description`, and the登记时间 (`registered_at`). The required-field and
/// description-length rules are applied by `register`, not by this struct, so an
/// `RegistrationApplication` may be constructed freely (including with invalid
/// content) and is only *accepted or rejected* at `register` time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationApplication {
    /// Contributor identifier; must be non-empty to be accepted (_Requirement 9.1_).
    pub contributor_id: FayID,
    /// Target functioning merit chain; must be non-empty to be accepted
    /// (_Requirement 9.1_).
    pub chain_id: ChainId,
    /// Intended-contribution description; at most [`MAX_DESCRIPTION_CHARS`] characters
    /// (_Requirements 9.1, 9.2_).
    pub description: String,
    /// On-chain registration time (_Requirement 9.1_).
    pub registered_at: Timestamp,
}

impl RegistrationApplication {
    /// Builds a [`RegistrationApplication`] from its parts.
    pub fn new(
        contributor_id: FayID,
        chain_id: ChainId,
        description: impl Into<String>,
        registered_at: Timestamp,
    ) -> Self {
        RegistrationApplication {
            contributor_id,
            chain_id,
            description: description.into(),
            registered_at,
        }
    }
}

/// Abstraction over the two contribution-derived facts the grant guard needs.
///
/// `Registration_Service` owns this trait so the授予 guard (_Requirements 9.5, 9.8_)
/// does **not** depend on the concrete `Recording_Service` types (`src/recording.rs`,
/// authored separately). This mirrors how `Recording_Service` owns its
/// `RegistrationLookup` trait rather than importing this module — each side depends
/// only on a small, locally-owned interface, so both stay independently compilable.
///
/// The integration task (20.1) implements this trait over the real
/// `ContributionRecord`:
///
/// - [`has_linked_record`](GrantContext::has_linked_record) ← `record.is_linked()`
///   (the record is associated with a valid registration), and
/// - [`evaluation_passed`](GrantContext::evaluation_passed) ←
///   `record.evaluation_status() == EvaluationStatus::Passed`.
pub trait GrantContext {
    /// Whether an **associated contribution record** exists for the grant
    /// (_Requirement 9.8_, condition 2). For the standard flow this is the record's
    /// `is_linked()` (linked to a valid registration).
    fn has_linked_record(&self) -> bool;

    /// Whether that contribution record has **passed** its chain's
    /// `Evaluation_Mechanism` (_Requirements 9.5, 9.8_, condition 3).
    fn evaluation_passed(&self) -> bool;
}

/// The **pure three-condition授予 (grant) predicate** (design's `canGrant`).
///
/// Returns `true` **iff all three** grant conditions hold at once (_Requirement 9.8_):
///
/// 1. a **matching valid registration** exists — `registration` is `Some` *and* that
///    registration is currently `Valid` (validity is re-checked here defensively, so a
///    `Consumed`/`Revoked` registration can never satisfy condition 1 even if passed
///    in);
/// 2. an **associated contribution record** exists — `has_linked_contribution_record`;
/// 3. that record **passed evaluation** — `evaluation_passed`.
///
/// When the predicate returns `true` the caller may fire minting; when it returns
/// `false` (any single condition false) **no MeriToken is minted** (_Requirement 9.5_:
/// mint only when the record passes evaluation — this predicate is the gate). The
/// function is deliberately side-effect free: it neither mints nor mutates anything,
/// which is what lets Property 20 (task 11.6) exercise the full boolean truth table.
#[inline]
pub fn can_grant(
    registration: Option<&Registration>,
    has_linked_contribution_record: bool,
    evaluation_passed: bool,
) -> bool {
    let has_valid_registration = registration.is_some_and(Registration::is_valid);
    has_valid_registration && has_linked_contribution_record && evaluation_passed
}

/// The `Registration_Service` store: all登记记录 plus the validating intake.
///
/// Holds every [`Registration`] keyed by [`RegistrationId`] in a `BTreeMap` (for
/// deterministic iteration), and a monotonic counter used to mint fresh ids. The
/// public surface is intentionally small so other modules (notably the
/// `Recording_Service`, task 11.2) depend only on:
///
/// - [`register`](RegistrationService::register) — create a `Valid` registration after
///   field validation, or reject atomically; and
/// - [`find_valid_registration`](RegistrationService::find_valid_registration) — the
///   `(contributorId, chainId, status == Valid)` lookup.
#[derive(Debug, Clone, Default)]
pub struct RegistrationService {
    registrations: BTreeMap<RegistrationId, Registration>,
    next_seq: u64,
}

impl RegistrationService {
    /// Creates an empty registration service.
    pub fn new() -> Self {
        RegistrationService {
            registrations: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Receives a registration application and, if valid, creates a `Valid`
    /// registration record (_Requirements 9.1, 9.2_).
    ///
    /// Validation runs **up front**, and any failure returns
    /// [`GmcError::FieldValidation`] while leaving the service **completely
    /// unchanged** (no record created, counter not advanced):
    ///
    /// 1. `contributor_id` must be non-empty (_Requirement 9.1_).
    /// 2. `chain_id` must be non-empty (_Requirement 9.1_).
    /// 3. `description` must be at most [`MAX_DESCRIPTION_CHARS`] **Unicode
    ///    characters** (_Requirements 9.1, 9.2_).
    ///
    /// On success a [`Registration`] is built with a freshly-generated
    /// [`RegistrationId`] and `status = `[`RegistrationStatus::Valid`], stored, and its
    /// id returned.
    ///
    /// > **L1 anchoring seam (_Requirement 9.1_).** The登记状态根 must ultimately be
    /// > anchored to `L1_Settlement`. That is the infrastructure task 18.1; here we
    /// > only perform the pure-logic validation + write and expose
    /// > [`anchor_registration_root`](RegistrationService::anchor_registration_root)
    /// > as the documented wiring point.
    pub fn register(&mut self, app: RegistrationApplication) -> GmcResult<RegistrationId> {
        // 1. Required field: contributor id (Requirement 9.1).
        if app.contributor_id.is_empty() {
            return Err(GmcError::FieldValidation);
        }
        // 2. Required field: chain id (Requirement 9.1).
        if app.chain_id.is_empty() {
            return Err(GmcError::FieldValidation);
        }
        // 3. Description length, counted in Unicode characters (Requirements 9.1/9.2).
        if app.description.chars().count() > MAX_DESCRIPTION_CHARS {
            return Err(GmcError::FieldValidation);
        }

        // All checks passed: mint an id, build the Valid record, and store it.
        let id = self.allocate_id();
        let registration = Registration {
            id: id.clone(),
            contributor_id: app.contributor_id,
            chain_id: app.chain_id,
            description: app.description,
            registered_at: app.registered_at,
            status: RegistrationStatus::Valid,
        };
        self.registrations.insert(id.clone(), registration);
        Ok(id)
    }

    /// Finds the registration matching `contributor_id` **and** `chain_id` whose
    /// `status` is [`RegistrationStatus::Valid`] (_Requirement 9.3_).
    ///
    /// Returns the first such record in deterministic id order, or `None` if no valid
    /// registration matches. This is the lookup the `Recording_Service` (task 11.2)
    /// uses to decide whether a contribution record may be created against an existing
    /// valid registration.
    pub fn find_valid_registration(
        &self,
        contributor_id: &FayID,
        chain_id: &ChainId,
    ) -> Option<&Registration> {
        self.registrations.values().find(|reg| {
            reg.status.is_valid()
                && reg.contributor_id() == contributor_id
                && reg.chain_id() == chain_id
        })
    }

    /// The授予 (grant) three-condition guard — the single integration entry point
    /// (design's `canGrant`, _Requirements 9.5, 9.8_).
    ///
    /// Returns `true` **iff** all three conditions hold at once:
    ///
    /// 1. a **matching valid registration** exists for `(contributor_id, chain_id)` —
    ///    supplied here by [`find_valid_registration`](RegistrationService::find_valid_registration);
    /// 2. an **associated contribution record** exists — `ctx.has_linked_record()`;
    /// 3. that record **passed evaluation** — `ctx.evaluation_passed()`.
    ///
    /// The two contribution-derived facts come from the [`GrantContext`] so this
    /// service stays decoupled from the concrete `Recording_Service` record type. The
    /// method delegates the actual AND to the free [`can_grant`] predicate, so the
    /// guard logic lives in exactly one place.
    ///
    /// This is a **pure query**: it mints nothing and mutates nothing. When it returns
    /// `true`, the integration layer (task 20.1) invokes `Minting_Service.mint`
    /// (_Requirement 9.5_); when it returns `false`, no MeriToken is minted.
    pub fn can_grant(
        &self,
        contributor_id: &FayID,
        chain_id: &ChainId,
        ctx: &impl GrantContext,
    ) -> bool {
        let registration = self.find_valid_registration(contributor_id, chain_id);
        can_grant(
            registration,
            ctx.has_linked_record(),
            ctx.evaluation_passed(),
        )
    }

    /// Returns the registration with `id`, if present.
    pub fn get(&self, id: &RegistrationId) -> Option<&Registration> {
        self.registrations.get(id)
    }

    /// Number of registrations currently stored.
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// `true` if no registrations are stored.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    /// Iterates over all registrations in deterministic id order.
    pub fn iter(&self) -> impl Iterator<Item = &Registration> {
        self.registrations.values()
    }

    /// Documented seam for anchoring the registration state root to `L1_Settlement`
    /// (_Requirement 9.1_).
    ///
    /// In the pure-logic core this is a no-op: the actual L1 anchoring (computing and
    /// submitting the state root) belongs to the Substrate settlement layer and is
    /// implemented by task 18.1. Keeping the seam here makes the wiring point explicit
    /// and lets infrastructure code call a stable method instead of reaching into the
    /// store.
    pub fn anchor_registration_root(&self) -> GmcResult<()> {
        // Seam only — real anchoring is task 18.1.
        Ok(())
    }

    /// Generates the next unique [`RegistrationId`] (`"reg-{seq}"`), advancing the
    /// internal counter. Deterministic so tests and the L2/L1 layers stay in sync.
    fn allocate_id(&mut self) -> RegistrationId {
        let id = RegistrationId::new(format!("reg-{}", self.next_seq));
        self.next_seq += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(contributor: &str, chain: &str, description: &str) -> RegistrationApplication {
        RegistrationApplication::new(
            FayID::new(contributor),
            ChainId::new(chain),
            description,
            Timestamp::from_secs(1_000),
        )
    }

    // --- Successful registration (Requirement 9.1) -------------------------

    #[test]
    fn valid_application_creates_a_valid_registration() {
        let mut svc = RegistrationService::new();
        let id = svc
            .register(app("fay-1", "academic", "intend to publish a paper"))
            .expect("a complete, in-bounds application must be accepted");

        let reg = svc.get(&id).expect("registration stored");
        assert_eq!(reg.contributor_id(), &FayID::new("fay-1"));
        assert_eq!(reg.chain_id(), &ChainId::new("academic"));
        assert_eq!(reg.description(), "intend to publish a paper");
        assert_eq!(reg.registered_at(), Timestamp::from_secs(1_000));
        assert_eq!(reg.status(), RegistrationStatus::Valid);
        assert!(reg.is_valid());
        assert_eq!(svc.len(), 1);
    }

    // --- Missing required fields rejected, nothing created (Requirement 9.2) ---

    #[test]
    fn missing_contributor_id_is_rejected_and_nothing_created() {
        let mut svc = RegistrationService::new();
        let result = svc.register(app("", "academic", "desc"));
        assert_eq!(result, Err(GmcError::FieldValidation));
        assert!(svc.is_empty());
    }

    #[test]
    fn missing_chain_id_is_rejected_and_nothing_created() {
        let mut svc = RegistrationService::new();
        let result = svc.register(app("fay-1", "", "desc"));
        assert_eq!(result, Err(GmcError::FieldValidation));
        assert!(svc.is_empty());
    }

    // --- Description length boundary (Requirements 9.1, 9.2) ---------------

    #[test]
    fn description_of_exactly_2000_chars_is_accepted() {
        let mut svc = RegistrationService::new();
        let desc: String = "a".repeat(MAX_DESCRIPTION_CHARS);
        assert_eq!(desc.chars().count(), 2000);
        let id = svc
            .register(app("fay-1", "academic", &desc))
            .expect("a 2000-char description is within bounds");
        assert_eq!(svc.get(&id).unwrap().description().chars().count(), 2000);
    }

    #[test]
    fn description_of_2001_chars_is_rejected_and_nothing_created() {
        let mut svc = RegistrationService::new();
        let desc: String = "a".repeat(MAX_DESCRIPTION_CHARS + 1);
        assert_eq!(desc.chars().count(), 2001);
        let result = svc.register(app("fay-1", "academic", &desc));
        assert_eq!(result, Err(GmcError::FieldValidation));
        assert!(svc.is_empty());
    }

    #[test]
    fn description_length_counts_unicode_chars_not_bytes() {
        // 2000 multi-byte CJK characters: > 2000 bytes but exactly 2000 *characters*,
        // so it must be accepted (the bound is "字" = characters, not bytes).
        let mut svc = RegistrationService::new();
        let desc: String = "字".repeat(MAX_DESCRIPTION_CHARS);
        assert!(desc.len() > MAX_DESCRIPTION_CHARS); // byte length far exceeds 2000
        assert_eq!(desc.chars().count(), 2000);
        svc.register(app("fay-1", "academic", &desc))
            .expect("2000 CJK characters is within the character bound");

        // One more character must tip it over.
        let mut svc2 = RegistrationService::new();
        let too_long: String = "字".repeat(MAX_DESCRIPTION_CHARS + 1);
        assert_eq!(
            svc2.register(app("fay-1", "academic", &too_long)),
            Err(GmcError::FieldValidation)
        );
        assert!(svc2.is_empty());
    }

    // --- find_valid_registration (Requirement 9.3 support) -----------------

    #[test]
    fn find_valid_registration_returns_match_for_contributor_and_chain() {
        let mut svc = RegistrationService::new();
        svc.register(app("fay-1", "academic", "desc")).unwrap();

        let found = svc.find_valid_registration(&FayID::new("fay-1"), &ChainId::new("academic"));
        assert!(found.is_some());
        let reg = found.unwrap();
        assert_eq!(reg.contributor_id(), &FayID::new("fay-1"));
        assert_eq!(reg.chain_id(), &ChainId::new("academic"));
        assert!(reg.is_valid());
    }

    #[test]
    fn find_valid_registration_requires_both_contributor_and_chain_to_match() {
        let mut svc = RegistrationService::new();
        svc.register(app("fay-1", "academic", "desc")).unwrap();

        // Right contributor, wrong chain.
        assert!(svc
            .find_valid_registration(&FayID::new("fay-1"), &ChainId::new("charity"))
            .is_none());
        // Wrong contributor, right chain.
        assert!(svc
            .find_valid_registration(&FayID::new("fay-2"), &ChainId::new("academic"))
            .is_none());
    }

    #[test]
    fn find_valid_registration_ignores_non_valid_status() {
        // Build a service holding a single non-Valid registration directly, to confirm
        // the lookup keys off `status == Valid` (the recording stage must not match a
        // Consumed/Revoked registration).
        let mut svc = RegistrationService::new();
        let id = svc.register(app("fay-1", "academic", "desc")).unwrap();

        // Mutate the stored record's status out of `Valid` via a rebuilt map entry.
        // (The public API has no status setter yet — that lands in tasks 11.2/11.3 —
        // so we reconstruct the store for this status-sensitivity check.)
        let mut consumed = svc.get(&id).unwrap().clone();
        consumed.status = RegistrationStatus::Consumed;
        let mut svc2 = RegistrationService::new();
        svc2.registrations.insert(id, consumed);

        assert!(svc2
            .find_valid_registration(&FayID::new("fay-1"), &ChainId::new("academic"))
            .is_none());
    }

    #[test]
    fn each_registration_gets_a_distinct_id() {
        let mut svc = RegistrationService::new();
        let a = svc.register(app("fay-1", "academic", "first")).unwrap();
        let b = svc.register(app("fay-1", "academic", "second")).unwrap();
        assert_ne!(a, b);
        assert_eq!(svc.len(), 2);
    }

    #[test]
    fn anchor_registration_root_seam_is_callable() {
        let svc = RegistrationService::new();
        assert_eq!(svc.anchor_registration_root(), Ok(()));
    }

    // --- Grant three-condition guard (Requirements 9.5, 9.8) ---------------

    /// Test double for [`GrantContext`]: carries the two contribution-derived facts
    /// (whether an associated record exists, and whether it passed evaluation).
    struct StubGrantContext {
        has_linked_record: bool,
        evaluation_passed: bool,
    }

    impl GrantContext for StubGrantContext {
        fn has_linked_record(&self) -> bool {
            self.has_linked_record
        }
        fn evaluation_passed(&self) -> bool {
            self.evaluation_passed
        }
    }

    /// Builds a single `Valid` registration to stand in for "matching valid
    /// registration exists" in the pure-predicate tests.
    fn valid_registration() -> Registration {
        Registration {
            id: RegistrationId::new("reg-0"),
            contributor_id: FayID::new("fay-1"),
            chain_id: ChainId::new("academic"),
            description: "desc".to_owned(),
            registered_at: Timestamp::from_secs(1_000),
            status: RegistrationStatus::Valid,
        }
    }

    // Pure predicate: full truth table of the three conditions (Requirement 9.8).

    #[test]
    fn can_grant_predicate_true_only_when_all_three_conditions_hold() {
        let reg = valid_registration();
        // All true => grant.
        assert!(can_grant(Some(&reg), true, true));
    }

    #[test]
    fn can_grant_predicate_false_when_no_valid_registration() {
        // Condition 1 false: no registration at all.
        assert!(!can_grant(None, true, true));
    }

    #[test]
    fn can_grant_predicate_false_when_registration_not_valid() {
        // Condition 1 false: a registration exists but is not `Valid`.
        let mut consumed = valid_registration();
        consumed.status = RegistrationStatus::Consumed;
        assert!(!can_grant(Some(&consumed), true, true));

        let mut revoked = valid_registration();
        revoked.status = RegistrationStatus::Revoked;
        assert!(!can_grant(Some(&revoked), true, true));
    }

    #[test]
    fn can_grant_predicate_false_when_no_linked_record() {
        // Condition 2 false: no associated contribution record.
        let reg = valid_registration();
        assert!(!can_grant(Some(&reg), false, true));
    }

    #[test]
    fn can_grant_predicate_false_when_evaluation_not_passed() {
        // Condition 3 false: the record has not passed evaluation.
        let reg = valid_registration();
        assert!(!can_grant(Some(&reg), true, false));
    }

    #[test]
    fn can_grant_predicate_false_when_all_conditions_false() {
        assert!(!can_grant(None, false, false));
    }

    // Service entry point: condition 1 is supplied by find_valid_registration.

    #[test]
    fn service_can_grant_true_when_all_three_conditions_hold() {
        let mut svc = RegistrationService::new();
        svc.register(app("fay-1", "academic", "desc")).unwrap();
        let ctx = StubGrantContext {
            has_linked_record: true,
            evaluation_passed: true,
        };
        assert!(svc.can_grant(&FayID::new("fay-1"), &ChainId::new("academic"), &ctx));
    }

    #[test]
    fn service_can_grant_false_when_no_matching_valid_registration() {
        // No registration for this (contributor, chain) at all → condition 1 false,
        // even though the contribution facts are both true.
        let svc = RegistrationService::new();
        let ctx = StubGrantContext {
            has_linked_record: true,
            evaluation_passed: true,
        };
        assert!(!svc.can_grant(&FayID::new("fay-1"), &ChainId::new("academic"), &ctx));
    }

    #[test]
    fn service_can_grant_false_when_registration_matches_other_chain() {
        // A valid registration exists, but for a different chain → no match.
        let mut svc = RegistrationService::new();
        svc.register(app("fay-1", "academic", "desc")).unwrap();
        let ctx = StubGrantContext {
            has_linked_record: true,
            evaluation_passed: true,
        };
        assert!(!svc.can_grant(&FayID::new("fay-1"), &ChainId::new("charity"), &ctx));
    }

    #[test]
    fn service_can_grant_false_when_no_linked_record() {
        let mut svc = RegistrationService::new();
        svc.register(app("fay-1", "academic", "desc")).unwrap();
        let ctx = StubGrantContext {
            has_linked_record: false,
            evaluation_passed: true,
        };
        assert!(!svc.can_grant(&FayID::new("fay-1"), &ChainId::new("academic"), &ctx));
    }

    #[test]
    fn service_can_grant_false_when_evaluation_not_passed() {
        let mut svc = RegistrationService::new();
        svc.register(app("fay-1", "academic", "desc")).unwrap();
        let ctx = StubGrantContext {
            has_linked_record: true,
            evaluation_passed: false,
        };
        assert!(!svc.can_grant(&FayID::new("fay-1"), &ChainId::new("academic"), &ctx));
    }
}
