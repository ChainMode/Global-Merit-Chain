//! `Recovery_Service` — key rotation and guardian M-of-N social recovery.
//!
//! This module implements the design's *Recovery_Service* section and the
//! *Data Models → 轮换与恢复* records. It owns each identity's rotation history, guardian
//! configurations and in-flight recovery sessions, and performs the **key-rotation
//! effect** that keeps an identity's [`IdentityId`] stable while its active verifying key
//! changes (Requirements 11.1, 11.2, 11.3, 12.4).
//!
//! Task 14.1 fills in the **rotation effect + rotation-history record**
//! ([`RotationRecord`], [`RecoveryService::rotate_key`]). Task 14.2 adds **guardian
//! configuration** ([`GuardianConfig`], [`RecoveryService::configure_guardians`]) and the
//! **M-of-N social-recovery sessions** ([`RecoverySession`],
//! [`RecoveryService::submit_recovery_approval`]) in this same file, reusing the very same
//! [`rotate_key`](RecoveryService::rotate_key) effect once a recovery reaches its
//! threshold — so the `IdentityId`-invariant guarantee proven for rotation holds
//! identically for guardian recovery (Requirement 12.4).
//!
//! ## Rotation effect (design *Recovery_Service*; Requirements 11.1, 11.2, 11.3)
//!
//! [`RecoveryService::rotate_key`] validates a new verifying key's byte format under the
//! target identity's scheme, then:
//!
//! 1. sets the identity's `active_key` to the new key (Requirement 11.1),
//! 2. pushes the **old** active key into `retired_keys` (Requirements 11.1, 11.4), and
//! 3. appends a [`RotationRecord`] (old key, new key, rotation time) to that identity's
//!    rotation history (Requirement 11.3).
//!
//! The identity's [`IdentityId`] is **never re-derived** — it stays fixed across the
//! rotation, so the identity's Pocket binding and ownership relationships are
//! unaffected (Requirement 11.2). The id is derived once at creation from the *initial*
//! verifying key (design decision 4); only [`Identity::active_key`] /
//! [`Identity::retired_keys`] change here.
//!
//! ## Who is allowed to rotate (Requirements 11.5, 13.1) — *not* decided here
//!
//! Like [`crate::authority`] and [`crate::device`], this module is **pure** state-effect
//! logic: it performs the rotation but does **not** authenticate the *caller*. The design
//! routes every state-changing `RotateKey` request through `Identity_Core`, which runs
//! the fixed validation chain — scheme → key/sig format → signature → identity →
//! **authorize** → nonce — *before* the rotation effect would be applied. The signing-key
//! authorization for a rotation is one of:
//!
//! - the identity's **current active key** signs the rotation (Requirement 11.1, 11.5), or
//! - a **guardian M-of-N** recovery reaches its threshold (Requirement 12, task 14.2).
//!
//! `Identity_Core` currently **defers** the `RotateKey` payload (it authenticates the
//! operation but commits nothing yet); a later wiring task will route an authenticated
//! `RotateKey` here, and [`submit_recovery_approval`](RecoveryService::submit_recovery_approval)
//! calls [`rotate_key`](RecoveryService::rotate_key) once a guardian recovery meets its
//! threshold. This method performs the rotation effect **after** that authorization has
//! been established by the caller.
//!
//! Once a key lands in `retired_keys`, signing with it is unauthorized — that rule is
//! enforced by `Identity_Core`'s authorization step (which rejects keys present in
//! `retired_keys`, Requirement 11.4); here we only ensure the old key is recorded there.
//!
//! ## Guardian configuration + M-of-N recovery (Requirement 12, task 14.2)
//!
//! [`RecoveryService`] owns three pieces of state, mirroring the design's *Data Models*:
//!
//! - `rotation_history: BTreeMap<IdentityId, Vec<RotationRecord>>` — per-identity ordered
//!   rotation history (Requirement 11.3);
//! - `guardian_configs: BTreeMap<IdentityId, GuardianConfig>` — each iFay's `{guardians,
//!   threshold}` ([`configure_guardians`](RecoveryService::configure_guardians), requiring
//!   `1 ≤ M ≤ N`, Requirements 12.1, 12.2, 12.3);
//! - `sessions: BTreeMap<(IdentityId, /*new_key fingerprint*/ String), RecoverySession>`
//!   — the per-`(identity, candidate new key)` de-duplicated guardian approvals
//!   ([`submit_recovery_approval`](RecoveryService::submit_recovery_approval),
//!   Requirements 12.4, 12.5, 12.6).
//!
//! When a recovery session's de-duplicated approval count reaches the threshold,
//! [`submit_recovery_approval`](RecoveryService::submit_recovery_approval) reuses
//! [`rotate_key`](RecoveryService::rotate_key) to perform the active-key swap — so the
//! `IdentityId`-invariant guarantee proven for rotation holds identically for guardian
//! recovery (Requirement 12.4). As with [`rotate_key`](RecoveryService::rotate_key), this
//! module is **pure** state-effect logic: it performs the effect but does **not**
//! authenticate the *caller*. `Identity_Core` authenticates each signed guardian approval
//! (the guardian's signature is valid and the guardian belongs to the configured set)
//! *before* invoking [`submit_recovery_approval`](RecoveryService::submit_recovery_approval).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{IdentityError, IdentityResult};
use crate::identity_id::{base32_encode, IdentityId};
use crate::identity_service::IdentityService;
use crate::scheme::SchemeRegistry;
use crate::types::{Timestamp, VerifyingKey};

/// A single key-rotation history entry (design *Data Models → 轮换与恢复*:
/// `RotationRecord`).
///
/// Records the verifying key that was retired (`old_key`), the verifying key that became
/// active (`new_key`), and when the rotation was applied (`rotated_at`, Requirement
/// 11.3). Appended to the target identity's rotation history by
/// [`RecoveryService::rotate_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRecord {
    /// The verifying key that was active before this rotation and is now retired
    /// (Requirements 11.1, 11.4).
    pub old_key: VerifyingKey,
    /// The verifying key that became active in this rotation (Requirement 11.1).
    pub new_key: VerifyingKey,
    /// When the rotation was applied (Requirement 11.3).
    pub rotated_at: Timestamp,
}

/// An iFay's guardian set and recovery threshold (design *Data Models → 轮换与恢复*:
/// `GuardianConfig`).
///
/// Registered by [`RecoveryService::configure_guardians`] (Requirement 12.1). The
/// guardian set is **de-duplicated** — held as a [`BTreeSet`] so a guardian key counts
/// once toward `N` regardless of how many times it was supplied (Requirement 12.1) — and
/// the `threshold` (M) is constrained to `1 ≤ M ≤ N` at configuration time
/// (Requirements 12.2, 12.3). A `BTreeSet` also keeps iteration deterministic, matching
/// the rest of this layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianConfig {
    /// The iFay this configuration belongs to.
    pub ifay: IdentityId,
    /// The de-duplicated set of guardian verifying keys (the `N`, Requirement 12.1).
    pub guardians: BTreeSet<VerifyingKey>,
    /// The recovery threshold `M`, constrained to `1 ≤ M ≤ N` (Requirements 12.2, 12.3).
    pub threshold: u32,
}

impl GuardianConfig {
    /// The number of (de-duplicated) guardians, i.e. `N`.
    #[inline]
    pub fn guardian_count(&self) -> usize {
        self.guardians.len()
    }

    /// `true` iff `key` is one of this configuration's guardians.
    #[inline]
    pub fn is_guardian(&self, key: &VerifyingKey) -> bool {
        self.guardians.contains(key)
    }
}

/// An in-flight social-recovery session: the de-duplicated guardian approvals collected
/// for one `(identity, candidate new key)` pair (design *Data Models → 轮换与恢复*:
/// `RecoverySession`).
///
/// Accumulated by [`RecoveryService::submit_recovery_approval`]. Approvals are
/// de-duplicated **by approving guardian** — held as a [`BTreeSet`] of guardian key
/// fingerprints — so repeated approvals from the same guardian count exactly once toward
/// the threshold (Requirement 12.5). One session exists per candidate `new_key`, so
/// approvals for different candidate keys never cross-count (Requirement 12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySession {
    /// The iFay being recovered.
    pub ifay: IdentityId,
    /// The candidate new verifying key this session is collecting approvals for.
    pub new_key: VerifyingKey,
    /// Fingerprints of the guardians that have approved, de-duplicated (Requirement 12.5).
    pub approvals: BTreeSet<String>,
}

impl RecoverySession {
    /// The number of distinct guardians that have approved this candidate key so far.
    #[inline]
    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }
}

/// The recovery service: owns each identity's key-rotation history, guardian
/// configurations and in-flight recovery sessions, and performs the rotation effect
/// (design *Data Models*: `RecoveryService`).
///
/// It owns `rotation_history` (Requirement 11.3), `guardian_configs` (each iFay's
/// `{guardians, threshold}`, Requirements 12.1–12.3) and `sessions` (per-`(identity,
/// candidate new key)` de-duplicated guardian approvals, Requirements 12.4–12.6). A
/// [`BTreeMap`] keeps iteration order deterministic, matching the rest of this layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryService {
    /// Per-identity ordered key-rotation history (design `rotation_history`,
    /// Requirement 11.3).
    rotation_history: BTreeMap<IdentityId, Vec<RotationRecord>>,
    /// Per-iFay guardian configuration (design `guardian_configs`,
    /// Requirements 12.1, 12.2, 12.3).
    guardian_configs: BTreeMap<IdentityId, GuardianConfig>,
    /// In-flight recovery sessions keyed by `(identity, candidate new-key fingerprint)`
    /// (design `sessions`, Requirements 12.4, 12.5, 12.6).
    sessions: BTreeMap<(IdentityId, String), RecoverySession>,
}

impl RecoveryService {
    /// Creates an empty recovery service.
    #[inline]
    pub fn new() -> Self {
        RecoveryService {
            rotation_history: BTreeMap::new(),
            guardian_configs: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    /// Rotates `id`'s active verifying key to `new_key`, retiring the old key and
    /// recording the rotation (design *Recovery_Service*: `rotateKey`; Requirements
    /// 11.1, 11.2, 11.3, 11.4).
    ///
    /// Steps, in the design's fixed order — **all validation runs before any state is
    /// touched**, so a rejected request is atomic and leaves the identity, its rotation
    /// history and every collaborator unchanged:
    ///
    /// 1. **Resolve the target.** The identity must exist; an unknown `id` is rejected
    ///    with [`IdentityMismatch`](IdentityError::IdentityMismatch) — a rotation
    ///    declares a target identity, and a target that is not on record cannot be the
    ///    identity the rotation is for. **Nothing** is mutated.
    /// 2. **Validate the new key.** The `new_key` bytes are validated against the
    ///    **identity's own scheme** (`identity.scheme_tag`); a malformed key →
    ///    [`KeyFormatInvalid`](IdentityError::KeyFormatInvalid) (an unregistered scheme →
    ///    [`SchemeUnsupported`](IdentityError::SchemeUnsupported)). On either error
    ///    **nothing** changes — neither the active key nor the rotation history.
    /// 3. **Apply the rotation effect.** Only after validation passes: set
    ///    `active_key = new_key` (Requirement 11.1), push the prior active key into
    ///    `retired_keys` (Requirements 11.1, 11.4), and append a [`RotationRecord`]
    ///    `{ old_key, new_key, rotated_at }` to `id`'s history (Requirement 11.3). The
    ///    identity's [`IdentityId`], `kind` and `created_at` are **left untouched**, so
    ///    its Pocket binding and ownership relationships are unaffected (Requirement
    ///    11.2).
    ///
    /// Returns the appended [`RotationRecord`].
    ///
    /// # Authorization is the caller's job (Requirements 11.5, 13.1)
    ///
    /// This method does **not** check *who* may rotate. As described in the module docs,
    /// `Identity_Core` authenticates the signed `RotateKey` operation (current active key
    /// signs) — or task 14.2's guardian M-of-N recovery establishes authorization — and
    /// only then is this rotation effect applied. The retired key's loss of authority
    /// (Requirement 11.4) is enforced by `Identity_Core` rejecting keys present in
    /// `retired_keys`; here we only ensure the old key is recorded there.
    pub fn rotate_key(
        &mut self,
        identities: &mut IdentityService,
        registry: &SchemeRegistry,
        id: &IdentityId,
        new_key: &VerifyingKey,
        rotated_at: Timestamp,
    ) -> IdentityResult<RotationRecord> {
        // (1) Resolve the target identity (read-only). An unknown id cannot be the
        // identity this rotation targets → IdentityMismatch, with no state change.
        let scheme_tag = identities
            .get(id)
            .ok_or(IdentityError::IdentityMismatch)?
            .scheme_tag
            .clone();

        // (2) Validate the new key's byte format under the identity's OWN scheme BEFORE
        // any mutation. An unregistered scheme → SchemeUnsupported; malformed bytes →
        // KeyFormatInvalid. Either way nothing is touched (atomic — Requirement 11.x).
        registry
            .resolve(&scheme_tag)?
            .validate_verifying_key(new_key.as_bytes())?;

        // (3) All validation passed: apply the rotation effect. The identity is present
        // (checked in step 1) and we hold the only &mut, so this lookup cannot fail.
        let identity = identities
            .get_mut(id)
            .expect("identity present (checked above)");
        let old_key = identity.active_key.clone();
        identity.active_key = new_key.clone();
        identity.retired_keys.push(old_key.clone());
        // `id`, `kind` and `created_at` are deliberately left unchanged (Requirement 11.2).

        // Record the rotation in this identity's history (Requirement 11.3).
        let record = RotationRecord {
            old_key,
            new_key: new_key.clone(),
            rotated_at,
        };
        self.rotation_history
            .entry(id.clone())
            .or_default()
            .push(record.clone());

        Ok(record)
    }

    /// Returns `id`'s ordered key-rotation history (oldest first), or an empty slice if
    /// the identity has never been rotated (Requirement 11.3).
    #[inline]
    pub fn history_of(&self, id: &IdentityId) -> &[RotationRecord] {
        self.rotation_history
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The number of rotations recorded for `id`.
    #[inline]
    pub fn rotation_count(&self, id: &IdentityId) -> usize {
        self.rotation_history.get(id).map_or(0, Vec::len)
    }

    /// Registers `guardians` and a recovery `threshold` (M) for the iFay `id` (design
    /// *Recovery_Service*: `configureGuardians`; Requirements 12.1, 12.2, 12.3).
    ///
    /// The supplied `guardians` are **de-duplicated** into a [`BTreeSet`] (a guardian key
    /// counts once toward `N` no matter how many times it appears, Requirement 12.1), and
    /// `N` is taken as the size of that de-duplicated set. The threshold must satisfy
    /// `1 ≤ M ≤ N` (Requirement 12.2).
    ///
    /// All validation runs **before** any state is touched, so a rejected request is
    /// atomic and leaves any existing configuration unchanged:
    ///
    /// 1. **Resolve the target.** The identity must exist; an unknown `id` is rejected
    ///    with [`IdentityMismatch`](IdentityError::IdentityMismatch) — a configuration
    ///    declares a target identity, and a target that is not on record cannot be the
    ///    identity it is for. **Nothing** is mutated.
    /// 2. **Validate the threshold.** With `N` = de-duplicated guardian count, a
    ///    `threshold` of `0` (M < 1) or `threshold > N` (M > N) — including the empty
    ///    guardian set, where every positive M exceeds `N = 0` — is rejected with
    ///    [`RecoveryConfigInvalid`](IdentityError::RecoveryConfigInvalid), leaving any
    ///    **existing** guardian config for `id` unchanged (Requirement 12.3).
    /// 3. **Store the config.** Only after validation passes is the [`GuardianConfig`]
    ///    `{ ifay, guardians, threshold }` recorded, replacing any prior config for `id`.
    ///
    /// # Authorization is the caller's job (Requirement 12.1)
    ///
    /// This method does **not** check *who* may configure guardians. As with
    /// [`rotate_key`](RecoveryService::rotate_key), `Identity_Core` authenticates the
    /// signed configuration (the iFay's active key signs) *before* this effect is applied.
    pub fn configure_guardians(
        &mut self,
        identities: &IdentityService,
        id: &IdentityId,
        guardians: &[VerifyingKey],
        threshold: u32,
    ) -> IdentityResult<()> {
        // (1) Resolve the target identity (read-only). An unknown id cannot be the
        // identity this configuration targets → IdentityMismatch, with no state change.
        if identities.get(id).is_none() {
            return Err(IdentityError::IdentityMismatch);
        }

        // De-duplicate the guardian set BEFORE validating the threshold, so N counts each
        // distinct guardian key once (Requirement 12.1).
        let guardians: BTreeSet<VerifyingKey> = guardians.iter().cloned().collect();
        let n = guardians.len() as u32;

        // (2) Validate 1 ≤ M ≤ N BEFORE any mutation. M = 0 (below 1) or M > N (above the
        // guardian count, including the empty-set case where every positive M > 0 = N) →
        // RecoveryConfigInvalid, leaving any existing config untouched (Requirement 12.3).
        if threshold < 1 || threshold > n {
            return Err(IdentityError::RecoveryConfigInvalid);
        }

        // (3) Validation passed: record the configuration, replacing any prior one.
        self.guardian_configs.insert(
            id.clone(),
            GuardianConfig {
                ifay: id.clone(),
                guardians,
                threshold,
            },
        );

        Ok(())
    }

    /// Submits one guardian's approval of rotating `id`'s active key to `new_key`,
    /// accumulating de-duplicated approvals and performing the rotation once the threshold
    /// is reached (design *Recovery_Service*: `submitRecoveryApproval`; Requirements 12.4,
    /// 12.5, 12.6).
    ///
    /// Approvals are accumulated in a per-`(identity, candidate new key)`
    /// [`RecoverySession`] and **de-duplicated by approving guardian**, so repeated
    /// approvals from the same `guardian_key` count exactly once toward the threshold
    /// (Requirement 12.5). When the de-duplicated approval count reaches the configured
    /// threshold `M`, the active key is rotated to `new_key` by **reusing**
    /// [`rotate_key`](RecoveryService::rotate_key) — so the `IdentityId` stays fixed and
    /// the old key is retired and recorded exactly as for a self-signed rotation
    /// (Requirement 12.4).
    ///
    /// All validation runs **before** any state is touched, so a rejected request is
    /// atomic:
    ///
    /// 1. **Resolve the target & its guardian config.** An unknown `id`, or an `id` with
    ///    no guardian configuration, is rejected with
    ///    [`IdentityMismatch`](IdentityError::IdentityMismatch) — no recovery can target
    ///    an identity that is absent or has never configured guardians. **Nothing** is
    ///    mutated.
    /// 2. **Record the approval.** The `guardian_key`'s fingerprint is inserted into the
    ///    session for `(id, new_key)` (created on first approval). Duplicate approvals
    ///    from the same guardian are absorbed by the set (Requirement 12.5).
    /// 3. **Threshold check.** If the de-duplicated approval count is **below** `M`, the
    ///    request returns [`RecoveryThresholdNotMet`](IdentityError::RecoveryThresholdNotMet)
    ///    with the active key left **unchanged** (Requirement 12.6) — the partial session
    ///    is retained so later approvals can still reach the threshold.
    /// 4. **Rotate at threshold.** Once the count reaches `M`, [`rotate_key`] performs the
    ///    active-key swap (validating `new_key` against the identity's own scheme, exactly
    ///    as a self-signed rotation would). On success the session for `(id, new_key)` is
    ///    cleared, and the appended [`RotationRecord`] is returned (Requirement 12.4).
    ///
    /// # Caller-supplied authorization (Requirement 12.1, 12.4)
    ///
    /// This method does **not** verify guardian signatures. `Identity_Core` authenticates
    /// each signed approval (the guardian's signature is valid) *before* invoking this
    /// method; here we additionally enforce that `guardian_key` is a member of the
    /// identity's configured guardian set, and a non-guardian approval is rejected with
    /// [`UnauthorizedActor`](IdentityError::UnauthorizedActor) without recording anything.
    pub fn submit_recovery_approval(
        &mut self,
        identities: &mut IdentityService,
        registry: &SchemeRegistry,
        id: &IdentityId,
        new_key: &VerifyingKey,
        guardian_key: &VerifyingKey,
        rotated_at: Timestamp,
    ) -> IdentityResult<RotationRecord> {
        // (1) The identity must have a guardian configuration. An unknown identity or one
        // that never configured guardians cannot be a recovery target → IdentityMismatch,
        // with no state change.
        let config = self
            .guardian_configs
            .get(id)
            .ok_or(IdentityError::IdentityMismatch)?;

        // The approving key must be one of the configured guardians; a non-guardian
        // approval is unauthorized and records nothing (Requirement 12.1).
        if !config.is_guardian(guardian_key) {
            return Err(IdentityError::UnauthorizedActor);
        }
        let threshold = config.threshold as usize;

        // (2) Record this guardian's approval in the session for (id, new_key),
        // de-duplicating by guardian fingerprint (Requirement 12.5).
        let session_key = (id.clone(), base32_encode(new_key.as_bytes()));
        let session = self
            .sessions
            .entry(session_key.clone())
            .or_insert_with(|| RecoverySession {
                ifay: id.clone(),
                new_key: new_key.clone(),
                approvals: BTreeSet::new(),
            });
        session.approvals.insert(base32_encode(guardian_key.as_bytes()));

        // (3) Below threshold: leave the active key unchanged and keep the partial
        // session for later approvals (Requirement 12.6).
        if session.approval_count() < threshold {
            return Err(IdentityError::RecoveryThresholdNotMet);
        }

        // (4) Threshold reached: reuse rotate_key for the active-key swap, so the
        // IdentityId-invariant guarantee holds identically (Requirement 12.4). rotate_key
        // validates new_key against the identity's own scheme; on its (rare) failure the
        // session is retained unchanged so the rejection stays atomic.
        let record = self.rotate_key(identities, registry, id, new_key, rotated_at)?;

        // Recovery applied: clear the now-consumed session.
        self.sessions.remove(&session_key);

        Ok(record)
    }

    /// Returns the [`GuardianConfig`] registered for `id`, if any (Requirement 12.1).
    #[inline]
    pub fn guardian_config(&self, id: &IdentityId) -> Option<&GuardianConfig> {
        self.guardian_configs.get(id)
    }

    /// The number of distinct guardians that have approved rotating `id` to `new_key` so
    /// far (`0` if no session exists yet) (Requirement 12.5).
    #[inline]
    pub fn approval_count(&self, id: &IdentityId, new_key: &VerifyingKey) -> usize {
        self.sessions
            .get(&(id.clone(), base32_encode(new_key.as_bytes())))
            .map_or(0, RecoverySession::approval_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_service::IdentityService;
    use crate::ownership::OwnershipRegistry;
    use crate::pocket::PocketBinding;
    use crate::scheme::{ByteFormat, SchemeDescriptor};
    use crate::types::{IdentityKind, SchemeTag};

    /// A valid 32-byte ed25519 verifying key whose bytes vary with `seed`.
    fn vk(seed: u8) -> VerifyingKey {
        let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        VerifyingKey::new(bytes)
    }

    /// Fresh collaborators plus a recovery service for a rotation test.
    fn fixtures() -> (
        SchemeRegistry,
        OwnershipRegistry,
        PocketBinding,
        IdentityService,
        RecoveryService,
    ) {
        (
            SchemeRegistry::default(),
            OwnershipRegistry::new(),
            PocketBinding::new(),
            IdentityService::new(),
            RecoveryService::new(),
        )
    }

    /// Creates a reference-scheme iFay with active key `vk(key_seed)` and returns its id.
    fn make_ifay(
        registry: &SchemeRegistry,
        ownership: &mut OwnershipRegistry,
        binding: &mut PocketBinding,
        svc: &mut IdentityService,
        key_seed: u8,
        created_at: Timestamp,
    ) -> IdentityId {
        svc.create_ifay(
            registry,
            ownership,
            binding,
            &SchemeTag::ed25519(),
            &vk(key_seed),
            created_at,
        )
        .expect("valid ed25519 vk")
    }

    // --- rotate_key: happy path (Requirements 11.1, 11.2, 11.3) ------------

    #[test]
    fn rotate_sets_new_active_retires_old_and_records_history() {
        // Requirements 11.1/11.3: new key becomes active, old key is retired, and a
        // RotationRecord {old, new, rotated_at} is appended.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let created_at = Timestamp::from_secs(1_000);
        let id = make_ifay(&registry, &mut ownership, &mut binding, &mut svc, 0, created_at);

        let old_key = svc.get(&id).unwrap().active_key.clone();
        let new_key = vk(1);
        let rotated_at = Timestamp::from_secs(2_000);

        let record = recovery
            .rotate_key(&mut svc, &registry, &id, &new_key, rotated_at)
            .expect("valid new key");

        // The returned record describes the rotation.
        assert_eq!(record.old_key, old_key);
        assert_eq!(record.new_key, new_key);
        assert_eq!(record.rotated_at, rotated_at);

        // The identity now carries the new active key and the retired old key.
        let identity = svc.get(&id).unwrap();
        assert_eq!(identity.active_key, new_key);
        assert_eq!(identity.retired_keys, vec![old_key]);

        // History recorded exactly this one rotation.
        assert_eq!(recovery.rotation_count(&id), 1);
        assert_eq!(recovery.history_of(&id), &[record]);
    }

    #[test]
    fn rotate_keeps_identity_id_kind_and_created_at_invariant() {
        // Requirement 11.2: IdentityId (and kind/created_at) is stable across a rotation,
        // so the Pocket binding and ownership relationships are unaffected.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let created_at = Timestamp::from_secs(1_000);
        let id = make_ifay(&registry, &mut ownership, &mut binding, &mut svc, 0, created_at);

        // Snapshot the invariants tied to the id.
        let pocket_key_before = binding.pocket_key(&id);
        let owner_before = ownership.owner_of(&id).cloned();
        assert_eq!(svc.get(&id).unwrap().kind, IdentityKind::IFay);

        recovery
            .rotate_key(&mut svc, &registry, &id, &vk(1), Timestamp::from_secs(2_000))
            .unwrap();

        // The same id still resolves to the same record, kind and created_at.
        let identity = svc.get(&id).unwrap();
        assert_eq!(identity.id, id);
        assert_eq!(identity.kind, IdentityKind::IFay);
        assert_eq!(identity.created_at, created_at);

        // Pocket binding and ownership keyed by the (unchanged) id are unaffected.
        assert_eq!(binding.pocket_key(&id), pocket_key_before);
        assert_eq!(ownership.owner_of(&id).cloned(), owner_before);
    }

    // --- rotate_key: rotating twice accumulates retired keys & history -----

    #[test]
    fn rotating_twice_accumulates_two_retired_keys_and_two_records() {
        // Requirements 11.1/11.3: successive rotations chain — each old active key is
        // retired in order, and one RotationRecord is appended per rotation.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );

        let key0 = svc.get(&id).unwrap().active_key.clone(); // initial active key
        let key1 = vk(1);
        let key2 = vk(2);

        let rec1 = recovery
            .rotate_key(&mut svc, &registry, &id, &key1, Timestamp::from_secs(10))
            .unwrap();
        let rec2 = recovery
            .rotate_key(&mut svc, &registry, &id, &key2, Timestamp::from_secs(20))
            .unwrap();

        // Final state: active = key2, retired = [key0, key1] (in rotation order).
        let identity = svc.get(&id).unwrap();
        assert_eq!(identity.active_key, key2);
        assert_eq!(identity.retired_keys, vec![key0.clone(), key1.clone()]);

        // Two history records chaining old→new across the two rotations.
        assert_eq!(recovery.rotation_count(&id), 2);
        assert_eq!(recovery.history_of(&id), &[rec1.clone(), rec2.clone()]);
        assert_eq!(rec1.old_key, key0);
        assert_eq!(rec1.new_key, key1);
        assert_eq!(rec2.old_key, key1);
        assert_eq!(rec2.new_key, key2);
    }

    // --- rotate_key: malformed new key is rejected atomically (11.x) -------

    #[test]
    fn rotate_with_malformed_new_key_is_key_format_invalid_and_changes_nothing() {
        // A new key violating the identity's scheme ByteFormat → KeyFormatInvalid, and
        // NOTHING changes (active key, retired keys and history are all untouched).
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let before_active = svc.get(&id).unwrap().active_key.clone();

        // ed25519 requires exactly 32 bytes.
        let bad = VerifyingKey::new(vec![0u8; 31]);
        let result = recovery.rotate_key(&mut svc, &registry, &id, &bad, Timestamp::from_secs(2));

        assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        // Identity unchanged: active key kept, no retired keys, no history.
        let identity = svc.get(&id).unwrap();
        assert_eq!(identity.active_key, before_active);
        assert!(identity.retired_keys.is_empty());
        assert_eq!(recovery.rotation_count(&id), 0);
        assert!(recovery.history_of(&id).is_empty());
    }

    #[test]
    fn rotate_validates_new_key_against_the_identitys_own_scheme() {
        // The new key is validated against the identity's scheme, not a hard-coded
        // ed25519 length: under a custom 8-byte scheme, an 8-byte new key is accepted.
        let mut registry = SchemeRegistry::empty();
        let tag = SchemeTag::new("vk8");
        registry
            .register(SchemeDescriptor::new(
                tag.clone(),
                ByteFormat::exact(8),
                ByteFormat::exact(8),
                ByteFormat::exact(16),
            ))
            .expect("fresh registry");
        let mut ownership = OwnershipRegistry::new();
        let mut binding = PocketBinding::new();
        let mut svc = IdentityService::new();
        let mut recovery = RecoveryService::new();

        let id = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &VerifyingKey::new(vec![1u8; 8]),
                Timestamp::from_secs(1),
            )
            .expect("8-byte vk valid under vk8 scheme");

        // An 8-byte new key rotates successfully under the vk8 scheme.
        let new_key = VerifyingKey::new(vec![2u8; 8]);
        recovery
            .rotate_key(&mut svc, &registry, &id, &new_key, Timestamp::from_secs(2))
            .expect("8-byte new key valid under vk8 scheme");
        assert_eq!(svc.get(&id).unwrap().active_key, new_key);

        // A 32-byte (ed25519-sized) new key is rejected under this 8-byte scheme.
        let result = recovery.rotate_key(
            &mut svc,
            &registry,
            &id,
            &VerifyingKey::new(vec![3u8; 32]),
            Timestamp::from_secs(3),
        );
        assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        // Active key kept at the successful 8-byte rotation; one history record only.
        assert_eq!(svc.get(&id).unwrap().active_key, new_key);
        assert_eq!(recovery.rotation_count(&id), 1);
    }

    // --- rotate_key: unknown identity is rejected with no state change -----

    #[test]
    fn rotate_unknown_identity_is_identity_mismatch_and_changes_nothing() {
        // Rotating an identity that is not on record → IdentityMismatch, with no state
        // change (no identity touched, no history recorded).
        let (registry, _ownership, _binding, mut svc, mut recovery) = fixtures();
        // Derive a well-formed id that was never created in `svc`.
        let unknown = crate::identity_id::derive_identity_id(
            &registry,
            &SchemeTag::ed25519(),
            &vk(123),
        )
        .unwrap();

        let result =
            recovery.rotate_key(&mut svc, &registry, &unknown, &vk(124), Timestamp::from_secs(2));

        assert_eq!(result, Err(IdentityError::IdentityMismatch));
        // Nothing created or recorded.
        assert!(svc.is_empty());
        assert_eq!(recovery.rotation_count(&unknown), 0);
        assert!(recovery.history_of(&unknown).is_empty());
    }

    // --- configure_guardians: valid M-of-N (Requirements 12.1, 12.2) -------

    #[test]
    fn configure_guardians_records_dedup_set_and_threshold() {
        // Requirement 12.1/12.2: a valid 2-of-3 config is recorded with the de-duplicated
        // guardian set and threshold.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );

        // Supply a duplicate guardian to confirm N counts distinct keys only.
        let guardians = [vk(10), vk(11), vk(12), vk(10)];
        recovery
            .configure_guardians(&svc, &id, &guardians, 2)
            .expect("2-of-3 is valid");

        let config = recovery.guardian_config(&id).expect("config stored");
        assert_eq!(config.ifay, id);
        assert_eq!(config.threshold, 2);
        // The duplicate vk(10) is collapsed: N = 3, not 4.
        assert_eq!(config.guardian_count(), 3);
        assert!(config.is_guardian(&vk(10)));
        assert!(config.is_guardian(&vk(11)));
        assert!(config.is_guardian(&vk(12)));
        assert!(!config.is_guardian(&vk(99)));
    }

    #[test]
    fn configure_guardians_allows_m_equal_n() {
        // Requirement 12.2: M = N (3-of-3) is the upper bound and is accepted.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11), vk(12)], 3)
            .expect("3-of-3 is valid");
        assert_eq!(recovery.guardian_config(&id).unwrap().threshold, 3);
    }

    // --- configure_guardians: reject M = 0 and M > N (Requirement 12.3) ----

    #[test]
    fn configure_guardians_rejects_zero_threshold_leaving_config_unchanged() {
        // Requirement 12.3: M < 1 → RecoveryConfigInvalid, existing config unchanged.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );

        // Seed a valid prior config to prove a rejected reconfigure leaves it intact.
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11)], 2)
            .unwrap();
        let before = recovery.guardian_config(&id).cloned();

        let result = recovery.configure_guardians(&svc, &id, &[vk(10), vk(11)], 0);
        assert_eq!(result, Err(IdentityError::RecoveryConfigInvalid));
        // Existing config is untouched (Requirement 12.3).
        assert_eq!(recovery.guardian_config(&id).cloned(), before);
    }

    #[test]
    fn configure_guardians_rejects_threshold_above_guardian_count() {
        // Requirement 12.3: M > N (3-of-2) → RecoveryConfigInvalid, no config recorded.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );

        let result = recovery.configure_guardians(&svc, &id, &[vk(10), vk(11)], 3);
        assert_eq!(result, Err(IdentityError::RecoveryConfigInvalid));
        assert!(recovery.guardian_config(&id).is_none());
    }

    #[test]
    fn configure_guardians_rejects_positive_threshold_with_empty_guardian_set() {
        // Requirement 12.3: with N = 0, every M ≥ 1 exceeds N → RecoveryConfigInvalid.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let result = recovery.configure_guardians(&svc, &id, &[], 1);
        assert_eq!(result, Err(IdentityError::RecoveryConfigInvalid));
        assert!(recovery.guardian_config(&id).is_none());
    }

    #[test]
    fn configure_guardians_unknown_identity_is_identity_mismatch() {
        // An identity not on record cannot be configured → IdentityMismatch, no config.
        let (registry, _ownership, _binding, svc, mut recovery) = fixtures();
        let unknown =
            crate::identity_id::derive_identity_id(&registry, &SchemeTag::ed25519(), &vk(200))
                .unwrap();
        let result = recovery.configure_guardians(&svc, &unknown, &[vk(10), vk(11)], 1);
        assert_eq!(result, Err(IdentityError::IdentityMismatch));
        assert!(recovery.guardian_config(&unknown).is_none());
    }

    // --- submit_recovery_approval: threshold reached rotates (Req 12.4) ----

    #[test]
    fn approvals_reaching_threshold_rotate_active_key_keeping_identity_id() {
        // Requirement 12.4: when de-duplicated approvals reach M, the active key is
        // rotated to new_key (via rotate_key) and the IdentityId stays fixed.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let old_key = svc.get(&id).unwrap().active_key.clone();
        let new_key = vk(100);

        // Snapshot id-keyed invariants to confirm recovery leaves them untouched.
        let pocket_key_before = binding.pocket_key(&id);
        let owner_before = ownership.owner_of(&id).cloned();

        // 2-of-3 guardians.
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11), vk(12)], 2)
            .unwrap();

        // First approval: below threshold → RecoveryThresholdNotMet, active key unchanged.
        let first = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &new_key,
            &vk(10),
            Timestamp::from_secs(50),
        );
        assert_eq!(first, Err(IdentityError::RecoveryThresholdNotMet));
        assert_eq!(svc.get(&id).unwrap().active_key, old_key);
        assert_eq!(recovery.approval_count(&id, &new_key), 1);

        // Second approval from a DIFFERENT guardian: threshold met → rotation applied.
        let record = recovery
            .submit_recovery_approval(
                &mut svc,
                &registry,
                &id,
                &new_key,
                &vk(11),
                Timestamp::from_secs(60),
            )
            .expect("threshold reached → rotation");

        // The active key is now new_key, old key retired, IdentityId unchanged.
        let identity = svc.get(&id).unwrap();
        assert_eq!(identity.id, id);
        assert_eq!(identity.active_key, new_key);
        assert_eq!(identity.retired_keys, vec![old_key.clone()]);
        assert_eq!(record.old_key, old_key);
        assert_eq!(record.new_key, new_key);
        assert_eq!(record.rotated_at, Timestamp::from_secs(60));
        assert_eq!(recovery.rotation_count(&id), 1);

        // Pocket binding and ownership keyed by the (unchanged) id are unaffected.
        assert_eq!(binding.pocket_key(&id), pocket_key_before);
        assert_eq!(ownership.owner_of(&id).cloned(), owner_before);

        // The consumed session is cleared.
        assert_eq!(recovery.approval_count(&id, &new_key), 0);
    }

    // --- submit_recovery_approval: duplicate guardian counts once (12.5) ---

    #[test]
    fn duplicate_approvals_from_same_guardian_count_once() {
        // Requirement 12.5: repeated approvals from the same guardian count once, so a
        // 2-of-3 recovery is NOT triggered by one guardian approving twice.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let old_key = svc.get(&id).unwrap().active_key.clone();
        let new_key = vk(100);
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11), vk(12)], 2)
            .unwrap();

        // Same guardian approves twice.
        let first = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &new_key,
            &vk(10),
            Timestamp::from_secs(50),
        );
        assert_eq!(first, Err(IdentityError::RecoveryThresholdNotMet));
        let second = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &new_key,
            &vk(10),
            Timestamp::from_secs(51),
        );
        assert_eq!(second, Err(IdentityError::RecoveryThresholdNotMet));

        // De-duplicated count is still 1, active key unchanged, no rotation.
        assert_eq!(recovery.approval_count(&id, &new_key), 1);
        assert_eq!(svc.get(&id).unwrap().active_key, old_key);
        assert_eq!(recovery.rotation_count(&id), 0);
    }

    // --- submit_recovery_approval: below threshold (Requirement 12.6) ------

    #[test]
    fn below_threshold_returns_threshold_not_met_and_keeps_active_key() {
        // Requirement 12.6: with fewer distinct approvals than M, recovery is refused and
        // the active key is unchanged.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let old_key = svc.get(&id).unwrap().active_key.clone();
        let new_key = vk(100);
        // 3-of-3 needs three distinct guardians.
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11), vk(12)], 3)
            .unwrap();

        for (g, t) in [(vk(10), 50u64), (vk(11), 60)] {
            let result = recovery.submit_recovery_approval(
                &mut svc,
                &registry,
                &id,
                &new_key,
                &g,
                Timestamp::from_secs(t),
            );
            assert_eq!(result, Err(IdentityError::RecoveryThresholdNotMet));
        }
        // Two of three distinct approvals: still below threshold, active key untouched.
        assert_eq!(recovery.approval_count(&id, &new_key), 2);
        assert_eq!(svc.get(&id).unwrap().active_key, old_key);
        assert_eq!(recovery.rotation_count(&id), 0);
    }

    #[test]
    fn approvals_for_different_candidate_keys_do_not_cross_count() {
        // Requirement 12.4: each candidate new_key has its own session, so approvals for
        // different keys never combine to reach the threshold.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let old_key = svc.get(&id).unwrap().active_key.clone();
        let candidate_a = vk(100);
        let candidate_b = vk(101);
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11), vk(12)], 2)
            .unwrap();

        // One approval for A, one (different guardian) for B: neither session reaches 2.
        let _ = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &candidate_a,
            &vk(10),
            Timestamp::from_secs(50),
        );
        let _ = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &candidate_b,
            &vk(11),
            Timestamp::from_secs(51),
        );

        assert_eq!(recovery.approval_count(&id, &candidate_a), 1);
        assert_eq!(recovery.approval_count(&id, &candidate_b), 1);
        assert_eq!(svc.get(&id).unwrap().active_key, old_key);
        assert_eq!(recovery.rotation_count(&id), 0);
    }

    // --- submit_recovery_approval: non-guardian & unknown identity ---------

    #[test]
    fn approval_from_non_guardian_is_unauthorized_and_records_nothing() {
        // A key outside the configured guardian set cannot approve → UnauthorizedActor,
        // and no approval is recorded.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let new_key = vk(100);
        recovery
            .configure_guardians(&svc, &id, &[vk(10), vk(11)], 1)
            .unwrap();

        let result = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &new_key,
            &vk(99), // not a guardian
            Timestamp::from_secs(50),
        );
        assert_eq!(result, Err(IdentityError::UnauthorizedActor));
        // Nothing recorded, active key unchanged.
        assert_eq!(recovery.approval_count(&id, &new_key), 0);
        assert_eq!(recovery.rotation_count(&id), 0);
    }

    #[test]
    fn approval_for_identity_without_config_is_identity_mismatch() {
        // Requirement: an identity with no guardian configuration cannot be a recovery
        // target → IdentityMismatch (covers both unknown identity and unconfigured one).
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        // No configure_guardians call for `id`.
        let result = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &vk(100),
            &vk(10),
            Timestamp::from_secs(50),
        );
        assert_eq!(result, Err(IdentityError::IdentityMismatch));

        // Also an entirely unknown identity.
        let unknown =
            crate::identity_id::derive_identity_id(&registry, &SchemeTag::ed25519(), &vk(200))
                .unwrap();
        let result = recovery.submit_recovery_approval(
            &mut svc,
            &registry,
            &unknown,
            &vk(100),
            &vk(10),
            Timestamp::from_secs(50),
        );
        assert_eq!(result, Err(IdentityError::IdentityMismatch));
    }

    #[test]
    fn single_guardian_one_of_one_recovery_rotates_immediately() {
        // A 1-of-1 config rotates on the first (only) guardian's approval.
        let (registry, mut ownership, mut binding, mut svc, mut recovery) = fixtures();
        let id = make_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &mut svc,
            0,
            Timestamp::from_secs(1),
        );
        let old_key = svc.get(&id).unwrap().active_key.clone();
        let new_key = vk(100);
        recovery
            .configure_guardians(&svc, &id, &[vk(10)], 1)
            .unwrap();

        let record = recovery
            .submit_recovery_approval(
                &mut svc,
                &registry,
                &id,
                &new_key,
                &vk(10),
                Timestamp::from_secs(50),
            )
            .expect("1-of-1 rotates on first approval");
        assert_eq!(record.old_key, old_key);
        assert_eq!(record.new_key, new_key);
        assert_eq!(svc.get(&id).unwrap().active_key, new_key);
        assert_eq!(svc.get(&id).unwrap().id, id);
    }
}
