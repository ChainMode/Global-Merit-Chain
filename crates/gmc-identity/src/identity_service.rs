//! `Identity_Service` — iFay/coFay creation, `IdentityId` derivation, Pocket binding.
//!
//! This module implements the design's *Identity_Service* component together with the
//! `Identity` record from *Data Models → 身份标识与身份记录*. Task 7.1 lands iFay
//! creation ([`IdentityService::create_ifay`]); task 11.3 will add `create_cofay` on the
//! **same** shape (the authenticated `Identity_Core` payload path).
//!
//! ## The `Identity` record (design *Data Models*)
//!
//! [`Identity`] mirrors the design record one-to-one and is defined here **public** so
//! the later `Identity_Core` (applied-nonce updates) and `Recovery_Service`
//! (active/retired key changes) can reuse the *same* record type rather than redefining
//! it:
//!
//! ```text
//! Identity { id, kind, scheme_tag, active_key, retired_keys, applied_nonce, created_at }
//! ```
//!
//! Its fields are public because they are exactly the per-identity mutable state those
//! later modules own: `Identity_Core` bumps `applied_nonce` (Requirement 5.5), and
//! `Recovery_Service` moves `active_key` into `retired_keys` on rotation (Requirement
//! 11.1) — all while `id` stays fixed (Requirement 11.2). Keeping the record a plain
//! data holder avoids a second source of truth.
//!
//! ## Forward-compatible service shape (coordinate with task 11)
//!
//! [`IdentityService`] owns **only** the `identities: BTreeMap<IdentityId, Identity>`
//! map — the design's `IdentityState.identities` aggregate field — and operates on its
//! sibling collaborators (`SchemeRegistry`, `OwnershipRegistry`, `PocketBinding`) **by
//! reference**. This is deliberate so the future `IdentityState` can hold an
//! `IdentityService` alongside the other registries as *separate fields* and still call
//! creation methods that mutate several of them at once: borrowing distinct struct
//! fields (`&self.registry`, `&mut self.ownership`, `&mut self.binding`,
//! `&mut self.service`) is allowed by the borrow checker, whereas a method that borrowed
//! all of `IdentityState` would not be.
//!
//! Task 11.3's `create_cofay` will therefore be a second method with the same collaborator
//! signature — deriving the coFay's `IdentityId`, calling [`OwnershipRegistry::attach`]
//! (instead of `register_root`), binding a pocket, and inserting a `CoFay`-kind
//! [`Identity`] into the same `identities` map — after `Identity_Core` has authenticated
//! the operation.

use std::collections::BTreeMap;

use gmc_core::types::Timestamp;

use crate::error::IdentityResult;
use crate::identity_id::{derive_identity_id, IdentityId};
use crate::ownership::OwnershipRegistry;
use crate::pocket::PocketBinding;
use crate::scheme::SchemeRegistry;
use crate::types::{IdentityKind, Nonce, SchemeTag, VerifyingKey};

/// An identity record — the per-identity state tracked by this layer (design
/// *Data Models*: `Identity`).
///
/// Defined `public` (with public fields) so the later `Identity_Core` and
/// `Recovery_Service` tasks reuse this exact type. Note the **separation** the design
/// calls out: `id` is derived once at creation from the *initial* verifying key and
/// never changes, while [`Identity::active_key`] may change under rotation/recovery —
/// this is the data-model support for "`IdentityId` stays stable after a key change"
/// (Requirement 11.2). Ownership ("who owns this identity") is **not** stored here; it
/// lives in the [`OwnershipRegistry`] (an iFay is its own self-sovereign root, recorded
/// as a depth-0 root node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The stable identifier, derived once from `(scheme_tag, initial vk)` and never
    /// re-derived (Requirement 2.2; stable across rotation per 11.2).
    pub id: IdentityId,
    /// Whether this is a self-sovereign iFay or a collective coFay.
    pub kind: IdentityKind,
    /// The scheme this identity was derived/authenticated under (Requirement 2.2).
    pub scheme_tag: SchemeTag,
    /// The current active verifying key (changes on rotation/recovery, Requirement 11.1).
    pub active_key: VerifyingKey,
    /// Verifying keys retired by rotation; signing with a retired key is unauthorized
    /// (Requirements 11.1, 11.4).
    pub retired_keys: Vec<VerifyingKey>,
    /// The greatest applied operation nonce for this identity (Requirements 5.2, 5.5).
    pub applied_nonce: Nonce,
    /// The creation timestamp (Requirement 2.1).
    pub created_at: Timestamp,
}

impl Identity {
    /// Builds a freshly-created iFay record: `kind = IFay`, the given `active_key`, no
    /// retired keys, and `applied_nonce = 0` (no operation applied yet).
    ///
    /// The `scheme_tag` is taken from `id.scheme_tag()` so the record's scheme is always
    /// consistent with the identifier it was derived under.
    fn new_ifay(id: IdentityId, active_key: VerifyingKey, created_at: Timestamp) -> Self {
        let scheme_tag = id.scheme_tag().clone();
        Identity {
            id,
            kind: IdentityKind::IFay,
            scheme_tag,
            active_key,
            retired_keys: Vec::new(),
            applied_nonce: 0,
            created_at,
        }
    }

    /// Builds a freshly-created coFay record: `kind = CoFay`, the given `active_key`, no
    /// retired keys, and `applied_nonce = 0` (no operation applied yet).
    ///
    /// Identical in shape to [`Identity::new_ifay`] save for `kind = CoFay`: the
    /// per-identity record carries the same fields whether the identity is a
    /// self-sovereign iFay or a collective coFay. The distinction "who owns this coFay"
    /// is **not** stored here — it lives in the [`OwnershipRegistry`] (the coFay is
    /// attached beneath its owner by [`IdentityService::create_cofay`]). The
    /// `scheme_tag` is taken from `id.scheme_tag()` so the record's scheme is always
    /// consistent with the identifier it was derived under.
    fn new_cofay(id: IdentityId, active_key: VerifyingKey, created_at: Timestamp) -> Self {
        let scheme_tag = id.scheme_tag().clone();
        Identity {
            id,
            kind: IdentityKind::CoFay,
            scheme_tag,
            active_key,
            retired_keys: Vec::new(),
            applied_nonce: 0,
            created_at,
        }
    }
}

/// The identity service: owns the `IdentityId -> Identity` records and creates new
/// identities over borrowed sibling collaborators (design *Identity_Service* /
/// `IdentityState.identities`).
///
/// See the module docs for why this owns only the records map and borrows the registry,
/// ownership registry and pocket binding — it keeps the future `IdentityState` aggregate
/// composable without borrow-checker conflicts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityService {
    /// All identity records keyed by id (`BTreeMap` for deterministic iteration order).
    identities: BTreeMap<IdentityId, Identity>,
}

impl IdentityService {
    /// Creates an empty identity service.
    #[inline]
    pub fn new() -> Self {
        IdentityService {
            identities: BTreeMap::new(),
        }
    }

    /// Creates an **iFay** self-sovereign identity (design *Identity_Service*:
    /// `createIFay`; flow 1; Requirements 2.1, 2.5).
    ///
    /// Steps, in the design's fixed order — **all validation runs before any state is
    /// touched**, so a rejected request is atomic and leaves every collaborator
    /// unchanged:
    ///
    /// 1. **Derive + validate.** [`derive_identity_id`] resolves `tag` (unregistered →
    ///    [`SchemeUnsupported`](crate::error::IdentityError::SchemeUnsupported)) and
    ///    validates `vk`'s byte format (malformed → 
    ///    [`KeyFormatInvalid`](crate::error::IdentityError::KeyFormatInvalid)). On either
    ///    error **nothing is created**: no ownership root, no pocket, no record.
    /// 2. **Record ownership as a root.** The iFay owns itself (self-sovereign), recorded
    ///    by [`OwnershipRegistry::register_root`] as a depth-0 root (owner = `None`,
    ///    `path = [id]`) — the anchor (`path[0]`) of any coFay later attached beneath it.
    /// 3. **Store the record.** A `kind = IFay` [`Identity`] with `active_key = vk`,
    ///    empty `retired_keys`, `applied_nonce = 0`, and the given `created_at`.
    /// 4. **Bind a MeritPocket.** [`PocketBinding::bind`] establishes the one-to-one
    ///    binding keyed by the identity's canonical `FayID`.
    ///
    /// Returns the derived [`IdentityId`].
    ///
    /// ## Idempotent re-creation
    ///
    /// Because the derivation is deterministic, calling `create_ifay` again with the same
    /// `(tag, vk)` derives the **same** `IdentityId`. This is treated as an **idempotent
    /// no-op**: the existing record is left untouched (its `created_at`, `active_key`,
    /// retired keys and applied nonce are **not** overwritten), and the existing id is
    /// returned. This mirrors the idempotent posture of
    /// [`OwnershipRegistry::register_root`] and [`PocketBinding::bind`] and preserves the
    /// "exactly one identity / one pocket per id" invariant.
    pub fn create_ifay(
        &mut self,
        registry: &SchemeRegistry,
        ownership: &mut OwnershipRegistry,
        binding: &mut PocketBinding,
        tag: &SchemeTag,
        vk: &VerifyingKey,
        created_at: Timestamp,
    ) -> IdentityResult<IdentityId> {
        // (1) Validate scheme + vk format and derive the id BEFORE any mutation. A
        // failure here returns early with no side effect (atomic — Requirements 2.5).
        let id = derive_identity_id(registry, tag, vk)?;

        // Idempotent: re-creating an already-present iFay leaves its record untouched.
        if self.identities.contains_key(&id) {
            // Keep ownership/binding consistent without overwriting anything: both
            // register_root and bind are themselves idempotent no-ops for a present id.
            ownership.register_root(&id)?;
            binding.bind(&id)?;
            return Ok(id);
        }

        // (2) The iFay owns itself: record it as a depth-0 ownership root.
        ownership.register_root(&id)?;

        // (3) Store the iFay record: kind = IFay, active_key = vk, no retired keys,
        // applied_nonce = 0, created_at as given.
        self.identities
            .insert(id.clone(), Identity::new_ifay(id.clone(), vk.clone(), created_at));

        // (4) Bind its one MeritPocket (keyed by the canonical FayID).
        binding.bind(&id)?;

        Ok(id)
    }

    /// Creates a **coFay** collective identity owned by `owner`, as the committed effect
    /// of an authenticated `Identity_Core` `CreateCoFay` operation (design
    /// *Identity_Service*: `createCoFay`; flow 3; Requirements 6.1, 6.7).
    ///
    /// This mirrors [`create_ifay`](Self::create_ifay)'s borrow-friendly collaborator
    /// signature so [`crate::identity_core::IdentityState::apply`] can call it while
    /// holding distinct `&self.registry` / `&mut self.ownership` / `&mut self.binding`
    /// borrows. **Authentication (verify → authorize → nonce) is the caller's job** —
    /// `Identity_Core` runs the full validation chain *before* invoking this method; here
    /// we only perform the committed payload effect.
    ///
    /// Steps, in the design's fixed order — **all fallible validation runs before any
    /// state is touched**, so a rejected request is atomic and leaves every collaborator
    /// unchanged (Requirements 6.4/6.5/6.6, 13.4):
    ///
    /// 1. **Derive + validate.** [`derive_identity_id`] resolves `tag` (the owner's
    ///    scheme tag) and validates `new_cofay_key`'s byte format; a malformed key →
    ///    [`KeyFormatInvalid`](crate::error::IdentityError::KeyFormatInvalid). On error
    ///    **nothing is created** (no attach, no record, no pocket).
    /// 2. **Attach beneath the owner.** [`OwnershipRegistry::attach`] runs the ordered
    ///    `owner exists → no cycle → depth ≤ 16` guard, propagating
    ///    [`OwnerNotFound`](crate::error::IdentityError::OwnerNotFound) /
    ///    [`OwnershipCycle`](crate::error::IdentityError::OwnershipCycle) /
    ///    [`OwnershipDepthExceeded`](crate::error::IdentityError::OwnershipDepthExceeded).
    ///    On any error **nothing is created** — `attach` itself writes nothing on
    ///    failure, and steps 3–4 below never run. Attaching first and only proceeding on
    ///    `Ok` is what makes the whole effect atomic.
    /// 3. **Store the record.** A `kind = CoFay` [`Identity`] with
    ///    `active_key = new_cofay_key`, empty `retired_keys`, `applied_nonce = 0`, and
    ///    the given `created_at`.
    /// 4. **Bind a MeritPocket.** [`PocketBinding::bind`] establishes the coFay's own
    ///    one-to-one binding keyed by its canonical `FayID` (Requirement 6.7).
    ///
    /// Returns the derived coFay [`IdentityId`].
    ///
    /// ## Idempotent re-creation
    ///
    /// As with [`create_ifay`](Self::create_ifay), the derivation is deterministic, so a
    /// re-submitted `CreateCoFay` for an already-present coFay derives the **same** id
    /// and is treated as an **idempotent no-op**: the existing record is left untouched
    /// and the existing id returned (its `created_at` / `active_key` / nonce are not
    /// overwritten). `attach` and `bind` are themselves idempotent for a present id.
    pub fn create_cofay(
        &mut self,
        registry: &SchemeRegistry,
        ownership: &mut OwnershipRegistry,
        binding: &mut PocketBinding,
        owner: &IdentityId,
        new_cofay_key: &VerifyingKey,
        created_at: Timestamp,
    ) -> IdentityResult<IdentityId> {
        // (1) Validate scheme + key format and derive the coFay id BEFORE any mutation.
        // Reuse the owner's scheme tag (the coFay is authenticated under the same
        // scheme). A failure here returns early with no side effect (atomic).
        let id = derive_identity_id(registry, owner.scheme_tag(), new_cofay_key)?;

        // Idempotent: re-creating an already-present coFay leaves its record untouched.
        // Keep ownership/binding consistent without overwriting anything (attach and
        // bind are idempotent no-ops for a present id).
        if self.identities.contains_key(&id) {
            ownership.attach(&id, owner)?;
            binding.bind(&id)?;
            return Ok(id);
        }

        // (2) Attach beneath the owner FIRST: this runs the owner-exists → no-cycle →
        // depth-bound guard and writes nothing on failure. Only on Ok do we proceed to
        // insert the record and bind the pocket, so the whole effect is atomic
        // (Requirements 6.4/6.5/6.6).
        ownership.attach(&id, owner)?;

        // (3) Store the coFay record: kind = CoFay, active_key = new_cofay_key, no
        // retired keys, applied_nonce = 0, created_at as given.
        self.identities.insert(
            id.clone(),
            Identity::new_cofay(id.clone(), new_cofay_key.clone(), created_at),
        );

        // (4) Bind its own independent MeritPocket (Requirement 6.7).
        binding.bind(&id)?;

        Ok(id)
    }

    /// Returns the [`Identity`] record for `id`, if it exists.
    #[inline]
    pub fn get(&self, id: &IdentityId) -> Option<&Identity> {
        self.identities.get(id)
    }

    /// Returns a mutable reference to the [`Identity`] record for `id`, if it exists.
    ///
    /// Exposed for the later `Identity_Core` / `Recovery_Service` tasks that mutate
    /// per-identity state (`applied_nonce`, `active_key`, `retired_keys`).
    #[inline]
    pub fn get_mut(&mut self, id: &IdentityId) -> Option<&mut Identity> {
        self.identities.get_mut(id)
    }

    /// Returns `true` if an identity with `id` is recorded.
    #[inline]
    pub fn contains(&self, id: &IdentityId) -> bool {
        self.identities.contains_key(id)
    }

    /// The number of recorded identities.
    #[inline]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Returns `true` if no identities are recorded.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Iterates over all recorded identities in deterministic id order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&IdentityId, &Identity)> {
        self.identities.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IdentityError;
    use crate::scheme::{ByteFormat, SchemeDescriptor};

    /// A valid 32-byte ed25519 verifying key whose bytes vary with `seed`.
    fn vk(seed: u8) -> VerifyingKey {
        let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        VerifyingKey::new(bytes)
    }

    /// Fresh set of collaborators for a creation test.
    fn fixtures() -> (SchemeRegistry, OwnershipRegistry, PocketBinding, IdentityService) {
        (
            SchemeRegistry::default(),
            OwnershipRegistry::new(),
            PocketBinding::new(),
            IdentityService::new(),
        )
    }

    // --- create_ifay: happy path records the full iFay state ---------------

    #[test]
    fn create_ifay_records_kind_active_key_nonce_and_created_at() {
        // Requirement 2.1: create an iFay, record its VerifyingKey and creation time.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let tag = SchemeTag::ed25519();
        let key = vk(0);
        let created_at = Timestamp::from_secs(1_700_000_000);

        let id = svc
            .create_ifay(&registry, &mut ownership, &mut binding, &tag, &key, created_at)
            .expect("valid ed25519 vk");

        let record = svc.get(&id).expect("identity recorded");
        assert_eq!(record.id, id);
        assert_eq!(record.kind, IdentityKind::IFay);
        assert_eq!(record.scheme_tag, tag);
        assert_eq!(record.active_key, key);
        assert!(record.retired_keys.is_empty());
        assert_eq!(record.applied_nonce, 0);
        assert_eq!(record.created_at, created_at);
        assert_eq!(svc.len(), 1);
    }

    #[test]
    fn create_ifay_owner_is_self_recorded_as_depth_zero_root() {
        // Requirement 2.1: owner = itself (self-sovereign), recorded as an ownership root
        // (owner = None, depth = 0, path = [id]).
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let id = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &vk(1),
                Timestamp::from_secs(1),
            )
            .unwrap();

        assert!(ownership.contains(&id));
        assert_eq!(ownership.owner_of(&id), None); // self-sovereign root
        assert_eq!(ownership.depth_of(&id), Some(0));
        assert_eq!(ownership.path_of(&id), Some(&vec![id.clone()]));
        assert!(ownership.node(&id).unwrap().is_root());
    }

    #[test]
    fn create_ifay_binds_a_resolvable_merit_pocket() {
        // Requirement 10.1/10.3 (via flow 1): a MeritPocket is bound, keyed by the
        // identity's canonical FayID, and pocket_key resolves it.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let id = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &vk(2),
                Timestamp::from_secs(1),
            )
            .unwrap();

        assert_eq!(binding.pocket_key(&id), Some(id.to_fay_id()));
        assert!(binding.pocket(&id).is_some());
        assert_eq!(binding.len(), 1);
    }

    // --- create_ifay: rejection paths are atomic (nothing created) ---------

    #[test]
    fn create_ifay_malformed_vk_is_key_format_invalid_and_creates_nothing() {
        // Requirement 2.5: a vk violating the scheme's ByteFormat → KeyFormatInvalid,
        // and NOTHING is created (no identity, no ownership root, no pocket).
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let bad = VerifyingKey::new(vec![0u8; 31]); // ed25519 requires exactly 32

        let result = svc.create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &SchemeTag::ed25519(),
            &bad,
            Timestamp::from_secs(1),
        );

        assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        assert!(svc.is_empty());
        assert!(ownership.is_empty());
        assert!(binding.is_empty());
    }

    #[test]
    fn create_ifay_unsupported_scheme_is_rejected_and_creates_nothing() {
        // Requirement 1.4 (precondition of 2.x): an unregistered scheme tag →
        // SchemeUnsupported, and NOTHING is created.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let unknown = SchemeTag::new("does-not-exist");

        let result = svc.create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &unknown,
            &vk(3),
            Timestamp::from_secs(1),
        );

        assert_eq!(result, Err(IdentityError::SchemeUnsupported));
        assert!(svc.is_empty());
        assert!(ownership.is_empty());
        assert!(binding.is_empty());
    }

    // --- create_ifay: determinism / injectivity ----------------------------

    #[test]
    fn create_ifay_same_tag_and_vk_derives_same_identity_id() {
        // Requirement 2.3 (Property 1): same (tag, vk) → same IdentityId. Re-creation is
        // an idempotent no-op that leaves the existing record untouched.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let tag = SchemeTag::ed25519();
        let key = vk(9);
        let created_at = Timestamp::from_secs(100);

        let id1 = svc
            .create_ifay(&registry, &mut ownership, &mut binding, &tag, &key, created_at)
            .unwrap();
        let record_before = svc.get(&id1).cloned();

        // Second creation with the SAME (tag, vk) but a different timestamp.
        let id2 = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &key,
                Timestamp::from_secs(999),
            )
            .unwrap();

        assert_eq!(id1, id2);
        // Idempotent: still exactly one identity / pocket, record unchanged (created_at
        // is NOT overwritten by the second call).
        assert_eq!(svc.len(), 1);
        assert_eq!(binding.len(), 1);
        assert_eq!(svc.get(&id1).cloned(), record_before);
        assert_eq!(svc.get(&id1).unwrap().created_at, created_at);
    }

    #[test]
    fn create_ifay_distinct_vks_yield_distinct_identities() {
        // Requirement 2.4 (Property 1): two distinct VerifyingKeys → two distinct ids,
        // each with its own ownership root and pocket.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let tag = SchemeTag::ed25519();

        let id_a = svc
            .create_ifay(&registry, &mut ownership, &mut binding, &tag, &vk(10), Timestamp::from_secs(1))
            .unwrap();
        let id_b = svc
            .create_ifay(&registry, &mut ownership, &mut binding, &tag, &vk(11), Timestamp::from_secs(2))
            .unwrap();

        assert_ne!(id_a, id_b);
        assert_eq!(svc.len(), 2);
        assert_eq!(binding.len(), 2);
        assert_ne!(binding.pocket_key(&id_a), binding.pocket_key(&id_b));
    }

    // --- create_ifay: respects a custom (non-ed25519) scheme format --------

    #[test]
    fn create_ifay_uses_the_supplied_scheme_format() {
        // The vk is validated against the supplied registry's scheme, not a hard-coded
        // ed25519 length: an 8-byte vk is valid under a custom 8-byte scheme.
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

        let key = VerifyingKey::new(vec![5u8; 8]);
        let id = svc
            .create_ifay(&registry, &mut ownership, &mut binding, &tag, &key, Timestamp::from_secs(1))
            .expect("8-byte vk valid under vk8 scheme");
        assert_eq!(svc.get(&id).unwrap().active_key, key);

        // A 32-byte (ed25519-sized) vk is rejected under this 8-byte scheme, atomically.
        let result = svc.create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &tag,
            &VerifyingKey::new(vec![5u8; 32]),
            Timestamp::from_secs(2),
        );
        assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        assert_eq!(svc.len(), 1); // only the valid 8-byte iFay exists
    }

    // --- create_cofay: happy path (Requirements 6.1, 6.2, 6.3, 6.7) --------

    /// Creates a reference-scheme iFay root in the given collaborators and returns its id.
    fn make_root_ifay(
        registry: &SchemeRegistry,
        ownership: &mut OwnershipRegistry,
        binding: &mut PocketBinding,
        svc: &mut IdentityService,
        owner_key: &VerifyingKey,
    ) -> IdentityId {
        svc.create_ifay(
            registry,
            ownership,
            binding,
            &SchemeTag::ed25519(),
            owner_key,
            Timestamp::from_secs(1),
        )
        .expect("valid owner iFay")
    }

    #[test]
    fn create_cofay_records_cofay_kind_attached_under_owner_with_pocket() {
        // Requirement 6.1/6.7: an authenticated CreateCoFay creates a CoFay-kind record,
        // attaches it beneath the owner (depth = owner.depth + 1, root-first path), and
        // binds its own independent MeritPocket.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner_key = vk(1);
        let owner = make_root_ifay(&registry, &mut ownership, &mut binding, &mut svc, &owner_key);

        let cofay_key = vk(2);
        let created_at = Timestamp::from_secs(1_700_000_000);
        let cofay = svc
            .create_cofay(&registry, &mut ownership, &mut binding, &owner, &cofay_key, created_at)
            .expect("owner exists, no cycle, depth ok");

        // The record is a CoFay with the supplied active key and created_at.
        let record = svc.get(&cofay).expect("coFay recorded");
        assert_eq!(record.kind, IdentityKind::CoFay);
        assert_eq!(record.active_key, cofay_key);
        assert!(record.retired_keys.is_empty());
        assert_eq!(record.applied_nonce, 0);
        assert_eq!(record.created_at, created_at);

        // Attached beneath the owner: owner recorded, depth 1, root-first path [owner, cofay].
        assert_eq!(ownership.owner_of(&cofay), Some(&owner));
        assert_eq!(ownership.depth_of(&cofay), Some(1));
        assert_eq!(ownership.path_of(&cofay), Some(&vec![owner.clone(), cofay.clone()]));
        // path[0] is the root iFay (Requirement 6.3).
        assert_eq!(svc.get(&owner).unwrap().kind, IdentityKind::IFay);

        // Its own independent MeritPocket is bound, keyed by its canonical FayID.
        assert_eq!(binding.pocket_key(&cofay), Some(cofay.to_fay_id()));
        assert!(binding.pocket(&cofay).is_some());
        // Two identities (owner iFay + coFay) and two pockets exist.
        assert_eq!(svc.len(), 2);
        assert_eq!(binding.len(), 2);
        assert_ne!(binding.pocket_key(&owner), binding.pocket_key(&cofay));
    }

    #[test]
    fn create_cofay_nested_under_a_cofay_extends_depth_and_path() {
        // A coFay may own another coFay (org-in-org); depth and path extend by one level.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = make_root_ifay(&registry, &mut ownership, &mut binding, &mut svc, &vk(1));

        let mid = svc
            .create_cofay(&registry, &mut ownership, &mut binding, &owner, &vk(2), Timestamp::from_secs(2))
            .unwrap();
        let leaf = svc
            .create_cofay(&registry, &mut ownership, &mut binding, &mid, &vk(3), Timestamp::from_secs(3))
            .unwrap();

        assert_eq!(svc.get(&leaf).unwrap().kind, IdentityKind::CoFay);
        assert_eq!(ownership.depth_of(&leaf), Some(2));
        assert_eq!(
            ownership.path_of(&leaf),
            Some(&vec![owner.clone(), mid.clone(), leaf.clone()])
        );
        assert_eq!(svc.len(), 3);
    }

    // --- create_cofay: rejection paths are atomic (nothing created) --------

    #[test]
    fn create_cofay_malformed_key_is_key_format_invalid_and_creates_nothing() {
        // Requirement 2.5 (reused for coFay): a vk violating the scheme's ByteFormat →
        // KeyFormatInvalid, and NOTHING is created (no attach, no record, no pocket).
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = make_root_ifay(&registry, &mut ownership, &mut binding, &mut svc, &vk(1));
        let before_owner_pocket = binding.pocket(&owner).cloned();

        let bad = VerifyingKey::new(vec![0u8; 31]); // ed25519 requires exactly 32
        let result =
            svc.create_cofay(&registry, &mut ownership, &mut binding, &owner, &bad, Timestamp::from_secs(2));

        assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        // Only the owner iFay exists; nothing was created for the coFay.
        assert_eq!(svc.len(), 1);
        assert_eq!(ownership.len(), 1);
        assert_eq!(binding.len(), 1);
        assert_eq!(binding.pocket(&owner).cloned(), before_owner_pocket);
    }

    #[test]
    fn create_cofay_unknown_owner_is_owner_not_found_and_creates_nothing() {
        // Requirement 6.4: an owner registered in neither ownership nor identity records
        // → OwnerNotFound, and NOTHING is created.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        // A well-formed owner id that was never created as an identity/root.
        let ghost_owner = derive_identity_id(&registry, &SchemeTag::ed25519(), &vk(7)).unwrap();

        let result = svc.create_cofay(
            &registry,
            &mut ownership,
            &mut binding,
            &ghost_owner,
            &vk(2),
            Timestamp::from_secs(2),
        );

        assert_eq!(result, Err(IdentityError::OwnerNotFound));
        assert!(svc.is_empty());
        assert!(ownership.is_empty());
        assert!(binding.is_empty());
    }

    #[test]
    fn create_cofay_self_owning_reattach_is_cycle_and_state_unchanged() {
        // Requirement 6.5: re-submitting CreateCoFay for an EXISTING coFay but naming
        // that coFay itself as the owner would form a self-parent cycle → OwnershipCycle,
        // with state byte-for-byte unchanged (nothing newly created, no re-parent).
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = make_root_ifay(&registry, &mut ownership, &mut binding, &mut svc, &vk(1));
        let cofay_key = vk(2);
        let cofay = svc
            .create_cofay(&registry, &mut ownership, &mut binding, &owner, &cofay_key, Timestamp::from_secs(2))
            .unwrap();

        // Snapshot the whole world, then attempt the cyclic re-create.
        let svc_before = svc.clone();
        let ownership_before = ownership.clone();
        let binding_before = binding.clone();

        // Re-deriving with (owner-scheme, cofay_key) under owner == cofay forms a cycle.
        let result =
            svc.create_cofay(&registry, &mut ownership, &mut binding, &cofay, &cofay_key, Timestamp::from_secs(3));

        assert_eq!(result, Err(IdentityError::OwnershipCycle));
        assert_eq!(svc, svc_before, "rejected create must leave identities unchanged");
        assert_eq!(ownership, ownership_before, "ownership unchanged");
        assert_eq!(binding, binding_before, "binding unchanged");
    }

    #[test]
    fn create_cofay_beyond_max_depth_is_rejected_and_creates_nothing() {
        // Requirement 6.6: a CreateCoFay that would push depth beyond 16 (root iFay = 0)
        // → OwnershipDepthExceeded, and NOTHING is created.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = make_root_ifay(&registry, &mut ownership, &mut binding, &mut svc, &vk(0));

        // Build a chain root(0) -> c1(1) -> ... -> c16(16) at exactly MAX_DEPTH.
        let mut parent = owner;
        for d in 1..=16u8 {
            let child = svc
                .create_cofay(
                    &registry,
                    &mut ownership,
                    &mut binding,
                    &parent,
                    &vk(d.wrapping_add(10)),
                    Timestamp::from_secs(d as u64 + 1),
                )
                .expect("within depth bound");
            assert_eq!(ownership.depth_of(&child), Some(d as u32));
            parent = child;
        }

        let svc_before = svc.clone();
        let ownership_before = ownership.clone();
        let binding_before = binding.clone();

        // Attaching beneath the depth-16 leaf would be depth 17 → rejected.
        let result = svc.create_cofay(
            &registry,
            &mut ownership,
            &mut binding,
            &parent,
            &vk(200),
            Timestamp::from_secs(100),
        );
        assert_eq!(result, Err(IdentityError::OwnershipDepthExceeded));
        assert_eq!(svc, svc_before);
        assert_eq!(ownership, ownership_before);
        assert_eq!(binding, binding_before);
    }

    #[test]
    fn create_cofay_is_idempotent_for_same_owner_and_key() {
        // Re-submitting the same (owner, key) derives the same id and is an idempotent
        // no-op: the existing record/pocket are untouched and counts stay the same.
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = make_root_ifay(&registry, &mut ownership, &mut binding, &mut svc, &vk(1));
        let cofay_key = vk(2);

        let id1 = svc
            .create_cofay(&registry, &mut ownership, &mut binding, &owner, &cofay_key, Timestamp::from_secs(2))
            .unwrap();
        let record_before = svc.get(&id1).cloned();

        let id2 = svc
            .create_cofay(&registry, &mut ownership, &mut binding, &owner, &cofay_key, Timestamp::from_secs(999))
            .unwrap();

        assert_eq!(id1, id2);
        assert_eq!(svc.len(), 2); // owner + one coFay only
        assert_eq!(binding.len(), 2);
        assert_eq!(svc.get(&id1).cloned(), record_before); // created_at not overwritten
        assert_eq!(svc.get(&id1).unwrap().created_at, Timestamp::from_secs(2));
    }
}
