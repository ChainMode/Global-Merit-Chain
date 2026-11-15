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
use crate::ownership::{OwnerRef, OwnershipRegistry};
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
        _ownership: &mut OwnershipRegistry,
        binding: &mut PocketBinding,
        tag: &SchemeTag,
        vk: &VerifyingKey,
        created_at: Timestamp,
    ) -> IdentityResult<IdentityId> {
        let id = derive_identity_id(registry, tag, vk)?;

        if self.identities.contains_key(&id) {
            binding.bind(&id)?;
            return Ok(id);
        }

        // Single-layer ownership stores ONLY `coFay -> OwnerRef`; an iFay is never a
        // tree root inside `OwnershipRegistry`.
        self.identities.insert(
            id.clone(),
            Identity::new_ifay(id.clone(), vk.clone(), created_at),
        );

        binding.bind(&id)?;

        Ok(id)
    }

    /// Creates a **coFay** collective identity owned by a single-layer [`OwnerRef`]
    /// (`Human` or `Organization`), validating key format and owner type atomically
    /// before mutating any collaborator (`realign-cofay-ownership-to-fayid`).
    #[allow(clippy::too_many_arguments)]
    pub fn create_cofay(
        &mut self,
        registry: &SchemeRegistry,
        ownership: &mut OwnershipRegistry,
        binding: &mut PocketBinding,
        scheme_tag: &SchemeTag,
        owner: &OwnerRef,
        new_cofay_key: &VerifyingKey,
        created_at: Timestamp,
    ) -> IdentityResult<IdentityId> {
        let id = derive_identity_id(registry, scheme_tag, new_cofay_key)?;
        owner.validate()?;

        if let Some(existing) = self.identities.get(&id) {
            if existing.kind != IdentityKind::CoFay {
                return Err(crate::error::IdentityError::OwnerTypeNotAllowed);
            }
            if let Some(existing_owner) = ownership.owner_of(&id) {
                if existing_owner != owner {
                    return Err(crate::error::IdentityError::OwnerTypeNotAllowed);
                }
            } else {
                ownership.set_owner(id.clone(), owner.clone())?;
            }
            binding.bind(&id)?;
            return Ok(id);
        }

        ownership.set_owner(id.clone(), owner.clone())?;
        self.identities.insert(
            id.clone(),
            Identity::new_cofay(id.clone(), new_cofay_key.clone(), created_at),
        );
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
        let bytes: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(seed))
            .collect();
        VerifyingKey::new(bytes)
    }

    /// Fresh set of collaborators for a creation test.
    fn fixtures() -> (
        SchemeRegistry,
        OwnershipRegistry,
        PocketBinding,
        IdentityService,
    ) {
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
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &key,
                created_at,
            )
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
    fn create_ifay_leaves_cofay_ownership_registry_empty() {
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

        assert!(!ownership.contains(&id));
        assert_eq!(ownership.owner_of(&id), None);
        assert!(ownership.is_empty());
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
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &key,
                created_at,
            )
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
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &vk(10),
                Timestamp::from_secs(1),
            )
            .unwrap();
        let id_b = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &vk(11),
                Timestamp::from_secs(2),
            )
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
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &tag,
                &key,
                Timestamp::from_secs(1),
            )
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

    // --- create_cofay: single-layer Human / Organization ownership ----------

    #[test]
    fn create_cofay_records_cofay_kind_under_single_layer_owner_with_pocket() {
        use crate::ownership::OwnerKind;
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = OwnerRef::new(
            "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            OwnerKind::Human,
        );
        let cofay_key = vk(2);
        let created_at = Timestamp::from_secs(1_700_000_000);
        let cofay = svc
            .create_cofay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &owner,
                &cofay_key,
                created_at,
            )
            .expect("human owner accepted");

        let record = svc.get(&cofay).expect("coFay recorded");
        assert_eq!(record.kind, IdentityKind::CoFay);
        assert_eq!(record.active_key, cofay_key);
        assert_eq!(ownership.owner_of(&cofay), Some(&owner));
        assert_eq!(binding.pocket_key(&cofay), Some(cofay.to_fay_id()));
        assert!(binding.pocket(&cofay).is_some());
    }

    #[test]
    fn create_cofay_rejects_cofay_or_ifay_owner_atomically() {
        use crate::ownership::OwnerKind;
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let bad_owner = OwnerRef::new(
            "cofay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            OwnerKind::Organization,
        );
        let result = svc.create_cofay(
            &registry,
            &mut ownership,
            &mut binding,
            &SchemeTag::ed25519(),
            &bad_owner,
            &vk(3),
            Timestamp::from_secs(3),
        );
        assert_eq!(result, Err(IdentityError::OwnerTypeNotAllowed));
        assert!(svc.is_empty());
        assert!(ownership.is_empty());
        assert!(binding.is_empty());
    }

    #[test]
    fn create_cofay_malformed_key_is_key_format_invalid_and_creates_nothing() {
        use crate::ownership::OwnerKind;
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = OwnerRef::new("org_ifay-foundation", OwnerKind::Organization);
        let bad = VerifyingKey::new(vec![0u8; 31]);
        let result = svc.create_cofay(
            &registry,
            &mut ownership,
            &mut binding,
            &SchemeTag::ed25519(),
            &owner,
            &bad,
            Timestamp::from_secs(2),
        );

        assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        assert!(svc.is_empty());
        assert!(ownership.is_empty());
        assert!(binding.is_empty());
    }

    #[test]
    fn create_cofay_is_idempotent_for_same_owner_and_key() {
        use crate::ownership::OwnerKind;
        let (registry, mut ownership, mut binding, mut svc) = fixtures();
        let owner = OwnerRef::new("org_ifay-foundation", OwnerKind::Organization);
        let cofay_key = vk(2);

        let id1 = svc
            .create_cofay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &owner,
                &cofay_key,
                Timestamp::from_secs(2),
            )
            .unwrap();
        let record_before = svc.get(&id1).cloned();

        let id2 = svc
            .create_cofay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &owner,
                &cofay_key,
                Timestamp::from_secs(999),
            )
            .unwrap();

        assert_eq!(id1, id2);
        assert_eq!(svc.len(), 1);
        assert_eq!(binding.len(), 1);
        assert_eq!(svc.get(&id1).cloned(), record_before);
    }
}
