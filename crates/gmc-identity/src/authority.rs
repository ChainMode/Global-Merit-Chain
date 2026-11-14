//! `Authority_Resolver` — owner / ancestor / delegate authorization and delegate mgmt.
//!
//! This module implements the design's *Authority_Resolver* section and the
//! *Data Models → 授权与 Delegate* records. It answers the single question
//! "may this signer act **on behalf of** a given coFay?" and manages that coFay's set
//! of explicitly-authorized [`Delegate`](DelegateRecord) keys.
//!
//! ## Authorization rule (design *Authority_Resolver*; Requirements 7.1, 7.4)
//!
//! [`authorizes`] accepts a signer **iff** the signer is one of:
//!
//! 1. the coFay's **owner** (its direct parent in the ownership tree), or
//! 2. an **ancestor** on the coFay's root-first ownership path (which includes the
//!    root iFay and every intermediate owner), or
//! 3. a currently **Active** (non-revoked) **Delegate** `VerifyingKey` of that coFay.
//!
//! Anyone else — a non-owner / non-ancestor / non-delegate, or a delegate whose key has
//! been **revoked** (Requirement 7.5) — is **not** authorized. (1) and (2) are decided
//! by *deriving the signer's [`IdentityId`]* from its `(scheme_tag, VerifyingKey)` via
//! [`derive_identity_id`] and comparing against [`OwnershipRegistry::owner_of`] /
//! [`OwnershipRegistry::ancestors_of`]; (3) is matched on the raw `VerifyingKey` against
//! the [`DelegateStore`], so it holds independently of whether the signer key also
//! derives to a registered identity.
//!
//! ## Delegate set (design *Data Models → 授权与 Delegate*)
//!
//! [`DelegateStatus`], [`DelegateRecord`] and [`DelegateSet`] mirror the design records
//! exactly: a `DelegateSet` belongs to one coFay and stores its delegates in a
//! `BTreeMap` keyed by a **stable, deterministic fingerprint** of the delegate
//! `VerifyingKey` (the design's `BTreeMap<DeviceId /*key 指纹*/, DelegateRecord>`). The
//! fingerprint reuses this crate's reversible base32 encoding of the key bytes (see
//! [`fingerprint`]), so it introduces no new dependency and is a bijection of the key
//! bytes — distinct keys never collide. [`DelegateStore`] is the registry keyed by coFay
//! [`IdentityId`] (the design's `delegates: BTreeMap<IdentityId, DelegateSet>` field of
//! `IdentityState`).
//!
//! [`DelegateStore::add_delegate`] inserts (or re-activates) a delegate;
//! [`DelegateStore::revoke_delegate`] sets its status to [`DelegateStatus::Revoked`];
//! and [`DelegateStore::delegates_of`] returns **only** Active keys (revoked keys are
//! excluded, Requirement 7.5).
//!
//! ## Who is allowed to mutate the delegate set
//!
//! The functions here are **pure** resolver logic and delegate-set mutations. They do
//! **not** authenticate the *caller*: the design routes every state-changing request
//! (including `AddDelegate` / `RevokeDelegate`) through `Identity_Core`, which runs the
//! fixed validation chain — scheme → key/sig format → signature → identity → **authorize
//! (via [`authorizes`])** → nonce — *before* invoking these mutations (Requirements 7.2,
//! 7.3, 13.1). In other words, the caller (`Identity_Core`, task 11) is responsible for
//! verifying that an add/revoke request is signed by a key authorized for the coFay
//! (owner / ancestor / active delegate) **before** calling [`DelegateStore::add_delegate`]
//! / [`DelegateStore::revoke_delegate`]. This module provides the decision and the
//! mutation; it does not gate the mutation itself.

use std::collections::BTreeMap;

use crate::error::IdentityResult;
use crate::identity_id::{base32_encode, derive_identity_id, IdentityId};
use crate::ownership::OwnershipRegistry;
use crate::scheme::SchemeRegistry;
use crate::types::{SchemeTag, VerifyingKey};

/// Lifecycle status of a single delegate key (design *Data Models*: `DelegateStatus`).
///
/// A freshly added delegate is [`Active`](DelegateStatus::Active); revoking it sets it
/// to [`Revoked`](DelegateStatus::Revoked). Only `Active` delegates authorize
/// operations (Requirement 7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DelegateStatus {
    /// The delegate key may act on behalf of the coFay.
    Active,
    /// The delegate key has been revoked and may no longer act (Requirement 7.5).
    Revoked,
}

/// A single delegate entry: the delegate's `VerifyingKey` plus its lifecycle status
/// (design *Data Models*: `DelegateRecord`).
///
/// The record is retained (rather than removed) on revocation so the set keeps a stable
/// fingerprint→record mapping and a re-add can flip the same entry back to `Active`;
/// [`DelegateStore::delegates_of`] filters out the `Revoked` ones (Requirement 7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateRecord {
    /// The delegate's verifying key.
    key: VerifyingKey,
    /// Whether this delegate is currently active or has been revoked.
    status: DelegateStatus,
}

impl DelegateRecord {
    /// The delegate's verifying key.
    #[inline]
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }

    /// This delegate's current lifecycle status.
    #[inline]
    pub fn status(&self) -> DelegateStatus {
        self.status
    }

    /// `true` iff this delegate is currently [`Active`](DelegateStatus::Active).
    #[inline]
    pub fn is_active(&self) -> bool {
        self.status == DelegateStatus::Active
    }
}

/// The delegate set of **one** coFay (design *Data Models*: `DelegateSet`).
///
/// Holds the owning coFay's [`IdentityId`] plus its delegates keyed by the stable
/// [`fingerprint`] of each delegate `VerifyingKey`
/// (`BTreeMap<String /*key 指纹*/, DelegateRecord>`). A `BTreeMap` keeps iteration
/// order deterministic (a requirement of this layer's property tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateSet {
    /// The coFay this delegate set belongs to.
    cofay: IdentityId,
    /// Delegates keyed by a stable fingerprint of the delegate verifying key.
    delegates: BTreeMap<String, DelegateRecord>,
}

impl DelegateSet {
    /// Builds an empty delegate set for `cofay`.
    #[inline]
    fn new(cofay: IdentityId) -> Self {
        DelegateSet {
            cofay,
            delegates: BTreeMap::new(),
        }
    }

    /// The coFay this delegate set belongs to (design `cofay`).
    #[inline]
    pub fn cofay(&self) -> &IdentityId {
        &self.cofay
    }

    /// The [`DelegateRecord`] for `key`, regardless of status, if present.
    #[inline]
    pub fn record(&self, key: &VerifyingKey) -> Option<&DelegateRecord> {
        self.delegates.get(&fingerprint(key))
    }

    /// `true` iff `key` is present **and** currently [`Active`](DelegateStatus::Active).
    #[inline]
    pub fn is_active(&self, key: &VerifyingKey) -> bool {
        self.record(key).is_some_and(DelegateRecord::is_active)
    }

    /// The currently Active delegate keys, in deterministic fingerprint order
    /// (design `delegatesOf` — only `status == Active`, Requirement 7.5).
    pub fn active_keys(&self) -> Vec<VerifyingKey> {
        self.delegates
            .values()
            .filter(|record| record.is_active())
            .map(|record| record.key.clone())
            .collect()
    }
}

/// The delegate registry: every coFay's [`DelegateSet`] keyed by its [`IdentityId`]
/// (design *Data Models*: the `delegates: BTreeMap<IdentityId, DelegateSet>` field of
/// `IdentityState`).
///
/// A `BTreeMap` is used so iteration order is deterministic. This type owns the
/// delegate-set **mutations** ([`add_delegate`](Self::add_delegate) /
/// [`revoke_delegate`](Self::revoke_delegate)); the *authorization decision* that uses
/// it is the free function [`authorizes`]. Both are pure — the caller (`Identity_Core`)
/// authenticates the request first (see the module-level docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegateStore {
    /// Each coFay's delegate set keyed by the coFay's id (`BTreeMap` for determinism).
    sets: BTreeMap<IdentityId, DelegateSet>,
}

impl DelegateStore {
    /// Creates an empty delegate store.
    #[inline]
    pub fn new() -> Self {
        DelegateStore {
            sets: BTreeMap::new(),
        }
    }

    /// Adds (or re-activates) `delegate` in `cofay`'s delegate set (design
    /// `addDelegate`; Requirement 7.2).
    ///
    /// If the coFay has no delegate set yet, one is created. If `delegate` is already
    /// present, its status is set back to [`Active`](DelegateStatus::Active) (a re-add
    /// of a previously revoked key reinstates it); the key bytes are stored under their
    /// stable [`fingerprint`].
    ///
    /// # Authentication is the caller's job
    ///
    /// Per the design, only an authorized signer of `cofay` (its owner / ancestor /
    /// active delegate) may add delegates. That signature check is `Identity_Core`'s
    /// (task 11); this method assumes the caller has already authenticated and simply
    /// performs the mutation.
    ///
    /// Returns `Ok(())`; the [`IdentityResult`] signature matches the design's
    /// `addDelegate` so `Identity_Core` can compose it uniformly with other fallible
    /// state mutations.
    pub fn add_delegate(
        &mut self,
        cofay: &IdentityId,
        delegate: &VerifyingKey,
    ) -> IdentityResult<()> {
        let set = self
            .sets
            .entry(cofay.clone())
            .or_insert_with(|| DelegateSet::new(cofay.clone()));
        set.delegates.insert(
            fingerprint(delegate),
            DelegateRecord {
                key: delegate.clone(),
                status: DelegateStatus::Active,
            },
        );
        Ok(())
    }

    /// Revokes `delegate` in `cofay`'s delegate set (design `revokeDelegate`;
    /// Requirements 7.3, 7.5).
    ///
    /// If the delegate is present its status is set to
    /// [`Revoked`](DelegateStatus::Revoked); a revoked key is thereafter excluded from
    /// [`delegates_of`](Self::delegates_of) and never authorizes (Requirement 7.5).
    /// Revoking a key that is **absent** (or already revoked) is an **idempotent**
    /// no-op that returns `Ok(())` — consistent with the design's "幂等吊销" rule (no
    /// "not a delegate" code exists in the error vocabulary, and a re-revoke changes
    /// nothing).
    ///
    /// As with [`add_delegate`](Self::add_delegate), authenticating *who* may revoke is
    /// `Identity_Core`'s responsibility; this method performs the mutation only.
    pub fn revoke_delegate(
        &mut self,
        cofay: &IdentityId,
        delegate: &VerifyingKey,
    ) -> IdentityResult<()> {
        if let Some(set) = self.sets.get_mut(cofay) {
            if let Some(record) = set.delegates.get_mut(&fingerprint(delegate)) {
                record.status = DelegateStatus::Revoked;
            }
        }
        Ok(())
    }

    /// Returns `cofay`'s currently **Active** delegate keys, in deterministic
    /// fingerprint order (design `delegatesOf` — only `status == Active`,
    /// Requirement 7.5).
    ///
    /// Returns an empty vector for a coFay with no delegate set or whose delegates are
    /// all revoked.
    pub fn delegates_of(&self, cofay: &IdentityId) -> Vec<VerifyingKey> {
        match self.sets.get(cofay) {
            Some(set) => set.active_keys(),
            None => Vec::new(),
        }
    }

    /// `true` iff `delegate` is a currently **Active** delegate of `cofay`.
    ///
    /// A revoked or never-added key returns `false` (Requirement 7.5). This is the
    /// raw-key membership test [`authorizes`] uses for the delegate branch.
    #[inline]
    pub fn is_active_delegate(&self, cofay: &IdentityId, delegate: &VerifyingKey) -> bool {
        self.sets
            .get(cofay)
            .is_some_and(|set| set.is_active(delegate))
    }

    /// Returns `cofay`'s full [`DelegateSet`] (including revoked records), if any.
    #[inline]
    pub fn set(&self, cofay: &IdentityId) -> Option<&DelegateSet> {
        self.sets.get(cofay)
    }
}

/// A stable, deterministic fingerprint of a delegate `VerifyingKey`, used as the
/// `BTreeMap` key inside a [`DelegateSet`] (the design's `DeviceId /*key 指纹*/`).
///
/// It reuses this crate's reversible base32 encoding ([`base32_encode`]) of the key
/// bytes, so it adds **no new dependency** and is a bijection of the bytes: distinct
/// keys always produce distinct fingerprints (no collisions), and equal keys always
/// produce equal fingerprints (stable lookups).
#[inline]
fn fingerprint(key: &VerifyingKey) -> String {
    base32_encode(key.as_bytes())
}

/// Decides whether `signer_key` (under `signer_scheme`) is authorized to act **on
/// behalf of** `cofay` (design *Authority_Resolver*: `authorizes`; Requirements 7.1,
/// 7.4, 7.5).
///
/// Returns `true` **iff** the signer is one of:
///
/// 1. the **owner** of `cofay` ([`OwnershipRegistry::owner_of`]), or
/// 2. an **ancestor** on `cofay`'s ownership path ([`OwnershipRegistry::ancestors_of`],
///    which includes the root iFay and every intermediate owner), or
/// 3. a currently **Active** delegate `VerifyingKey` of `cofay`
///    ([`DelegateStore::is_active_delegate`]).
///
/// Otherwise it returns `false` (the caller, `Identity_Core`, maps that to
/// [`UnauthorizedActor`](crate::error::IdentityError::UnauthorizedActor), Requirement
/// 7.4). A **revoked** delegate fails branch (3) and so is unauthorized (Requirement
/// 7.5).
///
/// Branches (1)/(2) derive the signer's [`IdentityId`] from `(signer_scheme,
/// signer_key)` via [`derive_identity_id`] and compare it against the ownership
/// registry. If derivation fails (unregistered scheme or malformed key bytes) the
/// signer simply cannot match any owner/ancestor identity — but branch (3) still
/// applies, since a delegate is matched on the **raw** `VerifyingKey` independently of
/// derivation. This is a **read-only** query: it never mutates any registry (design:
/// "查询无副作用").
///
/// Note: this resolves authorization for acting *on behalf of a coFay*. Authorization
/// for an operation on an identity's *own* state (current active, non-revoked key /
/// active device key) is `Identity_Core`'s concern (task 11) and not decided here.
pub fn authorizes(
    cofay: &IdentityId,
    signer_scheme: &SchemeTag,
    signer_key: &VerifyingKey,
    schemes: &SchemeRegistry,
    ownership: &OwnershipRegistry,
    delegates: &DelegateStore,
) -> bool {
    // (1)/(2) owner & ancestor are decided on the signer's derived IdentityId. A
    // derivation failure just means the signer matches no identity here.
    if let Ok(signer_id) = derive_identity_id(schemes, signer_scheme, signer_key) {
        // (1) Owner: the coFay's direct parent.
        if ownership.owner_of(cofay) == Some(&signer_id) {
            return true;
        }
        // (2) Ancestor: any identity on the root-first ownership path (incl. root iFay).
        if ownership
            .ancestors_of(cofay)
            .iter()
            .any(|ancestor| ancestor == &signer_id)
        {
            return true;
        }
    }
    // (3) Active (non-revoked) delegate — matched on the raw VerifyingKey (7.5).
    delegates.is_active_delegate(cofay, signer_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 32-byte ed25519 verifying key whose bytes vary with `seed` (so distinct
    /// seeds derive distinct `IdentityId`s, matching `identity_id`'s test helper).
    fn vk(seed: u8) -> VerifyingKey {
        let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        VerifyingKey::new(bytes)
    }

    /// Derives the ed25519 `IdentityId` for `key` under the default registry.
    fn id_of(schemes: &SchemeRegistry, key: &VerifyingKey) -> IdentityId {
        derive_identity_id(schemes, &SchemeTag::ed25519(), key).expect("valid ed25519 vk")
    }

    /// Convenience wrapper calling [`authorizes`] with the ed25519 tag.
    fn authorized(
        cofay: &IdentityId,
        signer_key: &VerifyingKey,
        schemes: &SchemeRegistry,
        ownership: &OwnershipRegistry,
        delegates: &DelegateStore,
    ) -> bool {
        authorizes(
            cofay,
            &SchemeTag::ed25519(),
            signer_key,
            schemes,
            ownership,
            delegates,
        )
    }

    // --- owner / ancestor authorization (Requirement 7.1) ------------------

    #[test]
    fn owner_is_authorized() {
        // root iFay (owner) -> coFay; the direct owner authorizes (branch 1).
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let owner_id = id_of(&schemes, &owner_key);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership.register_root(&owner_id).unwrap();
        ownership.attach(&cofay_id, &owner_id).unwrap();

        let delegates = DelegateStore::new();
        assert!(authorized(&cofay_id, &owner_key, &schemes, &ownership, &delegates));
    }

    #[test]
    fn root_ifay_ancestor_is_authorized_over_depth_2_cofay() {
        // root iFay -> mid coFay -> leaf coFay (depth 2). The root iFay, though not the
        // direct owner of the leaf, is an ancestor and so authorizes (branch 2).
        let schemes = SchemeRegistry::default();
        let root_key = vk(10);
        let mid_key = vk(11);
        let leaf_key = vk(12);
        let root_id = id_of(&schemes, &root_key);
        let mid_id = id_of(&schemes, &mid_key);
        let leaf_id = id_of(&schemes, &leaf_key);

        let mut ownership = OwnershipRegistry::new();
        ownership.register_root(&root_id).unwrap();
        ownership.attach(&mid_id, &root_id).unwrap();
        ownership.attach(&leaf_id, &mid_id).unwrap();
        assert_eq!(ownership.depth_of(&leaf_id), Some(2));

        let delegates = DelegateStore::new();
        // The root iFay (ancestor) and the direct owner `mid` both authorize the leaf.
        assert!(authorized(&leaf_id, &root_key, &schemes, &ownership, &delegates));
        assert!(authorized(&leaf_id, &mid_key, &schemes, &ownership, &delegates));
    }

    // --- delegate authorization (Requirements 7.1, 7.2) --------------------

    #[test]
    fn active_delegate_is_authorized() {
        // A delegate that is neither owner nor ancestor authorizes once added (branch 3).
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let delegate_key = vk(99); // unrelated to the ownership tree
        let owner_id = id_of(&schemes, &owner_key);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership.register_root(&owner_id).unwrap();
        ownership.attach(&cofay_id, &owner_id).unwrap();

        let mut delegates = DelegateStore::new();
        // Before being added, the delegate is unauthorized.
        assert!(!authorized(&cofay_id, &delegate_key, &schemes, &ownership, &delegates));

        delegates.add_delegate(&cofay_id, &delegate_key).unwrap();
        assert!(authorized(&cofay_id, &delegate_key, &schemes, &ownership, &delegates));
        // delegates_of now lists exactly this active key.
        assert_eq!(delegates.delegates_of(&cofay_id), vec![delegate_key]);
    }

    // --- unauthorized signer (Requirement 7.4) -----------------------------

    #[test]
    fn non_owner_non_ancestor_non_delegate_is_unauthorized() {
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let stranger_key = vk(200);
        let owner_id = id_of(&schemes, &owner_key);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership.register_root(&owner_id).unwrap();
        ownership.attach(&cofay_id, &owner_id).unwrap();

        let delegates = DelegateStore::new();
        // A stranger (not owner, not ancestor, not a delegate) is rejected.
        assert!(!authorized(&cofay_id, &stranger_key, &schemes, &ownership, &delegates));
        // The coFay's own key does not, by itself, authorize acting on behalf of the
        // coFay (it is neither owner/ancestor of itself nor a delegate).
        assert!(!authorized(&cofay_id, &cofay_key, &schemes, &ownership, &delegates));
    }

    // --- revoked delegate (Requirements 7.3, 7.5) --------------------------

    #[test]
    fn revoked_delegate_is_unauthorized() {
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let delegate_key = vk(99);
        let owner_id = id_of(&schemes, &owner_key);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership.register_root(&owner_id).unwrap();
        ownership.attach(&cofay_id, &owner_id).unwrap();

        let mut delegates = DelegateStore::new();
        delegates.add_delegate(&cofay_id, &delegate_key).unwrap();
        delegates.revoke_delegate(&cofay_id, &delegate_key).unwrap();

        // Revoked → unauthorized (7.5), and excluded from delegates_of.
        assert!(!authorized(&cofay_id, &delegate_key, &schemes, &ownership, &delegates));
        assert!(delegates.delegates_of(&cofay_id).is_empty());
        // The record is retained but marked Revoked.
        assert_eq!(
            delegates.set(&cofay_id).unwrap().record(&delegate_key).unwrap().status(),
            DelegateStatus::Revoked
        );
    }

    #[test]
    fn add_then_revoke_then_readd_round_trips() {
        let schemes = SchemeRegistry::default();
        let cofay_id = id_of(&schemes, &vk(2));
        let delegate_key = vk(99);
        let ownership = OwnershipRegistry::new(); // owner/ancestor irrelevant here
        let mut delegates = DelegateStore::new();

        // add → active.
        delegates.add_delegate(&cofay_id, &delegate_key).unwrap();
        assert!(delegates.is_active_delegate(&cofay_id, &delegate_key));
        assert!(authorized(&cofay_id, &delegate_key, &schemes, &ownership, &delegates));

        // revoke → inactive.
        delegates.revoke_delegate(&cofay_id, &delegate_key).unwrap();
        assert!(!delegates.is_active_delegate(&cofay_id, &delegate_key));
        assert!(!authorized(&cofay_id, &delegate_key, &schemes, &ownership, &delegates));

        // re-add reinstates the same key as active.
        delegates.add_delegate(&cofay_id, &delegate_key).unwrap();
        assert!(delegates.is_active_delegate(&cofay_id, &delegate_key));
        assert_eq!(delegates.delegates_of(&cofay_id), vec![delegate_key]);
    }

    #[test]
    fn revoke_absent_delegate_is_idempotent_no_op() {
        let schemes = SchemeRegistry::default();
        let cofay_id = id_of(&schemes, &vk(2));
        let mut delegates = DelegateStore::new();

        // Revoking with no delegate set / absent key is a harmless no-op success.
        assert!(delegates.revoke_delegate(&cofay_id, &vk(99)).is_ok());
        assert!(delegates.delegates_of(&cofay_id).is_empty());

        // Re-revoking an existing delegate twice changes nothing further.
        delegates.add_delegate(&cofay_id, &vk(5)).unwrap();
        delegates.revoke_delegate(&cofay_id, &vk(5)).unwrap();
        let after_first = delegates.clone();
        delegates.revoke_delegate(&cofay_id, &vk(5)).unwrap();
        assert_eq!(delegates, after_first);
    }

    // --- delegates_of returns only active keys (Requirement 7.5) -----------

    #[test]
    fn delegates_of_returns_only_active_keys() {
        let schemes = SchemeRegistry::default();
        let cofay_id = id_of(&schemes, &vk(2));
        let d1 = vk(50);
        let d2 = vk(51);
        let d3 = vk(52);
        let mut delegates = DelegateStore::new();

        delegates.add_delegate(&cofay_id, &d1).unwrap();
        delegates.add_delegate(&cofay_id, &d2).unwrap();
        delegates.add_delegate(&cofay_id, &d3).unwrap();
        // Revoke the middle one.
        delegates.revoke_delegate(&cofay_id, &d2).unwrap();

        let active = delegates.delegates_of(&cofay_id);
        assert_eq!(active.len(), 2);
        assert!(active.contains(&d1));
        assert!(active.contains(&d3));
        assert!(!active.contains(&d2));
    }

    #[test]
    fn delegates_of_empty_for_unknown_cofay() {
        let schemes = SchemeRegistry::default();
        let unknown = id_of(&schemes, &vk(123));
        let delegates = DelegateStore::new();
        assert!(delegates.delegates_of(&unknown).is_empty());
        assert!(!delegates.is_active_delegate(&unknown, &vk(1)));
    }

    // --- delegate fingerprint is stable & collision-free -------------------

    #[test]
    fn fingerprint_is_stable_and_distinct_per_key() {
        // Equal keys → equal fingerprint (stable lookups); distinct keys → distinct.
        assert_eq!(fingerprint(&vk(7)), fingerprint(&vk(7)));
        assert_ne!(fingerprint(&vk(7)), fingerprint(&vk(8)));
    }
}
