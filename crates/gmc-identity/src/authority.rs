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
use crate::ownership::{OwnerKind, OwnershipRegistry};
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

    /// Ordered iterator over all delegate records (both `Active` and `Revoked`).
    pub fn records(&self) -> impl Iterator<Item = (&String, &DelegateRecord)> {
        self.delegates.iter()
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

    /// Ordered iterator over all delegate sets across `coFay` identities.
    pub fn iter_sets(&self) -> impl Iterator<Item = (&IdentityId, &DelegateSet)> {
        self.sets.iter()
    }

    /// Restores a persisted delegate record (preserving `Active` / `Revoked` status) during snapshot loading.
    pub fn restore_record(
        &mut self,
        cofay: &IdentityId,
        key: VerifyingKey,
        status: DelegateStatus,
    ) {
        let set = self
            .sets
            .entry(cofay.clone())
            .or_insert_with(|| DelegateSet::new(cofay.clone()));
        set.delegates
            .insert(fingerprint(&key), DelegateRecord { key, status });
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
/// behalf of** `cofay` (`realign-cofay-ownership-to-fayid`, FayID ADR 0001).
///
/// Returns `true` **iff** the signer belongs to **one of the two permitted classes**:
///
/// 1. the single-layer **owner** of `cofay` ([`OwnershipRegistry::owner_of`]): either
///    an explicitly bound owner key ([`OwnershipRegistry::owner_key_of`]) or a
///    key-derived `hid_<key_repr>` (`OwnerKind::Human`) / `org_<key_repr>`
///    (`OwnerKind::Organization`); or
/// 2. a currently **Active** delegate `VerifyingKey` of `cofay`
///    ([`DelegateStore::is_active_delegate`]) — including any `iFay` granted management
///    authority without altering `owner`.
///
/// Multi-hop ancestor traversal does **not** exist in the single-layer ownership model
/// and is never accepted.
pub fn authorizes(
    cofay: &IdentityId,
    signer_scheme: &SchemeTag,
    signer_key: &VerifyingKey,
    schemes: &SchemeRegistry,
    ownership: &OwnershipRegistry,
    delegates: &DelegateStore,
) -> bool {
    if ownership.owner_key_of(cofay) == Some(signer_key) {
        return true;
    }
    if let (Some(owner), Ok(signer_id)) = (
        ownership.owner_of(cofay),
        derive_identity_id(schemes, signer_scheme, signer_key),
    ) {
        let expected_prefix = match owner.kind {
            OwnerKind::Human => "hid_",
            OwnerKind::Organization => "org_",
        };
        if let Some(rest) = owner.id.strip_prefix(expected_prefix) {
            if rest == signer_id.key_repr() {
                return true;
            }
        }
    }
    delegates.is_active_delegate(cofay, signer_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 32-byte ed25519 verifying key whose bytes vary with `seed` (so distinct
    /// seeds derive distinct `IdentityId`s, matching `identity_id`'s test helper).
    fn vk(seed: u8) -> VerifyingKey {
        let bytes: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(seed))
            .collect();
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

    // --- single-layer owner authorization (two-class model) ----------------

    fn human_owner_ref(schemes: &SchemeRegistry, key: &VerifyingKey) -> crate::ownership::OwnerRef {
        let id = id_of(schemes, key);
        crate::ownership::OwnerRef::new(format!("hid_{}", id.key_repr()), OwnerKind::Human)
    }

    #[test]
    fn owner_is_authorized() {
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership
            .set_owner(cofay_id.clone(), human_owner_ref(&schemes, &owner_key))
            .unwrap();

        let delegates = DelegateStore::new();
        assert!(authorized(
            &cofay_id, &owner_key, &schemes, &ownership, &delegates
        ));
    }

    #[test]
    fn former_ancestor_is_rejected_under_two_class_authorization() {
        // Under single-layer ownership, an unrelated or parent-org key that is neither
        // the direct owner of `cofay_id` nor an Active Delegate is strictly rejected.
        let schemes = SchemeRegistry::default();
        let parent_org_key = vk(10);
        let child_org_key = vk(11);
        let leaf_id = id_of(&schemes, &vk(12));

        let mut ownership = OwnershipRegistry::new();
        ownership
            .set_owner(
                leaf_id.clone(),
                crate::ownership::OwnerRef::new(
                    format!("org_{}", id_of(&schemes, &child_org_key).key_repr()),
                    OwnerKind::Organization,
                ),
            )
            .unwrap();

        let delegates = DelegateStore::new();
        assert!(authorized(
            &leaf_id,
            &child_org_key,
            &schemes,
            &ownership,
            &delegates
        ));
        assert!(!authorized(
            &leaf_id,
            &parent_org_key,
            &schemes,
            &ownership,
            &delegates
        ));
    }

    // --- delegate authorization (Requirements 7.1, 7.2) --------------------

    #[test]
    fn active_delegate_is_authorized() {
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let delegate_key = vk(99);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership
            .set_owner(cofay_id.clone(), human_owner_ref(&schemes, &owner_key))
            .unwrap();

        let mut delegates = DelegateStore::new();
        assert!(!authorized(
            &cofay_id,
            &delegate_key,
            &schemes,
            &ownership,
            &delegates
        ));

        delegates.add_delegate(&cofay_id, &delegate_key).unwrap();
        assert!(authorized(
            &cofay_id,
            &delegate_key,
            &schemes,
            &ownership,
            &delegates
        ));
        assert_eq!(delegates.delegates_of(&cofay_id), vec![delegate_key]);
    }

    // --- unauthorized signer (Requirement 7.4) -----------------------------

    #[test]
    fn non_owner_non_delegate_is_unauthorized() {
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let stranger_key = vk(200);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership
            .set_owner(cofay_id.clone(), human_owner_ref(&schemes, &owner_key))
            .unwrap();

        let delegates = DelegateStore::new();
        assert!(!authorized(
            &cofay_id,
            &stranger_key,
            &schemes,
            &ownership,
            &delegates
        ));
        assert!(!authorized(
            &cofay_id, &cofay_key, &schemes, &ownership, &delegates
        ));
    }

    // --- revoked delegate (Requirements 7.3, 7.5) --------------------------

    #[test]
    fn revoked_delegate_is_unauthorized() {
        let schemes = SchemeRegistry::default();
        let owner_key = vk(1);
        let cofay_key = vk(2);
        let delegate_key = vk(99);
        let cofay_id = id_of(&schemes, &cofay_key);

        let mut ownership = OwnershipRegistry::new();
        ownership
            .set_owner(cofay_id.clone(), human_owner_ref(&schemes, &owner_key))
            .unwrap();

        let mut delegates = DelegateStore::new();
        delegates.add_delegate(&cofay_id, &delegate_key).unwrap();
        delegates.revoke_delegate(&cofay_id, &delegate_key).unwrap();

        // Revoked → unauthorized (7.5), and excluded from delegates_of.
        assert!(!authorized(
            &cofay_id,
            &delegate_key,
            &schemes,
            &ownership,
            &delegates
        ));
        assert!(delegates.delegates_of(&cofay_id).is_empty());
        // The record is retained but marked Revoked.
        assert_eq!(
            delegates
                .set(&cofay_id)
                .unwrap()
                .record(&delegate_key)
                .unwrap()
                .status(),
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
        assert!(authorized(
            &cofay_id,
            &delegate_key,
            &schemes,
            &ownership,
            &delegates
        ));

        // revoke → inactive.
        delegates.revoke_delegate(&cofay_id, &delegate_key).unwrap();
        assert!(!delegates.is_active_delegate(&cofay_id, &delegate_key));
        assert!(!authorized(
            &cofay_id,
            &delegate_key,
            &schemes,
            &ownership,
            &delegates
        ));

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
