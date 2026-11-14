//! `Pocket_Binding` — one-to-one `IdentityId` ↔ `FayID` ↔ `MeritPocket` mapping.
//!
//! Implements the design's *Pocket_Binding (MeritPocket 绑定)* component over the
//! existing `gmc-core` [`MeritPocket`]. Each [`IdentityId`] is mapped **one-to-one** to
//! a single [`MeritPocket`] keyed by the identity's canonical [`FayID`]
//! (`== id.to_fay_id()`), so "opening Meritora shows your MeriToken" has a precise
//! data-model definition (_Requirements 10.1–10.5_, Property 16).
//!
//! ## Integration posture (gmc-core is NOT modified, _Requirement 10.5_)
//!
//! This layer is a pure mapping: it only ever *creates* an empty pocket via
//! [`MeritPocket::new`] and stores it. It **never** recomputes any MeriToken balance or
//! decay (`cur_merit` / `min_merit` math stays entirely in `gmc-core`). A freshly bound
//! pocket therefore carries `gmc-core`'s initial floor `min_merit == E` untouched.
//!
//! ## One-to-one invariant (Property 16, _Requirements 10.1, 10.2_)
//!
//! - `by_identity` is **injective**: distinct [`IdentityId`]s derive distinct canonical
//!   `FayID`s (guaranteed by `IdentityId` derivation, Requirement 2.4 / 3.x), so they
//!   key distinct pockets.
//! - Every bound [`IdentityId`] maps to **exactly one** [`MeritPocket`].
//!
//! ### Binding is idempotent (documented behavior for "establish exactly one")
//!
//! [`PocketBinding::bind`] establishes **and only establishes one** binding per identity
//! (_Requirement 10.1_). Re-binding the same [`IdentityId`] is therefore **idempotent**:
//! it returns the already-bound `FayID` and does **not** create a second pocket nor
//! overwrite the existing one. This keeps the "exactly one MeritPocket per IdentityId"
//! invariant of Property 16 intact even if a caller requests a bind twice.

use std::collections::BTreeMap;

use gmc_core::merit::MeritPocket;
use gmc_core::types::FayID;

use crate::error::IdentityResult;
use crate::identity_id::IdentityId;

/// One-to-one mapping from each [`IdentityId`] to a single [`MeritPocket`], keyed by the
/// identity's canonical [`FayID`] (design *Data Models*: `PocketBinding`).
///
/// Invariants (Property 16, _Requirements 10.1–10.3_):
/// - `by_identity` is injective (distinct ids → distinct `FayID` keys);
/// - the two maps are kept consistent: every value in `by_identity` is a key in
///   `pockets`, and every key in `pockets` is the canonical `FayID` of exactly one
///   bound identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PocketBinding {
    /// `IdentityId -> FayID` (`== canonical(IdentityId)`), one-to-one
    /// (_Requirements 10.2, 10.3_).
    by_identity: BTreeMap<IdentityId, FayID>,
    /// `FayID -> MeritPocket`, reusing `gmc-core::MeritPocket`; this layer never
    /// computes any balance/decay over it (_Requirement 10.5_).
    pockets: BTreeMap<FayID, MeritPocket>,
}

impl PocketBinding {
    /// Creates an empty binding with no identities bound.
    pub fn new() -> Self {
        PocketBinding {
            by_identity: BTreeMap::new(),
            pockets: BTreeMap::new(),
        }
    }

    /// Establishes (and only establishes) **one** `MeritPocket` binding for `id`, keyed
    /// by its canonical `FayID` (`id.to_fay_id()`), returning that lookup key
    /// (_Requirements 10.1, 10.3_).
    ///
    /// On the **first** bind of `id`, exactly one empty pocket is created via
    /// [`MeritPocket::new`] and inserted into both maps. The pocket carries `gmc-core`'s
    /// initial floor `min_merit == E`; this layer performs **no** balance/decay
    /// computation (_Requirement 10.5_).
    ///
    /// Binding is **idempotent** (see the module docs): re-binding an already-bound `id`
    /// returns the existing `FayID` key and creates **no** second pocket, preserving the
    /// "each `IdentityId` maps to exactly one `MeritPocket`" invariant (Property 16).
    ///
    /// Returns an [`IdentityResult`] to match the design's `bind(id): Result<FayID, …>`
    /// signature and to leave room for future fallible policies; the pure mapping itself
    /// has no rejection path at this layer.
    pub fn bind(&mut self, id: &IdentityId) -> IdentityResult<FayID> {
        // Idempotent: a second bind of the same identity must not create a second
        // pocket. Return the already-bound canonical key unchanged.
        if let Some(existing) = self.by_identity.get(id) {
            return Ok(existing.clone());
        }

        // First bind: the lookup key is the identity's canonical FayID (Requirement 3 /
        // 10.3). Create EXACTLY ONE empty pocket via gmc-core and store it in both maps.
        let fay_id = id.to_fay_id();
        self.by_identity.insert(id.clone(), fay_id.clone());
        self.pockets
            .insert(fay_id.clone(), MeritPocket::new(fay_id.clone()));
        Ok(fay_id)
    }

    /// Resolves the `MeritPocket` lookup key for `id`: the bound `FayID`, or `None` if
    /// `id` has not been bound (_Requirement 10.4_).
    pub fn pocket_key(&self, id: &IdentityId) -> Option<FayID> {
        self.by_identity.get(id).cloned()
    }

    /// Returns the [`MeritPocket`] bound to `id`, if any.
    ///
    /// This is a read accessor only; it never triggers any `gmc-core` balance/decay
    /// computation (_Requirement 10.5_).
    pub fn pocket(&self, id: &IdentityId) -> Option<&MeritPocket> {
        let key = self.by_identity.get(id)?;
        self.pockets.get(key)
    }

    /// Returns the [`MeritPocket`] stored under the lookup key `key`, if any.
    pub fn pocket_by_key(&self, key: &FayID) -> Option<&MeritPocket> {
        self.pockets.get(key)
    }

    /// Returns `true` if `id` already has a bound pocket.
    pub fn is_bound(&self, id: &IdentityId) -> bool {
        self.by_identity.contains_key(id)
    }

    /// Number of bound identities (equal to the number of pockets by the consistency
    /// invariant).
    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    /// Returns `true` if no identities are bound.
    pub fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SchemeTag;
    use gmc_core::merit::E;
    use gmc_core::types::Timestamp;

    /// Builds a distinct `IdentityId` for each `key_repr` (canonical FayID differs with
    /// `key_repr`, so distinct labels give distinct identities). The `key_repr` here is
    /// an opaque label for the test; binding does not re-validate it.
    fn id(key_repr: &str) -> IdentityId {
        IdentityId::new(SchemeTag::ed25519(), key_repr)
    }

    #[test]
    fn bind_creates_exactly_one_pocket_keyed_by_canonical_fay_id() {
        // Requirements 10.1, 10.3: one pocket per identity, keyed by canonical FayID.
        let mut binding = PocketBinding::new();
        let identity = id("aaaa");

        let key = binding.bind(&identity).unwrap();

        // The lookup key is exactly the identity's canonical FayID (== to_fay_id).
        assert_eq!(key, identity.to_fay_id());
        // Exactly one binding and one pocket were created.
        assert_eq!(binding.len(), 1);
        // The pocket is reachable both by identity and by its canonical key.
        assert!(binding.pocket(&identity).is_some());
        assert!(binding.pocket_by_key(&identity.to_fay_id()).is_some());
        // The stored pocket carries the canonical FayID.
        assert_eq!(binding.pocket(&identity).unwrap().fay_id, identity.to_fay_id());
    }

    #[test]
    fn distinct_identities_map_to_distinct_fay_ids_and_pockets() {
        // Requirement 10.2 / Property 16: the mapping is injective.
        let mut binding = PocketBinding::new();
        let id_a = id("aaaa");
        let id_b = id("bbbb");

        let key_a = binding.bind(&id_a).unwrap();
        let key_b = binding.bind(&id_b).unwrap();

        // Two distinct identities → two distinct FayID keys …
        assert_ne!(key_a, key_b);
        // … and two distinct pockets (two entries total).
        assert_eq!(binding.len(), 2);
        assert_eq!(binding.pocket(&id_a).unwrap().fay_id, key_a);
        assert_eq!(binding.pocket(&id_b).unwrap().fay_id, key_b);
        assert_ne!(
            binding.pocket(&id_a).unwrap().fay_id,
            binding.pocket(&id_b).unwrap().fay_id
        );
    }

    #[test]
    fn rebinding_same_identity_is_one_to_one_no_second_pocket() {
        // Requirement 10.1 / Property 16: bind establishes exactly ONE pocket; a second
        // bind of the same identity is idempotent and creates no second pocket.
        let mut binding = PocketBinding::new();
        let identity = id("cccc");

        let first = binding.bind(&identity).unwrap();
        // Capture the pocket before re-binding to ensure it is not replaced.
        let pocket_before = binding.pocket(&identity).cloned();
        let second = binding.bind(&identity).unwrap();

        // Same key returned, still exactly one binding/pocket.
        assert_eq!(first, second);
        assert_eq!(binding.len(), 1);
        // The pre-existing pocket is left untouched (not overwritten with a fresh one).
        assert_eq!(binding.pocket(&identity).cloned(), pocket_before);
    }

    #[test]
    fn pocket_key_returns_bound_key_and_none_when_unbound() {
        // Requirement 10.4: pocket_key resolves the bound FayID lookup key.
        let mut binding = PocketBinding::new();
        let bound = id("dddd");
        let unbound = id("eeee");

        // Unbound identity has no key.
        assert_eq!(binding.pocket_key(&unbound), None);
        assert!(!binding.is_bound(&bound));

        let key = binding.bind(&bound).unwrap();
        assert_eq!(binding.pocket_key(&bound), Some(key));
        assert_eq!(binding.pocket_key(&bound), Some(bound.to_fay_id()));
        // The other identity is still unbound.
        assert_eq!(binding.pocket_key(&unbound), None);
    }

    #[test]
    fn freshly_bound_pocket_has_min_merit_e_and_no_decay_invoked() {
        // Requirement 10.5 / Pocket balance-boundary example: a freshly bound pocket
        // carries gmc-core's initial floor min_merit == E, and this layer creates it as
        // an empty pocket without computing any balance/decay.
        let mut binding = PocketBinding::new();
        let identity = id("ffff");
        binding.bind(&identity).unwrap();

        let pocket = binding.pocket(&identity).unwrap();
        // Initial floor is exactly gmc-core's E; this layer did not alter it.
        assert_eq!(pocket.min_merit(), E);
        // The pocket is empty: no batches were created by the binding.
        assert!(pocket.batches.is_empty());
        // cur_merit at any time is 0 for an empty pocket — confirming the binding did
        // not pre-compute or mutate any balance (decay math stays in gmc-core).
        assert!(pocket.cur_merit(Timestamp::from_secs(1_000)).is_zero());
    }

    #[test]
    fn empty_binding_reports_empty() {
        let binding = PocketBinding::new();
        assert!(binding.is_empty());
        assert_eq!(binding.len(), 0);
        assert_eq!(binding.pocket_key(&id("zzzz")), None);
    }
}
