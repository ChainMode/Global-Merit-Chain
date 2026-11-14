//! Property 16 — MeritPocket one-to-one binding.
//!
//! Design *Pocket_Binding* / Property 16: MeritPocket 一对一绑定.
//! Validates Requirements 6.7, 10.1, 10.2, 10.3, 10.4.
//!
//! For any set of created identities, each [`IdentityId`] maps to **exactly one**
//! [`MeritPocket`] keyed by its canonical [`FayID`] (`== id.to_fay_id()`), and two
//! distinct [`IdentityId`]s map to two distinct `FayID`/`MeritPocket`s (the mapping is
//! **injective**). Resolving the lookup key for some [`IdentityId`] returns its
//! corresponding `FayID`.
//!
//! The generator draws a small `Vec` of valid-format ed25519 verifying keys (duplicates
//! may occur), each of which derives a real [`IdentityId`]. Because derivation is an
//! injective bijection of the key bytes, distinct keys give distinct ids and equal keys
//! give equal ids — so the binding's idempotence and injectivity are both exercised.

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::BTreeSet;

use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::SchemeTag;

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 16: MeritPocket 一对一绑定
    #[test]
    fn property_16_pocket_binding_one_to_one(
        keys in proptest::collection::vec(generators::verifying_key_valid(), 1..=12),
    ) {
        // The default registry supports ed25519; every valid-format vk derives an id.
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();

        let ids: Vec<_> = keys
            .iter()
            .map(|vk| derive_identity_id(&registry, &tag, vk).expect("valid ed25519 vk derives"))
            .collect();

        let mut binding = PocketBinding::new();

        // Distinct identities and the distinct canonical FayIDs they bind to; comparing
        // the two cardinalities below is the injectivity check (Requirement 10.2).
        let mut distinct_ids = BTreeSet::new();
        let mut distinct_fay_ids = BTreeSet::new();

        for id in &ids {
            // The lookup key is the identity's canonical FayID (Requirement 10.3).
            let canonical = id.to_fay_id();

            // bind(id) creates (and only creates) one pocket keyed by that FayID and
            // returns the lookup key (Requirements 10.1, 10.3).
            let key = binding.bind(id).expect("pure mapping never rejects");
            prop_assert_eq!(&key, &canonical);

            // Resolving the lookup key for this id returns its corresponding FayID
            // (Requirement 10.4).
            prop_assert_eq!(binding.pocket_key(id), Some(canonical.clone()));

            // Exactly one MeritPocket exists for this id, stored under its canonical
            // key, and that pocket carries the same FayID (Requirements 10.1, 6.7).
            let pocket = binding.pocket(id).expect("a pocket was bound for this id");
            prop_assert_eq!(&pocket.fay_id, &canonical);
            prop_assert!(binding.pocket_by_key(&canonical).is_some());

            distinct_ids.insert(id.clone());
            distinct_fay_ids.insert(canonical);
        }

        // Idempotence: re-binding each id returns the same key and creates no second
        // pocket, so the "exactly one MeritPocket per IdentityId" invariant holds even
        // when a bind is requested twice (Requirement 10.1).
        let len_after_first_pass = binding.len();
        for id in &ids {
            let again = binding.bind(id).expect("idempotent re-bind never rejects");
            prop_assert_eq!(again, id.to_fay_id());
        }
        prop_assert_eq!(binding.len(), len_after_first_pass);

        // Injectivity: distinct IdentityIds map to distinct FayIDs/MeritPockets, so the
        // number of distinct FayIDs equals the number of distinct IdentityIds
        // (Requirement 10.2 / Property 16).
        prop_assert_eq!(distinct_fay_ids.len(), distinct_ids.len());

        // Exactly one MeritPocket per distinct IdentityId — no extras, no merges
        // (Requirements 10.1, 10.2).
        prop_assert_eq!(binding.len(), distinct_ids.len());
    }
}
