//! Property 4 — **(父链, 领域) 全局唯一** (Validates: Requirements 2.9).
//!
//! This is one of the design's 30 numbered correctness properties. It exercises the
//! `Chain_Registry`'s `(parentId, domain)` uniqueness guarantee against generated
//! sequences of derive requests that deliberately reuse already-taken
//! `(parent, domain)` slots (each with a *fresh* proposed id), asserting that:
//!
//! - any duplicate creation is rejected with [`GmcError::DomainConflict`];
//! - on such a rejection the existing chain that owns the slot is preserved
//!   unchanged and the duplicate's fresh id is never added (atomic failure); and
//! - after the whole sequence, no two distinct chains in the registry share the
//!   same `(parent_id, domain)` pair.
//!
//! See `tests/common/mod.rs` for the `Feature: gmc-core-protocol, Property N: ...`
//! labelling convention every numbered property test follows.

use std::collections::HashSet;

use gmc_core::error::GmcError;
use gmc_core::registry::{ChainRegistry, DeriveRequest, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, FayID, Timestamp};
use proptest::prelude::*;

/// A small fixed pool of (non-empty) domain identifiers. Keeping the pool small makes
/// `(parent, domain)` collisions — the whole point of Property 4 — overwhelmingly
/// likely under any given parent.
const DOMAINS: [&str; 3] = ["academic", "charity", "environment"];

/// A single raw derive operation over the *currently existing* chains.
///
/// `parent_sel` selects (modulo the live chain count) which already-existing chain to
/// derive under — so requests never fail merely because the parent is missing, which
/// would mask the genuine `(parent, domain)` collisions we want to test. `domain_sel`
/// picks one of [`DOMAINS`].
#[derive(Debug, Clone, Copy)]
struct RawOp {
    parent_sel: usize,
    domain_sel: usize,
}

fn raw_op() -> impl Strategy<Value = RawOp> {
    (0usize..256, 0usize..DOMAINS.len()).prop_map(|(parent_sel, domain_sel)| RawOp {
        parent_sel,
        domain_sel,
    })
}

/// A sequence of `0..=max_len` derive operations.
fn op_sequence(max_len: usize) -> impl Strategy<Value = Vec<RawOp>> {
    proptest::collection::vec(raw_op(), 0..=max_len)
}

/// Builds a fresh registry seeded with the `GMC_Base` depth-0 root, returning the
/// registry together with the root id.
fn fresh_registry() -> (ChainRegistry, ChainId) {
    let root_id = ChainId::new("gmc-base");
    let root = NestedMeritChain::root(
        root_id.clone(),
        "root",
        vec![FayID::new("founder")],
        Timestamp::from_secs(1_000),
    );
    let registry = ChainRegistry::with_root(root).expect("root is a valid depth-0 root");
    (registry, root_id)
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 4: (父链, 领域) 全局唯一
    #[test]
    fn property_4_parent_domain_globally_unique(ops in op_sequence(48)) {
        let (mut registry, root_id) = fresh_registry();

        // Ids of chains that currently exist, so every request derives under a real
        // parent (the root or a previously created chain). This maximises genuine
        // (parent, domain) collisions rather than ParentNotFound rejections.
        let mut existing: Vec<ChainId> = vec![root_id];

        for (i, op) in ops.iter().enumerate() {
            let parent_id = existing[op.parent_sel % existing.len()].clone();
            let domain = DOMAINS[op.domain_sel].to_owned();

            // A fresh, never-before-used proposed id. Because it is brand new, the only
            // (parent, domain)-related rejection it can trigger is DomainConflict — it
            // can never form a cycle or collide on id.
            let proposed_id = ChainId::new(format!("c{i}"));

            // Snapshot the targeted slot and the registry size BEFORE the request, so
            // we can assert atomic, no-op failure on rejection.
            let owner_before = registry
                .lookup_by_domain(Some(&parent_id), &domain)
                .cloned();
            let len_before = registry.len();

            let req = DeriveRequest::new(
                proposed_id.clone(),
                parent_id.clone(),
                domain.clone(),
                vec![FayID::new("steward")],
                OriginType::StewardInitiated,
                Timestamp::from_secs(2_000 + i as u64),
            );

            match registry.derive(req) {
                Ok(new_id) => {
                    // A successful creation only happens into a previously-free slot.
                    prop_assert_eq!(&new_id, &proposed_id);
                    prop_assert!(
                        owner_before.is_none(),
                        "a (parent, domain) slot that was already owned must not accept a second chain"
                    );
                    prop_assert_eq!(
                        registry.lookup_by_domain(Some(&parent_id), &domain),
                        Some(&proposed_id)
                    );
                    existing.push(new_id);
                }
                Err(GmcError::DomainConflict) => {
                    // 2.9: the duplicate is rejected, the existing owner is preserved,
                    // and the duplicate's fresh id was never added (atomic no-op).
                    prop_assert!(
                        owner_before.is_some(),
                        "DomainConflict must only fire when the (parent, domain) slot is already owned"
                    );
                    prop_assert_eq!(
                        registry.lookup_by_domain(Some(&parent_id), &domain).cloned(),
                        owner_before,
                        "the ORIGINAL chain owning the (parent, domain) slot must be preserved unchanged"
                    );
                    prop_assert!(
                        !registry.contains(&proposed_id),
                        "the rejected duplicate's id must not be added to the registry"
                    );
                    prop_assert_eq!(registry.len(), len_before);
                }
                Err(_other) => {
                    // Rejections unrelated to Property 4 (e.g. DepthExceeded) must
                    // still leave the registry completely unchanged.
                    prop_assert!(!registry.contains(&proposed_id));
                    prop_assert_eq!(registry.len(), len_before);
                }
            }
        }

        // Global invariant: no two distinct chains share a (parent_id, domain) pair.
        let mut seen: HashSet<(Option<ChainId>, String)> = HashSet::new();
        let mut count = 0usize;
        for chain in registry.iter() {
            let key = (chain.parent_id().cloned(), chain.domain().to_owned());
            prop_assert!(
                seen.insert(key),
                "two distinct chains share the same (parent_id, domain) combination"
            );
            count += 1;
        }
        prop_assert_eq!(seen.len(), count);
        prop_assert_eq!(count, registry.len());
    }
}
