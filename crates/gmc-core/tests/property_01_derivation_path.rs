//! Property 1 — 派生路径与元数据完整性 (derivation path & metadata integrity).
//!
//! This is the dedicated property-based test for **Property 1** of the
//! `gmc-core-protocol` design's *Correctness Properties* section (task 2.4).
//!
//! > **Property 1: 派生路径与元数据完整性** — For any chain registry built from a
//! > sequence of valid derivation requests, every non-root `Nested_Merit_Chain`
//! > satisfies: its `parentId` points to a chain that exists in the registry; its
//! > `path` starts with `GMC_Base`, ends with the chain itself, adjacent elements
//! > form parent-child relationships, and `len(path) == depth + 1`; and it records a
//! > non-empty domain id, parent id, and creation time.
//!
//! **Validates: Requirements 1.2, 1.3, 1.4**
//!
//! Per the harness convention (`tests/common/mod.rs`), the single proptest below is
//! labelled `Feature: gmc-core-protocol, Property 1: ...` and runs with `>= 100`
//! random iterations. Inputs are built directly here (no shared generator needed):
//! each generated step is mapped onto a **valid** [`DeriveRequest`] so the resulting
//! registry is exactly "a registry built from a sequence of valid derivations", and
//! the Property 1 invariants are then asserted over every non-root chain.

use gmc_core::registry::{ChainRegistry, DeriveRequest, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, FayID, Timestamp};
use proptest::prelude::*;

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 1: 派生路径与元数据完整性
    #[test]
    fn property_1_derivation_path_and_metadata_integrity(
        // Each element selects (modulo the current tree size) an existing parent to
        // derive a fresh chain under; the vector length sets the number of derivations.
        parent_selectors in proptest::collection::vec(any::<u16>(), 0..40usize),
    ) {
        // --- Build a registry from a sequence of *valid* derivation requests. ---
        let root_id = ChainId::new("gmc-base");
        let root = NestedMeritChain::root(
            root_id.clone(),
            "root-domain",
            vec![FayID::new("founder")],
            Timestamp::from_secs(1_000),
        );
        let mut registry = ChainRegistry::with_root(root).expect("a valid depth-0 root");

        // Track created chain ids (root first) so each parent selector resolves to a
        // chain that already exists — a precondition for a valid derivation.
        let mut created: Vec<ChainId> = vec![root_id.clone()];

        for (step, selector) in parent_selectors.into_iter().enumerate() {
            // Resolve a parent that already exists in the registry (no fixed depth cap).
            let parent_id = created[(selector as usize) % created.len()].clone();

            // A brand-new unique id (no cycle, no id clash) plus a globally unique
            // domain (so the `(parent, domain)` pair is always unique) and a non-empty
            // steward set make every constructed request a valid derivation.
            let proposed_id = ChainId::new(format!("c{step}"));
            let domain = format!("domain-{step}");
            let req = DeriveRequest::new(
                proposed_id.clone(),
                parent_id,
                domain,
                vec![FayID::new(format!("steward-{step}"))],
                OriginType::StewardInitiated,
                Timestamp::from_secs(2_000 + step as u64),
            );

            let new_id = registry
                .derive(req)
                .expect("each constructed request is a valid derivation");
            prop_assert_eq!(&new_id, &proposed_id);
            created.push(new_id);
        }

        // --- Assert the Property 1 invariants for every non-root chain. ---
        for chain in registry.iter() {
            if chain.is_root() {
                continue;
            }
            let id = chain.id();

            // (Req 1.4) records a parent id, and (Req 1.2) it points to an existing chain.
            let parent_id = chain.parent_id().expect("a non-root chain records a parent id");
            prop_assert!(registry.contains(parent_id));

            // (Req 1.3) the derivation path is retrievable and well-formed.
            let path = registry.get_path(id).expect("a registered chain exposes its path");
            prop_assert!(!path.is_empty());
            // ... starts with GMC_Base ...
            prop_assert_eq!(&path[0], &root_id);
            // ... ends with the chain itself ...
            prop_assert_eq!(path.last().expect("non-empty path"), id);
            // ... and len(path) == depth + 1.
            prop_assert_eq!(path.len() as u32, chain.depth() + 1);

            // ... adjacent elements form parent-child relationships: each path[k] is
            //     the parent of path[k + 1].
            for k in 0..path.len() - 1 {
                let descendant = registry
                    .get(&path[k + 1])
                    .expect("every path element is a registered chain");
                prop_assert_eq!(descendant.parent_id(), Some(&path[k]));
            }

            // (Req 1.4) records a non-empty domain id, a non-empty parent id, and a
            // creation time.
            prop_assert!(!chain.domain().is_empty());
            prop_assert!(!parent_id.is_empty());
            prop_assert!(chain.created_at().as_secs() > 0);
        }
    }
}
