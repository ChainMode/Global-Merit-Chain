//! Property 6 — 评判机制沿派生路径继承 (evaluation-mechanism inheritance).
//!
//! **Validates: Requirements 3.2**
//!
//! Requirement 3.2: when a `Nested_Merit_Chain` does **not** define its own
//! `Evaluation_Mechanism`, it inherits the configuration of the nearest ancestor
//! along its derivation path (walking from itself upward toward `GMC_Base`) that
//! does define one. If neither the chain itself nor any ancestor on its path defines
//! one, resolution yields `None`.
//!
//! This file contains the single numbered proptest for Property 6 (run with
//! `ProptestConfig::with_cases(100)`), plus one fixed-tree example unit test that
//! pins the "nearest, not farthest" behaviour by pointer identity. The example test
//! deliberately carries no `Property N` label, per the convention in
//! `tests/common/mod.rs`, so the numbered property set stays unambiguous.
//!
//! ## Why pointer identity proves "nearest"
//!
//! `registry.rs` uses the local placeholder [`EvaluationMechanismRef`], and every
//! placeholder compares **equal by value**. Value equality therefore cannot tell
//! *which* ancestor's mechanism was returned. Each chain stores its own mechanism in
//! a distinct slot inside the registry, so `std::ptr::eq` on the returned reference
//! uniquely identifies the defining chain — exactly what "nearest defining ancestor"
//! requires. The property builds an arbitrary derivation tree with an arbitrary
//! `defines / inherits` distribution, computes the expected nearest definer
//! independently, and asserts the resolved reference is the very slot of that chain
//! (or `None` when no path node defines one).

use gmc_core::registry::{ChainRegistry, EvaluationMechanismRef, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, FayID, Timestamp};
use proptest::prelude::*;

/// Stable id for the node at index `i` in a generated tree.
fn node_id(i: usize) -> ChainId {
    ChainId::new(format!("chain-{i}"))
}

/// A generated derivation tree plus a per-node "defines its own mechanism" flag.
///
/// `parents[i]` is the parent **index** of node `i`. By construction `parents[i] < i`
/// for every `i >= 1` (and `parents[0]` is an unused placeholder), so node 0 is the
/// `GMC_Base` root and the structure is always an acyclic tree in which each parent
/// is built before its children. `defines[i]` says whether node `i` attaches its own
/// `Evaluation_Mechanism` (vs. inheriting).
#[derive(Debug, Clone)]
struct TreeSpec {
    /// Parent index of each node; `parents[i] < i` for `i >= 1`.
    parents: Vec<usize>,
    /// Whether each node defines its own mechanism.
    defines: Vec<bool>,
}

/// Generates a derivation tree of `1..=12` nodes (so the deepest possible chain has
/// depth `<= 11`, comfortably within the registry's `MAX_DEPTH == 16`) together with
/// an arbitrary `defines / inherits` distribution across the nodes.
fn tree_spec() -> impl Strategy<Value = TreeSpec> {
    (1usize..=12)
        .prop_flat_map(|n| {
            (
                Just(n),
                // Raw parent seeds for nodes 1..n; mapped into `0..i` below so the
                // parent index is always strictly less than the child index.
                proptest::collection::vec(0usize..1_000, n.saturating_sub(1)),
                // One `defines` flag per node (including the root).
                proptest::collection::vec(any::<bool>(), n),
            )
        })
        .prop_map(|(n, seeds, defines)| {
            let mut parents = vec![0usize; n];
            for i in 1..n {
                parents[i] = seeds[i - 1] % i; // parent in 0..i
            }
            TreeSpec { parents, defines }
        })
}

/// Builds a [`ChainRegistry`] from a [`TreeSpec`].
///
/// The root is built via [`NestedMeritChain::root`]; every derived node via
/// [`NestedMeritChain::new`] + [`NestedMeritChain::with_evaluation_mechanism`] (when
/// it defines one) and inserted with [`ChainRegistry::insert`]. Because `derive` does
/// not attach a mechanism, this `new` + `with_evaluation_mechanism` + `insert` path is
/// the way to control exactly which chains define one. The generated tree always
/// satisfies the derive invariants (parent exists, no cycle, depth bound, unique
/// `(parent, domain)` — domains are globally unique here), so each insert succeeds and
/// the resulting registry is identical to what `derive` would have produced.
///
/// Returns the per-node `depth` and `path` vectors alongside the registry so the test
/// does not have to recompute them.
fn build_registry(spec: &TreeSpec) -> (ChainRegistry, Vec<u32>, Vec<Vec<ChainId>>) {
    let n = spec.defines.len();
    let mut depths = vec![0u32; n];
    let mut paths: Vec<Vec<ChainId>> = vec![Vec::new(); n];

    // Node 0 is the GMC_Base root (depth 0).
    depths[0] = 0;
    paths[0] = vec![node_id(0)];
    let mut root = NestedMeritChain::root(
        node_id(0),
        "domain-0",
        vec![FayID::new("steward-0")],
        Timestamp::from_secs(1_000),
    );
    if spec.defines[0] {
        root = root.with_evaluation_mechanism(EvaluationMechanismRef::placeholder());
    }
    let mut registry = ChainRegistry::with_root(root).expect("node 0 is a valid depth-0 root");

    for i in 1..n {
        let parent = spec.parents[i];
        depths[i] = depths[parent] + 1;
        let mut path = paths[parent].clone();
        path.push(node_id(i));
        paths[i] = path.clone();

        let mut chain = NestedMeritChain::new(
            node_id(i),
            node_id(parent),
            format!("domain-{i}"), // globally unique → no (parent, domain) conflict
            depths[i],
            path,
            vec![FayID::new(format!("steward-{i}"))],
            OriginType::StewardInitiated,
            Timestamp::from_secs(2_000 + i as u64),
        )
        .expect("derived chain has at least one steward");
        if spec.defines[i] {
            chain = chain.with_evaluation_mechanism(EvaluationMechanismRef::placeholder());
        }
        registry
            .insert(chain)
            .expect("unique id and unique (parent, domain) always insert cleanly");
    }

    (registry, depths, paths)
}

/// Independently computes the expected nearest-defining-ancestor node index for node
/// `i`: walk from the node itself up toward the root (node 0), returning the first
/// node whose `defines` flag is set, or `None` if none on the path defines one.
fn expected_definer(spec: &TreeSpec, i: usize) -> Option<usize> {
    let mut cur = i;
    loop {
        if spec.defines[cur] {
            return Some(cur);
        }
        if cur == 0 {
            return None; // reached GMC_Base, nothing on the path defines one
        }
        cur = spec.parents[cur];
    }
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 6: 评判机制沿派生路径继承
    #[test]
    fn property_6_mechanism_inheritance(spec in tree_spec()) {
        let (registry, depths, paths) = build_registry(&spec);
        let n = spec.defines.len();

        for i in 0..n {
            let id = node_id(i);

            // Sanity: the stored path is root-first and `len(path) == depth + 1`, so
            // walking it in reverse really is "nearest ancestor first".
            prop_assert_eq!(paths[i].first(), Some(&node_id(0)));
            prop_assert_eq!(paths[i].last(), Some(&id));
            prop_assert_eq!(paths[i].len() as u32, depths[i] + 1);

            let resolved = registry.resolve_evaluation_mechanism(&id);
            let expected = expected_definer(&spec, i);

            // Resolution returns Some exactly when some node on the path defines one.
            prop_assert_eq!(resolved.is_some(), expected.is_some());

            match expected {
                Some(definer) => {
                    // Prove it is the *nearest* definer (not merely "a" definer):
                    // placeholders are value-equal, so identity of the returned slot
                    // is what distinguishes which ancestor was chosen.
                    let definer_ref = registry
                        .get(&node_id(definer))
                        .expect("definer is a registered chain")
                        .evaluation_mechanism()
                        .expect("the nearest definer defines its own mechanism");
                    prop_assert!(std::ptr::eq(resolved.unwrap(), definer_ref));
                }
                None => {
                    prop_assert!(resolved.is_none());
                }
            }
        }
    }
}

/// Fixed-tree example (NOT a numbered property): `root(none) -> a(def) -> b(def) ->
/// c(none)`. Resolving `c` must inherit the **nearest** defining ancestor `b`, not the
/// farther `a`. Pinned by `std::ptr::eq`, mirroring `registry.rs`'s own unit tests.
#[test]
fn nearest_defining_ancestor_resolves_to_b_not_a() {
    // Builds a derived chain under `parent` at the given depth/path, optionally
    // attaching its own mechanism.
    fn derived(
        id: &str,
        parent: &str,
        depth: u32,
        path: &[&str],
        defines: bool,
    ) -> NestedMeritChain {
        let path: Vec<ChainId> = path.iter().map(|s| ChainId::new(*s)).collect();
        let chain = NestedMeritChain::new(
            ChainId::new(id),
            ChainId::new(parent),
            id, // domain == id keeps (parent, domain) unique
            depth,
            path,
            vec![FayID::new("steward")],
            OriginType::StewardInitiated,
            Timestamp::from_secs(10),
        )
        .expect("derived chain has a steward");
        if defines {
            chain.with_evaluation_mechanism(EvaluationMechanismRef::placeholder())
        } else {
            chain
        }
    }

    let root = NestedMeritChain::root(
        ChainId::new("root"),
        "root",
        vec![FayID::new("founder")],
        Timestamp::from_secs(1),
    );
    let mut registry = ChainRegistry::with_root(root).expect("valid depth-0 root");

    registry
        .insert(derived("a", "root", 1, &["root", "a"], true))
        .expect("insert a");
    registry
        .insert(derived("b", "a", 2, &["root", "a", "b"], true))
        .expect("insert b");
    registry
        .insert(derived("c", "b", 3, &["root", "a", "b", "c"], false))
        .expect("insert c");

    let resolved = registry
        .resolve_evaluation_mechanism(&ChainId::new("c"))
        .expect("c inherits from the nearest defining ancestor");
    let a_ref = registry
        .get(&ChainId::new("a"))
        .unwrap()
        .evaluation_mechanism()
        .unwrap();
    let b_ref = registry
        .get(&ChainId::new("b"))
        .unwrap()
        .evaluation_mechanism()
        .unwrap();

    // Nearest-first: `c` resolves to `b`'s mechanism slot, not `a`'s.
    assert!(std::ptr::eq(resolved, b_ref));
    assert!(!std::ptr::eq(resolved, a_ref));
}
