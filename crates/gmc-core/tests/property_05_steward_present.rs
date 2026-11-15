//! Property 5 (`Feature: gmc-core-protocol`) — **每条链至少一个 Steward**.
//!
//! For any successfully created `Nested_Merit_Chain`, its `stewards` set contains at
//! least one Steward identifier (_design Correctness Properties, Property 5;
//! Requirement 2.4_).
//!
//! This is the single numbered property test for Property 5. It drives a
//! [`ChainRegistry`] (seeded with a controlled, single-steward `GMC_Base` root) with a
//! generated sequence of [`DeriveRequest`]s. Most requests carry a generated
//! **non-empty** steward vector (`1..=4` stewards); a fraction carry an **empty**
//! steward vector. The empty-steward requests confirm the rejection side of the rule:
//! `Chain_Registry::derive` (through `NestedMeritChain::new`) returns an error and
//! creates **no** chain. After replaying the whole sequence, every chain present in
//! the registry other than the controlled root — i.e. every chain that was
//! *successfully created* via `derive` — must carry at least one Steward.

use gmc_core::registry::{ChainRegistry, DeriveRequest, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, FayID, Timestamp};
use proptest::prelude::*;

/// Id of the controlled `GMC_Base` root that seeds every generated registry.
const ROOT_ID: &str = "gmc-base";

/// Builds a fresh registry seeded with a controlled, single-steward depth-0 root.
///
/// The root is the only chain in the registry whose existence the test controls; all
/// other chains are produced by the generated `derive` sequence and are therefore the
/// "successfully created `Nested_Merit_Chain`s" Property 5 quantifies over.
fn fresh_registry() -> ChainRegistry {
    let root = NestedMeritChain::root(
        ChainId::new(ROOT_ID),
        "root",
        vec![FayID::new("root-steward")],
        Timestamp::from_secs(1_000),
    );
    ChainRegistry::with_root(root).expect("controlled root is a valid depth-0 root")
}

/// A generated derive request specification mapped onto [`DeriveRequest`].
#[derive(Debug, Clone)]
struct DeriveSpec {
    proposed_id: ChainId,
    parent_id: ChainId,
    domain: String,
    stewards: Vec<FayID>,
    origin_type: OriginType,
}

/// One of the three derivation origin channels.
fn origin_type() -> impl Strategy<Value = OriginType> {
    prop_oneof![
        Just(OriginType::VoteInitiated),
        Just(OriginType::StewardInitiated),
        Just(OriginType::InstitutionApplied),
    ]
}

/// A `ChainId` drawn from a small fixed pool (so proposed ids and parent ids collide,
/// exercising both successful derivations and assorted rejections).
fn pool_chain_id() -> impl Strategy<Value = ChainId> {
    (0u32..8).prop_map(|n| ChainId::new(format!("c{n}")))
}

/// Parent id for a derive request, biased toward the root (and existing pool ids) so
/// derivations frequently succeed and real chains get created to quantify over.
fn parent_id() -> impl Strategy<Value = ChainId> {
    prop_oneof![
        3 => Just(ChainId::new(ROOT_ID)),
        2 => pool_chain_id(),
    ]
}

/// A non-empty domain identifier (the empty-domain `MissingField` path is covered by
/// Property 4; here domains are non-empty so successful creations actually occur).
fn domain() -> impl Strategy<Value = String> {
    (0u32..6).prop_map(|n| format!("domain-{n}"))
}

/// A steward vector: roughly one in four is **empty** (to exercise the rejection of
/// stewardless chains), the rest carry `1..=4` stewards.
fn stewards() -> impl Strategy<Value = Vec<FayID>> {
    prop_oneof![
        1 => Just(Vec::<FayID>::new()),
        3 => proptest::collection::vec(
            (0u32..32).prop_map(|n| FayID::new(format!("fay-{n}"))),
            1..=4,
        ),
    ]
}

/// A single derive request specification.
fn derive_spec() -> impl Strategy<Value = DeriveSpec> {
    (
        pool_chain_id(),
        parent_id(),
        domain(),
        stewards(),
        origin_type(),
    )
        .prop_map(
            |(proposed_id, parent_id, domain, stewards, origin_type)| DeriveSpec {
                proposed_id,
                parent_id,
                domain,
                stewards,
                origin_type,
            },
        )
}

/// A sequence of `0..=max_len` derive request specifications.
fn derive_specs(max_len: usize) -> impl Strategy<Value = Vec<DeriveSpec>> {
    proptest::collection::vec(derive_spec(), 0..=max_len)
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 5: 每条链至少一个 Steward
    #[test]
    fn property_5_every_chain_has_at_least_one_steward(specs in derive_specs(24)) {
        let mut registry = fresh_registry();

        for spec in specs {
            let empty_stewards = spec.stewards.is_empty();
            let len_before = registry.len();

            let req = DeriveRequest::new(
                spec.proposed_id.clone(),
                spec.parent_id.clone(),
                spec.domain.clone(),
                spec.stewards.clone(),
                spec.origin_type,
                Timestamp::from_secs(2_000),
            );
            let result = registry.derive(req);

            if empty_stewards {
                // A stewardless derive request must be rejected and create no chain
                // (Requirement 2.4): `derive` validates up front and fails atomically.
                prop_assert!(
                    result.is_err(),
                    "empty-steward derive must be rejected, got Ok"
                );
                prop_assert_eq!(
                    registry.len(),
                    len_before,
                    "rejected empty-steward derive must not add a chain"
                );
            }
        }

        // Property 5: every successfully created chain — every chain in the registry
        // other than the controlled root — carries at least one Steward.
        let root_id = ChainId::new(ROOT_ID);
        for chain in registry.iter() {
            if chain.id() == &root_id {
                continue;
            }
            prop_assert!(
                chain.stewards().len() >= 1,
                "created chain {} must have >= 1 steward, found {}",
                chain.id(),
                chain.stewards().len()
            );
        }
    }
}
