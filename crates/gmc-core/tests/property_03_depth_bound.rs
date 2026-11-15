//! Property 3 — 无固定派生深度上限与可选实现侧显式边界 (`realign-cofay-ownership-to-fayid`).
//!
//! Per PO decision & `realign-cofay-ownership-to-fayid`, `Chain_Registry` imposes **no**
//! fixed protocol depth ceiling (depth 17+ derivations succeed cleanly while preserving
//! parent-exists, cycle-conflict, and `(parentId, domain)` uniqueness invariants). If an
//! implementation configures an explicit resource ceiling via `with_optional_max_depth`,
//! exceeding it is rejected atomically with [`GmcError::DepthExceeded`].

use gmc_core::error::GmcError;
use gmc_core::registry::{ChainRegistry, DeriveRequest, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, FayID, Timestamp};
use proptest::prelude::*;

const ROOT_ID: &str = "gmc-base";

fn new_registry() -> ChainRegistry {
    let root = NestedMeritChain::root(
        ChainId::new(ROOT_ID),
        "root",
        vec![FayID::new("hid_founder0000000000000000")],
        Timestamp::from_secs(0),
    );
    ChainRegistry::with_root(root).expect("GMC_Base is a valid depth-0 root")
}

#[derive(Debug, Clone)]
enum DeriveMove {
    ExtendDeepest,
    BranchAt(usize),
}

fn derive_move() -> impl Strategy<Value = DeriveMove> {
    prop_oneof![
        3 => Just(DeriveMove::ExtendDeepest),
        1 => (0usize..64).prop_map(DeriveMove::BranchAt),
    ]
}

fn derive_moves(max_len: usize) -> impl Strategy<Value = Vec<DeriveMove>> {
    proptest::collection::vec(derive_move(), 0..=max_len)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 3: 派生深度无固定上限与实现侧显式边界原子性
    #[test]
    fn property_3_unbounded_protocol_depth_and_explicit_impl_bound(moves in derive_moves(36)) {
        let mut unbounded = new_registry();
        let mut counter: u64 = 0;

        for mv in &moves {
            let parent_id: ChainId = match mv {
                DeriveMove::ExtendDeepest => unbounded
                    .iter()
                    .max_by_key(|chain| chain.depth())
                    .map(|chain| chain.id().clone())
                    .expect("registry always holds root"),
                DeriveMove::BranchAt(k) => {
                    let len = unbounded.len();
                    unbounded
                        .iter()
                        .nth(k % len)
                        .map(|chain| chain.id().clone())
                        .expect("non-zero len")
                }
            };

            counter += 1;
            let req = DeriveRequest::new(
                ChainId::new(format!("gen-{counter}")),
                parent_id,
                format!("dom-{counter}"),
                vec![FayID::new("hid_steward0000000000000000")],
                OriginType::StewardInitiated,
                Timestamp::from_secs(counter),
            );
            let derived = unbounded.derive(req).expect("unbounded protocol registry never rejects valid deep derive");
            let chain = unbounded.get(&derived).unwrap();
            prop_assert_eq!(chain.path().len() as u32, chain.depth() + 1);
        }
    }
}

#[test]
fn optional_implementation_depth_cap_rejects_explicitly_without_truncation() {
    let mut registry = new_registry().with_optional_max_depth(16);
    let mut parent = ChainId::new(ROOT_ID);

    for d in 1..=16u32 {
        let id = ChainId::new(format!("depth-{d}"));
        let req = DeriveRequest::new(
            id.clone(),
            parent,
            format!("domain-{d}"),
            vec![FayID::new("hid_steward0000000000000000")],
            OriginType::StewardInitiated,
            Timestamp::from_secs(d as u64),
        );
        registry.derive(req).expect("within configured impl cap");
        parent = id;
    }

    let before: Vec<NestedMeritChain> = registry.iter().cloned().collect();
    let req17 = DeriveRequest::new(
        ChainId::new("depth-17"),
        parent,
        "domain-17",
        vec![FayID::new("hid_steward0000000000000000")],
        OriginType::StewardInitiated,
        Timestamp::from_secs(17),
    );
    assert_eq!(registry.derive(req17), Err(GmcError::DepthExceeded));
    let after: Vec<NestedMeritChain> = registry.iter().cloned().collect();
    assert_eq!(before, after);
}
