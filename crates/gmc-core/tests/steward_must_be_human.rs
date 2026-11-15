//! Steward natural-person enforcement & management authority separation tests
//! (`realign-cofay-ownership-to-fayid` Task 4.6).

use gmc_core::error::GmcError;
use gmc_core::registry::{ChainRegistry, DeriveRequest, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, FayID, Timestamp};

fn base_registry() -> ChainRegistry {
    let root = NestedMeritChain::root(
        ChainId::new("gmc-base"),
        "root",
        vec![FayID::new(
            "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )],
        Timestamp::from_secs(0),
    );
    ChainRegistry::with_root(root).expect("valid root")
}

#[test]
fn steward_must_be_natural_person_rejecting_ifay_and_cofay() {
    let mut registry = base_registry();

    for forbidden_steward in [
        "ifay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cofay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "org_ifay-foundation",
        "fay1.ed25519.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let req = DeriveRequest::new(
            ChainId::new("subchain-bad-steward"),
            ChainId::new("gmc-base"),
            "domain-bad-steward",
            vec![FayID::new(forbidden_steward)],
            OriginType::StewardInitiated,
            Timestamp::from_secs(10),
        );
        assert_eq!(
            registry.derive(req),
            Err(GmcError::StewardTypeNotAllowed),
            "steward {forbidden_steward} must be rejected"
        );
        assert!(!registry.contains(&ChainId::new("subchain-bad-steward")));
    }
}

#[test]
fn granting_chain_manager_ifay_leaves_human_steward_unchanged() {
    let mut registry = base_registry();
    let human_steward = FayID::new("hid_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let chain_id = ChainId::new("subchain-managed");

    let req = DeriveRequest::new(
        chain_id.clone(),
        ChainId::new("gmc-base"),
        "domain-managed",
        vec![human_steward.clone()],
        OriginType::StewardInitiated,
        Timestamp::from_secs(20),
    );
    registry.derive(req).expect("human steward accepted");

    let manager_ifay = FayID::new("ifay_cccccccccccccccccccccccccccccccccccccccccccccccccccc");
    registry
        .grant_chain_manager(&chain_id, manager_ifay.clone())
        .expect("iFay can be granted chain management authority");

    assert!(registry.is_chain_manager(&chain_id, &manager_ifay));
    let chain = registry.get(&chain_id).unwrap();
    assert_eq!(chain.stewards(), &[human_steward]);
}
