//! Unbounded derivation depth, OrganizationID <-> ChainId 1:1 binding, and
//! natural-person Steward enforcement tests (`realign-cofay-ownership-to-fayid`).

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
fn derivation_succeeds_at_depth_17_and_beyond_while_retaining_cycle_guard() {
    let mut registry = base_registry();
    let mut parent = ChainId::new("gmc-base");

    for d in 1..=20u32 {
        let id = ChainId::new(format!("chain-depth-{d}"));
        let req = DeriveRequest::new(
            id.clone(),
            parent.clone(),
            format!("domain-{d}"),
            vec![FayID::new(
                "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
            OriginType::StewardInitiated,
            Timestamp::from_secs(d as u64),
        );
        registry
            .derive(req)
            .unwrap_or_else(|e| panic!("depth {d} must not be rejected, got {e:?}"));
        parent = id;
    }

    let deepest = registry.get(&parent).expect("depth 20 chain present");
    assert_eq!(deepest.depth(), 20);
    assert_eq!(deepest.path().len(), 21);

    // Cycle check remains enforced: self-parenting or re-parenting an ancestor fails
    let cycle_req = DeriveRequest::new(
        ChainId::new("chain-depth-1"),
        parent,
        "cycle-domain",
        vec![FayID::new(
            "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )],
        OriginType::StewardInitiated,
        Timestamp::from_secs(99),
    );
    assert_eq!(registry.derive(cycle_req), Err(GmcError::CycleConflict));
}

#[test]
fn organization_id_and_subchain_are_bound_one_to_one() {
    let mut registry = base_registry();
    let steward = vec![FayID::new(
        "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )];

    let req1 = DeriveRequest::new(
        ChainId::new("subchain-org-1"),
        ChainId::new("gmc-base"),
        "org-1-domain",
        steward.clone(),
        OriginType::InstitutionApplied,
        Timestamp::from_secs(10),
    )
    .with_organization_id("org_alpha-dao");

    let cid = registry
        .derive(req1)
        .expect("first org subchain derivation succeeds");
    assert_eq!(registry.chain_for_organization("org_alpha-dao"), Some(&cid));
    assert_eq!(registry.organization_for_chain(&cid), Some("org_alpha-dao"));

    // Duplicate OrganizationID binding to a second subchain MUST fail atomically
    let dup_org_req = DeriveRequest::new(
        ChainId::new("subchain-org-2"),
        ChainId::new("gmc-base"),
        "org-2-domain",
        steward,
        OriginType::InstitutionApplied,
        Timestamp::from_secs(11),
    )
    .with_organization_id("org_alpha-dao");

    assert_eq!(
        registry.derive(dup_org_req),
        Err(GmcError::OrganizationBindingConflict)
    );
    assert!(!registry.contains(&ChainId::new("subchain-org-2")));

    // Reject non-organization prefix in organization binding
    let bad_org_req = DeriveRequest::new(
        ChainId::new("subchain-org-3"),
        ChainId::new("gmc-base"),
        "org-3-domain",
        vec![FayID::new(
            "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )],
        OriginType::InstitutionApplied,
        Timestamp::from_secs(12),
    )
    .with_organization_id("ifay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        registry.derive(bad_org_req),
        Err(GmcError::OrganizationBindingConflict)
    );
}
