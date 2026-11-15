//! Executes normative JSON conformance vectors in `vectors/registry/` and
//! `vectors/bootstrap/` against `gmc_core` with zero external crates.

use gmc_core::bootstrap::{
    compute_normalized_governance_weight, BootstrapConfig, BootstrapMintRequest,
    BootstrapMintService, VoterIdentitySlice,
};
use gmc_core::error::GmcError;
use gmc_core::merit::{MeritPocket, E};
use gmc_core::registry::{ChainRegistry, DeriveRequest, NestedMeritChain, OriginType};
use gmc_core::types::{ChainId, Decimal, FayID, Timestamp};

const REGISTRY_VECTORS_JSON: &str =
    include_str!("../../../vectors/registry/chain-registry-vectors.json");
const BOOTSTRAP_VECTORS_JSON: &str =
    include_str!("../../../vectors/bootstrap/bootstrap-merit-vectors.json");

fn extract_str<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let idx = block.find(&needle)?;
    let rest = block[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn extract_i64(block: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let idx = block.find(&needle)?;
    let rest = block[idx + needle.len()..].trim_start();
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..digits_end].parse::<i64>().ok()
}

fn extract_i64_array(block: &str, key: &str) -> Option<Vec<i64>> {
    let needle = format!("\"{key}\":");
    let idx = block.find(&needle)?;
    let rest = block[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix('[')?;
    let end = rest.find(']')?;
    let items = rest[..end]
        .split(',')
        .map(|s| s.trim().parse::<i64>().expect("valid integer in array"))
        .collect();
    Some(items)
}

fn base_registry() -> ChainRegistry {
    let root = NestedMeritChain::root(
        ChainId::new("gmc-base"),
        "root",
        vec![FayID::new("hid_rootstewardaaaaaaaaaaaaaaaaaaaaa")],
        Timestamp::from_secs(0),
    );
    ChainRegistry::with_root(root).expect("valid root")
}

#[test]
fn all_registry_json_vectors_match_runtime_behavior() {
    let arr_start = REGISTRY_VECTORS_JSON
        .find("\"vectors\"")
        .expect("vectors array present");
    let body = &REGISTRY_VECTORS_JSON[arr_start..];
    let mut count = 0usize;

    for raw_obj in body.split('{').skip(1) {
        let Some(end_brace) = raw_obj.find('}') else {
            continue;
        };
        let obj = &raw_obj[..end_brace];
        let id = extract_str(obj, "id").expect("vector id");
        let scenario = extract_str(obj, "scenario").expect("scenario");

        match scenario {
            "unbounded_depth" => {
                let target_depth = extract_i64(obj, "targetDepth").unwrap() as u32;
                let steward = extract_str(obj, "stewardId").unwrap();
                let mut reg = base_registry();
                let mut parent = ChainId::new("gmc-base");
                for d in 1..=target_depth {
                    let cid = ChainId::new(format!("vec-depth-{d}"));
                    reg.derive(DeriveRequest::new(
                        cid.clone(),
                        parent,
                        format!("dom-{d}"),
                        vec![FayID::new(steward)],
                        OriginType::StewardInitiated,
                        Timestamp::from_secs(d as u64),
                    ))
                    .unwrap_or_else(|e| panic!("vector {id} failed at depth {d}: {e:?}"));
                    parent = cid;
                }
                assert_eq!(reg.get(&parent).unwrap().depth(), target_depth);
            }
            "duplicate_org_binding" => {
                let org_id = extract_str(obj, "organizationId").unwrap();
                let c1 = extract_str(obj, "firstChainId").unwrap();
                let c2 = extract_str(obj, "secondChainId").unwrap();
                let steward = extract_str(obj, "stewardId").unwrap();
                let mut reg = base_registry();
                reg.derive(
                    DeriveRequest::new(
                        ChainId::new(c1),
                        ChainId::new("gmc-base"),
                        "dom-1",
                        vec![FayID::new(steward)],
                        OriginType::InstitutionApplied,
                        Timestamp::from_secs(1),
                    )
                    .with_organization_id(org_id),
                )
                .expect("first org binding succeeds");
                let err = reg
                    .derive(
                        DeriveRequest::new(
                            ChainId::new(c2),
                            ChainId::new("gmc-base"),
                            "dom-2",
                            vec![FayID::new(steward)],
                            OriginType::InstitutionApplied,
                            Timestamp::from_secs(2),
                        )
                        .with_organization_id(org_id),
                    )
                    .unwrap_err();
                assert_eq!(err, GmcError::OrganizationBindingConflict, "vector {id}");
            }
            "steward_validation" => {
                let cid = extract_str(obj, "chainId").unwrap();
                let steward = extract_str(obj, "stewardId").unwrap();
                let mut reg = base_registry();
                let err = reg
                    .derive(DeriveRequest::new(
                        ChainId::new(cid),
                        ChainId::new("gmc-base"),
                        "dom-bad",
                        vec![FayID::new(steward)],
                        OriginType::StewardInitiated,
                        Timestamp::from_secs(3),
                    ))
                    .unwrap_err();
                assert_eq!(err, GmcError::StewardTypeNotAllowed, "vector {id}");
            }
            "manager_delegation_preserves_steward" => {
                let cid = ChainId::new(extract_str(obj, "chainId").unwrap());
                let steward = FayID::new(extract_str(obj, "stewardId").unwrap());
                let manager = FayID::new(extract_str(obj, "managerIfayId").unwrap());
                let mut reg = base_registry();
                reg.derive(DeriveRequest::new(
                    cid.clone(),
                    ChainId::new("gmc-base"),
                    "dom-ops",
                    vec![steward.clone()],
                    OriginType::StewardInitiated,
                    Timestamp::from_secs(4),
                ))
                .expect("valid steward");
                reg.grant_chain_manager(&cid, manager.clone())
                    .expect("grant manager");
                assert!(reg.is_chain_manager(&cid, &manager));
                assert_eq!(reg.get(&cid).unwrap().stewards(), &[steward]);
            }
            other => panic!("unknown registry scenario {other}"),
        }
        count += 1;
    }

    assert_eq!(count, 5, "expected 5 registry vectors");
}

#[test]
fn all_bootstrap_json_vectors_match_runtime_behavior() {
    let arr_start = BOOTSTRAP_VECTORS_JSON
        .find("\"vectors\"")
        .expect("vectors array present");
    let body = &BOOTSTRAP_VECTORS_JSON[arr_start..];
    let mut count = 0usize;

    for raw_obj in body.split('{').skip(1) {
        let Some(end_brace) = raw_obj.find('}') else {
            continue;
        };
        let obj = &raw_obj[..end_brace];
        let id = extract_str(obj, "id").expect("vector id");
        let scenario = extract_str(obj, "scenario").expect("scenario");

        match scenario {
            "bootstrap_grant" => {
                let opaque = extract_str(obj, "opaqueRef").unwrap();
                let amt = extract_i64(obj, "amountInt").unwrap();
                let mut svc =
                    BootstrapMintService::new(BootstrapConfig::neutral_baseline()).unwrap();
                let mut pocket = MeritPocket::new(FayID::new("ifay_vec1"));
                svc.grant_initial_merit(
                    &mut pocket,
                    BootstrapMintRequest {
                        batch_id: "b1".into(),
                        opaque_ref: opaque.into(),
                        amount: Decimal::from_int(amt),
                        base_influence_duration_secs: 90 * 86_400,
                        acquired_at: Timestamp::from_secs(1_000),
                        source_chain_id: ChainId::new("gmc-base"),
                    },
                )
                .expect("grant succeeds");
                assert_eq!(pocket.batches[0].b, Decimal::ZERO, "vector {id}");
                assert_eq!(pocket.min_merit(), E, "vector {id}");
            }
            "lifetime_cap_across_ifays" => {
                let opaque = extract_str(obj, "opaqueRef").unwrap();
                let a1 = extract_i64(obj, "firstIfayAmountInt").unwrap();
                let a2 = extract_i64(obj, "secondIfayAmountInt").unwrap();
                let a3 = extract_i64(obj, "thirdIfayOverflowInt").unwrap();
                let cfg = BootstrapConfig::neutral_baseline();
                let cd = cfg.cooldown_secs;
                let mut svc = BootstrapMintService::new(cfg).unwrap();
                let mut p1 = MeritPocket::new(FayID::new("ifay_v1"));
                let mut p2 = MeritPocket::new(FayID::new("ifay_v2"));
                let mut p3 = MeritPocket::new(FayID::new("ifay_v3"));

                svc.grant_initial_merit(
                    &mut p1,
                    BootstrapMintRequest {
                        batch_id: "cap-1".into(),
                        opaque_ref: opaque.into(),
                        amount: Decimal::from_int(a1),
                        base_influence_duration_secs: 86_400,
                        acquired_at: Timestamp::from_secs(1_000),
                        source_chain_id: ChainId::new("gmc-base"),
                    },
                )
                .unwrap();
                svc.grant_initial_merit(
                    &mut p2,
                    BootstrapMintRequest {
                        batch_id: "cap-2".into(),
                        opaque_ref: opaque.into(),
                        amount: Decimal::from_int(a2),
                        base_influence_duration_secs: 86_400,
                        acquired_at: Timestamp::from_secs(1_000 + cd + 1),
                        source_chain_id: ChainId::new("gmc-base"),
                    },
                )
                .unwrap();
                let err = svc
                    .grant_initial_merit(
                        &mut p3,
                        BootstrapMintRequest {
                            batch_id: "cap-3".into(),
                            opaque_ref: opaque.into(),
                            amount: Decimal::from_int(a3),
                            base_influence_duration_secs: 86_400,
                            acquired_at: Timestamp::from_secs(1_000 + 2 * (cd + 1)),
                            source_chain_id: ChainId::new("gmc-base"),
                        },
                    )
                    .unwrap_err();
                assert_eq!(err, GmcError::BootstrapCapExceeded, "vector {id}");
            }
            "one_way_lock" => {
                let batch_id = extract_str(obj, "batchId").unwrap();
                let svc = BootstrapMintService::new(BootstrapConfig::neutral_baseline()).unwrap();
                assert_eq!(
                    svc.reject_redemption(batch_id),
                    Err(GmcError::OperationNotAllowed)
                );
                assert_eq!(
                    svc.reject_transfer(batch_id, "ifay_other"),
                    Err(GmcError::OperationNotAllowed)
                );
            }
            "concave_voting_normalization" => {
                let opaque = extract_str(obj, "opaqueRef").unwrap();
                let splits = extract_i64_array(obj, "splitAmountsInt").unwrap();
                let consolidated = extract_i64(obj, "consolidatedAmountInt").unwrap();
                let expected_raw = extract_i64(obj, "expectedConsolidatedWeightRaw").unwrap();

                let split_slices: Vec<VoterIdentitySlice> = splits
                    .iter()
                    .enumerate()
                    .map(|(idx, &amt)| VoterIdentitySlice {
                        ifay_id: format!("ifay_split{idx}"),
                        opaque_ref: opaque.into(),
                        effective_merit: Decimal::from_int(amt),
                    })
                    .collect();
                let single_slice = vec![VoterIdentitySlice {
                    ifay_id: "ifay_single".into(),
                    opaque_ref: opaque.into(),
                    effective_merit: Decimal::from_int(consolidated),
                }];

                let w_split = compute_normalized_governance_weight(&split_slices).unwrap();
                let w_single = compute_normalized_governance_weight(&single_slice).unwrap();
                assert_eq!(w_split[opaque], w_single[opaque], "vector {id}");
                assert_eq!(w_single[opaque].raw(), expected_raw as i128, "vector {id}");
            }
            other => panic!("unknown bootstrap scenario {other}"),
        }
        count += 1;
    }

    assert_eq!(count, 4, "expected 4 bootstrap vectors");
}
