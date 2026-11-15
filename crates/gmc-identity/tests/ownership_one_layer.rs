//! Single-layer coFay ownership & two-class authorization conformance tests
//! (`realign-cofay-ownership-to-fayid`).

use gmc_identity::authority::{authorizes, DelegateStore};
use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::ownership::{OwnerKind, OwnerRef, OwnershipRegistry};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};
use proptest::prelude::*;

fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect();
    VerifyingKey::new(bytes)
}

fn make_id(seed: u8) -> IdentityId {
    derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk(seed))
        .expect("valid ed25519 vk")
}

#[test]
fn owner_must_be_human_or_organization() {
    let mut reg = OwnershipRegistry::new();
    let cofay_a = make_id(1);
    let human = OwnerRef {
        id: "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        kind: OwnerKind::Human,
    };
    reg.set_owner(cofay_a.clone(), human.clone())
        .expect("human owner accepted");
    assert_eq!(reg.owner_of(&cofay_a), Some(&human));

    let cofay_b = make_id(2);
    let org = OwnerRef {
        id: "org_ifay-foundation".into(),
        kind: OwnerKind::Organization,
    };
    reg.set_owner(cofay_b.clone(), org.clone())
        .expect("organization owner accepted");
    assert_eq!(reg.owner_of(&cofay_b), Some(&org));
    assert_eq!(reg.len(), 2);
}

#[test]
fn ownership_has_no_path_or_depth() {
    let reg = OwnershipRegistry::new();
    assert_eq!(reg.len(), 0);
    assert!(reg.is_empty());
}

#[test]
fn owner_type_not_allowed_is_rejected_without_state_mutation() {
    let mut reg = OwnershipRegistry::new();
    let cofay = make_id(3);

    // Raw kind other than "human" / "organization" -> OwnerTypeNotAllowed
    let err_ifay = reg
        .set_owner_raw(
            cofay.clone(),
            "ifay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ifay",
        )
        .unwrap_err();
    assert_eq!(err_ifay, IdentityError::OwnerTypeNotAllowed);
    assert!(reg.is_empty());

    let err_cofay = reg
        .set_owner_raw(
            cofay.clone(),
            "cofay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "cofay",
        )
        .unwrap_err();
    assert_eq!(err_cofay, IdentityError::OwnerTypeNotAllowed);
    assert!(reg.is_empty());

    // Spoofing an iFay or coFay or Organization ID under Human tag -> OwnerTypeNotAllowed
    for bad_human_id in [
        "ifay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cofay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "org_ifay-foundation",
        "fay1.ed25519.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let err = reg
            .set_owner(
                cofay.clone(),
                OwnerRef {
                    id: bad_human_id.into(),
                    kind: OwnerKind::Human,
                },
            )
            .unwrap_err();
        assert_eq!(
            err,
            IdentityError::OwnerTypeNotAllowed,
            "should reject {bad_human_id}"
        );
    }

    // Spoofing a Human ID under Organization tag -> OwnerTypeNotAllowed
    let err_mismatch = reg
        .set_owner(
            cofay.clone(),
            OwnerRef {
                id: "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                kind: OwnerKind::Organization,
            },
        )
        .unwrap_err();
    assert_eq!(err_mismatch, IdentityError::OwnerTypeNotAllowed);
    assert!(reg.is_empty());
}

#[test]
fn granting_ifay_delegate_authority_preserves_owner_and_rejects_unrelated_actor() {
    let schemes = SchemeRegistry::default();
    let tag = SchemeTag::ed25519();
    let human_vk = vk(10);
    let human_derived = derive_identity_id(&schemes, &tag, &human_vk).unwrap();
    let human_owner = OwnerRef {
        id: format!("hid_{}", human_derived.key_repr()),
        kind: OwnerKind::Human,
    };

    let cofay_id = make_id(20);
    let manager_ifay_vk = vk(30);
    let unrelated_vk = vk(40);

    let mut ownership = OwnershipRegistry::new();
    ownership
        .set_owner(cofay_id.clone(), human_owner.clone())
        .expect("set human owner");

    let mut delegates = DelegateStore::new();
    delegates
        .add_delegate(&cofay_id, &manager_ifay_vk)
        .expect("grant manager iFay delegate");

    // 1. Human owner key is authorized
    assert!(authorizes(
        &cofay_id, &tag, &human_vk, &schemes, &ownership, &delegates
    ));
    // 2. Active manager iFay delegate key is authorized, and owner is unchanged!
    assert!(authorizes(
        &cofay_id,
        &tag,
        &manager_ifay_vk,
        &schemes,
        &ownership,
        &delegates
    ));
    assert_eq!(ownership.owner_of(&cofay_id), Some(&human_owner));
    // 3. Unrelated actor is rejected
    assert!(!authorizes(
        &cofay_id,
        &tag,
        &unrelated_vk,
        &schemes,
        &ownership,
        &delegates
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_single_layer_ownership_never_accepts_ifay_or_cofay_prefix(
        seed in any::<u8>(),
        suffix in "[a-z2-7]{16,52}",
        as_org in any::<bool>(),
    ) {
        let mut reg = OwnershipRegistry::new();
        let cofay = make_id(seed);
        let kind = if as_org { OwnerKind::Organization } else { OwnerKind::Human };

        let ifay_attempt = OwnerRef { id: format!("ifay_{suffix}"), kind };
        let cofay_attempt = OwnerRef { id: format!("cofay_{suffix}"), kind };

        prop_assert_eq!(reg.set_owner(cofay.clone(), ifay_attempt), Err(IdentityError::OwnerTypeNotAllowed));
        prop_assert_eq!(reg.set_owner(cofay.clone(), cofay_attempt), Err(IdentityError::OwnerTypeNotAllowed));
        prop_assert!(reg.is_empty());
    }
}
