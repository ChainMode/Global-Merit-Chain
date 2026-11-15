//! FayID canonical string interop, OpaqueRef privacy boundary, and monotonic
//! RevocationRegistry conformance tests (`align-identity-with-fayid-authority`).

use gmc_identity::error::IdentityError;
use gmc_identity::fayid_interop::{
    from_fayid_canonical, parse_fayid_entity, to_fayid_canonical, FayIdEntityKind, OpaqueRef,
    OpaqueRefBinding, RevocationRegistry,
};
use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{IdentityKind, SchemeTag, VerifyingKey};

fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(13).wrapping_add(seed))
        .collect();
    VerifyingKey::new(bytes)
}

#[test]
fn canonical_ifay_and_cofay_mapping_is_lossless_and_roundtrips() {
    let schemes = SchemeRegistry::default();
    let id = derive_identity_id(&schemes, &SchemeTag::ed25519(), &vk(1)).unwrap();

    let ifay_str = to_fayid_canonical(&id, IdentityKind::IFay).expect("ed25519 maps to ifay_");
    assert!(ifay_str.starts_with("ifay_"));
    let (back_id, back_kind) =
        from_fayid_canonical(&schemes, &ifay_str).expect("valid canonical ifay_");
    assert_eq!(back_id, id);
    assert_eq!(back_kind, IdentityKind::IFay);

    let cofay_str = to_fayid_canonical(&id, IdentityKind::CoFay).expect("ed25519 maps to cofay_");
    assert!(cofay_str.starts_with("cofay_"));
    let (back_cofay_id, back_cofay_kind) =
        from_fayid_canonical(&schemes, &cofay_str).expect("valid canonical cofay_");
    assert_eq!(back_cofay_id, id);
    assert_eq!(back_cofay_kind, IdentityKind::CoFay);

    assert_eq!(
        from_fayid_canonical(&schemes, "ifay_UPPERCASE===="),
        Err(IdentityError::IdentityIdFormatInvalid)
    );
}

#[test]
fn opaque_ref_enforces_no_plaintext_human_id_on_chain_and_groups_ifays() {
    let human_str = "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let parsed_human = parse_fayid_entity(human_str).expect("valid hid_");
    assert_eq!(parsed_human.kind, FayIdEntityKind::Human);
    assert!(OpaqueRef::parse(human_str).is_err());

    let opaque_str = "gmcref_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let opaque = OpaqueRef::parse(opaque_str).expect("valid gmcref_");
    assert_eq!(opaque.as_str(), opaque_str);

    let schemes = SchemeRegistry::default();
    let ifay_1 = to_fayid_canonical(
        &derive_identity_id(&schemes, &SchemeTag::ed25519(), &vk(2)).unwrap(),
        IdentityKind::IFay,
    )
    .unwrap();
    let ifay_2 = to_fayid_canonical(
        &derive_identity_id(&schemes, &SchemeTag::ed25519(), &vk(3)).unwrap(),
        IdentityKind::IFay,
    )
    .unwrap();

    let mut binding = OpaqueRefBinding::new();
    binding.bind_ifay(&ifay_1, opaque.clone()).unwrap();
    binding.bind_ifay(&ifay_2, opaque.clone()).unwrap();

    assert_eq!(binding.opaque_ref_of(&ifay_1), Some(&opaque));
    assert_eq!(binding.opaque_ref_of(&ifay_2), Some(&opaque));
    assert_eq!(binding.ifays_of(&opaque).len(), 2);
}

#[test]
fn revocation_registry_is_strictly_monotonic() {
    let mut rev = RevocationRegistry::new();
    let subkey_id = "dyn_cccccccccccccccccccccccccccccccccccccccccccccccccccc";
    assert!(!rev.is_revoked(subkey_id));

    rev.revoke(subkey_id, 1_700_000_000)
        .expect("first revoke succeeds");
    assert!(rev.is_revoked(subkey_id));
    assert_eq!(rev.revoked_at(subkey_id), Some(1_700_000_000));

    rev.revoke(subkey_id, 1_800_000_000)
        .expect("idempotent monotonic revoke");
    assert_eq!(rev.revoked_at(subkey_id), Some(1_700_000_000));

    // Root Human ID cannot be entered into GMChain RevocationRegistry
    assert_eq!(
        rev.revoke(
            "hid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1_700_000_000
        ),
        Err(IdentityError::OwnerTypeNotAllowed)
    );
}
