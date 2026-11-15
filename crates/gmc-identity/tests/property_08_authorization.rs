//! Property 8 — 代表 coFay 行事的两类合法主体授权判定（owner / 有效 Delegate）.
//!
//! Aligned with `realign-cofay-ownership-to-fayid` & FayID ADR 0001:
//! A signer is authorized to act **on behalf of** a `coFay` **iff** the signer belongs
//! to **one of the two permitted classes**:
//! 1. the `coFay`'s single-layer **owner** (`HumanID` or `OrganizationID` key), or
//! 2. a currently **non-revoked (Active)** `Delegate` key (including an `iFay` granted
//!    management authority without altering `owner`).
//!
//! Any former "ancestor" key, revoked delegate, or unrelated key is strictly rejected.

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::BTreeSet;

use gmc_identity::authority::{authorizes, DelegateStore};
use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::ownership::{OwnerKind, OwnerRef, OwnershipRegistry};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::SchemeTag;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 8: 代表身份的两类授权判定（owner / 有效 Delegate）
    #[test]
    fn property_08_authorization_two_classes_owner_or_active_delegate(
        vk_parent_org in generators::verifying_key_valid(),
        vk_owner in generators::verifying_key_valid(),
        vk_cofay in generators::verifying_key_valid(),
        delegate_key in generators::verifying_key_valid(),
        unrelated_a in generators::verifying_key_valid(),
        unrelated_b in generators::verifying_key_valid(),
        owner_is_org in any::<bool>(),
    ) {
        let all = [&vk_parent_org, &vk_owner, &vk_cofay, &delegate_key, &unrelated_a, &unrelated_b];
        let distinct: BTreeSet<&[u8]> = all.iter().map(|k| k.as_bytes()).collect();
        prop_assume!(distinct.len() == all.len());

        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();

        let owner_derived = derive_identity_id(&registry, &tag, &vk_owner).expect("valid ed25519 vk");
        let cofay_id = derive_identity_id(&registry, &tag, &vk_cofay).expect("valid ed25519 vk");

        let owner_ref = if owner_is_org {
            OwnerRef::new(format!("org_{}", owner_derived.key_repr()), OwnerKind::Organization)
        } else {
            OwnerRef::new(format!("hid_{}", owner_derived.key_repr()), OwnerKind::Human)
        };

        let mut ownership = OwnershipRegistry::new();
        ownership.set_owner(cofay_id.clone(), owner_ref.clone()).expect("set single-layer owner");

        let mut delegates = DelegateStore::new();
        delegates.add_delegate(&cofay_id, &delegate_key).expect("add delegate");

        // Class 1: Direct owner key -> authorized.
        prop_assert!(authorizes(&cofay_id, &tag, &vk_owner, &registry, &ownership, &delegates));

        // Class 2: Active delegate key (e.g. manager iFay) -> authorized, and owner is unchanged.
        prop_assert!(authorizes(&cofay_id, &tag, &delegate_key, &registry, &ownership, &delegates));
        prop_assert_eq!(ownership.owner_of(&cofay_id), Some(&owner_ref));

        // Former "ancestor" / parent-org key -> strictly REJECTED (no multi-hop ancestor class).
        prop_assert!(!authorizes(&cofay_id, &tag, &vk_parent_org, &registry, &ownership, &delegates));

        // Unrelated keys -> REJECTED.
        prop_assert!(!authorizes(&cofay_id, &tag, &unrelated_a, &registry, &ownership, &delegates));
        prop_assert!(!authorizes(&cofay_id, &tag, &unrelated_b, &registry, &ownership, &delegates));

        // Revoke delegate -> now unauthorized; direct owner unaffected.
        delegates.revoke_delegate(&cofay_id, &delegate_key).expect("revoke delegate");
        prop_assert!(!authorizes(&cofay_id, &tag, &delegate_key, &registry, &ownership, &delegates));
        prop_assert!(authorizes(&cofay_id, &tag, &vk_owner, &registry, &ownership, &delegates));
    }
}
