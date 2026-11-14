//! Property 8 — on-behalf-of authorization (owner / ancestor / active delegate).
//!
//! Design *Authority_Resolver* / Property 8: 代表身份的授权判定（owner / 祖先 /
//! 有效 Delegate / 活跃未吊销密钥）.
//! Validates Requirements 7.1, 7.2, 7.3, 7.4, 7.5, 8.4, 9.3, 9.5, 11.4, 13.3.
//!
//! Full statement: a signer is authorized to act **on behalf of** a coFay **iff** the
//! signer is one of — the coFay's **owner**, any **ancestor** on its root-first
//! ownership path, or a currently **non-revoked (Active)** `Delegate` key. A revoked
//! delegate or a never-registered key is always **unauthorized**.
//!
//! The test builds a fixed-shape three-level ownership chain
//! `root iFay → coFay_1 → coFay_2`, deriving each [`IdentityId`] from its own
//! verifying key (so the structural identities are real derivations, exercising the
//! owner/ancestor branches that compare the signer's *derived* id). A delegate key and
//! two unrelated keys are drawn independently; `prop_assume!` keeps all six keys
//! pairwise distinct so no generated key accidentally collides with a structural
//! identity (which would turn an "unauthorized" probe into an authorized owner/ancestor
//! or vice versa). Each authorization branch and its negative are then asserted across
//! 100 random key draws.

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::BTreeSet;

use gmc_identity::authority::{authorizes, DelegateStore};
use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::SchemeTag;

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 8: 代表身份的授权判定（owner / 祖先 / 有效 Delegate / 活跃未吊销密钥）
    #[test]
    fn property_08_authorization_owner_ancestor_active_delegate(
        vk_root in generators::verifying_key_valid(),
        vk_c1 in generators::verifying_key_valid(),
        vk_c2 in generators::verifying_key_valid(),
        delegate_key in generators::verifying_key_valid(),
        unrelated_a in generators::verifying_key_valid(),
        unrelated_b in generators::verifying_key_valid(),
    ) {
        // Keep all six keys pairwise distinct. Derivation is an injective bijection of
        // the key bytes, so distinct valid-format keys derive distinct IdentityIds —
        // this guarantees the delegate / unrelated keys never collide with a structural
        // identity (root / c1 / c2) and that the ownership chain is well-formed (a
        // duplicate structural key would self-parent and fail to attach).
        let all = [&vk_root, &vk_c1, &vk_c2, &delegate_key, &unrelated_a, &unrelated_b];
        let distinct: BTreeSet<&[u8]> = all.iter().map(|k| k.as_bytes()).collect();
        prop_assume!(distinct.len() == all.len());

        // The default registry supports ed25519; every valid-format vk derives an id.
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();

        let root_id = derive_identity_id(&registry, &tag, &vk_root).expect("valid ed25519 vk");
        let c1_id = derive_identity_id(&registry, &tag, &vk_c1).expect("valid ed25519 vk");
        let c2_id = derive_identity_id(&registry, &tag, &vk_c2).expect("valid ed25519 vk");

        // Ownership chain: root iFay → coFay_1 → coFay_2.
        // ancestors_of(c2) = [root, c1]; owner_of(c2) = c1.
        let mut ownership = OwnershipRegistry::new();
        ownership.register_root(&root_id).expect("register root iFay");
        ownership.attach(&c1_id, &root_id).expect("attach coFay_1 under root");
        ownership.attach(&c2_id, &c1_id).expect("attach coFay_2 under coFay_1");

        // A delegate of coFay_2 that is neither owner nor ancestor of it.
        let mut delegates = DelegateStore::new();
        delegates.add_delegate(&c2_id, &delegate_key).expect("add delegate");

        // (1) Owner branch — coFay_1's key is coFay_2's direct owner → authorized.
        prop_assert!(authorizes(&c2_id, &tag, &vk_c1, &registry, &ownership, &delegates));

        // (2) Ancestor branch — the root iFay is an ancestor of coFay_2 → authorized.
        prop_assert!(authorizes(&c2_id, &tag, &vk_root, &registry, &ownership, &delegates));

        // (3) Active delegate branch — the non-revoked delegate key → authorized.
        prop_assert!(authorizes(&c2_id, &tag, &delegate_key, &registry, &ownership, &delegates));

        // Negative — unrelated, never-registered keys (not owner/ancestor/delegate) are
        // unauthorized (Requirement 7.4).
        prop_assert!(!authorizes(&c2_id, &tag, &unrelated_a, &registry, &ownership, &delegates));
        prop_assert!(!authorizes(&c2_id, &tag, &unrelated_b, &registry, &ownership, &delegates));

        // Revoke the delegate → the same key is now unauthorized (Requirement 7.5);
        // owner and ancestor branches are unaffected by the revocation.
        delegates.revoke_delegate(&c2_id, &delegate_key).expect("revoke delegate");
        prop_assert!(!authorizes(&c2_id, &tag, &delegate_key, &registry, &ownership, &delegates));
        prop_assert!(authorizes(&c2_id, &tag, &vk_c1, &registry, &ownership, &delegates));
        prop_assert!(authorizes(&c2_id, &tag, &vk_root, &registry, &ownership, &delegates));
    }
}
