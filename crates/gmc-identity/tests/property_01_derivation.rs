//! Property 1 — iFay 创建与 `IdentityId` 派生的确定性、单射性.
//!
//! Design *Identity_Service* / Property 1: iFay 创建与 IdentityId 派生的确定性、单射性.
//! Validates Requirements 2.1, 2.2, 2.3, 2.4.
//!
//! 对任意受支持方案标签 `tag` 与合法 `VerifyingKey`，创建 iFay 都会由 `(tag, vk)`
//! **确定性**派生出一个 `IdentityId`、将其拥有者记为自身、并记录该 `VerifyingKey` 与创建
//! 时间；且相同 `(tag, vk)` 始终得到相同 `IdentityId`（确定性），而同一方案下任意两个不同
//! 的 `VerifyingKey` 得到两个不同的 `IdentityId`（单射性）。
//!
//! - **确定性 (Requirement 2.3)**: `derive_identity_id` 对同一 `(tag, vk)` 调用两次返回
//!   相等的 `IdentityId`。
//! - **创建效果 (Requirements 2.1, 2.2)**: `create_ifay` 派生出的 id 与
//!   `derive_identity_id(tag, vk)` 相等；记录的 `kind` 为 `IFay`、`active_key == vk`、
//!   `created_at` 等于传入时间戳；该身份在归属注册表中记为自身拥有的深度 0 根
//!   (owner = None, depth = 0, 是 root)。
//! - **单射性 (Requirement 2.4)**: 同一 ed25519 方案下两个不同的 `VerifyingKey` 派生出两个
//!   不同的 `IdentityId`。

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_core::types::Timestamp;
use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::identity_service::IdentityService;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{IdentityKind, SchemeTag};

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 1: iFay 创建与 IdentityId 派生的确定性、单射性
    #[test]
    fn property_01_ifay_creation_derivation_determinism_and_injectivity(
        (tag, vk) in generators::scheme_and_verifying_key(),
        (vk_a, vk_b) in generators::two_distinct_verifying_keys(),
        secs in any::<u64>(),
    ) {
        // A default registry supports ed25519 (the tag produced by the generator).
        let registry = SchemeRegistry::default();
        let created_at = Timestamp::from_secs(secs);

        // --- 确定性 (Requirement 2.3): same (tag, vk) -> same IdentityId -------------
        let id1 = derive_identity_id(&registry, &tag, &vk)
            .expect("supported tag + valid-format vk derive an id");
        let id2 = derive_identity_id(&registry, &tag, &vk)
            .expect("derivation is deterministic for the same input");
        prop_assert_eq!(&id1, &id2);

        // --- 创建效果 (Requirements 2.1, 2.2): create_ifay records the full state ----
        let mut ownership = OwnershipRegistry::new();
        let mut binding = PocketBinding::new();
        let mut svc = IdentityService::new();

        let id = svc
            .create_ifay(&registry, &mut ownership, &mut binding, &tag, &vk, created_at)
            .expect("creating an iFay with a supported tag + valid vk succeeds");

        // The created id is exactly the deterministically-derived id from (tag, vk).
        prop_assert_eq!(&id, &id1);

        // The recorded identity captures kind = IFay, the VerifyingKey, and created_at.
        let record = svc.get(&id).expect("the created identity is recorded");
        prop_assert_eq!(record.kind, IdentityKind::IFay);
        prop_assert_eq!(&record.scheme_tag, &tag);
        prop_assert_eq!(&record.active_key, &vk);
        prop_assert_eq!(record.created_at, created_at);

        // Owner is itself: recorded as a self-sovereign depth-0 root (owner = None).
        prop_assert!(ownership.contains(&id));
        prop_assert!(ownership.owner_of(&id).is_none());
        prop_assert_eq!(ownership.depth_of(&id), Some(0));
        prop_assert!(ownership.node(&id).expect("root node recorded").is_root());

        // --- 单射性 (Requirement 2.4): distinct vks under one scheme -> distinct ids -
        let ed25519 = SchemeTag::ed25519();
        let id_a = derive_identity_id(&registry, &ed25519, &vk_a)
            .expect("valid-format vk_a derives an id");
        let id_b = derive_identity_id(&registry, &ed25519, &vk_b)
            .expect("valid-format vk_b derives an id");
        // vk_a != vk_b (generator guarantee) => the derived ids must differ.
        prop_assert_ne!(id_a, id_b);
    }
}
