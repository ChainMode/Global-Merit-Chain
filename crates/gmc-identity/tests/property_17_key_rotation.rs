//! Property 17 — 密钥轮换与 IdentityId 不变量.
//!
//! Design *Recovery_Service* / Property 17: 密钥轮换与 IdentityId 不变量.
//! Validates Requirements 11.1, 11.2, 11.3.
//!
//! 对任意由当前活跃密钥有效签名、携带新合法 VerifyingKey 的轮换序列，每次轮换都会将新
//! VerifyingKey 置为活跃、将原 VerifyingKey 置为已停用、追加一条含原/新 VerifyingKey 与
//! 轮换时间的轮换历史，并使该身份的 IdentityId 及其 Pocket 绑定与归属关系全程保持不变.
//!
//! ## How the sequence is driven
//!
//! [`RecoveryService::rotate_key`] performs the **rotation effect** but does not
//! authenticate the caller (that is `Identity_Core`'s job — the design routes a signed
//! `RotateKey` through verify → authorize → nonce before this effect runs). So this test
//! drives `rotate_key` directly with a sequence of distinct, valid new verifying keys,
//! each standing for "a rotation authorized by the current active key carrying a new
//! legal key".
//!
//! An iFay is created under the default ed25519 scheme from an initial key. We snapshot
//! the invariants tied to its (stable) [`IdentityId`] — the id itself, its Pocket lookup
//! key, and its ownership owner/path/depth — then apply each new key in turn. After every
//! rotation we assert: the new key is active, the *previous* active key has joined
//! `retired_keys` (which grows by exactly one), a [`RotationRecord`] `{old, new,
//! rotated_at}` was appended (history length == rotations so far, last record matches the
//! rotation), and the id / Pocket binding / ownership relationships are all unchanged.
//! Timestamps strictly increase across rotations, and each record's `rotated_at` matches.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::identity_service::IdentityService;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::recovery::RecoveryService;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, Timestamp, VerifyingKey};

/// The fixed initial active key the iFay is created with.
fn initial_key() -> VerifyingKey {
    VerifyingKey::new(vec![0xABu8; 32])
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 17: 密钥轮换与 IdentityId 不变量
    #[test]
    fn property_17_key_rotation_and_identity_id_invariant(
        raw_new_keys in proptest::collection::vec(generators::verifying_key_valid(), 0..=12),
    ) {
        let registry = SchemeRegistry::default();
        let mut ownership = OwnershipRegistry::new();
        let mut binding = PocketBinding::new();
        let mut svc = IdentityService::new();
        let mut recovery = RecoveryService::new();

        // Create the iFay from the fixed initial key under the default ed25519 scheme.
        let init = initial_key();
        let created_at = Timestamp::from_secs(1_000);
        let id = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &init,
                created_at,
            )
            .expect("32-byte vk is a valid ed25519 key");

        // Snapshot the invariants tied to the (stable) IdentityId (Requirement 11.2).
        let pocket_key_before = binding.pocket_key(&id);
        let owner_before = ownership.owner_of(&id).cloned();
        let path_before = ownership.path_of(&id).cloned();
        let depth_before = ownership.depth_of(&id);

        // Build a sequence of DISTINCT new verifying keys, each distinct from the initial
        // key, preserving first-occurrence order. Each rotation carries a fresh new key.
        let mut new_keys: Vec<VerifyingKey> = Vec::new();
        for k in raw_new_keys {
            if k != init && !new_keys.contains(&k) {
                new_keys.push(k);
            }
        }

        // The active key before the next rotation; starts at the initial key.
        let mut prev_active = init.clone();
        // Mirror of the expected retired_keys vector, in rotation order.
        let mut expected_retired: Vec<VerifyingKey> = Vec::new();

        for (i, new_key) in new_keys.iter().enumerate() {
            // Strictly increasing timestamp per rotation.
            let rotated_at = Timestamp::from_secs(2_000 + (i as u64) * 10);

            let record = recovery
                .rotate_key(&mut svc, &registry, &id, new_key, rotated_at)
                .expect("a valid new key rotates successfully");

            // The returned record describes this rotation exactly (Requirement 11.3).
            prop_assert_eq!(&record.old_key, &prev_active);
            prop_assert_eq!(&record.new_key, new_key);
            prop_assert_eq!(record.rotated_at, rotated_at);

            // The new key is now active; the previous active key joined retired_keys,
            // which grows by exactly one per rotation, in rotation order
            // (Requirements 11.1, 11.4).
            expected_retired.push(prev_active.clone());
            let identity = svc.get(&id).expect("identity still present after rotation");
            prop_assert_eq!(&identity.active_key, new_key);
            prop_assert_eq!(identity.retired_keys.len(), i + 1);
            prop_assert_eq!(&identity.retired_keys, &expected_retired);

            // One RotationRecord appended per rotation; history length == rotations so
            // far and the last record matches this rotation (Requirement 11.3).
            prop_assert_eq!(recovery.rotation_count(&id), i + 1);
            let history = recovery.history_of(&id);
            prop_assert_eq!(history.len(), i + 1);
            prop_assert_eq!(history.last(), Some(&record));

            // The IdentityId and everything keyed by it are unchanged throughout
            // (Requirement 11.2).
            prop_assert_eq!(&identity.id, &id);
            prop_assert_eq!(binding.pocket_key(&id), pocket_key_before.clone());
            prop_assert_eq!(ownership.owner_of(&id).cloned(), owner_before.clone());
            prop_assert_eq!(ownership.path_of(&id).cloned(), path_before.clone());
            prop_assert_eq!(ownership.depth_of(&id), depth_before);

            prev_active = new_key.clone();
        }

        // Final cross-check: total rotations == number of distinct new keys, and the
        // full rotation history chains old -> new across the whole sequence.
        prop_assert_eq!(recovery.rotation_count(&id), new_keys.len());
        let history = recovery.history_of(&id);
        for (i, rec) in history.iter().enumerate() {
            let expected_old = if i == 0 { &init } else { &new_keys[i - 1] };
            prop_assert_eq!(&rec.old_key, expected_old);
            prop_assert_eq!(&rec.new_key, &new_keys[i]);
        }
    }
}
