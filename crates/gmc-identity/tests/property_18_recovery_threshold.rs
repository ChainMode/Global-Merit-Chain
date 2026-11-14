//! Property 18 — 守护人 M-of-N 阈值与批准去重 (guardian M-of-N threshold + approval dedup).
//!
//! Design *Recovery_Service* `submitRecoveryApproval` / Property 18: 守护人 M-of-N 阈值与
//! 批准去重. Validates Requirements 12.4, 12.5, 12.6.
//!
//! Full statement: 对任意已配置 {守护人集合, 阈值 M} 的 iFay 及针对同一新 `VerifyingKey`
//! 的守护人批准序列（可含重复），账户恢复触发密钥轮换当且仅当按守护人去重后来自不同守护人的
//! 有效批准数达到 M：来自同一守护人的重复批准只计为一次；当去重后批准数达到 M 时活跃密钥轮换
//! 为该新 `VerifyingKey` 且 `IdentityId` 不变；当去重后批准数小于 M 时不轮换、活跃密钥保持
//! 不变并返回 `RecoveryThresholdNotMet`.
//!
//! ## What the test drives
//!
//! It configures an M-of-N guardian set for a freshly created ed25519 iFay, then replays
//! a guardian approval sequence (drawn from the configured guardians, *with possible
//! repeats*) for one candidate `new_key`, submitting one approval at a time. A model
//! [`BTreeSet`] of distinct guardians that have approved tracks the *effective*
//! (de-duplicated) approval count the service should compute:
//!
//! - while the distinct-approver count is **below** M, each submit returns
//!   `Err(RecoveryThresholdNotMet)` and the iFay's `active_key` is unchanged
//!   (Requirement 12.6); a repeat approval from an already-counted guardian does **not**
//!   raise the effective count (`approval_count` stays put);
//! - the **first** submit that pushes the distinct count to M returns
//!   `Ok(RotationRecord)`, rotates `active_key` to `new_key`, leaves the `IdentityId`
//!   fixed (Requirement 12.4), and clears the session so `approval_count` drops back to
//!   `0` (confirmed against `submit_recovery_approval` in `src/recovery.rs`, which
//!   `sessions.remove`s the consumed session after a successful rotate).
//!
//! `approval_count(&id, &new_key)` is asserted to equal the model's distinct-guardian
//! count at every pre-threshold step, so the dedup-by-guardian rule (Requirement 12.5) is
//! checked directly, not just via its threshold consequence.

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::BTreeSet;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_service::IdentityService;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::recovery::RecoveryService;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, Timestamp, VerifyingKey};

/// A valid-format (32-byte) ed25519 verifying key whose bytes vary with `seed`, so equal
/// seeds yield equal keys and distinct seeds yield distinct keys.
fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect();
    VerifyingKey::new(bytes)
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 18: 守护人 M-of-N 阈值与批准去重
    #[test]
    fn property_18_recovery_threshold_and_dedup(
        // A guardian pool of N distinct keys, N in 1..=6.
        guardian_count in 1usize..=6,
        // Threshold M in 1..=N, derived after we know N (see prop_assume below).
        m_raw in 1u32..=6,
        // Approver indices into the guardian pool, with repeats; non-empty so at least
        // one approval is exercised.
        approver_idx in proptest::collection::vec(0usize..6, 1..=24),
        // The candidate new key, drawn from the shared valid-vk generator so the
        // distinctness guards below have real work to do.
        new_key in generators::verifying_key_valid(),
    ) {
        // Build N DISTINCT guardian keys from seeds 1..=N (seed 0 reserved for the iFay's
        // initial active key; a high seed reserved for the candidate new_key).
        let guardians: Vec<VerifyingKey> = (1..=guardian_count as u8).map(vk).collect();
        let n = guardians.len() as u32;

        // Constrain M to 1..=N.
        let threshold = ((m_raw - 1) % n) + 1;
        prop_assume!(threshold >= 1 && threshold <= n);

        // The iFay's initial active key (seed 0), distinct from every guardian (seeds
        // 1..=6) by construction. The candidate `new_key` is generator-supplied; guard it
        // distinct from the guardians and the initial active key.
        let initial_key = vk(0);
        prop_assume!(!guardians.contains(&initial_key));
        prop_assume!(!guardians.contains(&new_key));
        prop_assume!(initial_key != new_key);

        // Fixtures: a default scheme registry (ed25519), ownership/pocket collaborators,
        // the identity service and the recovery service under test.
        let registry = SchemeRegistry::default();
        let mut ownership = OwnershipRegistry::new();
        let mut binding = PocketBinding::new();
        let mut svc = IdentityService::new();
        let mut recovery = RecoveryService::new();

        // Create the ed25519 iFay with the initial active key.
        let id = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &initial_key,
                Timestamp::from_secs(1_000),
            )
            .expect("valid ed25519 vk creates an iFay");

        // Configure M-of-N guardians for this iFay.
        recovery
            .configure_guardians(&svc, &id, &guardians, threshold)
            .expect("1 <= M <= N is a valid guardian configuration");

        // The stored config reflects the de-duplicated guardian set and threshold.
        let config = recovery.guardian_config(&id).expect("config was stored");
        prop_assert_eq!(config.threshold, threshold);
        prop_assert_eq!(config.guardian_count(), guardian_count);

        // Map raw approver indices onto actual guardian keys (mod N so every index hits a
        // configured guardian), preserving order and repeats.
        let approvers: Vec<VerifyingKey> = approver_idx
            .iter()
            .map(|&i| guardians[i % guardian_count].clone())
            .collect();

        // Model: the set of DISTINCT guardians that have approved so far, and whether the
        // rotation has already fired.
        let mut distinct_approvers: BTreeSet<VerifyingKey> = BTreeSet::new();
        let mut rotated = false;
        let threshold_usize = threshold as usize;

        for (step, guardian_key) in approvers.iter().enumerate() {
            let rotated_at = Timestamp::from_secs(2_000 + step as u64);

            if rotated {
                // After a successful rotation the session is cleared. Submitting further
                // approvals for the SAME new_key starts a fresh session; the active key is
                // already `new_key`, so we only assert the rotation has not been undone
                // and stop driving the model (the property's interesting window — the
                // first crossing of the threshold — has already been validated).
                let identity = svc.get(&id).expect("identity still present");
                prop_assert_eq!(&identity.active_key, &new_key);
                prop_assert_eq!(&identity.id, &id);
                break;
            }

            // Effective count BEFORE this approval, per the model.
            let count_before = distinct_approvers.len();
            prop_assert_eq!(recovery.approval_count(&id, &new_key), count_before);

            // Apply the approval to the model: a repeat from an already-counted guardian
            // does not raise the distinct count.
            let is_new_guardian = distinct_approvers.insert(guardian_key.clone());
            let effective_count = distinct_approvers.len();
            if !is_new_guardian {
                // Dedup: repeat approval leaves the effective count unchanged.
                prop_assert_eq!(effective_count, count_before);
            }

            // Snapshot the active key before submitting.
            let active_before = svc.get(&id).expect("identity present").active_key.clone();

            let result = recovery.submit_recovery_approval(
                &mut svc,
                &registry,
                &id,
                &new_key,
                guardian_key,
                rotated_at,
            );

            if effective_count < threshold_usize {
                // Below threshold: no rotation, active key unchanged, error returned
                // (Requirement 12.6).
                prop_assert_eq!(result, Err(IdentityError::RecoveryThresholdNotMet));
                let identity = svc.get(&id).expect("identity present");
                prop_assert_eq!(&identity.active_key, &active_before);
                prop_assert_eq!(&identity.active_key, &initial_key);
                // The de-duplicated session count tracks the model exactly (Req 12.5).
                prop_assert_eq!(recovery.approval_count(&id, &new_key), effective_count);
            } else {
                // First crossing of the threshold: rotation fires (Requirement 12.4).
                let record = result.expect("threshold reached rotates the active key");
                prop_assert_eq!(&record.old_key, &initial_key);
                prop_assert_eq!(&record.new_key, &new_key);
                prop_assert_eq!(record.rotated_at, rotated_at);

                let identity = svc.get(&id).expect("identity present after rotation");
                // Active key rotated to the candidate new_key, IdentityId unchanged.
                prop_assert_eq!(&identity.active_key, &new_key);
                prop_assert_eq!(&identity.id, &id);
                // The old active key is retired.
                prop_assert!(identity.retired_keys.contains(&initial_key));

                // The consumed session is cleared, so the approval count resets to 0.
                prop_assert_eq!(recovery.approval_count(&id, &new_key), 0);

                rotated = true;
            }
        }

        // If the distinct-approver count never reached M, no rotation may have occurred:
        // the active key must still be the initial key (Requirement 12.6).
        if !rotated {
            prop_assert!(distinct_approvers.len() < threshold_usize);
            let identity = svc.get(&id).expect("identity present");
            prop_assert_eq!(&identity.active_key, &initial_key);
        }
    }
}
