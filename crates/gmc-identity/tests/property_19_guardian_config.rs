//! Property 19 — 守护人配置阈值校验 (guardian-config threshold validation).
//!
//! Design *Recovery_Service* `configureGuardians` / Property 19: 守护人配置阈值校验.
//! Validates Requirements 12.1, 12.2, 12.3.
//!
//! Full statement: 对任意守护人 `VerifyingKey` 集合与阈值 `M`，守护人配置被接受当且仅当
//! `1 ≤ M ≤ N`（N 为去重后的守护人总数）；否则配置被拒绝、返回 `RecoveryConfigInvalid`，
//! 且既有守护人配置保持不变.
//!
//! ## What the test exercises
//!
//! [`generators::guardian_config`] yields a `{ guardians: Vec<VerifyingKey> (with
//! possible duplicates), threshold: u32 }` whose threshold spans `0..=N+2`, so both the
//! accepted band (`1 ≤ M ≤ N`) and the rejected extremes (`M = 0`, `M > N`, and the
//! empty-set case where every positive `M` exceeds `N = 0`) are covered.
//!
//! Because [`RecoveryService::configure_guardians`] rejects an unknown identity with
//! `IdentityMismatch` *before* the threshold check, the test always targets a freshly
//! created iFay. To pin down the "既有配置保持不变" clause it first installs a
//! KNOWN-VALID 2-of-3 baseline config and snapshots it; the generated config is then
//! attempted on top:
//!
//! - **accepted** (`1 ≤ M ≤ N`): `configure_guardians` returns `Ok`, and the stored
//!   config now records the *de-duplicated* guardian set (`guardian_count() == N`) and
//!   the chosen `threshold`, replacing the baseline.
//! - **rejected** (otherwise): `configure_guardians` returns
//!   `Err(RecoveryConfigInvalid)`, and the stored config is byte-for-byte the baseline
//!   snapshot — the prior configuration is untouched.

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::BTreeSet;

use gmc_identity::error::IdentityError;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::recovery::RecoveryService;
use gmc_identity::identity_service::IdentityService;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, Timestamp, VerifyingKey};

/// A valid-format (32-byte) ed25519 verifying key whose bytes vary with `seed`, used to
/// build the deterministic known-valid baseline guardian set.
fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect();
    VerifyingKey::new(bytes)
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 19: 守护人配置阈值校验
    #[test]
    fn property_19_guardian_config_threshold_validation(
        input in generators::guardian_config(),
    ) {
        let registry = SchemeRegistry::default();
        let mut ownership = OwnershipRegistry::new();
        let mut binding = PocketBinding::new();
        let mut svc = IdentityService::new();
        let mut recovery = RecoveryService::new();

        // An existing iFay, so configure_guardians reaches the threshold check rather
        // than rejecting an unknown identity with IdentityMismatch.
        let id = svc
            .create_ifay(
                &registry,
                &mut ownership,
                &mut binding,
                &SchemeTag::ed25519(),
                &vk(200),
                Timestamp::from_secs(1),
            )
            .expect("valid ed25519 iFay");

        // Install a KNOWN-VALID 2-of-3 baseline configuration (1 ≤ 2 ≤ 3), then snapshot
        // it so the "既有配置保持不变" clause can be checked on a rejected attempt.
        let baseline_guardians = [vk(10), vk(11), vk(12)];
        recovery
            .configure_guardians(&svc, &id, &baseline_guardians, 2)
            .expect("2-of-3 baseline is a valid guardian config");
        let baseline = recovery
            .guardian_config(&id)
            .cloned()
            .expect("baseline config is recorded");
        // Sanity: the baseline really is the valid config we expect.
        prop_assert_eq!(baseline.guardian_count(), 3);
        prop_assert_eq!(baseline.threshold, 2);

        // N = number of DISTINCT guardians in the generated input (configure_guardians
        // de-duplicates the slice into a BTreeSet before validating M).
        let distinct: BTreeSet<VerifyingKey> = input.guardians.iter().cloned().collect();
        let n = distinct.len() as u32;
        let threshold = input.threshold;

        let result = recovery.configure_guardians(&svc, &id, &input.guardians, threshold);

        // Accepted IFF 1 ≤ M ≤ N (Requirements 12.2, 12.3).
        let should_accept = threshold >= 1 && threshold <= n;

        if should_accept {
            prop_assert_eq!(result, Ok(()));

            // On Ok the stored config records the DE-DUPLICATED guardian set and the
            // chosen threshold, replacing the baseline (Requirement 12.1).
            let stored = recovery
                .guardian_config(&id)
                .expect("an accepted config is recorded");
            prop_assert_eq!(stored.guardian_count() as u32, n);
            prop_assert_eq!(stored.threshold, threshold);
            prop_assert_eq!(&stored.guardians, &distinct);
            // Every distinct guardian is recognised, and no stranger leaked in.
            for g in &distinct {
                prop_assert!(stored.is_guardian(g));
            }
        } else {
            // Rejected: RecoveryConfigInvalid, and the prior config is left untouched
            // (Requirement 12.3).
            prop_assert_eq!(result, Err(IdentityError::RecoveryConfigInvalid));
            let stored = recovery
                .guardian_config(&id)
                .expect("the baseline config survives a rejected attempt");
            prop_assert_eq!(stored, &baseline);
        }
    }
}
