//! Property tests verifying all 5 newly wired `OperationPayload` variants
//! (`EnrollDevice`, `RevokeDevice`, `RotateKey`, `ConfigureGuardians`, `RecoveryApproval`)
//! through `IdentityState::apply` (`align-identity-with-fayid-authority` `OQ-5`).

use gmc_identity::device::DeviceStatus;
use gmc_identity::error::IdentityError;
use gmc_identity::identity_core::{
    canonical_encode_operation, Applied, IdentityState, OperationPayload, SignedOperation,
};
use gmc_identity::identity_id::IdentityId;
use gmc_identity::scheme::{ByteFormat, SchemeDescriptor, SchemeRegistry};
use gmc_identity::signer::{
    reference_keypair, ReferenceSigner, ReferenceVerifier, Signer, REFERENCE_SCHEME_TAG,
};
use gmc_identity::types::{DeviceType, Nonce, SchemeTag, SigningKey, Timestamp, VerifyingKey};
use proptest::prelude::*;

fn reference_tag() -> SchemeTag {
    SchemeTag::new(REFERENCE_SCHEME_TAG)
}

fn reference_state() -> IdentityState {
    let mut registry = SchemeRegistry::empty();
    registry
        .register(SchemeDescriptor::new(
            reference_tag(),
            ByteFormat::exact(32),
            ByteFormat::exact(32),
            ByteFormat::range(36, 1 << 20),
        ))
        .unwrap();
    IdentityState {
        registry,
        ..IdentityState::default()
    }
}

fn sign_op(
    target: &IdentityId,
    payload: OperationPayload,
    nonce: Nonce,
    sk: &SigningKey,
    vk: &VerifyingKey,
) -> SignedOperation {
    let msg = canonical_encode_operation(target, &payload, nonce);
    let sig = ReferenceSigner.sign(sk, &msg).unwrap();
    SignedOperation::new(
        target.clone(),
        payload,
        nonce,
        reference_tag(),
        vk.clone(),
        sig,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_wired_rotation_and_m_of_n_recovery_preserve_identity_id_and_monotonic_nonce(
        rotations in 1usize..=4,
        guardian_n in 2usize..=5,
        m_seed in 1u32..=5,
    ) {
        let mut state = reference_state();
        let (mut active_sk, mut active_vk) = reference_keypair(b"initial-owner");
        let id = state
            .identities
            .create_ifay(
                &state.registry,
                &mut state.ownership,
                &mut state.binding,
                &reference_tag(),
                &active_vk,
                Timestamp::from_secs(1),
            )
            .unwrap();
        let pocket_key_before = state.binding.pocket_key(&id).unwrap();

        let mut nonce: Nonce = 0;

        // Apply `rotations` sequential RotateKey operations via IdentityState::apply.
        for r in 0..rotations {
            let (next_sk, next_vk) = reference_keypair(format!("rot-{r}").as_bytes());
            nonce += 1;
            let op = sign_op(
                &id,
                OperationPayload::RotateKey { new_key: next_vk.clone() },
                nonce,
                &active_sk,
                &active_vk,
            );
            let res = state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(10 + r as u64)).unwrap();
            prop_assert!(matches!(res, Applied::KeyRotated(_)));
            prop_assert_eq!(&state.identities.get(&id).unwrap().id, &id);
            prop_assert_eq!(&state.identities.get(&id).unwrap().active_key, &next_vk);
            prop_assert_eq!(state.identities.get(&id).unwrap().applied_nonce, nonce);
            active_sk = next_sk;
            active_vk = next_vk;
        }

        // Configure M-of-N guardians via IdentityState::apply.
        let threshold = ((m_seed - 1) % (guardian_n as u32)) + 1;
        let guardian_pairs: Vec<(SigningKey, VerifyingKey)> = (0..guardian_n)
            .map(|g| reference_keypair(format!("guardian-{g}").as_bytes()))
            .collect();
        let guardian_vks: Vec<VerifyingKey> = guardian_pairs.iter().map(|(_, vk)| vk.clone()).collect();

        // Invalid threshold (0) fails atomically without advancing nonce.
        let snap = state.clone();
        let bad_cfg = sign_op(
            &id,
            OperationPayload::ConfigureGuardians {
                guardians: guardian_vks.clone(),
                threshold: 0,
            },
            nonce + 1,
            &active_sk,
            &active_vk,
        );
        prop_assert_eq!(
            state.apply(&bad_cfg, &ReferenceVerifier, Timestamp::from_secs(100)),
            Err(IdentityError::RecoveryConfigInvalid)
        );
        prop_assert_eq!(&state, &snap);

        nonce += 1;
        let ok_cfg = sign_op(
            &id,
            OperationPayload::ConfigureGuardians {
                guardians: guardian_vks,
                threshold,
            },
            nonce,
            &active_sk,
            &active_vk,
        );
        prop_assert_eq!(
            state.apply(&ok_cfg, &ReferenceVerifier, Timestamp::from_secs(101)),
            Ok(Applied::GuardiansConfigured)
        );
        prop_assert_eq!(state.identities.get(&id).unwrap().applied_nonce, nonce);

        // Perform M-of-N guardian recovery via IdentityState::apply.
        let (rec_sk, rec_vk) = reference_keypair(b"recovered-owner");
        for (idx, (g_sk, g_vk)) in guardian_pairs.iter().take(threshold as usize).enumerate() {
            nonce += 1;
            let app_op = sign_op(
                &id,
                OperationPayload::RecoveryApproval {
                    new_key: rec_vk.clone(),
                    guardian_key: g_vk.clone(),
                },
                nonce,
                g_sk,
                g_vk,
            );
            let out = state
                .apply(&app_op, &ReferenceVerifier, Timestamp::from_secs(200 + idx as u64))
                .unwrap();
            if idx + 1 < threshold as usize {
                prop_assert_eq!(
                    out,
                    Applied::RecoveryApprovalRecorded {
                        approvals: idx + 1,
                        threshold,
                    }
                );
                prop_assert_eq!(&state.identities.get(&id).unwrap().active_key, &active_vk);
            } else {
                prop_assert!(matches!(out, Applied::RecoveryCompleted(_)));
                prop_assert_eq!(&state.identities.get(&id).unwrap().active_key, &rec_vk);
            }
            prop_assert_eq!(state.identities.get(&id).unwrap().applied_nonce, nonce);
        }

        // Enroll + duplicate check + revoke device with recovered key; IdentityId & pocket binding stay invariant!
        let (_dev_sk, dev_vk) = reference_keypair(b"watch-device");
        nonce += 1;
        let enroll = sign_op(
            &id,
            OperationPayload::EnrollDevice {
                device_key: dev_vk.clone(),
                device_type: DeviceType::Watch,
            },
            nonce,
            &rec_sk,
            &rec_vk,
        );
        let dev_id = match state.apply(&enroll, &ReferenceVerifier, Timestamp::from_secs(300)).unwrap() {
            Applied::DeviceEnrolled(d) => d,
            other => panic!("unexpected {other:?}"),
        };

        // Duplicate enroll fails atomically without advancing nonce!
        let snap_dup = state.clone();
        let dup_enroll = sign_op(
            &id,
            OperationPayload::EnrollDevice {
                device_key: dev_vk,
                device_type: DeviceType::Watch,
            },
            nonce + 1,
            &rec_sk,
            &rec_vk,
        );
        prop_assert_eq!(
            state.apply(&dup_enroll, &ReferenceVerifier, Timestamp::from_secs(301)),
            Err(IdentityError::DeviceDuplicate)
        );
        prop_assert_eq!(&state, &snap_dup);

        nonce += 1;
        let revoke = sign_op(
            &id,
            OperationPayload::RevokeDevice {
                device_id: dev_id.as_str().to_string(),
            },
            nonce,
            &rec_sk,
            &rec_vk,
        );
        prop_assert_eq!(
            state.apply(&revoke, &ReferenceVerifier, Timestamp::from_secs(302)),
            Ok(Applied::DeviceRevoked)
        );
        prop_assert_eq!(
            state.devices.credential(&id, &dev_id).unwrap().status(),
            DeviceStatus::Revoked
        );
        prop_assert_eq!(state.binding.pocket_key(&id).unwrap(), pocket_key_before);
    }
}
