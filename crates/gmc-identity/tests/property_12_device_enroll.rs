//! Property 12 — device enrollment & multi-device binding.
//!
//! Design *Device_Registry* / Property 12: 设备注册与多设备绑定.
//! Validates Requirements 8.1, 8.2, 8.3.
//!
//! Full statement: for any enrollment sequence signed by an authorized key carrying a
//! legal device [`VerifyingKey`] and a legal `Device_Type`, each enroll creates an
//! **Active** [`DeviceCredential`] whose `device_id` is **deterministically derived**
//! from the device verifying key and which records the `Device_Type`, registration
//! time and status; one identity may bind **arbitrarily many** credentials for distinct
//! devices, and listing returns **all** created credentials with their status.
//!
//! `DeviceRegistry::enroll` does not itself authenticate the signer (that is
//! `Identity_Core`'s job); this property exercises the registry effect *given* an
//! authorized enroll, so the test calls `enroll` directly against a real derived
//! identity. A fresh set of **distinct** device keys (deduplicated on their bytes) is
//! enrolled under one fixed identity, then the per-device assertions and the final
//! `list` assertion together demonstrate deterministic `device_id` derivation (Req 8.3)
//! and multi-device binding under a single identity (Req 8.2).

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::{BTreeMap, BTreeSet};

use gmc_identity::device::{DeviceId, DeviceRegistry, DeviceStatus};
use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{DeviceType, SchemeTag, Timestamp, VerifyingKey};

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 12: 设备注册与多设备绑定
    #[test]
    fn property_12_device_enroll_and_multi_binding(
        owner_vk in generators::verifying_key_valid(),
        raw_devices in proptest::collection::vec(
            (generators::verifying_key_valid(), any::<u8>()),
            1..=12,
        ),
        base_ts in 0u64..1_000_000,
    ) {
        // One fixed identity, derived for real from a valid ed25519 verifying key.
        let registry_schemes = SchemeRegistry::default();
        let identity = derive_identity_id(&registry_schemes, &SchemeTag::ed25519(), &owner_vk)
            .expect("valid ed25519 vk derives an IdentityId");

        // Deduplicate the device keys on their bytes so each enrolled device is DISTINCT
        // (a repeated key would be a duplicate-enrollment case, which is Property 13, not
        // this one). The first occurrence of a key keeps its generated Device_Type, and
        // each distinct device gets its own registration timestamp.
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut devices: Vec<(VerifyingKey, DeviceType, Timestamp)> = Vec::new();
        for (key, type_idx) in raw_devices {
            if seen.insert(key.as_bytes().to_vec()) {
                let device_type = DeviceType::ALL[(type_idx as usize) % DeviceType::ALL.len()];
                let registered_at = Timestamp::from_secs(base_ts + devices.len() as u64);
                devices.push((key, device_type, registered_at));
            }
        }

        let mut registry = DeviceRegistry::new();

        // Expected device_id -> (device_type, registered_at, device_key) for the final
        // `list` cross-check.
        let mut expected: BTreeMap<DeviceId, (DeviceType, Timestamp, VerifyingKey)> =
            BTreeMap::new();

        for (device_key, device_type, registered_at) in &devices {
            // Each enroll succeeds and returns the deterministic fingerprint of the key.
            let device_id = registry
                .enroll(&identity, device_key, *device_type, *registered_at)
                .expect("authorized enroll of a distinct device succeeds");
            prop_assert_eq!(&device_id, &DeviceId::derive(device_key)); // Req 8.3

            // The stored credential is Active and records id / identity / key / type /
            // time / status exactly (Req 8.1, 8.3).
            let credential = registry
                .credential(&identity, &device_id)
                .expect("a freshly enrolled credential is stored");
            prop_assert_eq!(credential.device_id(), &device_id);
            prop_assert_eq!(credential.identity_id(), &identity);
            prop_assert_eq!(credential.device_key(), device_key);
            prop_assert_eq!(credential.device_type(), *device_type);
            prop_assert_eq!(credential.registered_at(), *registered_at);
            prop_assert_eq!(credential.status(), DeviceStatus::Active);
            prop_assert!(credential.is_active());

            expected.insert(device_id, (*device_type, *registered_at, device_key.clone()));
        }

        // Multi-device binding (Req 8.2): listing returns EXACTLY all created credentials
        // — one per distinct device — each Active and carrying its recorded fields.
        let listed = registry.list(&identity);
        prop_assert_eq!(listed.len(), expected.len());

        let mut listed_ids: BTreeSet<DeviceId> = BTreeSet::new();
        for credential in &listed {
            let (exp_type, exp_ts, exp_key) = expected
                .get(credential.device_id())
                .expect("every listed credential was enrolled above");
            prop_assert_eq!(credential.identity_id(), &identity);
            prop_assert_eq!(credential.device_type(), *exp_type);
            prop_assert_eq!(credential.registered_at(), *exp_ts);
            prop_assert_eq!(credential.device_key(), exp_key);
            prop_assert_eq!(credential.device_id(), &DeviceId::derive(exp_key)); // Req 8.3
            prop_assert_eq!(credential.status(), DeviceStatus::Active); // Req 8.1
            prop_assert!(credential.is_active());
            prop_assert!(listed_ids.insert(credential.device_id().clone()));
        }

        // Every enrolled device is represented in the listing (full enumeration, Req 8.2).
        let expected_ids: BTreeSet<DeviceId> = expected.keys().cloned().collect();
        prop_assert_eq!(listed_ids, expected_ids);
    }
}
