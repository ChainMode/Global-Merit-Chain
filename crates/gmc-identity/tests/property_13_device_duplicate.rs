//! Property 13 — 设备重复注册被拒 (duplicate device enrollment is rejected).
//!
//! Design *Device_Registry* `enroll` / Property 13: 设备重复注册被拒.
//! Validates Requirements 8.5.
//!
//! Full statement: 对任意身份，若其下已存在某设备 `VerifyingKey` 的活跃凭证，则再次以同一
//! 设备 `VerifyingKey` 注册都会被拒绝、返回 `DeviceDuplicate`，且既有凭证保持不变。
//!
//! ## What "duplicate" means (Req 8.5)
//!
//! Reading [`DeviceRegistry::enroll`] confirms the duplicate condition is *"the device
//! key already has an **Active** credential **under this identity**"*. So the test:
//!
//! 1. Enrolls a device key once under identity A — it is born `Active`.
//! 2. Re-enrolls the **same** device key under the **same** identity (even with a
//!    different declared type / timestamp) and asserts it is rejected with
//!    [`DeviceDuplicate`](IdentityError::DeviceDuplicate), while the existing credential
//!    is left **byte-for-byte unchanged** (snapshot before == snapshot after; the
//!    `device_id`, `Active` status, `registered_at` and `device_type` all preserved) and
//!    identity A still holds exactly one credential.
//! 3. **Positive contrast** (duplicate is scoped *per identity*): the very same device
//!    key enrolled under a **different** identity B is *not* a duplicate and succeeds,
//!    leaving identity A untouched.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::device::{DeviceRegistry, DeviceStatus};
use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, Timestamp, VerifyingKey};

/// Derives the ed25519 [`IdentityId`] for `owner_vk` under the default scheme registry.
fn id_of(owner_vk: &VerifyingKey) -> IdentityId {
    derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), owner_vk)
        .expect("a valid ed25519 vk derives an IdentityId under the default registry")
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 13: 设备重复注册被拒
    #[test]
    fn property_13_duplicate_active_device_is_rejected(
        owners in generators::two_distinct_verifying_keys(),
        device_key in generators::verifying_key_valid(),
        first_type in generators::device_type_known(),
        second_type in generators::device_type_known(),
        t1 in 0u64..1_000_000,
        t2 in 0u64..1_000_000,
    ) {
        let (owner_a, owner_b) = owners;
        let identity_a = id_of(&owner_a);
        let identity_b = id_of(&owner_b);
        // Distinct owner keys derive distinct identities (derivation is injective), so A
        // and B are genuinely separate scopes for the per-identity duplicate check.
        prop_assume!(identity_a != identity_b);

        let mut registry = DeviceRegistry::new();
        let registered_at = Timestamp::from_secs(t1);

        // (1) Enroll the device once under identity A → a fresh Active credential.
        let device_id = registry
            .enroll(&identity_a, &device_key, first_type, registered_at)
            .expect("first enroll succeeds");

        // Snapshot the existing Active credential and the whole registry BEFORE the
        // duplicate attempt, so we can prove nothing changes on the rejection path.
        let before_credential = registry
            .credential(&identity_a, &device_id)
            .expect("credential stored after first enroll")
            .clone();
        prop_assert_eq!(before_credential.status(), DeviceStatus::Active);
        let before_registry = registry.clone();

        // (2) Re-enroll the SAME device key under the SAME identity — even declaring a
        // different device type and registration time — must be rejected.
        let err = registry
            .enroll(&identity_a, &device_key, second_type, Timestamp::from_secs(t2))
            .expect_err("duplicate active device key is rejected");
        prop_assert_eq!(err, IdentityError::DeviceDuplicate);

        // The existing credential is left UNCHANGED: id, status, registration time and
        // device type are all preserved (the failed enroll's type/time never took hold).
        let after_credential = registry
            .credential(&identity_a, &device_id)
            .expect("credential still stored after the rejected duplicate enroll");
        prop_assert_eq!(after_credential.device_id(), &device_id);
        prop_assert_eq!(after_credential.status(), DeviceStatus::Active);
        prop_assert_eq!(after_credential.registered_at(), registered_at);
        prop_assert_eq!(after_credential.device_type(), first_type);
        prop_assert_eq!(after_credential, &before_credential);

        // Identity A still holds exactly the one credential, and the whole registry is
        // byte-for-byte identical to its pre-rejection snapshot (atomic failure).
        prop_assert_eq!(registry.list(&identity_a).len(), 1);
        prop_assert_eq!(&registry, &before_registry);

        // (3) Positive contrast: the SAME device key under a DIFFERENT identity is NOT a
        // duplicate (Req 8.5 is scoped "under this identity"), so it enrolls Ok.
        let id_b = registry
            .enroll(&identity_b, &device_key, first_type, registered_at)
            .expect("the same device key under a different identity is allowed");
        // Same key → same deterministic fingerprint, but stored in a separate scope.
        prop_assert_eq!(&id_b, &device_id);
        prop_assert_eq!(registry.list(&identity_b).len(), 1);
        // Enrolling under B left identity A's single credential untouched.
        prop_assert_eq!(registry.list(&identity_a).len(), 1);
    }
}
