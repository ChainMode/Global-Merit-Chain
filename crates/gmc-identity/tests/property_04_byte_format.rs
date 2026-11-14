//! Property 4 — 密钥/签名字节格式校验与拒绝.
//!
//! For any byte sequence, if its length does NOT satisfy the declared
//! `Signature_Scheme`'s `ByteFormat` constraint, then submitting it as a creation
//! request's `VerifyingKey` (or as an operation's key/signature) is rejected with
//! [`IdentityError::KeyFormatInvalid`] — no identity is created and no state changes.
//! Conversely, bytes that satisfy the format constraint pass validation.
//!
//! Validates: Requirements 1.5, 2.5.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_core::types::Timestamp;
use gmc_identity::error::IdentityError;
use gmc_identity::identity_service::IdentityService;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::SchemeTag;

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 4: 密钥/签名字节格式校验与拒绝
    #[test]
    fn property_04_byte_format(
        vk_valid in generators::verifying_key_valid(),
        vk_invalid in generators::verifying_key_invalid(),
        sk_valid in generators::signing_key_valid(),
        sk_invalid in generators::signing_key_invalid(),
        sig_valid in generators::signature_valid(),
        sig_invalid in generators::signature_invalid(),
    ) {
        // Resolve the default-registered ed25519 descriptor from the default registry.
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();
        let descriptor = registry
            .resolve(&tag)
            .expect("ed25519 is always registered in the default registry");

        // --- Format-satisfying bytes pass each validator (Ok) ---------------
        prop_assert_eq!(descriptor.validate_verifying_key(vk_valid.as_bytes()), Ok(()));
        prop_assert_eq!(descriptor.validate_signing_key(sk_valid.as_bytes()), Ok(()));
        prop_assert_eq!(descriptor.validate_signature(sig_valid.as_bytes()), Ok(()));

        // --- Format-violating bytes are rejected with KeyFormatInvalid ------
        prop_assert_eq!(
            descriptor.validate_verifying_key(vk_invalid.as_bytes()),
            Err(IdentityError::KeyFormatInvalid)
        );
        prop_assert_eq!(
            descriptor.validate_signing_key(sk_invalid.as_bytes()),
            Err(IdentityError::KeyFormatInvalid)
        );
        prop_assert_eq!(
            descriptor.validate_signature(sig_invalid.as_bytes()),
            Err(IdentityError::KeyFormatInvalid)
        );

        // --- Creating an iFay with a malformed VerifyingKey is rejected and
        //     produces NO state change (no identity, no ownership root, no pocket) ---
        let mut ownership = OwnershipRegistry::new();
        let mut binding = PocketBinding::new();
        let mut service = IdentityService::new();

        let result = service.create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &tag,
            &vk_invalid,
            Timestamp::from_secs(1),
        );

        prop_assert_eq!(result, Err(IdentityError::KeyFormatInvalid));
        // Atomic failure: every collaborator stays empty.
        prop_assert!(service.is_empty());
        prop_assert!(ownership.is_empty());
        prop_assert!(binding.is_empty());

        // --- A valid VerifyingKey, by contrast, creates exactly one identity ---
        let ok_id = service.create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &tag,
            &vk_valid,
            Timestamp::from_secs(2),
        );
        prop_assert!(ok_id.is_ok());
        prop_assert_eq!(service.len(), 1);
    }
}
