//! Property 5 — scheme registry register/resolve & unregistered rejection.
//!
//! Design *Signature_Scheme* / Property 5: 方案注册表登记/解析与未登记拒绝.
//! Validates Requirements 1.3, 1.4.
//!
//! The default [`SchemeRegistry`] always contains `ed25519` (Requirement 1.3). This
//! property checks both halves of the statement against arbitrary scheme tags &
//! descriptors:
//!
//! - **Accept side**: registering a *fresh* (unoccupied) tag makes it resolvable back
//!   to the *same* descriptor, and the pre-existing `ed25519` scheme stays intact.
//! - **Reject side**: any tag that was never registered resolves to
//!   [`IdentityError::SchemeUnsupported`] (Requirement 1.4), and a second `register`
//!   under an already-occupied tag is rejected with **no state change**.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::scheme::{ByteFormat, SchemeDescriptor, SchemeRegistry};
use gmc_identity::types::SchemeTag;

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 5: 方案注册表登记/解析与未登记拒绝
    #[test]
    fn property_05_scheme_registry_register_resolve_and_reject(
        tag in generators::scheme_tag_unsupported(),
        other in generators::scheme_tag_unsupported(),
    ) {
        let ed25519 = SchemeTag::ed25519();

        // The generated "unsupported" tags must not collide with the default-registered
        // ed25519 (the accept side registers `tag`; the reject side probes `other`,
        // which must remain unregistered). Skip any draw that would break those
        // preconditions rather than mis-assert.
        prop_assume!(tag != ed25519);
        prop_assume!(other != ed25519);
        prop_assume!(other != tag);

        // A default registry that, by construction, already supports ed25519.
        let mut registry = SchemeRegistry::default();
        prop_assert!(registry.contains(&ed25519));

        // --- Accept side: register a fresh descriptor under the unoccupied tag -------
        let descriptor = SchemeDescriptor::new(
            tag.clone(),
            ByteFormat::exact(32),
            ByteFormat::exact(32),
            ByteFormat::exact(64),
        );
        prop_assert_eq!(registry.register(descriptor.clone()), Ok(()));

        // Resolving the just-registered tag returns the SAME descriptor.
        prop_assert_eq!(registry.resolve(&tag), Ok(&descriptor));
        // The pre-existing default scheme is untouched by the new registration.
        prop_assert_eq!(
            registry.resolve(&ed25519),
            Ok(&SchemeDescriptor::ed25519())
        );

        // --- No silent overwrite: re-registering an occupied tag is rejected ---------
        // (登记…不产生任何状态变更) — the registry is left byte-for-byte unchanged.
        let before = registry.clone();
        let impostor = SchemeDescriptor::new(
            tag.clone(),
            ByteFormat::exact(1),
            ByteFormat::exact(2),
            ByteFormat::exact(3),
        );
        prop_assert_eq!(registry.register(impostor.clone()), Err(impostor));
        prop_assert_eq!(&registry, &before);
        // The original descriptor still resolves (not the impostor).
        prop_assert_eq!(registry.resolve(&tag), Ok(&descriptor));

        // --- Reject side: a never-registered tag yields SchemeUnsupported ------------
        // (未登记拒绝 / Requirement 1.4) with no state change.
        prop_assert!(!registry.contains(&other));
        prop_assert_eq!(
            registry.resolve(&other),
            Err(IdentityError::SchemeUnsupported)
        );
    }
}
