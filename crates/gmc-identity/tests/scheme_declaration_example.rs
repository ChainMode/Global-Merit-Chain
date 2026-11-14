//! Worked EXAMPLE unit tests for scheme declaration and opaque-byte validation
//! (task 2.5). These are plain `#[test]` examples — **not** numbered properties — so
//! they carry no `Feature: gmc-identity, Property N` label and use no proptest.
//!
//! They illustrate two acceptance criteria of Requirement 1 with concrete values:
//!
//! - Req 1.1: the default registry's `ed25519` descriptor declares a scheme tag plus
//!   three [`ByteFormat`]s (signing key / verifying key / signature).
//! - Req 1.2: keys and signatures are opaque bytes judged **solely** by the format
//!   their owning scheme declares — a length that is valid under one scheme is rejected
//!   under another scheme whose format differs.

use gmc_identity::scheme::{ByteFormat, SchemeDescriptor, SchemeRegistry};
use gmc_identity::types::{Signature, SigningKey, VerifyingKey};
use gmc_identity::types::SchemeTag;

/// Req 1.1: resolving `ed25519` from the default registry yields a descriptor whose tag
/// is `ed25519` and whose three byte-formats pin the standard Ed25519 lengths
/// (signing key 32, verifying key 32, signature 64).
#[test]
fn default_registry_ed25519_descriptor_declares_tag_and_three_byte_formats() {
    let registry = SchemeRegistry::default();

    let descriptor = registry
        .resolve(&SchemeTag::ed25519())
        .expect("the default registry always registers ed25519 (Req 1.3)");

    // The scheme tag is exactly `ed25519`.
    assert_eq!(descriptor.tag(), &SchemeTag::ed25519());
    assert_eq!(descriptor.tag().as_str(), "ed25519");

    // Three declared ByteFormats, each pinning the standard Ed25519 length.
    let signing_key_format = descriptor.signing_key_format();
    let verifying_key_format = descriptor.verifying_key_format();
    let signature_format = descriptor.signature_format();

    assert_eq!(signing_key_format.exact_len(), Some(32));
    assert_eq!(verifying_key_format.exact_len(), Some(32));
    assert_eq!(signature_format.exact_len(), Some(64));

    // Cross-check against the named source constants so this example stays in lockstep
    // with the descriptor definition.
    assert_eq!(
        signing_key_format.exact_len(),
        Some(SchemeDescriptor::ED25519_SIGNING_KEY_LEN),
    );
    assert_eq!(
        verifying_key_format.exact_len(),
        Some(SchemeDescriptor::ED25519_VERIFYING_KEY_LEN),
    );
    assert_eq!(
        signature_format.exact_len(),
        Some(SchemeDescriptor::ED25519_SIGNATURE_LEN),
    );

    // And the formats accept exactly the standard-length opaque material.
    let vk = VerifyingKey::new(vec![0u8; 32]);
    let sk = SigningKey::new(vec![0u8; 32]);
    let sig = Signature::new(vec![0u8; 64]);
    assert_eq!(descriptor.validate_verifying_key(vk.as_bytes()), Ok(()));
    assert_eq!(descriptor.validate_signing_key(sk.as_bytes()), Ok(()));
    assert_eq!(descriptor.validate_signature(sig.as_bytes()), Ok(()));
}

/// Req 1.2: keys and signatures are opaque bytes validated *only* against the byte
/// format their owning scheme declares. A custom scheme with deliberately different
/// (shorter) length constraints accepts an 8-byte verifying key and a 16-byte signature
/// that the standard Ed25519 scheme would reject, and conversely rejects the 32-byte /
/// 64-byte Ed25519-sized material that Ed25519 accepts. Nothing about the bytes
/// themselves decides validity — only the declared scheme format does.
#[test]
fn keys_and_signatures_are_validated_only_against_their_declared_scheme_format() {
    // A fresh registry holding one custom scheme with non-Ed25519 length constraints:
    // verifying key exactly 8 bytes, signature exactly 16 bytes, signing key 8 bytes.
    let custom_tag = SchemeTag::new("custom-short");
    let custom = SchemeDescriptor::new(
        custom_tag.clone(),
        ByteFormat::exact(8),  // signing key
        ByteFormat::exact(8),  // verifying key
        ByteFormat::exact(16), // signature
    );

    let mut registry = SchemeRegistry::empty();
    registry
        .register(custom)
        .expect("registering into an empty registry never collides");

    let descriptor = registry
        .resolve(&custom_tag)
        .expect("the custom scheme was just registered");

    // Opaque material sized for the CUSTOM scheme passes under the custom scheme...
    let custom_vk = VerifyingKey::new(vec![0u8; 8]);
    let custom_sig = Signature::new(vec![0u8; 16]);
    assert_eq!(descriptor.validate_verifying_key(custom_vk.as_bytes()), Ok(()));
    assert_eq!(descriptor.validate_signature(custom_sig.as_bytes()), Ok(()));

    // ...while Ed25519-sized material (32-byte key, 64-byte signature) is REJECTED by
    // the custom scheme: the same bytes are judged solely by THIS scheme's format.
    let ed_sized_vk = VerifyingKey::new(vec![0u8; 32]);
    let ed_sized_sig = Signature::new(vec![0u8; 64]);
    assert!(descriptor.validate_verifying_key(ed_sized_vk.as_bytes()).is_err());
    assert!(descriptor.validate_signature(ed_sized_sig.as_bytes()).is_err());

    // The reverse confirms the verdict tracks the scheme, not the bytes: under the
    // standard Ed25519 descriptor the Ed25519-sized material is valid and the
    // custom-sized material is rejected.
    let ed25519 = SchemeDescriptor::ed25519();
    assert_eq!(ed25519.validate_verifying_key(ed_sized_vk.as_bytes()), Ok(()));
    assert_eq!(ed25519.validate_signature(ed_sized_sig.as_bytes()), Ok(()));
    assert!(ed25519.validate_verifying_key(custom_vk.as_bytes()).is_err());
    assert!(ed25519.validate_signature(custom_sig.as_bytes()).is_err());
}
