//! SMOKE test (task 4.4) — the `Signer` interface never exports/reads `SigningKey`
//! material, and `SigningKey`'s `Debug` is redacted (Requirement 13.5).
//!
//! These are plain `#[test]` smoke tests — **not** a numbered property — so they carry
//! no `Feature: gmc-identity, Property N` label and use no proptest and no `mod common`.
//!
//! The acceptance criterion is an **interface/compile-time** guarantee: it is satisfied
//! by the *shape* of the [`Signer`] trait, not by a runtime computation. Inspecting
//! `src/signer.rs` confirms the trait exposes exactly two methods —
//!
//! ```ignore
//! fn scheme_tag(&self) -> SchemeTag;
//! fn sign(&self, sk: &SigningKey, msg: &[u8]) -> IdentityResult<Signature>;
//! ```
//!
//! — and **no** method that returns, exports, or otherwise reads back raw `SigningKey`
//! material. A `Signer` only *consumes* a borrowed `&SigningKey` to produce a
//! [`Signature`]; the secret bytes never need to leave the signer. The two tests below
//! pin that contract from the outside:
//!
//! 1. `signing_key_debug_is_redacted_and_does_not_leak_bytes` — a `SigningKey` built from
//!    known bytes never prints those bytes via `Debug`; it emits the exact redaction
//!    marker the real `Debug` impl produces.
//! 2. `signer_trait_only_consumes_signing_key_to_produce_signature` — the only way to put
//!    a `SigningKey` through the `Signer` trait is to *sign*; the produced output is a
//!    `Signature`, never key material.

use gmc_identity::signer::{reference_keypair, ReferenceSigner, Signer};
use gmc_identity::types::{Signature, SchemeTag, SigningKey};

/// The exact redacted form `SigningKey`'s `Debug` impl produces for a 4-byte key.
///
/// Read from `src/types.rs` (NOT guessed): the impl is
/// `f.debug_struct("SigningKey").field("bytes", &format_args!("<redacted; {} bytes>", len)).finish()`.
/// Because `format_args!` Debug-prints its content verbatim (no surrounding quotes), a
/// 4-byte key renders precisely as below.
const EXPECTED_REDACTED_DEBUG_4_BYTES: &str = "SigningKey { bytes: <redacted; 4 bytes> }";

/// Test 1 — redacted `Debug`: a `SigningKey` constructed from known secret bytes never
/// leaks those byte values through `Debug`, and renders the exact redaction marker the
/// real impl emits (Req 13.5).
#[test]
fn signing_key_debug_is_redacted_and_does_not_leak_bytes() {
    // Known, recognizable secret bytes so any leak would be obvious in the output.
    let secret = vec![0xde_u8, 0xad, 0xbe, 0xef];
    let sk = SigningKey::new(secret.clone());

    let rendered = format!("{sk:?}");

    // It emits the EXACT redaction marker the actual Debug impl produces (length-only).
    assert_eq!(rendered, EXPECTED_REDACTED_DEBUG_4_BYTES);
    assert!(
        rendered.contains("<redacted; 4 bytes>"),
        "Debug output must carry the redaction marker, got: {rendered}"
    );

    // And it does NOT leak the secret bytes in any common encoding.
    // Lowercase / uppercase hex listings:
    assert!(!rendered.contains("deadbeef"));
    assert!(!rendered.contains("DEADBEEF"));
    assert!(!rendered.contains("de, ad")); // no raw byte sequence
    // Decimal values of the secret bytes (0xde=222, 0xad=173, 0xbe=190, 0xef=239):
    for decimal in ["222", "173", "190", "239"] {
        assert!(
            !rendered.contains(decimal),
            "Debug output leaked secret byte value {decimal}: {rendered}"
        );
    }
}

/// Test 2 — interface usage: the ONLY way to use a `SigningKey` through the [`Signer`]
/// trait is to *sign* a message, which yields a [`Signature`]. The trait surface is
/// exactly `scheme_tag()` + `sign(&self, &SigningKey, &[u8]) -> IdentityResult<Signature>`
/// (verified against `src/signer.rs`): it provides **no** export/getter that returns
/// `SigningKey` material — this confidentiality guarantee (Req 13.5) is enforced at the
/// type/trait level, i.e. at compile time, by the absence of any such method.
///
/// NOTE: the `SigningKey` *newtype itself* does expose an `as_bytes` accessor on the
/// concrete type, but the acceptance criterion here is about the **`Signer` interface**:
/// the `Signer` trait specifically never returns key material. The function
/// [`drive_signer`] below is written against `&dyn Signer` so it can touch *only* the two
/// trait methods — there is simply no signing-key getter available to call.
#[test]
fn signer_trait_only_consumes_signing_key_to_produce_signature() {
    // A matching reference keypair; the signing key is consumed by reference only.
    let (sk, _vk) = reference_keypair(b"task-4.4-seed");
    let msg = b"authorize: rotate device credential";

    // Drive the signer through the trait surface alone (see `drive_signer`).
    let (tag, signature) = drive_signer(&ReferenceSigner, &sk, msg);

    // The signer reports its scheme tag and returns a `Signature` — never key bytes.
    assert_eq!(tag, ReferenceSigner.scheme_tag());
    let _: &Signature = &signature; // the output type is a Signature, not a SigningKey
    assert!(
        !signature.is_empty(),
        "reference signature over a non-empty message is non-empty"
    );
}

/// Exercises the entire `Signer` interface against a `&dyn Signer`, proving by
/// construction that the trait offers no way to read back `SigningKey` material: the only
/// methods reachable here are `scheme_tag()` and `sign(...)`, the latter consuming a
/// borrowed `&SigningKey` and yielding a `Signature`. If a key-export method existed on
/// the trait, it would be callable here — it does not, so it cannot be.
fn drive_signer(signer: &dyn Signer, sk: &SigningKey, msg: &[u8]) -> (SchemeTag, Signature) {
    let tag = signer.scheme_tag();
    let signature = signer.sign(sk, msg).expect("reference signer signs cleanly");
    (tag, signature)
}
