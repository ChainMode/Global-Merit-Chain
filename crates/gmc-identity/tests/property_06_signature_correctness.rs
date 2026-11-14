//! Property 6 — 签名正确性与确定性 (signature correctness & determinism).
//!
//! Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 5.2.
//!
//! Drives the deterministic, non-secure reference `Signer` / `Verifier` pair in
//! [`gmc_identity::signer`] against the four facets of the design's *Property 6*:
//!
//! 1. **Correctness** — `verify(vk, msg, sign(sk, msg)) == true` for the *matching*
//!    `(sk, vk)` reference keypair and the *same* message (Req 4.1, 4.2).
//! 2. **Key mismatch** — `verify(other_vk, msg, sig) == false` for any `other_vk` that
//!    does not match the signing key (Req 4.3).
//! 3. **Message tamper** — `verify(vk, msg', sig) == false` for any `msg' != msg`
//!    (Req 4.4).
//! 4. **Determinism** — `verify` over identical `(vk, msg, sig)` and `sign` over
//!    identical `(sk, msg)` always yield the same result (Req 4.5, replay-relevant 5.2).

mod common;

// The shared generators are pulled in per the suite convention; this property derives
// its keypairs directly from byte seeds via `reference_keypair`, so the import is kept
// for consistency even though it is unused here.
#[allow(unused_imports)]
use common::generators;
use gmc_identity::signer::{reference_keypair, ReferenceSigner, ReferenceVerifier, Signer, Verifier};
use proptest::prelude::*;

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 6: 签名正确性与确定性
    #[test]
    fn property_06_signature_correctness(
        seed in proptest::collection::vec(any::<u8>(), 0..64),
        other_seed in proptest::collection::vec(any::<u8>(), 0..64),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
        tampered_msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        // A matching reference keypair derived from `seed`: `vk` is the deterministic
        // derivation of `sk`, so the pair always matches by construction.
        let (sk, vk) = reference_keypair(&seed);
        // A second keypair from a different seed; we only use its verifying key as the
        // mismatched candidate.
        let (_other_sk, other_vk) = reference_keypair(&other_seed);

        let signer = ReferenceSigner;
        let verifier = ReferenceVerifier;

        let sig = signer
            .sign(&sk, &msg)
            .expect("reference signer must sign opaque-byte messages");

        // Facet 1 — correctness: the matching vk + same message verifies true (Req 4.1, 4.2).
        prop_assert!(
            verifier.verify(&vk, &msg, &sig),
            "matching keypair + same message must verify true",
        );

        // Facet 2 — key mismatch: a non-matching vk verifies false (Req 4.3).
        // Guard so `other_vk` is genuinely different from the producing vk.
        prop_assume!(other_vk != vk);
        prop_assert!(
            !verifier.verify(&other_vk, &msg, &sig),
            "mismatched verifying key must verify false",
        );

        // Facet 3 — message tamper: the original vk over any altered message verifies
        // false (Req 4.4). Guard so the message is genuinely altered.
        prop_assume!(tampered_msg != msg);
        prop_assert!(
            !verifier.verify(&vk, &tampered_msg, &sig),
            "tampered message must verify false under the original verifying key",
        );

        // Facet 4 — determinism (Req 4.5):
        //   verify is a pure function of (vk, msg, sig): repeated calls agree.
        let verify_a = verifier.verify(&vk, &msg, &sig);
        let verify_b = verifier.verify(&vk, &msg, &sig);
        prop_assert_eq!(
            verify_a,
            verify_b,
            "verify must be deterministic over identical (vk, msg, sig) inputs",
        );

        //   sign is deterministic: identical (sk, msg) yield identical Signatures.
        let sig_again = signer
            .sign(&sk, &msg)
            .expect("reference signer must sign opaque-byte messages");
        prop_assert_eq!(
            sig,
            sig_again,
            "sign must be deterministic over identical (sk, msg) inputs",
        );
    }
}
