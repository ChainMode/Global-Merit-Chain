//! `Signer` / `Verifier` cryptographic trait seam (scheme-agnostic).
//!
//! This module defines the abstract signing/verification interface the identity layer
//! depends on (design *Signer / Verifier（密码学 trait 缝）*). gmc-identity stays
//! **scheme-agnostic**: it never binds a concrete algorithm here. Instead it encodes the
//! *contract* the cryptography must satisfy, so the same property tests hold for any
//! conforming implementation:
//!
//! - `sign(sk, msg)` then `verify(vk, msg, sig)` with a **matching** `(sk, vk)` pair and
//!   the **same** message ⇒ `true` (signature correctness, Req 4.2).
//! - `verify` with a **mismatched** `VerifyingKey` ⇒ `false` (Req 4.3).
//! - `verify` against a **tampered** message ⇒ `false` (Req 4.4).
//! - `verify` is a **deterministic pure function**: identical
//!   `(VerifyingKey, message, Signature, scheme tag)` inputs always yield the same result
//!   (Req 4.5).
//!
//! ## Two implementations against one contract
//!
//! - **gmc-node** injects a real **Ed25519** implementation of these traits at the node
//!   layer; gmc-identity itself ships **no** real cryptography.
//! - **gmc-identity** ships a deterministic, non-secure **reference implementation**
//!   (added in task 4.2, in this same file) used only to drive the signing domain logic
//!   and property tests under the "no real cryptography" constraint.
//!
//! Because the property tests target the trait *contract* (not an algorithm), they hold
//! for both the reference implementation and the real Ed25519 implementation.
//!
//! ## Signing-key confidentiality (Req 13.5)
//!
//! The [`Signer`] trait deliberately exposes **no** method that exports, reads, or
//! otherwise returns raw [`SigningKey`] material. A `Signer` only consumes a borrowed
//! `&SigningKey` to produce a [`Signature`]; the authentication result is surfaced solely
//! through the public [`VerifyingKey`] and the [`Signature`]. Combined with the redacted
//! `Debug` impl on [`SigningKey`] (see [`crate::types`]), the secret bytes never need to
//! leave the signer.

use crate::error::IdentityResult;
use crate::types::{SchemeTag, Signature, SigningKey, VerifyingKey};

/// Abstract signature **verifier** for one signature scheme.
///
/// A `Verifier` decides whether a [`Signature`] is valid for a given
/// `(VerifyingKey, message)` under the scheme it reports via [`scheme_tag`]. The decision
/// is a **deterministic pure function** of its inputs — no internal mutable state, no
/// randomness, no I/O — so the same inputs always produce the same answer (Req 4.5).
///
/// Implementations (real Ed25519 in gmc-node, the reference impl in task 4.2) must honor
/// the verification contract documented at the [module level](self):
/// matching key + same message ⇒ `true`; mismatched key ⇒ `false`; tampered message ⇒
/// `false`. The identity layer relies only on this contract (Req 4.2–4.5), never on a
/// specific algorithm.
///
/// [`scheme_tag`]: Verifier::scheme_tag
pub trait Verifier {
    /// Returns the [`SchemeTag`] this verifier understands.
    ///
    /// Used to confirm a verifier matches the scheme declared by an operation before its
    /// keys/signature are interpreted.
    fn scheme_tag(&self) -> SchemeTag;

    /// Returns `true` iff `sig` is a valid signature over `msg` under `vk` for this
    /// verifier's scheme.
    ///
    /// This MUST be deterministic: identical `(vk, msg, sig)` inputs always yield the same
    /// result (Req 4.5). It reports validity as a plain `bool` and never mutates state.
    fn verify(&self, vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool;
}

/// Abstract message **signer** for one signature scheme.
///
/// A `Signer` produces a [`Signature`] over a message using a borrowed [`SigningKey`],
/// under the scheme it reports via [`scheme_tag`]. Per Req 13.5 this trait intentionally
/// provides **no** way to export or read raw signing-key material: the only observable
/// outputs are the returned [`Signature`] and (separately) the holder's public
/// [`VerifyingKey`].
///
/// A produced signature must verify under the matching [`VerifyingKey`] via a [`Verifier`]
/// of the same scheme (`verify(vk, msg, sign(sk, msg)) == true`), tying this trait to the
/// [`Verifier`] contract documented at the [module level](self) (Req 4.1, 4.2).
///
/// [`scheme_tag`]: Signer::scheme_tag
pub trait Signer {
    /// Returns the [`SchemeTag`] this signer produces signatures for.
    fn scheme_tag(&self) -> SchemeTag;

    /// Signs `msg` with `sk`, returning the resulting [`Signature`] (Req 4.1).
    ///
    /// Takes `sk` by shared reference and never returns or exports the key bytes
    /// (Req 13.5). Returns [`IdentityResult`] so an implementation may reject malformed
    /// inputs (e.g. a key whose bytes do not satisfy the scheme's format) with a
    /// machine-identifiable [`crate::error::IdentityError`] instead of panicking.
    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> IdentityResult<Signature>;
}

// ---------------------------------------------------------------------------
// Deterministic, NON-secure reference implementation (task 4.2).
// ---------------------------------------------------------------------------
//
// gmc-identity ships **no** real cryptography (the real Ed25519 implementation is
// injected by gmc-node). To still exercise the signing *domain logic* and the
// signature-correctness property (design *Property 6*) under the "no real crypto"
// constraint, this module provides a deterministic, **non-secure** reference pair of
// [`Signer`]/[`Verifier`] implementations.
//
// **This is NOT cryptographically secure** — anyone can forge a "signature" because the
// transforms are public and trivially reversible. Its sole purpose is to satisfy the
// trait *contract* (design "Signer / Verifier" → 确定性参考方案) so the same property
// tests hold for both this reference impl and the real Ed25519 impl in gmc-node.

/// The scheme tag reported by the deterministic reference [`Signer`]/[`Verifier`].
///
/// It is intentionally distinct from [`SchemeTag::ED25519_STR`] so the reference scheme
/// can never be mistaken for (or registered as) the real `ed25519` scheme.
pub const REFERENCE_SCHEME_TAG: &str = "reference-insecure";

/// Fixed byte mask used by the reference key-derivation transform.
///
/// XOR-ing every signing-key byte with this constant is a *reversible* bijection over
/// equal-length byte sequences, so `derive_verifying_key` is injective and the matching
/// `(sk, vk)` relation is decidable (and unique) — see [`derive_verifying_key`].
const REFERENCE_DERIVE_MASK: u8 = 0xA5;

/// Reference length (in bytes) of a keypair produced by [`reference_keypair`].
const REFERENCE_KEY_LEN: usize = 32;

/// Deterministically derives the [`VerifyingKey`] that corresponds to a reference
/// [`SigningKey`] (non-secure; for tests / domain logic only).
///
/// The transform XORs every key byte with [`REFERENCE_DERIVE_MASK`]. Because XOR with a
/// fixed constant is its own inverse, this is a *reversible* bijection over equal-length
/// byte sequences: every `sk` maps to exactly one `vk`, distinct `sk`s map to distinct
/// `vk`s, and `derive(derive(sk)) == sk`. This makes "does `sk` match `vk`?" decidable as
/// `derive_verifying_key(sk) == *vk`.
///
/// Real schemes derive a public key one-way; this reference derivation is deliberately
/// reversible and **provides no secrecy**.
pub fn derive_verifying_key(sk: &SigningKey) -> VerifyingKey {
    let bytes: Vec<u8> = sk
        .as_bytes()
        .iter()
        .map(|b| b ^ REFERENCE_DERIVE_MASK)
        .collect();
    VerifyingKey::new(bytes)
}

/// Produces a matching reference `(SigningKey, VerifyingKey)` keypair from a `seed`
/// (non-secure; for tests / domain logic only).
///
/// The signing key is a fixed-length ([`REFERENCE_KEY_LEN`]) deterministic expansion of
/// `seed`, and the verifying key is [`derive_verifying_key`] of that signing key, so the
/// returned pair always *matches* by construction. Identical seeds yield identical
/// keypairs; differing seeds (almost always) yield differing keypairs. An empty seed is
/// accepted and produces a fixed keypair.
pub fn reference_keypair(seed: &[u8]) -> (SigningKey, VerifyingKey) {
    // Deterministically expand the seed to a fixed-length signing key. The mixing is a
    // simple, reproducible byte schedule — NOT a secure KDF.
    let basis: &[u8] = if seed.is_empty() { &[0u8] } else { seed };
    let sk_bytes: Vec<u8> = (0..REFERENCE_KEY_LEN)
        .map(|i| {
            let s = basis[i % basis.len()];
            s.wrapping_add(i as u8)
                .wrapping_mul(31)
                .wrapping_add(0x5b)
        })
        .collect();
    let sk = SigningKey::new(sk_bytes);
    let vk = derive_verifying_key(&sk);
    (sk, vk)
}

/// Deterministically encodes a reference signature that binds `vk` and `msg`.
///
/// Layout: `len(vk) as u32 big-endian ++ vk_bytes ++ msg`. The length prefix makes this
/// encoding **injective** in the `(vk, msg)` pair: two distinct `(vk, msg)` pairs can
/// never collide to the same bytes. `verify` recomputes this encoding from its own
/// `(vk, msg)` and compares for equality, which is what gives the reference scheme its
/// "binds `derive(sk)` and `msg`" property without any real cryptography.
fn encode_reference_signature(vk: &VerifyingKey, msg: &[u8]) -> Signature {
    let vk_bytes = vk.as_bytes();
    let mut out = Vec::with_capacity(4 + vk_bytes.len() + msg.len());
    out.extend_from_slice(&(vk_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(vk_bytes);
    out.extend_from_slice(msg);
    Signature::new(out)
}

/// Deterministic, **non-secure** reference [`Signer`] (task 4.2).
///
/// `sign(sk, msg)` returns [`encode_reference_signature`] of `derive_verifying_key(sk)`
/// and `msg`, so the produced signature deterministically binds the verifying key that
/// corresponds to `sk` together with the exact message. Verification under the matching
/// [`ReferenceVerifier`] therefore succeeds (`verify(vk, msg, sign(sk, msg)) == true`),
/// satisfying the [`Signer`]→[`Verifier`] contract (Req 4.1, 4.2) for property tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReferenceSigner;

/// Deterministic, **non-secure** reference [`Verifier`] (task 4.2).
///
/// `verify(vk, msg, sig)` recomputes [`encode_reference_signature`] from `vk` and `msg`
/// and returns whether it equals `sig`. Because the encoding is injective in `(vk, msg)`
/// and `sign` embeds `derive_verifying_key(sk)`, this returns `true` **iff** `sig` was
/// produced by an `sk` matching `vk` over the **same** `msg`: a mismatched `vk` (Req 4.3)
/// or a tampered `msg` (Req 4.4) changes the recomputed bytes and yields `false`. It is a
/// pure function of its inputs, so it is deterministic (Req 4.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReferenceVerifier;

impl Signer for ReferenceSigner {
    fn scheme_tag(&self) -> SchemeTag {
        SchemeTag::new(REFERENCE_SCHEME_TAG)
    }

    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> IdentityResult<Signature> {
        let vk = derive_verifying_key(sk);
        Ok(encode_reference_signature(&vk, msg))
    }
}

impl Verifier for ReferenceVerifier {
    fn scheme_tag(&self) -> SchemeTag {
        SchemeTag::new(REFERENCE_SCHEME_TAG)
    }

    fn verify(&self, vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
        let expected = encode_reference_signature(vk, msg);
        sig.as_bytes() == expected.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time confirmation that the traits are object-safe (usable as `dyn`), which
    /// is how gmc-node injects a concrete Ed25519 implementation behind the same seam.
    /// This also documents the seam shape without binding any algorithm (task 4.2 adds the
    /// deterministic reference impl in this file).
    #[test]
    fn traits_are_object_safe() {
        fn _accepts_dyn(_signer: &dyn Signer, _verifier: &dyn Verifier) {}
    }

    // --- deterministic reference Signer / Verifier (task 4.2) --------------

    /// A matching keypair + same message ⇒ `verify` is `true` (Req 4.1, 4.2).
    #[test]
    fn sign_then_verify_true_for_matching_keypair_and_msg() {
        let (sk, vk) = reference_keypair(b"alice-seed");
        let msg = b"transfer 10 merit";
        let sig = ReferenceSigner.sign(&sk, msg).expect("reference sign");
        assert!(ReferenceVerifier.verify(&vk, msg, &sig));
    }

    /// The derived verifying key always matches the signing key it came from, and the
    /// reversible derivation is its own inverse (matching is decidable).
    #[test]
    fn derive_verifying_key_matches_and_is_reversible() {
        let (sk, vk) = reference_keypair(b"seed");
        assert_eq!(derive_verifying_key(&sk), vk);
        // XOR with a fixed mask is its own inverse: derive(vk-as-sk) == original sk.
        let vk_as_sk = SigningKey::new(vk.as_bytes().to_vec());
        assert_eq!(derive_verifying_key(&vk_as_sk).as_bytes(), sk.as_bytes());
    }

    /// A wrong (mismatched) verifying key ⇒ `verify` is `false` (Req 4.3).
    #[test]
    fn verify_false_for_wrong_vk() {
        let (sk, _vk) = reference_keypair(b"alice-seed");
        let (_other_sk, wrong_vk) = reference_keypair(b"bob-seed");
        let msg = b"hello";
        let sig = ReferenceSigner.sign(&sk, msg).expect("reference sign");
        assert!(!ReferenceVerifier.verify(&wrong_vk, msg, &sig));
    }

    /// A tampered message ⇒ `verify` is `false` (Req 4.4).
    #[test]
    fn verify_false_for_tampered_msg() {
        let (sk, vk) = reference_keypair(b"alice-seed");
        let msg = b"send 10";
        let sig = ReferenceSigner.sign(&sk, msg).expect("reference sign");
        assert!(ReferenceVerifier.verify(&vk, msg, &sig));
        // Flip the message; the same signature must no longer verify.
        assert!(!ReferenceVerifier.verify(&vk, b"send 99", &sig));
        // Empty message also rejected against a signature over a non-empty message.
        assert!(!ReferenceVerifier.verify(&vk, b"", &sig));
    }

    /// `sign` and `verify` are deterministic across repeated calls (Req 4.5).
    #[test]
    fn sign_and_verify_are_deterministic() {
        let (sk, vk) = reference_keypair(b"seed-42");
        let msg = b"deterministic payload";
        let sig_a = ReferenceSigner.sign(&sk, msg).expect("sign a");
        let sig_b = ReferenceSigner.sign(&sk, msg).expect("sign b");
        assert_eq!(sig_a, sig_b, "identical inputs must yield identical signatures");

        // verify returns the same answer no matter how many times it is called.
        for _ in 0..5 {
            assert!(ReferenceVerifier.verify(&vk, msg, &sig_a));
        }
        let (_sk2, wrong_vk) = reference_keypair(b"other");
        for _ in 0..5 {
            assert!(!ReferenceVerifier.verify(&wrong_vk, msg, &sig_a));
        }
    }

    /// The same seed yields the same keypair; different seeds yield different keypairs.
    #[test]
    fn reference_keypair_is_seed_deterministic_and_injective() {
        let (sk1, vk1) = reference_keypair(b"seed");
        let (sk2, vk2) = reference_keypair(b"seed");
        assert_eq!(sk1, sk2);
        assert_eq!(vk1, vk2);

        let (sk3, vk3) = reference_keypair(b"different");
        assert_ne!(sk1, sk3);
        assert_ne!(vk1, vk3);

        // Empty seed is accepted and produces a stable keypair that still matches.
        let (sk_empty, vk_empty) = reference_keypair(b"");
        assert_eq!(derive_verifying_key(&sk_empty), vk_empty);
    }

    /// The reference signer/verifier report a tag distinct from `ed25519`.
    #[test]
    fn reference_scheme_tag_is_distinct_from_ed25519() {
        assert_eq!(ReferenceSigner.scheme_tag().as_str(), REFERENCE_SCHEME_TAG);
        assert_eq!(ReferenceVerifier.scheme_tag(), ReferenceSigner.scheme_tag());
        assert_ne!(ReferenceSigner.scheme_tag().as_str(), SchemeTag::ED25519_STR);
    }

    /// The reference impls satisfy object-safety too, mirroring how gmc-node injects a
    /// concrete implementation behind the same `dyn` seam.
    #[test]
    fn reference_impls_usable_as_dyn() {
        let signer: &dyn Signer = &ReferenceSigner;
        let verifier: &dyn Verifier = &ReferenceVerifier;
        let (sk, vk) = reference_keypair(b"dyn-seed");
        let msg = b"via dyn";
        let sig = signer.sign(&sk, msg).expect("dyn sign");
        assert!(verifier.verify(&vk, msg, &sig));
    }
}
