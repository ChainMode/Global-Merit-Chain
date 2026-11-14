//! `Signature_Scheme` abstraction (scheme-agnostic): byte-format constraints and
//! scheme descriptors.
//!
//! Per the design's *Signature_Scheme* section and *Data Models*, this layer is
//! **scheme-agnostic**: signing keys, verifying keys and signatures are opaque byte
//! sequences (see [`crate::types`]), validated **only** against the byte-format
//! constraints declared by their owning signature scheme. This module provides those
//! constraints and their checks:
//!
//! - [`ByteFormat`] — a length constraint (`exact_len` *or* an inclusive
//!   `[min_len, max_len]` range) for one kind of key/signature material (Requirement 1.1).
//! - [`SchemeDescriptor`] — a scheme tag plus the three [`ByteFormat`]s for its
//!   `SigningKey` / `VerifyingKey` / `Signature` (Requirement 1.1), with the
//!   `validate_*` checks that reject ill-formed bytes with
//!   [`IdentityError::KeyFormatInvalid`] (Requirements 1.2, 1.5).
//!
//! The `SchemeRegistry` (default `ed25519`, register/resolve, `SchemeUnsupported`) is
//! deliberately **not** defined here — it is added by task 2.2 in this same file. The
//! public [`ByteFormat`] / [`SchemeDescriptor`] constructors below (including the
//! convenience [`SchemeDescriptor::ed25519`]) are the building blocks that registry
//! will store and resolve, so it can be layered on without reshaping this code.
//!
//! No algorithm is implemented here: a descriptor declares *formats only*. Real
//! signing/verification is injected by gmc-node through the [`crate::signer`] trait
//! seam.

use std::collections::BTreeMap;

use crate::error::{IdentityError, IdentityResult};
use crate::types::SchemeTag;

/// A byte-length constraint for one kind of opaque key/signature material
/// (Requirement 1.1).
///
/// A `ByteFormat` either pins an **exact** length (`exact_len = Some(n)`, e.g. an
/// Ed25519 public key is exactly 32 bytes) or accepts any length inside the inclusive
/// range `[min_len, max_len]`. When `exact_len` is `Some(n)`, the range fields are kept
/// consistent (`min_len == max_len == n`) by the [`ByteFormat::exact`] constructor and
/// the exact bound takes precedence in [`ByteFormat::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteFormat {
    /// Required fixed length, if the format pins one. `Some(n)` ⇒ exactly `n` bytes.
    exact_len: Option<usize>,
    /// Inclusive lower bound on length when `exact_len` is `None`.
    min_len: usize,
    /// Inclusive upper bound on length when `exact_len` is `None`.
    max_len: usize,
}

impl ByteFormat {
    /// Builds a format that requires **exactly** `n` bytes.
    ///
    /// The range fields are set to `n` as well so the value is internally consistent
    /// regardless of which field a reader inspects.
    #[inline]
    pub const fn exact(n: usize) -> Self {
        ByteFormat {
            exact_len: Some(n),
            min_len: n,
            max_len: n,
        }
    }

    /// Builds a format that accepts any length within the inclusive range
    /// `[min_len, max_len]`.
    ///
    /// No exact length is pinned. If `min_len > max_len` the range admits no length
    /// (every input is rejected); callers are responsible for passing a sensible range.
    #[inline]
    pub const fn range(min_len: usize, max_len: usize) -> Self {
        ByteFormat {
            exact_len: None,
            min_len,
            max_len,
        }
    }

    /// The pinned exact length, if any.
    #[inline]
    pub const fn exact_len(&self) -> Option<usize> {
        self.exact_len
    }

    /// The inclusive lower length bound (equals the exact length when one is pinned).
    #[inline]
    pub const fn min_len(&self) -> usize {
        self.min_len
    }

    /// The inclusive upper length bound (equals the exact length when one is pinned).
    #[inline]
    pub const fn max_len(&self) -> usize {
        self.max_len
    }

    /// Returns `true` iff `bytes` satisfies this length constraint.
    ///
    /// With an exact length the byte slice must match it precisely; otherwise its
    /// length must lie within `[min_len, max_len]` inclusive.
    #[inline]
    pub fn accepts(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        match self.exact_len {
            Some(n) => len == n,
            None => len >= self.min_len && len <= self.max_len,
        }
    }

    /// Checks `bytes` against this format, mapping a violation to
    /// [`IdentityError::KeyFormatInvalid`] (Requirements 1.5, 2.5).
    #[inline]
    pub fn check(&self, bytes: &[u8]) -> IdentityResult<()> {
        if self.accepts(bytes) {
            Ok(())
        } else {
            Err(IdentityError::KeyFormatInvalid)
        }
    }
}

/// A signature scheme's declared identity: a unique tag plus the byte-format
/// constraints for its signing key, verifying key and signature (Requirement 1.1).
///
/// A descriptor carries **no algorithm** — only the formats used to validate opaque
/// key/signature bytes. The scheme registry (task 2.2) stores one descriptor per
/// registered [`SchemeTag`]; the algorithm itself is injected separately via the
/// [`crate::signer`] trait seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeDescriptor {
    tag: SchemeTag,
    signing_key_format: ByteFormat,
    verifying_key_format: ByteFormat,
    signature_format: ByteFormat,
}

impl SchemeDescriptor {
    /// Standard Ed25519 signing-key length in bytes (the 32-byte secret seed).
    pub const ED25519_SIGNING_KEY_LEN: usize = 32;
    /// Standard Ed25519 verifying-key (public key) length in bytes.
    pub const ED25519_VERIFYING_KEY_LEN: usize = 32;
    /// Standard Ed25519 signature length in bytes.
    pub const ED25519_SIGNATURE_LEN: usize = 64;

    /// Builds a descriptor from a tag and the three byte-format constraints.
    #[inline]
    pub fn new(
        tag: SchemeTag,
        signing_key_format: ByteFormat,
        verifying_key_format: ByteFormat,
        signature_format: ByteFormat,
    ) -> Self {
        SchemeDescriptor {
            tag,
            signing_key_format,
            verifying_key_format,
            signature_format,
        }
    }

    /// The standard `ed25519` descriptor: public/secret key 32 bytes, signature 64
    /// bytes, declared with **no algorithm** (design: "标签 + 标准字节格式…但不含算法实现").
    ///
    /// Provided here so the scheme registry (task 2.2) can register the default scheme
    /// by simply storing this descriptor.
    #[inline]
    pub fn ed25519() -> Self {
        SchemeDescriptor::new(
            SchemeTag::ed25519(),
            ByteFormat::exact(Self::ED25519_SIGNING_KEY_LEN),
            ByteFormat::exact(Self::ED25519_VERIFYING_KEY_LEN),
            ByteFormat::exact(Self::ED25519_SIGNATURE_LEN),
        )
    }

    /// The scheme tag this descriptor describes.
    #[inline]
    pub fn tag(&self) -> &SchemeTag {
        &self.tag
    }

    /// The `SigningKey` byte-format constraint.
    #[inline]
    pub fn signing_key_format(&self) -> &ByteFormat {
        &self.signing_key_format
    }

    /// The `VerifyingKey` byte-format constraint.
    #[inline]
    pub fn verifying_key_format(&self) -> &ByteFormat {
        &self.verifying_key_format
    }

    /// The `Signature` byte-format constraint.
    #[inline]
    pub fn signature_format(&self) -> &ByteFormat {
        &self.signature_format
    }

    /// Validates verifying-key bytes against this scheme's verifying-key format.
    ///
    /// Returns `Ok(())` when the bytes satisfy the format, otherwise
    /// [`IdentityError::KeyFormatInvalid`] (Requirements 1.2, 1.5, 2.5).
    #[inline]
    pub fn validate_verifying_key(&self, bytes: &[u8]) -> IdentityResult<()> {
        self.verifying_key_format.check(bytes)
    }

    /// Validates signing-key bytes against this scheme's signing-key format.
    ///
    /// Returns `Ok(())` when the bytes satisfy the format, otherwise
    /// [`IdentityError::KeyFormatInvalid`] (Requirements 1.2, 1.5).
    #[inline]
    pub fn validate_signing_key(&self, bytes: &[u8]) -> IdentityResult<()> {
        self.signing_key_format.check(bytes)
    }

    /// Validates signature bytes against this scheme's signature format.
    ///
    /// Returns `Ok(())` when the bytes satisfy the format, otherwise
    /// [`IdentityError::KeyFormatInvalid`] (Requirements 1.2, 1.5).
    #[inline]
    pub fn validate_signature(&self, bytes: &[u8]) -> IdentityResult<()> {
        self.signature_format.check(bytes)
    }
}

/// A deterministic registry mapping each [`SchemeTag`] to its [`SchemeDescriptor`]
/// (design *Signature_Scheme*: `SchemeRegistry { schemes: BTreeMap<SchemeTag,
/// SchemeDescriptor> }`).
///
/// The registry is the single point that answers "is this scheme tag supported, and
/// what byte formats does it declare?". It is intentionally **algorithm-free** — it
/// only stores descriptors (format declarations); real signing/verification is injected
/// separately via the [`crate::signer`] trait seam.
///
/// # Determinism
///
/// Backed by a [`BTreeMap`] so iteration order is the deterministic ascending
/// [`SchemeTag`] order regardless of insertion order, and [`register`](Self::register)
/// **rejects** an already-occupied tag rather than overwriting it. Together these make
/// the registry's observable behavior a pure function of the *set* of registered
/// descriptors, which is what Property 5 relies on.
///
/// # Default
///
/// [`SchemeRegistry::default`] always contains the standard `ed25519` descriptor
/// (Requirement 1.3); see [`SchemeDescriptor::ed25519`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeRegistry {
    schemes: BTreeMap<SchemeTag, SchemeDescriptor>,
}

impl SchemeRegistry {
    /// Builds an **empty** registry with no schemes registered.
    ///
    /// Most callers want [`SchemeRegistry::default`], which pre-registers `ed25519`
    /// (Requirement 1.3). `empty` exists for tests and for callers that want to choose
    /// every scheme explicitly.
    #[inline]
    pub fn empty() -> Self {
        SchemeRegistry {
            schemes: BTreeMap::new(),
        }
    }

    /// Registers `descriptor` under its own [`SchemeTag`], provided the tag is **not
    /// already occupied** (design: "allow registering additional schemes").
    ///
    /// Duplicate tags are **rejected** rather than overwritten, so registration never
    /// silently changes an existing scheme's declared formats — keeping the registry
    /// deterministic (Property 5). On success the tag becomes resolvable via
    /// [`resolve`](Self::resolve).
    ///
    /// # Errors
    ///
    /// On a duplicate tag the registry is left **unchanged** and the rejected
    /// `descriptor` is returned as `Err(descriptor)`, so the caller can recover it
    /// without a clone. (The shared [`IdentityError`] vocabulary has no "duplicate
    /// scheme" code — this is an internal configuration concern, not a request-level
    /// rejection — so the value itself is returned instead of an error code.)
    #[inline]
    pub fn register(&mut self, descriptor: SchemeDescriptor) -> Result<(), SchemeDescriptor> {
        if self.schemes.contains_key(descriptor.tag()) {
            // Reject duplicates; existing descriptor and registry left untouched.
            return Err(descriptor);
        }
        self.schemes.insert(descriptor.tag().clone(), descriptor);
        Ok(())
    }

    /// Resolves `tag` to its registered [`SchemeDescriptor`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::SchemeUnsupported`] when `tag` is not registered, with
    /// no state change (Requirement 1.4).
    #[inline]
    pub fn resolve(&self, tag: &SchemeTag) -> IdentityResult<&SchemeDescriptor> {
        self.schemes
            .get(tag)
            .ok_or(IdentityError::SchemeUnsupported)
    }

    /// Returns `true` iff `tag` is registered.
    #[inline]
    pub fn contains(&self, tag: &SchemeTag) -> bool {
        self.schemes.contains_key(tag)
    }

    /// The number of registered schemes.
    #[inline]
    pub fn len(&self) -> usize {
        self.schemes.len()
    }

    /// Returns `true` iff no schemes are registered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.schemes.is_empty()
    }

    /// Iterates over registered `(tag, descriptor)` pairs in ascending
    /// [`SchemeTag`] order (deterministic, insertion-order-independent).
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&SchemeTag, &SchemeDescriptor)> {
        self.schemes.iter()
    }
}

impl Default for SchemeRegistry {
    /// A registry that **always** contains the standard `ed25519` descriptor
    /// (Requirement 1.3).
    #[inline]
    fn default() -> Self {
        let mut registry = SchemeRegistry::empty();
        // The empty registry cannot already contain ed25519, so this never fails.
        let _ = registry.register(SchemeDescriptor::ed25519());
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ByteFormat: exact length -----------------------------------------

    #[test]
    fn exact_format_accepts_only_that_length() {
        let fmt = ByteFormat::exact(32);
        assert_eq!(fmt.exact_len(), Some(32));
        // min/max kept consistent with the exact bound.
        assert_eq!(fmt.min_len(), 32);
        assert_eq!(fmt.max_len(), 32);

        assert!(fmt.accepts(&vec![0u8; 32]));
        assert!(!fmt.accepts(&vec![0u8; 31]));
        assert!(!fmt.accepts(&vec![0u8; 33]));
        assert!(!fmt.accepts(&[]));
    }

    #[test]
    fn exact_format_check_maps_violation_to_key_format_invalid() {
        let fmt = ByteFormat::exact(64);
        assert_eq!(fmt.check(&vec![7u8; 64]), Ok(()));
        assert_eq!(
            fmt.check(&vec![7u8; 63]),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    // --- ByteFormat: min/max range ----------------------------------------

    #[test]
    fn range_format_accepts_within_inclusive_bounds() {
        let fmt = ByteFormat::range(4, 8);
        assert_eq!(fmt.exact_len(), None);
        // Boundaries are inclusive.
        assert!(fmt.accepts(&vec![0u8; 4]));
        assert!(fmt.accepts(&vec![0u8; 6]));
        assert!(fmt.accepts(&vec![0u8; 8]));
        // Outside the range is rejected.
        assert!(!fmt.accepts(&vec![0u8; 3]));
        assert!(!fmt.accepts(&vec![0u8; 9]));
    }

    #[test]
    fn range_format_check_accept_and_reject_paths() {
        let fmt = ByteFormat::range(1, 2);
        assert_eq!(fmt.check(&[1]), Ok(()));
        assert_eq!(fmt.check(&[1, 2]), Ok(()));
        assert_eq!(fmt.check(&[]), Err(IdentityError::KeyFormatInvalid));
        assert_eq!(
            fmt.check(&[1, 2, 3]),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    #[test]
    fn empty_range_admits_nothing() {
        // A deliberately empty range (min > max) rejects every input.
        let fmt = ByteFormat::range(5, 4);
        assert!(!fmt.accepts(&vec![0u8; 4]));
        assert!(!fmt.accepts(&vec![0u8; 5]));
        assert!(!fmt.accepts(&[]));
    }

    // --- SchemeDescriptor: ed25519 standard formats -----------------------

    #[test]
    fn ed25519_descriptor_declares_tag_and_three_formats() {
        let d = SchemeDescriptor::ed25519();
        assert_eq!(d.tag(), &SchemeTag::ed25519());
        assert_eq!(d.signing_key_format(), &ByteFormat::exact(32));
        assert_eq!(d.verifying_key_format(), &ByteFormat::exact(32));
        assert_eq!(d.signature_format(), &ByteFormat::exact(64));
    }

    #[test]
    fn ed25519_validators_accept_standard_lengths() {
        let d = SchemeDescriptor::ed25519();
        assert_eq!(d.validate_verifying_key(&vec![0u8; 32]), Ok(()));
        assert_eq!(d.validate_signing_key(&vec![0u8; 32]), Ok(()));
        assert_eq!(d.validate_signature(&vec![0u8; 64]), Ok(()));
    }

    #[test]
    fn ed25519_validators_reject_wrong_lengths_with_key_format_invalid() {
        let d = SchemeDescriptor::ed25519();
        assert_eq!(
            d.validate_verifying_key(&vec![0u8; 31]),
            Err(IdentityError::KeyFormatInvalid)
        );
        assert_eq!(
            d.validate_signing_key(&vec![0u8; 33]),
            Err(IdentityError::KeyFormatInvalid)
        );
        assert_eq!(
            d.validate_signature(&vec![0u8; 32]),
            Err(IdentityError::KeyFormatInvalid)
        );
        // Empty inputs are rejected too.
        assert_eq!(
            d.validate_verifying_key(&[]),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    // --- SchemeDescriptor: custom scheme uses its own formats only --------

    #[test]
    fn custom_descriptor_validates_against_its_own_formats() {
        // A scheme whose three materials have different length rules; each validator
        // must consult only its own ByteFormat (Requirement 1.2: opaque bytes checked
        // solely per the owning scheme's format).
        let d = SchemeDescriptor::new(
            SchemeTag::new("custom"),
            ByteFormat::exact(16),  // signing key
            ByteFormat::range(8, 12), // verifying key
            ByteFormat::range(70, 72), // signature
        );

        // Signing key: exactly 16.
        assert_eq!(d.validate_signing_key(&vec![0u8; 16]), Ok(()));
        assert_eq!(
            d.validate_signing_key(&vec![0u8; 12]),
            Err(IdentityError::KeyFormatInvalid)
        );

        // Verifying key: 8..=12 inclusive.
        assert_eq!(d.validate_verifying_key(&vec![0u8; 8]), Ok(()));
        assert_eq!(d.validate_verifying_key(&vec![0u8; 12]), Ok(()));
        assert_eq!(
            d.validate_verifying_key(&vec![0u8; 16]),
            Err(IdentityError::KeyFormatInvalid)
        );

        // Signature: 70..=72 inclusive — a 64-byte (Ed25519-sized) signature is
        // rejected here, proving validation is per-scheme, not global.
        assert_eq!(d.validate_signature(&vec![0u8; 71]), Ok(()));
        assert_eq!(
            d.validate_signature(&vec![0u8; 64]),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    // --- SchemeRegistry ----------------------------------------------------

    #[test]
    fn default_registry_always_contains_ed25519() {
        // Requirement 1.3: the default registry is never without ed25519.
        let registry = SchemeRegistry::default();
        assert!(registry.contains(&SchemeTag::ed25519()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn default_registry_resolves_ed25519_to_standard_descriptor() {
        let registry = SchemeRegistry::default();
        let d = registry.resolve(&SchemeTag::ed25519()).expect("ed25519 registered");
        assert_eq!(d, &SchemeDescriptor::ed25519());
        assert_eq!(d.signing_key_format(), &ByteFormat::exact(32));
        assert_eq!(d.verifying_key_format(), &ByteFormat::exact(32));
        assert_eq!(d.signature_format(), &ByteFormat::exact(64));
    }

    #[test]
    fn empty_registry_has_no_schemes() {
        let registry = SchemeRegistry::empty();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(!registry.contains(&SchemeTag::ed25519()));
    }

    #[test]
    fn register_then_resolve_returns_same_descriptor() {
        // Property 5 (happy path): register an unoccupied tag, then resolve it back.
        let mut registry = SchemeRegistry::default();
        let custom = SchemeDescriptor::new(
            SchemeTag::new("p256"),
            ByteFormat::exact(32),
            ByteFormat::range(33, 65),
            ByteFormat::range(70, 72),
        );
        assert_eq!(registry.register(custom.clone()), Ok(()));
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.resolve(&SchemeTag::new("p256")), Ok(&custom));
        // The pre-existing default scheme is untouched.
        assert_eq!(
            registry.resolve(&SchemeTag::ed25519()),
            Ok(&SchemeDescriptor::ed25519())
        );
    }

    #[test]
    fn resolve_unregistered_tag_returns_scheme_unsupported() {
        // Requirement 1.4: an unregistered tag is rejected with SchemeUnsupported.
        let registry = SchemeRegistry::default();
        assert_eq!(
            registry.resolve(&SchemeTag::new("does-not-exist")),
            Err(IdentityError::SchemeUnsupported)
        );
        // Empty registry rejects even ed25519.
        assert_eq!(
            SchemeRegistry::empty().resolve(&SchemeTag::ed25519()),
            Err(IdentityError::SchemeUnsupported)
        );
    }

    #[test]
    fn register_duplicate_tag_is_rejected_and_leaves_registry_unchanged() {
        // Documented choice: duplicate tags are REJECTED (not overwritten) to keep the
        // registry deterministic. The rejected descriptor is handed back unchanged.
        let mut registry = SchemeRegistry::default();
        let before = registry.clone();

        // A descriptor reusing the ed25519 tag but declaring DIFFERENT formats.
        let impostor = SchemeDescriptor::new(
            SchemeTag::ed25519(),
            ByteFormat::exact(1),
            ByteFormat::exact(2),
            ByteFormat::exact(3),
        );
        assert_eq!(registry.register(impostor.clone()), Err(impostor));

        // Registry is byte-for-byte unchanged, and ed25519 still resolves to the
        // standard descriptor (not the impostor).
        assert_eq!(registry, before);
        assert_eq!(
            registry.resolve(&SchemeTag::ed25519()),
            Ok(&SchemeDescriptor::ed25519())
        );
    }

    #[test]
    fn registry_iteration_is_deterministic_by_tag_order() {
        // Insertion order should not affect observable order: BTreeMap orders by tag.
        let mut a = SchemeRegistry::empty();
        let mut b = SchemeRegistry::empty();
        let p = SchemeDescriptor::new(
            SchemeTag::new("p256"),
            ByteFormat::exact(32),
            ByteFormat::exact(33),
            ByteFormat::exact(64),
        );
        let e = SchemeDescriptor::ed25519();

        a.register(p.clone()).unwrap();
        a.register(e.clone()).unwrap();
        b.register(e).unwrap();
        b.register(p).unwrap();

        let tags_a: Vec<&SchemeTag> = a.iter().map(|(t, _)| t).collect();
        let tags_b: Vec<&SchemeTag> = b.iter().map(|(t, _)| t).collect();
        assert_eq!(tags_a, tags_b);
        // "ed25519" sorts before "p256".
        assert_eq!(tags_a, vec![&SchemeTag::ed25519(), &SchemeTag::new("p256")]);
        assert_eq!(a, b);
    }
}
