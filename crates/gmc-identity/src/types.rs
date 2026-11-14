//! Shared primitive types for the gmc-identity (GMC identity & account) layer.
//!
//! Per the design's *Data Models* section, this layer is **scheme-agnostic**: signing
//! keys, verifying keys and signatures are all treated as **opaque byte sequences**,
//! validated only against the byte-format constraints declared by their owning
//! signature scheme (see [`crate::scheme`], filled in by later tasks). This module
//! defines those shared primitives so every later module (scheme, signer, identity id,
//! ownership, device, recovery, …) speaks the same identity vocabulary:
//!
//! - [`VerifyingKey`] / [`SigningKey`] / [`Signature`] — opaque-byte newtypes.
//! - [`SchemeTag`] — a string newtype naming a signature scheme (e.g. `ed25519`).
//! - [`Nonce`] — a per-identity monotonic operation counter (a `u64` alias, per design).
//! - [`IdentityKind`] — `IFay` (self-sovereign personal) vs `CoFay` (collective).
//! - [`DeviceType`] — the prescribed terminal-class enum (Requirement 8).
//!
//! Time is **reused** from `gmc-core`: [`Timestamp`] is re-exported from
//! [`gmc_core::types::Timestamp`] and is **not** redefined here (design: "所有时间字段
//! 复用 gmc-core 的 Timestamp").
//!
//! This module is deliberately validation-free: it provides only shared primitives.
//! Domain validation that maps to a specific [`crate::error::IdentityError`] code lives
//! in the modules that own each rule (e.g. byte-format checks live in [`crate::scheme`]).

use core::fmt;

/// On-chain (block) timestamp, **reused** from `gmc-core` (never redefined here).
///
/// Re-exported so sibling modules can refer to `crate::types::Timestamp` while the
/// single source of truth remains [`gmc_core::types::Timestamp`].
pub use gmc_core::types::Timestamp;

/// A per-identity, monotonically increasing operation counter used for replay
/// protection (design *Data Models*: `type Nonce = u64`).
///
/// Modeled as a transparent alias (not a newtype) to match the design exactly and to
/// keep arithmetic/comparison ergonomic in the `Identity_Core` replay check
/// (Requirements 5.2, 5.4, 5.5).
pub type Nonce = u64;

/// A public verifying key, represented as opaque bytes (Requirement 1.2).
///
/// Only the byte-format constraints of the owning [`SchemeTag`] are ever checked
/// against these bytes; this layer attaches no algorithmic meaning to them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VerifyingKey {
    bytes: Vec<u8>,
}

/// A private signing key, represented as opaque bytes (Requirement 1.2).
///
/// Per Requirement 13.5 this layer never *requires* exporting signing-key material.
/// The [`fmt::Debug`] impl is therefore **redacted** so the secret bytes are never
/// printed into logs or test output; the length is shown for diagnostics only.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SigningKey {
    bytes: Vec<u8>,
}

/// A signature over some message, represented as opaque bytes (Requirement 1.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Signature {
    bytes: Vec<u8>,
}

macro_rules! opaque_bytes_impl {
    ($ty:ident) => {
        impl $ty {
            /// Builds the value from any byte-like input.
            #[inline]
            pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
                $ty {
                    bytes: bytes.into(),
                }
            }

            /// Returns the underlying bytes as a slice.
            #[inline]
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }

            /// Number of bytes held.
            #[inline]
            pub fn len(&self) -> usize {
                self.bytes.len()
            }

            /// Returns `true` if no bytes are held.
            #[inline]
            pub fn is_empty(&self) -> bool {
                self.bytes.is_empty()
            }
        }

        impl From<Vec<u8>> for $ty {
            #[inline]
            fn from(bytes: Vec<u8>) -> Self {
                $ty { bytes }
            }
        }

        impl From<&[u8]> for $ty {
            #[inline]
            fn from(bytes: &[u8]) -> Self {
                $ty {
                    bytes: bytes.to_vec(),
                }
            }
        }
    };
}

opaque_bytes_impl!(VerifyingKey);
opaque_bytes_impl!(SigningKey);
opaque_bytes_impl!(Signature);

impl fmt::Debug for SigningKey {
    /// Redacted: never prints the secret bytes (Requirement 13.5), only the length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("bytes", &format_args!("<redacted; {} bytes>", self.bytes.len()))
            .finish()
    }
}

/// A unique signature-scheme tag, e.g. `"ed25519"` (Requirement 1.1).
///
/// Used as a `BTreeMap` key in the scheme registry and embedded in `IdentityId`, so it
/// derives `Ord`/`Hash` for deterministic ordered storage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SchemeTag(String);

impl SchemeTag {
    /// The default scheme tag string registered by the scheme registry (Requirement 1.3).
    pub const ED25519_STR: &'static str = "ed25519";

    /// Builds a `SchemeTag` from any string-like value.
    #[inline]
    pub fn new(tag: impl Into<String>) -> Self {
        SchemeTag(tag.into())
    }

    /// The default `ed25519` scheme tag (Requirement 1.3).
    #[inline]
    pub fn ed25519() -> Self {
        SchemeTag(Self::ED25519_STR.to_owned())
    }

    /// Returns the tag as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if the tag is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SchemeTag {
    fn from(value: String) -> Self {
        SchemeTag(value)
    }
}

impl From<&str> for SchemeTag {
    fn from(value: &str) -> Self {
        SchemeTag(value.to_owned())
    }
}

impl fmt::Display for SchemeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether an identity is a self-sovereign personal identity or a collective one.
///
/// `IFay` identities are the roots of every ownership path (depth 0); `CoFay`
/// identities are owned by an iFay or another coFay (design *Data Models*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityKind {
    /// Self-sovereign personal identity (owns itself).
    IFay,
    /// Collective / organizational identity (owned by an iFay or another coFay).
    CoFay,
}

/// The prescribed terminal-class enum a device credential may declare (Requirement 8).
///
/// Any device-type input outside this set is rejected with
/// [`crate::error::IdentityError::DeviceTypeInvalid`] (Requirement 8.6) by the device
/// registry in a later task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceType {
    /// A phone / mobile handset.
    Phone,
    /// A desktop or laptop computer.
    Computer,
    /// A smart watch / wearable.
    Watch,
    /// A robot.
    Robot,
    /// An in-car human-machine interface (HMI) head unit.
    CarHmi,
    /// A cloud-hosted SDK instance.
    CloudSdk,
}

impl DeviceType {
    /// All prescribed device types, in a stable order. Useful for exhaustive
    /// enumeration in tests and for device-type validation (Requirement 8.6).
    pub const ALL: [DeviceType; 6] = [
        DeviceType::Phone,
        DeviceType::Computer,
        DeviceType::Watch,
        DeviceType::Robot,
        DeviceType::CarHmi,
        DeviceType::CloudSdk,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    // --- opaque byte newtypes ----------------------------------------------

    #[test]
    fn opaque_keys_construct_and_expose_bytes() {
        let vk = VerifyingKey::new(vec![1, 2, 3]);
        assert_eq!(vk.as_bytes(), &[1, 2, 3]);
        assert_eq!(vk.len(), 3);
        assert!(!vk.is_empty());

        let sig = Signature::from(&[9u8, 8][..]);
        assert_eq!(sig.as_bytes(), &[9, 8]);

        let sk: SigningKey = vec![0u8; 32].into();
        assert_eq!(sk.len(), 32);
        assert!(VerifyingKey::default().is_empty());
    }

    #[test]
    fn verifying_keys_order_and_hash_for_collections() {
        // VerifyingKey is used in ordered sets/maps (delegates, guardians); confirm it
        // is usable as a BTreeMap key and orders by its bytes.
        let mut set = BTreeSet::new();
        set.insert(VerifyingKey::new(vec![2]));
        set.insert(VerifyingKey::new(vec![1]));
        set.insert(VerifyingKey::new(vec![1])); // duplicate
        assert_eq!(set.len(), 2);
        assert_eq!(set.iter().next().unwrap().as_bytes(), &[1]);
    }

    #[test]
    fn signing_key_debug_is_redacted() {
        let sk = SigningKey::new(vec![0xde, 0xad, 0xbe, 0xef]);
        let dbg = format!("{sk:?}");
        // Length is shown for diagnostics, but the secret bytes are not.
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains('4'));
        assert!(!dbg.contains("222")); // 0xde == 222 decimal, must not leak
        assert!(!dbg.contains("de, ad")); // no raw byte listing
    }

    // --- SchemeTag ----------------------------------------------------------

    #[test]
    fn scheme_tag_construction_and_default() {
        assert_eq!(SchemeTag::ed25519().as_str(), "ed25519");
        assert_eq!(SchemeTag::from("ed25519"), SchemeTag::ed25519());
        assert_eq!(SchemeTag::new("custom").to_string(), "custom");
        assert!(SchemeTag::new("").is_empty());
    }

    #[test]
    fn scheme_tag_usable_as_btreemap_key() {
        let mut registry: BTreeMap<SchemeTag, u8> = BTreeMap::new();
        registry.insert(SchemeTag::ed25519(), 1);
        registry.insert(SchemeTag::new("p256"), 2);
        assert_eq!(registry.get(&SchemeTag::from("ed25519")), Some(&1));
    }

    // --- enums --------------------------------------------------------------

    #[test]
    fn identity_kind_variants() {
        assert_ne!(IdentityKind::IFay, IdentityKind::CoFay);
        let k = IdentityKind::IFay;
        assert_eq!(k, IdentityKind::IFay);
    }

    #[test]
    fn device_type_all_lists_six_distinct_variants() {
        assert_eq!(DeviceType::ALL.len(), 6);
        let distinct: BTreeSet<DeviceType> = DeviceType::ALL.into_iter().collect();
        assert_eq!(distinct.len(), 6);
        assert!(DeviceType::ALL.contains(&DeviceType::CarHmi));
        assert!(DeviceType::ALL.contains(&DeviceType::CloudSdk));
    }

    // --- Timestamp re-export ------------------------------------------------

    #[test]
    fn timestamp_is_reused_from_gmc_core() {
        let t: Timestamp = Timestamp::from_secs(42);
        assert_eq!(t.as_secs(), 42);
        // Confirm the re-exported type is the very same gmc-core type.
        let _same: gmc_core::types::Timestamp = t;
    }

    // --- Nonce alias --------------------------------------------------------

    #[test]
    fn nonce_is_a_u64_alias() {
        let n: Nonce = 7;
        assert!(n + 1 > n);
    }
}
