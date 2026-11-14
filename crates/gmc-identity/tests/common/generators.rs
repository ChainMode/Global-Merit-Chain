//! Reusable `proptest` strategy generators for the `gmc-identity` property tests.
//!
//! This is the **skeleton** delivered by task 1.3 (`_Requirements: 1.2_`). Each
//! generator returns a compiling `impl Strategy<Value = ...>` (or [`BoxedStrategy`])
//! over the `gmc-identity` public primitives (task 1.2 — [`VerifyingKey`],
//! [`SigningKey`], [`Signature`], [`SchemeTag`], [`Nonce`], [`DeviceType`]) plus a
//! handful of lightweight, plain-data request shapes defined here. The later
//! property-test tasks (one file per numbered property) consume these generators and
//! map them onto the real identity APIs (`Signature_Scheme`, `Identity_Service`,
//! `Identity_Core`, `Ownership_Registry`, `Device_Registry`, `Recovery_Service`, …)
//! as those modules land.
//!
//! The generator categories mirror the design's *Testing Strategy*:
//!
//! 1. **Key / signature byte sequences** — bytes that both **satisfy** and **violate**
//!    a scheme's `ByteFormat`, plus distinct-key helpers
//!    ([`verifying_key_valid`] / [`verifying_key_invalid`] / [`verifying_key_any`],
//!    the `signing_key_*` / `signature_*` siblings, and
//!    [`two_distinct_verifying_keys`]). Drives format validation (Property 4) and
//!    derivation injectivity (Property 1).
//! 2. **Scheme tags & identity-id strings** — [`scheme_tag_supported`] /
//!    [`scheme_tag_unsupported`] / [`scheme_tag_any`], `(SchemeTag, VerifyingKey)`
//!    pairs ([`scheme_and_verifying_key`]), canonical id strings
//!    ([`canonical_identity_id_string`]) and malformed ones
//!    ([`illegal_identity_id_string`]). Drives round-trip (Property 2) and
//!    parse-rejection (Property 3); scheme registry support/rejection (Property 5).
//! 3. **Nonce sequences** — [`nonce_sequence`], drawn from a small range so the
//!    sequence naturally contains regressions and duplicates. Drives replay
//!    protection (Property 7).
//! 4. **Ownership attach / re-parent sequences** — [`OwnershipOp`] over a small
//!    identity-label pool (so self-parent, unknown-owner, cycle and over-depth edge
//!    cases all arise), mirroring `gmc-core`'s derivation-sequence generator. Drives
//!    ownership structure / guards (Property 9), no-cycles (Property 10) and the depth
//!    bound (Property 11).
//! 5. **Device VK sets & device types** — [`device_vk_set`] (pooled, so duplicates
//!    occur), [`device_type_input`] (valid enum variants **and** illegal tags) and the
//!    [`DeviceOp`] enroll/revoke sequence [`device_sequence`]. Drives device
//!    enrollment (Property 12), duplicate rejection (Property 13), device-type
//!    rejection (Property 14) and the revoke lifecycle (Property 15).
//! 6. **Guardian sets, thresholds & approval multisets** — [`guardian_set`],
//!    [`guardian_config`] (thresholds including out-of-range values) and
//!    [`guardian_approval_sequence`] (drawn from the guardian pool, so the same
//!    guardian can approve more than once). Drives M-of-N recovery (Property 18) and
//!    guardian-config threshold validation (Property 19).
//!
//! These are skeletons: ranges are chosen to cover both the valid input space and its
//! boundaries, but **no protocol logic is asserted here**. See `common/mod.rs` for the
//! `Feature: gmc-identity, Property N: ...` labelling convention every numbered
//! property test must follow.

use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{DeviceType, Nonce, SchemeTag, Signature, SigningKey, VerifyingKey};
use proptest::prelude::*;
use proptest::sample::select;
use proptest::strategy::BoxedStrategy;

// ---------------------------------------------------------------------------
// Reference byte-format lengths
// ---------------------------------------------------------------------------
//
// The default reference scheme mirrors Ed25519's standard byte lengths (design:
// "Ed25519 公钥 32 / 签名 64 字节"). These are kept as local constants because the
// concrete `ByteFormat` lives in `crate::scheme` (filled in by a later task); the
// generators only need to straddle the "exact length" boundary.

/// Reference verifying-key length in bytes (Ed25519 public key).
const VK_LEN: usize = 32;
/// Reference signing-key length in bytes (Ed25519 secret scalar).
const SK_LEN: usize = 32;
/// Reference signature length in bytes (Ed25519 signature).
const SIG_LEN: usize = 64;

/// base32 lowercase, no-pad alphabet — the `key_repr` encoding used by the design's
/// `IdentityId` canonical form (`canonicalEncode` → base32 lowercase, no padding).
const BASE32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/// A vector of exactly `len` arbitrary bytes.
fn bytes_of_len(len: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), len)
}

/// A byte length that is **not** equal to `exact`: either too short (`0..exact`) or too
/// long (`exact+1 ..= exact*3`). Used to build format-violating byte sequences.
fn invalid_len(exact: usize) -> impl Strategy<Value = usize> {
    prop_oneof![0usize..exact, (exact + 1)..=(exact * 3 + 1)]
}

// ---------------------------------------------------------------------------
// 1. Key / signature byte sequences (satisfy & violate ByteFormat)
// ---------------------------------------------------------------------------

/// A [`VerifyingKey`] whose byte length **satisfies** the reference format (`VK_LEN`).
pub fn verifying_key_valid() -> impl Strategy<Value = VerifyingKey> {
    bytes_of_len(VK_LEN).prop_map(VerifyingKey::new)
}

/// A [`VerifyingKey`] whose byte length **violates** the reference format.
pub fn verifying_key_invalid() -> impl Strategy<Value = VerifyingKey> {
    invalid_len(VK_LEN)
        .prop_flat_map(bytes_of_len)
        .prop_map(VerifyingKey::new)
}

/// A [`VerifyingKey`] that is roughly half valid-format, half invalid-format.
pub fn verifying_key_any() -> impl Strategy<Value = VerifyingKey> {
    prop_oneof![verifying_key_valid(), verifying_key_invalid()]
}

/// A [`SigningKey`] whose byte length **satisfies** the reference format (`SK_LEN`).
pub fn signing_key_valid() -> impl Strategy<Value = SigningKey> {
    bytes_of_len(SK_LEN).prop_map(SigningKey::new)
}

/// A [`SigningKey`] whose byte length **violates** the reference format.
pub fn signing_key_invalid() -> impl Strategy<Value = SigningKey> {
    invalid_len(SK_LEN)
        .prop_flat_map(bytes_of_len)
        .prop_map(SigningKey::new)
}

/// A [`Signature`] whose byte length **satisfies** the reference format (`SIG_LEN`).
pub fn signature_valid() -> impl Strategy<Value = Signature> {
    bytes_of_len(SIG_LEN).prop_map(Signature::new)
}

/// A [`Signature`] whose byte length **violates** the reference format.
pub fn signature_invalid() -> impl Strategy<Value = Signature> {
    invalid_len(SIG_LEN)
        .prop_flat_map(bytes_of_len)
        .prop_map(Signature::new)
}

/// A [`Signature`] that is roughly half valid-format, half invalid-format.
pub fn signature_any() -> impl Strategy<Value = Signature> {
    prop_oneof![signature_valid(), signature_invalid()]
}

/// Two valid-format [`VerifyingKey`]s guaranteed to be **distinct**. Drives the
/// injectivity side of `IdentityId` derivation (different vk → different id).
pub fn two_distinct_verifying_keys() -> impl Strategy<Value = (VerifyingKey, VerifyingKey)> {
    (bytes_of_len(VK_LEN), bytes_of_len(VK_LEN))
        .prop_filter("verifying keys must differ", |(a, b)| a != b)
        .prop_map(|(a, b)| (VerifyingKey::new(a), VerifyingKey::new(b)))
}

// ---------------------------------------------------------------------------
// 2. Scheme tags, (SchemeTag, VerifyingKey) pairs & identity-id strings
// ---------------------------------------------------------------------------

/// The default-registered scheme tag (`ed25519`). Resolvable against the default
/// scheme registry (Property 5 accept side).
pub fn scheme_tag_supported() -> impl Strategy<Value = SchemeTag> {
    Just(SchemeTag::ed25519())
}

/// A scheme tag that is **not** registered by the default registry — drives the
/// `SchemeUnsupported` rejection path (Property 5 reject side).
pub fn scheme_tag_unsupported() -> impl Strategy<Value = SchemeTag> {
    prop_oneof![
        Just(SchemeTag::new("p256")),
        Just(SchemeTag::new("secp256k1")),
        Just(SchemeTag::new("rsa2048")),
        Just(SchemeTag::new("bls12_381")),
        Just(SchemeTag::new("")),
        (0u32..1000).prop_map(|n| SchemeTag::new(format!("scheme-{n}"))),
    ]
}

/// A scheme tag that may or may not be registered (mix of supported / unsupported).
pub fn scheme_tag_any() -> impl Strategy<Value = SchemeTag> {
    prop_oneof![scheme_tag_supported(), scheme_tag_unsupported()]
}

/// A `(SchemeTag, VerifyingKey)` pair over the **supported** scheme with a valid-format
/// key — the well-formed input to `deriveIdentityId` (Property 1 / Property 2).
pub fn scheme_and_verifying_key() -> impl Strategy<Value = (SchemeTag, VerifyingKey)> {
    (scheme_tag_supported(), verifying_key_valid())
}

/// A `(SchemeTag, VerifyingKey)` pair where either side may be invalid (unsupported tag
/// and/or malformed key) — drives the derivation rejection paths (Property 4 / 5).
pub fn scheme_and_verifying_key_any() -> impl Strategy<Value = (SchemeTag, VerifyingKey)> {
    (scheme_tag_any(), verifying_key_any())
}

/// A non-empty `key_repr` drawn from the base32 lowercase no-pad alphabet.
fn base32_key_repr() -> impl Strategy<Value = String> {
    proptest::collection::vec(select(BASE32_ALPHABET.to_vec()), 1..=40)
        .prop_map(|bytes| String::from_utf8(bytes).expect("base32 alphabet is ascii"))
}

/// A **canonical** identity-id string of the form `fay1.<supported tag>.<base32>` — the
/// kind produced by this layer's serialization, expected to round-trip (Property 2).
///
/// Earlier this generator built `fay1.ed25519.<arbitrary base32 chars>` directly. That
/// was a defect: an arbitrary-length sequence of base32 alphabet characters is almost
/// never a *canonical* no-pad base32 string (its bit-length is usually invalid, or it
/// carries non-zero trailing pad bits), so the crate's strict `base32_decode` correctly
/// rejected it and `parse_identity_id` returned `IdentityIdFormatInvalid` — i.e. the
/// "canonical" generator produced strings that were not actually canonical, breaking the
/// Property 2 reverse round-trip `canonical(parse(s)) == s`.
///
/// The fix derives the string from a real key, exactly as this layer serializes it:
/// generate 32 arbitrary bytes (a valid ed25519 verifying key), derive an `IdentityId`
/// under the default [`SchemeRegistry`] with [`SchemeTag::ed25519`], and return its
/// `canonical()` form. Every produced string is therefore a genuine canonical
/// serialization that parses and round-trips by construction.
pub fn canonical_identity_id_string() -> impl Strategy<Value = String> {
    bytes_of_len(VK_LEN).prop_map(|key_bytes| {
        let vk = VerifyingKey::new(key_bytes);
        derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk)
            .expect("32-byte vk under the default ed25519 scheme always derives an IdentityId")
            .canonical()
    })
}

/// A **malformed** identity-id string that is *not* a canonical serialization (wrong
/// prefix, unregistered scheme, missing/empty segment, or illegal `key_repr` chars) —
/// drives the `IdentityIdFormatInvalid` rejection path (Property 3).
pub fn illegal_identity_id_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // No "fay1." prefix at all.
        base32_key_repr(),
        // Wrong prefix token.
        base32_key_repr().prop_map(|r| format!("fay2.ed25519.{r}")),
        // Unregistered scheme tag.
        base32_key_repr().prop_map(|r| format!("fay1.unknownscheme.{r}")),
        // Missing key_repr segment.
        Just(format!("fay1.{}.", SchemeTag::ED25519_STR)),
        // Illegal key_repr: uppercase + padding are outside the base32-lower no-pad set.
        base32_key_repr().prop_map(|r| format!("fay1.ed25519.{}=", r.to_uppercase())),
        // Too few dotted segments.
        base32_key_repr().prop_map(|r| format!("fay1{r}")),
        // Empty string.
        Just(String::new()),
    ]
}

// ---------------------------------------------------------------------------
// 3. Nonce sequences (with regressions & duplicates)
// ---------------------------------------------------------------------------

/// A sequence of `0..=max_len` [`Nonce`] values drawn from a small range, so the
/// sequence naturally contains **regressions** (a later value ≤ an earlier one) and
/// **duplicates**. Drives the monotonic replay-protection property (Property 7).
pub fn nonce_sequence(max_len: usize) -> impl Strategy<Value = Vec<Nonce>> {
    proptest::collection::vec(0u64..16, 0..=max_len)
}

// ---------------------------------------------------------------------------
// 4. Ownership attach / re-parent sequences (mirrors gmc-core derivation seq)
// ---------------------------------------------------------------------------

/// A lightweight identity label. Plain-data stand-in for an `IdentityId` (whose
/// concrete model lands in `crate::identity_id`); the small pool means labels collide,
/// so self-parent, unknown-owner, cycle and over-depth situations all arise naturally.
pub type IdLabel = String;

/// An identity label drawn from a small fixed pool. The pool is intentionally larger
/// than the depth bound (16) so an attach chain can exceed it (Property 11).
pub fn identity_label() -> impl Strategy<Value = IdLabel> {
    (0u32..24).prop_map(|n| format!("id-{n}"))
}

/// A single ownership-tree mutation request.
///
/// Skeleton plain-data shape consumed by `Ownership_Registry` property tests. `Attach`
/// covers placing a coFay under an owner (new-leaf creation); `Reparent` covers the
/// owner-pointer change that the cycle guard must reject. Mirrors `gmc-core`'s
/// `DerivationOp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipOp {
    /// Attach `cofay` beneath `owner`.
    Attach { cofay: IdLabel, owner: IdLabel },
    /// Re-attach `cofay` beneath `new_owner` (the cycle-risk operation).
    Reparent {
        cofay: IdLabel,
        new_owner: IdLabel,
    },
}

/// A single attach/re-parent operation over the shared identity-label pool.
pub fn ownership_op() -> impl Strategy<Value = OwnershipOp> {
    prop_oneof![
        3 => (identity_label(), identity_label())
            .prop_map(|(cofay, owner)| OwnershipOp::Attach { cofay, owner }),
        1 => (identity_label(), identity_label())
            .prop_map(|(cofay, new_owner)| OwnershipOp::Reparent { cofay, new_owner }),
    ]
}

/// A sequence of `0..=max_len` ownership operations.
pub fn ownership_sequence(max_len: usize) -> impl Strategy<Value = Vec<OwnershipOp>> {
    proptest::collection::vec(ownership_op(), 0..=max_len)
}

// ---------------------------------------------------------------------------
// 5. Device VK sets & device-type inputs (incl. duplicates & illegal tags)
// ---------------------------------------------------------------------------

/// Builds a valid-format [`VerifyingKey`] deterministically from a seed byte, so two
/// equal seeds yield equal keys (the source of intentional duplicates in pooled sets).
fn vk_from_seed(seed: u8) -> VerifyingKey {
    VerifyingKey::new(vec![seed; VK_LEN])
}

/// A valid-format [`VerifyingKey`] drawn from a small pool of `pool` distinct keys, so
/// duplicates recur across a collection.
pub fn verifying_key_pooled(pool: u8) -> impl Strategy<Value = VerifyingKey> {
    (0u8..pool.max(1)).prop_map(vk_from_seed)
}

/// A set of `0..=max_size` device verifying keys drawn from a small pool, so the same
/// device VK appears more than once (drives duplicate-enrollment rejection, Property 13).
pub fn device_vk_set(max_size: usize) -> impl Strategy<Value = Vec<VerifyingKey>> {
    proptest::collection::vec(verifying_key_pooled(4), 0..=max_size)
}

/// A device-type input, either a **valid** [`DeviceType`] enum variant or an **illegal**
/// free-form tag string outside the prescribed enum (drives Property 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceTypeInput {
    /// A value within the prescribed `DeviceType` enum.
    Known(DeviceType),
    /// A device-type tag outside the prescribed enum (must be rejected).
    Illegal(String),
}

/// One of the six prescribed [`DeviceType`] variants.
pub fn device_type_known() -> impl Strategy<Value = DeviceType> {
    select(DeviceType::ALL.to_vec())
}

/// A device-type **input**: roughly half valid enum variants, half illegal tags.
pub fn device_type_input() -> impl Strategy<Value = DeviceTypeInput> {
    prop_oneof![
        3 => device_type_known().prop_map(DeviceTypeInput::Known),
        1 => prop_oneof![
            Just("tablet".to_string()),
            Just("tv".to_string()),
            Just("drone".to_string()),
            Just("PHONE".to_string()),
            Just(String::new()),
            (0u32..1000).prop_map(|n| format!("device-{n}")),
        ].prop_map(DeviceTypeInput::Illegal),
    ]
}

/// A single device-registry mutation request.
///
/// Skeleton plain-data shape consumed by `Device_Registry` property tests. `Enroll`
/// carries a device VK plus a (possibly illegal) device type; `Revoke` targets a device
/// VK. Re-using a pooled VK lets enroll/revoke/duplicate/idempotent-revoke sequences
/// interleave (Property 12 / 13 / 15).
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceOp {
    /// Enroll `device_key` with the declared `device_type`.
    Enroll {
        device_key: VerifyingKey,
        device_type: DeviceTypeInput,
    },
    /// Revoke the credential identified by `device_key`.
    Revoke { device_key: VerifyingKey },
}

/// A single device enroll/revoke operation over the pooled device-VK space.
pub fn device_op() -> impl Strategy<Value = DeviceOp> {
    prop_oneof![
        3 => (verifying_key_pooled(4), device_type_input())
            .prop_map(|(device_key, device_type)| DeviceOp::Enroll { device_key, device_type }),
        2 => verifying_key_pooled(4).prop_map(|device_key| DeviceOp::Revoke { device_key }),
    ]
}

/// A sequence of `0..=max_len` device operations (enroll / revoke interleaved).
pub fn device_sequence(max_len: usize) -> impl Strategy<Value = Vec<DeviceOp>> {
    proptest::collection::vec(device_op(), 0..=max_len)
}

// ---------------------------------------------------------------------------
// 6. Guardian sets, thresholds & approval multisets
// ---------------------------------------------------------------------------

/// A guardian set of `0..=max_size` verifying keys drawn from a small pool, so the
/// **deduplicated** guardian count (`N`) is often smaller than the raw length.
pub fn guardian_set(max_size: usize) -> impl Strategy<Value = Vec<VerifyingKey>> {
    proptest::collection::vec(verifying_key_pooled(6), 0..=max_size)
}

/// A guardian configuration input: a guardian set plus a threshold `M` whose range
/// **extends beyond** `[1, N]` (it may be `0` or exceed the guardian count), so both the
/// accepted (`1 ≤ M ≤ N`) and rejected configurations are exercised (Property 19).
#[derive(Debug, Clone, PartialEq)]
pub struct GuardianConfigInput {
    /// Proposed guardian verifying keys (may contain duplicates).
    pub guardians: Vec<VerifyingKey>,
    /// Proposed approval threshold `M`.
    pub threshold: u32,
}

/// A guardian configuration whose threshold can be below, within, or above the valid
/// `[1, N]` band.
pub fn guardian_config() -> impl Strategy<Value = GuardianConfigInput> {
    guardian_set(6).prop_flat_map(|guardians| {
        // N is the deduplicated guardian count; allow thresholds from 0 to N + 2.
        let raw_n = guardians.len() as u32;
        (Just(guardians), 0u32..=(raw_n + 2))
            .prop_map(|(guardians, threshold)| GuardianConfigInput { guardians, threshold })
    })
}

/// A recovery-approval multiset: `0..=max_len` guardian verifying keys drawn from the
/// same pool as [`guardian_set`], so the **same guardian can approve more than once**.
/// Drives the dedup-then-threshold M-of-N recovery property (Property 18).
pub fn guardian_approval_sequence(max_len: usize) -> impl Strategy<Value = Vec<VerifyingKey>> {
    proptest::collection::vec(verifying_key_pooled(6), 0..=max_len)
}

// ---------------------------------------------------------------------------
// Boxed convenience aliases
// ---------------------------------------------------------------------------

/// A boxed `(SchemeTag, VerifyingKey)` strategy, handy when a test needs to store the
/// strategy in a variable of a single concrete type.
pub fn boxed_scheme_and_verifying_key() -> BoxedStrategy<(SchemeTag, VerifyingKey)> {
    scheme_and_verifying_key().boxed()
}
