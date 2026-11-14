//! `IdentityId` model, deterministic derivation, and (task 5.2) the canonical
//! string ↔ `FayID` mapping.
//!
//! This module implements the `Identity_Service` derivation core from the design's
//! *Identity_Service* section and the `IdentityId` data model from *Data Models*
//! ("身份标识与身份记录"):
//!
//! - [`IdentityId`] — `scheme_tag` + `key_repr` (the initial `VerifyingKey`'s reversible
//!   canonical encoding). Derives `Ord`/`Hash` so it works as a `BTreeMap`/`BTreeSet`
//!   key throughout the identity layer.
//! - [`derive_identity_id`] — the deterministic, **injective** derivation
//!   `(scheme_tag, VerifyingKey) → IdentityId` (Requirements 2.2, 2.3, 2.4, 2.5).
//!
//! # Why a reversible encoding instead of a hash (design decision 5)
//!
//! Because this layer introduces **no cryptographic dependency**, derivation encodes
//! the verifying-key bytes with a **deterministic, reversible** canonical encoding
//! (RFC 4648 base32, **lowercase, no padding**) rather than hashing them. This makes
//! determinism (Requirement 2.3) and injectivity (Requirement 2.4) hold **by
//! construction** and exactly verifiable: `base32` is a bijection between byte strings
//! and their canonical lowercase no-pad symbol strings, so equal `(tag, vk)` inputs
//! always yield equal ids, and distinct `vk` bytes always yield distinct `key_repr`
//! (hence distinct ids). gmc-node may swap in a hash-based derivation later (injectivity
//! degrading to "overwhelmingly likely"); this pure-logic layer gives the exact
//! guarantee.
//!
//! The [`base32_encode`] / [`base32_decode`] helpers below are small, std-only (no new
//! dependencies). `base32_decode` is **strict / canonical**: it rejects symbols outside
//! the alphabet and rejects non-canonical trailing bits, so `encode`∘`decode` and
//! `decode`∘`encode` round-trip exactly. The reversibility this provides is what
//! task 5.2's `parse_identity_id` will rely on; the canonical-string/`FayID` mapping
//! and parsing themselves are added by task 5.2 in this same file.

use crate::error::{IdentityError, IdentityResult};
use crate::scheme::SchemeRegistry;
use crate::types::{SchemeTag, VerifyingKey};
use gmc_core::types::FayID;

/// A stable identity identifier, deterministically derived once at creation from the
/// scheme tag and the initial verifying key (design *Data Models*: `IdentityId`).
///
/// `key_repr` is the **reversible** canonical encoding (RFC 4648 base32, lowercase, no
/// padding) of the initial `VerifyingKey`'s bytes — not a hash — so the derivation is a
/// deterministic bijection (Requirements 2.3, 2.4). The identifier is **not**
/// re-derived on key rotation/recovery, keeping it stable across the identity's
/// lifetime (design decision 4 / Requirement 11.2).
///
/// Derives `PartialOrd`/`Ord`/`Hash` so it can be used directly as a `BTreeMap` /
/// `BTreeSet` key (e.g. the ownership registry and pocket binding keyed by identity).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityId {
    /// The signature scheme used to derive this identifier (Requirement 2.2).
    scheme_tag: SchemeTag,
    /// The initial verifying key's reversible canonical encoding (base32, lowercase,
    /// no padding) — a deterministic bijection of the key bytes.
    key_repr: String,
}

impl IdentityId {
    /// Builds an `IdentityId` from its parts.
    ///
    /// Most callers should use [`derive_identity_id`] (which validates the scheme and
    /// key format and computes `key_repr`); this low-level constructor exists so the
    /// canonical-string parser (task 5.2) can reassemble an id from validated parts.
    #[inline]
    pub fn new(scheme_tag: SchemeTag, key_repr: impl Into<String>) -> Self {
        IdentityId {
            scheme_tag,
            key_repr: key_repr.into(),
        }
    }

    /// The scheme tag this identifier was derived under (Requirement 2.2).
    #[inline]
    pub fn scheme_tag(&self) -> &SchemeTag {
        &self.scheme_tag
    }

    /// The reversible canonical encoding of the initial verifying key's bytes.
    #[inline]
    pub fn key_repr(&self) -> &str {
        &self.key_repr
    }

    /// The canonical string form of this identifier (design *Identity_Service*:
    /// `canonical`), `"fay1." + scheme_tag + "." + key_repr` (e.g.
    /// `fay1.ed25519.nb2hi4...`).
    ///
    /// This string is, by construction, a valid `gmc-core` [`FayID`] value
    /// (Requirements 3.1, 3.2): `FayID::new` accepts any string. The form is also the
    /// exact input [`parse_identity_id`] expects, giving the round-trip guarantees of
    /// Requirement 3.3 (`parse(canonical(id)) == id` and `canonical(parse(s)) == s`).
    #[inline]
    pub fn canonical(&self) -> String {
        format!(
            "{}{}{}{}{}",
            CANONICAL_PREFIX, CANONICAL_SEP, self.scheme_tag, CANONICAL_SEP, self.key_repr
        )
    }

    /// Maps this identifier to its `gmc-core` [`FayID`] (design *Identity_Service*:
    /// `toFayId`), `FayID::new(self.canonical())`.
    ///
    /// The binding to `gmc-core` is intentionally narrow: this layer depends **only** on
    /// `FayID`'s string contract (`FayID::new` / `FayID::as_str`, Requirement 3.4), so
    /// `to_fay_id(id).as_str() == id.canonical()` (Property 2) and the existing
    /// `MeritPocket` binding keyed by `FayID` needs no change to `gmc-core`.
    #[inline]
    pub fn to_fay_id(&self) -> FayID {
        FayID::new(self.canonical())
    }
}

/// The fixed prefix every canonical `IdentityId` string carries (`fay1`).
const CANONICAL_PREFIX: &str = "fay1";

/// The single-character separator between the canonical string's three segments.
const CANONICAL_SEP: char = '.';

/// Parses a canonical `IdentityId` string back into an [`IdentityId`] (design
/// *Identity_Service*: `parseIdentityId`).
///
/// A string is accepted **iff** it has exactly the form `fay1.<tag>.<key_repr>` where:
///
/// 1. the literal prefix is `fay1`;
/// 2. `<tag>` is a scheme **registered** in `registry`; and
/// 3. `<key_repr>` is a **non-empty** valid lowercase no-pad base32 string (validated
///    with [`base32_decode`]).
///
/// The non-empty requirement on `<key_repr>` matters because `base32_decode("")` is a
/// canonical success (the empty string decodes to zero bytes): without it a trailing-dot
/// string such as `fay1.ed25519.` would parse to an id with an empty `key_repr`. But this
/// layer only ever serializes ids whose `key_repr` is the base32 encoding of a *validated*
/// (non-empty) verifying key, which is always non-empty — so an empty `key_repr` is not a
/// string this layer could have produced and is rejected as malformed.
///
/// The string is split into **exactly three** segments on its first two `.`
/// separators (`splitn(3, '.')`). Because registered scheme tags carry no dots and the
/// base32 alphabet excludes `.`, any stray dot lands inside `<key_repr>` and is
/// rejected by `base32_decode` as a non-alphabet symbol — so "extra dots" need no
/// special-casing.
///
/// Every rejection path — wrong/missing prefix, a missing segment, an unregistered (or
/// unknown-form) scheme tag, or an illegal `key_repr` — returns
/// [`IdentityError::IdentityIdFormatInvalid`] and produces **no** identity record
/// (Requirement 3.5 / Property 3). Per the design, an unknown scheme *tag* encountered
/// while parsing a candidate id string is treated as a malformed identity string
/// (`IdentityIdFormatInvalid`), **not** `SchemeUnsupported`: parsing only decides
/// whether `s` is a well-formed id of this layer, and a `fay1.<unknown>.<...>` string is
/// simply not one this layer could have produced.
///
/// Round-trip (Requirement 3.3): for any [`IdentityId`] `id` derived under a scheme in
/// `registry`, `parse_identity_id(registry, &id.canonical()) == Ok(id)`; and for any
/// string `s` this function accepts, `parse_identity_id(registry, s)?.canonical() == s`.
pub fn parse_identity_id(registry: &SchemeRegistry, s: &str) -> IdentityResult<IdentityId> {
    // Split into exactly three segments on the first two '.' separators.
    let mut parts = s.splitn(3, CANONICAL_SEP);
    let prefix = parts.next().ok_or(IdentityError::IdentityIdFormatInvalid)?;
    let tag_str = parts.next().ok_or(IdentityError::IdentityIdFormatInvalid)?;
    let key_repr = parts.next().ok_or(IdentityError::IdentityIdFormatInvalid)?;

    // (1) Literal prefix must be exactly "fay1".
    if prefix != CANONICAL_PREFIX {
        return Err(IdentityError::IdentityIdFormatInvalid);
    }

    // (2) Scheme tag must be registered. An unknown-form tag makes `s` a string this
    // layer could not have serialized → IdentityIdFormatInvalid (NOT SchemeUnsupported).
    let tag = SchemeTag::new(tag_str);
    if !registry.contains(&tag) {
        return Err(IdentityError::IdentityIdFormatInvalid);
    }

    // (3) key_repr must be a NON-EMPTY, valid lowercase no-pad base32 string.
    //
    // The empty segment must be rejected explicitly: `base32_decode("")` is a canonical
    // success (`Some(vec![])`), so without this guard a trailing-dot string such as
    // `fay1.ed25519.` would parse to an id with an empty `key_repr`. But this layer never
    // derives such an id — `derive_identity_id` encodes a *validated* verifying key, and a
    // non-empty key always base32-encodes to a non-empty string — so an empty `key_repr` is
    // not a serialization this layer could have produced and is malformed
    // (Requirement 3.5 / Property 3). This does not affect the round-trip guarantee:
    // `canonical(id)` for any derived id always carries a non-empty `key_repr`.
    if key_repr.is_empty() || base32_decode(key_repr).is_none() {
        return Err(IdentityError::IdentityIdFormatInvalid);
    }

    Ok(IdentityId::new(tag, key_repr))
}

/// Deterministically derives an [`IdentityId`] from a scheme tag and a verifying key
/// (design *Identity_Service*: `deriveIdentityId`).
///
/// The algorithm follows the design's fixed order, failing fast at the first violated
/// precondition with **no** value produced:
///
/// 1. `registry.resolve(tag)` — an unregistered tag is rejected with
///    [`IdentityError::SchemeUnsupported`] (Requirement 1.4 / 2.x precondition).
/// 2. `descriptor.validate_verifying_key(vk.as_bytes())` — key bytes that violate the
///    scheme's `ByteFormat` are rejected with [`IdentityError::KeyFormatInvalid`]
///    (Requirements 1.5, 2.5).
/// 3. Encode the verifying-key bytes with the reversible canonical encoding
///    ([`base32_encode`]) into `key_repr`.
///
/// Because step 3 is a deterministic bijection of the key bytes, equal `(tag, vk)`
/// inputs always derive the **same** id (Requirements 2.2, 2.3) and distinct `vk` bytes
/// always derive **distinct** ids (Requirement 2.4) — by construction.
pub fn derive_identity_id(
    registry: &SchemeRegistry,
    tag: &SchemeTag,
    vk: &VerifyingKey,
) -> IdentityResult<IdentityId> {
    // (1) Unregistered scheme → SchemeUnsupported (no value produced).
    let descriptor = registry.resolve(tag)?;
    // (2) Malformed verifying-key bytes → KeyFormatInvalid (no value produced).
    descriptor.validate_verifying_key(vk.as_bytes())?;
    // (3) Reversible, deterministic canonical encoding of the key bytes.
    let key_repr = base32_encode(vk.as_bytes());
    Ok(IdentityId::new(tag.clone(), key_repr))
}

/// RFC 4648 base32 alphabet, **lowercase** (`a`–`z` = 0–25, `2`–`7` = 26–31).
///
/// Lowercase + no padding is the canonical `key_repr` form used by [`IdentityId`].
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes bytes as a lowercase, **unpadded** RFC 4648 base32 string (deterministic,
/// reversible — see [`base32_decode`]).
///
/// Bits are consumed most-significant-first in 5-bit groups; a final partial group is
/// left-padded with zero bits to form one last symbol (standard no-pad base32). The
/// empty input maps to the empty string.
pub(crate) fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    // `buffer` holds at most the leftover (< 5) low bits between iterations, so a u32
    // accumulator (≤ 12 bits in use) never overflows.
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
        // Keep only the leftover low bits so the accumulator stays small.
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        // Left-pad the final partial group with zero bits to make one last symbol.
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

/// Decodes a lowercase, unpadded RFC 4648 base32 string back to bytes (strict /
/// canonical inverse of [`base32_encode`]).
///
/// Returns `None` for any non-canonical input:
/// - a symbol outside the lowercase base32 alphabet (`a`–`z`, `2`–`7`);
/// - a stray trailing symbol that cannot be part of a valid encoding (≥ 5 leftover
///   bits); or
/// - non-zero trailing pad bits (an encoding that `base32_encode` would never produce).
///
/// This strictness guarantees exact round-trips in both directions:
/// `base32_decode(base32_encode(x)) == Some(x)` for all `x`, and
/// `base32_encode(base32_decode(s).unwrap()) == s` for every canonical `s`.
pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let val: u32 = match c {
            b'a'..=b'z' => (c - b'a') as u32,
            b'2'..=b'7' => (c - b'2') as u32 + 26,
            _ => return None, // symbol outside the lowercase base32 alphabet
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // A canonical no-pad encoding leaves < 5 trailing bits, all zero.
    if bits >= 5 || buffer != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::SchemeDescriptor;
    use std::collections::BTreeMap;

    /// A valid 32-byte ed25519 verifying key whose bytes vary with `seed`.
    fn vk(seed: u8) -> VerifyingKey {
        let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        VerifyingKey::new(bytes)
    }

    // --- derive_identity_id: success, determinism, injectivity ------------

    #[test]
    fn derive_records_scheme_tag_and_reversible_key_repr() {
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();
        let key = vk(0);

        let id = derive_identity_id(&registry, &tag, &key).expect("valid ed25519 vk");
        assert_eq!(id.scheme_tag(), &tag);
        // key_repr is the reversible base32 encoding of the exact key bytes.
        assert_eq!(base32_decode(id.key_repr()), Some(key.as_bytes().to_vec()));
    }

    #[test]
    fn derive_is_deterministic_for_same_tag_and_vk() {
        // Requirement 2.3: same (tag, vk) → same IdentityId, across independent registries.
        let registry_a = SchemeRegistry::default();
        let registry_b = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();
        let key = vk(42);

        let id1 = derive_identity_id(&registry_a, &tag, &key).unwrap();
        let id2 = derive_identity_id(&registry_b, &tag, &key).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_is_injective_for_distinct_vks() {
        // Requirement 2.4: two distinct VerifyingKeys → two distinct IdentityIds.
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();

        let id_a = derive_identity_id(&registry, &tag, &vk(1)).unwrap();
        let id_b = derive_identity_id(&registry, &tag, &vk(2)).unwrap();
        assert_ne!(id_a, id_b);
        assert_ne!(id_a.key_repr(), id_b.key_repr());
    }

    #[test]
    fn derived_ids_usable_as_btreemap_key() {
        // The Ord/Hash derives must let IdentityId index ordered maps (ownership/pocket).
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();
        let mut map: BTreeMap<IdentityId, u8> = BTreeMap::new();
        let id_a = derive_identity_id(&registry, &tag, &vk(1)).unwrap();
        let id_b = derive_identity_id(&registry, &tag, &vk(2)).unwrap();
        map.insert(id_a.clone(), 1);
        map.insert(id_b.clone(), 2);
        map.insert(id_a.clone(), 9); // overwrite, distinct key count unchanged
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&id_a), Some(&9));
        assert_eq!(map.get(&id_b), Some(&2));
    }

    // --- derive_identity_id: rejection paths ------------------------------

    #[test]
    fn derive_unregistered_scheme_is_rejected() {
        // Requirement 1.4: unregistered scheme tag → SchemeUnsupported, no id produced.
        let registry = SchemeRegistry::default();
        let unknown = SchemeTag::new("does-not-exist");
        assert_eq!(
            derive_identity_id(&registry, &unknown, &vk(0)),
            Err(IdentityError::SchemeUnsupported)
        );
        // An empty registry rejects even ed25519.
        assert_eq!(
            derive_identity_id(&SchemeRegistry::empty(), &SchemeTag::ed25519(), &vk(0)),
            Err(IdentityError::SchemeUnsupported)
        );
    }

    #[test]
    fn derive_malformed_vk_is_rejected() {
        // Requirements 1.5, 2.5: vk bytes violating the scheme's ByteFormat →
        // KeyFormatInvalid, no id produced. ed25519 requires exactly 32 bytes.
        let registry = SchemeRegistry::default();
        let tag = SchemeTag::ed25519();
        assert_eq!(
            derive_identity_id(&registry, &tag, &VerifyingKey::new(vec![0u8; 31])),
            Err(IdentityError::KeyFormatInvalid)
        );
        assert_eq!(
            derive_identity_id(&registry, &tag, &VerifyingKey::new(vec![0u8; 33])),
            Err(IdentityError::KeyFormatInvalid)
        );
        assert_eq!(
            derive_identity_id(&registry, &tag, &VerifyingKey::new(Vec::new())),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    #[test]
    fn derive_checks_scheme_before_key_format() {
        // An unregistered tag is rejected as SchemeUnsupported even when the vk bytes
        // are also malformed (fixed order: resolve → validate).
        let registry = SchemeRegistry::default();
        assert_eq!(
            derive_identity_id(&registry, &SchemeTag::new("nope"), &VerifyingKey::new(vec![0u8; 7])),
            Err(IdentityError::SchemeUnsupported)
        );
    }

    #[test]
    fn derive_respects_custom_scheme_format() {
        // A custom scheme with a different vk length is validated against its own format.
        let mut registry = SchemeRegistry::empty();
        let tag = SchemeTag::new("vk8");
        registry
            .register(SchemeDescriptor::new(
                tag.clone(),
                crate::scheme::ByteFormat::exact(8),
                crate::scheme::ByteFormat::exact(8),
                crate::scheme::ByteFormat::exact(16),
            ))
            .expect("fresh registry");

        // 8 bytes accepted, 32 bytes (ed25519-sized) rejected under this scheme.
        let id = derive_identity_id(&registry, &tag, &VerifyingKey::new(vec![9u8; 8])).unwrap();
        assert_eq!(base32_decode(id.key_repr()), Some(vec![9u8; 8]));
        assert_eq!(
            derive_identity_id(&registry, &tag, &VerifyingKey::new(vec![9u8; 32])),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    // --- base32 encode/decode round-trip & vectors ------------------------

    #[test]
    fn base32_round_trips_for_many_lengths() {
        for len in 0usize..40 {
            let data: Vec<u8> = (0..len as u16).map(|i| (i.wrapping_mul(31) % 256) as u8).collect();
            let encoded = base32_encode(&data);
            assert_eq!(base32_decode(&encoded), Some(data.clone()), "len = {len}");
            // Canonical: re-encoding the decoded bytes yields the identical string.
            assert_eq!(base32_encode(&base32_decode(&encoded).unwrap()), encoded);
        }
    }

    #[test]
    fn base32_empty_input_is_empty_string() {
        assert_eq!(base32_encode(&[]), "");
        assert_eq!(base32_decode(""), Some(Vec::new()));
    }

    #[test]
    fn base32_matches_rfc4648_lowercase_vector() {
        // RFC 4648 test vector: base32("foobar") == "MZXW6YTBOI"; lowercased here.
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_decode("mzxw6ytboi"), Some(b"foobar".to_vec()));
        // A couple more standard vectors.
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
    }

    #[test]
    fn base32_decode_rejects_invalid_strings() {
        // Symbols outside the lowercase a-z2-7 alphabet are rejected.
        assert_eq!(base32_decode("MZXW6YTBOI"), None); // uppercase not in alphabet
        assert_eq!(base32_decode("01889"), None); // '0','1','8','9' not in alphabet
        assert_eq!(base32_decode("abc!"), None);
        // A lone trailing symbol carries 5 stray bits that no encoding produces.
        assert_eq!(base32_decode("a"), None);
        // Non-zero trailing pad bits are non-canonical: 'm' (12=01100) + 'b' (1=00001)
        // → 10 bits = one byte plus 2 leftover bits equal to 0b01 ≠ 0, so it is rejected.
        assert_eq!(base32_decode("mb"), None);
    }

    // --- task 5.2: canonical / to_fay_id / parse_identity_id ---------------

    /// Derives a valid ed25519 id under the default registry for the given seed.
    fn id(seed: u8) -> IdentityId {
        derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk(seed)).unwrap()
    }

    #[test]
    fn canonical_has_fay1_tag_key_shape() {
        // canonical(id) == "fay1." + scheme_tag + "." + key_repr (design Identity_Service).
        let identity = id(0);
        let canon = identity.canonical();
        let expected = format!("fay1.{}.{}", identity.scheme_tag(), identity.key_repr());
        assert_eq!(canon, expected);
        assert!(canon.starts_with("fay1.ed25519."));
        // Exactly three dot-separated segments (tag/base32 carry no dots).
        assert_eq!(canon.split('.').count(), 3);
    }

    #[test]
    fn to_fay_id_round_trips_through_fayid_string_contract() {
        // Property 2: to_fay_id(id).as_str() == canonical(id); relies only on FayID's
        // string contract (FayID::new + as_str).
        let identity = id(7);
        let fay = identity.to_fay_id();
        assert_eq!(fay.as_str(), identity.canonical());
        // Reconstructing a FayID from the canonical string yields the same value.
        assert_eq!(fay, FayID::new(identity.canonical()));
    }

    #[test]
    fn parse_round_trips_canonical_for_derived_ids() {
        // Property 2 / Requirement 3.3: parse(canonical(id)) == id for many ids.
        let registry = SchemeRegistry::default();
        for seed in 0u8..20 {
            let identity = id(seed);
            let parsed = parse_identity_id(&registry, &identity.canonical()).unwrap();
            assert_eq!(parsed, identity);
        }
    }

    #[test]
    fn canonical_round_trips_parse_for_valid_strings() {
        // Property 2 / Requirement 3.3: canonical(parse(s)) == s for valid s.
        let registry = SchemeRegistry::default();
        for seed in 0u8..20 {
            let s = id(seed).canonical();
            let reserialized = parse_identity_id(&registry, &s).unwrap().canonical();
            assert_eq!(reserialized, s);
        }
    }

    #[test]
    fn parse_accepts_registered_custom_scheme_tag() {
        // The tag must be registered in the supplied registry, not hard-coded to ed25519.
        let mut registry = SchemeRegistry::empty();
        let tag = SchemeTag::new("vk8");
        registry
            .register(SchemeDescriptor::new(
                tag.clone(),
                crate::scheme::ByteFormat::exact(8),
                crate::scheme::ByteFormat::exact(8),
                crate::scheme::ByteFormat::exact(16),
            ))
            .expect("fresh registry");
        let identity =
            derive_identity_id(&registry, &tag, &VerifyingKey::new(vec![3u8; 8])).unwrap();
        let parsed = parse_identity_id(&registry, &identity.canonical()).unwrap();
        assert_eq!(parsed, identity);
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        // Requirement 3.5 / Property 3: a non-"fay1" prefix → IdentityIdFormatInvalid.
        let registry = SchemeRegistry::default();
        let key_repr = id(0).key_repr().to_owned();
        assert_eq!(
            parse_identity_id(&registry, &format!("fay2.ed25519.{key_repr}")),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
        assert_eq!(
            parse_identity_id(&registry, &format!("xfay1.ed25519.{key_repr}")),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
        assert_eq!(
            parse_identity_id(&registry, &format!("FAY1.ed25519.{key_repr}")),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
    }

    #[test]
    fn parse_rejects_unregistered_scheme_tag_as_format_invalid() {
        // Per design: an unknown scheme tag encountered while PARSING a candidate id
        // string is treated as a malformed identity string (IdentityIdFormatInvalid),
        // NOT SchemeUnsupported (Property 3 / Requirement 3.5).
        let registry = SchemeRegistry::default(); // contains only ed25519
        let key_repr = id(0).key_repr().to_owned();
        assert_eq!(
            parse_identity_id(&registry, &format!("fay1.p256.{key_repr}")),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
        // Even ed25519 is "unknown form" against an empty registry.
        assert_eq!(
            parse_identity_id(&SchemeRegistry::empty(), &format!("fay1.ed25519.{key_repr}")),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
    }

    #[test]
    fn parse_rejects_missing_segments() {
        // Requirement 3.5 / Property 3: fewer than three segments → format invalid.
        let registry = SchemeRegistry::default();
        let key_repr = id(0).key_repr().to_owned();
        for bad in [
            String::from("fay1"),                       // prefix only
            String::from("fay1.ed25519"),               // missing key_repr segment
            format!("ed25519.{key_repr}"),              // missing prefix segment
            String::new(),                              // empty string
        ] {
            assert_eq!(
                parse_identity_id(&registry, &bad),
                Err(IdentityError::IdentityIdFormatInvalid),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_empty_key_repr_trailing_dot() {
        // Requirement 3.5 / Property 3: a canonical-shaped string whose key_repr segment
        // is empty (e.g. a trailing dot) must be rejected. base32_decode("") succeeds with
        // zero bytes, but this layer never derives an id with an empty key_repr (a validated
        // verifying key always base32-encodes to a non-empty string), so `fay1.ed25519.` is
        // not a string this layer could have produced.
        let registry = SchemeRegistry::default();
        assert_eq!(
            parse_identity_id(&registry, "fay1.ed25519."),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
        // Same for a registered custom scheme with a trailing (empty) key_repr.
        let mut custom = SchemeRegistry::empty();
        let tag = SchemeTag::new("vk8");
        custom
            .register(SchemeDescriptor::new(
                tag,
                crate::scheme::ByteFormat::exact(8),
                crate::scheme::ByteFormat::exact(8),
                crate::scheme::ByteFormat::exact(16),
            ))
            .expect("fresh registry");
        assert_eq!(
            parse_identity_id(&custom, "fay1.vk8."),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
    }

    #[test]
    fn parse_rejects_illegal_key_repr() {
        // Requirement 3.5 / Property 3: a key_repr that is not valid base32 → invalid.
        let registry = SchemeRegistry::default();
        // Uppercase symbols are outside the lowercase base32 alphabet.
        assert_eq!(
            parse_identity_id(&registry, "fay1.ed25519.MZXW6YTBOI"),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
        // '0','1','8','9' are not in the alphabet.
        assert_eq!(
            parse_identity_id(&registry, "fay1.ed25519.01889"),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
        // An extra dot lands inside key_repr ('.' is not an alphabet symbol) → rejected,
        // confirming the splitn(3) + base32 strategy needs no special-casing for dots.
        let key_repr = id(0).key_repr().to_owned();
        let mid = key_repr.len() / 2;
        let dotted = format!("{}.{}", &key_repr[..mid], &key_repr[mid..]);
        assert_eq!(
            parse_identity_id(&registry, &format!("fay1.ed25519.{dotted}")),
            Err(IdentityError::IdentityIdFormatInvalid)
        );
    }
}
