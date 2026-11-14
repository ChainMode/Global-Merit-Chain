//! Property 2 — `IdentityId` ↔ `FayID` canonical-mapping round-trip.
//!
//! Design *Identity_Service* / Property 2: IdentityId ↔ FayID 规范映射往返一致.
//! Validates Requirements 3.1, 3.2, 3.3.
//!
//! Full statement: for any `IdentityId`, its canonical string form is a value accepted
//! by gmc-core's `FayID` (`to_fay_id(id).as_str() == canonical(id)`) and
//! `parse_identity_id(canonical(id)) == id`; conversely, for any well-formed canonical
//! string `s`, `canonical(parse_identity_id(s)) == s`.
//!
//! Both directions are checked here against the default [`SchemeRegistry`] (which
//! always supports `ed25519`):
//!
//! - **Forward**: a `(supported tag, valid vk)` pair derives an `IdentityId`; its
//!   `to_fay_id` exposes exactly the canonical string (Req 3.1, 3.2), and re-parsing
//!   that canonical string returns the same id (Req 3.3, parse∘canonical = id).
//! - **Reverse**: a generated canonical `fay1.ed25519.<base32>` string parses
//!   successfully and re-serializes to the identical string (Req 3.3,
//!   canonical∘parse = s).

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::identity_id::{derive_identity_id, parse_identity_id};
use gmc_identity::scheme::SchemeRegistry;

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 2: IdentityId ↔ FayID 规范映射往返一致
    #[test]
    fn property_02_identity_id_fayid_canonical_roundtrip(
        (tag, vk) in generators::scheme_and_verifying_key(),
        s in generators::canonical_identity_id_string(),
    ) {
        let registry = SchemeRegistry::default();

        // --- Forward: IdentityId -> canonical/FayID -> IdentityId ----------------
        // The (supported tag, valid vk) pair must derive an id (Req 3.1 precondition).
        let id = derive_identity_id(&registry, &tag, &vk)
            .expect("supported tag + valid vk derives an IdentityId");

        // to_fay_id exposes EXACTLY the canonical string (Req 3.1, 3.2).
        let canon = id.canonical();
        let fay = id.to_fay_id();
        prop_assert_eq!(fay.as_str(), canon.as_str());

        // parse(canonical(id)) == id (Req 3.3, parse∘canonical = identity).
        prop_assert_eq!(parse_identity_id(&registry, &canon), Ok(id));

        // --- Reverse: canonical string -> IdentityId -> canonical string ---------
        // A well-formed canonical string parses (Req 3.2) ...
        let parsed = parse_identity_id(&registry, &s)
            .expect("a canonical fay1.ed25519.<base32> string must parse");
        // ... and re-serializes to the identical string (Req 3.3, canonical∘parse = s).
        prop_assert_eq!(parsed.canonical(), s);
    }
}
