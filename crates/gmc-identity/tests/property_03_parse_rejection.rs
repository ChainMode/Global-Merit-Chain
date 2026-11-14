//! Property 3 — illegal identity-id string parsing is rejected.
//!
//! Design *Identity_Service* / Property 3: 非法身份标识字符串解析被拒.
//! Validates Requirements 3.5.
//!
//! Statement: for any string that was *not* produced by this layer's serialization
//! (i.e. its shape is not `fay1.<registered scheme>.<legal key_repr>`), parsing it into
//! an `IdentityId` is rejected with [`IdentityError::IdentityIdFormatInvalid`] and **no**
//! identity record is produced.
//!
//! The generator [`generators::illegal_identity_id_string`] yields malformed strings
//! across every non-canonical shape: a missing `fay1.` prefix, a wrong prefix token, an
//! **unregistered** scheme tag (`fay1.unknownscheme.<repr>`), a missing/empty key_repr
//! segment, illegal `key_repr` characters (uppercase + padding), too few dotted
//! segments, and the empty string.
//!
//! Error-variant note for the unregistered-scheme case: per the implementation contract
//! in `identity_id::parse_identity_id` (and its `parse_rejects_unregistered_scheme_tag_
//! as_format_invalid` unit test), an unknown scheme *tag* encountered while **parsing**
//! a candidate id string is treated as a malformed identity string — it returns
//! [`IdentityError::IdentityIdFormatInvalid`], **not** `SchemeUnsupported` (the latter is
//! reserved for *derivation* against an unregistered scheme). Every rejection shape this
//! generator produces therefore contracts to the single variant `IdentityIdFormatInvalid`,
//! which is exactly what this property asserts.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::parse_identity_id;
use gmc_identity::scheme::SchemeRegistry;

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 3: 非法身份标识字符串解析被拒
    #[test]
    fn property_03_parse_rejection(s in generators::illegal_identity_id_string()) {
        // Parse against the default registry (which supports `ed25519`): the only way a
        // string parses is if it is a canonical `fay1.<registered scheme>.<legal repr>`
        // serialization, which the illegal-string generator never produces.
        let registry = SchemeRegistry::default();

        // Every malformed shape is rejected with the single machine-identifiable code
        // IdentityIdFormatInvalid (Requirement 3.5) — including the unregistered-scheme
        // shape, per the parser's contract documented above.
        prop_assert_eq!(
            parse_identity_id(&registry, &s),
            Err(IdentityError::IdentityIdFormatInvalid),
            "expected IdentityIdFormatInvalid for malformed id string {:?}",
            s
        );
    }
}
