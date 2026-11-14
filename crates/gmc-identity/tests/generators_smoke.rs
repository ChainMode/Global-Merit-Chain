//! Harness smoke test for the property-based testing infrastructure (task 1.3).
//!
//! This is **NOT** one of the numbered design properties (Property 1–21). It exists
//! only to prove the test harness wiring works end to end:
//!
//! - the shared module include path (`mod common;`) resolves,
//! - the reusable generators in [`common::generators`] produce values, and
//! - the `>= 100` iteration `ProptestConfig` convention compiles and runs.
//!
//! Each numbered property gets its own dedicated test file in a later task, labelled
//! `Feature: gmc-identity, Property N: ...` per the convention in
//! `tests/common/mod.rs`. This smoke test deliberately carries no such label.

mod common;

use common::generators;
use gmc_identity::types::DeviceType;
use proptest::prelude::*;

proptest! {
    // Mirror the >= 100-iteration convention every numbered property test uses.
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// HARNESS SMOKE TEST (not a numbered property): a valid-format verifying key has
    /// exactly the reference byte length, and an invalid-format one does not.
    #[test]
    fn smoke_verifying_key_format_split(
        valid in generators::verifying_key_valid(),
        invalid in generators::verifying_key_invalid(),
    ) {
        prop_assert_eq!(valid.len(), 32);
        prop_assert_ne!(invalid.len(), 32);
    }

    /// HARNESS SMOKE TEST (not a numbered property): two-distinct-key helper never
    /// yields a pair of equal keys (drives derivation injectivity later).
    #[test]
    fn smoke_two_distinct_verifying_keys_differ(
        (a, b) in generators::two_distinct_verifying_keys(),
    ) {
        prop_assert_ne!(a, b);
    }

    /// HARNESS SMOKE TEST (not a numbered property): an ownership op sequence respects
    /// the requested length bound.
    #[test]
    fn smoke_ownership_sequence_respects_length_bound(
        ops in generators::ownership_sequence(16),
    ) {
        prop_assert!(ops.len() <= 16);
    }

    /// HARNESS SMOKE TEST (not a numbered property): a nonce sequence stays within the
    /// requested length bound (its values may regress/duplicate, which is intended).
    #[test]
    fn smoke_nonce_sequence_respects_length_bound(
        nonces in generators::nonce_sequence(12),
    ) {
        prop_assert!(nonces.len() <= 12);
    }

    /// HARNESS SMOKE TEST (not a numbered property): every "known" device-type input is
    /// one of the six prescribed `DeviceType` variants.
    #[test]
    fn smoke_known_device_type_is_in_enum(
        input in generators::device_type_input(),
    ) {
        if let generators::DeviceTypeInput::Known(dt) = input {
            prop_assert!(DeviceType::ALL.contains(&dt));
        }
    }

    /// HARNESS SMOKE TEST (not a numbered property): a guardian config's threshold lies
    /// within the generated `0..=N+2` band (so out-of-range thresholds are exercised).
    #[test]
    fn smoke_guardian_config_threshold_band(
        cfg in generators::guardian_config(),
    ) {
        prop_assert!(cfg.threshold <= cfg.guardians.len() as u32 + 2);
    }
}
