#![allow(dead_code)]
//! Shared test support for the `gmc-identity` property-based test suite.
//!
//! Rust compiles every file directly under `tests/` as its *own* test binary, so
//! shared helpers cannot live there. Instead they live under `tests/common/` and are
//! pulled into each test binary with `mod common;`. Because any given test binary
//! only uses a subset of the helpers, this module is annotated `#![allow(dead_code)]`
//! to keep the "unused" lint quiet.
//!
//! The reusable proptest [`generators`] live in [`common::generators`]. They produce
//! values built only from the `gmc-identity` public types (task 1.2 — `VerifyingKey`,
//! `SigningKey`, `Signature`, `SchemeTag`, `Nonce`, `DeviceType`) plus a handful of
//! lightweight plain-data request shapes, so the later property-test tasks can map
//! them onto the real identity APIs (`Signature_Scheme`, `Identity_Service`,
//! `Ownership_Registry`, `Device_Registry`, `Recovery_Service`, …) as those land.
//!
//! # Property-test conventions (task 1.3, _Requirements: 1.2_)
//!
//! The design document defines **21 numbered correctness properties** (Property 1–21).
//! Every numbered property MUST be implemented by **exactly one** proptest test, run
//! with **at least 100** random iterations, and labelled with a comment of the form:
//!
//! ```text
//! Feature: gmc-identity, Property N: <property text>
//! ```
//!
//! The 100-iteration floor is set with [`proptest::test_runner::Config`] via
//! `ProptestConfig::with_cases(100)` (use a larger number when desired, never fewer).
//! A complete example of the shape every later property-test task should follow:
//!
//! ```ignore
//! mod common;
//! use common::generators;
//! use proptest::prelude::*;
//!
//! proptest! {
//!     // Run each numbered property with >= 100 random iterations.
//!     #![proptest_config(ProptestConfig::with_cases(100))]
//!
//!     // Feature: gmc-identity, Property 10: 归属树永不成环
//!     #[test]
//!     fn property_10_ownership_never_cycles(ops in generators::ownership_sequence(32)) {
//!         // ... drive the ownership registry with `ops` and assert no cycle forms ...
//!         let _ = ops; // placeholder; real assertions arrive in the Property 10 task
//!     }
//! }
//! ```
//!
//! Rules that follow from the conventions above:
//!
//! - **One test per property.** Do not fold two numbered properties into one test, and
//!   do not split one property across several tests.
//! - **Label every property test.** The `Feature: gmc-identity, Property N: ...`
//!   comment sits directly above the `#[test]` fn so the property is traceable to the
//!   design and to its `Validates: Requirements ...` line.
//! - **>= 100 iterations.** Always configure `ProptestConfig::with_cases(>= 100)`.
//! - **Not a property?** Harness/unit/example tests (such as
//!   `tests/generators_smoke.rs`) MUST NOT carry a `Property N` label, so the numbered
//!   set stays unambiguous.

pub mod generators;
