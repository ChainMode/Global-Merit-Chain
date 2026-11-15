//! # gmc-core — GMC (Global Merit Chain) pure-logic core
//!
//! `gmc-core` is the deterministic, runtime-agnostic logic core of the GMC protocol.
//! It contains no chain-runtime dependencies so the very same logic can be reused by
//! both a future **Substrate L1 pallet** and a **ZK Rollup L2** implementation. This
//! crate is where the deterministic core logic (derivation-tree invariants, scoring
//! math, quota accounting, the MeriToken decay model, voter selection, etc.) lives,
//! and it is the target of the property-based tests (Property 1–30).
//!
//! ## Canonical tech-stack direction (_Requirements: 5.2_)
//!
//! This Rust workspace (`gmc-core` + `gmc-identity` + `gmc-node`) is the **sole
//! canonical implementation stack** of the GMC protocol, pairing zero-dependency
//! fixed-point (`i128`) domain crates with **[`proptest`]** for property-based
//! verification and `gmc-node` for Ed25519 BFT consensus, persistence, and zero-fee
//! settlement. Earlier exploratory notes mentioning a TypeScript reference model have
//! been retired; downstream SDKs in other languages act solely as client libraries.
//!
//! [`proptest`]: https://docs.rs/proptest
//!
//! ## Module layout
//!
//! Each protocol module has a dedicated home below, enforcing strict zero-runtime-dependency
//! determinism across every scoring, decay, intimacy, governance, and settlement rule.

// --- Shared primitives & error vocabulary (task 1.2) ---

/// Shared primitive types: fixed-point `Decimal`/`Ratio`, `ChainId`/`FayID`/`Timestamp`,
/// and `Dimension`/`DimensionWeights`.
pub mod types;

/// Unified, machine-identifiable error codes (`GmcError`) returned across all modules.
pub mod error;

// --- Protocol module skeleton (placeholders to be implemented by later tasks) ---

/// `Chain_Registry` — derivation tree, lifecycle, and `(parentId, domain)` uniqueness.
pub mod registry;

/// `Evaluation_Mechanism` — per-chain evaluation config and change governance.
pub mod mechanism;

/// Quota & refresh-period accounting (per-chain isolation, one-time vs periodic).
pub mod quota;

/// `Scoring_Engine` — three-dimensional classification, inflation index, weighted sum.
pub mod scoring;

/// MeritPocket / Merit batch model: exponential decay and `minMerit` floor value.
pub mod merit;

/// `Minting_Service` — minting pipeline, quota metering, `minMerit` updates.
pub mod minting;

/// `Registration_Service` — merit registration and grant-trigger guards.
pub mod registration;

/// `Recording_Service` — contribution recording and registration matching.
pub mod recording;

/// `Retroactive_Review_Module` — retroactive declaration intake, evidence checks, voting.
pub mod retroactive;

/// `AntiFraud_Engine` — high-intimacy exclusion, sampling, anomaly detection, clawback.
pub mod antifraud;

/// `Governance_Module` — weighted voting, threshold decisions, proposal handling.
pub mod governance;

/// Carbon-credit → MeriToken application scenario (voucher state, single conversion).
pub mod carbon;

/// `GMC_Base` — root node (depth = 0) and the monetary-exchange rejection choke point.
pub mod gmc_base;

/// `L1_Settlement` — pure-logic model of the Substrate L1 layer: stores registration
/// records, identities, governance vote results, penalties and the state root, and is
/// the concrete home for the modules' L1 anchoring seams (fee-free; GRANDPA/BABE).
pub mod l1_settlement;

/// `L2_Rollup` — pure-logic model of the ZK Rollup L2 layer: high-frequency per-record
/// processing (Req 13.2), the 1,000-record / 60-second batch-proof trigger (Req 13.3),
/// the `submitRollupBatch` L2→L1 seam (Req 9.7), and BFT consensus markers (Req 13.7).
pub mod l2_rollup;

/// Nested merit-chain creation channels (`ChainCreationService`): the three Requirement 2
/// initiation paths — vote-initiated (Req 2.1), steward-initiated (Req 2.2/2.7), and
/// institution-applied (Req 2.3/2.8) — each recording the matching `originType` and
/// surfacing `MissingField` for a missing parent/domain (Req 2.5).
pub mod chain_creation;

/// End-to-end flow wiring (task 20.1): composes the protocol modules into the design's
/// four key flows — chain derivation, register→record→grant, retroactive review/voting,
/// and carbon→MeriToken — joining the cross-module trait seams (`RegistrationLookup`,
/// `GrantContext`, `L1ProofSink`) so no module is left isolated/un-integrated.
pub mod flows;

/// Cold-start decaying initial Merit bootstrap (`B_i = 0` zero floor, faster decay,
/// per-`opaqueRef` caps/cooldowns) and natural-person governance weight normalization.
pub mod bootstrap;

/// Social relationship graph, bilateral interaction anti-farming, deterministic
/// fixed-point decaying intimacy, and 5-tier / `coFay` inheritance (`OQ-P2-GMC-6`, `OQ-P2-GMC-8`).
pub mod relationship;

/// Batch-bound complaints, anti-malicious-complaint screening, `>= 3/4` severity-graded
/// penalties (sole `minMerit` reduction channel), and wider-community appeals (`OQ-P2-GMC-7`).
pub mod penalty;
