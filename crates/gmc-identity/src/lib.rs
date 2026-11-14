//! # gmc-identity — GMC (Global Merit Chain) identity & account layer
//!
//! `gmc-identity` is the first segment of the Meritora five-stage roadmap
//! (gmc-identity → gmc-node → gmc-api → meritora-sdk → meritora-app). It sits **on top
//! of** the existing pure-logic `gmc-core` library and supplies the identity semantics
//! that `gmc-core` deliberately leaves out: iFay self-sovereign personal identities,
//! coFay collective/organizational identities, keys & signatures, device binding,
//! MeritPocket association, key rotation & social recovery, and the anti-impersonation /
//! anti-abuse constraints that bind them together.
//!
//! ## Scope & dependency posture (task 1.1, _Requirements: 1.2_)
//!
//! gmc-identity shares `gmc-core`'s philosophy — **pure logic, zero runtime
//! dependencies, deterministic, property-testable**:
//!
//! - **No networking, no node, no persistence, no real cryptography**: this layer only
//!   models the identity/account *domain logic*. Concrete cryptographic algorithms
//!   (default **Ed25519**) are deferred to **gmc-node**.
//! - **Scheme-agnostic**: signing keys, verifying keys and signatures are all treated as
//!   opaque byte sequences, validated only against the byte-format constraints declared
//!   by their owning signature scheme. Real algorithms are injected by gmc-node through
//!   the `Signer` / `Verifier` trait seam, against which this layer's property tests are
//!   written so they hold for both the reference and the real implementation.
//! - **Deterministic**: every derivation, authentication and authorization decision is a
//!   pure function — same input, same output — reproducible bit-for-bit on an L1 pallet
//!   and an L2 rollup alike.
//!
//! ## Integration seam with gmc-core (gmc-core is NOT modified)
//!
//! gmc-identity depends on exactly two existing `gmc-core` types and modifies neither
//! contract:
//!
//! | gmc-core type | Usage in gmc-identity |
//! |---------------|-----------------------|
//! | [`FayID`](gmc_core::types::FayID)    | The canonical string form of an `IdentityId` is itself a valid `FayID` value; this layer relies only on `FayID`'s string contract (Req 3.2 / 3.4). |
//! | [`MeritPocket`](gmc_core::merit::MeritPocket) | `Pocket_Binding` maps each `IdentityId` one-to-one to a `MeritPocket` keyed by its `FayID`; this layer never recomputes any balance/decay (Req 10.5). |
//!
//! ## Module layout
//!
//! Each module from the design document has a dedicated home below. They are empty
//! placeholders at this stage (task 1.1, scaffolding only); shared types & the unified
//! error vocabulary (task 1.2) and the property-test generator skeleton (task 1.3) are
//! filled in by later tasks.

// --- Shared primitives & error vocabulary (task 1.2) ---

/// Shared opaque-byte primitives: `VerifyingKey` / `SigningKey` / `Signature`,
/// `SchemeTag`, `Nonce`, `IdentityKind`, `DeviceType` (timestamps reuse `gmc-core`).
pub mod types;

/// Unified, machine-identifiable error codes (`IdentityError`) returned across all
/// modules, mirroring `gmc-core::error::GmcError`'s style.
pub mod error;

// --- Cryptographic primitive seam (scheme-agnostic) ---

/// `Signature_Scheme` — scheme tag, key/signature byte-format constraints, and the
/// scheme registry (Ed25519 registered as the default, algorithm-free).
pub mod scheme;

/// `Signer` / `Verifier` trait seam plus a deterministic, non-secure reference
/// implementation used only to drive the signing domain logic & property tests.
pub mod signer;

// --- Identity core ---

/// `IdentityId` model: deterministic, reversible derivation from `(scheme_tag, vk)` and
/// the canonical string ↔ `FayID` mapping.
pub mod identity_id;

/// `Pocket_Binding` — one-to-one `IdentityId` ↔ `FayID` ↔ `MeritPocket` mapping over
/// `gmc-core::MeritPocket` (no balance/decay computation here).
pub mod pocket;

/// `Identity_Service` — iFay/coFay creation, `IdentityId` derivation, and Pocket binding.
pub mod identity_service;

// --- Relationships & authority ---

/// `Ownership_Registry` — coFay ownership, ordered ownership paths, root-is-iFay,
/// depth ≤ 16 and cycle guards (mirrors `gmc-core`'s derivation-tree guards).
pub mod ownership;

/// `Authority_Resolver` — owner / ancestor / delegate authorization decisions and
/// delegate add/revoke management.
pub mod authority;

/// `Identity_Core` — the single state-mutation entry point: signed-operation
/// authentication, Nonce replay protection and atomic-failure state changes.
pub mod identity_core;

// --- Account association & recovery ---

/// `Device_Registry` — device-credential enrollment, listing and revocation, with
/// `Device_Type` enum validation.
pub mod device;

/// `Recovery_Service` — key rotation and guardian M-of-N social recovery, keeping the
/// `IdentityId` invariant.
pub mod recovery;
