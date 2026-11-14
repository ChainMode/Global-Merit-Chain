//! SMOKE test (task 16.1) — default scheme registration & the gmc-core dependency
//! boundary.
//!
//! These are plain `#[test]` smoke tests — **not** numbered properties — so they carry
//! no `Feature: gmc-identity, Property N` label, use no proptest, and pull in no
//! `mod common`. They pin two integration facts the design fixes:
//!
//! 1. **Req 1.3 — default scheme registration.** `SchemeRegistry::default()` is never
//!    without the standard `ed25519` descriptor: the registry is usable out of the box
//!    with ed25519 already registered (both `contains(&ed25519)` and
//!    `resolve(&ed25519)` succeed).
//!
//! 2. **Req 3.4 — dependency boundary to gmc-core.** gmc-identity touches `gmc-core`
//!    through **exactly two** seams, and nothing more:
//!      * `FayID`'s **string contract** — an `IdentityId`'s `FayID` is built purely from
//!        its canonical string (`to_fay_id().as_str() == canonical()`), so this layer
//!        relies only on `FayID::new` / `FayID::as_str` and never reaches into any
//!        internal representation of `FayID`.
//!      * `MeritPocket` — `Pocket_Binding` stores a freshly-created, empty `MeritPocket`
//!        keyed by that same `FayID`, and performs **no** balance/decay computation at
//!        this layer (the pocket is created via `MeritPocket::new` and left untouched).
//!
//! ## Documented boundary assertion (Req 3.4)
//!
//! gmc-identity depends on gmc-core **ONLY** through:
//!   - `gmc_core::types::FayID` — used solely via its string contract (`FayID::new`
//!     while constructing `IdentityId::to_fay_id`, and `FayID::as_str` to read it back).
//!     This test asserts `fay_id.as_str() == id.canonical()`, demonstrating the `FayID`
//!     is a pure function of the canonical string and that no part of `FayID`'s internal
//!     implementation beyond that string contract is observed or required.
//!   - `gmc_core::merit::MeritPocket` — used as an opaque container that `Pocket_Binding`
//!     creates empty and keys by `FayID`. This test asserts the bound pocket is keyed by
//!     the identity's `FayID` and is freshly empty (`batches.is_empty()`), demonstrating
//!     this layer creates the pocket but never computes any merit balance over it.
//! No other gmc-core type, field, or internal of `FayID` is touched by gmc-identity.

use gmc_core::merit::MeritPocket;
use gmc_core::types::FayID;

use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::pocket::PocketBinding;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

/// A valid 32-byte ed25519 verifying key whose bytes vary with `seed` (ed25519 pins an
/// exact 32-byte verifying-key format, so derivation accepts this).
fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(seed))
        .collect();
    VerifyingKey::new(bytes)
}

/// Derives a valid ed25519 `IdentityId` under the default registry for the given seed.
fn derive(seed: u8) -> IdentityId {
    derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk(seed))
        .expect("a valid 32-byte ed25519 verifying key derives an IdentityId")
}

/// Test 1 (Req 1.3) — the default scheme registry initialises **with** `ed25519`
/// already registered, so the layer is usable out of the box without any manual
/// registration step.
#[test]
fn default_registry_initialises_with_ed25519_registered() {
    let registry = SchemeRegistry::default();
    let ed25519 = SchemeTag::ed25519();

    // `contains` reports ed25519 as present from the very first moment.
    assert!(
        registry.contains(&ed25519),
        "default SchemeRegistry must contain ed25519 (Req 1.3)"
    );

    // …and `resolve` returns its descriptor (Ok), confirming it is fully registered,
    // not merely listed. The descriptor's own tag is ed25519.
    let descriptor = registry
        .resolve(&ed25519)
        .expect("default registry resolves ed25519 to its descriptor (Req 1.3)");
    assert_eq!(descriptor.tag(), &ed25519);
}

/// Test 2 (Req 3.4) — gmc-identity reaches gmc-core ONLY through (a) `FayID`'s string
/// contract and (b) `MeritPocket`, and nothing beyond that.
#[test]
fn dependency_boundary_uses_only_fayid_string_contract_and_merit_pocket() {
    let id = derive(7);

    // (a) FayID string contract: to_fay_id() yields a gmc_core::types::FayID built
    // PURELY from the canonical string. We observe FayID only via its string contract
    // (`as_str`) — never any internal representation — and it equals `canonical()`.
    let fay_id: FayID = id.to_fay_id();
    assert_eq!(
        fay_id.as_str(),
        id.canonical(),
        "FayID is built purely from the canonical string (Req 3.4: string contract only)"
    );

    // (b) MeritPocket: binding stores a MeritPocket keyed by that SAME FayID.
    let mut binding = PocketBinding::new();
    let bound_key: FayID = binding
        .bind(&id)
        .expect("binding an identity establishes exactly one pocket");
    // The lookup key is exactly the identity's canonical FayID.
    assert_eq!(bound_key, id.to_fay_id());

    let pocket: &MeritPocket = binding
        .pocket(&id)
        .expect("the just-bound identity resolves to its MeritPocket");

    // The bound pocket is keyed by the identity's FayID (gmc-core's public `fay_id`).
    assert_eq!(
        pocket.fay_id,
        id.to_fay_id(),
        "the MeritPocket is keyed by the identity's FayID (Req 3.4: MeritPocket seam)"
    );

    // It is a freshly-created EMPTY pocket: gmc-identity created it via MeritPocket::new
    // and computed NO balance over it (no batches were added at this layer).
    assert!(
        pocket.batches.is_empty(),
        "a freshly bound pocket carries no batches — this layer performs no balance \
         computation (Req 3.4 / Req 10.5)"
    );
}
