//! Worked EXAMPLE unit tests for the Pocket balance **boundary** (task 6.3). These are
//! plain `#[test]` examples — **not** numbered properties — so they carry no
//! `Feature: gmc-identity, Property N` label and use no proptest.
//!
//! They pin one concrete acceptance criterion of Requirement 10.5 with real values: a
//! freshly bound [`MeritPocket`] carries `gmc-core`'s initial floor `min_merit == E`,
//! and the binding layer (`PocketBinding` / `IdentityService`) performs **no** balance
//! or decay computation of its own — it only ever *creates* an empty pocket via
//! `gmc-core` and stores it. The pocket starts with **zero batches**, so no decay math
//! could have run, and its floor is exactly the documented `gmc-core` constant `E`
//! (`≈ 2.718281`), untouched by this layer.
//!
//! The `E` constant used here is `gmc_core::merit::E` — the value `MeritPocket::new`
//! initialises `min_merit` to (blueprint 4.5, _Requirement 8.2_); this test asserts the
//! identity layer hands that floor through unchanged (_Requirement 10.5_).

use gmc_core::merit::E;
use gmc_core::types::Timestamp;

use gmc_identity::identity_id::derive_identity_id;
use gmc_identity::identity_service::IdentityService;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

/// A valid 32-byte ed25519 verifying key whose bytes vary with `seed` (mirrors the
/// in-crate test helpers so derivation succeeds under the default registry).
fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
    VerifyingKey::new(bytes)
}

/// Req 10.5 — boundary via the real `PocketBinding` getter: binding an identity creates
/// exactly one empty pocket whose floor is `gmc-core`'s `E`. The binding layer runs no
/// balance/decay math, which is demonstrated by the pocket being freshly created with
/// **no batches** — there is nothing for any decay computation to act on, and the floor
/// is the untouched initial constant `E`.
#[test]
fn freshly_bound_pocket_has_min_merit_e_and_no_balance_math() {
    // Bind an identity directly through the Pocket_Binding layer.
    let mut binding = PocketBinding::new();
    let identity = derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk(0))
        .expect("valid ed25519 vk derives an IdentityId");
    binding.bind(&identity).expect("binding has no rejection path");

    // Fetch the freshly bound MeritPocket via the binding's real read accessor.
    let pocket = binding.pocket(&identity).expect("pocket was just bound");

    // The floor is EXACTLY gmc-core's documented initial value E (≈ 2.718281): the
    // binding layer handed it through untouched (Requirement 10.5).
    assert_eq!(pocket.min_merit(), E);
    assert_eq!(pocket.min_merit, E); // same value via the public field

    // The pocket is freshly created with no batches: binding added nothing, so no
    // decay/balance computation could have run at this layer (Requirement 10.5).
    assert!(
        pocket.batches.is_empty(),
        "binding must not create any Merit batch (no balance/decay math at this layer)"
    );

    // The pocket is keyed by the identity's canonical FayID, confirming this is the
    // pocket the binding established for THIS identity.
    assert_eq!(pocket.fay_id, identity.to_fay_id());
}

/// Req 10.5 — boundary via the full `IdentityService::create_ifay` flow: creating an
/// iFay binds a MeritPocket whose floor is `gmc-core`'s `E`, with no batches and hence
/// no balance/decay computation triggered by the identity layer. This exercises the
/// real end-to-end creation path (derive id → ownership root → record → bind pocket)
/// and asserts the same boundary contract on the resulting pocket.
#[test]
fn ifay_creation_binds_pocket_with_min_merit_e_and_no_decay() {
    let registry = SchemeRegistry::default();
    let mut ownership = OwnershipRegistry::new();
    let mut binding = PocketBinding::new();
    let mut svc = IdentityService::new();

    let id = svc
        .create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &SchemeTag::ed25519(),
            &vk(0),
            Timestamp::from_secs(1_700_000_000),
        )
        .expect("valid ed25519 vk");

    // The created iFay's pocket carries the initial floor E, unchanged by this layer.
    let pocket = binding.pocket(&id).expect("create_ifay binds a pocket");
    assert_eq!(pocket.min_merit(), E);

    // Freshly created: no batches ⇒ the identity layer ran no balance/decay math.
    assert!(
        pocket.batches.is_empty(),
        "iFay creation must not populate batches or compute any balance"
    );
    assert_eq!(pocket.fay_id, id.to_fay_id());
}
