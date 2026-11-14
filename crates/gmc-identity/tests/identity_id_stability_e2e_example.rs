//! Worked EXAMPLE end-to-end unit test for the **`IdentityId` stability** invariant
//! across a full *create → rotate → recover* lifecycle (task 14.6). This is a plain
//! `#[test]` example — **not** a numbered property — so it carries no
//! `Feature: gmc-identity, Property N` label and uses no proptest. It complements the
//! universal Properties 17/18 with one concrete, fully wired walkthrough.
//!
//! ## What this pins (Requirement 11.2)
//!
//! Requirement 11.2 says an identity's [`IdentityId`] is **derived once** from the
//! *initial* verifying key and stays **fixed** even as the active key changes under key
//! rotation and guardian social recovery — so the identity's MeritPocket binding
//! (`pocket_key`) and ownership relationship (`owner_of`) are never disturbed by a key
//! change. This test builds the whole chain with concrete deterministic keys and asserts
//! the three id-keyed facts (`id`, `pocket_key(&id)`, `owner_of(&id)`) are **identical**
//! at every step, while the identity's `active_key` walks `key0 → key1 → key2`:
//!
//! 1. **Create** an ed25519 iFay with `key0`; snapshot `id` / `pocket_key` / `owner_of`.
//! 2. **Rotate** the active key `key0 → key1` (self-signed style rotation effect); the
//!    three snapshots must be unchanged and `key0` retired.
//! 3. **Recover** via a 2-of-3 guardian set, rotating `key1 → key2` once the threshold is
//!    met; the three snapshots must *still* be unchanged end-to-end.
//!
//! The rotation history must reflect **both** rotations (`rotation_count == 2`), chaining
//! `key0 → key1` then `key1 → key2`.

use gmc_identity::error::IdentityError;
use gmc_identity::identity_service::IdentityService;
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::pocket::PocketBinding;
use gmc_identity::recovery::RecoveryService;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{IdentityKind, SchemeTag, VerifyingKey};
use gmc_core::types::Timestamp;

/// A valid 32-byte ed25519 verifying key whose bytes vary with `seed` (mirrors the
/// in-crate recovery/identity test helpers so derivation and rotation succeed under the
/// default registry, and distinct seeds give distinct valid keys).
fn vk(seed: u8) -> VerifyingKey {
    let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
    VerifyingKey::new(bytes)
}

/// Full *create → rotate → recover* chain: the `IdentityId`, its `pocket_key` and its
/// `owner_of` are invariant across both an explicit key rotation and a guardian social
/// recovery, even though the active key changes twice (`key0 → key1 → key2`).
/// (_Requirement 11.2_.)
#[test]
fn identity_id_pocket_key_and_owner_are_invariant_across_create_rotate_recover() {
    let registry = SchemeRegistry::default();
    let mut ownership = OwnershipRegistry::new();
    let mut binding = PocketBinding::new();
    let mut svc = IdentityService::new();
    let mut recovery = RecoveryService::new();

    let key0 = vk(0); // initial active key the id is derived from
    let key1 = vk(1); // explicit-rotation target
    let key2 = vk(2); // guardian-recovery target

    // --- (1) CREATE an ed25519 iFay with key0 ------------------------------
    let id = svc
        .create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &SchemeTag::ed25519(),
            &key0,
            Timestamp::from_secs(1_000),
        )
        .expect("valid ed25519 vk");

    // Snapshot the three id-keyed facts that must NEVER change (Requirement 11.2).
    let id_snapshot = id.clone();
    let pocket_key_snapshot = binding.pocket_key(&id);
    let owner_snapshot = ownership.owner_of(&id).cloned();

    // Sanity: the pocket is bound (keyed by the canonical FayID) and the iFay is a
    // self-sovereign root (owner = None) before any key change.
    assert_eq!(pocket_key_snapshot, Some(id.to_fay_id()));
    assert_eq!(owner_snapshot, None);
    assert_eq!(svc.get(&id).unwrap().active_key, key0);
    assert_eq!(svc.get(&id).unwrap().kind, IdentityKind::IFay);

    // --- (2) ROTATE the active key key0 -> key1 ----------------------------
    let rec1 = recovery
        .rotate_key(&mut svc, &registry, &id, &key1, Timestamp::from_secs(2_000))
        .expect("valid new key under the identity's scheme");

    // The active key is now key1 and key0 is retired.
    let identity = svc.get(&id).unwrap();
    assert_eq!(identity.active_key, key1);
    assert_eq!(identity.retired_keys, vec![key0.clone()]);

    // The id-keyed facts are UNCHANGED after the rotation.
    assert_eq!(svc.get(&id).unwrap().id, id_snapshot);
    assert_eq!(binding.pocket_key(&id), pocket_key_snapshot);
    assert_eq!(ownership.owner_of(&id).cloned(), owner_snapshot);

    // --- (3) RECOVER via guardians: configure a 2-of-3 set -----------------
    let guardians = [vk(10), vk(11), vk(12)];
    recovery
        .configure_guardians(&svc, &id, &guardians, 2)
        .expect("2-of-3 is a valid M-of-N config");

    // First guardian approval for key2: below the threshold of 2, so the active key is
    // left UNCHANGED (still key1) and recovery has not happened yet.
    let below = recovery.submit_recovery_approval(
        &mut svc,
        &registry,
        &id,
        &key2,
        &vk(10),
        Timestamp::from_secs(3_000),
    );
    assert_eq!(below, Err(IdentityError::RecoveryThresholdNotMet));
    assert_eq!(svc.get(&id).unwrap().active_key, key1);

    // Second DISTINCT guardian approval for the same key2: the de-duplicated count now
    // reaches the threshold (2), so recovery reuses the rotation effect to swap the
    // active key key1 -> key2.
    let rec2 = recovery
        .submit_recovery_approval(
            &mut svc,
            &registry,
            &id,
            &key2,
            &vk(11),
            Timestamp::from_secs(4_000),
        )
        .expect("threshold reached -> rotation applied");

    // The active key is now key2; key0 and key1 are both retired (in rotation order).
    let identity = svc.get(&id).unwrap();
    assert_eq!(identity.active_key, key2);
    assert_eq!(identity.retired_keys, vec![key0.clone(), key1.clone()]);

    // --- The id-keyed facts are STILL UNCHANGED end-to-end -----------------
    assert_eq!(svc.get(&id).unwrap().id, id_snapshot);
    assert_eq!(binding.pocket_key(&id), pocket_key_snapshot);
    assert_eq!(ownership.owner_of(&id).cloned(), owner_snapshot);
    // The kind and the canonical FayID derived from the (unchanged) id are also stable.
    assert_eq!(svc.get(&id).unwrap().kind, IdentityKind::IFay);
    assert_eq!(binding.pocket_key(&id), Some(id_snapshot.to_fay_id()));

    // --- Rotation history reflects BOTH rotations, chained -----------------
    assert_eq!(recovery.rotation_count(&id), 2);
    assert_eq!(recovery.history_of(&id), &[rec1.clone(), rec2.clone()]);
    // Record 1: key0 -> key1 (the explicit rotation).
    assert_eq!(rec1.old_key, key0);
    assert_eq!(rec1.new_key, key1);
    assert_eq!(rec1.rotated_at, Timestamp::from_secs(2_000));
    // Record 2: key1 -> key2 (the guardian recovery). The chain links: rec1.new == rec2.old.
    assert_eq!(rec2.old_key, key1);
    assert_eq!(rec2.new_key, key2);
    assert_eq!(rec2.rotated_at, Timestamp::from_secs(4_000));
    assert_eq!(rec1.new_key, rec2.old_key);
}

/// Companion example: the same invariant holds when the iFay anchors a coFay beneath it.
/// Rotating the **owner** iFay's active key must not disturb the coFay's ownership
/// relationship (`owner_of(&cofay)` still points at the same, unchanged owner id) nor the
/// owner's own `id` / `pocket_key`. This isolates the "a key change leaves ownership
/// relationships intact" half of Requirement 11.2 on a real two-node tree.
#[test]
fn rotating_owner_key_leaves_cofay_ownership_and_owner_pocket_intact() {
    let registry = SchemeRegistry::default();
    let mut ownership = OwnershipRegistry::new();
    let mut binding = PocketBinding::new();
    let mut svc = IdentityService::new();
    let mut recovery = RecoveryService::new();

    // Create the owner iFay (key0) and a coFay attached beneath it.
    let owner = svc
        .create_ifay(
            &registry,
            &mut ownership,
            &mut binding,
            &SchemeTag::ed25519(),
            &vk(0),
            Timestamp::from_secs(1),
        )
        .expect("valid owner iFay");
    let cofay = svc
        .create_cofay(&registry, &mut ownership, &mut binding, &owner, &vk(5), Timestamp::from_secs(2))
        .expect("owner exists, no cycle, depth ok");

    // Snapshot the owner's id-keyed facts and the coFay's ownership edge.
    let owner_id_snapshot = owner.clone();
    let owner_pocket_snapshot = binding.pocket_key(&owner);
    let cofay_owner_snapshot = ownership.owner_of(&cofay).cloned();
    assert_eq!(cofay_owner_snapshot, Some(owner.clone()));

    // Rotate the OWNER's active key key0 -> key1.
    recovery
        .rotate_key(&mut svc, &registry, &owner, &vk(1), Timestamp::from_secs(3))
        .expect("valid new key");
    assert_eq!(svc.get(&owner).unwrap().active_key, vk(1));

    // The owner's id and pocket key are unchanged, and the coFay still points at the
    // same owner id — the key change disturbed no relationship (Requirement 11.2).
    assert_eq!(svc.get(&owner).unwrap().id, owner_id_snapshot);
    assert_eq!(binding.pocket_key(&owner), owner_pocket_snapshot);
    assert_eq!(ownership.owner_of(&cofay).cloned(), cofay_owner_snapshot);
    assert_eq!(binding.pocket_key(&cofay), Some(cofay.to_fay_id()));
}
