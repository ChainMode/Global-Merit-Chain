//! Property 10 — 归属树永不成环 (the ownership tree never forms a cycle).
//!
//! Design *Ownership_Registry* / Property 10: 归属树永不成环.
//! Validates Requirements 6.5.
//!
//! Full statement: 对任意包含挂接与重挂接(re-parent)操作的请求序列，归属注册表在任意
//! 时刻都不存在环路；任何会形成环路的请求都被拒绝、返回 `OwnershipCycle`，且被拒后归属
//! 记录保持不变.
//!
//! This drives the public [`OwnershipRegistry`] API with a generated sequence of
//! attach / re-parent requests. Both [`OwnershipOp::Attach`] and
//! [`OwnershipOp::Reparent`] map onto [`OwnershipRegistry::attach`] — re-parent is just
//! an `attach` whose `cofay` already exists (the owner-pointer change the cycle guard
//! must reject). The label pool (`id-0`..`id-23`) is small, so self-parent,
//! unknown-owner, cycle and deep-chain situations all arise naturally.
//!
//! ## Registration policy
//!
//! `attach` requires the owner to already exist and roots must be registered first, so
//! the driver adopts one simple, consistent policy: the first time a label is used as
//! an **owner** and is not yet present, it is registered as a **root**
//! ([`OwnershipRegistry::register_root`]). Every operation is then an
//! `attach(cofay, owner)` whose result is `Ok` or one of the documented rejections
//! (`OwnerNotFound` / `OwnershipCycle` / `OwnershipDepthExceeded`).
//!
//! ## What is asserted
//!
//! 1. **No cycle at any moment.** After every operation, an independent oracle walks
//!    every node's `owner_of` pointers upward; the walk must terminate at a root
//!    without ever revisiting its starting id (no node is its own ancestor).
//! 2. **Cycle-forming requests are rejected with state unchanged.** Whenever
//!    [`OwnershipRegistry::would_cycle`] flags a request as cycle-forming, `attach` must
//!    return `Err(OwnershipCycle)` and leave that `cofay`'s record
//!    (`owner_of` / `path_of` / `depth_of` / presence) byte-for-byte unchanged.

mod common;

use std::collections::HashMap;

use common::generators::{self, OwnershipOp};
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

/// Maps a label string to a **distinct, deterministic** [`IdentityId`].
///
/// A 32-byte ed25519 verifying key is built from the label so the derivation is
/// injective for the label pool: byte 0 holds the label length and the remaining bytes
/// carry the label's UTF-8 (zero-padded). Distinct labels (different content and/or
/// length, all ≤ 31 bytes here) therefore yield distinct keys, hence distinct
/// `IdentityId`s under the default `ed25519` scheme.
fn id_for_label(label: &str) -> IdentityId {
    let label_bytes = label.as_bytes();
    let mut key_bytes = vec![0u8; 32];
    key_bytes[0] = label_bytes.len() as u8;
    for (i, &b) in label_bytes.iter().take(31).enumerate() {
        key_bytes[i + 1] = b;
    }
    let vk = VerifyingKey::new(key_bytes);
    derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk)
        .expect("a 32-byte vk derives an IdentityId under the default ed25519 scheme")
}

/// Extracts the `(cofay, owner)` labels from either operation shape. Both `Attach` and
/// `Reparent` are driven through `attach`; the latter simply names an existing `cofay`.
fn op_labels(op: &OwnershipOp) -> (&str, &str) {
    match op {
        OwnershipOp::Attach { cofay, owner } => (cofay, owner),
        OwnershipOp::Reparent { cofay, new_owner } => (cofay, new_owner),
    }
}

/// Independent acyclicity oracle over the **actual** owner-pointer graph.
///
/// For every registered node it follows `owner_of` upward, bounded by `len() + 1`
/// steps. The registry is acyclic iff every such walk terminates at a root
/// (`owner_of == None`) without revisiting its starting id. Revisiting the start means
/// the start is its own ancestor (a cycle); exceeding the step bound means an
/// undetected loop somewhere along the chain.
fn registry_is_acyclic(registry: &OwnershipRegistry) -> bool {
    let step_limit = registry.len() + 1;
    for node in registry.iter() {
        let start = node.id().clone();
        let mut cursor = start.clone();
        let mut steps = 0usize;
        loop {
            match registry.owner_of(&cursor) {
                // Reached a root: this walk terminates cleanly.
                None => break,
                Some(owner) => {
                    if *owner == start {
                        // Walked back to the starting id => it is its own ancestor.
                        return false;
                    }
                    steps += 1;
                    if steps > step_limit {
                        // Took more steps than there are nodes => an undetected loop.
                        return false;
                    }
                    cursor = owner.clone();
                }
            }
        }
    }
    true
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 10: 归属树永不成环
    #[test]
    fn property_10_ownership_never_cycles(
        ops in generators::ownership_sequence(32),
    ) {
        let mut registry = OwnershipRegistry::new();
        // Lazily-built label -> IdentityId cache (deterministic derivation).
        let mut ids: HashMap<String, IdentityId> = HashMap::new();
        let resolve = |label: &str, ids: &mut HashMap<String, IdentityId>| -> IdentityId {
            ids.entry(label.to_owned())
                .or_insert_with(|| id_for_label(label))
                .clone()
        };

        // The empty registry is trivially acyclic before any operation.
        prop_assert!(registry_is_acyclic(&registry), "empty registry must be acyclic");

        for (seq, op) in ops.iter().enumerate() {
            let (cofay_label, owner_label) = op_labels(op);
            let cofay_id = resolve(cofay_label, &mut ids);
            let owner_id = resolve(owner_label, &mut ids);

            // Registration policy: an owner not yet present enters the tree as a root,
            // so `attach` never trivially fails with OwnerNotFound for a fresh owner.
            if !registry.contains(&owner_id) {
                prop_assert_eq!(registry.register_root(&owner_id), Ok(()));
            }

            // Snapshot the cofay's record BEFORE the attach so a rejection can be shown
            // to leave it unchanged.
            let contained_before = registry.contains(&cofay_id);
            let owner_before = registry.owner_of(&cofay_id).cloned();
            let path_before = registry.path_of(&cofay_id).cloned();
            let depth_before = registry.depth_of(&cofay_id);

            // Identify whether this request forms a cycle, then attempt it.
            let cycle_expected = registry.would_cycle(&cofay_id, &owner_id);
            let result = registry.attach(&cofay_id, &owner_id);

            if cycle_expected {
                // A cycle-forming request is rejected with OwnershipCycle ...
                prop_assert_eq!(
                    result.as_ref().err(),
                    Some(&IdentityError::OwnershipCycle),
                    "would_cycle request must be rejected with OwnershipCycle (op #{}: {:?})",
                    seq,
                    op
                );
                // ... and the cofay's ownership record is left exactly as it was.
                prop_assert_eq!(
                    registry.contains(&cofay_id),
                    contained_before,
                    "rejected request must not change cofay presence (op #{})",
                    seq
                );
                prop_assert_eq!(
                    registry.owner_of(&cofay_id).cloned(),
                    owner_before,
                    "rejected request must not change owner_of(cofay) (op #{})",
                    seq
                );
                prop_assert_eq!(
                    registry.path_of(&cofay_id).cloned(),
                    path_before,
                    "rejected request must not change path_of(cofay) (op #{})",
                    seq
                );
                prop_assert_eq!(
                    registry.depth_of(&cofay_id),
                    depth_before,
                    "rejected request must not change depth_of(cofay) (op #{})",
                    seq
                );
            } else if let Err(err) = result {
                // Any other rejection must be one of the documented ownership errors.
                prop_assert!(
                    matches!(
                        err,
                        IdentityError::OwnerNotFound | IdentityError::OwnershipDepthExceeded
                    ),
                    "unexpected error {:?} for a non-cycle request (op #{}: {:?})",
                    err,
                    seq,
                    op
                );
            }

            // The core invariant: regardless of accept/reject, the ownership tree must
            // never contain a cycle at any point in time (Requirement 6.5).
            prop_assert!(
                registry_is_acyclic(&registry),
                "ownership tree must remain acyclic after every operation (op #{}: {:?})",
                seq,
                op
            );
        }
    }
}
