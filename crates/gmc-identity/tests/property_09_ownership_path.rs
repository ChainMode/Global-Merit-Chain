//! Property 9 — coFay 归属路径结构与创建守卫.
//!
//! Design *Ownership_Registry* / Property 9: coFay 归属路径结构与创建守卫.
//! Validates Requirements 6.1, 6.2, 6.3, 6.4.
//!
//! 对任意合法的归属挂接序列，coFay 挂接成功时记录的归属路径都满足：以根 iFay 为首
//! (`path[0]` 种类为 iFay)、以该 coFay 自身为末位、相邻元素构成拥有者—被拥有关系，且
//! `len(path) == depth + 1`；当指定拥有者在归属注册表与身份记录中均不存在时，创建被拒绝、
//! 返回 `OwnerNotFound` 且不创建任何 coFay。
//!
//! ## How the sequence is driven (consistent registration policy)
//!
//! The shared [`generators::ownership_sequence`] yields `Attach` / `Reparent` ops over a
//! small label pool (`id-0`..`id-23`). Labels are mapped to real [`IdentityId`]s by
//! deriving a per-label deterministic 32-byte verifying key under the default ed25519
//! scheme — distinct labels therefore yield distinct ids (derivation is injective).
//!
//! Each op is applied with one consistent policy: **an owner that is not yet present is
//! registered as a root iFay the first time it is needed as an owner.** This keeps the
//! `OwnerNotFound` guard out of the sequence (owners always exist) so that the *structure*
//! invariants can be asserted on every successful attach, while the guard itself is driven
//! deterministically below with a fresh, never-registered owner.
//!
//! Re-parents are restricted to **leaf** nodes (a node with no live children is never an
//! ancestor of anyone). The registry deliberately recomputes only the moved node on a
//! re-parent (its doc-documented shallow behaviour, with deep subtree re-derivation
//! deferred to a later task); confining re-parents to leaves keeps every stored path
//! consistent, which is the exact scope of this property's "recorded path" invariants.

mod common;

use common::generators;
use generators::OwnershipOp;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

/// Maps a label to a stable [`IdentityId`] by deriving a per-label deterministic 32-byte
/// verifying key under the default ed25519 scheme.
///
/// The label bytes are written into the front of a zero-padded 32-byte key, so distinct
/// labels produce distinct key bytes and — because derivation is injective — distinct
/// [`IdentityId`]s. Every label used by this test is well under 32 bytes.
fn id_for(label: &str) -> IdentityId {
    let raw = label.as_bytes();
    assert!(raw.len() <= 32, "labels in this test fit in a 32-byte vk");
    let mut vk_bytes = [0u8; 32];
    vk_bytes[..raw.len()].copy_from_slice(raw);
    derive_identity_id(
        &SchemeRegistry::default(),
        &SchemeTag::ed25519(),
        &VerifyingKey::new(vk_bytes.to_vec()),
    )
    .expect("a 32-byte vk under the default ed25519 scheme always derives an id")
}

/// `true` if any registered node currently lists `parent` as its owner (i.e. `parent`
/// has at least one live child and is therefore an internal node, not a leaf).
fn has_live_child(reg: &OwnershipRegistry, parent: &IdentityId) -> bool {
    reg.iter().any(|node| node.owner() == Some(parent))
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 9: coFay 归属路径结构与创建守卫
    #[test]
    fn property_09_cofay_ownership_path_structure_and_creation_guard(
        ops in generators::ownership_sequence(32),
    ) {
        let mut reg = OwnershipRegistry::new();

        for op in &ops {
            let (cofay_label, owner_label) = match op {
                OwnershipOp::Attach { cofay, owner } => (cofay, owner),
                OwnershipOp::Reparent { cofay, new_owner } => (cofay, new_owner),
            };
            let cofay = id_for(cofay_label);
            let owner = id_for(owner_label);

            // Registration policy: register an absent owner as a root iFay the first
            // time it is needed, so an attach in the sequence never hits OwnerNotFound.
            if !reg.contains(&owner) {
                reg.register_root(&owner).expect("register_root always succeeds");
            }

            // Keep re-parents to leaves: skip moving a node that already has a live
            // child. The registry recomputes only the moved node (documented shallow
            // re-parent), so moving an internal node would leave descendant paths stale —
            // out of scope for this property's recorded-path invariants.
            if reg.contains(&cofay) && has_live_child(&reg, &cofay) {
                continue;
            }

            match reg.attach(&cofay, &owner) {
                Ok(path) => {
                    // The recorded path equals the returned path (Requirement 6.2).
                    prop_assert_eq!(reg.path_of(&cofay), Some(&path));

                    // path[0] is the root iFay: a registered, self-sovereign root
                    // (owner None / is_root) — Requirements 6.1, 6.3.
                    let head = &path[0];
                    prop_assert!(reg.contains(head));
                    prop_assert!(
                        reg.node(head).expect("head node is registered").is_root(),
                        "path[0] must be a root iFay"
                    );
                    prop_assert!(reg.owner_of(head).is_none(), "root iFay has no owner");

                    // The path ends with the coFay itself (Requirement 6.2).
                    prop_assert_eq!(path.last(), Some(&cofay));

                    // len(path) == depth + 1 (Requirement 6.2).
                    let depth = reg.depth_of(&cofay).expect("attached node has a depth");
                    prop_assert_eq!(path.len() as u32, depth + 1);

                    // Adjacent elements form an owner -> owned relation (Requirement 6.2):
                    // for each (path[i], path[i+1]), owner_of(path[i+1]) == path[i].
                    for pair in path.windows(2) {
                        prop_assert_eq!(reg.owner_of(&pair[1]), Some(&pair[0]));
                    }
                }
                Err(err) => {
                    // The owner was ensured present above, so the only legitimate
                    // rejections here are a cycle or a depth-bound violation — never
                    // OwnerNotFound.
                    prop_assert!(
                        err == IdentityError::OwnershipCycle
                            || err == IdentityError::OwnershipDepthExceeded,
                        "attach with a present owner rejected unexpectedly: {err:?}"
                    );
                }
            }
        }

        // --- Creation guard (Requirement 6.4) ---------------------------------------
        // Attaching beneath an owner that exists in neither the ownership registry nor the
        // identity records is rejected with OwnerNotFound and creates no coFay. Driven on a
        // fresh registry with labels outside the generated pool so the owner is guaranteed
        // absent.
        let mut guard_reg = OwnershipRegistry::new();
        let unknown_owner = id_for("owner-not-registered");
        let guarded_cofay = id_for("cofay-guarded");
        prop_assert!(!guard_reg.contains(&unknown_owner));

        let result = guard_reg.attach(&guarded_cofay, &unknown_owner);
        prop_assert_eq!(result, Err(IdentityError::OwnerNotFound));
        // Nothing created: neither the coFay nor the absent owner exist afterwards.
        prop_assert!(!guard_reg.contains(&guarded_cofay));
        prop_assert!(!guard_reg.contains(&unknown_owner));
        prop_assert!(guard_reg.is_empty());
    }
}
