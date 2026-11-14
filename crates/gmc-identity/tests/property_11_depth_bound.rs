//! Property 11 — 归属深度上界 (ownership depth upper bound).
//!
//! Design *Ownership_Registry* / Property 11: 归属深度上界.
//! Validates Requirements 6.6.
//!
//! > 对任意归属挂接请求序列，注册表中每个节点的 `depth` 都不超过 16（以根 iFay 为
//! > depth 0）；任何会使深度超过 16 的请求都被拒绝、返回 `OwnershipDepthExceeded`，
//! > 且被拒后状态保持不变。
//!
//! This single property test drives the depth bound from **two** complementary angles,
//! both in one `#[test]` (per the suite's "one test per numbered property" convention
//! in `tests/common/mod.rs`):
//!
//! 1. A **deliberately-constructed deep chain** that probes the exact boundary. It
//!    registers a root iFay (depth 0) and attaches a straight chain `id_1` under the
//!    root, `id_2` under `id_1`, … up to depth [`MAX_DEPTH`] (16). Every successful
//!    attach has `depth == previous + 1` and `<= 16`; the **first** attach that would
//!    create depth 17 is asserted to return [`IdentityError::OwnershipDepthExceeded`]
//!    and to leave the registry unchanged (the rejected coFay is absent, `len` is
//!    unchanged, and the deepest node stays at depth 16). The `salt` /
//!    `overflow_probes` inputs vary the chain's ids and how many over-depth attaches
//!    are probed, while the boundary assertion (depth 16 ok, 17 rejected) holds for
//!    every generated input.
//!
//! 2. An **arbitrary attach/re-parent request sequence** (`generators::ownership_sequence`)
//!    applied to an independent registry seeded with a few roots — the "对任意归属挂接
//!    请求序列" of the property. After every operation the global invariant is checked:
//!    **every** registered node has `depth <= 16`, and any `OwnershipDepthExceeded`
//!    rejection leaves the registry byte-for-byte unchanged.
//!
//! Ids are derived deterministically from string labels via the real
//! [`derive_identity_id`] under the default ed25519 scheme, with a distinct 32-byte
//! verifying key per label, so distinct labels give distinct ids and the chain forms
//! correctly.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::ownership::{OwnershipNode, OwnershipRegistry, MAX_DEPTH};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

/// Derives a distinct, deterministic [`IdentityId`] from a string `label`.
///
/// The label bytes are copied into the first bytes of a fixed-length 32-byte buffer
/// (the rest left zero), giving a valid ed25519 verifying key. Distinct labels — all
/// short ASCII tokens with no embedded NUL — therefore yield distinct key bytes, and
/// because [`derive_identity_id`] is injective on the key bytes, distinct labels yield
/// distinct ids. Equal labels yield the identical id, so a chain built from positional
/// labels links up correctly.
fn id_from_label(label: &str) -> IdentityId {
    let bytes = label.as_bytes();
    // ed25519 verifying keys are exactly 32 bytes (the default scheme's format).
    let mut key = [0u8; 32];
    let take = bytes.len().min(32);
    key[..take].copy_from_slice(&bytes[..take]);
    let vk = VerifyingKey::new(key.to_vec());
    derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &vk)
        .expect("a 32-byte vk under the default ed25519 scheme always derives an IdentityId")
}

/// The `cofay` / `owner` label pair an [`OwnershipOp`](generators::OwnershipOp)
/// requests (both `Attach` and `Reparent` map onto `OwnershipRegistry::attach`).
fn op_labels(op: &generators::OwnershipOp) -> (&str, &str) {
    match op {
        generators::OwnershipOp::Attach { cofay, owner } => (cofay, owner),
        generators::OwnershipOp::Reparent { cofay, new_owner } => (cofay, new_owner),
    }
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 11: 归属深度上界
    #[test]
    fn property_11_depth_bound(
        salt in 0u32..1000,
        overflow_probes in 1usize..=4,
        ops in generators::ownership_sequence(40),
    ) {
        // --- Part 1: deliberately-constructed deep chain probes the boundary -------

        let mut reg = OwnershipRegistry::new();

        // Positional labels in a dedicated namespace (varied by `salt`) so the chain's
        // ids differ across runs yet never collide with the Part-2 "id-N" pool.
        let chain_label = |pos: u32| format!("chain-{salt}-{pos}");

        // Root iFay at depth 0.
        let root = id_from_label(&chain_label(0));
        reg.register_root(&root).unwrap();
        prop_assert_eq!(reg.depth_of(&root), Some(0));

        // Attach a straight chain root -> n1 -> ... -> n16. Each successful attach has
        // depth == previous + 1 and <= MAX_DEPTH, with a root-first path of the right
        // length whose path[0] is the root iFay.
        let mut owner = root.clone();
        for d in 1..=MAX_DEPTH {
            let child = id_from_label(&chain_label(d));
            let path = reg
                .attach(&child, &owner)
                .expect("an attach that stays within the depth bound succeeds");

            // depth == previous + 1 == d, and never exceeds the bound.
            prop_assert_eq!(reg.depth_of(&child), Some(d));
            prop_assert!(reg.depth_of(&child).unwrap() <= MAX_DEPTH);
            // root-first path: path[0] is the root iFay, len(path) == depth + 1.
            prop_assert_eq!(&path[0], &root);
            prop_assert_eq!(path.len() as u32, d + 1);

            owner = child;
        }

        // `owner` is now the depth-16 leaf, sitting exactly at MAX_DEPTH.
        prop_assert_eq!(reg.depth_of(&owner), Some(MAX_DEPTH));

        // Snapshot before probing the over-depth boundary so we can prove "unchanged".
        let len_before = reg.len();
        let deepest = owner.clone();

        // The FIRST attach beneath the depth-16 leaf would create depth 17 and MUST be
        // rejected with OwnershipDepthExceeded, leaving the registry unchanged. Probing
        // it `overflow_probes` times shows the rejection is stable and side-effect-free.
        for p in 0..overflow_probes {
            let too_deep = id_from_label(&chain_label(MAX_DEPTH + 1 + p as u32));
            let result = reg.attach(&too_deep, &owner);

            prop_assert_eq!(result, Err(IdentityError::OwnershipDepthExceeded));
            // Rejected coFay is NOT in the registry; len unchanged; deepest stays 16.
            prop_assert!(!reg.contains(&too_deep));
            prop_assert_eq!(reg.len(), len_before);
            prop_assert_eq!(reg.depth_of(&deepest), Some(MAX_DEPTH));
        }

        // Global invariant on the chain registry: every node's depth <= 16.
        for node in reg.iter() {
            prop_assert!(node.depth() <= MAX_DEPTH);
            prop_assert_eq!(reg.depth_of(node.id()), Some(node.depth()));
        }

        // --- Part 2: arbitrary attach/re-parent sequence keeps depth <= 16 ---------

        // An independent registry seeded with a few roots so generated attaches can
        // actually grow chains (and so the depth bound genuinely engages).
        let mut noise = OwnershipRegistry::new();
        for seed in ["id-0", "id-1", "id-2"] {
            noise.register_root(&id_from_label(seed)).unwrap();
        }

        for op in &ops {
            let (cofay_label, owner_label) = op_labels(op);
            let cofay = id_from_label(cofay_label);
            let owner_id = id_from_label(owner_label);

            // Snapshot the full node set; OwnershipNode derives Clone + PartialEq.
            let before: Vec<OwnershipNode> = noise.iter().cloned().collect();

            match noise.attach(&cofay, &owner_id) {
                Ok(path) => {
                    // A successful attach never produces an over-bound node.
                    prop_assert!(path.len() as u32 <= MAX_DEPTH + 1);
                }
                Err(IdentityError::OwnershipDepthExceeded) => {
                    // A depth-bound rejection leaves the registry completely unchanged.
                    let after: Vec<OwnershipNode> = noise.iter().cloned().collect();
                    prop_assert_eq!(before, after);
                }
                // OwnerNotFound / OwnershipCycle are other guards, out of scope here.
                Err(_) => {}
            }

            // The core invariant of Property 11: after ANY request, every registered
            // node's depth is bounded by MAX_DEPTH (16).
            for node in noise.iter() {
                prop_assert!(
                    node.depth() <= MAX_DEPTH,
                    "node reached depth {} > MAX_DEPTH {}",
                    node.depth(),
                    MAX_DEPTH
                );
            }
        }
    }
}
