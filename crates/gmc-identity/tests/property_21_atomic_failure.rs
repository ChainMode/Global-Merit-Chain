//! Property 21 — atomic failure & no side effects (no signature-bypassable mutation).
//!
//! Design *Identity_Core* / Property 21: 原子失败与无副作用（无可绕过签名的状态变更路径）.
//! Validates Requirements 5.3, 13.1, 13.4.
//!
//! Full statement: 对任意被拒绝的身份操作——无论其拒绝原因是方案不支持、密钥/签名格式
//! 无效、签名无效、未授权、身份不匹配或重放——该操作都不产生任何状态变更（无副作用），
//! 且不存在可绕过签名认证的状态变更路径。
//!
//! The test stands up a fresh [`IdentityState`] holding exactly one reference-scheme
//! **iFay** whose active key is `signer_vk` (so a fully-valid operation *exists*
//! against it, with `applied_nonce = 0` and no delegates). It then snapshots the
//! aggregate and submits a **battery of distinct rejection causes** — each built from a
//! valid op by perturbing *one* thing so it fails at a *different* step of the fixed
//! validation chain (`scheme → key/sig format → verify → authorize → identity → nonce`):
//!
//! 1. `SchemeUnsupported`  — a correctly-signed op carrying an unregistered scheme tag.
//! 2. `KeyFormatInvalid`   — a registered scheme, but a 31-byte (≠ 32) verifying key.
//! 3. `SignatureInvalid`   — valid-format key & signature, but signed over a *different*
//!    message (a different nonce), so verification fails over the submitted op.
//! 4. `UnauthorizedActor`  — a *validly*-signed op signed by a key that is neither the
//!    target's own active key nor an owner / ancestor / active delegate.
//! 5. `ReplayDetected`     — a correctly-signed, authorized op at nonce 0 (not strictly
//!    greater than the target's `applied_nonce`, which starts at 0).
//!
//! After each rejection the aggregate must be **byte-for-byte equal** to the snapshot
//! (atomic failure, no side effect). Finally the **no-bypass** invariant is asserted
//! *positively*: a fully-authenticated `AddDelegate` *does* mutate state
//! ([`Applied::DelegateAdded`], delegate now active, `applied_nonce` advanced) — proving
//! the only path that changes state is one carrying a valid signature from an authorized
//! key.

mod common;

use common::generators;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_core::{
    canonical_encode_operation, Applied, IdentityState, OperationPayload, SignedOperation,
};
use gmc_identity::identity_id::IdentityId;
use gmc_identity::scheme::{ByteFormat, SchemeDescriptor, SchemeRegistry};
use gmc_identity::signer::{
    reference_keypair, ReferenceSigner, ReferenceVerifier, Signer, REFERENCE_SCHEME_TAG,
};
use gmc_identity::types::{Nonce, SchemeTag, SigningKey, Timestamp, VerifyingKey};

/// The deterministic reference scheme tag (distinct from `ed25519`).
fn reference_tag() -> SchemeTag {
    SchemeTag::new(REFERENCE_SCHEME_TAG)
}

/// A registry that registers only the deterministic reference scheme, so the
/// first-half chain (scheme → format) can resolve it. The reference signature length is
/// `4 + 32 + len(msg)` (variable), so the signature format is a generous range whose
/// lower bound (36) still rejects obviously-too-short signatures; the 32-byte key
/// format matches `reference_keypair`'s output.
fn reference_registry() -> SchemeRegistry {
    let mut registry = SchemeRegistry::empty();
    registry
        .register(SchemeDescriptor::new(
            reference_tag(),
            ByteFormat::exact(32),          // signing key (unused here)
            ByteFormat::exact(32),          // verifying key
            ByteFormat::range(36, 1 << 20), // signature (variable length)
        ))
        .expect("fresh registry");
    registry
}

/// Builds a fresh aggregate holding one reference-scheme **iFay** whose active key is
/// `signer_vk` (`applied_nonce = 0`, no delegates). Returns the aggregate and the
/// iFay's `IdentityId` (the valid operation target).
fn state_with_ifay(signer_vk: &VerifyingKey) -> (IdentityState, IdentityId) {
    let mut state = IdentityState::new();
    state.registry = reference_registry();
    // Disjoint-field borrows (`&state.registry`, `&mut state.ownership`,
    // `&mut state.binding`, receiver `&mut state.identities`) — the same shape
    // `IdentityState::apply` itself uses.
    let target = state
        .identities
        .create_ifay(
            &state.registry,
            &mut state.ownership,
            &mut state.binding,
            &reference_tag(),
            signer_vk,
            Timestamp::from_secs(1),
        )
        .expect("create reference iFay");
    (state, target)
}

/// Builds a **properly-signed** [`SignedOperation`]: the signature is the reference
/// signature over `canonical_encode_operation(target, payload, nonce)`, produced by
/// `sk` (whose verifying key is `signer_vk`).
fn signed_op(
    target: &IdentityId,
    payload: OperationPayload,
    nonce: Nonce,
    sk: &SigningKey,
    signer_vk: &VerifyingKey,
) -> SignedOperation {
    let msg = canonical_encode_operation(target, &payload, nonce);
    let sig = ReferenceSigner.sign(sk, &msg).expect("reference sign");
    SignedOperation::new(
        target.clone(),
        payload,
        nonce,
        reference_tag(),
        signer_vk.clone(),
        sig,
    )
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 21: 原子失败与无副作用（无可绕过签名的状态变更路径）
    #[test]
    fn property_21_atomic_failure_no_bypass(
        signer_seed in prop_vec(any::<u8>(), 1..16),
        actor_seed in prop_vec(any::<u8>(), 1..16),
        delegate in generators::verifying_key_valid(),
        nonce in 1u64..1_000,
    ) {
        let (signer_sk, signer_vk) = reference_keypair(&signer_seed);
        let (actor_sk, actor_vk) = reference_keypair(&actor_seed);
        // The unauthorized actor must be a genuinely different key from the iFay's active
        // key; reference derivation is an injective bijection of the key bytes, so
        // distinct keys ⇒ distinct derived IdentityIds (a real "other" signer).
        prop_assume!(signer_vk != actor_vk);

        let ts = Timestamp::from_secs(42);
        let payload = OperationPayload::AddDelegate { delegate: delegate.clone() };

        // A fresh aggregate holding ONE reference-scheme iFay (active key = signer_vk),
        // applied_nonce = 0, no delegates: a fully-valid op exists against it.
        let (mut state, target) = state_with_ifay(&signer_vk);

        // Snapshot: every REJECTED op below must leave the aggregate byte-for-byte equal.
        let before = state.clone();

        // (1) SchemeUnsupported — a correctly-signed op whose scheme tag is unregistered.
        // Rejected at chain step 1 (scheme resolve), before key/sig/verify are consulted.
        {
            let mut op = signed_op(&target, payload.clone(), nonce, &signer_sk, &signer_vk);
            op.scheme_tag = SchemeTag::new("nope");
            prop_assert_eq!(
                state.apply(&op, &ReferenceVerifier, ts),
                Err(IdentityError::SchemeUnsupported)
            );
            prop_assert_eq!(&state, &before);
        }

        // (2) KeyFormatInvalid — registered scheme, but a 31-byte verifying key (≠ 32).
        // Rejected at chain step 2 (byte-format), before signature verification.
        {
            let mut op = signed_op(&target, payload.clone(), nonce, &signer_sk, &signer_vk);
            op.verifying_key = VerifyingKey::new(vec![0u8; 31]);
            prop_assert_eq!(
                state.apply(&op, &ReferenceVerifier, ts),
                Err(IdentityError::KeyFormatInvalid)
            );
            prop_assert_eq!(&state, &before);
        }

        // (3) SignatureInvalid — valid-format key & signature, but the signature covers a
        // DIFFERENT message (a different nonce) than the submitted op. Rejected at chain
        // step 3 (verify), before authorization is consulted.
        {
            let wrong_msg_nonce = nonce + 1; // ≠ `nonce`, so the bound canonical message differs
            let bad_sig_msg = canonical_encode_operation(&target, &payload, wrong_msg_nonce);
            let bad_sig = ReferenceSigner
                .sign(&signer_sk, &bad_sig_msg)
                .expect("reference sign");
            let op = SignedOperation::new(
                target.clone(),
                payload.clone(),
                nonce, // submitted nonce ≠ the nonce the signature actually covers
                reference_tag(),
                signer_vk.clone(),
                bad_sig,
            );
            prop_assert_eq!(
                state.apply(&op, &ReferenceVerifier, ts),
                Err(IdentityError::SignatureInvalid)
            );
            prop_assert_eq!(&state, &before);
        }

        // (4) UnauthorizedActor — a VALIDLY-signed op, but signed by a key that is neither
        // the target's own active key nor an owner / ancestor / active delegate. Passes
        // verify, rejected at chain step 4 (authorization).
        {
            let op = signed_op(&target, payload.clone(), nonce, &actor_sk, &actor_vk);
            prop_assert_eq!(
                state.apply(&op, &ReferenceVerifier, ts),
                Err(IdentityError::UnauthorizedActor)
            );
            prop_assert_eq!(&state, &before);
        }

        // (5) ReplayDetected — a correctly-signed, authorized op at nonce 0 (not strictly
        // greater than the target's applied_nonce, which starts at 0). Passes verify and
        // authorization, rejected at chain step 5 (nonce replay guard).
        {
            let op = signed_op(&target, payload.clone(), 0, &signer_sk, &signer_vk);
            prop_assert_eq!(
                state.apply(&op, &ReferenceVerifier, ts),
                Err(IdentityError::ReplayDetected)
            );
            prop_assert_eq!(&state, &before);
        }

        // After the whole battery of rejected ops, the aggregate is still unchanged: no
        // rejection path produced any side effect (Requirements 13.1, 13.4).
        prop_assert_eq!(&state, &before);

        // No-bypass invariant (positive): the ONLY path that mutates state is a
        // fully-authenticated one. A valid AddDelegate (correct signature from the
        // target's own active key, nonce > applied_nonce) DOES change state.
        let good = signed_op(&target, payload.clone(), nonce, &signer_sk, &signer_vk);
        prop_assert_eq!(
            state.apply(&good, &ReferenceVerifier, ts),
            Ok(Applied::DelegateAdded)
        );
        // The aggregate changed, and the change is exactly the authenticated effect:
        // the delegate is now active and applied_nonce advanced to the op's nonce.
        prop_assert_ne!(&state, &before);
        prop_assert!(state.delegates.is_active_delegate(&target, &delegate));
        prop_assert_eq!(state.identities.get(&target).unwrap().applied_nonce, nonce);
    }
}
