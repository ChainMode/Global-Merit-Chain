//! Property 20 — 目标身份一致性 (declared-target identity consistency).
//!
//! Design *Identity_Core* `apply`, step 3 (identity match) / Property 20: 目标身份一致性.
//! Validates Requirements 13.2.
//!
//! Full statement: 对任意已签名操作，若其载荷声明的目标 `IdentityId` 与认证其签名的密钥
//! 所属（或所授权）的身份不一致，则该操作被拒绝、返回 `IdentityMismatch`，且不产生任何
//! 状态变更.
//!
//! ## Construction that deterministically yields `IdentityMismatch`
//!
//! Reading the `IdentityState::apply` chain (steps 2 authorization → 3 identity match)
//! shows that reaching the identity-match step requires authorization to **pass first**.
//! The `own-state` branch only accepts a declared target that is itself a **registered
//! identity** (it reads `self.identities.get(&declared_target)`), so a signer whose key
//! derives to an *unregistered* target fails `own-state` and — absent any other
//! authorization — is rejected earlier with `UnauthorizedActor`, never reaching step 3.
//!
//! The only path that authorizes a signer for a **non-registered** declared target is
//! the `on-behalf` delegate branch, which matches on the **raw `VerifyingKey`** against
//! the `DelegateStore` independently of whether that target is a real identity. So this
//! test builds a *phantom* target `b_id` that is **never created as an identity** and
//! authorizes the signer's key as an **active delegate** of it. Authentication and
//! authorization then pass, but `apply`'s identity-match step finds no registered
//! identity for `b_id` and returns `IdentityMismatch` with the aggregate unchanged —
//! exactly the "declared target inconsistent with the authorized key's identity" case of
//! Requirement 13.2.
//!
//! A correctly-targeted positive control (an operation declaring the **registered**
//! identity `a_id` and signed by its own active key) applies `Ok`, demonstrating that
//! the *mismatch* is what triggers the rejection, not the operation shape itself.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_core::{
    canonical_encode_operation, Applied, IdentityState, OperationPayload, SignedOperation,
};
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::scheme::{ByteFormat, SchemeDescriptor, SchemeRegistry};
use gmc_identity::signer::{
    reference_keypair, ReferenceSigner, ReferenceVerifier, Signer, REFERENCE_SCHEME_TAG,
};
use gmc_identity::types::{SchemeTag, SigningKey, Timestamp, VerifyingKey};

/// A scheme registry carrying the deterministic reference scheme, so signed operations
/// under it can be authenticated end-to-end (reconstructed from the public API — the
/// in-crate test helper is private). The reference signature length is `4 + 32 +
/// len(msg)` (variable), so the signature format is a generous range whose lower bound
/// (36) still rejects obviously-too-short signatures.
fn reference_registry() -> SchemeRegistry {
    let mut registry = SchemeRegistry::empty();
    registry
        .register(SchemeDescriptor::new(
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            ByteFormat::exact(32),          // signing key (unused here)
            ByteFormat::exact(32),          // verifying key
            ByteFormat::range(36, 1 << 20), // signature (variable length)
        ))
        .expect("fresh registry accepts the reference scheme");
    registry
}

/// A fresh aggregate whose scheme registry knows the deterministic reference scheme.
fn reference_state() -> IdentityState {
    IdentityState {
        registry: reference_registry(),
        ..IdentityState::default()
    }
}

/// Creates a self-sovereign iFay in `state` under the reference scheme with
/// `active_key = signer_vk`, returning its derived id (so a signer presenting
/// `signer_vk` authenticates as this identity's own active key).
fn create_reference_ifay(state: &mut IdentityState, signer_vk: &VerifyingKey) -> IdentityId {
    let tag = SchemeTag::new(REFERENCE_SCHEME_TAG);
    state
        .identities
        .create_ifay(
            &state.registry,
            &mut state.ownership,
            &mut state.binding,
            &tag,
            signer_vk,
            Timestamp::from_secs(1),
        )
        .expect("reference ifay creation")
}

/// Builds a `SignedOperation` for `target` carrying `payload` at `nonce`, signed with
/// the reference signer under `sk`/`signer_vk` (so the signature verifies and the actor
/// derives to `signer_vk`'s identity).
fn signed_op(
    target: &IdentityId,
    payload: OperationPayload,
    nonce: u64,
    sk: &SigningKey,
    signer_vk: &VerifyingKey,
) -> SignedOperation {
    let msg = canonical_encode_operation(target, &payload, nonce);
    let sig = ReferenceSigner.sign(sk, &msg).expect("reference sign");
    SignedOperation::new(
        target.clone(),
        payload,
        nonce,
        SchemeTag::new(REFERENCE_SCHEME_TAG),
        signer_vk.clone(),
        sig,
    )
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 20: 目标身份一致性
    #[test]
    fn property_20_declared_target_inconsistent_is_identity_mismatch(
        seed_a in proptest::collection::vec(any::<u8>(), 1..=12),
        seed_b in proptest::collection::vec(any::<u8>(), 1..=12),
        payload_delegate in generators::verifying_key_valid(),
    ) {
        let tag = SchemeTag::new(REFERENCE_SCHEME_TAG);

        // Two matching reference keypairs. `reference_keypair` is deterministic and
        // (almost always) injective on seeds, so distinct seeds yield distinct keys —
        // but guard on the derived verifying keys directly to be certain.
        let (sk_a, vk_a) = reference_keypair(&seed_a);
        let (sk_b, vk_b) = reference_keypair(&seed_b);
        prop_assume!(vk_a != vk_b);

        // A registered iFay A whose own active key is `vk_a`. This is the only identity
        // this layer knows about.
        let mut state = reference_state();
        let a_id = create_reference_ifay(&mut state, &vk_a);

        // A PHANTOM target derived from `vk_b` that is NEVER created as an identity.
        // Derivation is injective, so distinct `vk_a`/`vk_b` ⇒ `b_id != a_id`.
        let b_id = derive_identity_id(&state.registry, &tag, &vk_b)
            .expect("valid reference vk derives an id");
        prop_assume!(b_id != a_id);

        // Authorize `vk_b` as an ACTIVE delegate of the phantom target. The delegate
        // branch matches on the raw `VerifyingKey`, so authorization will pass for `b_id`
        // even though `b_id` is not a registered identity — this is precisely what lets
        // the chain reach (and fail at) the identity-match step rather than stopping at
        // authorization.
        state
            .delegates
            .add_delegate(&b_id, &vk_b)
            .expect("authorize delegate key for the phantom target");

        // Snapshot the full aggregate before submitting the mismatching operation.
        let before = state.clone();

        // A signed operation whose signature is VALID (signed by `sk_b` over the exact
        // canonical message) and whose signer `vk_b` IS authorized for `b_id` (delegate),
        // but whose declared target `b_id` is inconsistent with any coherent registered
        // identity. Expect: IdentityMismatch, with zero state change (Requirement 13.2).
        let mismatch_op = signed_op(
            &b_id,
            OperationPayload::AddDelegate { delegate: payload_delegate.clone() },
            1,
            &sk_b,
            &vk_b,
        );
        let result = state.apply(&mismatch_op, &ReferenceVerifier, Timestamp::from_secs(2));
        prop_assert_eq!(result, Err(IdentityError::IdentityMismatch));
        // No partial write: the aggregate is byte-for-byte unchanged after rejection.
        prop_assert_eq!(&state, &before);

        // Positive control: the SAME operation shape, but correctly targeted at the
        // registered identity `a_id` and signed by A's own active key `vk_a`, applies
        // `Ok` — proving the declared-target *mismatch* (not the operation itself) is
        // what triggers the rejection above.
        let consistent_op = signed_op(
            &a_id,
            OperationPayload::AddDelegate { delegate: payload_delegate },
            1,
            &sk_a,
            &vk_a,
        );
        let ok_result = state.apply(&consistent_op, &ReferenceVerifier, Timestamp::from_secs(3));
        prop_assert_eq!(ok_result, Ok(Applied::DelegateAdded));
    }
}
