//! Property 7 — Nonce 单调防重放 (monotonic replay protection).
//!
//! Design *Identity_Core* / Property 7: Nonce 单调防重放.
//! Validates Requirements 5.1, 5.4, 5.5.
//!
//! Full statement: for any sequence of signed operations targeting the **same**
//! identity, an operation is successfully applied **iff** its `Nonce` is **strictly
//! greater** than that identity's last-applied `Nonce`; on a successful apply the
//! identity's applied `Nonce` is updated to this operation's `Nonce`; any operation
//! whose `Nonce` is **not** strictly greater than the applied value is rejected with
//! [`IdentityError::ReplayDetected`] and produces **no** state change.
//!
//! The test stands up an [`IdentityState`] over the deterministic reference signature
//! scheme and creates a single iFay whose **own active key is the signer**, so every
//! `AddDelegate` operation it signs passes the scheme → format → verify → authorize →
//! identity-match chain and the *only* gate left is the Nonce replay guard. It then
//! drives [`generators::nonce_sequence`] — `u64`s drawn from a small range, so the
//! sequence naturally contains regressions and duplicates — applying one `AddDelegate`
//! per nonce. A mirror `expected_applied` (starting at `0`, a fresh iFay's applied
//! nonce; note nonce `0` is **not** `> 0` and so is rejected) reproduces the strict-`>`
//! rule, and after every attempt we assert both the returned `Result` and the on-chain
//! `applied_nonce` agree with it.

mod common;

use common::generators;
use proptest::prelude::*;

use gmc_identity::error::IdentityError;
use gmc_identity::identity_core::{
    canonical_encode_operation, Applied, IdentityState, OperationPayload, SignedOperation,
};
use gmc_identity::scheme::{ByteFormat, SchemeDescriptor, SchemeRegistry};
use gmc_identity::signer::{
    reference_keypair, ReferenceSigner, ReferenceVerifier, Signer, REFERENCE_SCHEME_TAG,
};
use gmc_identity::types::{SchemeTag, Timestamp, VerifyingKey};

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 7: Nonce 单调防重放
    #[test]
    fn property_07_nonce_monotonic_replay_protection(
        nonces in generators::nonce_sequence(24),
    ) {
        // A registry carrying only the deterministic reference scheme: 32-byte signing /
        // verifying keys and a generous signature-length range that the reference
        // signature (4 + 32 + |msg| bytes) always satisfies.
        let mut registry = SchemeRegistry::empty();
        registry
            .register(SchemeDescriptor::new(
                SchemeTag::new(REFERENCE_SCHEME_TAG),
                ByteFormat::exact(32),
                ByteFormat::exact(32),
                ByteFormat::range(36, 1 << 20),
            ))
            .expect("register reference scheme");

        let mut state = IdentityState { registry, ..IdentityState::default() };

        // Create the iFay whose own active key is the signer. Borrowing distinct fields
        // (`&state.registry`, `&mut state.ownership`, `&mut state.binding`) alongside the
        // `&mut state.identities` receiver is the borrow-friendly aggregate shape.
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let target = state
            .identities
            .create_ifay(
                &state.registry,
                &mut state.ownership,
                &mut state.binding,
                &SchemeTag::new(REFERENCE_SCHEME_TAG),
                &signer_vk,
                Timestamp::from_secs(1),
            )
            .expect("create iFay");

        // A freshly-created iFay starts with applied_nonce == 0 (no operation applied).
        let mut expected_applied: u64 = 0;
        prop_assert_eq!(
            state.identities.get(&target).expect("target exists").applied_nonce,
            expected_applied
        );

        for (idx, &nonce) in nonces.iter().enumerate() {
            // Vary the delegate per attempt so each successful apply is a distinct
            // change; AddDelegate signed by the identity's own active key is authorized,
            // so the Nonce guard is the only thing that can reject it.
            let delegate = VerifyingKey::new(vec![idx as u8; 32]);
            let payload = OperationPayload::AddDelegate { delegate };

            // Sign the canonical (target, payload, nonce) message with the iFay's own key.
            let msg = canonical_encode_operation(&target, &payload, nonce);
            let sig = ReferenceSigner.sign(&sk, &msg).expect("reference sign");
            let op = SignedOperation::new(
                target.clone(),
                payload,
                nonce,
                SchemeTag::new(REFERENCE_SCHEME_TAG),
                signer_vk.clone(),
                sig,
            );

            let result = state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2));

            if nonce > expected_applied {
                // Strictly greater than the applied value ⇒ applied (Requirements 5.1, 5.4),
                // and the applied nonce advances to this operation's nonce (Requirement 5.5).
                prop_assert_eq!(result, Ok(Applied::DelegateAdded));
                expected_applied = nonce;
            } else {
                // Not strictly greater ⇒ rejected as a replay with no state change
                // (Requirement 5.4): the applied nonce is left unchanged below.
                prop_assert_eq!(result, Err(IdentityError::ReplayDetected));
            }

            // The on-chain applied nonce always equals the strict-monotonic expectation,
            // whether the last attempt committed or was rejected.
            prop_assert_eq!(
                state.identities.get(&target).expect("target exists").applied_nonce,
                expected_applied
            );
        }
    }
}
