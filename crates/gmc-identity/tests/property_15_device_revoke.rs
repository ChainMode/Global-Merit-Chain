//! Property 15 — 设备吊销生命周期与幂等.
//!
//! Design *Device_Registry* / Property 15: 设备吊销生命周期与幂等.
//! Validates Requirements 9.1, 9.2, 9.4.
//!
//! 对任意设备注册/吊销操作序列，以被授权密钥吊销一条活跃凭证后该凭证状态变为"已吊销"；
//! 对一条已处于"已吊销"状态的凭证再次吊销保持其为"已吊销"且不产生任何其它状态变更（幂等）；
//! 列举在任意时刻都如实反映每条凭证的当前状态。
//!
//! ## How the sequence is driven
//!
//! The shared [`generators::device_sequence`] yields `Enroll` / `Revoke` ops over a small
//! pooled device-VK space (so the same device recurs and enroll/revoke/duplicate/
//! idempotent-revoke situations all interleave). The whole sequence runs against **one
//! fixed identity** — Property 15 is about a single identity's credential lifecycle.
//!
//! Alongside the real [`DeviceRegistry`] we maintain an in-test **model**
//! (`DeviceId -> DeviceStatus`) of every credential's *expected* current status, applying
//! the registry's documented semantics:
//!
//! - `Enroll(Known)` on an absent or already-`Revoked` device succeeds → `Active`; on an
//!   already-`Active` device it is a `DeviceDuplicate` that changes nothing (Req 8.5).
//! - `Enroll(Illegal)` is a parse-boundary rejection — it never reaches the registry, so
//!   it is skipped (and `parse_device_type` is asserted to reject the tag).
//! - `Revoke` flips an `Active` credential to `Revoked` (Req 9.2); revoking an
//!   already-`Revoked` or unknown credential is an idempotent `Ok(())` no-op (Req 9.4).
//!
//! After **every** op we assert that `list` faithfully reflects every credential's
//! current status (the set of `(device_id, status)` equals the model, Req 9.1) and that
//! `credential(...).status()` agrees. Each `Revoke` additionally snapshots the full list
//! before the call and compares it after: an idempotent revoke must change **nothing**,
//! while an effective revoke must flip **only** the target's status and preserve every
//! other field and credential.

mod common;

use common::generators;
use proptest::prelude::*;

use std::collections::BTreeMap;

use generators::{DeviceOp, DeviceTypeInput};
use gmc_identity::device::{parse_device_type, DeviceId, DeviceRegistry, DeviceStatus};
use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, Timestamp, VerifyingKey};

/// The single fixed identity this property exercises (its owner's ed25519 key is fixed,
/// so the id is stable across the whole sequence).
fn fixed_identity() -> IdentityId {
    let owner_vk = VerifyingKey::new(vec![7u8; 32]);
    derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), &owner_vk)
        .expect("a 32-byte vk under the default ed25519 scheme always derives an id")
}

/// The current `(device_id -> status)` view the registry reports via `list` — the exact
/// shape Property 15 compares against the model (Req 9.1).
fn listed_status(registry: &DeviceRegistry, identity: &IdentityId) -> BTreeMap<DeviceId, DeviceStatus> {
    registry
        .list(identity)
        .into_iter()
        .map(|credential| (credential.device_id().clone(), credential.status()))
        .collect()
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 15: 设备吊销生命周期与幂等
    #[test]
    fn property_15_device_revoke_lifecycle_and_idempotence(
        ops in generators::device_sequence(48),
    ) {
        let identity = fixed_identity();
        let mut registry = DeviceRegistry::new();

        // Model of every credential's expected current status (DeviceId -> DeviceStatus).
        let mut model: BTreeMap<DeviceId, DeviceStatus> = BTreeMap::new();

        for (i, op) in ops.iter().enumerate() {
            match op {
                DeviceOp::Enroll { device_key, device_type } => {
                    match device_type {
                        DeviceTypeInput::Known(dt) => {
                            let device_id = DeviceId::derive(device_key);
                            let was_active =
                                model.get(&device_id) == Some(&DeviceStatus::Active);

                            let result = registry.enroll(
                                &identity,
                                device_key,
                                *dt,
                                Timestamp::from_secs(i as u64),
                            );

                            if was_active {
                                // Duplicate of an already-Active device → rejected,
                                // status unchanged (Req 8.5); model stays as-is.
                                prop_assert_eq!(result, Err(IdentityError::DeviceDuplicate));
                            } else {
                                // Absent or previously-Revoked device → fresh Active
                                // credential (Req 8.1); its id is the key's fingerprint.
                                let enrolled = result.expect("enroll of a non-active device succeeds");
                                prop_assert_eq!(&enrolled, &device_id);
                                model.insert(device_id, DeviceStatus::Active);
                            }
                        }
                        DeviceTypeInput::Illegal(tag) => {
                            // Illegal device-type tags are rejected at the parse boundary
                            // and never create a credential (Req 8.6) — skip enrolling.
                            prop_assert_eq!(
                                parse_device_type(tag),
                                Err(IdentityError::DeviceTypeInvalid)
                            );
                        }
                    }
                }
                DeviceOp::Revoke { device_key } => {
                    let device_id = DeviceId::derive(device_key);
                    let was_active = model.get(&device_id) == Some(&DeviceStatus::Active);

                    // Snapshot the full list so we can prove what (if anything) changed.
                    let before = registry.list(&identity);

                    // revoke is total + idempotent: always Ok(()) (Req 9.2, 9.4).
                    registry
                        .revoke(&identity, &device_id)
                        .expect("revoke is total and idempotent → Ok(())");

                    let after = registry.list(&identity);

                    if was_active {
                        // Effective revoke (Req 9.2): the target flips Active -> Revoked
                        // and NOTHING else changes — same credentials, same order, every
                        // other field preserved.
                        model.insert(device_id.clone(), DeviceStatus::Revoked);
                        prop_assert_eq!(after.len(), before.len());
                        for (b, a) in before.iter().zip(after.iter()) {
                            // Deterministic DeviceId order means positions align.
                            prop_assert_eq!(a.device_id(), b.device_id());
                            prop_assert_eq!(a.device_key(), b.device_key());
                            prop_assert_eq!(a.device_type(), b.device_type());
                            prop_assert_eq!(a.registered_at(), b.registered_at());
                            if a.device_id() == &device_id {
                                prop_assert_eq!(b.status(), DeviceStatus::Active);
                                prop_assert_eq!(a.status(), DeviceStatus::Revoked);
                            } else {
                                prop_assert_eq!(a.status(), b.status());
                            }
                        }
                    } else {
                        // Idempotent no-op: re-revoking an already-Revoked credential (or
                        // revoking an unknown one) keeps it Revoked/absent and changes
                        // nothing at all — the full list is byte-for-byte identical
                        // (Req 9.4). Model is unchanged.
                        prop_assert_eq!(
                            &after,
                            &before,
                            "idempotent revoke must not change any state"
                        );
                    }
                }
            }

            // --- Invariant checked after EVERY op (Req 9.1) -------------------------
            // `list` faithfully reflects every credential's current status: the reported
            // (device_id, status) set equals the model exactly.
            prop_assert_eq!(listed_status(&registry, &identity), model.clone());

            // And each modeled credential's `credential(...).status()` agrees with `list`.
            for (device_id, expected) in &model {
                let credential = registry
                    .credential(&identity, device_id)
                    .expect("a modeled credential is present in the registry");
                prop_assert_eq!(credential.status(), *expected);
            }
        }
    }
}
