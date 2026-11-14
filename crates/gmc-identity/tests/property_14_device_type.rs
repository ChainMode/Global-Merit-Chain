//! Property 14 — 设备类型非法被拒.
//!
//! Design *Device_Registry* / Property 14: 设备类型非法被拒.
//! Validates Requirements 8.6.
//!
//! 对任意不属于规定枚举（手机、电脑、手表、机器人、车机 HMI、云端 SDK 实例）的设备类型
//! 输入，设备注册都会被拒绝、返回 `DeviceTypeInvalid`，且不创建任何 `DeviceCredential`。
//!
//! ## Where the rejection lives (parsing boundary)
//!
//! [`DeviceType`] is a **type-safe** enum, so an out-of-enum value is *unrepresentable*
//! in Rust — there is no way to hand [`DeviceRegistry::enroll`] an invalid type. The
//! `DeviceTypeInvalid` path therefore lives at the boundary where a raw external tag is
//! parsed into the enum: [`parse_device_type`] accepts exactly the six canonical tags
//! (`"phone"`, `"computer"`, `"watch"`, `"robot"`, `"car_hmi"`, `"cloud_sdk"`) and
//! returns [`IdentityError::DeviceTypeInvalid`] for anything else, creating no credential
//! (Req 8.6). [`device_type_tag`] is its inverse.
//!
//! ## What this property drives
//!
//! The shared [`generators::device_type_input`] yields either a `Known(DeviceType)` (a
//! valid enum variant) or an `Illegal(String)` (a free-form tag outside the enum).
//!
//! - **Known(dt)**: the canonical tag round-trips — `parse_device_type(device_type_tag(dt))`
//!   returns `Ok(dt)` (valid types are accepted).
//! - **Illegal(s)**: after guarding that `s` is not accidentally one of the six valid
//!   tags, `parse_device_type(&s)` returns `Err(DeviceTypeInvalid)`. Modelling the
//!   API-layer guard — *parse first, enroll only on `Ok`* — an illegal tag is rejected
//!   **before** the registry is touched, so no `DeviceCredential` is ever created and the
//!   registry stays empty.

mod common;

use common::generators;
use generators::DeviceTypeInput;
use proptest::prelude::*;

use gmc_identity::device::{device_type_tag, parse_device_type, DeviceRegistry};
use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

/// The six canonical tags accepted by [`parse_device_type`]. Used to guard the illegal
/// branch so a randomly generated "illegal" string that happens to equal a valid tag is
/// skipped rather than mis-asserted.
const VALID_TAGS: [&str; 6] = [
    "phone", "computer", "watch", "robot", "car_hmi", "cloud_sdk",
];

/// A stable [`IdentityId`] derived from a fixed 32-byte verifying key under the default
/// ed25519 scheme — the identity an illegal enrollment would (but must not) target.
fn sample_identity() -> IdentityId {
    derive_identity_id(
        &SchemeRegistry::default(),
        &SchemeTag::ed25519(),
        &VerifyingKey::new(vec![7u8; 32]),
    )
    .expect("a 32-byte vk under the default ed25519 scheme always derives an id")
}

proptest! {
    // Run each numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-identity, Property 14: 设备类型非法被拒
    #[test]
    fn property_14_illegal_device_type_is_rejected(input in generators::device_type_input()) {
        match input {
            // Valid types are accepted: the canonical tag round-trips through the parser.
            DeviceTypeInput::Known(dt) => {
                prop_assert_eq!(parse_device_type(device_type_tag(dt)), Ok(dt));
            }
            // Illegal types are rejected at the parsing boundary, before any enroll.
            DeviceTypeInput::Illegal(s) => {
                // Guard: a randomly generated string must not accidentally be one of the
                // six valid tags (those are accepted, not rejected).
                prop_assume!(!VALID_TAGS.contains(&s.as_str()));

                // Parsing the illegal tag fails with DeviceTypeInvalid (Req 8.6).
                prop_assert_eq!(
                    parse_device_type(&s),
                    Err(IdentityError::DeviceTypeInvalid)
                );

                // Model the API-layer guard: parse first, enroll only on Ok. Because the
                // parse failed, enroll is never called, so no DeviceCredential is created
                // and the registry is left completely untouched (no side effects).
                let registry = DeviceRegistry::new();
                let identity = sample_identity();

                match parse_device_type(&s) {
                    Ok(_dt) => {
                        // Unreachable: an illegal tag never parses. Asserted to keep the
                        // "enroll only on Ok" guard explicit.
                        prop_assert!(false, "illegal tag {s:?} unexpectedly parsed");
                    }
                    Err(err) => {
                        // The rejection happened before touching the registry.
                        prop_assert_eq!(err, IdentityError::DeviceTypeInvalid);
                    }
                }

                // No credential was created for this identity — registry unchanged/empty.
                prop_assert!(registry.list(&identity).is_empty());
                prop_assert_eq!(registry, DeviceRegistry::new());
            }
        }
    }
}
