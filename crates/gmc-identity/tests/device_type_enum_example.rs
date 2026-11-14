//! Worked EXAMPLE unit tests for the `Device_Type` enum validation (task 13.7). These
//! are plain `#[test]` examples — **not** numbered properties — so they carry no
//! `Feature: gmc-identity, Property N` label and use no proptest.
//!
//! They pin Requirement 8.6 with concrete values at the parsing boundary where a raw
//! external device-type tag is mapped into the type-safe [`DeviceType`] enum:
//!
//! - The **six** prescribed device types (手机/电脑/手表/机器人/车机 HMI/云端 SDK ⇒
//!   `Phone`/`Computer`/`Watch`/`Robot`/`CarHmi`/`CloudSdk`) are each accepted by
//!   [`parse_device_type`] via their canonical tag and round-trip through
//!   [`device_type_tag`].
//! - A representative set of **illegal** tags (unknown classes, wrong case, wrong
//!   separator, surrounding whitespace, the empty string, and "squashed" spellings) is
//!   rejected with [`IdentityError::DeviceTypeInvalid`], creating no credential.

use gmc_identity::device::{device_type_tag, parse_device_type};
use gmc_identity::error::IdentityError;
use gmc_identity::types::DeviceType;

/// Req 8.6 (positive side) — each of the six prescribed device types is accepted via its
/// canonical tag and round-trips: `parse_device_type(device_type_tag(dt)) == Ok(dt)`.
///
/// We also confirm `DeviceType::ALL` enumerates exactly six **distinct** variants and
/// that it includes the two less-obvious classes, `CarHmi` (车机 HMI) and `CloudSdk`
/// (云端 SDK), so the "six legal types" claim is anchored to the real enum.
#[test]
fn six_valid_device_types_are_accepted_and_round_trip() {
    // The enum lists exactly six device types, all distinct.
    assert_eq!(DeviceType::ALL.len(), 6, "exactly six prescribed device types");
    for (i, a) in DeviceType::ALL.iter().enumerate() {
        for b in &DeviceType::ALL[i + 1..] {
            assert_ne!(a, b, "DeviceType::ALL variants must be distinct");
        }
    }

    // The six legal types include the two compound classes explicitly called out by
    // Requirement 8 (车机 HMI and 云端 SDK).
    assert!(DeviceType::ALL.contains(&DeviceType::CarHmi));
    assert!(DeviceType::ALL.contains(&DeviceType::CloudSdk));

    // Every prescribed device type is accepted by its canonical tag and round-trips
    // (parse is the inverse of tag) — so all six legal types are reachable from a string.
    for device_type in DeviceType::ALL {
        let tag = device_type_tag(device_type);
        assert_eq!(
            parse_device_type(tag),
            Ok(device_type),
            "canonical tag {tag:?} must parse back to {device_type:?}"
        );
    }

    // Pin the concrete canonical spelling of each accepted tag (single source of truth
    // is DEVICE_TYPE_TAGS in src/device.rs).
    assert_eq!(parse_device_type("phone"), Ok(DeviceType::Phone));
    assert_eq!(parse_device_type("computer"), Ok(DeviceType::Computer));
    assert_eq!(parse_device_type("watch"), Ok(DeviceType::Watch));
    assert_eq!(parse_device_type("robot"), Ok(DeviceType::Robot));
    assert_eq!(parse_device_type("car_hmi"), Ok(DeviceType::CarHmi));
    assert_eq!(parse_device_type("cloud_sdk"), Ok(DeviceType::CloudSdk));
}

/// Req 8.6 (negative side) — a representative set of illegal device-type tags is rejected
/// with [`IdentityError::DeviceTypeInvalid`]. None of these strings is one of the six
/// canonical tags, so each must fail (and, per the design, create no credential):
///
/// - unknown classes:           `"tablet"`, `"tv"`, `"drone"`
/// - wrong case:                `"PHONE"`, `"Phone"`
/// - empty / whitespace:        `""`, `"phone "` (trailing space)
/// - wrong separator / squashed `"car-hmi"` (hyphen, canonical is `car_hmi`),
///                              `"cloudsdk"` (missing the underscore in `cloud_sdk`)
#[test]
fn representative_illegal_device_type_tags_are_rejected() {
    let illegal_tags = [
        "tablet",   // not one of the six classes
        "tv",       // not one of the six classes
        "drone",    // not one of the six classes
        "PHONE",    // wrong case (canonical is lowercase "phone")
        "Phone",    // wrong case
        "",         // empty string
        "phone ",   // trailing whitespace
        "car-hmi",  // wrong separator: canonical is "car_hmi"
        "cloudsdk", // squashed: canonical is "cloud_sdk"
    ];

    for tag in illegal_tags {
        assert_eq!(
            parse_device_type(tag),
            Err(IdentityError::DeviceTypeInvalid),
            "illegal tag {tag:?} must be rejected with DeviceTypeInvalid"
        );
    }
}
