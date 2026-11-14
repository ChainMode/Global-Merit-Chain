//! `Device_Registry` — device-credential enrollment, listing and revocation.
//!
//! This module implements the design's *Device_Registry* section and the
//! *Data Models → 设备凭证* records. It binds a terminal's **device key** to an identity
//! as a [`DeviceCredential`] and answers "which devices does this identity have, and in
//! what state?".
//!
//! Task 13.1 fills in the **data model + `enroll`**; listing and (idempotent) revocation
//! are added by task 13.2 in this same file (see *Shape left for task 13.2* below).
//!
//! ## Data model (design *Data Models → 设备凭证*)
//!
//! - [`DeviceStatus`] — `Active` / `Revoked` (a credential is born `Active`, Req 8.1).
//! - [`DeviceId`] — a stable, deterministic **fingerprint** of the device
//!   [`VerifyingKey`], reusing this crate's reversible base32 encoding
//!   ([`base32_encode`], the same encoding family as [`IdentityId`]'s `key_repr`,
//!   Req 8.3). Being a bijection of the key bytes, equal device keys always map to the
//!   same `DeviceId` and distinct keys never collide.
//! - [`DeviceCredential`] — `device_id` + `identity_id` + `device_key` + `device_type`
//!   + `registered_at` + `status` (Req 8.3).
//! - [`DeviceRegistry`] — `credentials: BTreeMap<IdentityId, BTreeMap<DeviceId,
//!   DeviceCredential>>`, so **one identity may hold many credentials** (Req 8.2) and
//!   iteration order is deterministic.
//!
//! ## `enroll` (Req 8.1, 8.2, 8.3, 8.5)
//!
//! [`DeviceRegistry::enroll`] creates an `Active` credential whose `device_id` is
//! derived from the device key, recording the `device_type`, `registered_at` and
//! `status`. It rejects a device key that **already has an `Active` credential under
//! this identity** with [`DeviceDuplicate`](IdentityError::DeviceDuplicate) (Req 8.5),
//! leaving the existing credential unchanged; a previously **revoked** device key may be
//! re-enrolled (its credential flips back to a fresh `Active` one).
//!
//! ## Device-type validation (Req 8.6)
//!
//! The [`DeviceType`] enum is **type-safe**, so an out-of-enum value is *unrepresentable*
//! in Rust — there is no way to construct a `DeviceType` outside the prescribed six. The
//! [`DeviceTypeInvalid`](IdentityError::DeviceTypeInvalid) path (Req 8.6) therefore lives
//! at the **boundary where a raw external tag is parsed into the enum**: callers
//! (`Identity_Core` / the future API layer) validate raw input via [`parse_device_type`],
//! which maps one of the six canonical tags to its [`DeviceType`] and returns
//! `DeviceTypeInvalid` for any unknown tag — without creating any credential.
//!
//! ## Who is allowed to enroll (Req 8.4) — *not* decided here
//!
//! Like [`crate::authority`], this module is **pure** registry logic: it performs the
//! mutation/decision but does **not** authenticate the *caller*. The design routes every
//! state-changing request through `Identity_Core` (task 11), which runs the fixed
//! validation chain — scheme → key/sig format → signature → identity → **authorize** →
//! nonce — *before* invoking [`enroll`](DeviceRegistry::enroll). An enroll request not
//! signed by an authorized key of the identity is rejected there with
//! [`UnauthorizedActor`](IdentityError::UnauthorizedActor) (Req 8.4); this module
//! provides only the mutation.
//!
//! ## Listing & revocation (Req 9.1, 9.2, 9.4) — task 13.2
//!
//! [`DeviceRegistry::list`] returns **all** of an identity's credentials, each carrying
//! its **current** [`DeviceStatus`], in deterministic `DeviceId` order (the `BTreeMap`
//! iteration order); an unknown identity yields an empty list (Req 9.1).
//!
//! [`DeviceRegistry::revoke`] sets a credential's status to
//! [`Revoked`](DeviceStatus::Revoked) (Req 9.2). It is deliberately **idempotent**
//! (design *Error Handling*: "幂等吊销"): re-revoking an already-`Revoked` credential is a
//! no-op that returns `Ok(())` and changes **no** other state (Req 9.4). Revoking a
//! credential that does **not exist** (unknown identity, or unknown `device_id` under a
//! known identity) is likewise an **idempotent `Ok(())` no-op** — the post-condition
//! ("that device is not an `Active` credential of this identity") already holds, the
//! design exposes no "device not found" error code, and this keeps `revoke` total and
//! side-effect-free on every non-mutating path, consistent with the idempotent-revocation
//! posture.
//!
//! ## Authentication & disempowerment (Req 9.3, 9.5) — *not* decided here
//!
//! Like [`enroll`](DeviceRegistry::enroll), `revoke` is **pure** registry logic and does
//! **not** authenticate the caller: `Identity_Core` (task 11) runs the fixed validation
//! chain and rejects a revoke not signed by an authorized key of the identity with
//! [`UnauthorizedActor`](IdentityError::UnauthorizedActor) (Req 9.5) *before* invoking
//! this method. The disempowerment of a revoked device key (Req 9.3) — refusing
//! operations signed by a `Revoked` device key — is also enforced in `Identity_Core`'s
//! authorization step, which reads the status this method records.

use std::collections::BTreeMap;

use crate::error::{IdentityError, IdentityResult};
use crate::identity_id::{base32_encode, IdentityId};
use crate::types::{DeviceType, Timestamp, VerifyingKey};

/// Lifecycle status of a single device credential (design *Data Models*: `DeviceStatus`).
///
/// A freshly enrolled credential is [`Active`](DeviceStatus::Active) (Req 8.1); task
/// 13.2's `revoke` sets it to [`Revoked`](DeviceStatus::Revoked) (Req 9.2). Only
/// `Active` credentials count as currently bound; `Identity_Core` treats a `Revoked`
/// device key as disempowered (Req 9.3/9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceStatus {
    /// The device credential is currently valid / bound.
    Active,
    /// The device credential has been revoked (Req 9.2).
    Revoked,
}

/// A stable, deterministic identifier for a device, derived from its
/// [`VerifyingKey`] (design *Data Models*: `type DeviceId = string`, Req 8.3).
///
/// `DeviceId` reuses this crate's reversible base32 encoding ([`base32_encode`]) of the
/// device key bytes — the **same encoding family** as [`IdentityId`]'s `key_repr`. Being
/// a bijection of the bytes, it adds **no new dependency** and guarantees that equal
/// device keys derive equal ids (stable lookups) while distinct keys derive distinct ids
/// (no collisions). It is a `BTreeMap` key, so it derives `Ord`/`Hash`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Deterministically derives the [`DeviceId`] of `device_key` (Req 8.3).
    ///
    /// Equal keys always yield the same id; distinct keys always yield distinct ids.
    #[inline]
    pub fn derive(device_key: &VerifyingKey) -> Self {
        DeviceId(base32_encode(device_key.as_bytes()))
    }

    /// The fingerprint as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A record binding a terminal's device key to an identity (design *Data Models*:
/// `DeviceCredential`).
///
/// Holds the deterministically derived [`DeviceId`], the owning [`IdentityId`], the
/// device's [`VerifyingKey`], its declared [`DeviceType`], the registration
/// [`Timestamp`], and the current [`DeviceStatus`] (Req 8.3). Fields are private and
/// exposed through accessors so the record stays immutable to callers (mirroring
/// [`crate::authority::DelegateRecord`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCredential {
    /// Deterministic fingerprint of `device_key` (Req 8.3).
    device_id: DeviceId,
    /// The identity this credential is bound to.
    identity_id: IdentityId,
    /// The device's verifying key.
    device_key: VerifyingKey,
    /// The declared terminal class (Req 8.3).
    device_type: DeviceType,
    /// When the credential was registered (Req 8.3).
    registered_at: Timestamp,
    /// Current lifecycle status; born `Active` (Req 8.1).
    status: DeviceStatus,
}

impl DeviceCredential {
    /// The deterministic device fingerprint (Req 8.3).
    #[inline]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// The identity this credential is bound to.
    #[inline]
    pub fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    /// The device's verifying key.
    #[inline]
    pub fn device_key(&self) -> &VerifyingKey {
        &self.device_key
    }

    /// The declared terminal class.
    #[inline]
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// The registration timestamp.
    #[inline]
    pub fn registered_at(&self) -> Timestamp {
        self.registered_at
    }

    /// The current lifecycle status.
    #[inline]
    pub fn status(&self) -> DeviceStatus {
        self.status
    }

    /// `true` iff this credential is currently [`Active`](DeviceStatus::Active).
    #[inline]
    pub fn is_active(&self) -> bool {
        self.status == DeviceStatus::Active
    }
}

/// The device registry: every identity's device credentials keyed by identity, then by
/// [`DeviceId`] (design *Data Models*: `credentials: BTreeMap<IdentityId,
/// BTreeMap<DeviceId, DeviceCredential>>`).
///
/// Nesting the per-identity credentials in their own `BTreeMap` lets **one identity hold
/// many credentials** (Req 8.2) while keeping iteration deterministic. This type owns the
/// [`enroll`](Self::enroll) mutation (task 13.1); `list` / `revoke` are added by task
/// 13.2. As with [`crate::authority::DelegateStore`], it is **pure**: the caller
/// (`Identity_Core`) authenticates the request first (see the module-level docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRegistry {
    /// identity → (device_id → credential); a `BTreeMap` for determinism (Req 8.2).
    credentials: BTreeMap<IdentityId, BTreeMap<DeviceId, DeviceCredential>>,
}

impl DeviceRegistry {
    /// Creates an empty device registry.
    #[inline]
    pub fn new() -> Self {
        DeviceRegistry {
            credentials: BTreeMap::new(),
        }
    }

    /// Enrolls `device_key` under `identity_id`, creating an `Active`
    /// [`DeviceCredential`] (design *Device_Registry*: `enroll`; Req 8.1, 8.2, 8.3, 8.5).
    ///
    /// The `device_id` is derived deterministically from `device_key` ([`DeviceId::derive`])
    /// and the credential records the `device_type`, `registered_at` and an `Active`
    /// `status` (Req 8.1, 8.3). The same identity may enroll many distinct devices
    /// (Req 8.2). Returns the new [`DeviceId`].
    ///
    /// # Duplicate rejection (Req 8.5)
    ///
    /// If `device_key` **already has an `Active` credential under `identity_id`**, the
    /// request is rejected with [`DeviceDuplicate`](IdentityError::DeviceDuplicate) and
    /// the existing credential is left **unchanged** (no mutation on the rejection path,
    /// preserving atomic-failure / no-side-effects). A device key whose only credential
    /// under this identity is `Revoked` may be re-enrolled: a fresh `Active` credential
    /// replaces the revoked one.
    ///
    /// # Authentication is the caller's job (Req 8.4)
    ///
    /// This method does **not** check *who* may enroll. `Identity_Core` (task 11)
    /// authenticates the signed operation and rejects an unauthorized signer with
    /// [`UnauthorizedActor`](IdentityError::UnauthorizedActor) *before* calling here.
    ///
    /// # Device-type validity (Req 8.6)
    ///
    /// The [`DeviceType`] argument is already type-safe, so an invalid type cannot reach
    /// this method. Raw external device-type tags are validated at the boundary via
    /// [`parse_device_type`] (which yields
    /// [`DeviceTypeInvalid`](IdentityError::DeviceTypeInvalid) for an unknown tag).
    pub fn enroll(
        &mut self,
        identity_id: &IdentityId,
        device_key: &VerifyingKey,
        device_type: DeviceType,
        registered_at: Timestamp,
    ) -> IdentityResult<DeviceId> {
        let device_id = DeviceId::derive(device_key);

        // Duplicate (Req 8.5): same device key already ACTIVE under this identity.
        // Checked WITHOUT mutating, so a rejected enroll leaves state untouched.
        let already_active = self
            .credentials
            .get(identity_id)
            .and_then(|per_identity| per_identity.get(&device_id))
            .is_some_and(DeviceCredential::is_active);
        if already_active {
            return Err(IdentityError::DeviceDuplicate);
        }

        let credential = DeviceCredential {
            device_id: device_id.clone(),
            identity_id: identity_id.clone(),
            device_key: device_key.clone(),
            device_type,
            registered_at,
            status: DeviceStatus::Active,
        };

        // Insert (or replace a previously revoked credential for the same device key).
        self.credentials
            .entry(identity_id.clone())
            .or_default()
            .insert(device_id.clone(), credential);

        Ok(device_id)
    }

    /// Returns the [`DeviceCredential`] for `device_key` under `identity_id`, if any
    /// (regardless of status). A small read helper used by tests and later tasks.
    #[inline]
    pub fn credential(
        &self,
        identity_id: &IdentityId,
        device_id: &DeviceId,
    ) -> Option<&DeviceCredential> {
        self.credentials
            .get(identity_id)
            .and_then(|per_identity| per_identity.get(device_id))
    }

    /// Lists **all** of `identity_id`'s device credentials, each with its **current**
    /// [`DeviceStatus`] (design *Device_Registry*: `list`; Req 9.1).
    ///
    /// The credentials are returned in deterministic [`DeviceId`] order (the per-identity
    /// `BTreeMap`'s iteration order), so two equal registries always list identically.
    /// Both `Active` and `Revoked` credentials are included — the caller sees every bound
    /// device and its state. An **unknown** identity (one that never enrolled a device)
    /// yields an empty `Vec` (Req 9.1).
    ///
    /// Cloning the records keeps [`DeviceCredential`]'s fields immutable to callers
    /// (mirroring the accessor-only design); this is a read-only query with **no** state
    /// change (design *Error Handling*: "查询无副作用").
    pub fn list(&self, identity_id: &IdentityId) -> Vec<DeviceCredential> {
        self.credentials
            .get(identity_id)
            .map(|per_identity| per_identity.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Revokes the credential `device_id` under `identity_id`, setting its status to
    /// [`Revoked`](DeviceStatus::Revoked) (design *Device_Registry*: `revoke`; Req 9.2).
    ///
    /// # Idempotence (Req 9.4)
    ///
    /// Revocation is **idempotent** (design *Error Handling*: "幂等吊销"):
    ///
    /// - An `Active` credential flips to `Revoked` and `Ok(())` is returned (Req 9.2).
    /// - Re-revoking an **already-`Revoked`** credential is a no-op: the status stays
    ///   `Revoked`, **no** other field (or any other credential) changes, and `Ok(())` is
    ///   returned (Req 9.4).
    /// - Revoking a credential that **does not exist** — an unknown `identity_id`, or an
    ///   unknown `device_id` under a known identity — is likewise an idempotent `Ok(())`
    ///   no-op. The post-condition (that device is not an `Active` credential of this
    ///   identity) already holds, the design defines no "device not found" error code,
    ///   and this keeps `revoke` total and side-effect-free on every non-mutating path.
    ///
    /// Only the targeted credential's `status` is ever touched; `device_id`,
    /// `identity_id`, `device_key`, `device_type` and `registered_at` are preserved, and
    /// no other identity or credential is affected.
    ///
    /// # Authentication & disempowerment are the caller's job (Req 9.5, 9.3)
    ///
    /// This method does **not** check *who* may revoke. `Identity_Core` (task 11)
    /// authenticates the signed operation and rejects an unauthorized signer with
    /// [`UnauthorizedActor`](IdentityError::UnauthorizedActor) (Req 9.5) before calling
    /// here. Refusing operations later signed by a `Revoked` device key (Req 9.3) is also
    /// enforced in `Identity_Core`'s authorization step, which reads the status this
    /// method records.
    pub fn revoke(
        &mut self,
        identity_id: &IdentityId,
        device_id: &DeviceId,
    ) -> IdentityResult<()> {
        // Idempotent: only flip an Active credential. Already-Revoked or non-existent
        // credentials leave state completely untouched and still return Ok (Req 9.4).
        if let Some(credential) = self
            .credentials
            .get_mut(identity_id)
            .and_then(|per_identity| per_identity.get_mut(device_id))
        {
            if credential.status == DeviceStatus::Active {
                credential.status = DeviceStatus::Revoked;
            }
        }
        Ok(())
    }
}

/// The six canonical external tags accepted by [`parse_device_type`], paired with the
/// [`DeviceType`] each maps to (design Req 8 enum: 手机/电脑/手表/机器人/车机 HMI/云端 SDK).
///
/// Kept as a single source of truth so the accepted tag set and the round-trip
/// [`device_type_tag`] stay in lock-step.
const DEVICE_TYPE_TAGS: [(&str, DeviceType); 6] = [
    ("phone", DeviceType::Phone),
    ("computer", DeviceType::Computer),
    ("watch", DeviceType::Watch),
    ("robot", DeviceType::Robot),
    ("car_hmi", DeviceType::CarHmi),
    ("cloud_sdk", DeviceType::CloudSdk),
];

/// Maps a raw external device-type `tag` to its [`DeviceType`], enforcing Req 8.6 at the
/// parsing boundary.
///
/// Because [`DeviceType`] is a type-safe enum, an out-of-enum value is unrepresentable in
/// Rust; this helper is where the [`DeviceTypeInvalid`](IdentityError::DeviceTypeInvalid)
/// path lives, so `Identity_Core` / the API layer can validate untyped input before it
/// ever reaches [`DeviceRegistry::enroll`]. It accepts exactly the six canonical tags
/// (`"phone"`, `"computer"`, `"watch"`, `"robot"`, `"car_hmi"`, `"cloud_sdk"`) and
/// returns `Err(DeviceTypeInvalid)` for anything else — creating **no** credential
/// (Req 8.6).
pub fn parse_device_type(tag: &str) -> IdentityResult<DeviceType> {
    DEVICE_TYPE_TAGS
        .iter()
        .find(|(candidate, _)| *candidate == tag)
        .map(|(_, device_type)| *device_type)
        .ok_or(IdentityError::DeviceTypeInvalid)
}

/// The canonical external tag for a [`DeviceType`] — the inverse of [`parse_device_type`]
/// (`parse_device_type(device_type_tag(dt)) == Ok(dt)` for every `dt`).
pub fn device_type_tag(device_type: DeviceType) -> &'static str {
    DEVICE_TYPE_TAGS
        .iter()
        .find(|(_, candidate)| *candidate == device_type)
        .map(|(tag, _)| *tag)
        // Exhaustive by construction: DEVICE_TYPE_TAGS covers all six DeviceType variants.
        .expect("DEVICE_TYPE_TAGS covers every DeviceType variant")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_id::derive_identity_id;
    use crate::scheme::SchemeRegistry;
    use crate::types::SchemeTag;

    /// A valid 32-byte ed25519 verifying key whose bytes vary with `seed` (distinct
    /// seeds → distinct keys → distinct `IdentityId`/`DeviceId`).
    fn vk(seed: u8) -> VerifyingKey {
        let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        VerifyingKey::new(bytes)
    }

    /// Derives the ed25519 `IdentityId` for `key` under the default registry.
    fn id_of(key: &VerifyingKey) -> IdentityId {
        derive_identity_id(&SchemeRegistry::default(), &SchemeTag::ed25519(), key)
            .expect("valid ed25519 vk")
    }

    // --- enroll: creates an Active credential (Req 8.1, 8.3) ---------------

    #[test]
    fn enroll_creates_active_credential_recording_id_type_and_time() {
        // Property 12: an enroll creates an Active credential whose device_id is derived
        // from the device key and which records type, registration time and status.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let device_key = vk(50);
        let registered_at = Timestamp::from_secs(1_234);

        let device_id = registry
            .enroll(&identity, &device_key, DeviceType::Phone, registered_at)
            .expect("first enroll succeeds");

        // device_id is the deterministic fingerprint of the device key (Req 8.3).
        assert_eq!(device_id, DeviceId::derive(&device_key));

        let credential = registry
            .credential(&identity, &device_id)
            .expect("credential stored");
        assert_eq!(credential.device_id(), &device_id);
        assert_eq!(credential.identity_id(), &identity);
        assert_eq!(credential.device_key(), &device_key);
        assert_eq!(credential.device_type(), DeviceType::Phone);
        assert_eq!(credential.registered_at(), registered_at);
        assert_eq!(credential.status(), DeviceStatus::Active);
        assert!(credential.is_active());
    }

    // --- enroll: same identity, many devices (Req 8.2) ---------------------

    #[test]
    fn same_identity_can_enroll_many_distinct_devices() {
        // Req 8.2 / Property 12: one identity may hold many credentials.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let phone = vk(50);
        let computer = vk(51);
        let watch = vk(52);

        let phone_id = registry
            .enroll(&identity, &phone, DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();
        let computer_id = registry
            .enroll(&identity, &computer, DeviceType::Computer, Timestamp::from_secs(2))
            .unwrap();
        let watch_id = registry
            .enroll(&identity, &watch, DeviceType::Watch, Timestamp::from_secs(3))
            .unwrap();

        // Three distinct credentials coexist under the same identity.
        assert_ne!(phone_id, computer_id);
        assert_ne!(computer_id, watch_id);
        assert_eq!(
            registry.credential(&identity, &phone_id).unwrap().device_type(),
            DeviceType::Phone
        );
        assert_eq!(
            registry.credential(&identity, &computer_id).unwrap().device_type(),
            DeviceType::Computer
        );
        assert_eq!(
            registry.credential(&identity, &watch_id).unwrap().device_type(),
            DeviceType::Watch
        );
    }

    // --- enroll: duplicate active device key rejected (Req 8.5) ------------

    #[test]
    fn duplicate_active_device_key_is_rejected_leaving_existing_unchanged() {
        // Property 13: re-enrolling a device key that already has an Active credential
        // under this identity → DeviceDuplicate, existing credential unchanged.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let device_key = vk(50);

        let device_id = registry
            .enroll(&identity, &device_key, DeviceType::Phone, Timestamp::from_secs(10))
            .unwrap();
        let before = registry.clone();

        // A second enroll of the same device key (even with a different type/time) fails.
        let err = registry
            .enroll(&identity, &device_key, DeviceType::Computer, Timestamp::from_secs(99))
            .unwrap_err();
        assert_eq!(err, IdentityError::DeviceDuplicate);

        // The existing credential is unchanged and the whole registry is untouched.
        assert_eq!(registry, before);
        let credential = registry.credential(&identity, &device_id).unwrap();
        assert_eq!(credential.device_type(), DeviceType::Phone);
        assert_eq!(credential.registered_at(), Timestamp::from_secs(10));
    }

    #[test]
    fn same_device_key_under_different_identities_is_not_a_duplicate() {
        // Duplicate is scoped to a single identity (Req 8.5 is "under this identity").
        let mut registry = DeviceRegistry::new();
        let identity_a = id_of(&vk(1));
        let identity_b = id_of(&vk(2));
        let device_key = vk(50);

        let id_a = registry
            .enroll(&identity_a, &device_key, DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();
        // Enrolling the same device key under a DIFFERENT identity is allowed.
        let id_b = registry
            .enroll(&identity_b, &device_key, DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();

        // Same key → same fingerprint, but stored under separate identities.
        assert_eq!(id_a, id_b);
        assert!(registry.credential(&identity_a, &id_a).is_some());
        assert!(registry.credential(&identity_b, &id_b).is_some());
    }

    // --- device-type parsing helper (Req 8.6) ------------------------------

    #[test]
    fn parse_device_type_accepts_the_six_valid_tags() {
        // Property 14 (positive side): the six canonical tags map to their enum values.
        assert_eq!(parse_device_type("phone"), Ok(DeviceType::Phone));
        assert_eq!(parse_device_type("computer"), Ok(DeviceType::Computer));
        assert_eq!(parse_device_type("watch"), Ok(DeviceType::Watch));
        assert_eq!(parse_device_type("robot"), Ok(DeviceType::Robot));
        assert_eq!(parse_device_type("car_hmi"), Ok(DeviceType::CarHmi));
        assert_eq!(parse_device_type("cloud_sdk"), Ok(DeviceType::CloudSdk));

        // Every DeviceType has exactly one accepted tag and round-trips.
        for device_type in DeviceType::ALL {
            assert_eq!(parse_device_type(device_type_tag(device_type)), Ok(device_type));
        }
    }

    #[test]
    fn parse_device_type_rejects_unknown_tag_with_device_type_invalid() {
        // Property 14: any tag outside the prescribed enum → DeviceTypeInvalid.
        for bad in ["", "tablet", "Phone", "PHONE", "carhmi", "cloudsdk", "phone "] {
            assert_eq!(
                parse_device_type(bad),
                Err(IdentityError::DeviceTypeInvalid),
                "tag {bad:?} should be rejected"
            );
        }
    }

    // --- DeviceId derivation ------------------------------------------------

    #[test]
    fn device_id_is_deterministic_and_collision_free() {
        // Equal keys → equal id; distinct keys → distinct id (Req 8.3).
        assert_eq!(DeviceId::derive(&vk(7)), DeviceId::derive(&vk(7)));
        assert_ne!(DeviceId::derive(&vk(7)), DeviceId::derive(&vk(8)));
    }

    // --- list: returns all credentials with current status (Req 9.1) -------

    #[test]
    fn list_of_unknown_identity_is_empty() {
        // Req 9.1: an identity that never enrolled a device lists nothing.
        let registry = DeviceRegistry::new();
        let unknown = id_of(&vk(1));
        assert!(registry.list(&unknown).is_empty());
    }

    #[test]
    fn list_returns_all_credentials_with_their_status() {
        // Req 9.1 / Property 15: list reports every credential and its current status,
        // including a mix of Active and Revoked.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let phone = vk(50);
        let computer = vk(51);
        let watch = vk(52);

        let phone_id = registry
            .enroll(&identity, &phone, DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();
        let computer_id = registry
            .enroll(&identity, &computer, DeviceType::Computer, Timestamp::from_secs(2))
            .unwrap();
        let watch_id = registry
            .enroll(&identity, &watch, DeviceType::Watch, Timestamp::from_secs(3))
            .unwrap();

        // Revoke one of them so the list carries a mix of states.
        registry.revoke(&identity, &computer_id).unwrap();

        let listed = registry.list(&identity);
        assert_eq!(listed.len(), 3);

        // Every enrolled credential is present.
        let ids: Vec<&DeviceId> = listed.iter().map(DeviceCredential::device_id).collect();
        assert!(ids.contains(&&phone_id));
        assert!(ids.contains(&&computer_id));
        assert!(ids.contains(&&watch_id));

        // Each credential reports its current status.
        for credential in &listed {
            let expected = if credential.device_id() == &computer_id {
                DeviceStatus::Revoked
            } else {
                DeviceStatus::Active
            };
            assert_eq!(credential.status(), expected);
        }
    }

    #[test]
    fn list_is_deterministic_in_device_id_order() {
        // Req 9.1: list order is the deterministic BTreeMap (DeviceId) order.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        for (i, seed) in [50u8, 51, 52, 53].into_iter().enumerate() {
            registry
                .enroll(
                    &identity,
                    &vk(seed),
                    DeviceType::Phone,
                    Timestamp::from_secs(i as u64),
                )
                .unwrap();
        }

        let first = registry.list(&identity);
        let second = registry.list(&identity);
        assert_eq!(first, second, "list is stable across calls");

        // Sorted by DeviceId (BTreeMap order).
        let mut sorted = first.clone();
        sorted.sort_by(|a, b| a.device_id().cmp(b.device_id()));
        assert_eq!(first, sorted, "list yields credentials in DeviceId order");
    }

    #[test]
    fn list_is_scoped_to_the_queried_identity() {
        // Req 9.1: an identity's list contains only its own credentials.
        let mut registry = DeviceRegistry::new();
        let identity_a = id_of(&vk(1));
        let identity_b = id_of(&vk(2));
        registry
            .enroll(&identity_a, &vk(50), DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();
        registry
            .enroll(&identity_b, &vk(60), DeviceType::Computer, Timestamp::from_secs(2))
            .unwrap();
        registry
            .enroll(&identity_b, &vk(61), DeviceType::Watch, Timestamp::from_secs(3))
            .unwrap();

        assert_eq!(registry.list(&identity_a).len(), 1);
        assert_eq!(registry.list(&identity_b).len(), 2);
    }

    // --- revoke: Active → Revoked (Req 9.2) --------------------------------

    #[test]
    fn revoke_flips_active_credential_to_revoked() {
        // Property 15: revoking an active credential sets its status to Revoked,
        // touching nothing else on the record.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let device_key = vk(50);
        let device_id = registry
            .enroll(&identity, &device_key, DeviceType::Phone, Timestamp::from_secs(7))
            .unwrap();

        assert!(registry.credential(&identity, &device_id).unwrap().is_active());

        registry.revoke(&identity, &device_id).expect("revoke succeeds");

        let credential = registry.credential(&identity, &device_id).unwrap();
        assert_eq!(credential.status(), DeviceStatus::Revoked);
        assert!(!credential.is_active());
        // Every other field is preserved.
        assert_eq!(credential.device_id(), &device_id);
        assert_eq!(credential.identity_id(), &identity);
        assert_eq!(credential.device_key(), &device_key);
        assert_eq!(credential.device_type(), DeviceType::Phone);
        assert_eq!(credential.registered_at(), Timestamp::from_secs(7));
    }

    #[test]
    fn list_reflects_status_before_and_after_revoke() {
        // Property 15: list faithfully reflects each credential's status at any time.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let device_id = registry
            .enroll(&identity, &vk(50), DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();

        // Before revoke: Active.
        let before = registry.list(&identity);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].status(), DeviceStatus::Active);

        registry.revoke(&identity, &device_id).unwrap();

        // After revoke: Revoked.
        let after = registry.list(&identity);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].status(), DeviceStatus::Revoked);
    }

    // --- revoke: idempotence (Req 9.4) -------------------------------------

    #[test]
    fn re_revoking_an_already_revoked_credential_is_an_idempotent_noop() {
        // Req 9.4 / Property 15: re-revoking keeps the credential Revoked and changes
        // no other state — the whole registry is identical after the redundant call.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let device_id = registry
            .enroll(&identity, &vk(50), DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();

        registry.revoke(&identity, &device_id).expect("first revoke");
        let after_first = registry.clone();

        // Re-revoke twice more: each is Ok and leaves the entire registry unchanged.
        registry.revoke(&identity, &device_id).expect("second revoke is a no-op");
        assert_eq!(registry, after_first);
        registry.revoke(&identity, &device_id).expect("third revoke is a no-op");
        assert_eq!(registry, after_first);

        assert_eq!(
            registry.credential(&identity, &device_id).unwrap().status(),
            DeviceStatus::Revoked
        );
    }

    #[test]
    fn revoke_only_affects_the_targeted_credential() {
        // Req 9.2/9.4: revoking one device leaves the identity's other credentials Active.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        let target = registry
            .enroll(&identity, &vk(50), DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();
        let other = registry
            .enroll(&identity, &vk(51), DeviceType::Computer, Timestamp::from_secs(2))
            .unwrap();

        registry.revoke(&identity, &target).unwrap();

        assert_eq!(
            registry.credential(&identity, &target).unwrap().status(),
            DeviceStatus::Revoked
        );
        assert!(registry.credential(&identity, &other).unwrap().is_active());
    }

    // --- revoke: non-existent credential is an idempotent Ok no-op ---------

    #[test]
    fn revoking_unknown_device_under_known_identity_is_ok_noop() {
        // Documented choice: revoking a device_id that isn't enrolled under a known
        // identity is an idempotent Ok no-op leaving state unchanged.
        let mut registry = DeviceRegistry::new();
        let identity = id_of(&vk(1));
        registry
            .enroll(&identity, &vk(50), DeviceType::Phone, Timestamp::from_secs(1))
            .unwrap();
        let before = registry.clone();

        let phantom = DeviceId::derive(&vk(99));
        registry.revoke(&identity, &phantom).expect("no-op Ok");

        assert_eq!(registry, before, "state unchanged for unknown device");
    }

    #[test]
    fn revoking_under_unknown_identity_is_ok_noop() {
        // Documented choice: revoking under an identity with no credentials is an
        // idempotent Ok no-op leaving state unchanged.
        let mut registry = DeviceRegistry::new();
        let unknown = id_of(&vk(1));
        let before = registry.clone();

        let device_id = DeviceId::derive(&vk(50));
        registry.revoke(&unknown, &device_id).expect("no-op Ok");

        assert_eq!(registry, before, "state unchanged for unknown identity");
        assert!(registry.list(&unknown).is_empty());
    }
}
