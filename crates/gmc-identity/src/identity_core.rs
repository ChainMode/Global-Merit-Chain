//! `Identity_Core` — the single state-mutation entry point for signed operations.
//!
//! This module implements the design's *Identity_Core（身份内核）* component and the
//! *Data Models → 已签名操作* / *状态聚合* records. `Identity_Core` is the **only**
//! path through which identity state may change (design decision 1 / Requirement 13.1):
//! every mutating request is packaged as a [`SignedOperation`] and run through a
//! **fixed validation chain** before any state is touched:
//!
//! ```text
//! 方案 → 密钥/签名格式 → 验签 → 授权 → 身份一致性 → Nonce → 单一原子提交
//! ```
//!
//! ## Split across tasks 11.1 / 11.2
//!
//! - **Task 11.1 (this task)** lands the operation data model and the **first half** of
//!   the chain: [`OperationPayload`], [`SignedOperation`], the deterministic
//!   [`canonical_encode_operation`] signing-message encoder, the
//!   [`SignedOperation::verify_signature`] check (scheme → key/signature format →
//!   verify), and the forward-compatible [`IdentityState`] aggregate that the rest of
//!   the chain will commit into.
//! - **Task 11.2** appends the **second half** — derive the actor's `IdentityId`,
//!   `authorize` (via [`crate::authority::authorizes`]) → identity match → Nonce replay
//!   guard → single atomic commit to [`IdentityState`] + `applied_nonce` update — onto
//!   the exact structure established here (see [`IdentityState`]'s docs for the shape it
//!   leaves for that task).
//!
//! ## Why a length-prefixed canonical encoding (and not a hash / a new dependency)
//!
//! The signed message must **bind** the declared target, the payload and the Nonce so
//! that a signature can only ever apply to exactly one (target, payload, nonce) triple
//! (Requirement 5.2). Mirroring the rest of this crate's "std-only, no new dependency"
//! posture, [`canonical_encode_operation`] uses a **deterministic, unambiguous,
//! length-prefixed** byte encoding: every variable-length field is preceded by its
//! exact `u64` big-endian length and every enum is preceded by a discriminant byte, so
//! two distinct inputs can never serialize to the same bytes (no field-boundary
//! ambiguity). Changing **any** field — the target's scheme tag or key repr, any
//! payload field, the payload variant, or the nonce — changes the encoded bytes, and
//! therefore the signature.

use crate::authority::{authorizes, DelegateStore};
use crate::error::{IdentityError, IdentityResult};
use crate::identity_id::{derive_identity_id, IdentityId};
use crate::identity_service::IdentityService;
use crate::ownership::OwnershipRegistry;
use crate::pocket::PocketBinding;
use crate::scheme::SchemeRegistry;
use crate::signer::Verifier;
use crate::types::{DeviceType, Nonce, SchemeTag, Signature, Timestamp, VerifyingKey};

/// The payload of a signed identity operation (design *Data Models → 已签名操作*:
/// `OperationPayload`).
///
/// Each variant names a state change that must be authenticated by `Identity_Core`
/// before it is applied. The concrete state mutations for each variant are owned by the
/// respective modules (`Identity_Service`, `Device_Registry`, `Authority_Resolver`,
/// `Recovery_Service`) and wired up in later tasks; this enum is the closed set of
/// operations the canonical encoder and the validation chain understand.
///
/// `Eq`/`PartialEq` are derived so tests can assert payload equality and so the
/// canonical encoding can be checked to change whenever a payload field changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationPayload {
    /// Create a coFay owned by the operation's target, with the given initial verifying
    /// key (Requirement 6.1).
    CreateCoFay {
        /// The initial verifying key of the new coFay.
        new_cofay_key: VerifyingKey,
    },
    /// Enroll a device credential under the target identity (Requirement 8.1).
    EnrollDevice {
        /// The device's verifying key.
        device_key: VerifyingKey,
        /// The device's prescribed terminal class (Requirement 8.6).
        device_type: DeviceType,
    },
    /// Revoke a device credential of the target identity by its device id
    /// (Requirement 9.2).
    RevokeDevice {
        /// The deterministic device id (fingerprint of the device verifying key).
        device_id: String,
    },
    /// Add a delegate verifying key to the target coFay (Requirement 7.2).
    AddDelegate {
        /// The delegate verifying key to authorize.
        delegate: VerifyingKey,
    },
    /// Revoke a delegate verifying key of the target coFay (Requirement 7.3).
    RevokeDelegate {
        /// The delegate verifying key to revoke.
        delegate: VerifyingKey,
    },
    /// Rotate the target identity's active key to a new verifying key (Requirement
    /// 11.1), keeping its `IdentityId` unchanged (Requirement 11.2).
    RotateKey {
        /// The new active verifying key.
        new_key: VerifyingKey,
    },
    /// Configure the target iFay's social-recovery guardians and threshold
    /// (Requirements 12.1–12.3).
    ConfigureGuardians {
        /// The guardian verifying keys.
        guardians: Vec<VerifyingKey>,
        /// The recovery threshold `M` (requires `1 ≤ M ≤ N`).
        threshold: u32,
    },
    /// Submit one guardian's approval toward recovering the target identity to a new
    /// key (Requirements 12.4–12.6).
    RecoveryApproval {
        /// The proposed new active verifying key being recovered to.
        new_key: VerifyingKey,
        /// The approving guardian's verifying key.
        guardian_key: VerifyingKey,
    },
}

/// A signed identity operation submitted to `Identity_Core` (design *Data Models →
/// 已签名操作*: `SignedOperation`).
///
/// The signature is over the [`canonical_encode_operation`] of
/// `(declared_target, payload, nonce)`, so it binds all three together (Requirement
/// 5.2). `scheme_tag` selects the signature scheme whose byte-format constraints the
/// `verifying_key` / `signature` must satisfy, and under which the [`Verifier`]
/// interprets them.
///
/// Fields are public because this is a transport/data record (mirroring the public
/// [`crate::identity_service::Identity`] record); construction never validates — all
/// validation happens in the `Identity_Core` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOperation {
    /// The identity the payload declares it targets (Requirement 13.2).
    pub declared_target: IdentityId,
    /// The operation to perform.
    pub payload: OperationPayload,
    /// A per-identity monotonic operation counter for replay protection (Requirement
    /// 5.2).
    pub nonce: Nonce,
    /// The signature scheme of `verifying_key` / `signature`.
    pub scheme_tag: SchemeTag,
    /// The signer's verifying key.
    pub verifying_key: VerifyingKey,
    /// The signature over `canonical_encode_operation(declared_target, payload, nonce)`.
    pub signature: Signature,
}

impl SignedOperation {
    /// Builds a [`SignedOperation`] from its parts (no validation; the `Identity_Core`
    /// chain validates).
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        declared_target: IdentityId,
        payload: OperationPayload,
        nonce: Nonce,
        scheme_tag: SchemeTag,
        verifying_key: VerifyingKey,
        signature: Signature,
    ) -> Self {
        SignedOperation {
            declared_target,
            payload,
            nonce,
            scheme_tag,
            verifying_key,
            signature,
        }
    }

    /// Returns the canonical signing message for this operation — the exact bytes a
    /// signature over it must cover (see [`canonical_encode_operation`]).
    #[inline]
    pub fn canonical_message(&self) -> Vec<u8> {
        canonical_encode_operation(&self.declared_target, &self.payload, self.nonce)
    }

    /// Runs the **first half** of the `Identity_Core` fixed validation chain against an
    /// injected `verifier` (design *Identity_Core* `apply`, steps 1–3):
    ///
    /// 1. **Scheme** — resolve `scheme_tag` in `registry`; an unregistered tag is
    ///    rejected with [`IdentityError::SchemeUnsupported`] (Requirement 1.4).
    /// 2. **Key/signature format** — the `verifying_key` and `signature` bytes must
    ///    satisfy the scheme's [`ByteFormat`](crate::scheme::ByteFormat); a violation is
    ///    rejected with [`IdentityError::KeyFormatInvalid`] (Requirement 1.5).
    /// 3. **Verify** — `verifier.verify(verifying_key, canonical_message, signature)`
    ///    must be `true`; otherwise the operation is rejected with
    ///    [`IdentityError::SignatureInvalid`] (Requirement 5.3).
    ///
    /// On success it returns `Ok(())` having touched **no** state — it is a read-only
    /// pure check. The checks run in the design's **fixed order** and fail fast, so the
    /// returned error code is predictable and no later step runs after an earlier one
    /// fails.
    ///
    /// ## What task 11.2 appends
    ///
    /// `IdentityState::apply` (task 11.2) calls this first, then continues the chain on
    /// success: derive the actor `IdentityId` from `(scheme_tag, verifying_key)`,
    /// `authorize` the actor for `declared_target` (→ [`IdentityError::UnauthorizedActor`]),
    /// check the declared target matches the authenticated identity (→
    /// [`IdentityError::IdentityMismatch`]), enforce `nonce > applied_nonce` (→
    /// [`IdentityError::ReplayDetected`]), then perform a single atomic commit to
    /// [`IdentityState`] and update `applied_nonce`.
    ///
    /// The `verifier` is taken as `&V` with `V: Verifier + ?Sized`, so both a concrete
    /// reference (`&ReferenceVerifier`) and a trait object (`&dyn Verifier`, as gmc-node
    /// injects) are accepted.
    pub fn verify_signature<V: Verifier + ?Sized>(
        &self,
        registry: &SchemeRegistry,
        verifier: &V,
    ) -> IdentityResult<()> {
        // (1) Scheme must be registered (Requirement 1.4).
        let descriptor = registry.resolve(&self.scheme_tag)?;
        // (2) Verifying-key and signature bytes must satisfy the scheme's formats
        // (Requirement 1.5). Order: key then signature, matching the design pseudocode.
        descriptor.validate_verifying_key(self.verifying_key.as_bytes())?;
        descriptor.validate_signature(self.signature.as_bytes())?;
        // (3) The signature must verify over the canonical message (Requirement 5.3).
        let msg = self.canonical_message();
        if verifier.verify(&self.verifying_key, &msg, &self.signature) {
            Ok(())
        } else {
            Err(IdentityError::SignatureInvalid)
        }
    }
}

/// Domain-separation header prefixed to every canonical operation encoding.
///
/// A fixed constant prefix ensures these bytes can never be confused with another
/// protocol's signed message. Everything after it is length-prefixed or fixed-width, so
/// a constant header introduces no ambiguity.
const OPERATION_DOMAIN: &[u8] = b"gmc-identity:signed-operation:v1";

// --- payload variant discriminants (stable; do not renumber) ---------------
const TAG_CREATE_COFAY: u8 = 1;
const TAG_ENROLL_DEVICE: u8 = 2;
const TAG_REVOKE_DEVICE: u8 = 3;
const TAG_ADD_DELEGATE: u8 = 4;
const TAG_REVOKE_DELEGATE: u8 = 5;
const TAG_ROTATE_KEY: u8 = 6;
const TAG_CONFIGURE_GUARDIANS: u8 = 7;
const TAG_RECOVERY_APPROVAL: u8 = 8;

/// Appends a length-prefixed byte field: an 8-byte big-endian length, then the bytes.
///
/// The explicit length prefix is what makes the overall encoding **unambiguous**: a
/// decoder (and, more importantly, the binding argument) can never confuse where one
/// variable-length field ends and the next begins, so two distinct field layouts can
/// never produce identical bytes.
#[inline]
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Stable discriminant byte for a [`DeviceType`], so that two `EnrollDevice` operations
/// differing only in device type encode to different bytes.
#[inline]
fn device_type_tag(device_type: DeviceType) -> u8 {
    match device_type {
        DeviceType::Phone => 1,
        DeviceType::Computer => 2,
        DeviceType::Watch => 3,
        DeviceType::Robot => 4,
        DeviceType::CarHmi => 5,
        DeviceType::CloudSdk => 6,
    }
}

/// Appends a payload's discriminant byte and its length-prefixed / fixed-width fields.
fn encode_payload(out: &mut Vec<u8>, payload: &OperationPayload) {
    match payload {
        OperationPayload::CreateCoFay { new_cofay_key } => {
            out.push(TAG_CREATE_COFAY);
            push_len_prefixed(out, new_cofay_key.as_bytes());
        }
        OperationPayload::EnrollDevice {
            device_key,
            device_type,
        } => {
            out.push(TAG_ENROLL_DEVICE);
            push_len_prefixed(out, device_key.as_bytes());
            out.push(device_type_tag(*device_type));
        }
        OperationPayload::RevokeDevice { device_id } => {
            out.push(TAG_REVOKE_DEVICE);
            push_len_prefixed(out, device_id.as_bytes());
        }
        OperationPayload::AddDelegate { delegate } => {
            out.push(TAG_ADD_DELEGATE);
            push_len_prefixed(out, delegate.as_bytes());
        }
        OperationPayload::RevokeDelegate { delegate } => {
            out.push(TAG_REVOKE_DELEGATE);
            push_len_prefixed(out, delegate.as_bytes());
        }
        OperationPayload::RotateKey { new_key } => {
            out.push(TAG_ROTATE_KEY);
            push_len_prefixed(out, new_key.as_bytes());
        }
        OperationPayload::ConfigureGuardians {
            guardians,
            threshold,
        } => {
            out.push(TAG_CONFIGURE_GUARDIANS);
            // Count-prefix the guardian list, then length-prefix each key, so guardian
            // boundaries (and the list length) are unambiguous.
            out.extend_from_slice(&(guardians.len() as u64).to_be_bytes());
            for guardian in guardians {
                push_len_prefixed(out, guardian.as_bytes());
            }
            out.extend_from_slice(&threshold.to_be_bytes());
        }
        OperationPayload::RecoveryApproval {
            new_key,
            guardian_key,
        } => {
            out.push(TAG_RECOVERY_APPROVAL);
            push_len_prefixed(out, new_key.as_bytes());
            push_len_prefixed(out, guardian_key.as_bytes());
        }
    }
}

/// Deterministically encodes the signing message for an operation, binding the declared
/// target, the payload and the Nonce (design *Data Models → 已签名操作*:
/// `msg = canonicalEncode(declared_target ‖ payload ‖ nonce)`; Requirement 5.2).
///
/// Layout:
///
/// 1. the fixed [`OPERATION_DOMAIN`] header;
/// 2. the target's `scheme_tag` and `key_repr`, each as a length-prefixed UTF-8 field
///    (binding **both** components of the [`IdentityId`] independently);
/// 3. the payload: a discriminant byte followed by its length-prefixed / fixed-width
///    fields (see [`encode_payload`]);
/// 4. the `nonce` as 8 bytes big-endian.
///
/// The encoding is **deterministic** (a pure function of its inputs) and
/// **unambiguous** (length-prefixed variable fields + discriminant bytes), so:
/// equal inputs always produce equal bytes, and changing **any** field — the target's
/// scheme tag or key repr, any payload field, the payload variant, or the nonce —
/// always changes the output bytes.
pub fn canonical_encode_operation(
    declared_target: &IdentityId,
    payload: &OperationPayload,
    nonce: Nonce,
) -> Vec<u8> {
    let mut out = Vec::new();
    // (1) Domain separation header.
    out.extend_from_slice(OPERATION_DOMAIN);
    // (2) Declared target: bind both the scheme tag and the key repr separately.
    push_len_prefixed(&mut out, declared_target.scheme_tag().as_str().as_bytes());
    push_len_prefixed(&mut out, declared_target.key_repr().as_bytes());
    // (3) Payload (discriminant + fields).
    encode_payload(&mut out, payload);
    // (4) Nonce, fixed 8 bytes big-endian.
    out.extend_from_slice(&nonce.to_be_bytes());
    out
}

/// The outcome of a successfully-authenticated [`IdentityState::apply`] (design
/// *Identity_Core* `apply` → `Result<Applied, IdentityError>`).
///
/// Task 11.2 wires the **delegate** payload effects (`AddDelegate` / `RevokeDelegate`)
/// and task 11.3 wires the **coFay creation** effect (`CreateCoFay`) fully through to
/// their collaborators; the remaining payload effects are owned by later tasks and
/// surface here as [`Applied::Deferred`] (see [`IdentityState::apply`]). Distinguishing
/// the outcomes lets callers (and tests) tell a committed change apart from an
/// authenticated-but-not-yet-applied operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// An `AddDelegate` payload committed: the delegate key is now Active on the target
    /// (Requirement 7.2) and the target's `applied_nonce` was bumped (Requirement 5.5).
    DelegateAdded,
    /// A `RevokeDelegate` payload committed: the delegate key is now Revoked on the
    /// target (Requirement 7.3) and the target's `applied_nonce` was bumped (5.5).
    DelegateRevoked,
    /// A `CreateCoFay` payload committed: a new coFay was created beneath the target
    /// owner (its `IdentityId` derived, attached under the owner, a `CoFay`-kind record
    /// stored, and its own MeritPocket bound — Requirements 6.1, 6.7) and the **owner's**
    /// `applied_nonce` was bumped (Requirement 5.5). The newly-created coFay's
    /// `IdentityId` is carried so callers can locate it.
    CoFayCreated(IdentityId),
    /// The operation passed the **entire** validation chain (scheme → format → verify →
    /// authorize → identity-match → nonce) but its payload effect is owned by a later
    /// task — `EnrollDevice` / `RevokeDevice` by task 13, and `RotateKey` /
    /// `ConfigureGuardians` / `RecoveryApproval` by task 14.
    ///
    /// To preserve the **atomic / no-partial-write** guarantee (Requirement 13.4), a
    /// deferred operation changes **nothing**: no payload effect *and* no
    /// `applied_nonce` bump. The nonce is intentionally left unconsumed so the operation
    /// can be re-submitted unchanged once the owning task lands its commit.
    Deferred,
}

/// The aggregate identity state `Identity_Core` validates against and commits into
/// (design *Data Models → 状态聚合*: `IdentityState`).
///
/// Fields are kept as **separate, public** collaborators — exactly the borrow-friendly
/// shape [`crate::identity_service`] documents — so the task 11.2 `apply` method can
/// mutate several of them at once: borrowing distinct struct fields
/// (`&self.registry`, `&mut self.ownership`, `&mut self.identities`, …) is allowed by
/// the borrow checker, whereas a method that borrowed all of `self` at once would not
/// compose with the existing creation methods (`IdentityService::create_ifay`, which
/// already takes its sibling registries by reference).
///
/// ## Mapping to the design aggregate
///
/// | design field            | here                                   | landed by |
/// |-------------------------|----------------------------------------|-----------|
/// | `registry`              | [`IdentityState::registry`]            | task 2    |
/// | `identities`            | [`IdentityState::identities`] (service)| task 7    |
/// | `ownership`             | [`IdentityState::ownership`]           | task 9    |
/// | `delegates`             | [`IdentityState::delegates`] (store)   | task 10   |
/// | `binding`               | [`IdentityState::binding`]             | task 6    |
/// | `devices`               | *(future field, task 13)*              | task 13   |
/// | `recovery`              | *(future field, task 14)*              | task 14   |
///
/// `devices` (`Device_Registry`, task 13) and `recovery` (`Recovery_Service`, task 14)
/// are intentionally **not** fields yet — those modules are still placeholders. They
/// will be added here as additional separate fields without reshaping this struct.
///
/// ## What task 11.2 appends
///
/// Task 11.2 adds an `apply(&mut self, op: &SignedOperation, verifier: &V)` method that:
/// 1. calls [`SignedOperation::verify_signature`] (scheme → format → verify);
/// 2. derives the actor `IdentityId` and calls [`crate::authority::authorizes`]
///    against `self.ownership` / `self.delegates`;
/// 3. checks `op.declared_target` matches the authenticated identity;
/// 4. reads `self.identities.get(&target).applied_nonce` and enforces strict
///    monotonicity;
/// 5. on success only, performs the single atomic commit (dispatch on
///    `op.payload`) and sets the target's `applied_nonce = op.nonce`.
///
/// Any earlier failure returns its error code with every field left byte-for-byte
/// unchanged (Requirements 13.1, 13.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityState {
    /// Signature-scheme registry (defaults to one containing `ed25519`).
    pub registry: SchemeRegistry,
    /// Identity records keyed by `IdentityId` (owns the design `identities` map).
    pub identities: IdentityService,
    /// coFay ownership tree (roots, paths, depth/cycle guards).
    pub ownership: OwnershipRegistry,
    /// Per-coFay delegate sets (owns the design `delegates` map).
    pub delegates: DelegateStore,
    /// One-to-one `IdentityId` ↔ `MeritPocket` binding.
    pub binding: PocketBinding,
}

impl IdentityState {
    /// Creates a fresh aggregate: a default [`SchemeRegistry`] (containing `ed25519`)
    /// and empty identity / ownership / delegate / pocket collections.
    #[inline]
    pub fn new() -> Self {
        IdentityState::default()
    }

    /// Runs the **full** `Identity_Core` fixed validation chain for a signed operation
    /// and, only if every step passes, performs a **single atomic commit** to the
    /// aggregate (design *Identity_Core* `apply`; flow 2).
    ///
    /// The chain runs in the design's fixed order and **fails fast** — any earlier
    /// failure returns its machine-identifiable [`IdentityError`] *before* a single byte
    /// of `self` is mutated, so a rejected operation is atomic and side-effect free
    /// (Requirements 5.3, 5.4, 13.1, 13.4; Property 21):
    ///
    /// 1. **Scheme → format → verify** — delegated to
    ///    [`SignedOperation::verify_signature`] (steps 1–3 of the chain). A failure here
    ///    surfaces [`SchemeUnsupported`](IdentityError::SchemeUnsupported) /
    ///    [`KeyFormatInvalid`](IdentityError::KeyFormatInvalid) /
    ///    [`SignatureInvalid`](IdentityError::SignatureInvalid) (Requirement 5.3).
    /// 2. **Authorization** — the actor's [`IdentityId`] is derived from
    ///    `(op.scheme_tag, op.verifying_key)` and the signer is accepted **iff** either:
    ///    - **own-state**: the signer *is* the declared target and is signing with that
    ///      identity's **current active, non-retired** key — i.e. the derived actor id
    ///      equals `op.declared_target` *and* that registered identity's `active_key`
    ///      equals `op.verifying_key` (and the key is not among its `retired_keys`); or
    ///    - **on-behalf**: [`crate::authority::authorizes`] accepts the signer as the
    ///      declared target coFay's owner / ancestor / active (non-revoked) delegate.
    ///
    ///    A signer presenting a never-registered, retired (rotated-out) or revoked key
    ///    matches neither branch and is rejected with
    ///    [`UnauthorizedActor`](IdentityError::UnauthorizedActor) (Requirements 7.4,
    ///    11.4, 13.3).
    /// 3. **Identity match** — the `op.declared_target` must be a coherent, **registered
    ///    identity** in [`self.identities`](IdentityState::identities): the only identity
    ///    the authenticated key can consistently belong to / be authorized for is one
    ///    this layer actually knows. A declared target that is not a registered identity
    ///    (e.g. a signer authorized only by a raw delegate-key match against a phantom
    ///    id) is inconsistent and rejected with
    ///    [`IdentityMismatch`](IdentityError::IdentityMismatch) (Requirement 13.2). This
    ///    also guarantees the target's nonce/record exist for steps 4–5.
    /// 4. **Nonce replay** — `op.nonce` must be **strictly greater** than the target
    ///    identity's `applied_nonce`; otherwise
    ///    [`ReplayDetected`](IdentityError::ReplayDetected) (Requirement 5.4).
    /// 5. **Single atomic commit** — only now is the payload effect applied and the
    ///    target's `applied_nonce` advanced to `op.nonce` (Requirement 5.5).
    ///
    /// ## Wired vs deferred payload commits (this task)
    ///
    /// Tasks 11.2 / 11.3 wire the collaborators that already exist:
    /// - the [`DelegateStore`](crate::authority::DelegateStore):
    ///   [`OperationPayload::AddDelegate`] → [`Applied::DelegateAdded`] and
    ///   [`OperationPayload::RevokeDelegate`] → [`Applied::DelegateRevoked`];
    /// - the [`IdentityService`](crate::identity_service::IdentityService):
    ///   [`OperationPayload::CreateCoFay`] → [`Applied::CoFayCreated`] (task 11.3), via
    ///   [`IdentityService::create_cofay`](crate::identity_service::IdentityService::create_cofay).
    ///
    /// Each committed effect is followed by the **target's** `applied_nonce` bump (for
    /// `CreateCoFay` the target *is* the owner). The delegate mutations are
    /// **infallible**; `create_cofay`'s fallible validation (derive + `attach`) is run
    /// **before** any record/pocket is written, so on an attach failure (owner-not-found
    /// / cycle / depth) **nothing** is created and the nonce is **not** bumped — the
    /// error propagates and the aggregate is left byte-for-byte unchanged
    /// (Requirements 6.4/6.5/6.6, 13.4).
    ///
    /// The remaining payloads pass the entire authentication chain but their state
    /// effects are owned by later tasks, so they commit **nothing** (no effect *and* no
    /// nonce bump) and return [`Applied::Deferred`], preserving the no-partial-write
    /// guarantee until their owners land:
    /// - [`OperationPayload::EnrollDevice`] / [`OperationPayload::RevokeDevice`] → task 13
    ///   (`Device_Registry`);
    /// - [`OperationPayload::RotateKey`] / [`OperationPayload::ConfigureGuardians`] /
    ///   [`OperationPayload::RecoveryApproval`] → task 14 (`Recovery_Service`).
    ///
    /// The committed `CreateCoFay` effect threads a `created_at` [`Timestamp`] into the
    /// new coFay record (Requirement 2.1, reused for coFay), supplied by the caller
    /// alongside the operation.
    ///
    /// The `verifier` is taken as `&V` with `V: Verifier + ?Sized` so both a concrete
    /// reference (`&ReferenceVerifier`) and a trait object (`&dyn Verifier`, as gmc-node
    /// injects) are accepted.
    pub fn apply<V: Verifier + ?Sized>(
        &mut self,
        op: &SignedOperation,
        verifier: &V,
        created_at: Timestamp,
    ) -> IdentityResult<Applied> {
        // (1) Scheme → key/signature format → signature verification. Read-only; on
        // failure returns before any mutation (Requirement 5.3).
        op.verify_signature(&self.registry, verifier)?;

        // (2) Authorization (Requirements 7.4, 11.4, 13.3). Derive the actor id from the
        // authenticated key; `derive_identity_id` re-runs the same scheme/format checks
        // `verify_signature` already passed, so on this path it succeeds — a defensive
        // `Err` simply means the actor matches no own-state identity.
        let actor_id = derive_identity_id(&self.registry, &op.scheme_tag, &op.verifying_key);
        let own_state = matches!(&actor_id, Ok(id) if *id == op.declared_target)
            && self
                .identities
                .get(&op.declared_target)
                .is_some_and(|identity| {
                    identity.active_key == op.verifying_key
                        && !identity.retired_keys.contains(&op.verifying_key)
                });
        let on_behalf = authorizes(
            &op.declared_target,
            &op.scheme_tag,
            &op.verifying_key,
            &self.registry,
            &self.ownership,
            &self.delegates,
        );
        if !(own_state || on_behalf) {
            return Err(IdentityError::UnauthorizedActor);
        }

        // (3) Identity match (Requirement 13.2): the declared target must be a registered
        // identity this layer knows — otherwise it is inconsistent with the identity the
        // authenticated key belongs to / is authorized for. Reading the record here also
        // guarantees the nonce read in (4) and the commit in (5) have a target to act on.
        let applied_nonce = match self.identities.get(&op.declared_target) {
            Some(identity) => identity.applied_nonce,
            None => return Err(IdentityError::IdentityMismatch),
        };

        // (4) Nonce replay guard (Requirement 5.4): strictly-greater-than monotonicity.
        if op.nonce <= applied_nonce {
            return Err(IdentityError::ReplayDetected);
        }

        // (5) Single atomic commit. Every precondition above has passed, so from here we
        // perform exactly one state change and advance the applied nonce (Requirement
        // 5.5). The delegate mutations are infallible, so there is no partial-write
        // window; deferred payloads mutate nothing and leave the nonce unconsumed.
        match &op.payload {
            OperationPayload::AddDelegate { delegate } => {
                self.delegates.add_delegate(&op.declared_target, delegate)?;
                self.set_applied_nonce(&op.declared_target, op.nonce);
                Ok(Applied::DelegateAdded)
            }
            OperationPayload::RevokeDelegate { delegate } => {
                self.delegates.revoke_delegate(&op.declared_target, delegate)?;
                self.set_applied_nonce(&op.declared_target, op.nonce);
                Ok(Applied::DelegateRevoked)
            }
            // CreateCoFay (task 11.3): the declared target is the OWNER. Create the new
            // coFay beneath it via Identity_Service. `create_cofay` validates (derive +
            // attach) BEFORE writing anything, so on any error (KeyFormatInvalid /
            // OwnerNotFound / OwnershipCycle / OwnershipDepthExceeded) NOTHING is created
            // and the `?` propagates with the nonce left unbumped — the aggregate stays
            // byte-for-byte unchanged (Requirements 6.1, 6.7, 13.4). Only on Ok do we
            // bump the owner's applied_nonce (the op targets the owner, Requirement 5.5).
            OperationPayload::CreateCoFay { new_cofay_key } => {
                let cofay_id = self.identities.create_cofay(
                    &self.registry,
                    &mut self.ownership,
                    &mut self.binding,
                    &op.declared_target,
                    new_cofay_key,
                    created_at,
                )?;
                self.set_applied_nonce(&op.declared_target, op.nonce);
                Ok(Applied::CoFayCreated(cofay_id))
            }
            // Deferred to tasks 13 / 14. To preserve atomicity and the no-partial-write
            // guarantee (Requirement 13.4), these commit nothing and do NOT bump
            // `applied_nonce`, so the operation can be re-submitted unchanged once its
            // owning task lands the real effect.
            OperationPayload::EnrollDevice { .. }
            | OperationPayload::RevokeDevice { .. }
            | OperationPayload::RotateKey { .. }
            | OperationPayload::ConfigureGuardians { .. }
            | OperationPayload::RecoveryApproval { .. } => Ok(Applied::Deferred),
        }
    }

    /// Advances the target identity's `applied_nonce` (Requirement 5.5). Called only on
    /// a successful commit, after every precondition has passed and the target is known
    /// to be a registered identity (identity-match step), so the lookup is `Some`.
    #[inline]
    fn set_applied_nonce(&mut self, target: &IdentityId, nonce: Nonce) {
        if let Some(identity) = self.identities.get_mut(target) {
            identity.applied_nonce = nonce;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{ByteFormat, SchemeDescriptor};
    use crate::signer::{reference_keypair, ReferenceSigner, ReferenceVerifier, Signer, REFERENCE_SCHEME_TAG};

    /// A target `IdentityId`; the first-half chain treats it opaquely (no derivation),
    /// so a literal `(tag, key_repr)` is sufficient and keeps tests focused.
    fn target() -> IdentityId {
        IdentityId::new(SchemeTag::ed25519(), "targetkeyrepr")
    }

    /// A `VerifyingKey` from raw bytes.
    fn vk(bytes: Vec<u8>) -> VerifyingKey {
        VerifyingKey::new(bytes)
    }

    /// A registry that registers the deterministic reference scheme so the first-half
    /// chain can resolve it. The reference signature length is `4 + 32 + len(msg)`
    /// (variable), so the signature format is a generous range whose lower bound (36)
    /// still rejects obviously-too-short signatures.
    fn reference_registry() -> SchemeRegistry {
        let mut registry = SchemeRegistry::empty();
        registry
            .register(SchemeDescriptor::new(
                SchemeTag::new(REFERENCE_SCHEME_TAG),
                ByteFormat::exact(32),         // signing key (unused here)
                ByteFormat::exact(32),         // verifying key
                ByteFormat::range(36, 1 << 20), // signature (variable length)
            ))
            .expect("fresh registry");
        registry
    }

    // --- canonical_encode_operation: determinism ---------------------------

    #[test]
    fn canonical_encode_is_deterministic() {
        let t = target();
        let p = OperationPayload::AddDelegate {
            delegate: vk(vec![1u8; 32]),
        };
        let a = canonical_encode_operation(&t, &p, 7);
        let b = canonical_encode_operation(&t, &p, 7);
        assert_eq!(a, b);
        // It always begins with the domain header (non-empty, unambiguous).
        assert!(a.starts_with(OPERATION_DOMAIN));
    }

    // --- canonical_encode_operation: binds every field ---------------------

    #[test]
    fn canonical_encode_binds_target_payload_and_nonce() {
        let t = target();
        let p = OperationPayload::RotateKey {
            new_key: vk(vec![2u8; 32]),
        };
        let base = canonical_encode_operation(&t, &p, 1);

        // Changing the nonce changes the bytes.
        assert_ne!(base, canonical_encode_operation(&t, &p, 2));

        // Changing the target's key_repr changes the bytes.
        let t_key = IdentityId::new(SchemeTag::ed25519(), "otherkeyrepr");
        assert_ne!(base, canonical_encode_operation(&t_key, &p, 1));

        // Changing the target's scheme_tag changes the bytes.
        let t_tag = IdentityId::new(SchemeTag::new("other-scheme"), "targetkeyrepr");
        assert_ne!(base, canonical_encode_operation(&t_tag, &p, 1));

        // Changing a payload field changes the bytes.
        let p_field = OperationPayload::RotateKey {
            new_key: vk(vec![3u8; 32]),
        };
        assert_ne!(base, canonical_encode_operation(&t, &p_field, 1));

        // Changing the payload variant changes the bytes (discriminant byte differs),
        // even when the embedded key bytes match.
        let p_variant = OperationPayload::AddDelegate {
            delegate: vk(vec![2u8; 32]),
        };
        assert_ne!(
            canonical_encode_operation(&t, &p, 1),
            canonical_encode_operation(&t, &p_variant, 1)
        );
    }

    #[test]
    fn canonical_encode_is_unambiguous_across_field_boundaries() {
        let t = target();
        // Two guardian lists with the same concatenated bytes but different boundaries
        // must NOT collide — this is exactly what length-prefixing guarantees.
        let a = OperationPayload::ConfigureGuardians {
            guardians: vec![vk(vec![1, 2]), vk(vec![3])],
            threshold: 1,
        };
        let b = OperationPayload::ConfigureGuardians {
            guardians: vec![vk(vec![1]), vk(vec![2, 3])],
            threshold: 1,
        };
        assert_ne!(
            canonical_encode_operation(&t, &a, 1),
            canonical_encode_operation(&t, &b, 1)
        );

        // The threshold is bound too.
        let a_thr2 = OperationPayload::ConfigureGuardians {
            guardians: vec![vk(vec![1, 2]), vk(vec![3])],
            threshold: 2,
        };
        assert_ne!(
            canonical_encode_operation(&t, &a, 1),
            canonical_encode_operation(&t, &a_thr2, 1)
        );

        // EnrollDevice binds the device type.
        let phone = OperationPayload::EnrollDevice {
            device_key: vk(vec![7u8; 32]),
            device_type: DeviceType::Phone,
        };
        let computer = OperationPayload::EnrollDevice {
            device_key: vk(vec![7u8; 32]),
            device_type: DeviceType::Computer,
        };
        assert_ne!(
            canonical_encode_operation(&t, &phone, 1),
            canonical_encode_operation(&t, &computer, 1)
        );

        // RecoveryApproval distinguishes new_key vs guardian_key (order matters).
        let r1 = OperationPayload::RecoveryApproval {
            new_key: vk(vec![10u8; 32]),
            guardian_key: vk(vec![20u8; 32]),
        };
        let r2 = OperationPayload::RecoveryApproval {
            new_key: vk(vec![20u8; 32]),
            guardian_key: vk(vec![10u8; 32]),
        };
        assert_ne!(
            canonical_encode_operation(&t, &r1, 1),
            canonical_encode_operation(&t, &r2, 1)
        );
    }

    // --- verify_signature: happy path --------------------------------------

    #[test]
    fn correctly_signed_operation_passes_first_half() {
        let registry = reference_registry();
        let (sk, signer_vk) = reference_keypair(b"actor-seed");
        let payload = OperationPayload::AddDelegate {
            delegate: vk(vec![9u8; 32]),
        };
        let nonce = 1;
        let msg = canonical_encode_operation(&target(), &payload, nonce);
        let sig = ReferenceSigner.sign(&sk, &msg).expect("reference sign");

        let op = SignedOperation::new(
            target(),
            payload,
            nonce,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            signer_vk,
            sig,
        );
        assert_eq!(op.verify_signature(&registry, &ReferenceVerifier), Ok(()));
    }

    // --- verify_signature: rejection paths, in fixed-chain order -----------

    #[test]
    fn unsupported_scheme_is_rejected_first() {
        // An empty registry does not contain the reference scheme → SchemeUnsupported,
        // even though the signature would otherwise verify.
        let registry = SchemeRegistry::empty();
        let (sk, signer_vk) = reference_keypair(b"actor-seed");
        let payload = OperationPayload::RotateKey {
            new_key: vk(vec![5u8; 32]),
        };
        let nonce = 3;
        let msg = canonical_encode_operation(&target(), &payload, nonce);
        let sig = ReferenceSigner.sign(&sk, &msg).expect("reference sign");

        let op = SignedOperation::new(
            target(),
            payload,
            nonce,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            signer_vk,
            sig,
        );
        assert_eq!(
            op.verify_signature(&registry, &ReferenceVerifier),
            Err(IdentityError::SchemeUnsupported)
        );
    }

    #[test]
    fn malformed_verifying_key_is_key_format_invalid() {
        let registry = reference_registry();
        let (sk, _signer_vk) = reference_keypair(b"actor-seed");
        let payload = OperationPayload::AddDelegate {
            delegate: vk(vec![1u8; 32]),
        };
        let nonce = 1;
        let msg = canonical_encode_operation(&target(), &payload, nonce);
        let sig = ReferenceSigner.sign(&sk, &msg).expect("reference sign");

        // A 31-byte verifying key violates the reference scheme's exact(32) format.
        let op = SignedOperation::new(
            target(),
            payload,
            nonce,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            vk(vec![0u8; 31]),
            sig,
        );
        assert_eq!(
            op.verify_signature(&registry, &ReferenceVerifier),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    #[test]
    fn malformed_signature_is_key_format_invalid() {
        let registry = reference_registry();
        let (_sk, signer_vk) = reference_keypair(b"actor-seed");
        let payload = OperationPayload::AddDelegate {
            delegate: vk(vec![1u8; 32]),
        };

        // A 4-byte signature is below the reference scheme's range(36, ..) lower bound;
        // the verifying key is valid (32 bytes) so the signature format is the failing
        // step.
        let op = SignedOperation::new(
            target(),
            payload,
            1,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            signer_vk,
            Signature::new(vec![0u8; 4]),
        );
        assert_eq!(
            op.verify_signature(&registry, &ReferenceVerifier),
            Err(IdentityError::KeyFormatInvalid)
        );
    }

    #[test]
    fn bad_signature_over_different_message_is_signature_invalid() {
        let registry = reference_registry();
        let (sk, signer_vk) = reference_keypair(b"actor-seed");
        let payload = OperationPayload::AddDelegate {
            delegate: vk(vec![1u8; 32]),
        };
        let nonce = 1;

        // Sign a DIFFERENT message (different nonce): the signature has a valid format
        // but does not verify against this operation's canonical message.
        let wrong_msg = canonical_encode_operation(&target(), &payload, 999);
        let wrong_sig = ReferenceSigner.sign(&sk, &wrong_msg).expect("reference sign");

        let op = SignedOperation::new(
            target(),
            payload,
            nonce,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            signer_vk,
            wrong_sig,
        );
        assert_eq!(
            op.verify_signature(&registry, &ReferenceVerifier),
            Err(IdentityError::SignatureInvalid)
        );
    }

    #[test]
    fn signature_under_mismatched_key_is_signature_invalid() {
        let registry = reference_registry();
        let (sk, _signer_vk) = reference_keypair(b"actor-seed");
        let (_other_sk, other_vk) = reference_keypair(b"someone-else");
        let payload = OperationPayload::RotateKey {
            new_key: vk(vec![4u8; 32]),
        };
        let nonce = 2;
        let msg = canonical_encode_operation(&target(), &payload, nonce);
        let sig = ReferenceSigner.sign(&sk, &msg).expect("reference sign");

        // Signature is correct over the message, but the operation carries a different
        // (valid-format) verifying key → verification fails.
        let op = SignedOperation::new(
            target(),
            payload,
            nonce,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            other_vk,
            sig,
        );
        assert_eq!(
            op.verify_signature(&registry, &ReferenceVerifier),
            Err(IdentityError::SignatureInvalid)
        );
    }

    // --- IdentityState aggregate -------------------------------------------

    #[test]
    fn identity_state_default_is_composable_and_empty() {
        let state = IdentityState::new();
        // Default registry carries ed25519 (Requirement 1.3); the rest start empty.
        assert!(state.registry.contains(&SchemeTag::ed25519()));
        assert!(state.identities.is_empty());
        assert!(state.ownership.is_empty());
        assert!(state.binding.is_empty());
        assert!(state
            .delegates
            .delegates_of(&IdentityId::new(SchemeTag::ed25519(), "none"))
            .is_empty());
    }

    #[test]
    fn identity_state_fields_are_independently_borrowable() {
        // Documents the borrow-friendly shape task 11.2 relies on: distinct fields can
        // be borrowed simultaneously (here, an immutable registry alongside mutable
        // sibling collaborators).
        let mut state = IdentityState::new();
        let registry = &state.registry;
        assert!(registry.contains(&SchemeTag::ed25519()));
        // Independent mutable borrows of other fields compile alongside `registry`.
        let _ownership = &mut state.ownership;
        let _binding = &mut state.binding;
    }

    // --- IdentityState::apply (task 11.2): full chain + atomic commit ------

    use crate::types::Timestamp;

    /// A fresh aggregate whose scheme registry knows the deterministic reference scheme
    /// (so signed operations under it can be authenticated end-to-end).
    fn reference_state() -> IdentityState {
        IdentityState {
            registry: reference_registry(),
            ..IdentityState::default()
        }
    }

    /// Creates a self-sovereign iFay in `state` under the reference scheme with
    /// `active_key = signer_vk`, returning its derived id. The id is derived from
    /// `(reference tag, signer_vk)`, so a signer presenting `signer_vk` authenticates as
    /// this identity's own active key.
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
    /// the reference signer under `sk`/`signer_vk`.
    fn signed_op(
        target: &IdentityId,
        payload: OperationPayload,
        nonce: Nonce,
        sk: &crate::types::SigningKey,
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

    #[test]
    fn valid_add_delegate_applies_and_bumps_applied_nonce() {
        // A fully-valid AddDelegate signed by the identity's own active key commits the
        // delegate (Requirement 7.2) and advances applied_nonce (Requirement 5.5).
        let mut state = reference_state();
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &signer_vk);
        assert_eq!(state.identities.get(&id).unwrap().applied_nonce, 0);

        let delegate = vk(vec![9u8; 32]);
        let op = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: delegate.clone(),
            },
            1,
            &sk,
            &signer_vk,
        );

        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Ok(Applied::DelegateAdded)
        );
        // The delegate is now active on the target, and applied_nonce advanced to 1.
        assert!(state.delegates.is_active_delegate(&id, &delegate));
        assert_eq!(state.identities.get(&id).unwrap().applied_nonce, 1);
    }

    #[test]
    fn valid_revoke_delegate_applies_and_bumps_applied_nonce() {
        // RevokeDelegate is wired through too: it commits the revocation and bumps nonce.
        let mut state = reference_state();
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &signer_vk);
        let delegate = vk(vec![9u8; 32]);

        let add = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: delegate.clone(),
            },
            1,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&add, &ReferenceVerifier, Timestamp::from_secs(2)),
            Ok(Applied::DelegateAdded)
        );

        let revoke = signed_op(
            &id,
            OperationPayload::RevokeDelegate {
                delegate: delegate.clone(),
            },
            2,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&revoke, &ReferenceVerifier, Timestamp::from_secs(3)),
            Ok(Applied::DelegateRevoked)
        );
        assert!(!state.delegates.is_active_delegate(&id, &delegate));
        assert_eq!(state.identities.get(&id).unwrap().applied_nonce, 2);
    }

    #[test]
    fn replayed_nonce_is_rejected_and_state_unchanged() {
        // Requirement 5.4: a nonce not strictly greater than the applied value →
        // ReplayDetected, with the aggregate left byte-for-byte unchanged.
        let mut state = reference_state();
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &signer_vk);
        let delegate = vk(vec![9u8; 32]);

        let first = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: delegate.clone(),
            },
            5,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&first, &ReferenceVerifier, Timestamp::from_secs(2)),
            Ok(Applied::DelegateAdded)
        );
        assert_eq!(state.identities.get(&id).unwrap().applied_nonce, 5);

        // Snapshot, then replay: nonce 5 is not > applied 5, and nonce 4 is < applied.
        let before = state.clone();
        let replay_equal = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: vk(vec![7u8; 32]),
            },
            5,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&replay_equal, &ReferenceVerifier, Timestamp::from_secs(3)),
            Err(IdentityError::ReplayDetected)
        );
        assert_eq!(state, before, "rejected replay must leave state unchanged");

        let replay_lower = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: vk(vec![7u8; 32]),
            },
            4,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&replay_lower, &ReferenceVerifier, Timestamp::from_secs(4)),
            Err(IdentityError::ReplayDetected)
        );
        assert_eq!(state, before, "rejected replay must leave state unchanged");
    }

    #[test]
    fn unauthorized_signer_is_rejected_and_state_unchanged() {
        // Requirement 13.3 / 7.4: a signer who is neither the target's active key nor an
        // owner / ancestor / active delegate → UnauthorizedActor, state unchanged. The
        // signature itself is valid (so the authorization step is what rejects it).
        let mut state = reference_state();
        let (_owner_sk, owner_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &owner_vk);

        let (stranger_sk, stranger_vk) = reference_keypair(b"stranger-seed");
        let before = state.clone();
        let op = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: vk(vec![9u8; 32]),
            },
            1,
            &stranger_sk,
            &stranger_vk,
        );
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Err(IdentityError::UnauthorizedActor)
        );
        assert_eq!(state, before, "rejected op must leave state unchanged");
    }

    #[test]
    fn retired_key_signer_is_unauthorized_and_state_unchanged() {
        // Requirement 11.4: signing with a key that has been retired (rotated out) is
        // unauthorized even though it once was the active key.
        let mut state = reference_state();
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &signer_vk);
        // Simulate a prior rotation: retire the current active key (active_key stays for
        // this construction, but the key is now also listed as retired → not allowed).
        state
            .identities
            .get_mut(&id)
            .unwrap()
            .retired_keys
            .push(signer_vk.clone());

        let before = state.clone();
        let op = signed_op(
            &id,
            OperationPayload::AddDelegate {
                delegate: vk(vec![9u8; 32]),
            },
            1,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Err(IdentityError::UnauthorizedActor)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn declared_target_not_a_registered_identity_is_identity_mismatch() {
        // Requirement 13.2: an operation authorized only by a raw delegate-key match
        // against a target that is NOT a registered identity is inconsistent →
        // IdentityMismatch, state unchanged.
        let mut state = reference_state();
        // A phantom target id that is never created as an identity.
        let phantom = IdentityId::new(SchemeTag::new(REFERENCE_SCHEME_TAG), "phantomtarget");
        // Authorize a delegate key for the phantom (raw-key membership; no identity).
        let (del_sk, del_vk) = reference_keypair(b"delegate-seed");
        state.delegates.add_delegate(&phantom, &del_vk).unwrap();

        let before = state.clone();
        let op = signed_op(
            &phantom,
            OperationPayload::AddDelegate {
                delegate: vk(vec![3u8; 32]),
            },
            1,
            &del_sk,
            &del_vk,
        );
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Err(IdentityError::IdentityMismatch)
        );
        assert_eq!(state, before, "rejected op must leave state unchanged");
    }

    #[test]
    fn invalid_signature_is_rejected_before_any_mutation() {
        // Requirement 5.3: a signature that does not verify is rejected with
        // SignatureInvalid and no state changes (first-half chain inside apply).
        let mut state = reference_state();
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &signer_vk);

        // Sign a DIFFERENT nonce so the signature does not match this operation's message.
        let payload = OperationPayload::AddDelegate {
            delegate: vk(vec![9u8; 32]),
        };
        let wrong_msg = canonical_encode_operation(&id, &payload, 999);
        let wrong_sig = ReferenceSigner.sign(&sk, &wrong_msg).expect("reference sign");
        let op = SignedOperation::new(
            id.clone(),
            payload,
            1,
            SchemeTag::new(REFERENCE_SCHEME_TAG),
            signer_vk.clone(),
            wrong_sig,
        );

        let before = state.clone();
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Err(IdentityError::SignatureInvalid)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn deferred_payload_authenticates_but_commits_nothing() {
        // A RotateKey (task 14) passes the full authentication chain but its effect is
        // deferred: it returns Applied::Deferred and changes nothing — crucially it does
        // NOT consume the nonce, so the operation can be re-submitted unchanged later
        // (Requirement 13.4 atomicity).
        let mut state = reference_state();
        let (sk, signer_vk) = reference_keypair(b"owner-seed");
        let id = create_reference_ifay(&mut state, &signer_vk);

        let before = state.clone();
        let op = signed_op(
            &id,
            OperationPayload::RotateKey {
                new_key: vk(vec![2u8; 32]),
            },
            1,
            &sk,
            &signer_vk,
        );
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Ok(Applied::Deferred)
        );
        // No effect AND no nonce bump (deferred operations leave the nonce unconsumed).
        assert_eq!(state, before);
        assert_eq!(state.identities.get(&id).unwrap().applied_nonce, 0);
    }

    // --- IdentityState::apply (task 11.3): CreateCoFay via the Identity_Core path ---

    #[test]
    fn valid_create_cofay_creates_cofay_and_bumps_owner_nonce() {
        // Requirements 6.1, 6.7: an authenticated CreateCoFay signed by the OWNER's own
        // active key creates a CoFay-kind identity attached beneath the owner (depth+1),
        // binds its own MeritPocket, bumps the OWNER's applied_nonce, and returns
        // Applied::CoFayCreated carrying the new coFay id.
        let mut state = reference_state();
        let (sk, owner_vk) = reference_keypair(b"owner-seed");
        let owner = create_reference_ifay(&mut state, &owner_vk);
        assert_eq!(state.identities.get(&owner).unwrap().applied_nonce, 0);

        // The new coFay's initial verifying key (any valid 32-byte reference key).
        let new_cofay_key = vk(vec![3u8; 32]);
        let op = signed_op(
            &owner,
            OperationPayload::CreateCoFay {
                new_cofay_key: new_cofay_key.clone(),
            },
            1,
            &sk,
            &owner_vk,
        );

        let created_at = Timestamp::from_secs(1_700_000_000);
        let applied = state
            .apply(&op, &ReferenceVerifier, created_at)
            .expect("authenticated CreateCoFay commits");

        // The returned coFay id is the deterministic derivation under the owner's scheme.
        let cofay_id = match applied {
            Applied::CoFayCreated(id) => id,
            other => panic!("expected CoFayCreated, got {other:?}"),
        };
        let expected = derive_identity_id(
            &state.registry,
            &SchemeTag::new(REFERENCE_SCHEME_TAG),
            &new_cofay_key,
        )
        .unwrap();
        assert_eq!(cofay_id, expected);

        // A CoFay-kind record exists with the right active key / created_at.
        let record = state.identities.get(&cofay_id).expect("coFay recorded");
        assert_eq!(record.kind, crate::types::IdentityKind::CoFay);
        assert_eq!(record.active_key, new_cofay_key);
        assert_eq!(record.created_at, created_at);
        assert_eq!(record.applied_nonce, 0);

        // Attached beneath the owner at depth 1 with its own pocket.
        assert_eq!(state.ownership.owner_of(&cofay_id), Some(&owner));
        assert_eq!(state.ownership.depth_of(&cofay_id), Some(1));
        assert!(state.binding.pocket(&cofay_id).is_some());

        // The OWNER's applied_nonce advanced to the op nonce (the op targets the owner).
        assert_eq!(state.identities.get(&owner).unwrap().applied_nonce, 1);
    }

    #[test]
    fn create_cofay_by_authorized_delegate_of_owner_creates_cofay() {
        // Requirement 7.1: a signer authorized on-behalf of the owner (an active
        // delegate of the owner) may create a coFay under it. Here the owner is itself a
        // coFay with a delegate; the delegate signs the CreateCoFay.
        let mut state = reference_state();
        // Root iFay owns `owner_cofay`.
        let (root_sk, root_vk) = reference_keypair(b"root-seed");
        let root = create_reference_ifay(&mut state, &root_vk);
        let owner_cofay_key = vk(vec![4u8; 32]);
        let create_owner = signed_op(
            &root,
            OperationPayload::CreateCoFay {
                new_cofay_key: owner_cofay_key.clone(),
            },
            1,
            &root_sk,
            &root_vk,
        );
        let owner_cofay = match state
            .apply(&create_owner, &ReferenceVerifier, Timestamp::from_secs(2))
            .unwrap()
        {
            Applied::CoFayCreated(id) => id,
            other => panic!("expected CoFayCreated, got {other:?}"),
        };

        // Authorize a delegate key for the owner coFay (raw-key membership).
        let (del_sk, del_vk) = reference_keypair(b"delegate-seed");
        state.delegates.add_delegate(&owner_cofay, &del_vk).unwrap();

        // The delegate signs a CreateCoFay targeting the owner coFay.
        let new_cofay_key = vk(vec![6u8; 32]);
        let op = signed_op(
            &owner_cofay,
            OperationPayload::CreateCoFay {
                new_cofay_key: new_cofay_key.clone(),
            },
            1,
            &del_sk,
            &del_vk,
        );
        let cofay_id = match state
            .apply(&op, &ReferenceVerifier, Timestamp::from_secs(3))
            .expect("delegate-authorized CreateCoFay commits")
        {
            Applied::CoFayCreated(id) => id,
            other => panic!("expected CoFayCreated, got {other:?}"),
        };

        // The new coFay is attached beneath the owner coFay (depth 2 below the root).
        assert_eq!(state.ownership.owner_of(&cofay_id), Some(&owner_cofay));
        assert_eq!(state.ownership.depth_of(&cofay_id), Some(2));
        // The owner coFay's nonce advanced (the op targets the owner).
        assert_eq!(state.identities.get(&owner_cofay).unwrap().applied_nonce, 1);
    }

    #[test]
    fn create_cofay_with_malformed_key_is_key_format_invalid_and_state_unchanged() {
        // Requirement 2.5 (reused for coFay) / 13.4: a malformed new_cofay_key →
        // KeyFormatInvalid, nothing created, owner nonce NOT bumped, state unchanged.
        let mut state = reference_state();
        let (sk, owner_vk) = reference_keypair(b"owner-seed");
        let owner = create_reference_ifay(&mut state, &owner_vk);

        // A 31-byte key violates the reference scheme's exact(32) verifying-key format.
        let bad_key = vk(vec![0u8; 31]);
        let op = signed_op(
            &owner,
            OperationPayload::CreateCoFay {
                new_cofay_key: bad_key,
            },
            1,
            &sk,
            &owner_vk,
        );

        let before = state.clone();
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(2)),
            Err(IdentityError::KeyFormatInvalid)
        );
        assert_eq!(state, before, "rejected CreateCoFay must leave state unchanged");
        // Owner nonce was not consumed, so the op can be re-submitted once corrected.
        assert_eq!(state.identities.get(&owner).unwrap().applied_nonce, 0);
    }

    #[test]
    fn create_cofay_forming_a_cycle_is_rejected_and_state_unchanged() {
        // Requirement 6.5 / 13.4: re-submitting CreateCoFay for an existing coFay while
        // naming that coFay itself as the owner forms a self-parent cycle →
        // OwnershipCycle, with the aggregate left byte-for-byte unchanged and the
        // (cofay's) nonce unconsumed.
        let mut state = reference_state();
        let (owner_sk, owner_vk) = reference_keypair(b"owner-seed");
        let owner = create_reference_ifay(&mut state, &owner_vk);

        // First, create a coFay normally under the owner; its key authenticates it as
        // its own active key for a self-targeted op.
        let (cofay_sk, cofay_vk) = reference_keypair(b"cofay-seed");
        let create = signed_op(
            &owner,
            OperationPayload::CreateCoFay {
                new_cofay_key: cofay_vk.clone(),
            },
            1,
            &owner_sk,
            &owner_vk,
        );
        let cofay = match state
            .apply(&create, &ReferenceVerifier, Timestamp::from_secs(2))
            .unwrap()
        {
            Applied::CoFayCreated(id) => id,
            other => panic!("expected CoFayCreated, got {other:?}"),
        };

        // Now the coFay (signing with its own active key) tries to create a coFay whose
        // derived id equals itself (same key) under itself as owner → self-parent cycle.
        let op = signed_op(
            &cofay,
            OperationPayload::CreateCoFay {
                new_cofay_key: cofay_vk.clone(),
            },
            1,
            &cofay_sk,
            &cofay_vk,
        );

        let before = state.clone();
        assert_eq!(
            state.apply(&op, &ReferenceVerifier, Timestamp::from_secs(3)),
            Err(IdentityError::OwnershipCycle)
        );
        assert_eq!(state, before, "rejected cyclic CreateCoFay must leave state unchanged");
        assert_eq!(state.identities.get(&cofay).unwrap().applied_nonce, 0);
    }
}
