//! Unified, machine-identifiable error vocabulary for gmc-identity.
//!
//! Per the design's *Error Handling* section, gmc-identity follows the same single
//! principle as `gmc-core`: **validate up front, fail atomically, leave state
//! unchanged, return a machine-identifiable code**. Every rejected request must
//! produce *no* partial write (no side effects) and return one of the
//! [`IdentityError`] variants below.
//!
//! gmc-identity defines its **own** unified error enum (the identity domain differs
//! from `gmc-core`'s, so it does not reuse [`gmc_core::error::GmcError`]'s variant
//! set), but it deliberately mirrors that type's design paradigm: `#[non_exhaustive]`,
//! a stable machine-readable [`IdentityError::code`], a [`Display`](core::fmt::Display)
//! impl, and `Debug, Clone, PartialEq, Eq` derives.
//!
//! Each variant is annotated with its triggering condition and the requirement /
//! design "Error Handling" table row it maps to. The variants are intentionally
//! data-light at this stage (task 1.2 defines the shared error vocabulary); richer
//! per-variant payloads can be added by the modules that own each rule in later tasks
//! without changing the variant set.

use core::fmt;

/// The single unified error type returned across all gmc-identity modules.
///
/// Deriving `PartialEq`/`Eq` lets tests assert on the exact error code, and `Clone`
/// lets callers retain a code while unwinding. The mapping below mirrors the design's
/// "身份层错误词汇（IdentityError）" (identity-layer error vocabulary) table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    // --- Signature scheme (Signature_Scheme / registry) ---
    /// A request referenced a scheme tag that is not registered in the
    /// `Signature_Scheme` registry.
    /// Reject; state unchanged. _Requirement 1.4._
    SchemeUnsupported,
    /// Key or signature bytes do not satisfy their scheme's `ByteFormat` constraint.
    /// Reject; nothing created / unchanged. _Requirements 1.5, 2.5._
    KeyFormatInvalid,

    // --- Identity id parsing ---
    /// A string is not a valid canonical `IdentityId` form (`fay1.<tag>.<key_repr>`).
    /// Reject; no identity record produced. _Requirement 3.5._
    IdentityIdFormatInvalid,

    // --- Authentication & replay (Identity_Core) ---
    /// Signature verification reported invalid for the signed operation.
    /// Reject; state unchanged. _Requirement 5.3._
    SignatureInvalid,
    /// The operation's `Nonce` is not strictly greater than the applied value.
    /// Reject; state unchanged. _Requirement 5.4._
    ReplayDetected,

    // --- Ownership registry ---
    /// The specified owner exists in neither the ownership registry nor the identity
    /// records.
    /// Reject; no coFay created. _Requirement 6.4._
    OwnerNotFound,
    /// An ownership change would make a coFay its own ancestor (forms a cycle).
    /// Reject; ownership records unchanged. _Requirement 6.5._
    OwnershipCycle,
    /// An attach would push ownership depth beyond 16 (root iFay = depth 0).
    /// Reject; nothing created. _Requirement 6.6._
    OwnershipDepthExceeded,

    // --- Authorization (Authority_Resolver / Identity_Core) ---
    /// The signer is not the owner, an ancestor, a currently-valid delegate, nor an
    /// active (non-revoked / non-retired) key of the target identity.
    /// Reject; state unchanged. _Requirements 7.4, 8.4, 9.5, 11.5, 13.3._
    UnauthorizedActor,

    // --- Device registry ---
    /// The device `VerifyingKey` already has an active credential under this identity.
    /// Reject; existing credential unchanged. _Requirement 8.5._
    DeviceDuplicate,
    /// The `Device_Type` is not one of the prescribed enum values.
    /// Reject; no credential created. _Requirement 8.6._
    DeviceTypeInvalid,

    // --- Identity consistency (Identity_Core) ---
    /// The payload's declared target `IdentityId` differs from the identity the
    /// authenticating key belongs to / is authorized for.
    /// Reject; state unchanged. _Requirement 13.2._
    IdentityMismatch,

    // --- Recovery (Recovery_Service) ---
    /// A guardian recovery threshold is below 1 or above the guardian count.
    /// Reject; existing guardian config unchanged. _Requirement 12.3._
    RecoveryConfigInvalid,
    /// The de-duplicated valid approval count is below the recovery threshold.
    /// Reject; active key unchanged. _Requirement 12.6._
    RecoveryThresholdNotMet,
}

impl IdentityError {
    /// Returns a short, stable machine-readable code for this error.
    ///
    /// Useful for logging and cross-layer error propagation where a compact identifier
    /// is preferable to the `Debug` representation. The codes are stable contract: do
    /// not rename them without a coordinated change across layers.
    pub const fn code(&self) -> &'static str {
        match self {
            IdentityError::SchemeUnsupported => "SchemeUnsupported",
            IdentityError::KeyFormatInvalid => "KeyFormatInvalid",
            IdentityError::IdentityIdFormatInvalid => "IdentityIdFormatInvalid",
            IdentityError::SignatureInvalid => "SignatureInvalid",
            IdentityError::ReplayDetected => "ReplayDetected",
            IdentityError::OwnerNotFound => "OwnerNotFound",
            IdentityError::OwnershipCycle => "OwnershipCycle",
            IdentityError::OwnershipDepthExceeded => "OwnershipDepthExceeded",
            IdentityError::UnauthorizedActor => "UnauthorizedActor",
            IdentityError::DeviceDuplicate => "DeviceDuplicate",
            IdentityError::DeviceTypeInvalid => "DeviceTypeInvalid",
            IdentityError::IdentityMismatch => "IdentityMismatch",
            IdentityError::RecoveryConfigInvalid => "RecoveryConfigInvalid",
            IdentityError::RecoveryThresholdNotMet => "RecoveryThresholdNotMet",
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for IdentityError {}

/// Convenience result alias used across gmc-identity modules.
pub type IdentityResult<T> = Result<T, IdentityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_matches_variant_name() {
        assert_eq!(IdentityError::SchemeUnsupported.code(), "SchemeUnsupported");
        assert_eq!(IdentityError::KeyFormatInvalid.code(), "KeyFormatInvalid");
        assert_eq!(
            IdentityError::IdentityIdFormatInvalid.code(),
            "IdentityIdFormatInvalid"
        );
        assert_eq!(IdentityError::SignatureInvalid.code(), "SignatureInvalid");
        assert_eq!(IdentityError::ReplayDetected.code(), "ReplayDetected");
        assert_eq!(IdentityError::OwnerNotFound.code(), "OwnerNotFound");
        assert_eq!(IdentityError::OwnershipCycle.code(), "OwnershipCycle");
        assert_eq!(
            IdentityError::OwnershipDepthExceeded.code(),
            "OwnershipDepthExceeded"
        );
        assert_eq!(IdentityError::UnauthorizedActor.code(), "UnauthorizedActor");
        assert_eq!(IdentityError::DeviceDuplicate.code(), "DeviceDuplicate");
        assert_eq!(IdentityError::DeviceTypeInvalid.code(), "DeviceTypeInvalid");
        assert_eq!(IdentityError::IdentityMismatch.code(), "IdentityMismatch");
        assert_eq!(
            IdentityError::RecoveryConfigInvalid.code(),
            "RecoveryConfigInvalid"
        );
        assert_eq!(
            IdentityError::RecoveryThresholdNotMet.code(),
            "RecoveryThresholdNotMet"
        );
    }

    #[test]
    fn display_uses_code() {
        assert_eq!(IdentityError::ReplayDetected.to_string(), "ReplayDetected");
        assert_eq!(
            IdentityError::OwnershipDepthExceeded.to_string(),
            IdentityError::OwnershipDepthExceeded.code()
        );
    }

    #[test]
    fn errors_are_comparable_and_cloneable() {
        let a = IdentityError::UnauthorizedActor;
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(IdentityError::OwnerNotFound, IdentityError::OwnershipCycle);
    }

    #[test]
    fn result_alias_round_trips() {
        fn ok() -> IdentityResult<u8> {
            Ok(7)
        }
        fn err() -> IdentityResult<u8> {
            Err(IdentityError::SchemeUnsupported)
        }
        assert_eq!(ok(), Ok(7));
        assert_eq!(err(), Err(IdentityError::SchemeUnsupported));
    }

    #[test]
    fn requirement_13_2_and_12_6_variants_exist() {
        // Requirement 13.2 -> IdentityMismatch, Requirement 12.6 -> RecoveryThresholdNotMet.
        let _r132: IdentityError = IdentityError::IdentityMismatch;
        let _r126: IdentityError = IdentityError::RecoveryThresholdNotMet;
    }
}
