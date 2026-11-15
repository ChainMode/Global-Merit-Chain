//! Unified, machine-identifiable error codes for the GMC pure-logic core.
//!
//! Per the design's *Error Handling* section, error handling follows a single
//! principle: **validate up front, fail atomically, leave state unchanged, return a
//! machine-identifiable code**. Every rejected request must produce *no* partial
//! write (no side effects) and return one of the [`GmcError`] variants below.
//!
//! Each variant is annotated with its triggering condition and the requirement /
//! design "Error Handling" table row it maps to. The variants are intentionally
//! data-light at this stage (task 1.2 defines the shared error vocabulary); richer
//! per-variant payloads can be added by the modules that own each rule in later
//! tasks without changing the variant set.

use core::fmt;

/// The single unified error type returned across all GMC core modules.
///
/// Deriving `PartialEq`/`Eq` lets tests assert on the exact error code, and `Clone`
/// lets callers retain a code while unwinding. The mapping below mirrors the design's
/// "错误分类与处理策略" (error classification & handling) table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GmcError {
    // --- Derivation validation (Chain_Registry) ---
    /// Derivation request named a parent chain that is not in the registry.
    /// Reject; registry unchanged. _Requirement 1.6._
    ParentNotFound,
    /// Request would make a chain its own ancestor (forms a cycle).
    /// Reject; registry unchanged. _Requirement 1.5._
    CycleConflict,
    /// Derivation would push chain depth beyond 16 (GMC_Base = depth 0).
    /// Reject; registry unchanged. _Requirement 1.7._
    DepthExceeded,

    // --- Creation validation (Chain_Registry) ---
    /// Create request is missing the parent-chain id or the domain id.
    /// Reject; nothing created. The offending field is identified by `MissingField`.
    /// _Requirement 2.5._
    MissingField,
    /// `(parentId, domain)` combination already exists.
    /// Reject; existing chain preserved. _Requirement 2.9._
    DomainConflict,
    /// "Steward-initiated" request from an entity lacking steward qualification.
    /// Reject; nothing created. _Requirement 2.7._
    StewardNotQualified,
    /// Institution creation application failed review.
    /// Reject; nothing created. _Requirement 2.8._
    InstitutionReviewFailed,
    /// Organization ID or target subchain is already bound, or the organization ID
    /// prefix is invalid (`realign-cofay-ownership-to-fayid`).
    OrganizationBindingConflict,
    /// Steward identifier is not a natural-person Human ID (e.g. an iFay, coFay, or
    /// Organization ID was supplied as Steward).
    StewardTypeNotAllowed,

    // --- Initial Merit Bootstrap (`define-decaying-bootstrap-parameters`) ---
    /// Cold-start bootstrap parameter configuration violates safety invariants
    /// (e.g. `decay_multiplier < 2`, non-positive caps).
    BootstrapConfigInvalid,
    /// Bootstrap grant exceeds single-grant or per-`opaqueRef` lifetime cap.
    BootstrapCapExceeded,
    /// Bootstrap repeat-grant attempted while per-`opaqueRef` cooldown is still active.
    BootstrapCooldownActive,

    // --- Evaluation mechanism & governance ---
    /// Evaluation mechanism config is invalid (no acquisition mode declared, or the
    /// consensus threshold is outside `(0, 1]`).
    /// Reject; previous valid config preserved. _Requirements 3.3, 3.6._
    MechanismConfigInvalid,
    /// A governed change did not reach this chain's governance threshold.
    /// Reject; current state preserved. _Requirements 3.7, 7.9._
    GovernanceThresholdNotMet,

    // --- Quota accounting ---
    /// Mint would exceed the period quota, or a one-time chain is exhausted.
    /// Reject; counter unchanged; one-time quota never restored. _Requirements 4.3, 4.7._
    QuotaExceeded,
    /// Quota/refresh-period config is invalid (quota not a positive finite value, or
    /// an illegal refresh period).
    /// Reject the config. _Requirements 4.1, 4.8._
    QuotaConfigInvalid,

    // --- Scoring engine ---
    /// Contribution cannot be classified into any of the three dimensions.
    /// Reject scoring; mint nothing. _Requirement 6.6._
    DimensionUnmatched,
    /// Dimension weights do not sum to exactly 100% (1).
    /// Reject scoring; mint nothing. _Requirement 6.7._
    WeightSumInvalid,
    /// An inflation index falls outside its dimension's allowed range
    /// (Thought (1.00, 10.00]; Training [0.95, 1.05]; Technique [0.01, 1.00]).
    /// Reject the config; the dimension's prior value is preserved. _Requirement 7.8._
    InflationIndexOutOfRange,

    // --- Minting ---
    /// Computed mint amount is not strictly positive (`amount <= 0`).
    /// Reject; no batch created; curMerit/minMerit unchanged. _Requirement 8.7._
    InvalidMintAmount,

    // --- Registration & recording ---
    /// Registration application is missing a required field or its description
    /// exceeds 2000 characters.
    /// Reject; no registration created. _Requirement 9.2._
    FieldValidation,
    /// A contribution record has no matching valid registration and is not going
    /// through the retroactive path.
    /// Reject the record. _Requirement 9.4._
    NotRegistered,

    // --- Retroactive review & evidence ---
    /// Evidence reference fails replayability validation / cannot be independently
    /// verified by reviewers.
    /// Reject; do not enter voting. _Requirements 10.8, 12.4._
    EvidenceInvalid,
    /// Retroactive declaration's weighted approval is below the (stricter) retro
    /// threshold.
    /// Mark rejected; mint nothing. _Requirement 10.5._
    RetroThresholdNotMet,

    // --- Anti-fraud / voter selection ---
    /// Fewer than 7 stakeholders remain after excluding high-intimacy entities.
    /// Defer voting; mint nothing. _Requirement 11.3._
    StakeholderInsufficient,
    /// A monetary-exchange / purchase-of-recognition request, or any other
    /// disallowed operation, was received.
    /// Reject; mint nothing; recognition results unchanged. _Requirement 11.8._
    OperationNotAllowed,

    // --- Carbon-credit scenario ---
    /// The referenced carbon-credit voucher is already marked converted.
    /// Reject; mint nothing; consume no quota. _Requirement 12.6._
    DoubleConversion,

    // --- L1/L2 layering ---
    /// L1 failed to verify a batch's zero-knowledge proof.
    /// Reject the batch state update; retain the previous confirmed state root.
    /// _Requirement 13.8._
    ProofVerificationFailed,

    // --- Social relationship graph & inheritance (Blueprint Ch. 7, Ch. 10) ---
    /// Relationship was registered after the target governance/inheritance event
    /// (`registered_at > event_at`), violating mandatory pre-event registration.
    RetroactiveRelationshipDisallowed,
    /// Relationship lacks bilateral confirmation from both endpoints, or self-loop was supplied.
    RelationshipNotConfirmed,
    /// Natural-person (`iFay`) inheritance attempted with intimacy `< 0.1`.
    InsufficientIntimacyForInheritance,

    // --- Penalty & appeal governance (Blueprint Ch. 9) ---
    /// Complaint is missing a valid target `batch_id` or canonical `evidence_hash`,
    /// or the target batch does not exist in the respondent's pocket.
    ComplaintInvalid,
    /// Complainant attempted to file a new complaint while their cooldown window is active.
    ComplaintCooldownActive,
    /// Complainant lacks the minimum `curMerit` floor or has reached the dismissed-complaint strike cap.
    MaliciousComplainantBlocked,
    /// Stakeholder admissibility vote failed or penalty execution was attempted before admissibility passed.
    AdmissibilityNotMet,
    /// Appeal submitted after the post-penalty appeal window expired or on a non-penalized case.
    AppealWindowExpired,
    /// Appeal resolution attempted without a strictly expanded wider-community electorate.
    AppealElectorateNotExpanded,
}

impl GmcError {
    /// Returns a short, stable machine-readable code for this error.
    ///
    /// Useful for logging, anchoring, and cross-layer error propagation where a
    /// compact identifier is preferable to the `Debug` representation.
    pub const fn code(&self) -> &'static str {
        match self {
            GmcError::ParentNotFound => "ParentNotFound",
            GmcError::CycleConflict => "CycleConflict",
            GmcError::DepthExceeded => "DepthExceeded",
            GmcError::MissingField => "MissingField",
            GmcError::DomainConflict => "DomainConflict",
            GmcError::StewardNotQualified => "StewardNotQualified",
            GmcError::InstitutionReviewFailed => "InstitutionReviewFailed",
            GmcError::OrganizationBindingConflict => "OrganizationBindingConflict",
            GmcError::StewardTypeNotAllowed => "StewardTypeNotAllowed",
            GmcError::BootstrapConfigInvalid => "BootstrapConfigInvalid",
            GmcError::BootstrapCapExceeded => "BootstrapCapExceeded",
            GmcError::BootstrapCooldownActive => "BootstrapCooldownActive",
            GmcError::MechanismConfigInvalid => "MechanismConfigInvalid",
            GmcError::GovernanceThresholdNotMet => "GovernanceThresholdNotMet",
            GmcError::QuotaExceeded => "QuotaExceeded",
            GmcError::QuotaConfigInvalid => "QuotaConfigInvalid",
            GmcError::DimensionUnmatched => "DimensionUnmatched",
            GmcError::WeightSumInvalid => "WeightSumInvalid",
            GmcError::InflationIndexOutOfRange => "InflationIndexOutOfRange",
            GmcError::InvalidMintAmount => "InvalidMintAmount",
            GmcError::FieldValidation => "FieldValidation",
            GmcError::NotRegistered => "NotRegistered",
            GmcError::EvidenceInvalid => "EvidenceInvalid",
            GmcError::RetroThresholdNotMet => "RetroThresholdNotMet",
            GmcError::StakeholderInsufficient => "StakeholderInsufficient",
            GmcError::OperationNotAllowed => "OperationNotAllowed",
            GmcError::DoubleConversion => "DoubleConversion",
            GmcError::ProofVerificationFailed => "ProofVerificationFailed",
            GmcError::RetroactiveRelationshipDisallowed => "RetroactiveRelationshipDisallowed",
            GmcError::RelationshipNotConfirmed => "RelationshipNotConfirmed",
            GmcError::InsufficientIntimacyForInheritance => "InsufficientIntimacyForInheritance",
            GmcError::ComplaintInvalid => "ComplaintInvalid",
            GmcError::ComplaintCooldownActive => "ComplaintCooldownActive",
            GmcError::MaliciousComplainantBlocked => "MaliciousComplainantBlocked",
            GmcError::AdmissibilityNotMet => "AdmissibilityNotMet",
            GmcError::AppealWindowExpired => "AppealWindowExpired",
            GmcError::AppealElectorateNotExpanded => "AppealElectorateNotExpanded",
        }
    }
}

impl fmt::Display for GmcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for GmcError {}

/// Convenience result alias used across GMC core modules.
pub type GmcResult<T> = Result<T, GmcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_matches_variant_name() {
        assert_eq!(GmcError::DimensionUnmatched.code(), "DimensionUnmatched");
        assert_eq!(GmcError::WeightSumInvalid.code(), "WeightSumInvalid");
        assert_eq!(
            GmcError::ProofVerificationFailed.code(),
            "ProofVerificationFailed"
        );
    }

    #[test]
    fn display_uses_code() {
        assert_eq!(GmcError::QuotaExceeded.to_string(), "QuotaExceeded");
    }

    #[test]
    fn errors_are_comparable_and_cloneable() {
        let a = GmcError::ParentNotFound;
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(GmcError::ParentNotFound, GmcError::CycleConflict);
    }

    #[test]
    fn requirements_6_6_and_6_7_variants_exist() {
        // Requirement 6.6 -> DimensionUnmatched, Requirement 6.7 -> WeightSumInvalid.
        let _r66: GmcError = GmcError::DimensionUnmatched;
        let _r67: GmcError = GmcError::WeightSumInvalid;
    }
}
