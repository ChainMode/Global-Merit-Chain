//! Nested merit-chain creation channels — the three ways a `Nested_Merit_Chain`
//! can be brought into existence (design *Requirement 2* / sequence *流程 1：功勋链派生*).
//!
//! Requirement 2 defines **three** initiation channels, each of which — when its
//! upstream gate is satisfied — ends in a single [`ChainRegistry::derive`] call that
//! runs the design's ordered derivation validation (parent exists → no cycle →
//! depth ≤ 16 → `(parent, domain)` unique) and records an [`OriginType`]:
//!
//! 1. **投票发起 / vote-initiated** ([`ChainCreationService::create_by_vote`]): a
//!    creation *proposal* reached the chain's governance threshold
//!    (_Requirement 2.1_). The weighted-tally decision is produced by the
//!    `Governance_Module`; this service consumes the resulting boolean. On a passing
//!    vote it derives with [`OriginType::VoteInitiated`].
//! 2. **主理人发起 / steward-initiated** ([`ChainCreationService::create_by_steward`]):
//!    a *qualified* Steward submitted the request (_Requirement 2.2_). An entity that
//!    lacks steward qualification is rejected with [`GmcError::StewardNotQualified`]
//!    and **nothing is created** (_Requirement 2.7_). On a qualified request it
//!    derives with [`OriginType::StewardInitiated`].
//! 3. **机构申请 / institution-applied** ([`ChainCreationService::create_by_institution`]):
//!    an institution's creation application *passed review* (_Requirement 2.3_). An
//!    application that failed review is rejected with
//!    [`GmcError::InstitutionReviewFailed`] and **nothing is created**
//!    (_Requirement 2.8_). On a passing review it derives with
//!    [`OriginType::InstitutionApplied`].
//!
//! ## Decisions are inputs, not computed here
//!
//! The governance tally (_Req 2.1_), the steward-qualification check (_Req 2.7_) and
//! the institution review (_Req 2.8_) are performed by other modules / the
//! integration layer (`Governance_Module`, identity / qualification services,
//! institutional review). This service is the **pure-logic choke point** that turns
//! each already-made decision into either a derivation (recording the right
//! `originType`) or an atomic rejection. Modelling each decision as a plain `bool`
//! keeps the channel logic deterministic and trivially testable.
//!
//! ## Missing field handling (_Requirement 2.5_)
//!
//! A creation request that omits its parent-chain id or its domain id must be
//! rejected with [`GmcError::MissingField`] and create nothing. Rather than
//! duplicate that check, every channel (once its gate passes) defers to
//! [`ChainRegistry::derive`], which performs the `MissingField` check as the *first*
//! step of its ordered validation. This keeps the missing-field behaviour identical
//! across all three channels and consistent with plain derivation.
//!
//! ## Atomicity & ordering
//!
//! Each channel first consults its upstream gate; a failed gate returns the mapped
//! error **before** any registry mutation, so a rejected request leaves the registry
//! completely unchanged ("validate up front, fail atomically, state unchanged"). When
//! the gate passes, [`ChainRegistry::derive`] is itself atomic, so any derivation-time
//! rejection (`MissingField` / `ParentNotFound` / `CycleConflict` / `DepthExceeded` /
//! `DomainConflict`) likewise leaves the registry untouched.
//!
//! > **L1 anchoring note (_Requirement 2.6_):** the creation record is anchored to L1
//! > via `L1Settlement::anchor_chain_creation` (task 18.1) and wired end-to-end by the
//! > flow-wiring task (20.1). This module performs only the pure-logic gate + derive;
//! > it intentionally does not depend on `l1_settlement`.

use crate::error::{GmcError, GmcResult};
use crate::registry::{ChainRegistry, DeriveRequest, OriginType};
use crate::types::{ChainId, FayID, Timestamp};

/// The channel-agnostic fields needed to create a `Nested_Merit_Chain`.
///
/// This mirrors a [`DeriveRequest`] *minus* its `origin_type`: the `origin_type` is
/// supplied by the channel (vote / steward / institution) so a caller cannot pick a
/// channel and then claim a mismatched origin. The derived chain's `depth` and `path`
/// are intentionally absent — [`ChainRegistry::derive`] computes them from the parent
/// (_Requirements 1.3, 1.7_).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationRequest {
    /// Identifier the new chain should take.
    pub proposed_id: ChainId,
    /// The parent chain to derive under; must be non-empty (_Requirement 2.5_) and
    /// already exist in the registry (_Requirement 1.6_).
    pub parent_id: ChainId,
    /// Domain identifier the new chain will own; must be non-empty (_Requirement 2.5_)
    /// and unique under `parent_id` (_Requirement 2.9_).
    pub domain: String,
    /// Stewards for the new chain; at least one is required (_Requirement 2.4_).
    pub stewards: Vec<FayID>,
    /// On-chain creation time (_Requirement 1.4_).
    pub created_at: Timestamp,
}

impl CreationRequest {
    /// Builds a [`CreationRequest`] from its parts.
    pub fn new(
        proposed_id: ChainId,
        parent_id: ChainId,
        domain: impl Into<String>,
        stewards: Vec<FayID>,
        created_at: Timestamp,
    ) -> Self {
        CreationRequest {
            proposed_id,
            parent_id,
            domain: domain.into(),
            stewards,
            created_at,
        }
    }

    /// Promotes this request into a [`DeriveRequest`] stamped with `origin_type`.
    ///
    /// Each channel calls this with its own [`OriginType`] so the recorded origin is
    /// always consistent with the channel that succeeded (_Requirements 2.1–2.3_).
    fn into_derive_request(self, origin_type: OriginType) -> DeriveRequest {
        DeriveRequest::new(
            self.proposed_id,
            self.parent_id,
            self.domain,
            self.stewards,
            origin_type,
            self.created_at,
        )
    }
}

/// The three nested-chain creation channels (design *Requirement 2*).
///
/// Stateless: every method operates on a borrowed [`ChainRegistry`]; the upstream
/// governance / qualification / review *decision* is passed in as a `bool`. The
/// struct exists purely to group the channels behind one named, documented entry
/// point — free-function callers can use the inherent methods directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainCreationService;

impl ChainCreationService {
    /// **投票发起** — create a chain because a creation proposal reached the chain's
    /// governance threshold (_Requirement 2.1_).
    ///
    /// `governance_passed` is the `Governance_Module`'s weighted-tally outcome for the
    /// creation proposal. When it is `false` the proposal did not reach the threshold,
    /// so the request is rejected with [`GmcError::GovernanceThresholdNotMet`] and
    /// **no chain is created** (the registry is left unchanged). When it is `true` the
    /// request is forwarded to [`ChainRegistry::derive`] with
    /// [`OriginType::VoteInitiated`]; on success the new chain's id is returned and the
    /// `VoteInitiated` origin is recorded.
    pub fn create_by_vote(
        registry: &mut ChainRegistry,
        request: CreationRequest,
        governance_passed: bool,
    ) -> GmcResult<ChainId> {
        if !governance_passed {
            return Err(GmcError::GovernanceThresholdNotMet);
        }
        registry.derive(request.into_derive_request(OriginType::VoteInitiated))
    }

    /// **主理人发起** — create a chain on behalf of a qualified Steward
    /// (_Requirement 2.2_).
    ///
    /// `steward_qualified` is the qualification-check result for the requesting entity.
    /// When it is `false` the entity lacks steward qualification, so the request is
    /// rejected with [`GmcError::StewardNotQualified`] and **no chain is created**
    /// (_Requirement 2.7_). When it is `true` the request is forwarded to
    /// [`ChainRegistry::derive`] with [`OriginType::StewardInitiated`]; on success the
    /// new chain's id is returned and the `StewardInitiated` origin is recorded.
    pub fn create_by_steward(
        registry: &mut ChainRegistry,
        request: CreationRequest,
        steward_qualified: bool,
    ) -> GmcResult<ChainId> {
        if !steward_qualified {
            return Err(GmcError::StewardNotQualified);
        }
        registry.derive(request.into_derive_request(OriginType::StewardInitiated))
    }

    /// **机构申请** — create a chain from an institution's creation application
    /// (_Requirement 2.3_).
    ///
    /// `review_passed` is the institutional review outcome. When it is `false` the
    /// application did not pass review, so the request is rejected with
    /// [`GmcError::InstitutionReviewFailed`] and **no chain is created**
    /// (_Requirement 2.8_). When it is `true` the request is forwarded to
    /// [`ChainRegistry::derive`] with [`OriginType::InstitutionApplied`]; on success
    /// the new chain's id is returned and the `InstitutionApplied` origin is recorded.
    pub fn create_by_institution(
        registry: &mut ChainRegistry,
        request: CreationRequest,
        review_passed: bool,
    ) -> GmcResult<ChainId> {
        if !review_passed {
            return Err(GmcError::InstitutionReviewFailed);
        }
        registry.derive(request.into_derive_request(OriginType::InstitutionApplied))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::NestedMeritChain;

    /// Builds a single-steward `GMC_Base` registry for the channel tests.
    fn registry_with_root() -> ChainRegistry {
        let root = NestedMeritChain::root(
            ChainId::new("gmc-base"),
            "root",
            vec![FayID::new("founder")],
            Timestamp::from_secs(1_000),
        );
        ChainRegistry::with_root(root).expect("root is a valid depth-0 root")
    }

    /// A well-formed creation request deriving `child` under the `gmc-base` root.
    fn request(proposed_id: &str, domain: &str) -> CreationRequest {
        CreationRequest::new(
            ChainId::new(proposed_id),
            ChainId::new("gmc-base"),
            domain,
            vec![FayID::new("steward-1")],
            Timestamp::from_secs(2_000),
        )
    }

    // --- 投票发起 / vote channel (Requirements 2.1) ------------------------

    #[test]
    fn vote_channel_creates_with_vote_initiated_when_passed() {
        let mut registry = registry_with_root();
        let id = ChainCreationService::create_by_vote(
            &mut registry,
            request("academic", "academic"),
            true,
        )
        .expect("a passing vote derives the chain");
        assert_eq!(id, ChainId::new("academic"));
        let chain = registry.get(&id).expect("chain was created");
        assert_eq!(chain.origin_type(), Some(OriginType::VoteInitiated));
    }

    #[test]
    fn vote_channel_rejects_and_creates_nothing_when_not_passed() {
        let mut registry = registry_with_root();
        let before = registry.len();
        let err = ChainCreationService::create_by_vote(
            &mut registry,
            request("academic", "academic"),
            false,
        )
        .expect_err("a failed vote must be rejected");
        assert_eq!(err, GmcError::GovernanceThresholdNotMet);
        // No chain created; registry unchanged.
        assert_eq!(registry.len(), before);
        assert!(!registry.contains(&ChainId::new("academic")));
    }

    // --- 主理人发起 / steward channel (Requirements 2.2, 2.7) --------------

    #[test]
    fn steward_channel_creates_with_steward_initiated_when_qualified() {
        let mut registry = registry_with_root();
        let id = ChainCreationService::create_by_steward(
            &mut registry,
            request("charity", "charity"),
            true,
        )
        .expect("a qualified steward derives the chain");
        let chain = registry.get(&id).expect("chain was created");
        assert_eq!(chain.origin_type(), Some(OriginType::StewardInitiated));
    }

    #[test]
    fn steward_channel_rejects_unqualified_and_creates_nothing() {
        let mut registry = registry_with_root();
        let before = registry.len();
        let err = ChainCreationService::create_by_steward(
            &mut registry,
            request("charity", "charity"),
            false,
        )
        .expect_err("an unqualified steward must be rejected");
        assert_eq!(err, GmcError::StewardNotQualified);
        assert_eq!(registry.len(), before);
        assert!(!registry.contains(&ChainId::new("charity")));
    }

    // --- 机构申请 / institution channel (Requirements 2.3, 2.8) ------------

    #[test]
    fn institution_channel_creates_with_institution_applied_when_review_passes() {
        let mut registry = registry_with_root();
        let id = ChainCreationService::create_by_institution(
            &mut registry,
            request("environment", "environment"),
            true,
        )
        .expect("a passing review derives the chain");
        let chain = registry.get(&id).expect("chain was created");
        assert_eq!(chain.origin_type(), Some(OriginType::InstitutionApplied));
    }

    #[test]
    fn institution_channel_rejects_failed_review_and_creates_nothing() {
        let mut registry = registry_with_root();
        let before = registry.len();
        let err = ChainCreationService::create_by_institution(
            &mut registry,
            request("environment", "environment"),
            false,
        )
        .expect_err("a failed institution review must be rejected");
        assert_eq!(err, GmcError::InstitutionReviewFailed);
        assert_eq!(registry.len(), before);
        assert!(!registry.contains(&ChainId::new("environment")));
    }

    // --- Missing field surfacing (Requirement 2.5) -------------------------

    #[test]
    fn missing_parent_id_surfaces_missing_field_on_each_channel() {
        // Gate passes on every channel; derive must still reject the empty parent_id.
        let make = || {
            CreationRequest::new(
                ChainId::new("orphan"),
                ChainId::new(""), // missing parent id
                "domain",
                vec![FayID::new("steward-1")],
                Timestamp::from_secs(2_000),
            )
        };

        let mut registry = registry_with_root();
        let before = registry.len();
        assert_eq!(
            ChainCreationService::create_by_vote(&mut registry, make(), true),
            Err(GmcError::MissingField)
        );
        assert_eq!(
            ChainCreationService::create_by_steward(&mut registry, make(), true),
            Err(GmcError::MissingField)
        );
        assert_eq!(
            ChainCreationService::create_by_institution(&mut registry, make(), true),
            Err(GmcError::MissingField)
        );
        assert_eq!(registry.len(), before);
    }

    #[test]
    fn missing_domain_surfaces_missing_field() {
        let mut registry = registry_with_root();
        let before = registry.len();
        let req = CreationRequest::new(
            ChainId::new("nodomain"),
            ChainId::new("gmc-base"),
            "", // missing domain
            vec![FayID::new("steward-1")],
            Timestamp::from_secs(2_000),
        );
        assert_eq!(
            ChainCreationService::create_by_vote(&mut registry, req, true),
            Err(GmcError::MissingField)
        );
        assert_eq!(registry.len(), before);
        assert!(!registry.contains(&ChainId::new("nodomain")));
    }

    // --- Stored origin matches the channel (Requirements 2.1/2.2/2.3) ------

    #[test]
    fn each_created_chain_records_its_channel_origin() {
        let mut registry = registry_with_root();
        ChainCreationService::create_by_vote(&mut registry, request("a", "a"), true).unwrap();
        ChainCreationService::create_by_steward(&mut registry, request("b", "b"), true).unwrap();
        ChainCreationService::create_by_institution(&mut registry, request("c", "c"), true)
            .unwrap();

        assert_eq!(
            registry.get(&ChainId::new("a")).unwrap().origin_type(),
            Some(OriginType::VoteInitiated)
        );
        assert_eq!(
            registry.get(&ChainId::new("b")).unwrap().origin_type(),
            Some(OriginType::StewardInitiated)
        );
        assert_eq!(
            registry.get(&ChainId::new("c")).unwrap().origin_type(),
            Some(OriginType::InstitutionApplied)
        );
    }
}
