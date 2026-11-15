//! Initiation-channel & end-to-end flow integration tests (task 20.3).
//!
//! **Validates: Requirements 2.1, 2.2, 2.3, 2.7, 2.8, 9.5, 10.6, 12.2**
//!
//! These are plain `#[test]` integration/scenario tests (not numbered properties), so
//! they carry no `Feature: ... Property N` label. They drive the real public APIs of
//! `chain_creation` and `flows` against live `gmc-core` modules (no mocks) to prove:
//!
//! - **The three nested-chain initiation channels each have a working success AND a
//!   working rejection path** (Requirement 2):
//!   - 投票发起 / vote-initiated: a vote *at/above* threshold derives the chain
//!     (Req 2.1, recording `OriginType::VoteInitiated`); a vote *below* threshold is
//!     rejected with `GovernanceThresholdNotMet` and creates nothing.
//!   - 主理人发起 / steward-initiated: a *qualified* steward derives the chain
//!     (Req 2.2, `OriginType::StewardInitiated`); an *unqualified* steward is rejected
//!     with `StewardNotQualified` and creates nothing (Req 2.7).
//!   - 机构申请 / institution-applied: a *passing* review derives the chain (Req 2.3,
//!     `OriginType::InstitutionApplied`); a *failed* review is rejected with
//!     `InstitutionReviewFailed` and creates nothing (Req 2.8).
//! - **The four key design flows run end-to-end** through the wired modules:
//!   - Flow 1 — 功勋链派生: a creation channel derives a chain and anchors the creation
//!     record to L1 (the success/rejection channel tests above run *through* this flow).
//!   - Flow 2 — 登记 → 记录 → 授予: a registered contribution flows record → grant →
//!     mint, and minting happens **iff** the three-condition grant guard holds
//!     (Req 9.5).
//!   - Flow 3 — 事后申报审核投票: a retroactive declaration flows review/vote → grant,
//!     minting only on an approving (≥ retro-threshold) vote (Req 10.6).
//!   - Flow 4 — 碳积分转 MeriToken: a carbon voucher flows conversion → mint, charging
//!     the env chain's quota and marking the voucher converted on approval (Req 12.2).

use gmc_core::antifraud::Stakeholder;
use gmc_core::carbon::CarbonCreditVoucher;
use gmc_core::chain_creation::CreationRequest;
use gmc_core::error::GmcError;
use gmc_core::flows::{
    run_carbon_conversion, run_chain_creation, run_register_record_grant, run_retroactive_review,
    CarbonFlowInput, CarbonOutcome, CreationChannel, GrantFlowInput, GrantOutcome, RetroFlowInput,
    RetroOutcome, RetroVoter,
};
use gmc_core::governance::GovernanceModule;
use gmc_core::l1_settlement::{L1Settlement, StateRoot};
use gmc_core::merit::{MeritBatch, MeritPocket, E};
use gmc_core::minting::MintingService;
use gmc_core::quota::{QuotaConfig, QuotaLedger, RefreshPeriod, TimeUnit};
use gmc_core::recording::{
    ContributionRequest, EvidenceRef as RecordingEvidenceRef, RecordingService,
};
use gmc_core::registration::{RegistrationApplication, RegistrationService};
use gmc_core::registry::{ChainRegistry, NestedMeritChain, OriginType};
use gmc_core::retroactive::{
    EvidenceRef as RetroEvidenceRef, RetroactiveApplication, RetroactiveReviewModule,
};
use gmc_core::scoring::{BaseScores, InflationIndexConfig, ScoringEngine};
use gmc_core::types::{ChainId, Decimal, Dimension, DimensionWeights, FayID, Ratio, Timestamp};

// ---------------------------------------------------------------------------
// Shared fixtures (mirrors the constructions used by the modules' own tests).
// ---------------------------------------------------------------------------

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).expect("valid decimal literal")
}

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(secs)
}

/// A `GMC_Base` registry rooted at `gmc-base`.
fn registry_with_root() -> ChainRegistry {
    let root = NestedMeritChain::root(
        ChainId::new("gmc-base"),
        "root",
        vec![FayID::new("founder")],
        ts(1_000),
    );
    ChainRegistry::with_root(root).expect("root is a valid depth-0 root")
}

/// A well-formed creation request deriving `proposed_id` (in `domain`) under the root.
fn creation_request(proposed_id: &str, domain: &str) -> CreationRequest {
    CreationRequest::new(
        ChainId::new(proposed_id),
        ChainId::new("gmc-base"),
        domain,
        vec![FayID::new("steward-1")],
        ts(2_000),
    )
}

/// A pocket whose floor `E` is backed by a slowly-decaying batch with `B = E`, so the
/// `curMerit >= minMerit` invariant is well-defined through subsequent mints.
fn backed_pocket() -> MeritPocket {
    let mut pocket = MeritPocket::new(FayID::from("alice"));
    pocket.add_batch(MeritBatch::new(
        "seed",
        Decimal::from_int(100),
        E,
        dec("0.001"),
        Decimal::from_int(1_000),
        ts(0),
        ChainId::from("academic"),
    ));
    pocket
}

fn periodic_quota(quota: &str) -> QuotaConfig {
    QuotaConfig::new(
        dec(quota),
        RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: Decimal::ONE,
        },
    )
    .expect("valid periodic config")
}

/// Weights {Thought:0.7, Technique:0.3} summing to 1.
fn standard_weights() -> DimensionWeights {
    DimensionWeights::from_entries([
        (Dimension::Thought, Ratio::from_percent(70).unwrap()),
        (Dimension::Technique, Ratio::from_percent(30).unwrap()),
    ])
}

/// Base scores {Thought:10, Technique:10}. With default indices (Thought 2.00,
/// Technique 1.00) the mint amount is 0.7·10·2.00 + 0.3·10·1.00 = 17.
fn standard_base_scores() -> BaseScores {
    BaseScores::from_entries([
        (Dimension::Thought, Decimal::from_int(10)),
        (Dimension::Technique, Decimal::from_int(10)),
    ])
}

/// The amount `standard_weights` × `standard_base_scores` × default indices yields.
fn standard_amount() -> Decimal {
    Decimal::from_int(17)
}

/// Seven low-intimacy (0.5) voters of equal `curMerit`, all casting the same ballot.
fn retro_voters(approve: bool) -> Vec<RetroVoter> {
    (0..7)
        .map(|i| {
            RetroVoter::new(
                Stakeholder::new(
                    FayID::new(format!("voter-{i}")),
                    Ratio::from_percent(50).unwrap(),
                ),
                Decimal::from_int(10),
                approve,
            )
        })
        .collect()
}

// ===========================================================================
// The three initiation channels — success AND rejection (run through Flow 1).
//
// Each channel is driven via `run_chain_creation` (Flow 1), so a success also
// proves the end-to-end derive → L1-anchor wiring, and a rejection proves the
// atomic "create nothing / anchor nothing" guarantee.
// ===========================================================================

/// 投票发起 — a vote **at/above** threshold derives the chain (Req 2.1) and the Flow 1
/// wiring anchors the creation record to L1, advancing the state root.
#[test]
fn vote_channel_success_derives_and_anchors() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();
    assert_eq!(l1.state_root(), StateRoot::GENESIS);

    let (chain_id, state_root) = run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("academic", "academic"),
        CreationChannel::Vote {
            governance_passed: true,
        },
    )
    .expect("a passing vote derives and anchors the chain");

    // Chain exists and records the vote-initiated origin (Req 2.1).
    assert_eq!(chain_id, ChainId::new("academic"));
    assert!(registry.contains(&chain_id));
    assert_eq!(
        registry.get(&chain_id).unwrap().origin_type(),
        Some(OriginType::VoteInitiated)
    );

    // Flow 1 anchored the creation record to L1 and advanced the state root (Req 2.6).
    assert!(l1.chain_registration(&chain_id).is_some());
    assert_ne!(state_root, StateRoot::GENESIS);
    assert_eq!(l1.state_root(), state_root);
}

/// 投票发起 — a vote **below** threshold is rejected; nothing is created or anchored.
#[test]
fn vote_channel_rejection_creates_and_anchors_nothing() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();
    let before = registry.len();

    let err = run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("academic", "academic"),
        CreationChannel::Vote {
            governance_passed: false,
        },
    )
    .expect_err("a below-threshold vote must be rejected");

    assert_eq!(err, GmcError::GovernanceThresholdNotMet);
    assert_eq!(registry.len(), before);
    assert!(!registry.contains(&ChainId::new("academic")));
    assert_eq!(l1.state_root(), StateRoot::GENESIS);
    assert_eq!(l1.chain_registration_count(), 0);
}

/// 主理人发起 — a **qualified** steward derives the chain (Req 2.2) and Flow 1 anchors it.
#[test]
fn steward_channel_success_derives_and_anchors() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();

    let (chain_id, state_root) = run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("charity", "charity"),
        CreationChannel::Steward {
            steward_qualified: true,
        },
    )
    .expect("a qualified steward derives and anchors the chain");

    assert_eq!(
        registry.get(&chain_id).unwrap().origin_type(),
        Some(OriginType::StewardInitiated)
    );
    assert!(l1.chain_registration(&chain_id).is_some());
    assert_ne!(state_root, StateRoot::GENESIS);
}

/// 主理人发起 — an **unqualified** steward is rejected with `StewardNotQualified`;
/// nothing is created or anchored (Req 2.7).
#[test]
fn steward_channel_rejection_creates_and_anchors_nothing() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();
    let before = registry.len();

    let err = run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("charity", "charity"),
        CreationChannel::Steward {
            steward_qualified: false,
        },
    )
    .expect_err("an unqualified steward must be rejected");

    assert_eq!(err, GmcError::StewardNotQualified);
    assert_eq!(registry.len(), before);
    assert!(!registry.contains(&ChainId::new("charity")));
    assert_eq!(l1.state_root(), StateRoot::GENESIS);
    assert_eq!(l1.chain_registration_count(), 0);
}

/// 机构申请 — a **passing** review derives the chain (Req 2.3) and Flow 1 anchors it.
#[test]
fn institution_channel_success_derives_and_anchors() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();

    let (chain_id, state_root) = run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("environment", "environment"),
        CreationChannel::Institution {
            review_passed: true,
        },
    )
    .expect("a passing institution review derives and anchors the chain");

    assert_eq!(
        registry.get(&chain_id).unwrap().origin_type(),
        Some(OriginType::InstitutionApplied)
    );
    assert!(l1.chain_registration(&chain_id).is_some());
    assert_ne!(state_root, StateRoot::GENESIS);
}

/// 机构申请 — a **failed** review is rejected with `InstitutionReviewFailed`; nothing is
/// created or anchored (Req 2.8).
#[test]
fn institution_channel_rejection_creates_and_anchors_nothing() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();
    let before = registry.len();

    let err = run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("environment", "environment"),
        CreationChannel::Institution {
            review_passed: false,
        },
    )
    .expect_err("a failed institution review must be rejected");

    assert_eq!(err, GmcError::InstitutionReviewFailed);
    assert_eq!(registry.len(), before);
    assert!(!registry.contains(&ChainId::new("environment")));
    assert_eq!(l1.state_root(), StateRoot::GENESIS);
    assert_eq!(l1.chain_registration_count(), 0);
}

/// The three channels are independent: driving all three under the same root creates
/// three distinct chains, each stamped with its own channel origin.
#[test]
fn three_channels_create_three_distinctly_originated_chains() {
    let mut registry = registry_with_root();
    let mut l1 = L1Settlement::new();

    run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("a", "a"),
        CreationChannel::Vote {
            governance_passed: true,
        },
    )
    .unwrap();
    run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("b", "b"),
        CreationChannel::Steward {
            steward_qualified: true,
        },
    )
    .unwrap();
    run_chain_creation(
        &mut registry,
        &mut l1,
        creation_request("c", "c"),
        CreationChannel::Institution {
            review_passed: true,
        },
    )
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
    // Three creation records anchored to L1.
    assert_eq!(l1.chain_registration_count(), 3);
}

// ===========================================================================
// Flow 2 — 登记 → 记录 → 授予 (register → record → grant → mint), Req 9.5.
// ===========================================================================

fn grant_input(evaluation_passed: bool) -> GrantFlowInput {
    GrantFlowInput {
        application: RegistrationApplication::new(
            FayID::new("alice"),
            ChainId::new("academic"),
            "intend to publish a paper",
            ts(1_000),
        ),
        contribution: ContributionRequest::new(
            FayID::new("alice"),
            ChainId::new("academic"),
            vec![RecordingEvidenceRef::new("ipfs://cid", "0xhash")],
            ts(1_100),
        ),
        evaluation_passed,
        weights: standard_weights(),
        base_scores: standard_base_scores(),
        indices: InflationIndexConfig::default(),
        influence_duration: Decimal::from_int(1_000),
        batch_id: "m1".to_owned(),
    }
}

/// A registered contribution flows record → grant → mint: with all three grant
/// conditions holding, a batch is minted and the chain's quota is charged (Req 9.5).
#[test]
fn flow2_registered_contribution_flows_through_to_mint() {
    let mut registrations = RegistrationService::new();
    let mut recordings = RecordingService::new();
    let scoring = ScoringEngine::new();
    let minting = MintingService::new();
    let mut pocket = backed_pocket();
    let quota = periodic_quota("1000");
    let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));

    let outcome = run_register_record_grant(
        &mut registrations,
        &mut recordings,
        &scoring,
        &minting,
        &mut pocket,
        &quota,
        &mut ledger,
        grant_input(true),
    )
    .expect("the happy path mints");

    match outcome {
        GrantOutcome::Minted(receipt) => {
            assert_eq!(receipt.minted_amount, standard_amount());
            assert_eq!(ledger.minted_this_period(), standard_amount());
        }
        GrantOutcome::NotGranted => panic!("expected a mint when all conditions hold"),
    }
}

/// Req 9.5: when a grant condition fails (the evaluation did not pass), the guard blocks
/// minting — the flow completes without error but mints nothing and leaves quota/pocket
/// untouched.
#[test]
fn flow2_grant_guard_blocks_mint_when_condition_fails() {
    let mut registrations = RegistrationService::new();
    let mut recordings = RecordingService::new();
    let scoring = ScoringEngine::new();
    let minting = MintingService::new();
    let mut pocket = backed_pocket();
    let quota = periodic_quota("1000");
    let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));
    let pocket_before = pocket.clone();

    let outcome = run_register_record_grant(
        &mut registrations,
        &mut recordings,
        &scoring,
        &minting,
        &mut pocket,
        &quota,
        &mut ledger,
        grant_input(false),
    )
    .expect("the flow completes (no error) but does not mint");

    assert!(matches!(outcome, GrantOutcome::NotGranted));
    assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
    assert_eq!(pocket, pocket_before);
}

// ===========================================================================
// Flow 3 — 事后申报审核投票 (retroactive review / vote → grant), Req 10.6.
// ===========================================================================

fn retro_input(approve: bool) -> RetroFlowInput {
    RetroFlowInput {
        application: RetroactiveApplication::new(
            FayID::new("alice"),
            ChainId::new("academic"),
            "Did the work in 2023, never registered up front.",
            ts(1_600_000_000),
            vec![RetroEvidenceRef::new("ipfs://cid-abc", "0xhash", true)],
        ),
        voters: retro_voters(approve),
        sample_size: 7,
        seed: 42,
        regular_threshold: Ratio::from_percent(50).unwrap(),
        subject: "retro-academic".to_owned(),
        weights: standard_weights(),
        base_scores: standard_base_scores(),
        indices: InflationIndexConfig::default(),
        influence_duration: Decimal::from_int(1_000),
        batch_id: "retro-m1".to_owned(),
        acquired_at: ts(1_600_000_100),
    }
}

/// A retroactive declaration flows review/vote → grant: an approving (≥ retro-threshold)
/// vote mints a batch, charges the quota and anchors the outcome to L1 (Req 10.6).
#[test]
fn flow3_approved_retroactive_declaration_flows_through_to_mint() {
    let mut retro = RetroactiveReviewModule::new();
    let mut governance = GovernanceModule::new();
    let scoring = ScoringEngine::new();
    let minting = MintingService::new();
    let mut pocket = backed_pocket();
    let quota = periodic_quota("1000");
    let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));
    let mut l1 = L1Settlement::new();

    let outcome = run_retroactive_review(
        &mut retro,
        &mut governance,
        &scoring,
        &minting,
        &mut pocket,
        &quota,
        &mut ledger,
        &mut l1,
        retro_input(true),
    )
    .expect("an approved retro declaration mints");

    match outcome {
        RetroOutcome::Approved(receipt) => {
            assert_eq!(receipt.minted_amount, standard_amount());
            assert_eq!(ledger.minted_this_period(), standard_amount());
        }
        RetroOutcome::Rejected => panic!("expected approval to mint"),
    }
    // The approved outcome was anchored to L1 (Req 10.7).
    assert_ne!(l1.state_root(), StateRoot::GENESIS);
}

/// Req 10.6 (negative side): a vote that falls short of the retro threshold mints
/// nothing and leaves the pocket/quota untouched, while still anchoring the rejection.
#[test]
fn flow3_rejected_retroactive_declaration_mints_nothing() {
    let mut retro = RetroactiveReviewModule::new();
    let mut governance = GovernanceModule::new();
    let scoring = ScoringEngine::new();
    let minting = MintingService::new();
    let mut pocket = backed_pocket();
    let quota = periodic_quota("1000");
    let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));
    let mut l1 = L1Settlement::new();
    let pocket_before = pocket.clone();

    let outcome = run_retroactive_review(
        &mut retro,
        &mut governance,
        &scoring,
        &minting,
        &mut pocket,
        &quota,
        &mut ledger,
        &mut l1,
        retro_input(false),
    )
    .expect("a rejected retro declaration is a normal (non-error) outcome");

    assert!(matches!(outcome, RetroOutcome::Rejected));
    assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
    assert_eq!(pocket, pocket_before);
    // The rejection was still anchored to L1 (Req 10.7).
    assert_ne!(l1.state_root(), StateRoot::GENESIS);
}

// ===========================================================================
// Flow 4 — 碳积分转 MeriToken (carbon voucher → conversion → mint), Req 12.2.
// ===========================================================================

fn carbon_input(approve: bool) -> CarbonFlowInput {
    CarbonFlowInput {
        contributor_id: FayID::new("eco-alice"),
        chain_id: ChainId::new("carbon-reduction"),
        description: "Restored 5 hectares of wetland in 2023.".to_owned(),
        occurred_at: ts(1_650_000_000),
        voters: retro_voters(approve),
        sample_size: 7,
        seed: 7,
        regular_threshold: Ratio::from_percent(50).unwrap(),
        subject: "carbon-conversion".to_owned(),
        weights: standard_weights(),
        base_scores: standard_base_scores(),
        indices: InflationIndexConfig::default(),
        acquired_at: ts(1_650_000_100),
    }
}

fn verifiable_voucher() -> CarbonCreditVoucher {
    CarbonCreditVoucher::new(
        "voucher-001",
        RetroEvidenceRef::new("ipfs://carbon-cid", "0xcarbonhash", true),
    )
}

/// A carbon voucher flows conversion → mint: an approving vote charges the env chain's
/// current-period quota for the converted amount and marks the voucher converted exactly
/// once (Req 12.2 / 12.5 / 12.7).
#[test]
fn flow4_carbon_voucher_flows_through_to_conversion() {
    let mut voucher = verifiable_voucher();
    let mut retro = RetroactiveReviewModule::new();
    let mut governance = GovernanceModule::new();
    let scoring = ScoringEngine::new();
    let env_quota = periodic_quota("1000");
    let mut env_ledger = QuotaLedger::new(ChainId::new("carbon-reduction"), ts(0));
    let mut l1 = L1Settlement::new();

    let outcome = run_carbon_conversion(
        &mut voucher,
        &mut retro,
        &mut governance,
        &scoring,
        &env_quota,
        &mut env_ledger,
        &mut l1,
        carbon_input(true),
    )
    .expect("an approved carbon claim converts");

    match outcome {
        CarbonOutcome::Converted(amount) => assert_eq!(amount, standard_amount()),
        CarbonOutcome::Rejected => panic!("expected approval to convert"),
    }
    // The env chain's current-period quota was charged by the converted amount (Req 12.5).
    assert_eq!(env_ledger.minted_this_period(), standard_amount());
    assert!(env_ledger.minted_this_period() <= env_quota.quota());
    // The voucher is marked converted exactly once (Req 12.7) and the outcome anchored.
    assert!(voucher.is_converted());
    assert_ne!(l1.state_root(), StateRoot::GENESIS);
}

/// Req 12.2 (negative side): a rejected carbon claim converts nothing, leaves the
/// voucher unconverted and consumes no env-chain quota.
#[test]
fn flow4_rejected_carbon_claim_converts_nothing() {
    let mut voucher = verifiable_voucher();
    let mut retro = RetroactiveReviewModule::new();
    let mut governance = GovernanceModule::new();
    let scoring = ScoringEngine::new();
    let env_quota = periodic_quota("1000");
    let mut env_ledger = QuotaLedger::new(ChainId::new("carbon-reduction"), ts(0));
    let mut l1 = L1Settlement::new();

    let outcome = run_carbon_conversion(
        &mut voucher,
        &mut retro,
        &mut governance,
        &scoring,
        &env_quota,
        &mut env_ledger,
        &mut l1,
        carbon_input(false),
    )
    .expect("a rejected carbon claim is a normal outcome");

    assert!(matches!(outcome, CarbonOutcome::Rejected));
    assert!(!voucher.is_converted());
    assert_eq!(env_ledger.minted_this_period(), Decimal::ZERO);
}
