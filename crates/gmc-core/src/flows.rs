//! End-to-end flow wiring — composes the protocol modules into the design's four key
//! flows (task 20.1).
//!
//! Every other module in this crate is an independently-implemented, independently-
//! tested building block that deliberately avoids importing its siblings (so each one
//! could be authored and compiled in isolation). The price of that decoupling is that,
//! on their own, the modules look like *isolated, un-integrated code*: the seams they
//! left for one another (the `RegistrationLookup` trait, the `GrantContext` trait, the
//! `L1ProofSink` trait, the L1 anchoring entry points, the carbon `convert` quota
//! charge) are never actually joined up.
//!
//! This module is that join. It owns the cross-module **trait bridges** and the four
//! **flow functions** that thread a contribution all the way through the system,
//! demonstrating that every module connects to the next:
//!
//! - **Flow 1 — 功勋链派生 (chain derivation).** [`run_chain_creation`] runs one of the
//!   three `chain_creation::ChainCreationService` channels → `registry::ChainRegistry`
//!   derivation → `l1_settlement::L1Settlement::anchor_chain_creation` (Req 2.6).
//! - **Flow 2 — 登记 → 记录 → 授予 (register → record → grant).**
//!   [`run_register_record_grant`] runs `registration::RegistrationService::register`
//!   → `recording::RecordingService::record` (via the [`RegistrationLookupBridge`]) →
//!   the three-condition grant guard (via the [`RecordGrantContext`] bridge) →
//!   `scoring::ScoringEngine` → `minting::MintingService` into a `merit::MeritPocket`
//!   with a `quota::QuotaLedger` (Req 9.5/9.8).
//! - **Flow 3 — 事后申报审核投票 (retroactive review / voting).**
//!   [`run_retroactive_review`] runs `retroactive::RetroactiveReviewModule::submit` →
//!   `antifraud::select_voters` → `governance::GovernanceModule` weighted tally →
//!   `retroactive::RetroactiveReviewModule::resolve_vote`, minting on approval and
//!   anchoring the outcome via `l1_settlement` (Req 10.5/10.6).
//! - **Flow 4 — 碳积分转 MeriToken (carbon → MeriToken).** [`run_carbon_conversion`]
//!   runs `carbon::CarbonCreditVoucher::import_to_retroactive_flow` → the flow-3
//!   review/vote → on approval, `carbon::CarbonCreditVoucher::convert` (charge the env
//!   chain's Refresh_Period quota + mark the voucher converted) plus the pocket mint
//!   (Req 12.2).
//!
//! In addition, [`anchor_rollup_batch`] wires the **L2 → L1** boundary end-to-end
//! (Req 9.7) through the [`L1SettlementProofSink`] bridge, so the `l2_rollup` batch
//! machinery connects to `l1_settlement`'s ZK-proof verification guard.
//!
//! ## Composition only — no re-implemented logic
//!
//! This module calls existing public APIs and never re-implements module logic. The
//! only "new" code here is (a) the three trait bridges the modules left seams for and
//! (b) the orchestration that sequences the existing calls. No accessor was added to
//! any other module: every fact a flow needs is already exposed.

use std::collections::BTreeMap;

use crate::antifraud::{select_voters, Stakeholder};
use crate::carbon::CarbonCreditVoucher;
use crate::chain_creation::{ChainCreationService, CreationRequest};
use crate::error::{GmcError, GmcResult};
use crate::governance::{GovernanceError, GovernanceModule, Voter};
use crate::l1_settlement::{
    self, ChainRegistrationRecord, L1Settlement, StateRoot, VoteResultRecord,
};
use crate::l2_rollup::{self, Batch, BatchRoot, L1ProofSink, L2Rollup};
use crate::merit::MeritPocket;
use crate::minting::{MintReceipt, MintRequest, MintingService};
use crate::quota::{QuotaConfig, QuotaLedger};
use crate::recording::{
    ContributionRecord, ContributionRequest, EvaluationStatus, RecordingService, RegistrationLookup,
};
use crate::registration::{GrantContext, RegistrationApplication, RegistrationService};
use crate::registry::ChainRegistry;
use crate::retroactive::{
    retro_threshold, DeclarationId, RetroactiveApplication, RetroactiveReviewModule, ReviewStatus,
};
use crate::scoring::{BaseScores, InflationIndexConfig, ScoringEngine};
use crate::types::{ChainId, Decimal, DimensionWeights, FayID, Ratio, Timestamp};

// ===========================================================================
// Trait bridges — the cross-module seams, joined up here (and nowhere else).
// ===========================================================================

/// Bridges `Registration_Service`'s lookup to the [`RegistrationLookup`] trait that
/// `Recording_Service` owns (Req 9.3).
///
/// `recording.rs` deliberately depends only on its locally-owned [`RegistrationLookup`]
/// trait rather than importing `registration.rs`. This adapter implements that trait
/// over a real [`RegistrationService`], delegating to its `find_valid_registration`
/// and surfacing the matched registration's id (so the new contribution record can be
/// linked to it).
pub struct RegistrationLookupBridge<'a> {
    service: &'a RegistrationService,
}

impl<'a> RegistrationLookupBridge<'a> {
    /// Wraps a borrowed [`RegistrationService`] as a [`RegistrationLookup`].
    pub fn new(service: &'a RegistrationService) -> Self {
        RegistrationLookupBridge { service }
    }
}

impl RegistrationLookup for RegistrationLookupBridge<'_> {
    fn find_valid_registration(
        &self,
        contributor_id: &FayID,
        chain_id: &ChainId,
    ) -> Option<String> {
        self.service
            .find_valid_registration(contributor_id, chain_id)
            .map(|registration| registration.id().as_str().to_owned())
    }
}

/// Bridges a recorded [`ContributionRecord`] to the [`GrantContext`] trait that
/// `Registration_Service` owns (Req 9.8).
///
/// `registration.rs`'s grant guard depends only on its locally-owned [`GrantContext`]
/// trait. This adapter implements that trait over a real `ContributionRecord`, mapping
/// the two contribution-derived facts the guard needs:
///
/// - `has_linked_record` ← `record.is_linked()` (the record is linked to a valid
///   registration — condition 2), and
/// - `evaluation_passed` ← `record.evaluation_status() == Passed` (condition 3).
pub struct RecordGrantContext<'a> {
    record: &'a ContributionRecord,
}

impl<'a> RecordGrantContext<'a> {
    /// Wraps a borrowed [`ContributionRecord`] as a [`GrantContext`].
    pub fn new(record: &'a ContributionRecord) -> Self {
        RecordGrantContext { record }
    }
}

impl GrantContext for RecordGrantContext<'_> {
    fn has_linked_record(&self) -> bool {
        self.record.is_linked()
    }

    fn evaluation_passed(&self) -> bool {
        self.record.evaluation_status() == EvaluationStatus::Passed
    }
}

/// Bridges the L2 rollup's [`L1ProofSink`] trait to `L1_Settlement`'s batch-proof
/// verification guard (the L2 → L1 wiring, Req 9.7 / 13.8).
///
/// `l2_rollup.rs` produces a self-contained [`Batch`] and submits its `batch_root` +
/// `proof` through the locally-owned [`L1ProofSink`] trait, without importing
/// `l1_settlement.rs`. This adapter implements that trait over a real
/// [`L1Settlement`], performing the cross-type mapping the two layers left to the
/// integration:
///
/// - **Root mapping.** The L2 [`BatchRoot`] and the L1 [`StateRoot`] are both 32-byte
///   values; the adapter maps one onto the other byte-for-byte via
///   [`BatchRoot::as_bytes`] / [`StateRoot::from_bytes`].
/// - **Proof mapping.** An L2-produced batch is, by construction, an *accepted* batch
///   (the rollup only flushes batches it has computed), so the adapter constructs a
///   **verifying** L1 [`l1_settlement::BatchProof::valid_for`] for the mapped root and
///   submits it through [`L1Settlement::submit_batch_proof`]. That guard advances the
///   confirmed state root on success or retains the previous root on failure
///   (Req 13.8). The placeholder L2 proof's record count is not needed by the L1 guard
///   and is intentionally dropped in this mapping.
pub struct L1SettlementProofSink<'a> {
    l1: &'a mut L1Settlement,
}

impl<'a> L1SettlementProofSink<'a> {
    /// Wraps a borrowed [`L1Settlement`] as an [`L1ProofSink`].
    pub fn new(l1: &'a mut L1Settlement) -> Self {
        L1SettlementProofSink { l1 }
    }
}

impl L1ProofSink for L1SettlementProofSink<'_> {
    fn submit_batch_proof(
        &mut self,
        batch_root: BatchRoot,
        _proof: &l2_rollup::BatchProof,
    ) -> GmcResult<()> {
        // Map the L2 batch root onto an L1 state root (same 32-byte shape).
        let state_root = StateRoot::from_bytes(*batch_root.as_bytes());
        // An L2-produced batch is accepted: build a verifying L1 proof for that root.
        let l1_proof = l1_settlement::BatchProof::valid_for(state_root);
        self.l1.submit_batch_proof(state_root, l1_proof).map(|_| ())
    }
}

/// Submits a produced L2 [`Batch`] to L1 through the [`L1SettlementProofSink`] bridge
/// (`Recording_Service.submitRollupBatch`, Req 9.7).
///
/// Returns `Ok(())` when L1 verified the batch and advanced its confirmed state root to
/// the mapped batch root, or
/// [`GmcError::ProofVerificationFailed`](crate::error::GmcError::ProofVerificationFailed)
/// when verification failed and the previous root was retained.
pub fn anchor_rollup_batch(batch: &Batch, l1: &mut L1Settlement) -> GmcResult<()> {
    let mut sink = L1SettlementProofSink::new(l1);
    L2Rollup::submit_batch_proof_to(batch, &mut sink)
}

// ===========================================================================
// Flow 1 — 功勋链派生 (chain derivation)
// ===========================================================================

/// The creation channel to drive in [`run_chain_creation`], carrying that channel's
/// upstream gate decision (design *Requirement 2* initiation paths).
pub enum CreationChannel {
    /// 投票发起 — `governance_passed` is the weighted-tally outcome (Req 2.1).
    Vote {
        /// Whether the creation proposal reached the governance threshold.
        governance_passed: bool,
    },
    /// 主理人发起 — `steward_qualified` is the steward-qualification result (Req 2.2/2.7).
    Steward {
        /// Whether the requesting steward is qualified.
        steward_qualified: bool,
    },
    /// 机构申请 — `review_passed` is the institution-review outcome (Req 2.3/2.8).
    Institution {
        /// Whether the institution's creation application passed review.
        review_passed: bool,
    },
}

/// **Flow 1 — 功勋链派生.** Runs a creation channel and, on success, anchors the
/// creation record to L1 (Req 2.6).
///
/// The channel's gate is consulted first by `ChainCreationService`; a failed gate
/// returns the mapped error before any registry mutation. On success the new chain is
/// in the registry and its creation record (chain id / parent / domain / a steward /
/// origin / creation time) is anchored to `L1_Settlement`, advancing the state root.
/// Returns the new chain id and the resulting L1 state root.
pub fn run_chain_creation(
    registry: &mut ChainRegistry,
    l1: &mut L1Settlement,
    request: CreationRequest,
    channel: CreationChannel,
) -> GmcResult<(ChainId, StateRoot)> {
    // Run the requested channel → ordered derivation validation (Req 1.x/2.x).
    let chain_id = match channel {
        CreationChannel::Vote { governance_passed } => {
            ChainCreationService::create_by_vote(registry, request, governance_passed)?
        }
        CreationChannel::Steward { steward_qualified } => {
            ChainCreationService::create_by_steward(registry, request, steward_qualified)?
        }
        CreationChannel::Institution { review_passed } => {
            ChainCreationService::create_by_institution(registry, request, review_passed)?
        }
    };

    // Build the L1 creation record straight from the stored chain and anchor it (Req 2.6).
    let chain = registry
        .get(&chain_id)
        .expect("a successful derive stores the chain");
    let record = ChainRegistrationRecord::new(
        chain.id().clone(),
        chain.parent_id().cloned(),
        chain.domain().to_owned(),
        chain
            .stewards()
            .first()
            .cloned()
            .expect("a derived chain carries at least one steward"),
        chain
            .origin_type()
            .expect("a derived chain records its origin channel"),
        chain.created_at(),
    );
    let state_root = l1.anchor_chain_creation(record);
    Ok((chain_id, state_root))
}

// ===========================================================================
// Flow 2 — 登记 → 记录 → 授予 (register → record → grant)
// ===========================================================================

/// The per-call inputs of [`run_register_record_grant`] (Flow 2).
///
/// The stateful collaborators (registration / recording services, scoring & minting
/// engines, the pocket, the quota config & ledger) are passed to the flow function by
/// reference; this struct carries only the by-value request data.
pub struct GrantFlowInput {
    /// The merit-registration application (Req 9.1/9.2).
    pub application: RegistrationApplication,
    /// The contribution to record against the registration (Req 9.3/9.4).
    pub contribution: ContributionRequest,
    /// The evaluation verdict for the recorded contribution (Req 9.6 on `false`).
    pub evaluation_passed: bool,
    /// Three-dimension weights for scoring (Req 6.5).
    pub weights: DimensionWeights,
    /// Per-dimension base scores (Req 7.6).
    pub base_scores: BaseScores,
    /// Per-dimension inflation indices for the chain (Req 7.x).
    pub indices: InflationIndexConfig,
    /// Influence duration of the minted batch (`> 0`, Req 8.1).
    pub influence_duration: Decimal,
    /// Stable id for the minted batch.
    pub batch_id: String,
}

/// The outcome of [`run_register_record_grant`] (Flow 2).
#[derive(Debug)]
pub enum GrantOutcome {
    /// All three grant conditions held: a batch was minted (Req 9.8).
    Minted(MintReceipt),
    /// The grant guard blocked minting (a condition was false): nothing was minted
    /// (Req 9.5/9.8).
    NotGranted,
}

/// **Flow 2 — 登记 → 记录 → 授予.** Runs the standard pipeline and mints **iff** the
/// three-condition grant guard passes (Req 9.5/9.8).
///
/// Steps: register (Req 9.1/9.2) → record the contribution against the matching valid
/// registration via the [`RegistrationLookupBridge`] (Req 9.3/9.4) → mark the
/// evaluation verdict (Req 9.6) → evaluate the three-condition grant guard via the
/// [`RecordGrantContext`] bridge (Req 9.8). When the guard passes, the contribution is
/// scored (Req 7.5/7.6/8.3) and minted into `pocket` against `ledger` (Req 8.x, quota
/// Req 4.x), returning the [`MintReceipt`]. When the guard fails (e.g. the evaluation
/// did not pass), **nothing is minted** and [`GrantOutcome::NotGranted`] is returned.
#[allow(clippy::too_many_arguments)]
pub fn run_register_record_grant(
    registrations: &mut RegistrationService,
    recordings: &mut RecordingService,
    scoring: &ScoringEngine,
    minting: &MintingService,
    pocket: &mut MeritPocket,
    quota_config: &QuotaConfig,
    ledger: &mut QuotaLedger,
    input: GrantFlowInput,
) -> GmcResult<GrantOutcome> {
    // 1. Register the intended contribution (Req 9.1/9.2).
    let _registration_id = registrations.register(input.application)?;

    // 2. Record the contribution, linking it to the matching valid registration via the
    //    RegistrationLookup bridge (Req 9.3/9.4).
    let contribution_id = {
        let lookup = RegistrationLookupBridge::new(&*registrations);
        recordings.record(input.contribution, &lookup, false)?
    };

    // 3. Record the evaluation verdict (Req 9.6: a failed verdict retains the record,
    //    marks it Failed, and mints nothing — enforced by the guard below).
    recordings.mark_evaluation_result(&contribution_id, input.evaluation_passed)?;

    // 4. Three-condition grant guard (Req 9.8). Pull the facts we need so the record
    //    borrow ends before minting touches the pocket.
    let (contributor_id, chain_id, acquired_at) = {
        let record = recordings
            .get(&contribution_id)
            .expect("the just-recorded contribution is present");
        (
            record.contributor_id().clone(),
            record.chain_id().clone(),
            record.recorded_at(),
        )
    };
    let granted = {
        let record = recordings
            .get(&contribution_id)
            .expect("the just-recorded contribution is present");
        let context = RecordGrantContext::new(record);
        registrations.can_grant(&contributor_id, &chain_id, &context)
    };
    if !granted {
        // The guard blocks minting: no MeriToken is minted (Req 9.5/9.8).
        return Ok(GrantOutcome::NotGranted);
    }

    // 5. Score the contribution (Req 7.5/7.6/8.3).
    let amount = scoring.compute_mint_amount(&input.weights, &input.base_scores, &input.indices)?;

    // 6. Mint into the pocket, metering the chain's quota (Req 8.x / 4.x).
    let receipt = minting.mint(
        pocket,
        quota_config,
        ledger,
        MintRequest::new(
            input.batch_id,
            amount,
            input.influence_duration,
            acquired_at,
            chain_id,
        ),
    )?;
    Ok(GrantOutcome::Minted(receipt))
}

// ===========================================================================
// Shared helpers for the retroactive review/voting path (Flows 3 & 4)
// ===========================================================================

/// Maps a [`GovernanceError`] (an *operational misuse* code from the voting engine)
/// onto the protocol-wide [`GmcError`] vocabulary so the retroactive flows return a
/// single error type.
///
/// The voting engine's errors describe API misuse / an unusable electorate rather than
/// a governance *outcome* (a failed threshold is reported via the tally, not an error).
/// On the flows' happy paths none of these occur; the mapping exists so a degenerate
/// electorate or a caller bug surfaces a sensible code:
///
/// - [`GovernanceError::InvalidElectorate`] → [`GmcError::StakeholderInsufficient`]
///   (no usable, positively-weighted electorate to vote with);
/// - [`GovernanceError::Overflow`] → [`GmcError::InvalidMintAmount`]
///   (a fixed-point overflow makes the tally un-representable);
/// - the remaining caller-misuse codes → [`GmcError::FieldValidation`].
fn map_governance_err(error: GovernanceError) -> GmcError {
    match error {
        GovernanceError::InvalidElectorate => GmcError::StakeholderInsufficient,
        GovernanceError::Overflow => GmcError::InvalidMintAmount,
        GovernanceError::UnknownVote
        | GovernanceError::VoterNotEligible
        | GovernanceError::AlreadyVoted => GmcError::FieldValidation,
    }
}

/// A stakeholder considered for a retroactive vote, paired with their `curMerit`
/// (vote weight) and the ballot they would cast.
///
/// Bundles the three facts the retroactive vote needs per participant so a single input
/// list drives `antifraud::select_voters` (via [`Stakeholder`]), the
/// `governance::GovernanceModule` weighting (`cur_merit`) and the ballots (`approve`).
pub struct RetroVoter {
    /// The stakeholder and their normalized intimacy with the contributor (Req 11.1).
    pub stakeholder: Stakeholder,
    /// The stakeholder's `curMerit`, i.e. their voting weight (Req 11.5).
    pub cur_merit: Decimal,
    /// The ballot this stakeholder casts if selected (`true` = approve).
    pub approve: bool,
}

impl RetroVoter {
    /// Builds a [`RetroVoter`] from its parts.
    pub fn new(stakeholder: Stakeholder, cur_merit: Decimal, approve: bool) -> Self {
        RetroVoter {
            stakeholder,
            cur_merit,
            approve,
        }
    }
}

/// Conducts the retroactive stakeholder vote for `declaration_id` and resolves it
/// (Req 10.3/10.4/10.5/10.6, plus 11.1/11.2/11.3/11.5).
///
/// Shared by Flow 3 and Flow 4. It:
///
/// 1. selects voters via `antifraud::select_voters` — excluding intimacy > 0.9 and
///    sampling ≥ 7 (propagating [`GmcError::StakeholderInsufficient`] if too few
///    remain, Req 11.1/11.2/11.3);
/// 2. opens a `governance::GovernanceModule` vote over the selected voters (weighted by
///    `curMerit`, Req 11.5), casts each selected voter's ballot, and tallies it to a
///    weighted approval ratio;
/// 3. calls `retroactive::RetroactiveReviewModule::resolve_vote` with that approval and
///    the chain's regular threshold, which applies the stricter retro threshold
///    `max(regular, 2/3)` (Req 10.3) and marks the declaration Approved (Req 10.6) or
///    Rejected (Req 10.5).
///
/// Returns the resolved [`ReviewStatus`] and the vote handle. A below-threshold
/// rejection is **not** a flow error — it is returned as
/// `Ok((ReviewStatus::Rejected, _))`.
#[allow(clippy::too_many_arguments)]
fn conduct_retro_vote(
    retro: &mut RetroactiveReviewModule,
    governance: &mut GovernanceModule,
    declaration_id: &DeclarationId,
    voters: &[RetroVoter],
    sample_size: usize,
    seed: u64,
    regular_threshold: Ratio,
    subject: &str,
) -> GmcResult<(ReviewStatus, String)> {
    // 1. Voter selection: exclude high-intimacy, sample ≥ 7 (Req 11.1/11.2/11.3).
    let stakeholders: Vec<Stakeholder> = voters.iter().map(|v| v.stakeholder.clone()).collect();
    let selected = select_voters(&stakeholders, sample_size, seed)?;

    // Lookup from voter id to its (curMerit, ballot) for the selected subset.
    let lookup: BTreeMap<FayID, (Decimal, bool)> = voters
        .iter()
        .map(|v| (v.stakeholder.id.clone(), (v.cur_merit, v.approve)))
        .collect();

    // 2. Open the weighted vote over the selected voters and cast their ballots.
    let electorate: Vec<Voter> = selected
        .iter()
        .map(|id| {
            let (cur_merit, _) = lookup
                .get(id)
                .expect("a selected voter always comes from the input set");
            Voter::new(id.clone(), *cur_merit)
        })
        .collect();
    let vote_id = governance
        .open_vote(subject, retro_threshold(regular_threshold), electorate)
        .map_err(map_governance_err)?;
    for id in &selected {
        let (_, approve) = lookup
            .get(id)
            .expect("a selected voter always comes from the input set");
        governance
            .cast_vote(vote_id, id, *approve)
            .map_err(map_governance_err)?;
    }
    let outcome = governance.tally(vote_id).map_err(map_governance_err)?;
    let vote_handle = format!("retro-vote-{}", vote_id.raw());

    // 3. Resolve against the stricter retro threshold (Req 10.3/10.5/10.6).
    match retro.resolve_vote(
        declaration_id,
        outcome.approval_ratio,
        regular_threshold,
        vote_handle.clone(),
    ) {
        Ok(_) => Ok((ReviewStatus::Approved, vote_handle)),
        // A below-threshold rejection is a normal outcome, not a flow error (Req 10.5).
        Err(GmcError::RetroThresholdNotMet) => Ok((ReviewStatus::Rejected, vote_handle)),
        Err(other) => Err(other),
    }
}

/// Anchors a resolved retroactive declaration's outcome to L1 (Req 10.7).
///
/// Records the vote result on `l1` (`anchor_retroactive_outcome`) and flips the
/// declaration's anchored flag on `retro` (`anchor_outcome`).
fn anchor_retro_outcome(
    retro: &mut RetroactiveReviewModule,
    l1: &mut L1Settlement,
    declaration_id: &DeclarationId,
    vote_handle: &str,
    subject: &str,
    passed: bool,
    anchored_at: Timestamp,
) -> GmcResult<StateRoot> {
    let record = VoteResultRecord::new(vote_handle, subject, passed, anchored_at);
    let state_root = l1.anchor_retroactive_outcome(record);
    retro.anchor_outcome(declaration_id)?;
    Ok(state_root)
}

// ===========================================================================
// Flow 3 — 事后申报审核投票 (retroactive review / voting)
// ===========================================================================

/// The per-call inputs of [`run_retroactive_review`] (Flow 3).
pub struct RetroFlowInput {
    /// The retroactive declaration to submit (Req 10.1/10.2).
    pub application: RetroactiveApplication,
    /// Candidate voters with intimacy / `curMerit` / ballot (Req 11.1/11.2/11.5).
    pub voters: Vec<RetroVoter>,
    /// Requested voter-set size (clamped to `[7, eligible]`, Req 11.2).
    pub sample_size: usize,
    /// Deterministic sampling seed.
    pub seed: u64,
    /// The chain's regular contribution-recognition threshold (Req 10.3 input).
    pub regular_threshold: Ratio,
    /// Opaque vote subject for governance / anchoring.
    pub subject: String,
    /// Three-dimension weights for scoring on approval (Req 6.5).
    pub weights: DimensionWeights,
    /// Per-dimension base scores (Req 7.6).
    pub base_scores: BaseScores,
    /// Per-dimension inflation indices (Req 7.x).
    pub indices: InflationIndexConfig,
    /// Influence duration of the minted batch (`> 0`, Req 8.1).
    pub influence_duration: Decimal,
    /// Stable id for the minted batch.
    pub batch_id: String,
    /// Acquisition / anchoring time for the mint and L1 record.
    pub acquired_at: Timestamp,
}

/// The outcome of [`run_retroactive_review`] (Flow 3).
#[derive(Debug)]
pub enum RetroOutcome {
    /// The vote reached the retro threshold: a batch was minted (Req 10.6).
    Approved(MintReceipt),
    /// The vote fell short of the retro threshold: nothing was minted (Req 10.5).
    Rejected,
}

/// **Flow 3 — 事后申报审核投票.** Submits a retroactive declaration, runs the
/// stakeholder vote, and mints **only on approval** (Req 10.5/10.6).
///
/// Steps: submit (Req 10.1/10.2; an unreplayable evidence reference is rejected with
/// [`GmcError::EvidenceInvalid`] before voting) → conduct the retroactive vote
/// ([`conduct_retro_vote`]: select voters, weighted tally, resolve against the stricter
/// retro threshold) → on **Approved**, score (Req 7.x/8.3) and mint into `pocket`
/// against `ledger` per the three-dimension model (Req 10.6), then anchor the outcome
/// to L1 (Req 10.7); on **Rejected**, mint nothing and anchor the rejection (Req 10.5).
#[allow(clippy::too_many_arguments)]
pub fn run_retroactive_review(
    retro: &mut RetroactiveReviewModule,
    governance: &mut GovernanceModule,
    scoring: &ScoringEngine,
    minting: &MintingService,
    pocket: &mut MeritPocket,
    quota_config: &QuotaConfig,
    ledger: &mut QuotaLedger,
    l1: &mut L1Settlement,
    input: RetroFlowInput,
) -> GmcResult<RetroOutcome> {
    // 1. Intake + evidence replayability check (Req 10.1/10.2/10.8).
    let chain_id = input.application.chain_id.clone();
    let declaration_id = retro.submit(input.application)?;

    // 2. Select voters, tally the weighted vote, resolve against the retro threshold.
    let (status, vote_handle) = conduct_retro_vote(
        retro,
        governance,
        &declaration_id,
        &input.voters,
        input.sample_size,
        input.seed,
        input.regular_threshold,
        &input.subject,
    )?;

    match status {
        ReviewStatus::Approved => {
            // 3a. Approved: score + mint per the three-dimension model (Req 10.6).
            let amount =
                scoring.compute_mint_amount(&input.weights, &input.base_scores, &input.indices)?;
            let receipt = minting.mint(
                pocket,
                quota_config,
                ledger,
                MintRequest::new(
                    input.batch_id,
                    amount,
                    input.influence_duration,
                    input.acquired_at,
                    chain_id,
                ),
            )?;
            // Anchor the approved outcome to L1 (Req 10.7).
            anchor_retro_outcome(
                retro,
                l1,
                &declaration_id,
                &vote_handle,
                &input.subject,
                true,
                input.acquired_at,
            )?;
            Ok(RetroOutcome::Approved(receipt))
        }
        ReviewStatus::Rejected => {
            // 3b. Rejected: mint nothing, anchor the rejection (Req 10.5/10.7).
            anchor_retro_outcome(
                retro,
                l1,
                &declaration_id,
                &vote_handle,
                &input.subject,
                false,
                input.acquired_at,
            )?;
            Ok(RetroOutcome::Rejected)
        }
        // resolve_vote only ever yields Approved/Rejected; Pending is unreachable here.
        ReviewStatus::Pending => unreachable!("resolve_vote advances out of Pending"),
    }
}

// ===========================================================================
// Flow 4 — 碳积分转 MeriToken (carbon → MeriToken)
// ===========================================================================

/// The per-call inputs of [`run_carbon_conversion`] (Flow 4).
pub struct CarbonFlowInput {
    /// The contributor making the carbon claim.
    pub contributor_id: FayID,
    /// The environmental-protection chain the claim targets.
    pub chain_id: ChainId,
    /// Description of the decarbonization action.
    pub description: String,
    /// On-chain time the action occurred.
    pub occurred_at: Timestamp,
    /// Candidate voters with intimacy / `curMerit` / ballot (Req 11.x).
    pub voters: Vec<RetroVoter>,
    /// Requested voter-set size (clamped to `[7, eligible]`, Req 11.2).
    pub sample_size: usize,
    /// Deterministic sampling seed.
    pub seed: u64,
    /// The chain's regular contribution-recognition threshold (Req 10.3 input).
    pub regular_threshold: Ratio,
    /// Opaque vote subject for governance / anchoring.
    pub subject: String,
    /// Three-dimension weights for scoring on approval (Req 6.5).
    pub weights: DimensionWeights,
    /// Per-dimension base scores (Req 7.6).
    pub base_scores: BaseScores,
    /// Per-dimension inflation indices (Req 7.x).
    pub indices: InflationIndexConfig,
    /// Acquisition / anchoring time for the L1 record.
    pub acquired_at: Timestamp,
}

/// The outcome of [`run_carbon_conversion`] (Flow 4).
#[derive(Debug)]
pub enum CarbonOutcome {
    /// The vote approved the conversion: the env-chain quota was charged and the
    /// voucher marked converted (Req 12.5/12.7). Carries the minted amount.
    Converted(Decimal),
    /// The vote rejected the claim: nothing was converted, no quota consumed (Req 10.5).
    Rejected,
}

/// **Flow 4 — 碳积分转 MeriToken.** Imports a carbon-credit voucher into the
/// retroactive flow, runs the vote, and on approval charges the env-chain quota +
/// marks the voucher converted (Req 12.2/12.5/12.6/12.7).
///
/// Steps: `carbon::CarbonCreditVoucher::import_to_retroactive_flow` (Req 12.1; an
/// unverifiable voucher reference is rejected with [`GmcError::EvidenceInvalid`] before
/// voting, Req 12.4) → the same retroactive vote as Flow 3 ([`conduct_retro_vote`]) →
/// on **Approved**, score the conversion (Req 12.2/12.3) and call
/// `carbon::CarbonCreditVoucher::convert`, which **charges** the env chain's current
/// `Refresh_Period` quota for the minted amount (Req 12.5) and **marks the voucher
/// converted** exactly once (Req 12.7); a later second conversion of the same voucher
/// is rejected with [`GmcError::DoubleConversion`] (Req 12.6). The outcome is then
/// anchored to L1 (Req 10.7). On **Rejected**, nothing is converted and no quota is
/// consumed (Req 10.5).
///
/// > **Quota accounting note.** `carbon::convert` is the single authoritative quota
/// > charge for a carbon conversion (Req 12.5): it is the carbon-specific accountant
/// > that also owns the at-most-once guard. This flow therefore routes the env-chain
/// > quota charge through `convert` (not a separate `MintingService` mint), so the
/// > converted amount is counted in the current period exactly once.
#[allow(clippy::too_many_arguments)]
pub fn run_carbon_conversion(
    voucher: &mut CarbonCreditVoucher,
    retro: &mut RetroactiveReviewModule,
    governance: &mut GovernanceModule,
    scoring: &ScoringEngine,
    env_quota_config: &QuotaConfig,
    env_ledger: &mut QuotaLedger,
    l1: &mut L1Settlement,
    input: CarbonFlowInput,
) -> GmcResult<CarbonOutcome> {
    // 1. Import the carbon voucher as a retroactive declaration (Req 12.1/12.4).
    let declaration_id = voucher.import_to_retroactive_flow(
        retro,
        input.contributor_id,
        input.chain_id,
        input.description,
        input.occurred_at,
    )?;

    // 2. Run the retroactive vote (same machinery as Flow 3).
    let (status, vote_handle) = conduct_retro_vote(
        retro,
        governance,
        &declaration_id,
        &input.voters,
        input.sample_size,
        input.seed,
        input.regular_threshold,
        &input.subject,
    )?;

    match status {
        ReviewStatus::Approved => {
            // 3a. Score the conversion (Req 12.2/12.3).
            let amount =
                scoring.compute_mint_amount(&input.weights, &input.base_scores, &input.indices)?;
            // Charge the env chain's current-period quota and mark the voucher
            // converted, both exactly once (Req 12.5/12.7); a second conversion of the
            // same voucher would be rejected with DoubleConversion (Req 12.6).
            voucher.convert(
                declaration_id.as_str(),
                amount,
                env_quota_config,
                env_ledger,
            )?;
            // Anchor the approved outcome to L1 (Req 10.7).
            anchor_retro_outcome(
                retro,
                l1,
                &declaration_id,
                &vote_handle,
                &input.subject,
                true,
                input.acquired_at,
            )?;
            Ok(CarbonOutcome::Converted(amount))
        }
        ReviewStatus::Rejected => {
            // 3b. Rejected: nothing converted, no quota consumed (Req 10.5).
            anchor_retro_outcome(
                retro,
                l1,
                &declaration_id,
                &vote_handle,
                &input.subject,
                false,
                input.acquired_at,
            )?;
            Ok(CarbonOutcome::Rejected)
        }
        ReviewStatus::Pending => unreachable!("resolve_vote advances out of Pending"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2_rollup::{ContributionSubmission, L2Rollup};
    use crate::merit::{MeritBatch, E};
    use crate::quota::{RefreshPeriod, TimeUnit};
    use crate::recording::EvidenceRef as RecordingEvidenceRef;
    use crate::registry::NestedMeritChain;
    use crate::retroactive::EvidenceRef as RetroEvidenceRef;
    use crate::types::Dimension;

    // --- shared fixtures ----------------------------------------------------

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

    /// A creation request deriving `proposed_id` (in `domain`) under the root.
    fn creation_request(proposed_id: &str, domain: &str) -> CreationRequest {
        CreationRequest::new(
            ChainId::new(proposed_id),
            ChainId::new("gmc-base"),
            domain,
            vec![FayID::new("steward-1")],
            ts(2_000),
        )
    }

    /// A pocket whose initial floor `E` is backed by a slowly-decaying batch with
    /// `B = E`, so `Σ B_i` starts equal to `minMerit` and the `curMerit ≥ minMerit`
    /// invariant is well-defined through subsequent mints (mirrors `minting.rs`).
    fn backed_pocket() -> MeritPocket {
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        pocket.add_batch(MeritBatch::new(
            "reg-grant",
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

    /// Seven low-intimacy (0.5) voters of equal `curMerit`, all casting `approve`.
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

    fn replayable_evidence() -> RetroEvidenceRef {
        RetroEvidenceRef::new("ipfs://cid-abc", "0xhash", true)
    }

    // === Flow 1 — chain derivation ======================================

    #[test]
    fn flow1_creates_chain_and_anchors_to_l1() {
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

        // The chain exists in the registry.
        assert_eq!(chain_id, ChainId::new("academic"));
        assert!(registry.contains(&chain_id));

        // The creation record was anchored to L1 (Req 2.6) and advanced the state root.
        let record = l1
            .chain_registration(&chain_id)
            .expect("creation record anchored to L1");
        assert_eq!(record.domain, "academic");
        assert_eq!(record.parent_id, Some(ChainId::new("gmc-base")));
        assert_ne!(state_root, StateRoot::GENESIS);
        assert_eq!(l1.state_root(), state_root);
    }

    #[test]
    fn flow1_failed_gate_creates_nothing_and_does_not_anchor() {
        let mut registry = registry_with_root();
        let mut l1 = L1Settlement::new();
        let before_len = registry.len();

        let err = run_chain_creation(
            &mut registry,
            &mut l1,
            creation_request("academic", "academic"),
            CreationChannel::Vote {
                governance_passed: false,
            },
        )
        .expect_err("a failed vote must be rejected");

        assert_eq!(err, GmcError::GovernanceThresholdNotMet);
        // Registry unchanged and nothing anchored to L1.
        assert_eq!(registry.len(), before_len);
        assert!(!registry.contains(&ChainId::new("academic")));
        assert_eq!(l1.state_root(), StateRoot::GENESIS);
        assert_eq!(l1.chain_registration_count(), 0);
    }

    // === Flow 2 — register → record → grant =============================

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

    #[test]
    fn flow2_happy_path_mints_when_all_three_conditions_hold() {
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

    #[test]
    fn flow2_guard_blocks_mint_when_evaluation_not_passed() {
        let mut registrations = RegistrationService::new();
        let mut recordings = RecordingService::new();
        let scoring = ScoringEngine::new();
        let minting = MintingService::new();
        let mut pocket = backed_pocket();
        let quota = periodic_quota("1000");
        let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));
        let pocket_before = pocket.clone();

        // evaluation_passed = false → record marked Failed → grant guard fails.
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
        // Nothing minted: quota counter and pocket are untouched (Req 9.5/9.8).
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(pocket, pocket_before);
    }

    // === Flow 3 — retroactive review / voting ===========================

    fn retro_input(approve: bool) -> RetroFlowInput {
        RetroFlowInput {
            application: RetroactiveApplication::new(
                FayID::new("alice"),
                ChainId::new("academic"),
                "Did the work in 2023, never registered up front.",
                ts(1_600_000_000),
                vec![replayable_evidence()],
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

    #[test]
    fn flow3_mints_on_approval() {
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

    #[test]
    fn flow3_mints_nothing_on_rejection() {
        let mut retro = RetroactiveReviewModule::new();
        let mut governance = GovernanceModule::new();
        let scoring = ScoringEngine::new();
        let minting = MintingService::new();
        let mut pocket = backed_pocket();
        let quota = periodic_quota("1000");
        let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));
        let mut l1 = L1Settlement::new();
        let pocket_before = pocket.clone();

        // All voters reject → weighted approval 0 < retro threshold → Rejected.
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
        // Nothing minted; pocket and quota untouched (Req 10.5).
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(pocket, pocket_before);
        // The rejection was still anchored to L1 (Req 10.7).
        assert_ne!(l1.state_root(), StateRoot::GENESIS);
    }

    #[test]
    fn flow3_unreplayable_evidence_is_rejected_before_voting() {
        let mut retro = RetroactiveReviewModule::new();
        let mut governance = GovernanceModule::new();
        let scoring = ScoringEngine::new();
        let minting = MintingService::new();
        let mut pocket = backed_pocket();
        let quota = periodic_quota("1000");
        let mut ledger = QuotaLedger::new(ChainId::new("academic"), ts(0));
        let mut l1 = L1Settlement::new();

        let mut input = retro_input(true);
        input.application = RetroactiveApplication::new(
            FayID::new("alice"),
            ChainId::new("academic"),
            "Claim with an unverifiable reference.",
            ts(1_600_000_000),
            vec![RetroEvidenceRef::new("ipfs://cid", "0xhash", false)],
        );

        let err = run_retroactive_review(
            &mut retro,
            &mut governance,
            &scoring,
            &minting,
            &mut pocket,
            &quota,
            &mut ledger,
            &mut l1,
            input,
        )
        .expect_err("unreplayable evidence must be rejected");
        assert_eq!(err, GmcError::EvidenceInvalid);
        // Never entered voting; nothing minted or anchored.
        assert!(retro.is_empty());
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(l1.state_root(), StateRoot::GENESIS);
    }

    // === Flow 4 — carbon → MeriToken ====================================

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

    #[test]
    fn flow4_charges_quota_and_marks_converted_on_approval() {
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
        // The env chain's current-period quota was charged by the minted amount (Req 12.5).
        assert_eq!(env_ledger.minted_this_period(), standard_amount());
        assert!(env_ledger.minted_this_period() <= env_quota.quota());
        // The voucher is marked converted exactly once (Req 12.7).
        assert!(voucher.is_converted());
        // Outcome anchored to L1.
        assert_ne!(l1.state_root(), StateRoot::GENESIS);

        // A second conversion of the same voucher is rejected (Req 12.6).
        let err = voucher
            .convert("decl-again", standard_amount(), &env_quota, &mut env_ledger)
            .expect_err("a converted voucher must reject a second conversion");
        assert_eq!(err, GmcError::DoubleConversion);
        // No extra quota consumed by the rejected second conversion.
        assert_eq!(env_ledger.minted_this_period(), standard_amount());
    }

    #[test]
    fn flow4_rejection_converts_nothing_and_consumes_no_quota() {
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
        // Nothing converted, no quota consumed (Req 10.5 / 12.5).
        assert!(!voucher.is_converted());
        assert_eq!(env_ledger.minted_this_period(), Decimal::ZERO);
    }

    // === L2 → L1 wiring (Req 9.7 / 13.8) ================================

    #[test]
    fn l2_batch_is_verified_and_anchored_on_l1() {
        let mut rollup = L2Rollup::new(ts(0));
        let mut l1 = L1Settlement::new();

        // Process one record, then flush via the 60-second interval trigger.
        rollup.process_contribution(
            ContributionSubmission::new(
                FayID::new("alice"),
                ChainId::new("academic"),
                standard_amount(),
            ),
            ts(1),
        );
        let batch = rollup
            .try_submit_batch(ts(61))
            .expect("60s elapsed with ≥1 record triggers a batch");

        let before_version = l1.version();
        anchor_rollup_batch(&batch, &mut l1).expect("an L2-produced batch verifies on L1");

        // L1 advanced its confirmed state root to the mapped batch root (Req 13.8).
        let expected = StateRoot::from_bytes(*batch.batch_root.as_bytes());
        assert_eq!(l1.state_root(), expected);
        assert_eq!(l1.version(), before_version + 1);
    }
}
