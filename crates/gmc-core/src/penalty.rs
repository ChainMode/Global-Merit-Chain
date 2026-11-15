//! Blueprint Chapter 9 penalty, batch-bound complaint admissibility, and
//! wider-community appeal engine (`OQ-P2-GMC-7`).
//!
//! ## Architectural Invariant — Sole `minMerit` Reduction Channel
//!
//! Across the entire GMChain protocol, natural batch decay only reduces `curMerit`
//! toward `minMerit`, and new minting/inheritance only ever increases `minMerit`.
//! **Governance penalty execution in this module (`Severe` / `Critical` severities
//! reaching the `>= 3/4` weighted supermajority) is the SOLE mechanism in GMChain
//! permitted to reduce an identity's `minMerit` floor** (Blueprint §4.5, §9.1).
//!
//! Every calculation uses `gmc-core`'s pure `i128` fixed-point [`Decimal`] / [`Ratio`]
//! (`SCALE = 1_000_000`) with full-precision cross-multiplication for supermajority
//! checks (`approve * SCALE >= total * threshold`), eliminating floating-point drift
//! and intermediate rounding bias.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{GmcError, GmcResult};
use crate::merit::{MeritBatch, MeritPocket, E};
use crate::types::{Decimal, FayID, Ratio, Timestamp};

const fn const_ratio(raw: i128) -> Ratio {
    match Ratio::new(Decimal::from_raw(raw)) {
        Some(r) => r,
        None => panic!("const_ratio out of [0, 1]"),
    }
}

/// Mandatory weighted supermajority (`3/4 = 0.750000`) required to execute any penalty (§9.2).
pub const PENALTY_SUPERMAJORITY_THRESHOLD: Ratio = const_ratio(750_000);

/// Default stakeholder admissibility threshold (`>= 1/3` weighted approval, §9.2).
pub const DEFAULT_ADMISSIBILITY_THRESHOLD: Ratio = const_ratio(333_334);

/// Default wider-community appeal overturn threshold (`>= 3/5 = 0.600000`, §9.4).
pub const DEFAULT_APPEAL_THRESHOLD: Ratio = const_ratio(600_000);

/// Default cooldown between complaints filed by the same complainant (`24h = 86,400s`, §9.3).
pub const DEFAULT_COMPLAINT_COOLDOWN_SECS: u64 = 86_400;

/// Default maximum dismissed complaints before a vexatious filer is blocked (§9.3).
pub const DEFAULT_MAX_DISMISSED_STRIKES: u32 = 3;

/// Default time window after penalty execution during which an appeal may be filed (`7d = 604,800s`, §9.4).
pub const DEFAULT_APPEAL_WINDOW_SECS: u64 = 7 * 86_400;

/// Four graded penalty severities defined in Blueprint §9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PenaltySeverity {
    /// Minor violation (`轻微违规`): reduces `curMerit` (`20%` of offending batch excess),
    /// leaves `minMerit` strictly unchanged (`0%` floor slash).
    Minor,
    /// Moderate violation (`中度违规`): reduces `curMerit` (`50%` of offending batch excess),
    /// leaves `minMerit` strictly unchanged (`0%` floor slash).
    Moderate,
    /// Severe violation (`严重违规`): slashes `curMerit` (`80%` on offending batch + `25%`
    /// pocket-wide) and reduces `minMerit` by `25%`.
    Severe,
    /// Critical violation (`极端违规`, e.g. Sybil / fabricated contribution): slashes `100%`
    /// of offending batch + `50%` of remaining batches and reduces `minMerit` by `60%`.
    Critical,
}

impl PenaltySeverity {
    /// Returns `true` iff this severity is permitted to lower `minMerit` (`Severe` / `Critical`).
    pub const fn reduces_min_merit(self) -> bool {
        matches!(self, PenaltySeverity::Severe | PenaltySeverity::Critical)
    }

    /// Slash ratio applied to the offending batch's decayable value (`V - B`, or full `V` when reducing floor).
    pub const fn offending_batch_slash_ratio(self) -> Ratio {
        match self {
            PenaltySeverity::Minor => const_ratio(200_000),    // 20%
            PenaltySeverity::Moderate => const_ratio(500_000), // 50%
            PenaltySeverity::Severe => const_ratio(800_000),   // 80%
            PenaltySeverity::Critical => Ratio::ONE,           // 100%
        }
    }

    /// Additional slash ratio applied across non-offending batches (`0%` for `Minor`/`Moderate`).
    pub const fn pocket_wide_slash_ratio(self) -> Ratio {
        match self {
            PenaltySeverity::Minor | PenaltySeverity::Moderate => Ratio::ZERO,
            PenaltySeverity::Severe => const_ratio(250_000),   // 25%
            PenaltySeverity::Critical => const_ratio(500_000), // 50%
        }
    }

    /// Slash ratio applied to `minMerit` (`0%` for `Minor`/`Moderate`, `25%` for `Severe`, `60%` for `Critical`).
    pub const fn min_merit_slash_ratio(self) -> Ratio {
        match self {
            PenaltySeverity::Minor | PenaltySeverity::Moderate => Ratio::ZERO,
            PenaltySeverity::Severe => const_ratio(250_000),   // 25%
            PenaltySeverity::Critical => const_ratio(600_000), // 60%
        }
    }
}

/// Configurable governance parameters for complaint screening, penalty execution, and appeals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PenaltyPolicy {
    /// Minimum `curMerit` a complainant must hold to file a complaint (§9.3 anti-spam guard).
    pub min_complainant_merit: Decimal,
    /// Minimum seconds between complaints by the same complainant (§9.3).
    pub complaint_cooldown_secs: u64,
    /// Maximum dismissed complaints before complainant is blocked (§9.3).
    pub max_dismissed_strikes: u32,
    /// Weighted approval threshold required to pass Stage 1 admissibility (§9.2).
    pub admissibility_threshold: Ratio,
    /// Weighted approval supermajority required to execute Stage 2 penalty (`>= 3/4`, §9.2).
    pub penalty_threshold: Ratio,
    /// Post-execution window in seconds within which an appeal must be filed (§9.4).
    pub appeal_window_secs: u64,
    /// Weighted approval threshold required in wider-community appeal to overturn penalty (§9.4).
    pub appeal_threshold: Ratio,
}

impl Default for PenaltyPolicy {
    fn default() -> Self {
        PenaltyPolicy {
            min_complainant_merit: E,
            complaint_cooldown_secs: DEFAULT_COMPLAINT_COOLDOWN_SECS,
            max_dismissed_strikes: DEFAULT_MAX_DISMISSED_STRIKES,
            admissibility_threshold: DEFAULT_ADMISSIBILITY_THRESHOLD,
            penalty_threshold: PENALTY_SUPERMAJORITY_THRESHOLD,
            appeal_window_secs: DEFAULT_APPEAL_WINDOW_SECS,
            appeal_threshold: DEFAULT_APPEAL_THRESHOLD,
        }
    }
}

/// Weighted governance ballot cast in admissibility, penalty, or appeal stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyBallot {
    pub voter: FayID,
    pub cur_merit: Decimal,
    pub approve: bool,
}

/// Batch-bound complaint record (§9.2, §9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complaint {
    pub complaint_id: String,
    pub complainant: FayID,
    pub respondent: FayID,
    /// Specific contribution/mint `batch_id` being challenged (vague/batchless complaints are invalid).
    pub batch_id: String,
    /// Canonical 64-character lowercase hex digest of verifiable evidence.
    pub evidence_hash: String,
    pub severity: PenaltySeverity,
    pub filed_at: Timestamp,
}

/// Anti-malicious-complaint tracking state per complainant (§9.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComplainantStanding {
    pub last_filed_at: Option<Timestamp>,
    pub dismissed_strikes: u32,
}

/// Lifecycle stage of a complaint / penalty case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaseStage {
    /// Filed and awaiting stakeholder admissibility vote.
    Filed,
    /// Dismissed during admissibility screening (complainant strike incremented).
    Dismissed,
    /// Admitted by stakeholders and awaiting `>= 3/4` supermajority penalty vote.
    Admitted,
    /// Penalty executed on respondent's pocket; open for appeal within `appeal_window_secs`.
    Executed,
    /// Appeal submitted within window; awaiting wider-community resolution.
    Appealed,
    /// Penalty overturned by wider-community appeal; respondent pocket atomically restored.
    OverturnedOnAppeal,
    /// Penalty upheld after wider-community appeal; case closed.
    AppealUpheld,
}

/// Pre-penalty snapshot used to guarantee lossless atomic restoration if an appeal succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltySnapshot {
    pub pre_min_merit: Decimal,
    pub pre_batches: Vec<MeritBatch>,
}

/// Auditable L1-anchorable penalty execution receipt (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyExecutionRecord {
    pub complaint_id: String,
    pub respondent: FayID,
    pub batch_id: String,
    pub severity: PenaltySeverity,
    pub executed_at: Timestamp,
    pub voter_count: usize,
    pub approve_merit: Decimal,
    pub total_merit: Decimal,
    pub cur_merit_before: Decimal,
    pub cur_merit_after: Decimal,
    pub min_merit_before: Decimal,
    pub min_merit_after: Decimal,
}

/// Appeal filing record (§9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealSubmission {
    pub submitted_at: Timestamp,
    pub counter_evidence_hash: String,
}

/// Outcome of resolving a wider-community appeal (§9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppealOutcome {
    /// Appeal passed: respondent's slashed `curMerit` batches and `minMerit` were atomically restored.
    Overturned {
        restored_cur_merit: Decimal,
        restored_min_merit: Decimal,
    },
    /// Appeal did not reach threshold: original penalty remains in force.
    PenaltyUpheld,
}

/// Full state of a tracked complaint/penalty/appeal case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyCase {
    pub complaint: Complaint,
    pub stage: CaseStage,
    pub snapshot: Option<PenaltySnapshot>,
    pub execution: Option<PenaltyExecutionRecord>,
    pub appeal: Option<AppealSubmission>,
}

/// Validates that `hash_hex` is a canonical 64-character hex digest and not all-zero.
pub fn is_valid_evidence_hash(hash_hex: &str) -> bool {
    if hash_hex.len() != 64 {
        return false;
    }
    let mut non_zero = false;
    for b in hash_hex.bytes() {
        let is_hex = b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b);
        if !is_hex {
            return false;
        }
        if b != b'0' {
            non_zero = true;
        }
    }
    non_zero
}

/// Tallies deduplicated weighted ballots (excluding the complainant and respondent so neither
/// party votes on their own dispute), returning `(voter_count, approve_merit, total_merit)`.
fn tally_ballots(
    ballots: &[PenaltyBallot],
    complainant: &FayID,
    respondent: &FayID,
) -> GmcResult<(usize, Decimal, Decimal)> {
    let mut seen = BTreeSet::new();
    let mut approve_merit = Decimal::ZERO;
    let mut total_merit = Decimal::ZERO;

    for ballot in ballots {
        if &ballot.voter == complainant || &ballot.voter == respondent {
            continue;
        }
        if !ballot.cur_merit.is_positive() {
            continue;
        }
        if !seen.insert(ballot.voter.clone()) {
            continue;
        }
        total_merit = total_merit
            .checked_add(ballot.cur_merit)
            .ok_or(GmcError::InvalidMintAmount)?;
        if ballot.approve {
            approve_merit = approve_merit
                .checked_add(ballot.cur_merit)
                .ok_or(GmcError::InvalidMintAmount)?;
        }
    }

    if seen.is_empty() || !total_merit.is_positive() {
        return Err(GmcError::StakeholderInsufficient);
    }

    Ok((seen.len(), approve_merit, total_merit))
}

/// Full-precision cross-multiplied threshold test: `approve / total >= threshold`
/// computed as `approve.raw() * SCALE >= total.raw() * threshold.value().raw()`.
#[inline]
fn meets_weighted_threshold(approve: Decimal, total: Decimal, threshold: Ratio) -> bool {
    if !total.is_positive() {
        return false;
    }
    approve.raw() * Decimal::SCALE >= total.raw() * threshold.value().raw()
}

/// Applies the deterministic `i128` slash for `severity` targeting `offending_batch_id`
/// while preserving `curMerit(now) >= minMerit >= 0` and `sum(batch.b) >= minMerit`.
fn apply_slash_to_pocket(
    pocket: &mut MeritPocket,
    offending_batch_id: &str,
    severity: PenaltySeverity,
    now: Timestamp,
) -> GmcResult<()> {
    if !pocket.batches.iter().any(|b| b.batch_id == offending_batch_id) {
        return Err(GmcError::ComplaintInvalid);
    }

    let one = Decimal::ONE;
    let offending_keep = one
        .checked_sub(severity.offending_batch_slash_ratio().value())
        .unwrap_or(Decimal::ZERO);
    let pocket_keep = one
        .checked_sub(severity.pocket_wide_slash_ratio().value())
        .unwrap_or(Decimal::ONE);
    let floor_keep = one
        .checked_sub(severity.min_merit_slash_ratio().value())
        .unwrap_or(Decimal::ONE);

    if !severity.reduces_min_merit() {
        // Minor & Moderate: NEVER reduce `min_merit` or any batch's floor `b`!
        let cur_before = pocket.cur_merit(now);
        let max_removable = cur_before
            .checked_sub(pocket.min_merit)
            .unwrap_or(Decimal::ZERO)
            .max(Decimal::ZERO);

        if let Some(batch) = pocket
            .batches
            .iter_mut()
            .find(|b| b.batch_id == offending_batch_id)
        {
            let batch_now = batch.merit_at(now);
            let excess_now = batch_now.checked_sub(batch.b).unwrap_or(Decimal::ZERO);
            let desired_cut = excess_now
                .checked_mul(severity.offending_batch_slash_ratio().value())
                .unwrap_or(Decimal::ZERO);
            let actual_cut = desired_cut.min(max_removable);

            if excess_now.is_positive() && actual_cut.is_positive() {
                let remain_excess = excess_now
                    .checked_sub(actual_cut)
                    .unwrap_or(Decimal::ZERO);
                let amp = batch.v.checked_sub(batch.b).unwrap_or(Decimal::ZERO);
                let new_amp = amp
                    .checked_mul(remain_excess)
                    .and_then(|x| x.checked_div(excess_now))
                    .unwrap_or(Decimal::ZERO);
                batch.v = batch.b.checked_add(new_amp).unwrap_or(batch.b);
            }
        }
        let cur_after = pocket.cur_merit(now);
        if cur_after < pocket.min_merit {
            let deficit = pocket
                .min_merit
                .checked_sub(cur_after)
                .unwrap_or(Decimal::ZERO);
            if let Some(batch) = pocket
                .batches
                .iter_mut()
                .find(|b| b.batch_id == offending_batch_id)
            {
                batch.v = batch.v.checked_add(deficit).unwrap_or(batch.v);
                batch.b = batch.b.max(
                    batch
                        .b
                        .checked_add(deficit)
                        .unwrap_or(batch.b)
                        .min(batch.v),
                );
            }
        }
    } else {
        // Severe & Critical: SOLE mechanism permitted to lower `minMerit`.
        for batch in &mut pocket.batches {
            let keep = if batch.batch_id == offending_batch_id {
                offending_keep
            } else {
                pocket_keep
            };
            batch.v = batch.v.checked_mul(keep).unwrap_or(Decimal::ZERO);
            batch.b = batch
                .b
                .checked_mul(keep)
                .unwrap_or(Decimal::ZERO)
                .min(batch.v);
        }
        let target_min = pocket
            .min_merit
            .checked_mul(floor_keep)
            .unwrap_or(Decimal::ZERO)
            .max(Decimal::ZERO);
        let cur_after = pocket.cur_merit(now);
        pocket.min_merit = target_min.min(cur_after).max(Decimal::ZERO);
    }

    Ok(())
}

/// Deterministic Chapter 9 penalty & appeal governance engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyEngine {
    pub policy: PenaltyPolicy,
    cases: BTreeMap<String, PenaltyCase>,
    complainants: BTreeMap<FayID, ComplainantStanding>,
}

impl Default for PenaltyEngine {
    fn default() -> Self {
        Self::new(PenaltyPolicy::default())
    }
}

impl PenaltyEngine {
    /// Creates a new `PenaltyEngine` with the given `policy`.
    pub fn new(policy: PenaltyPolicy) -> Self {
        PenaltyEngine {
            policy,
            cases: BTreeMap::new(),
            complainants: BTreeMap::new(),
        }
    }

    /// Inspects a tracked case by `complaint_id`.
    pub fn get_case(&self, complaint_id: &str) -> Option<&PenaltyCase> {
        self.cases.get(complaint_id)
    }

    /// Ordered iterator over all cases for deterministic persistence / state root hashing.
    pub fn cases(&self) -> impl Iterator<Item = (&String, &PenaltyCase)> {
        self.cases.iter()
    }

    /// Ordered iterator over all complainant standings.
    pub fn complainant_standings(&self) -> impl Iterator<Item = (&FayID, &ComplainantStanding)> {
        self.complainants.iter()
    }

    /// Restores a case during deterministic snapshot loading.
    pub fn restore_case(&mut self, case: PenaltyCase) {
        self.cases.insert(case.complaint.complaint_id.clone(), case);
    }

    /// Restores complainant standing during deterministic snapshot loading.
    pub fn restore_complainant_standing(
        &mut self,
        complainant: FayID,
        standing: ComplainantStanding,
    ) {
        self.complainants.insert(complainant, standing);
    }

    /// Stage 0: Files a batch-bound complaint (§9.2, §9.3).
    pub fn file_complaint(
        &mut self,
        complaint: Complaint,
        complainant_cur_merit: Decimal,
        respondent_pocket: &MeritPocket,
    ) -> GmcResult<()> {
        if complaint.complaint_id.trim().is_empty()
            || self.cases.contains_key(&complaint.complaint_id)
            || complaint.complainant == complaint.respondent
            || complaint.respondent != respondent_pocket.fay_id
            || complaint.batch_id.trim().is_empty()
            || !is_valid_evidence_hash(&complaint.evidence_hash)
        {
            return Err(GmcError::ComplaintInvalid);
        }

        if !respondent_pocket
            .batches
            .iter()
            .any(|b| b.batch_id == complaint.batch_id)
        {
            return Err(GmcError::ComplaintInvalid);
        }

        if complainant_cur_merit < self.policy.min_complainant_merit {
            return Err(GmcError::MaliciousComplainantBlocked);
        }

        let standing = self
            .complainants
            .get(&complaint.complainant)
            .cloned()
            .unwrap_or_default();
        if standing.dismissed_strikes >= self.policy.max_dismissed_strikes {
            return Err(GmcError::MaliciousComplainantBlocked);
        }
        if let Some(last_ts) = standing.last_filed_at {
            if complaint.filed_at < last_ts
                || complaint.filed_at.saturating_elapsed_since(last_ts)
                    < self.policy.complaint_cooldown_secs
            {
                return Err(GmcError::ComplaintCooldownActive);
            }
        }

        let updated_standing = ComplainantStanding {
            last_filed_at: Some(complaint.filed_at),
            dismissed_strikes: standing.dismissed_strikes,
        };
        self.complainants
            .insert(complaint.complainant.clone(), updated_standing);
        self.cases.insert(
            complaint.complaint_id.clone(),
            PenaltyCase {
                complaint,
                stage: CaseStage::Filed,
                snapshot: None,
                execution: None,
                appeal: None,
            },
        );
        Ok(())
    }

    /// Stage 1: Evaluates stakeholder admissibility vote (§9.2).
    pub fn resolve_admissibility(
        &mut self,
        complaint_id: &str,
        ballots: &[PenaltyBallot],
    ) -> GmcResult<bool> {
        let (complainant, respondent, stage) = {
            let case = self
                .cases
                .get(complaint_id)
                .ok_or(GmcError::ComplaintInvalid)?;
            (
                case.complaint.complainant.clone(),
                case.complaint.respondent.clone(),
                case.stage,
            )
        };
        if stage != CaseStage::Filed {
            return Err(GmcError::OperationNotAllowed);
        }

        let (_voter_count, approve_merit, total_merit) =
            tally_ballots(ballots, &complainant, &respondent)?;
        let admitted =
            meets_weighted_threshold(approve_merit, total_merit, self.policy.admissibility_threshold);

        let case = self.cases.get_mut(complaint_id).unwrap();
        if admitted {
            case.stage = CaseStage::Admitted;
            Ok(true)
        } else {
            case.stage = CaseStage::Dismissed;
            let standing = self.complainants.entry(complainant).or_default();
            standing.dismissed_strikes = standing.dismissed_strikes.saturating_add(1);
            Ok(false)
        }
    }

    /// Stage 2: Evaluates the `>= 3/4` (`750_000 / 1_000_000`) weighted supermajority vote
    /// and, if passed, atomically executes the severity-graded slash on `respondent_pocket` (§9.1, §9.2).
    pub fn execute_penalty(
        &mut self,
        complaint_id: &str,
        respondent_pocket: &mut MeritPocket,
        ballots: &[PenaltyBallot],
        executed_at: Timestamp,
    ) -> GmcResult<PenaltyExecutionRecord> {
        let (complainant, respondent, batch_id, severity, stage, filed_at) = {
            let case = self
                .cases
                .get(complaint_id)
                .ok_or(GmcError::ComplaintInvalid)?;
            (
                case.complaint.complainant.clone(),
                case.complaint.respondent.clone(),
                case.complaint.batch_id.clone(),
                case.complaint.severity,
                case.stage,
                case.complaint.filed_at,
            )
        };

        if stage != CaseStage::Admitted {
            return Err(GmcError::AdmissibilityNotMet);
        }
        if respondent_pocket.fay_id != respondent || executed_at < filed_at {
            return Err(GmcError::ComplaintInvalid);
        }

        let (voter_count, approve_merit, total_merit) =
            tally_ballots(ballots, &complainant, &respondent)?;

        if !meets_weighted_threshold(approve_merit, total_merit, self.policy.penalty_threshold) {
            return Err(GmcError::GovernanceThresholdNotMet);
        }

        let snapshot = PenaltySnapshot {
            pre_min_merit: respondent_pocket.min_merit,
            pre_batches: respondent_pocket.batches.clone(),
        };
        let cur_merit_before = respondent_pocket.cur_merit(executed_at);
        let min_merit_before = respondent_pocket.min_merit;

        apply_slash_to_pocket(respondent_pocket, &batch_id, severity, executed_at)?;

        let cur_merit_after = respondent_pocket.cur_merit(executed_at);
        let min_merit_after = respondent_pocket.min_merit;

        let record = PenaltyExecutionRecord {
            complaint_id: complaint_id.to_string(),
            respondent,
            batch_id,
            severity,
            executed_at,
            voter_count,
            approve_merit,
            total_merit,
            cur_merit_before,
            cur_merit_after,
            min_merit_before,
            min_merit_after,
        };

        let case = self.cases.get_mut(complaint_id).unwrap();
        case.snapshot = Some(snapshot);
        case.execution = Some(record.clone());
        case.stage = CaseStage::Executed;
        Ok(record)
    }

    /// Stage 3a: Submits a time-bounded appeal against an executed penalty (§9.4).
    pub fn submit_appeal(
        &mut self,
        complaint_id: &str,
        counter_evidence_hash: impl Into<String>,
        submitted_at: Timestamp,
    ) -> GmcResult<()> {
        let counter_hash = counter_evidence_hash.into();
        if !is_valid_evidence_hash(&counter_hash) {
            return Err(GmcError::EvidenceInvalid);
        }

        let case = self
            .cases
            .get_mut(complaint_id)
            .ok_or(GmcError::ComplaintInvalid)?;
        if case.stage != CaseStage::Executed {
            return Err(GmcError::AppealWindowExpired);
        }

        let execution = case
            .execution
            .as_ref()
            .ok_or(GmcError::AppealWindowExpired)?;
        if submitted_at < execution.executed_at {
            return Err(GmcError::AppealWindowExpired);
        }
        if submitted_at.saturating_elapsed_since(execution.executed_at)
            > self.policy.appeal_window_secs
        {
            return Err(GmcError::AppealWindowExpired);
        }

        case.appeal = Some(AppealSubmission {
            submitted_at,
            counter_evidence_hash: counter_hash,
        });
        case.stage = CaseStage::Appealed;
        Ok(())
    }

    /// Stage 3b: Resolves a filed appeal via a wider-community electorate (§9.4).
    pub fn resolve_appeal(
        &mut self,
        complaint_id: &str,
        respondent_pocket: &mut MeritPocket,
        wider_ballots: &[PenaltyBallot],
        resolved_at: Timestamp,
    ) -> GmcResult<AppealOutcome> {
        let (complainant, respondent, stage, snapshot, execution, submitted_at) = {
            let case = self
                .cases
                .get(complaint_id)
                .ok_or(GmcError::ComplaintInvalid)?;
            (
                case.complaint.complainant.clone(),
                case.complaint.respondent.clone(),
                case.stage,
                case.snapshot.clone(),
                case.execution.clone(),
                case.appeal.as_ref().map(|a| a.submitted_at),
            )
        };

        if stage != CaseStage::Appealed {
            return Err(GmcError::OperationNotAllowed);
        }
        let snapshot = snapshot.ok_or(GmcError::ComplaintInvalid)?;
        let execution = execution.ok_or(GmcError::ComplaintInvalid)?;
        let submitted_at = submitted_at.ok_or(GmcError::ComplaintInvalid)?;

        if respondent_pocket.fay_id != respondent || resolved_at < submitted_at {
            return Err(GmcError::ComplaintInvalid);
        }

        let (voter_count, approve_merit, total_merit) =
            tally_ballots(wider_ballots, &complainant, &respondent)?;

        if voter_count <= execution.voter_count || total_merit <= execution.total_merit {
            return Err(GmcError::AppealElectorateNotExpanded);
        }

        let passed =
            meets_weighted_threshold(approve_merit, total_merit, self.policy.appeal_threshold);
        let case = self.cases.get_mut(complaint_id).unwrap();

        if passed {
            let pre_ids: BTreeSet<&str> = snapshot
                .pre_batches
                .iter()
                .map(|b| b.batch_id.as_str())
                .collect();
            let post_batches: Vec<MeritBatch> = respondent_pocket
                .batches
                .iter()
                .filter(|b| !pre_ids.contains(b.batch_id.as_str()))
                .cloned()
                .collect();

            let mut restored_batches = snapshot.pre_batches.clone();
            restored_batches.extend(post_batches);
            respondent_pocket.batches = restored_batches;

            let cur_restored = respondent_pocket.cur_merit(resolved_at);
            respondent_pocket.min_merit = respondent_pocket
                .min_merit
                .max(snapshot.pre_min_merit)
                .min(cur_restored);

            let restored_min_merit = respondent_pocket.min_merit;
            case.stage = CaseStage::OverturnedOnAppeal;
            Ok(AppealOutcome::Overturned {
                restored_cur_merit: cur_restored,
                restored_min_merit,
            })
        } else {
            case.stage = CaseStage::AppealUpheld;
            Ok(AppealOutcome::PenaltyUpheld)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChainId;

    fn id(s: &str) -> FayID {
        FayID::new(s)
    }

    fn valid_hash(byte_hex: char) -> String {
        core::iter::repeat_n(byte_hex, 64).collect()
    }

    fn sample_pocket(owner: &FayID) -> MeritPocket {
        let mut p = MeritPocket::new(owner.clone());
        let batch = MeritBatch::with_influence_duration(
            "batch-001",
            Decimal::from_int(100),
            Decimal::from_int(20),
            Decimal::from_int(86_400 * 365),
            Timestamp::from_secs(1_000),
            ChainId::new("gmc"),
        )
        .unwrap();
        p.add_batch(batch);
        p.min_merit = Decimal::from_int(20);
        p
    }

    #[test]
    fn rejects_batchless_or_unknown_batch_complaints_and_enforces_cooldown_and_strikes() {
        let complainant = id("ifay:ed25519:complainant");
        let respondent = id("ifay:ed25519:respondent");
        let pocket = sample_pocket(&respondent);
        let mut engine = PenaltyEngine::default();

        let bad_batch = Complaint {
            complaint_id: "c-bad".into(),
            complainant: complainant.clone(),
            respondent: respondent.clone(),
            batch_id: "nonexistent-batch".into(),
            evidence_hash: valid_hash('a'),
            severity: PenaltySeverity::Minor,
            filed_at: Timestamp::from_secs(2_000),
        };
        assert_eq!(
            engine.file_complaint(bad_batch, Decimal::from_int(50), &pocket),
            Err(GmcError::ComplaintInvalid)
        );

        let c1 = Complaint {
            complaint_id: "c-1".into(),
            complainant: complainant.clone(),
            respondent: respondent.clone(),
            batch_id: "batch-001".into(),
            evidence_hash: valid_hash('a'),
            severity: PenaltySeverity::Minor,
            filed_at: Timestamp::from_secs(2_000),
        };
        engine
            .file_complaint(c1, Decimal::from_int(50), &pocket)
            .unwrap();

        let c_cooldown = Complaint {
            complaint_id: "c-2".into(),
            complainant: complainant.clone(),
            respondent: respondent.clone(),
            batch_id: "batch-001".into(),
            evidence_hash: valid_hash('b'),
            severity: PenaltySeverity::Minor,
            filed_at: Timestamp::from_secs(2_100),
        };
        assert_eq!(
            engine.file_complaint(c_cooldown, Decimal::from_int(50), &pocket),
            Err(GmcError::ComplaintCooldownActive)
        );

        let nays = vec![PenaltyBallot {
            voter: id("ifay:ed25519:v1"),
            cur_merit: Decimal::from_int(100),
            approve: false,
        }];
        assert!(!engine.resolve_admissibility("c-1", &nays).unwrap());

        for idx in 2..=3 {
            let c = Complaint {
                complaint_id: format!("c-{idx}"),
                complainant: complainant.clone(),
                respondent: respondent.clone(),
                batch_id: "batch-001".into(),
                evidence_hash: valid_hash('c'),
                severity: PenaltySeverity::Minor,
                filed_at: Timestamp::from_secs(2_000 + idx * 100_000),
            };
            engine
                .file_complaint(c, Decimal::from_int(50), &pocket)
                .unwrap();
            assert!(!engine
                .resolve_admissibility(&format!("c-{idx}"), &nays)
                .unwrap());
        }

        let c4 = Complaint {
            complaint_id: "c-4".into(),
            complainant,
            respondent,
            batch_id: "batch-001".into(),
            evidence_hash: valid_hash('d'),
            severity: PenaltySeverity::Minor,
            filed_at: Timestamp::from_secs(900_000),
        };
        assert_eq!(
            engine.file_complaint(c4, Decimal::from_int(50), &pocket),
            Err(GmcError::MaliciousComplainantBlocked)
        );
    }

    #[test]
    fn minor_leaves_min_merit_unchanged_while_severe_lowers_min_merit_and_appeal_restores() {
        let complainant = id("ifay:ed25519:complainant");
        let respondent = id("ifay:ed25519:respondent");
        let mut pocket = sample_pocket(&respondent);
        let mut engine = PenaltyEngine::default();

        engine
            .file_complaint(
                Complaint {
                    complaint_id: "case-minor".into(),
                    complainant: complainant.clone(),
                    respondent: respondent.clone(),
                    batch_id: "batch-001".into(),
                    evidence_hash: valid_hash('1'),
                    severity: PenaltySeverity::Minor,
                    filed_at: Timestamp::from_secs(1_000),
                },
                Decimal::from_int(50),
                &pocket,
            )
            .unwrap();

        let panel = vec![
            PenaltyBallot {
                voter: id("ifay:ed25519:v1"),
                cur_merit: Decimal::from_int(30),
                approve: true,
            },
            PenaltyBallot {
                voter: id("ifay:ed25519:v2"),
                cur_merit: Decimal::from_int(45),
                approve: true,
            },
            PenaltyBallot {
                voter: id("ifay:ed25519:v3"),
                cur_merit: Decimal::from_int(25),
                approve: false,
            },
        ];
        assert!(engine.resolve_admissibility("case-minor", &panel).unwrap());
        let rec_minor = engine
            .execute_penalty(
                "case-minor",
                &mut pocket,
                &panel,
                Timestamp::from_secs(1_000),
            )
            .unwrap();
        assert!(rec_minor.cur_merit_after < rec_minor.cur_merit_before);
        assert_eq!(rec_minor.min_merit_after, rec_minor.min_merit_before);
        assert!(pocket.invariant_holds(Timestamp::from_secs(1_000)));

        let expected_cur_at_appeal = pocket.cur_merit(Timestamp::from_secs(100_500));
        let pre_severe_min = pocket.min_merit;

        engine
            .file_complaint(
                Complaint {
                    complaint_id: "case-severe".into(),
                    complainant,
                    respondent,
                    batch_id: "batch-001".into(),
                    evidence_hash: valid_hash('2'),
                    severity: PenaltySeverity::Severe,
                    filed_at: Timestamp::from_secs(100_000),
                },
                Decimal::from_int(50),
                &pocket,
            )
            .unwrap();
        assert!(engine.resolve_admissibility("case-severe", &panel).unwrap());

        let sub_supermajority = vec![
            PenaltyBallot {
                voter: id("ifay:ed25519:v1"),
                cur_merit: Decimal::from_int(74),
                approve: true,
            },
            PenaltyBallot {
                voter: id("ifay:ed25519:v2"),
                cur_merit: Decimal::from_int(26),
                approve: false,
            },
        ];
        assert_eq!(
            engine.execute_penalty(
                "case-severe",
                &mut pocket,
                &sub_supermajority,
                Timestamp::from_secs(100_000)
            ),
            Err(GmcError::GovernanceThresholdNotMet)
        );
        assert_eq!(pocket.min_merit, pre_severe_min);

        let rec_severe = engine
            .execute_penalty(
                "case-severe",
                &mut pocket,
                &panel,
                Timestamp::from_secs(100_000),
            )
            .unwrap();
        assert!(rec_severe.min_merit_after < pre_severe_min);
        assert_eq!(rec_severe.min_merit_after, Decimal::from_int(15));
        assert!(pocket.invariant_holds(Timestamp::from_secs(100_000)));

        assert_eq!(
            engine.submit_appeal(
                "case-severe",
                valid_hash('3'),
                Timestamp::from_secs(800_000)
            ),
            Err(GmcError::AppealWindowExpired)
        );

        engine
            .submit_appeal(
                "case-severe",
                valid_hash('3'),
                Timestamp::from_secs(100_500),
            )
            .unwrap();
        assert_eq!(
            engine.resolve_appeal(
                "case-severe",
                &mut pocket,
                &panel,
                Timestamp::from_secs(100_500)
            ),
            Err(GmcError::AppealElectorateNotExpanded)
        );

        let wider_community = vec![
            PenaltyBallot {
                voter: id("ifay:ed25519:w1"),
                cur_merit: Decimal::from_int(50),
                approve: true,
            },
            PenaltyBallot {
                voter: id("ifay:ed25519:w2"),
                cur_merit: Decimal::from_int(50),
                approve: true,
            },
            PenaltyBallot {
                voter: id("ifay:ed25519:w3"),
                cur_merit: Decimal::from_int(50),
                approve: true,
            },
            PenaltyBallot {
                voter: id("ifay:ed25519:w4"),
                cur_merit: Decimal::from_int(50),
                approve: false,
            },
        ];
        let outcome = engine
            .resolve_appeal(
                "case-severe",
                &mut pocket,
                &wider_community,
                Timestamp::from_secs(100_500),
            )
            .unwrap();
        assert_eq!(
            outcome,
            AppealOutcome::Overturned {
                restored_cur_merit: expected_cur_at_appeal,
                restored_min_merit: pre_severe_min,
            }
        );
        assert_eq!(pocket.min_merit, pre_severe_min);
        assert_eq!(
            pocket.cur_merit(Timestamp::from_secs(100_500)),
            expected_cur_at_appeal
        );
    }
}
