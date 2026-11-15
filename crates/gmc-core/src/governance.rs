//! `Governance_Module` — weighted voting, threshold decisions, proposal handling.
//!
//! This module implements the design's `Governance_Module` interface (see the design
//! document's *Components and Interfaces* section):
//!
//! ```text
//! openVote(subject, threshold: Ratio, voters: VoterSet): VoteId
//! castVote(voteId, voter, approve: bool): Result   // identity protected via ZK
//! tally(voteId): VoteOutcome
//! anchorOutcome(voteId): Result                    // anchor to L1
//! ```
//!
//! ## Weighting rule (Requirement 11.5)
//!
//! Each voter's voting weight equals their `curMerit` as a **proportion of the voter
//! set's total `curMerit`**:
//!
//! ```text
//! weight(voter) = voter.curMerit / Σ(voters.curMerit)
//! ```
//!
//! By construction the per-voter weights sum to `1` (i.e. `Σ curMerit_i / total =
//! total / total = 1`). A vote **passes** when the weighted approval ratio — the
//! combined weight of every voter that cast an *approve* ballot — is `≥ threshold`.
//!
//! ### Fixed-point note
//!
//! All weight math uses the crate's fixed-point [`Decimal`] / [`Ratio`] types (no
//! floating point). [`Decimal`] division truncates toward zero, so summing the
//! *independently rounded* per-voter weights can differ from exactly `1` by up to
//! `(n − 1)` units in the last place. The exact proportional identity holds at full
//! precision (`Σ curMerit_i = total`), so the pass/fail decision in [`tally`] is
//! computed from the **sum of approver `curMerit` numerators divided by the total**
//! ([`GovernanceModule::tally`]) rather than from rounded weights, keeping the
//! decision free of accumulated rounding bias.
//!
//! [`tally`]: GovernanceModule::tally
//!
//! ## Placeholders wired by later tasks
//!
//! - [`GovernanceModule::anchor_outcome`] is a documented stub. Real anchoring of the
//!   outcome to the L1 settlement layer is wired in task 18.1 (Requirements 3.8, 7.7,
//!   10.7); here it only records that anchoring was requested.
//! - **ZK voter-identity protection** (Requirement 11.7) is applied at the L2
//!   integration layer (task 19.2): only the aggregate result is published, never the
//!   per-voter identities. At this pure-logic layer ballots are keyed by [`FayID`] so
//!   the weighting and tally math can be expressed deterministically; the privacy
//!   wrapper sits above this module.
//!
//! The concrete vote subjects (evaluation-mechanism change, inflation-index change,
//! retroactive declaration, chain creation) are intentionally **not** modelled here.
//! [`VoteSubject`] is an opaque, general identifier so later tasks (5.2, 8.2, 15.2,
//! 20.2) can attach their own subject semantics without changing this module.

use std::collections::BTreeMap;

use crate::types::{Decimal, FayID, Ratio};

/// A voter together with their current merit (`curMerit`), which determines weight.
///
/// `cur_merit` must be non-negative; the voter's weight is its share of the voter
/// set's total `curMerit` (Requirement 11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voter {
    /// The voter's identity.
    pub id: FayID,
    /// The voter's current merit value at the time the vote is opened.
    pub cur_merit: Decimal,
}

impl Voter {
    /// Convenience constructor for a [`Voter`].
    pub fn new(id: impl Into<FayID>, cur_merit: Decimal) -> Self {
        Voter {
            id: id.into(),
            cur_merit,
        }
    }
}

/// Opaque, general vote subject.
///
/// Concrete subjects (mechanism change, inflation-index change, retroactive
/// declaration, chain creation) are wired by later tasks; this module only needs an
/// opaque handle so it can stay subject-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VoteSubject(String);

impl VoteSubject {
    /// Builds a vote subject from any string-like value.
    pub fn new(subject: impl Into<String>) -> Self {
        VoteSubject(subject.into())
    }

    /// Returns the subject as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for VoteSubject {
    fn from(value: &str) -> Self {
        VoteSubject(value.to_owned())
    }
}

impl From<String> for VoteSubject {
    fn from(value: String) -> Self {
        VoteSubject(value)
    }
}

/// Opaque vote identifier minted by [`GovernanceModule::open_vote`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VoteId(u64);

impl VoteId {
    /// Returns the raw numeric handle (useful for anchoring / logging).
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Operational / structural errors specific to vote management.
///
/// These are distinct from the protocol-wide [`crate::error::GmcError`] decision
/// codes: they describe *how a caller misused the voting API* (unknown vote, an
/// ineligible voter, a duplicate ballot, an unusable electorate) rather than a
/// governance outcome. A failed-threshold tally is **not** an error — it is reported
/// via [`VoteOutcome::passed`] being `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceError {
    /// No open vote exists for the supplied [`VoteId`].
    UnknownVote,
    /// The voter is not a member of this vote's electorate.
    VoterNotEligible,
    /// The voter already cast a ballot for this vote.
    AlreadyVoted,
    /// The voter set is empty, contains a negative `curMerit`, or has a total
    /// `curMerit` of zero — none of which yields a well-defined weighting. This is
    /// the explicit guard against dividing by a zero total merit (Requirement 11.5).
    InvalidElectorate,
    /// A fixed-point accumulation overflowed while summing merit.
    Overflow,
}

/// The result of tallying a vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteOutcome {
    /// The vote that was tallied.
    pub vote_id: VoteId,
    /// The weighted approval ratio: combined weight of all *approve* ballots.
    pub approval_ratio: Ratio,
    /// The threshold the vote was opened with.
    pub threshold: Ratio,
    /// `true` when `approval_ratio ≥ threshold` (Requirement 11.5 pass condition).
    pub passed: bool,
}

/// Internal per-vote state.
#[derive(Debug, Clone)]
struct VoteState {
    #[allow(dead_code)] // subject is opaque here; consumed by later subject-aware tasks.
    subject: VoteSubject,
    threshold: Ratio,
    /// Electorate: each eligible voter's `curMerit`. The denominator of every weight.
    electorate: BTreeMap<FayID, Decimal>,
    /// Σ of every electorate member's `curMerit`. Guaranteed `> 0` by `open_vote`.
    total_merit: Decimal,
    /// Cast ballots: `true` = approve, `false` = reject.
    ballots: BTreeMap<FayID, bool>,
    /// Set once [`GovernanceModule::anchor_outcome`] has been requested (placeholder).
    anchored: bool,
}

/// Stateful weighted-voting engine.
///
/// Holds the set of open votes and mints sequential [`VoteId`]s. The engine is pure
/// logic (no chain-runtime dependencies) so it can be reused by both the L1 pallet
/// and the L2 rollup.
#[derive(Debug, Default)]
pub struct GovernanceModule {
    next_id: u64,
    votes: BTreeMap<u64, VoteState>,
}

impl GovernanceModule {
    /// Creates an empty governance engine.
    pub fn new() -> Self {
        GovernanceModule::default()
    }

    /// Opens a weighted vote over `subject` with the given pass `threshold` and
    /// electorate `voters`, returning a fresh [`VoteId`].
    ///
    /// The voter set is deduplicated by [`FayID`] (a repeated id keeps its last
    /// `curMerit`). The total `curMerit` is captured at open time and used as the
    /// denominator for every weight (Requirement 11.5).
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidElectorate`] when the electorate is empty,
    /// contains a negative `curMerit`, or sums to a total `curMerit` of zero — the
    /// edge case that would otherwise divide by zero. Returns
    /// [`GovernanceError::Overflow`] if summing the electorate's merit overflows.
    pub fn open_vote(
        &mut self,
        subject: impl Into<VoteSubject>,
        threshold: Ratio,
        voters: impl IntoIterator<Item = Voter>,
    ) -> Result<VoteId, GovernanceError> {
        let mut electorate: BTreeMap<FayID, Decimal> = BTreeMap::new();
        for voter in voters {
            if voter.cur_merit.is_negative() {
                return Err(GovernanceError::InvalidElectorate);
            }
            electorate.insert(voter.id, voter.cur_merit);
        }

        if electorate.is_empty() {
            return Err(GovernanceError::InvalidElectorate);
        }

        let mut total_merit = Decimal::ZERO;
        for merit in electorate.values() {
            total_merit = total_merit
                .checked_add(*merit)
                .ok_or(GovernanceError::Overflow)?;
        }

        // Guard the divide-by-zero edge: a zero-total electorate has no well-defined
        // weighting, so reject it rather than producing meaningless weights.
        if !total_merit.is_positive() {
            return Err(GovernanceError::InvalidElectorate);
        }

        let id = self.next_id;
        self.next_id += 1;
        self.votes.insert(
            id,
            VoteState {
                subject: subject.into(),
                threshold,
                electorate,
                total_merit,
                ballots: BTreeMap::new(),
                anchored: false,
            },
        );
        Ok(VoteId(id))
    }

    /// Records `voter`'s ballot (`approve`) for vote `vote_id`.
    ///
    /// At this pure-logic layer ballots are keyed by [`FayID`]; ZK voter-identity
    /// protection (Requirement 11.7) is layered above by the L2 integration (task
    /// 19.2), which publishes only the aggregate result.
    ///
    /// # Errors
    ///
    /// - [`GovernanceError::UnknownVote`] if `vote_id` has no open vote.
    /// - [`GovernanceError::VoterNotEligible`] if `voter` is not in the electorate.
    /// - [`GovernanceError::AlreadyVoted`] if `voter` already cast a ballot.
    pub fn cast_vote(
        &mut self,
        vote_id: VoteId,
        voter: &FayID,
        approve: bool,
    ) -> Result<(), GovernanceError> {
        let state = self
            .votes
            .get_mut(&vote_id.0)
            .ok_or(GovernanceError::UnknownVote)?;
        if !state.electorate.contains_key(voter) {
            return Err(GovernanceError::VoterNotEligible);
        }
        if state.ballots.contains_key(voter) {
            return Err(GovernanceError::AlreadyVoted);
        }
        state.ballots.insert(voter.clone(), approve);
        Ok(())
    }

    /// Returns `voter`'s weight in `vote_id`: `curMerit / Σ(electorate.curMerit)`.
    ///
    /// Returns `None` if the vote or voter is unknown. The weight lies in `[0, 1]`
    /// because each member's `curMerit` is non-negative and never exceeds the total.
    pub fn voter_weight(&self, vote_id: VoteId, voter: &FayID) -> Option<Ratio> {
        let state = self.votes.get(&vote_id.0)?;
        let merit = state.electorate.get(voter)?;
        let weight = merit.checked_div(state.total_merit)?;
        Ratio::new(weight)
    }

    /// Returns every electorate member's weight, in a stable order.
    ///
    /// Useful for verifying the Requirement 11.5 invariant that the weights are each
    /// `curMerit / total` and (at full precision) sum to `1`.
    pub fn voter_weights(&self, vote_id: VoteId) -> Option<Vec<(FayID, Ratio)>> {
        let state = self.votes.get(&vote_id.0)?;
        let mut out = Vec::with_capacity(state.electorate.len());
        for (id, merit) in &state.electorate {
            let weight = merit.checked_div(state.total_merit)?;
            out.push((id.clone(), Ratio::new(weight)?));
        }
        Some(out)
    }

    /// Returns the total `curMerit` of the vote's electorate (the weight denominator).
    pub fn total_merit(&self, vote_id: VoteId) -> Option<Decimal> {
        self.votes.get(&vote_id.0).map(|s| s.total_merit)
    }

    /// Tallies `vote_id` and returns its [`VoteOutcome`].
    ///
    /// The weighted approval ratio is computed as `Σ(curMerit of approvers) / total`,
    /// which is exact in fixed point (no accumulated rounding from per-voter weights).
    /// The vote **passes** when `approval_ratio ≥ threshold` (Requirement 11.5).
    /// Electorate members that did not cast a ballot contribute to the denominator but
    /// not the numerator, so abstaining counts against approval.
    ///
    /// # Errors
    ///
    /// [`GovernanceError::UnknownVote`] if `vote_id` is unknown;
    /// [`GovernanceError::Overflow`] on fixed-point overflow while summing merit.
    pub fn tally(&self, vote_id: VoteId) -> Result<VoteOutcome, GovernanceError> {
        let state = self
            .votes
            .get(&vote_id.0)
            .ok_or(GovernanceError::UnknownVote)?;

        let mut approve_merit = Decimal::ZERO;
        for (voter, &approved) in &state.ballots {
            if approved {
                // Every balloting voter is in the electorate (enforced by cast_vote).
                if let Some(merit) = state.electorate.get(voter) {
                    approve_merit = approve_merit
                        .checked_add(*merit)
                        .ok_or(GovernanceError::Overflow)?;
                }
            }
        }

        let approval = approve_merit
            .checked_div(state.total_merit)
            .ok_or(GovernanceError::Overflow)?;
        let approval_ratio = Ratio::new(approval).ok_or(GovernanceError::Overflow)?;

        // Pass condition: weighted approval ≥ threshold (compared in fixed point).
        let passed = approval >= state.threshold.value();

        Ok(VoteOutcome {
            vote_id,
            approval_ratio,
            threshold: state.threshold,
            passed,
        })
    }

    /// **Placeholder** for anchoring a vote's outcome to the L1 settlement layer.
    ///
    /// Real L1 anchoring (Requirements 3.8, 7.7, 10.7) is wired in task 18.1. For now
    /// this only marks the vote as "anchor requested" so the surrounding flow can be
    /// exercised; it performs no real settlement-layer write.
    ///
    /// # Errors
    ///
    /// [`GovernanceError::UnknownVote`] if `vote_id` is unknown.
    pub fn anchor_outcome(&mut self, vote_id: VoteId) -> Result<(), GovernanceError> {
        let state = self
            .votes
            .get_mut(&vote_id.0)
            .ok_or(GovernanceError::UnknownVote)?;
        state.anchored = true;
        Ok(())
    }

    /// Returns whether [`anchor_outcome`](Self::anchor_outcome) has been requested for
    /// `vote_id` (placeholder bookkeeping; see that method's docs).
    pub fn is_anchored(&self, vote_id: VoteId) -> Option<bool> {
        self.votes.get(&vote_id.0).map(|s| s.anchored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voter(id: &str, merit: &str) -> Voter {
        Voter::new(FayID::new(id), Decimal::from_str(merit).unwrap())
    }

    fn ratio(s: &str) -> Ratio {
        Ratio::new(Decimal::from_str(s).unwrap()).unwrap()
    }

    // --- Weighting (Requirement 11.5) ---------------------------------------

    #[test]
    fn weights_are_curmerit_proportions_that_sum_to_one() {
        // Merits chosen so each curMerit/total is exact at 6 dp: 25/100, 25/100, 50/100.
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote(
                "subject",
                ratio("0.5"),
                [voter("a", "25"), voter("b", "25"), voter("c", "50")],
            )
            .unwrap();

        assert_eq!(gov.voter_weight(id, &FayID::new("a")), Some(ratio("0.25")));
        assert_eq!(gov.voter_weight(id, &FayID::new("b")), Some(ratio("0.25")));
        assert_eq!(gov.voter_weight(id, &FayID::new("c")), Some(ratio("0.5")));

        // All weights sum to exactly 1.
        let sum = gov
            .voter_weights(id)
            .unwrap()
            .into_iter()
            .fold(Decimal::ZERO, |acc, (_, w)| {
                acc.checked_add(w.value()).unwrap()
            });
        assert_eq!(sum, Decimal::ONE);
    }

    #[test]
    fn two_equal_voters_each_have_half_weight() {
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "7"), voter("b", "7")])
            .unwrap();
        assert_eq!(gov.voter_weight(id, &FayID::new("a")), Some(ratio("0.5")));
        assert_eq!(gov.voter_weight(id, &FayID::new("b")), Some(ratio("0.5")));
    }

    // --- Threshold decision -------------------------------------------------

    #[test]
    fn weighted_approval_above_threshold_passes() {
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "60"), voter("b", "40")])
            .unwrap();
        gov.cast_vote(id, &FayID::new("a"), true).unwrap();
        gov.cast_vote(id, &FayID::new("b"), false).unwrap();

        let outcome = gov.tally(id).unwrap();
        assert_eq!(outcome.approval_ratio, ratio("0.6"));
        assert!(outcome.passed);
    }

    #[test]
    fn weighted_approval_exactly_at_threshold_passes() {
        // 50/50 split, threshold 0.5 -> approval 0.5 >= 0.5 passes (inclusive).
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "50"), voter("b", "50")])
            .unwrap();
        gov.cast_vote(id, &FayID::new("a"), true).unwrap();
        gov.cast_vote(id, &FayID::new("b"), false).unwrap();

        let outcome = gov.tally(id).unwrap();
        assert_eq!(outcome.approval_ratio, ratio("0.5"));
        assert!(outcome.passed);
    }

    #[test]
    fn weighted_approval_below_threshold_fails() {
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "40"), voter("b", "60")])
            .unwrap();
        gov.cast_vote(id, &FayID::new("a"), true).unwrap();
        gov.cast_vote(id, &FayID::new("b"), false).unwrap();

        let outcome = gov.tally(id).unwrap();
        assert_eq!(outcome.approval_ratio, ratio("0.4"));
        assert!(!outcome.passed);
    }

    #[test]
    fn abstaining_voter_counts_against_approval() {
        // a approves (60), b abstains (40). approval = 60/100 = 0.6 >= 0.5 -> passes.
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "60"), voter("b", "40")])
            .unwrap();
        gov.cast_vote(id, &FayID::new("a"), true).unwrap();
        // b does not vote.
        let outcome = gov.tally(id).unwrap();
        assert_eq!(outcome.approval_ratio, ratio("0.6"));
        assert!(outcome.passed);

        // With a higher threshold the same abstention sinks the vote.
        let id2 = gov
            .open_vote("s", ratio("0.7"), [voter("a", "60"), voter("b", "40")])
            .unwrap();
        gov.cast_vote(id2, &FayID::new("a"), true).unwrap();
        assert!(!gov.tally(id2).unwrap().passed);
    }

    // --- Zero-total-merit edge case -----------------------------------------

    #[test]
    fn zero_total_merit_electorate_is_rejected() {
        let mut gov = GovernanceModule::new();
        let err = gov
            .open_vote("s", ratio("0.5"), [voter("a", "0"), voter("b", "0")])
            .unwrap_err();
        assert_eq!(err, GovernanceError::InvalidElectorate);
    }

    #[test]
    fn empty_electorate_is_rejected() {
        let mut gov = GovernanceModule::new();
        let err = gov.open_vote("s", ratio("0.5"), []).unwrap_err();
        assert_eq!(err, GovernanceError::InvalidElectorate);
    }

    #[test]
    fn negative_merit_is_rejected() {
        let mut gov = GovernanceModule::new();
        let err = gov
            .open_vote("s", ratio("0.5"), [voter("a", "-1"), voter("b", "10")])
            .unwrap_err();
        assert_eq!(err, GovernanceError::InvalidElectorate);
    }

    #[test]
    fn voter_with_zero_merit_is_allowed_when_total_positive() {
        // A zero-merit member is fine as long as the set total is positive; it simply
        // carries weight 0.
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "0"), voter("b", "10")])
            .unwrap();
        assert_eq!(gov.voter_weight(id, &FayID::new("a")), Some(Ratio::ZERO));
        assert_eq!(gov.voter_weight(id, &FayID::new("b")), Some(Ratio::ONE));
    }

    // --- cast_vote validation ----------------------------------------------

    #[test]
    fn cast_vote_rejects_unknown_vote_ineligible_voter_and_double_vote() {
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "10"), voter("b", "10")])
            .unwrap();

        // Unknown vote id.
        let bogus = VoteId(9999);
        assert_eq!(
            gov.cast_vote(bogus, &FayID::new("a"), true),
            Err(GovernanceError::UnknownVote)
        );

        // Ineligible voter.
        assert_eq!(
            gov.cast_vote(id, &FayID::new("z"), true),
            Err(GovernanceError::VoterNotEligible)
        );

        // First ballot ok, second from same voter rejected.
        gov.cast_vote(id, &FayID::new("a"), true).unwrap();
        assert_eq!(
            gov.cast_vote(id, &FayID::new("a"), false),
            Err(GovernanceError::AlreadyVoted)
        );
    }

    // --- anchor placeholder & tally errors ----------------------------------

    #[test]
    fn anchor_outcome_placeholder_marks_anchored() {
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "10")])
            .unwrap();
        assert_eq!(gov.is_anchored(id), Some(false));
        gov.anchor_outcome(id).unwrap();
        assert_eq!(gov.is_anchored(id), Some(true));
    }

    #[test]
    fn tally_and_anchor_reject_unknown_vote() {
        let mut gov = GovernanceModule::new();
        let bogus = VoteId(0);
        assert_eq!(gov.tally(bogus), Err(GovernanceError::UnknownVote));
        assert_eq!(gov.anchor_outcome(bogus), Err(GovernanceError::UnknownVote));
    }

    #[test]
    fn no_ballots_yields_zero_approval() {
        let mut gov = GovernanceModule::new();
        let id = gov
            .open_vote("s", ratio("0.5"), [voter("a", "10"), voter("b", "10")])
            .unwrap();
        let outcome = gov.tally(id).unwrap();
        assert_eq!(outcome.approval_ratio, Ratio::ZERO);
        assert!(!outcome.passed);
    }
}
