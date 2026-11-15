//! `AntiFraud_Engine` — high-intimacy exclusion, sampling, anomaly detection, clawback.
//!
//! This module implements the design's `AntiFraud_Engine` voter-selection step (see
//! the design document's *Components and Interfaces* + flow 3 "事后申报审核投票", and
//! blueprint ch.6 §6.3 / §6.5 "排除高亲密度者 + 随机抽样"). Task 12.1 covers **voter
//! selection only**:
//!
//! 1. **Exclude high-intimacy entities** (Requirement 11.1): within the normalized
//!    intimacy interval `[0, 1]`, drop every stakeholder whose intimacy with the
//!    contributor is **strictly greater than `0.9`**. This is the core defence
//!    against "自己人给自己人投票" (insiders voting for insiders).
//! 2. **Random sampling** (Requirement 11.2): from the remaining stakeholders, draw a
//!    voter set whose size is **at least 7** and **at most the remaining count**.
//! 3. **Insufficient stakeholders** (Requirement 11.3): if fewer than 7 remain after
//!    exclusion, defer the vote, return [`GmcError::StakeholderInsufficient`], and
//!    mint nothing (the caller performs no minting on `Err`).
//!
//! ## Determinism & the seeded PRNG
//!
//! Production randomness for voter sampling is ultimately sourced from on-chain
//! randomness / a VRF and wired at the L1/L2 integration layer. At this **pure-logic**
//! layer we keep sampling *deterministic and dependency-free* by driving it from a
//! caller-supplied `u64` seed through a small inline [`SplitMix64`] PRNG. This keeps
//! the logic reproducible — the same `(stakeholders, sample_size, seed)` always yields
//! the same voter set — which is exactly what the Property 24 test (task 12.3) needs,
//! and avoids adding the `rand` crate as a dependency. The integration layer supplies
//! a real unpredictable seed; the selection *algorithm* it feeds is the one below.
//!
//! ## Anomaly detection (Requirement 11.4)
//!
//! Beyond voter *selection*, this module also implements **anomalous voting-behaviour
//! detection** (task 12.2): when a voter, within the most recent **30-day** evaluation
//! window, casts **≥ 5** approve votes toward a single object **and** those approvals
//! make up **strictly more than 80%** of all of that voter's votes toward that object,
//! the behaviour is flagged and recorded as a *pending-audit* entry. See
//! [`detect_anomaly`] and [`AntiFraudEngine`].
//!
//! ## Scope boundaries (other 11.x parts live elsewhere)
//!
//! - **Post-hoc collusion clawback** (Requirement 11.6) is a later unit-test task.
//! - **ZK voter-identity privacy** (Requirement 11.7) is applied above this layer at
//!   the L2 integration (task 19.2); here voters are plain [`FayID`]s so the selection
//!   math can be expressed deterministically.

use crate::error::{GmcError, GmcResult};
use crate::types::{Decimal, FayID, Ratio, Timestamp};

/// Intimacy exclusion threshold on the normalized `[0, 1]` scale (Requirement 11.1).
///
/// Stakeholders whose intimacy is **strictly greater** than this value are excluded
/// from the voter pool. The raw value `900_000` equals `0.9` given the fixed-point
/// [`Decimal`] scale (6 fractional digits).
pub const INTIMACY_EXCLUSION_THRESHOLD: Decimal = Decimal::from_raw(900_000);

/// Minimum voter-set size (Requirements 11.2, 11.3).
///
/// After exclusion there must be at least this many stakeholders, and any sampled
/// voter set is at least this large.
pub const MIN_VOTER_SET_SIZE: usize = 7;

/// A stakeholder considered for the voter pool, paired with their normalized intimacy
/// (in `[0, 1]`) relative to the contributor being evaluated.
///
/// Intimacy is a [`Ratio`], so it is already constrained to `[0, 1]` by construction
/// (Requirement 11.1's "归一化亲密度区间 [0, 1]").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stakeholder {
    /// The stakeholder's identity.
    pub id: FayID,
    /// Normalized intimacy with the contributor, in `[0, 1]`.
    pub intimacy: Ratio,
}

impl Stakeholder {
    /// Convenience constructor for a [`Stakeholder`].
    pub fn new(id: impl Into<FayID>, intimacy: Ratio) -> Self {
        Stakeholder {
            id: id.into(),
            intimacy,
        }
    }

    /// Returns `true` if this stakeholder must be excluded for being *too* intimate
    /// with the contributor, i.e. intimacy **strictly greater than** `0.9`
    /// (Requirement 11.1). Intimacy of exactly `0.9` is **kept**.
    #[inline]
    pub fn is_high_intimacy(&self) -> bool {
        self.intimacy.value() > INTIMACY_EXCLUSION_THRESHOLD
    }
}

/// Small, fast, dependency-free deterministic PRNG (SplitMix64).
///
/// Used purely to make voter sampling reproducible from a caller-supplied seed at this
/// pure-logic layer (see the module docs). It is **not** a cryptographic RNG; real
/// unpredictable randomness/VRF is supplied at integration time and only feeds this
/// algorithm its seed.
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds the generator.
    #[inline]
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Returns the next 64-bit pseudo-random value (the canonical SplitMix64 step).
    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value uniformly in `0..bound`. `bound` must be non-zero.
    ///
    /// Uses Lemire's multiply-shift reduction to map a 64-bit draw into `0..bound`
    /// without the modulo bias being meaningful at the small electorate sizes used
    /// here, while staying allocation- and branch-light.
    #[inline]
    fn below(&mut self, bound: usize) -> usize {
        debug_assert!(bound > 0, "below() requires a non-zero bound");
        let product = (self.next_u64() as u128) * (bound as u128);
        (product >> 64) as usize
    }
}

/// Selects voters for a recognition vote, applying high-intimacy exclusion and
/// deterministic random sampling (Requirements 11.1, 11.2, 11.3).
///
/// Steps:
/// 1. Exclude every stakeholder whose intimacy is strictly greater than `0.9`
///    (Requirement 11.1).
/// 2. If fewer than [`MIN_VOTER_SET_SIZE`] (7) stakeholders remain, return
///    [`GmcError::StakeholderInsufficient`] and select no voters (Requirement 11.3) —
///    the caller mints nothing on `Err`.
/// 3. Otherwise draw a uniform random subset of size `k` from the remaining
///    stakeholders, where `k` is `sample_size` **clamped** to `[7, remaining]`
///    (Requirement 11.2). The sampling is a partial Fisher–Yates shuffle driven by the
///    seeded [`SplitMix64`] PRNG, so the result is reproducible for a given `seed`.
///
/// ### `sample_size` clamping
///
/// - `sample_size < 7` is treated as `7` (the floor mandated by Requirement 11.2).
/// - `sample_size > remaining` is capped at `remaining` (cannot pick more voters than
///   exist after exclusion).
///
/// ### Guarantees on a successful return
///
/// - Every returned voter has intimacy `<= 0.9` (none of the excluded high-intimacy
///   entities appear).
/// - `7 <= result.len() <= remaining_count`.
/// - The returned voters are distinct (no stakeholder is picked twice).
pub fn select_voters(
    stakeholders: &[Stakeholder],
    sample_size: usize,
    seed: u64,
) -> GmcResult<Vec<FayID>> {
    // Step 1: exclude high-intimacy stakeholders (> 0.9). Keep their indices into the
    // input so we can return their ids without cloning the whole input up front.
    let eligible: Vec<&Stakeholder> = stakeholders
        .iter()
        .filter(|s| !s.is_high_intimacy())
        .collect();

    let remaining = eligible.len();

    // Step 2 / Requirement 11.3: fewer than 7 remain -> defer, mint nothing.
    if remaining < MIN_VOTER_SET_SIZE {
        return Err(GmcError::StakeholderInsufficient);
    }

    // Clamp the requested sample size into [MIN_VOTER_SET_SIZE, remaining].
    let k = sample_size.clamp(MIN_VOTER_SET_SIZE, remaining);

    // Step 3: partial Fisher–Yates over eligible indices, take the first `k`.
    let mut indices: Vec<usize> = (0..remaining).collect();
    let mut rng = SplitMix64::new(seed);
    for i in 0..k {
        // Pick j uniformly in [i, remaining) and swap into position i.
        let j = i + rng.below(remaining - i);
        indices.swap(i, j);
    }

    let voters = indices[..k]
        .iter()
        .map(|&i| eligible[i].id.clone())
        .collect();
    Ok(voters)
}

// ===========================================================================
// Anomaly detection (Requirement 11.4)
// ===========================================================================

/// Length of the anomaly-evaluation window, expressed in days (Requirement 11.4).
///
/// Only votes whose timestamp falls within the most recent `ANOMALY_WINDOW_DAYS`
/// (relative to the supplied `now`) are considered when judging anomalous behaviour.
pub const ANOMALY_WINDOW_DAYS: u64 = 30;

/// Length of the anomaly-evaluation window, expressed in **seconds**.
///
/// This is [`ANOMALY_WINDOW_DAYS`] converted to seconds (`30 * 86_400`) so it can be
/// compared directly against [`Timestamp`] second counts.
pub const ANOMALY_WINDOW_SECS: u64 = ANOMALY_WINDOW_DAYS * 86_400;

/// Minimum number of *approve* votes toward one object, within the window, required
/// before a voter's behaviour can be flagged as anomalous (Requirement 11.4).
///
/// The rule is "**not fewer than** 5", i.e. `approvals >= 5`.
pub const ANOMALY_MIN_APPROVALS: u64 = 5;

/// Approval-ratio threshold (`0.8` == 80%) above which behaviour is anomalous.
///
/// The rule requires the approval ratio to be **strictly greater than** this value
/// (Requirement 11.4's "比例超过 80%"); a ratio of exactly `0.8` is **not** flagged.
/// The raw value `800_000` equals `0.8` on the fixed-point [`Decimal`] scale. It is
/// kept as a [`Decimal`] (rather than a [`Ratio`]) because it is used directly in the
/// exact fixed-point ratio comparison below.
pub const ANOMALY_APPROVAL_RATIO_THRESHOLD: Decimal = Decimal::from_raw(800_000);

/// A single vote cast by `voter` toward `target`, with its approve/reject value and
/// the on-chain time at which it occurred.
///
/// `target` is an opaque object identifier (the "对象" voted on can be a contribution
/// record, a retroactive declaration, a proposal, …), kept as a [`String`] so anomaly
/// detection stays decoupled from any specific subject type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteEvent {
    /// Identity of the voter who cast this vote.
    pub voter: FayID,
    /// Opaque identifier of the object that was voted on.
    pub target: String,
    /// `true` for an approve (赞成) vote, `false` for a reject vote.
    pub approve: bool,
    /// On-chain time at which the vote was cast.
    pub at: Timestamp,
}

impl VoteEvent {
    /// Convenience constructor for a [`VoteEvent`].
    pub fn new(
        voter: impl Into<FayID>,
        target: impl Into<String>,
        approve: bool,
        at: Timestamp,
    ) -> Self {
        VoteEvent {
            voter: voter.into(),
            target: target.into(),
            approve,
            at,
        }
    }
}

/// A *pending-audit* entry recording that a `(voter, target)` pair exhibited anomalous
/// voting behaviour within the evaluation window (Requirement 11.4).
///
/// The entry captures the evidence used to flag the behaviour: how many approve votes
/// were counted, the total votes by that voter toward that target inside the window,
/// and the window end (`now`) the judgement was made against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The voter whose behaviour was flagged.
    pub voter: FayID,
    /// The object the anomalous approvals targeted.
    pub target: String,
    /// Number of approve votes toward `target` within the window (`>= 5` when flagged).
    pub approval_count: u64,
    /// Total votes by `voter` toward `target` within the window (the ratio denominator).
    pub total_count: u64,
    /// The window end the judgement was evaluated against (the supplied `now`).
    pub window_end: Timestamp,
}

/// Returns `true` if a `(voter, target)` vote tally — `approvals` approve votes out of
/// `total` votes within the window — meets the anomaly criteria (Requirement 11.4):
/// `approvals >= 5` **and** `approvals / total > 0.8` (strictly).
///
/// Uses exact fixed-point arithmetic (never floats): rather than dividing, it compares
/// `approvals * 1` against `0.8 * total` via the [`Decimal`] type. `total == 0` (no
/// votes) is never anomalous.
fn is_anomalous_tally(approvals: u64, total: u64) -> bool {
    if approvals < ANOMALY_MIN_APPROVALS || total == 0 {
        return false;
    }
    // Strict ratio test without division: approvals/total > 0.8  <=>  approvals > 0.8 * total.
    let approvals_dec = Decimal::from_int(approvals as i64);
    let total_dec = Decimal::from_int(total as i64);
    match total_dec.checked_mul(ANOMALY_APPROVAL_RATIO_THRESHOLD) {
        Some(threshold_count) => approvals_dec > threshold_count,
        // Overflow is not expected at realistic vote counts; treat as not-anomalous
        // rather than panicking, keeping detection side-effect free.
        None => false,
    }
}

/// Detects anomalous approve-voting behaviour by `voter` toward `target`
/// (Requirement 11.4).
///
/// Considers only votes in `history` that were cast by `voter` toward `target` **and**
/// fall within the most recent [`ANOMALY_WINDOW_DAYS`] (30 days) relative to `now`
/// (i.e. `now - 30d <= at <= now`). Within that window it counts approve votes and
/// total votes, then flags the behaviour when **both** hold:
///
/// - approve count `>= 5` ([`ANOMALY_MIN_APPROVALS`]), and
/// - approve ratio **strictly greater than** `0.8` ([`ANOMALY_APPROVAL_RATIO_THRESHOLD`]).
///
/// Returns `Some(AuditEntry)` describing the flagged behaviour when anomalous, or
/// `None` otherwise. This function is pure (no side effects); recording the entry is
/// the caller's responsibility — see [`AntiFraudEngine::record_if_anomalous`].
pub fn detect_anomaly(
    voter: &FayID,
    target: &str,
    history: &[VoteEvent],
    now: Timestamp,
) -> Option<AuditEntry> {
    let mut approval_count: u64 = 0;
    let mut total_count: u64 = 0;

    for event in history {
        if &event.voter != voter || event.target != target {
            continue;
        }
        // Within the most recent 30-day window: now - 30d <= at <= now.
        // Future-dated votes (at > now) are out of window and ignored.
        if event.at > now {
            continue;
        }
        if now.saturating_elapsed_since(event.at) > ANOMALY_WINDOW_SECS {
            continue;
        }
        total_count += 1;
        if event.approve {
            approval_count += 1;
        }
    }

    if is_anomalous_tally(approval_count, total_count) {
        Some(AuditEntry {
            voter: voter.clone(),
            target: target.to_owned(),
            approval_count,
            total_count,
            window_end: now,
        })
    } else {
        None
    }
}

/// Accumulates flagged anomalous-voting [`AuditEntry`] records for later review.
///
/// This is the minimal stateful surface the anti-fraud engine needs for Requirement
/// 11.4: callers feed in a `(voter, target, history, now)` observation and the engine
/// records a pending-audit entry whenever [`detect_anomaly`] flags it. Voter-selection
/// (`select_voters`) remains a free function since it is stateless.
#[derive(Debug, Clone, Default)]
pub struct AntiFraudEngine {
    pending_audit: Vec<AuditEntry>,
}

impl AntiFraudEngine {
    /// Creates an engine with an empty pending-audit log.
    pub fn new() -> Self {
        AntiFraudEngine {
            pending_audit: Vec::new(),
        }
    }

    /// Runs [`detect_anomaly`] for `(voter, target)` over `history` at time `now`; if
    /// the behaviour is anomalous (Requirement 11.4), records the resulting
    /// [`AuditEntry`] in the pending-audit log and returns a reference to it.
    ///
    /// Returns `None` (and records nothing) when the behaviour is not anomalous.
    pub fn record_if_anomalous(
        &mut self,
        voter: &FayID,
        target: &str,
        history: &[VoteEvent],
        now: Timestamp,
    ) -> Option<&AuditEntry> {
        match detect_anomaly(voter, target, history, now) {
            Some(entry) => {
                self.pending_audit.push(entry);
                self.pending_audit.last()
            }
            None => None,
        }
    }

    /// Returns the recorded pending-audit entries, in the order they were flagged.
    pub fn pending_audit(&self) -> &[AuditEntry] {
        &self.pending_audit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ratio(s: &str) -> Ratio {
        Ratio::new(Decimal::from_str(s).unwrap()).unwrap()
    }

    /// Builds `n` stakeholders all sharing the same intimacy, ids `prefix0..prefixN`.
    fn pool(prefix: &str, n: usize, intimacy: &str) -> Vec<Stakeholder> {
        (0..n)
            .map(|i| Stakeholder::new(FayID::new(format!("{prefix}{i}")), ratio(intimacy)))
            .collect()
    }

    // --- Requirement 11.1: high-intimacy exclusion --------------------------

    #[test]
    fn excludes_intimacy_strictly_above_threshold() {
        // 7 low-intimacy keepers + several > 0.9 that must be excluded.
        let mut stakeholders = pool("ok", 7, "0.5");
        stakeholders.push(Stakeholder::new(FayID::new("hi-0.91"), ratio("0.91")));
        stakeholders.push(Stakeholder::new(FayID::new("hi-0.95"), ratio("0.95")));
        stakeholders.push(Stakeholder::new(FayID::new("hi-1.0"), ratio("1")));

        let voters = select_voters(&stakeholders, 100, 42).unwrap();

        // No high-intimacy entity appears in the result.
        for excluded in ["hi-0.91", "hi-0.95", "hi-1.0"] {
            assert!(
                !voters.iter().any(|v| v.as_str() == excluded),
                "{excluded} should have been excluded"
            );
        }
        // With sample_size capped at remaining (7), all 7 keepers are selected.
        assert_eq!(voters.len(), 7);
    }

    #[test]
    fn intimacy_exactly_at_threshold_is_kept() {
        // Boundary: 0.9 is "not strictly greater than 0.9", so it must be kept.
        let stakeholders = pool("edge", 7, "0.9");
        let voters = select_voters(&stakeholders, 7, 1).unwrap();
        assert_eq!(voters.len(), 7);
        // Every keeper has intimacy <= 0.9 (here exactly 0.9).
        for s in &stakeholders {
            assert!(!s.is_high_intimacy());
        }
    }

    #[test]
    fn all_selected_voters_have_intimacy_at_most_threshold() {
        // Mixed pool; verify each selected voter maps back to intimacy <= 0.9.
        let mut stakeholders = pool("low", 10, "0.3");
        stakeholders.extend(pool("mid", 5, "0.9"));
        stakeholders.extend(pool("high", 8, "0.99")); // all excluded

        let voters = select_voters(&stakeholders, 12, 7).unwrap();
        for v in &voters {
            let s = stakeholders.iter().find(|s| &s.id == v).unwrap();
            assert!(
                s.intimacy.value() <= INTIMACY_EXCLUSION_THRESHOLD,
                "selected voter {v} has intimacy > 0.9"
            );
        }
    }

    // --- Requirement 11.3: insufficient stakeholders ------------------------

    #[test]
    fn fewer_than_seven_remaining_yields_stakeholder_insufficient() {
        // 6 keepers (< 7) plus excluded high-intimacy ones.
        let mut stakeholders = pool("ok", 6, "0.2");
        stakeholders.extend(pool("hi", 10, "0.95"));
        let err = select_voters(&stakeholders, 7, 99).unwrap_err();
        assert_eq!(err, GmcError::StakeholderInsufficient);
    }

    #[test]
    fn all_high_intimacy_yields_stakeholder_insufficient() {
        let stakeholders = pool("hi", 20, "0.95");
        assert_eq!(
            select_voters(&stakeholders, 7, 0).unwrap_err(),
            GmcError::StakeholderInsufficient
        );
    }

    #[test]
    fn empty_pool_yields_stakeholder_insufficient() {
        assert_eq!(
            select_voters(&[], 7, 0).unwrap_err(),
            GmcError::StakeholderInsufficient
        );
    }

    #[test]
    fn exactly_seven_remaining_succeeds() {
        let stakeholders = pool("ok", 7, "0.1");
        let voters = select_voters(&stakeholders, 7, 123).unwrap();
        assert_eq!(voters.len(), 7);
    }

    // --- Requirement 11.2: sample size bounds & clamping --------------------

    #[test]
    fn sample_size_below_floor_is_clamped_up_to_seven() {
        let stakeholders = pool("ok", 20, "0.1");
        // Asking for 3 must still yield at least 7.
        let voters = select_voters(&stakeholders, 3, 5).unwrap();
        assert_eq!(voters.len(), MIN_VOTER_SET_SIZE);
    }

    #[test]
    fn sample_size_above_remaining_is_capped() {
        let stakeholders = pool("ok", 9, "0.1");
        // Asking for 50 caps at the 9 that remain.
        let voters = select_voters(&stakeholders, 50, 5).unwrap();
        assert_eq!(voters.len(), 9);
    }

    #[test]
    fn sample_size_within_range_is_respected() {
        let stakeholders = pool("ok", 20, "0.1");
        let voters = select_voters(&stakeholders, 11, 5).unwrap();
        assert_eq!(voters.len(), 11);
        assert!(voters.len() >= MIN_VOTER_SET_SIZE && voters.len() <= 20);
    }

    #[test]
    fn selected_voters_are_distinct() {
        let stakeholders = pool("ok", 30, "0.4");
        let voters = select_voters(&stakeholders, 15, 777).unwrap();
        let mut sorted: Vec<&str> = voters.iter().map(|v| v.as_str()).collect();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), voters.len(), "voters must be distinct");
    }

    // --- Determinism --------------------------------------------------------

    #[test]
    fn same_seed_yields_same_selection() {
        let stakeholders = pool("ok", 25, "0.5");
        let a = select_voters(&stakeholders, 10, 0xDEAD_BEEF).unwrap();
        let b = select_voters(&stakeholders, 10, 0xDEAD_BEEF).unwrap();
        assert_eq!(a, b, "selection must be reproducible for a fixed seed");
    }

    #[test]
    fn different_seeds_generally_differ() {
        // Not a hard guarantee for all inputs, but with 25 choose 10 the odds of an
        // identical ordered pick across two distinct seeds are vanishingly small.
        let stakeholders = pool("ok", 25, "0.5");
        let a = select_voters(&stakeholders, 10, 1).unwrap();
        let b = select_voters(&stakeholders, 10, 2).unwrap();
        assert_ne!(a, b);
    }

    // --- Requirement 11.4: anomalous voting-behaviour detection -------------

    const DAY: u64 = 86_400;

    /// Builds a `VoteEvent` for `voter`/`target` at `days_ago` before `now_secs`.
    fn vote_at(voter: &str, target: &str, approve: bool, secs: u64) -> VoteEvent {
        VoteEvent::new(
            FayID::new(voter),
            target,
            approve,
            Timestamp::from_secs(secs),
        )
    }

    #[test]
    fn five_approvals_above_80_percent_within_window_is_flagged() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // 5 approvals + 1 reject => 5/6 ≈ 83.3% > 80%, count 5 >= 5 -> anomalous.
        let history = vec![
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
            vote_at("v1", "obj", true, 97 * DAY),
            vote_at("v1", "obj", true, 96 * DAY),
            vote_at("v1", "obj", true, 95 * DAY),
            vote_at("v1", "obj", false, 94 * DAY),
        ];
        let entry = detect_anomaly(&voter, "obj", &history, now).expect("should be flagged");
        assert_eq!(entry.voter, voter);
        assert_eq!(entry.target, "obj");
        assert_eq!(entry.approval_count, 5);
        assert_eq!(entry.total_count, 6);
        assert_eq!(entry.window_end, now);
    }

    #[test]
    fn four_approvals_below_count_threshold_is_not_flagged() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // 4 approvals only (100% ratio) but count < 5 -> not anomalous.
        let history = vec![
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
            vote_at("v1", "obj", true, 97 * DAY),
            vote_at("v1", "obj", true, 96 * DAY),
        ];
        assert!(detect_anomaly(&voter, "obj", &history, now).is_none());
    }

    #[test]
    fn exactly_80_percent_ratio_is_not_flagged() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // 8 approvals + 2 rejects => 8/10 = exactly 80%; must be strictly greater.
        let mut history = Vec::new();
        for i in 0..8 {
            history.push(vote_at("v1", "obj", true, (99 - i) * DAY));
        }
        history.push(vote_at("v1", "obj", false, 90 * DAY));
        history.push(vote_at("v1", "obj", false, 89 * DAY));
        assert_eq!(history.iter().filter(|e| e.approve).count(), 8);
        assert!(
            detect_anomaly(&voter, "obj", &history, now).is_none(),
            "exactly 80% must NOT be flagged (strictly greater required)"
        );
    }

    #[test]
    fn just_above_80_percent_ratio_is_flagged() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // 9 approvals + 2 rejects => 9/11 ≈ 81.8% > 80%, count 9 >= 5 -> anomalous.
        let mut history = Vec::new();
        for i in 0..9 {
            history.push(vote_at("v1", "obj", true, (99 - i) * DAY));
        }
        history.push(vote_at("v1", "obj", false, 90 * DAY));
        history.push(vote_at("v1", "obj", false, 89 * DAY));
        let entry = detect_anomaly(&voter, "obj", &history, now).expect("should be flagged");
        assert_eq!(entry.approval_count, 9);
        assert_eq!(entry.total_count, 11);
    }

    #[test]
    fn votes_older_than_30_days_are_excluded_from_window() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // 3 approvals inside the window + 4 approvals older than 30 days.
        // In-window count is 3 (< 5) so NOT anomalous despite 100% ratio overall.
        let history = vec![
            vote_at("v1", "obj", true, 99 * DAY), // 1 day ago - in window
            vote_at("v1", "obj", true, 80 * DAY), // 20 days ago - in window
            vote_at("v1", "obj", true, 71 * DAY), // 29 days ago - in window
            vote_at("v1", "obj", true, 60 * DAY), // 40 days ago - outside
            vote_at("v1", "obj", true, 50 * DAY), // outside
            vote_at("v1", "obj", true, 40 * DAY), // outside
            vote_at("v1", "obj", true, 30 * DAY), // outside
        ];
        assert!(
            detect_anomaly(&voter, "obj", &history, now).is_none(),
            "only the 3 in-window approvals count; below the 5-approval threshold"
        );
    }

    #[test]
    fn vote_exactly_30_days_old_is_inside_window() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // Place 5 approvals, the oldest exactly 30 days old (boundary == in window).
        let history = vec![
            vote_at("v1", "obj", true, 100 * DAY - ANOMALY_WINDOW_SECS), // exactly 30d ago
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
            vote_at("v1", "obj", true, 97 * DAY),
            vote_at("v1", "obj", true, 96 * DAY),
        ];
        let entry = detect_anomaly(&voter, "obj", &history, now).expect("boundary vote counts");
        assert_eq!(entry.approval_count, 5);
        assert_eq!(entry.total_count, 5);
    }

    #[test]
    fn votes_toward_other_targets_and_other_voters_are_ignored() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // Only 4 approvals toward "obj"; the rest are noise toward other targets/voters.
        let history = vec![
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
            vote_at("v1", "obj", true, 97 * DAY),
            vote_at("v1", "obj", true, 96 * DAY),
            vote_at("v1", "other-obj", true, 95 * DAY), // different target
            vote_at("v2", "obj", true, 94 * DAY),       // different voter
        ];
        assert!(
            detect_anomaly(&voter, "obj", &history, now).is_none(),
            "only v1's votes toward obj count; that is 4 (< 5)"
        );
    }

    #[test]
    fn future_dated_votes_are_ignored() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        let history = vec![
            vote_at("v1", "obj", true, 101 * DAY), // future
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
        ];
        // Only 2 in-window approvals -> not anomalous.
        assert!(detect_anomaly(&voter, "obj", &history, now).is_none());
    }

    #[test]
    fn engine_records_pending_audit_entry_when_anomalous() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        let history = vec![
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
            vote_at("v1", "obj", true, 97 * DAY),
            vote_at("v1", "obj", true, 96 * DAY),
            vote_at("v1", "obj", true, 95 * DAY),
        ];
        let mut engine = AntiFraudEngine::new();
        assert!(engine.pending_audit().is_empty());

        let recorded = engine
            .record_if_anomalous(&voter, "obj", &history, now)
            .cloned()
            .expect("anomalous behaviour should be recorded");
        assert_eq!(recorded.approval_count, 5);
        assert_eq!(recorded.total_count, 5);

        assert_eq!(engine.pending_audit().len(), 1);
        assert_eq!(engine.pending_audit()[0], recorded);
    }

    #[test]
    fn engine_records_nothing_when_not_anomalous() {
        let now = Timestamp::from_secs(100 * DAY);
        let voter = FayID::new("v1");
        // 4 approvals -> below count threshold.
        let history = vec![
            vote_at("v1", "obj", true, 99 * DAY),
            vote_at("v1", "obj", true, 98 * DAY),
            vote_at("v1", "obj", true, 97 * DAY),
            vote_at("v1", "obj", true, 96 * DAY),
        ];
        let mut engine = AntiFraudEngine::new();
        assert!(engine
            .record_if_anomalous(&voter, "obj", &history, now)
            .is_none());
        assert!(engine.pending_audit().is_empty());
    }
}
