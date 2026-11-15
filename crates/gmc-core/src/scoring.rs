//! `Scoring_Engine` — three-dimensional classification, inflation index, weighted sum.
//!
//! This module implements the design's *三维评分计算流程 (Scoring Computation Flow)*.
//! It is built up across three sequential tasks in this same file:
//!
//! - **Task 8.1:** dimension classification + proportion validation
//!   ([`ScoringEngine::classify`]).
//! - **Task 8.2:** inflation-index configuration & range validation
//!   ([`InflationIndexConfig`] + [`InflationIndexConfig::set_inflation_index`]) plus the
//!   governance-gated change seam ([`InflationIndexConfig::apply_governed_change`]).
//! - **Task 8.3 (this task):** weighted mint-amount sum
//!   ([`ScoringEngine::compute_mint_amount`]) over a [`BaseScores`] map.
//!
//! Tasks 8.2 and 8.3 append to this file without disturbing the classification logic
//! implemented in task 8.1.

use std::collections::BTreeMap;

use crate::error::{GmcError, GmcResult};
use crate::types::{Decimal, Dimension, DimensionWeights};

/// The scoring engine computes a contribution's dimension classification, applies the
/// per-dimension inflation index, and produces the single-mint amount.
///
/// At this stage it is a stateless validator for the dimension-weight classification
/// (task 8.1). Tasks 8.2/8.3 extend it with inflation-index state and the weighted
/// mint-amount computation; this struct is therefore the shared seam those tasks build
/// on.
#[derive(Debug, Clone, Default)]
pub struct ScoringEngine;

impl ScoringEngine {
    /// Creates a new scoring engine.
    pub fn new() -> Self {
        ScoringEngine
    }

    /// Validates a proposed three-dimensional classification and returns the accepted
    /// [`DimensionWeights`] on success (design step *维度分类 / 占比校验*).
    ///
    /// The concrete `Evaluation_Mechanism`-driven dimension *selection* (deciding which
    /// of Thought / Training / Technique a given contribution belongs to, per
    /// Requirements 6.1–6.4) is owned by the mechanism module and is wired into this
    /// entry point by a later integration task. What this function implements now is the
    /// dimension-count + proportion validation that Requirements 6.5–6.7 demand of any
    /// classification result, regardless of how the proportions were proposed:
    ///
    /// - **1..=3 dimensions** must be present. A classification covering *zero*
    ///   dimensions means the contribution could not be placed in any dimension and is
    ///   rejected with [`GmcError::DimensionUnmatched`] (Requirement 6.6). The upper
    ///   bound of 3 is structurally guaranteed by [`DimensionWeights`] (keyed by the
    ///   three-variant `Dimension` enum), so it can never be exceeded.
    /// - **Each proportion ∈ (0, 1].** [`crate::types::Ratio`] already constrains values
    ///   to `[0, 1]`; this function additionally rejects a present-but-zero proportion.
    ///   A zero proportion means that dimension should not have been listed at all, so it
    ///   is a proportion-validity failure and is reported as [`GmcError::WeightSumInvalid`]
    ///   (the only scoring error code covering proportion validity besides the
    ///   "no dimension at all" case; Requirement 6.5).
    /// - **Σ proportions == 1 (100%) exactly.** Because amounts are fixed-point
    ///   [`Decimal`]s, exact equality with [`Decimal::ONE`] is the correct test; any other
    ///   sum is rejected with [`GmcError::WeightSumInvalid`] (Requirement 6.7).
    ///
    /// Both error paths are pure validation outcomes: this function returns a `Result`
    /// and performs no minting. Minting is gated separately by the `Minting_Service`,
    /// which never runs when classification fails.
    pub fn classify(&self, proposed: DimensionWeights) -> GmcResult<DimensionWeights> {
        // (1) Dimension count: at least one dimension must apply (Requirement 6.6).
        // The 1..=3 range's upper bound is guaranteed by the type (3 enum keys max).
        if proposed.is_empty() {
            return Err(GmcError::DimensionUnmatched);
        }

        // (2) Each applicable proportion must lie in (0, 1]. Ratio already guarantees
        // the closed [0, 1] range, so here we only need to reject a zero proportion: a
        // listed dimension with 0% weight should not be present (Requirement 6.5).
        for (_dimension, ratio) in proposed.iter() {
            if ratio.is_zero() {
                return Err(GmcError::WeightSumInvalid);
            }
        }

        // (3) Proportions must sum to exactly 1 (100%). Fixed-point arithmetic makes the
        // exact comparison correct (Requirement 6.7).
        let sum = proposed.weight_sum().ok_or(GmcError::WeightSumInvalid)?;
        if sum != Decimal::ONE {
            return Err(GmcError::WeightSumInvalid);
        }

        Ok(proposed)
    }

    /// Computes the single-mint amount as the weighted sum over applicable dimensions
    /// (design *Scoring Computation Flow* steps 4–6; Requirements 7.5, 7.6, 8.3):
    ///
    /// ```text
    /// amount = Σ_dim  weights[dim] × baseScore[dim] × inflationIndex[dim]
    /// ```
    ///
    /// # Inputs
    ///
    /// - `weights`: a dimension classification. It is **re-validated** here via
    ///   [`classify`](Self::classify) so this entry point is safe to call directly:
    ///   the weights must cover 1..=3 dimensions, each weight ∈ (0, 1], and Σ == 1
    ///   (Requirements 6.5–6.7). An invalid classification surfaces the same
    ///   [`GmcError::DimensionUnmatched`] / [`GmcError::WeightSumInvalid`] codes.
    /// - `base_scores`: the per-dimension base scores ([`BaseScores`]). Every dimension
    ///   present in `weights` **must** have a base score; a missing base score for a
    ///   present dimension is malformed input and is rejected with
    ///   [`GmcError::InvalidMintAmount`]. Base scores must be non-negative (design step 6
    ///   / Property 15 precondition); a negative base score is likewise rejected.
    /// - `indices`: the chain's [`InflationIndexConfig`]. Each dimension's index is
    ///   already range-validated to be strictly positive (≥ 0.01), so it never zeroes a
    ///   contribution.
    ///
    /// # Strictly-positive guarantee (Requirements 7.5, 8.3, 8.7)
    ///
    /// Because every applicable weight is > 0 and every inflation index is > 0, the only
    /// way the sum can be non-positive is if **all** base scores are 0 (the worked
    /// design example requires at least one base score > 0). When the computed amount is
    /// not strictly greater than zero this function returns [`GmcError::InvalidMintAmount`]
    /// so the `Minting_Service` blocks minting; on success the returned [`Decimal`] is
    /// guaranteed strictly positive.
    ///
    /// Note: arithmetic is fixed-point and truncates toward zero, so a contribution from
    /// extremely small weight/base/index operands can truncate to 0; if the whole sum
    /// truncates to 0 the call is rejected, consistent with the "amount must be > 0" rule.
    ///
    /// On fixed-point overflow the contribution/accumulation is rejected with
    /// [`GmcError::InvalidMintAmount`] (no separate overflow code exists in the shared
    /// error vocabulary, and an un-representable amount cannot be safely minted).
    pub fn compute_mint_amount(
        &self,
        weights: &DimensionWeights,
        base_scores: &BaseScores,
        indices: &InflationIndexConfig,
    ) -> GmcResult<Decimal> {
        // Defensively re-validate the classification (1..=3 dims, each weight ∈ (0, 1],
        // Σ == 1). This guarantees every present dimension carries a strictly-positive
        // weight, which underpins the strictly-positive output guarantee below.
        self.classify(weights.clone())?;

        let mut amount = Decimal::ZERO;
        for (dimension, weight) in weights.iter() {
            // Every present dimension must supply a base score (Requirement 7.6: the sum
            // ranges over applicable dimensions). A missing one is malformed input.
            let base = base_scores
                .get(dimension)
                .ok_or(GmcError::InvalidMintAmount)?;
            // Base scores are non-negative; a negative value is invalid input.
            if base.is_negative() {
                return Err(GmcError::InvalidMintAmount);
            }
            let index = indices.get(dimension);
            // contribution = weight × base × index, with checked fixed-point arithmetic.
            let contribution = weight
                .value()
                .checked_mul(base)
                .and_then(|weighted_base| weighted_base.checked_mul(index))
                .ok_or(GmcError::InvalidMintAmount)?;
            amount = amount
                .checked_add(contribution)
                .ok_or(GmcError::InvalidMintAmount)?;
        }

        // Strictly-positive guarantee: reject when all base scores are 0 (or the result
        // is otherwise ≤ 0) so minting is blocked (Requirements 7.5, 8.3, 8.7).
        if !amount.is_positive() {
            return Err(GmcError::InvalidMintAmount);
        }
        Ok(amount)
    }
}

/// Per-dimension base scores consumed by [`ScoringEngine::compute_mint_amount`]
/// (design data model `ContributionRecord.baseScores: { Thought?, Training?, Technique?: Decimal }`).
///
/// This mirrors [`DimensionWeights`]'s shape — a sparse 1..=3 map keyed by [`Dimension`]
/// — so weights and base scores read symmetrically at the call site (and so the minting
/// pipeline in task 9.3 and the Property 15 test in task 8.6 can build inputs the same
/// way). Each present dimension's value is that dimension's raw, pre-inflation base
/// score; `compute_mint_amount` multiplies it by the dimension's weight and inflation
/// index. Base scores are expected to be non-negative.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BaseScores {
    scores: BTreeMap<Dimension, Decimal>,
}

impl BaseScores {
    /// Creates an empty base-score map.
    pub fn new() -> Self {
        BaseScores {
            scores: BTreeMap::new(),
        }
    }

    /// Builds a base-score map from an iterator of `(Dimension, Decimal)` entries.
    pub fn from_entries(entries: impl IntoIterator<Item = (Dimension, Decimal)>) -> Self {
        BaseScores {
            scores: entries.into_iter().collect(),
        }
    }

    /// Sets the base score for `dimension`, returning the previous value if any.
    pub fn set(&mut self, dimension: Dimension, score: Decimal) -> Option<Decimal> {
        self.scores.insert(dimension, score)
    }

    /// Returns the base score for `dimension`, if present.
    pub fn get(&self, dimension: Dimension) -> Option<Decimal> {
        self.scores.get(&dimension).copied()
    }

    /// Number of dimensions carrying a base score.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Returns `true` if no base scores are present.
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

/// Per-chain inflation-index configuration for the three scoring dimensions
/// (design *Nested_Merit_Chain 配置* → `inflationIndex`; Requirement 7).
///
/// Each dimension carries an independent multiplier ([`Decimal`]) that
/// [`ScoringEngine::compute_mint_amount`] (task 8.3) applies to that dimension's base
/// score. This configuration is the **state** behind Requirement 7's validation rules;
/// it lives here (rather than on the stateless [`ScoringEngine`]) so it can be attached
/// to each chain's `NestedMeritChainConfig` and anchored to L1 independently of the
/// pure-function scoring engine. Keeping it separate also preserves task 8.1's
/// [`ScoringEngine::classify`] as a stateless validator.
///
/// # Per-dimension valid ranges (validated to two-decimal precision)
///
/// - **Thought**: `(1.00, 10.00]` — strictly greater than `1.00`, at most `10.00`
///   (Requirement 7.2).
/// - **Training**: `[0.95, 1.05]` — i.e. `1.00 ± 0.05` (Requirement 7.3).
/// - **Technique**: `[0.01, 1.00]` (Requirement 7.4).
///
/// Any value carrying more than two decimal places, or falling outside its dimension's
/// band, is rejected with [`GmcError::InflationIndexOutOfRange`] and the dimension's
/// previous value is left untouched (validate-then-replace discipline; Requirements
/// 7.1–7.4, 7.8).
///
/// # Defaults
///
/// [`InflationIndexConfig::default`] constructs an in-range configuration so a chain
/// config is always valid out of the box:
///
/// - Thought = `2.00` (inside `(1.00, 10.00]`),
/// - Training = `1.00` (inside `[0.95, 1.05]`),
/// - Technique = `1.00` (inside `[0.01, 1.00]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflationIndexConfig {
    thought: Decimal,
    training: Decimal,
    technique: Decimal,
}

impl InflationIndexConfig {
    /// Builds the default, in-range inflation-index configuration
    /// (Thought = 2.00, Training = 1.00, Technique = 1.00).
    ///
    /// These defaults are chosen so the configuration is valid the moment it is
    /// constructed; they can be changed afterwards via
    /// [`set_inflation_index`](Self::set_inflation_index) (subject to range validation)
    /// or [`apply_governed_change`](Self::apply_governed_change) (subject to governance).
    pub fn new() -> Self {
        InflationIndexConfig {
            // 2.00, 1.00, 1.00 — all strictly inside their respective bands.
            thought: Decimal::from_int(2),
            training: Decimal::ONE,
            technique: Decimal::ONE,
        }
    }

    /// Returns the current inflation index for `dimension`.
    pub fn get(&self, dimension: Dimension) -> Decimal {
        match dimension {
            Dimension::Thought => self.thought,
            Dimension::Training => self.training,
            Dimension::Technique => self.technique,
        }
    }

    /// Inclusive lower / exclusive-or-inclusive upper bounds for `dimension`, expressed
    /// as raw fixed-point [`Decimal`]s alongside whether the lower bound is *open*.
    ///
    /// Returned tuple: `(lower, lower_is_open, upper)` where the accepted interval is
    /// `(lower, upper]` when `lower_is_open` and `[lower, upper]` otherwise. The upper
    /// bound is always inclusive across the three dimensions.
    fn band(dimension: Dimension) -> (Decimal, bool, Decimal) {
        match dimension {
            // Thought: (1.00, 10.00] — open lower bound (Requirement 7.2).
            Dimension::Thought => (Decimal::ONE, true, Decimal::from_int(10)),
            // Training: [0.95, 1.05] (Requirement 7.3).
            Dimension::Training => (
                Decimal::from_str("0.95").expect("valid literal"),
                false,
                Decimal::from_str("1.05").expect("valid literal"),
            ),
            // Technique: [0.01, 1.00] (Requirement 7.4).
            Dimension::Technique => (
                Decimal::from_str("0.01").expect("valid literal"),
                false,
                Decimal::ONE,
            ),
        }
    }

    /// Returns `true` if `value` has at most two fractional decimal digits
    /// (Requirement 7.1: indices are "精确到两位小数" / precise to two decimals).
    ///
    /// Because [`Decimal`] carries [`Decimal::SCALE_DIGITS`] fractional digits, a value
    /// with at most two decimals must be an exact multiple of `10^(SCALE_DIGITS - 2)`.
    fn has_at_most_two_decimals(value: Decimal) -> bool {
        let step = 10i128.pow(Decimal::SCALE_DIGITS - 2);
        value.raw() % step == 0
    }

    /// Returns `true` if `value` is a valid index for `dimension`: it carries at most two
    /// decimal places and lies within the dimension's band.
    fn is_valid(dimension: Dimension, value: Decimal) -> bool {
        if !Self::has_at_most_two_decimals(value) {
            return false;
        }
        let (lower, lower_is_open, upper) = Self::band(dimension);
        let lower_ok = if lower_is_open {
            value > lower
        } else {
            value >= lower
        };
        lower_ok && value <= upper
    }

    /// Validates and sets the inflation index for a single `dimension`
    /// (design `Scoring_Engine.setInflationIndex`; Requirements 7.1–7.4, 7.8).
    ///
    /// On success the new value replaces the dimension's index and `Ok(())` is returned.
    /// On failure (value outside the dimension's band, or carrying more than two decimal
    /// places) the configuration is left **completely unchanged** and
    /// [`GmcError::InflationIndexOutOfRange`] is returned — i.e. the prior value is
    /// preserved (validate-then-replace, Requirement 7.8). This setter intentionally
    /// performs no governance check; it models a direct, locally-validated configuration
    /// edit. Governance-gated changes go through
    /// [`apply_governed_change`](Self::apply_governed_change).
    pub fn set_inflation_index(&mut self, dimension: Dimension, value: Decimal) -> GmcResult<()> {
        if !Self::is_valid(dimension, value) {
            // Validate first: on any failure the stored value is untouched.
            return Err(GmcError::InflationIndexOutOfRange);
        }
        match dimension {
            Dimension::Thought => self.thought = value,
            Dimension::Training => self.training = value,
            Dimension::Technique => self.technique = value,
        }
        Ok(())
    }

    /// Applies an inflation-index change **only after** a governance threshold has been
    /// met (Requirements 7.7, 7.9).
    ///
    /// This is the documented seam for governance-gated index changes. The real wiring to
    /// [`crate::governance`] (weighted tally vs. this chain's threshold) and the L1
    /// anchoring of the accepted change are integrated by a later task (18.1); modeling
    /// the guard here keeps Requirement 7.9's "reject-and-preserve" behavior testable in
    /// isolation:
    ///
    /// - `governance_passed == false`: the change is rejected with
    ///   [`GmcError::GovernanceThresholdNotMet`] and **no** value changes (Requirement
    ///   7.9), regardless of whether the value itself would have been in range.
    /// - `governance_passed == true`: the value still has to pass the same range / two-
    ///   decimal validation as [`set_inflation_index`](Self::set_inflation_index); an
    ///   out-of-range value is rejected with [`GmcError::InflationIndexOutOfRange`] and
    ///   the prior value is preserved.
    ///
    /// On success the change takes effect locally and would, in the integrated system, be
    /// anchored to L1 (see [`anchor_to_l1`](Self::anchor_to_l1) placeholder).
    pub fn apply_governed_change(
        &mut self,
        dimension: Dimension,
        value: Decimal,
        governance_passed: bool,
    ) -> GmcResult<()> {
        if !governance_passed {
            // Governance gate fails first: current index preserved (Requirement 7.9).
            return Err(GmcError::GovernanceThresholdNotMet);
        }
        self.set_inflation_index(dimension, value)?;
        // L1 anchoring of the accepted change is wired in task 18.1.
        self.anchor_to_l1(dimension);
        Ok(())
    }

    /// Placeholder for anchoring an accepted inflation-index change to `L1_Settlement`
    /// (Requirement 7.7). The concrete anchoring is implemented by the L1 integration
    /// task (18.1); this no-op keeps the call site explicit so the governance flow above
    /// reads end-to-end.
    fn anchor_to_l1(&self, _dimension: Dimension) {
        // Intentionally empty: see task 18.1 for the real L1 anchoring implementation.
    }
}

impl Default for InflationIndexConfig {
    fn default() -> Self {
        InflationIndexConfig::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Dimension, Ratio};

    /// Helper: build a `DimensionWeights` from `(Dimension, percent)` pairs.
    fn weights(entries: &[(Dimension, u8)]) -> DimensionWeights {
        DimensionWeights::from_entries(
            entries
                .iter()
                .map(|(dim, pct)| (*dim, Ratio::from_percent(*pct).unwrap())),
        )
    }

    #[test]
    fn single_dimension_full_weight_is_accepted() {
        let engine = ScoringEngine::new();
        let input = weights(&[(Dimension::Thought, 100)]);
        let result = engine.classify(input.clone());
        assert_eq!(result, Ok(input));
    }

    #[test]
    fn two_dimensions_summing_to_one_are_accepted() {
        let engine = ScoringEngine::new();
        // {Thought: 0.7, Technique: 0.3} — a cross-dimension contribution.
        let input = weights(&[(Dimension::Thought, 70), (Dimension::Technique, 30)]);
        let result = engine.classify(input.clone());
        assert_eq!(result, Ok(input));
    }

    #[test]
    fn three_dimensions_summing_to_one_are_accepted() {
        let engine = ScoringEngine::new();
        // {Thought: 0.5, Training: 0.3, Technique: 0.2}.
        let input = weights(&[
            (Dimension::Thought, 50),
            (Dimension::Training, 30),
            (Dimension::Technique, 20),
        ]);
        let result = engine.classify(input.clone());
        assert_eq!(result, Ok(input));
    }

    #[test]
    fn empty_classification_is_dimension_unmatched() {
        let engine = ScoringEngine::new();
        let input = DimensionWeights::new();
        assert_eq!(engine.classify(input), Err(GmcError::DimensionUnmatched));
    }

    #[test]
    fn proportions_not_summing_to_one_are_weight_sum_invalid() {
        let engine = ScoringEngine::new();
        // {Thought: 0.7, Technique: 0.4} sums to 1.1 != 1.
        let input = weights(&[(Dimension::Thought, 70), (Dimension::Technique, 40)]);
        assert_eq!(engine.classify(input), Err(GmcError::WeightSumInvalid));
    }

    #[test]
    fn proportions_summing_below_one_are_weight_sum_invalid() {
        let engine = ScoringEngine::new();
        // {Thought: 0.6, Technique: 0.3} sums to 0.9 != 1.
        let input = weights(&[(Dimension::Thought, 60), (Dimension::Technique, 30)]);
        assert_eq!(engine.classify(input), Err(GmcError::WeightSumInvalid));
    }

    #[test]
    fn zero_proportion_dimension_is_rejected() {
        let engine = ScoringEngine::new();
        // A present-but-zero dimension violates the (0, 1] rule even though the
        // remaining weights sum to 1.
        let input = DimensionWeights::from_entries([
            (Dimension::Thought, Ratio::ONE),
            (Dimension::Technique, Ratio::ZERO),
        ]);
        assert_eq!(engine.classify(input), Err(GmcError::WeightSumInvalid));
    }

    // --- Task 8.2: InflationIndexConfig range validation -------------------

    /// Helper: parse a two-decimal literal into a `Decimal`.
    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).expect("valid decimal literal")
    }

    #[test]
    fn default_config_is_in_range() {
        let cfg = InflationIndexConfig::default();
        assert_eq!(cfg.get(Dimension::Thought), Decimal::from_int(2));
        assert_eq!(cfg.get(Dimension::Training), Decimal::ONE);
        assert_eq!(cfg.get(Dimension::Technique), Decimal::ONE);
    }

    #[test]
    fn valid_in_range_set_is_accepted_per_dimension() {
        let mut cfg = InflationIndexConfig::default();
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("3.50")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Thought), dec("3.50"));

        assert_eq!(
            cfg.set_inflation_index(Dimension::Training, dec("1.00")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Training), dec("1.00"));

        assert_eq!(
            cfg.set_inflation_index(Dimension::Technique, dec("0.50")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Technique), dec("0.50"));
    }

    #[test]
    fn thought_open_lower_bound_rejects_exactly_one() {
        let mut cfg = InflationIndexConfig::default();
        // Thought band is (1.00, 10.00]; exactly 1.00 is excluded.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("1.00")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        // Prior value preserved.
        assert_eq!(cfg.get(Dimension::Thought), Decimal::from_int(2));
    }

    #[test]
    fn thought_upper_bound_inclusive_and_above_rejected() {
        let mut cfg = InflationIndexConfig::default();
        // 10.00 is the inclusive upper bound.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("10.00")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Thought), dec("10.00"));
        // Just above 10.00 is rejected, preserving the accepted 10.00.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("10.01")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        assert_eq!(cfg.get(Dimension::Thought), dec("10.00"));
    }

    #[test]
    fn training_closed_bounds_accept_and_reject() {
        let mut cfg = InflationIndexConfig::default();
        // [0.95, 1.05] — both endpoints accepted.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Training, dec("0.95")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Training), dec("0.95"));
        assert_eq!(
            cfg.set_inflation_index(Dimension::Training, dec("1.05")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Training), dec("1.05"));
        // Just outside either endpoint is rejected, preserving the prior 1.05.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Training, dec("0.94")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        assert_eq!(cfg.get(Dimension::Training), dec("1.05"));
        assert_eq!(
            cfg.set_inflation_index(Dimension::Training, dec("1.06")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        assert_eq!(cfg.get(Dimension::Training), dec("1.05"));
    }

    #[test]
    fn technique_closed_bounds_accept_and_reject_zero() {
        let mut cfg = InflationIndexConfig::default();
        // [0.01, 1.00] — both endpoints accepted.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Technique, dec("0.01")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Technique), dec("0.01"));
        assert_eq!(
            cfg.set_inflation_index(Dimension::Technique, dec("1.00")),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Technique), dec("1.00"));
        // 0.00 is below the lower bound and rejected, preserving the prior 1.00.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Technique, dec("0.00")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        assert_eq!(cfg.get(Dimension::Technique), dec("1.00"));
    }

    #[test]
    fn value_with_more_than_two_decimals_is_rejected() {
        let mut cfg = InflationIndexConfig::default();
        // 2.001 is inside Thought's band numerically but has three decimals.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("2.001")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        // Prior value preserved.
        assert_eq!(cfg.get(Dimension::Thought), Decimal::from_int(2));
    }

    #[test]
    fn rejection_preserves_prior_value() {
        let mut cfg = InflationIndexConfig::default();
        // First set a valid value.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("4.20")),
            Ok(())
        );
        // A subsequent out-of-range set must not clobber it.
        assert_eq!(
            cfg.set_inflation_index(Dimension::Thought, dec("0.50")),
            Err(GmcError::InflationIndexOutOfRange)
        );
        assert_eq!(cfg.get(Dimension::Thought), dec("4.20"));
    }

    #[test]
    fn governance_passed_change_is_applied() {
        let mut cfg = InflationIndexConfig::default();
        assert_eq!(
            cfg.apply_governed_change(Dimension::Thought, dec("5.00"), true),
            Ok(())
        );
        assert_eq!(cfg.get(Dimension::Thought), dec("5.00"));
    }

    #[test]
    fn governance_not_passed_change_is_rejected_and_preserves_value() {
        let mut cfg = InflationIndexConfig::default();
        // Even an otherwise-valid value is rejected when governance has not passed.
        assert_eq!(
            cfg.apply_governed_change(Dimension::Thought, dec("5.00"), false),
            Err(GmcError::GovernanceThresholdNotMet)
        );
        // Current index preserved (Requirement 7.9).
        assert_eq!(cfg.get(Dimension::Thought), Decimal::from_int(2));
    }

    #[test]
    fn governance_passed_but_out_of_range_is_rejected_and_preserves_value() {
        let mut cfg = InflationIndexConfig::default();
        // Governance passed, but the value is out of Thought's band.
        assert_eq!(
            cfg.apply_governed_change(Dimension::Thought, dec("1.00"), true),
            Err(GmcError::InflationIndexOutOfRange)
        );
        assert_eq!(cfg.get(Dimension::Thought), Decimal::from_int(2));
    }

    // --- Task 8.3: compute_mint_amount weighted sum -----------------------

    /// Helper: build a `BaseScores` from `(Dimension, decimal-literal)` pairs.
    fn base_scores(entries: &[(Dimension, &str)]) -> BaseScores {
        BaseScores::from_entries(entries.iter().map(|(dim, s)| (*dim, dec(s))))
    }

    #[test]
    fn worked_example_cross_dimension_sums_exactly() {
        // Design's worked example: a cross-dimension (research + engineering) contribution.
        //   Thought:   0.7 × base 10 × index 3.00 = 21.0
        //   Technique: 0.3 × base 10 × index 0.80 =  2.4
        //   total = 23.4 (> 0, proceeds to minting)
        let engine = ScoringEngine::new();
        let mut indices = InflationIndexConfig::default();
        indices
            .set_inflation_index(Dimension::Thought, dec("3.00"))
            .unwrap();
        indices
            .set_inflation_index(Dimension::Technique, dec("0.80"))
            .unwrap();

        let weights = weights(&[(Dimension::Thought, 70), (Dimension::Technique, 30)]);
        let scores = base_scores(&[(Dimension::Thought, "10"), (Dimension::Technique, "10")]);

        let amount = engine
            .compute_mint_amount(&weights, &scores, &indices)
            .expect("valid contribution mints a positive amount");
        assert_eq!(amount, dec("23.4"));
        assert!(amount.is_positive());
    }

    #[test]
    fn single_dimension_full_weight_amount() {
        // Thought 100% × base 5 × index 2.00 (default) = 10.0.
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[(Dimension::Thought, 100)]);
        let scores = base_scores(&[(Dimension::Thought, "5")]);

        let amount = engine
            .compute_mint_amount(&weights, &scores, &indices)
            .expect("single-dimension contribution mints a positive amount");
        assert_eq!(amount, dec("10"));
        assert!(amount.is_positive());
    }

    #[test]
    fn three_dimension_weighted_sum() {
        // {Thought 0.5, Training 0.3, Technique 0.2} with bases & default indices
        // (Thought 2.00, Training 1.00, Technique 1.00):
        //   0.5 × 10 × 2.00 = 10.0
        //   0.3 × 10 × 1.00 =  3.0
        //   0.2 × 10 × 1.00 =  2.0
        //   total = 15.0
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[
            (Dimension::Thought, 50),
            (Dimension::Training, 30),
            (Dimension::Technique, 20),
        ]);
        let scores = base_scores(&[
            (Dimension::Thought, "10"),
            (Dimension::Training, "10"),
            (Dimension::Technique, "10"),
        ]);

        let amount = engine
            .compute_mint_amount(&weights, &scores, &indices)
            .expect("three-dimension contribution mints a positive amount");
        assert_eq!(amount, dec("15"));
        assert!(amount.is_positive());
    }

    #[test]
    fn all_zero_base_scores_is_invalid_mint_amount() {
        // Every base score is 0 → amount = 0 → minting blocked (Requirements 8.3, 8.7).
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[(Dimension::Thought, 70), (Dimension::Technique, 30)]);
        let scores = base_scores(&[(Dimension::Thought, "0"), (Dimension::Technique, "0")]);

        assert_eq!(
            engine.compute_mint_amount(&weights, &scores, &indices),
            Err(GmcError::InvalidMintAmount)
        );
    }

    #[test]
    fn missing_base_score_for_present_dimension_is_invalid() {
        // Technique is weighted but has no base score → malformed input.
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[(Dimension::Thought, 70), (Dimension::Technique, 30)]);
        let scores = base_scores(&[(Dimension::Thought, "10")]);

        assert_eq!(
            engine.compute_mint_amount(&weights, &scores, &indices),
            Err(GmcError::InvalidMintAmount)
        );
    }

    #[test]
    fn negative_base_score_is_invalid() {
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[(Dimension::Thought, 100)]);
        let scores = base_scores(&[(Dimension::Thought, "-1")]);

        assert_eq!(
            engine.compute_mint_amount(&weights, &scores, &indices),
            Err(GmcError::InvalidMintAmount)
        );
    }

    #[test]
    fn invalid_classification_propagates_through_compute() {
        // Weights summing to 1.1 are rejected before any arithmetic.
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[(Dimension::Thought, 70), (Dimension::Technique, 40)]);
        let scores = base_scores(&[(Dimension::Thought, "10"), (Dimension::Technique, "10")]);

        assert_eq!(
            engine.compute_mint_amount(&weights, &scores, &indices),
            Err(GmcError::WeightSumInvalid)
        );
    }

    #[test]
    fn one_positive_base_among_zeros_is_strictly_positive() {
        // At least one base score > 0 guarantees a strictly-positive amount.
        //   Thought:   0.5 × 0  × 2.00 = 0.0
        //   Technique: 0.5 × 4  × 1.00 = 2.0
        //   total = 2.0 (> 0)
        let engine = ScoringEngine::new();
        let indices = InflationIndexConfig::default();
        let weights = weights(&[(Dimension::Thought, 50), (Dimension::Technique, 50)]);
        let scores = base_scores(&[(Dimension::Thought, "0"), (Dimension::Technique, "4")]);

        let amount = engine
            .compute_mint_amount(&weights, &scores, &indices)
            .expect("a single positive base score yields a positive amount");
        assert_eq!(amount, dec("2"));
        assert!(amount.is_positive());
    }
}
