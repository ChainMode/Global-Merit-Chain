//! `Evaluation_Mechanism` — per-chain evaluation config and change governance.
//!
//! This module implements the **evaluation mechanism model + config validation**
//! (task 5.1). Each `Nested_Merit_Chain` stores its own independent
//! [`EvaluationMechanism`] (Requirement 3.1), held in an [`EvaluationMechanismSlot`]
//! so the registry can model "defined here" vs. "inherit from an ancestor"
//! (`null` in the design data model, Requirement 3.2).
//!
//! ## What a valid config requires (Requirements 3.3, 3.6)
//!
//! An [`EvaluationMechanism`] is accepted **iff** both hold:
//!
//! 1. it declares **at least one** contribution-acquisition mode
//!    ([`AcquisitionMode`]: objective metering, bounty task, or both), and
//! 2. its consensus pass-threshold lies in the half-open interval `(0, 1]` —
//!    strictly greater than 0% and at most 100%.
//!
//! Note that [`Ratio`] already constrains values to the closed interval `[0, 1]`, so
//! the type system rules out the upper bound (`> 1` is unrepresentable). The `(0, 1]`
//! rule therefore reduces, at this layer, to *additionally rejecting exactly `0`*.
//! The [`EvaluationMechanism::from_threshold_decimal`] constructor accepts a raw
//! [`Decimal`] and rejects any value outside `(0, 1]` (including `> 1`) up front.
//!
//! When a config is rejected the previous valid config must be preserved
//! (Requirement 3.6). This is modelled by [`EvaluationMechanismSlot::try_set`], which
//! validates first and only replaces the stored config on success — a failed update
//! returns [`GmcError::MechanismConfigInvalid`] and mutates nothing. The standalone
//! constructors are pure: they return `Err` without touching any stored state.
//!
//! ## High-intimacy exclusion (Requirement 3.5)
//!
//! Every mechanism carries an [`EvaluationMechanism::exclude_high_intimacy`] flag that
//! defaults to `true` ([`DEFAULT_EXCLUDE_HIGH_INTIMACY`]), reusing the existing
//! stakeholder-voting + high-intimacy-exclusion rules enforced by `AntiFraud_Engine`.
//!
//! ## Governance-threshold-gated change flow (task 5.2)
//!
//! A change to a chain's [`EvaluationMechanism`] only takes effect after it reaches
//! the chain's own governance threshold (Requirement 3.4); a change that does not
//! reach the threshold is rejected with [`GmcError::GovernanceThresholdNotMet`] and
//! the existing config is preserved unchanged (Requirement 3.7). This is implemented
//! by [`EvaluationMechanismSlot::propose_change`] /
//! [`EvaluationMechanismSlot::propose_change_from_parts`], which take the chain's
//! governance outcome as an explicit [`GovernanceDecision`] input.
//!
//! ### Governance decision is an input, not a dependency
//!
//! The pure-logic core models the governance vote *result* as the caller-supplied
//! [`GovernanceDecision`] value rather than calling the `Governance_Module` directly.
//! This keeps `mechanism` free of any compile/runtime dependency on the (separately
//! authored) governance engine; the real wiring — running the weighted vote, applying
//! the chain's threshold, and protecting voter identity — happens at the integration
//! layer (tasks 18.1 / 20.x), which translates a `Governance_Module` tally into a
//! [`GovernanceDecision`] before invoking the change flow here.
//!
//! ### L1 anchoring seam (Requirement 3.8)
//!
//! When a change is applied, the flow returns a [`MechanismChangeReceipt`] marking
//! that the now-effective change must be **anchored to L1_Settlement**. The real
//! anchoring is wired in task 18.1; this receipt is the documented seam the
//! integration layer consumes to perform the settlement-layer write. No L1 anchoring
//! is performed at this pure-logic layer.

use std::collections::BTreeSet;

use crate::error::{GmcError, GmcResult};
use crate::types::{Decimal, Ratio};

/// Default value of [`EvaluationMechanism::exclude_high_intimacy`] (Requirement 3.5).
///
/// Per the design data model (`excludeHighIntimacy: bool = true`) a chain reuses the
/// high-intimacy-exclusion rule by default.
pub const DEFAULT_EXCLUDE_HIGH_INTIMACY: bool = true;

/// A contribution-recognition acquisition mode an [`EvaluationMechanism`] may declare.
///
/// Per Requirement 3.3 a mechanism must declare at least one of these (it may declare
/// both, i.e. a combination).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AcquisitionMode {
    /// Recognition obtained via objective measurement / metering of the contribution.
    ObjectiveMetering,
    /// Recognition obtained via a posted bounty task.
    BountyTask,
}

impl AcquisitionMode {
    /// All acquisition modes, in a stable order.
    pub const ALL: [AcquisitionMode; 2] = [
        AcquisitionMode::ObjectiveMetering,
        AcquisitionMode::BountyTask,
    ];
}

/// A `Nested_Merit_Chain`'s self-contained evaluation-mechanism configuration.
///
/// Construction is validating: every [`EvaluationMechanism`] that exists is, by
/// construction, valid per Requirements 3.3/3.6 (≥1 acquisition mode and a consensus
/// threshold in `(0, 1]`). Invalid inputs never yield a value — they return
/// [`GmcError::MechanismConfigInvalid`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationMechanism {
    /// The declared acquisition mode(s); always non-empty (Requirement 3.3).
    acquisition_modes: BTreeSet<AcquisitionMode>,
    /// Consensus pass-threshold; always in `(0, 1]` (Requirements 3.3, 3.6).
    consensus_threshold: Ratio,
    /// Whether to exclude high-intimacy entities from voting (Requirement 3.5).
    exclude_high_intimacy: bool,
}

impl EvaluationMechanism {
    /// Builds a validated [`EvaluationMechanism`].
    ///
    /// Accepts the config **iff** at least one [`AcquisitionMode`] is declared and the
    /// `consensus_threshold` lies in `(0, 1]`. Because [`Ratio`] already guarantees the
    /// closed interval `[0, 1]`, the only additional check here is that the threshold
    /// is not exactly `0`.
    ///
    /// # Errors
    /// Returns [`GmcError::MechanismConfigInvalid`] when no acquisition mode is declared
    /// or the threshold is `0`. On error nothing is constructed and no state is touched.
    pub fn new(
        acquisition_modes: impl IntoIterator<Item = AcquisitionMode>,
        consensus_threshold: Ratio,
        exclude_high_intimacy: bool,
    ) -> GmcResult<Self> {
        let acquisition_modes: BTreeSet<AcquisitionMode> = acquisition_modes.into_iter().collect();

        // Requirement 3.3 / 3.6: at least one acquisition mode must be declared.
        if acquisition_modes.is_empty() {
            return Err(GmcError::MechanismConfigInvalid);
        }

        // Requirement 3.3 / 3.6: threshold ∈ (0, 1]. `Ratio` enforces the `≤ 1` (and
        // `≥ 0`) bounds; here we additionally reject exactly `0` to enforce `> 0`.
        if consensus_threshold.is_zero() {
            return Err(GmcError::MechanismConfigInvalid);
        }

        Ok(Self {
            acquisition_modes,
            consensus_threshold,
            exclude_high_intimacy,
        })
    }

    /// Builds a validated [`EvaluationMechanism`] with the default high-intimacy
    /// exclusion ([`DEFAULT_EXCLUDE_HIGH_INTIMACY`] = `true`, Requirement 3.5).
    ///
    /// # Errors
    /// See [`EvaluationMechanism::new`].
    pub fn with_default_exclusion(
        acquisition_modes: impl IntoIterator<Item = AcquisitionMode>,
        consensus_threshold: Ratio,
    ) -> GmcResult<Self> {
        Self::new(
            acquisition_modes,
            consensus_threshold,
            DEFAULT_EXCLUDE_HIGH_INTIMACY,
        )
    }

    /// Builds a validated [`EvaluationMechanism`] from a raw [`Decimal`] threshold.
    ///
    /// This is the constructor to use when the threshold comes from un-validated input:
    /// any value outside `(0, 1]` — including a value strictly greater than `1` — is
    /// rejected with [`GmcError::MechanismConfigInvalid`]. (With the type-safe
    /// [`EvaluationMechanism::new`], a `> 1` threshold is already unrepresentable
    /// because [`Ratio::new`] would have returned `None`.)
    ///
    /// # Errors
    /// Returns [`GmcError::MechanismConfigInvalid`] when the threshold is `≤ 0` or `> 1`,
    /// or when no acquisition mode is declared.
    pub fn from_threshold_decimal(
        acquisition_modes: impl IntoIterator<Item = AcquisitionMode>,
        consensus_threshold: Decimal,
        exclude_high_intimacy: bool,
    ) -> GmcResult<Self> {
        // `Ratio::new` rejects anything outside [0, 1]; the `(0, …]` lower bound is then
        // enforced by `new`'s zero check.
        let threshold = Ratio::new(consensus_threshold).ok_or(GmcError::MechanismConfigInvalid)?;
        Self::new(acquisition_modes, threshold, exclude_high_intimacy)
    }

    /// Returns `true` if `mode` is among the declared acquisition modes.
    pub fn has_acquisition_mode(&self, mode: AcquisitionMode) -> bool {
        self.acquisition_modes.contains(&mode)
    }

    /// Iterates over the declared acquisition modes, in a stable order.
    pub fn acquisition_modes(&self) -> impl Iterator<Item = AcquisitionMode> + '_ {
        self.acquisition_modes.iter().copied()
    }

    /// Number of declared acquisition modes (always `≥ 1`).
    pub fn acquisition_mode_count(&self) -> usize {
        self.acquisition_modes.len()
    }

    /// The consensus pass-threshold (always in `(0, 1]`).
    pub fn consensus_threshold(&self) -> Ratio {
        self.consensus_threshold
    }

    /// Whether high-intimacy entities are excluded from voting (Requirement 3.5).
    pub fn exclude_high_intimacy(&self) -> bool {
        self.exclude_high_intimacy
    }
}

/// The governance outcome for a proposed [`EvaluationMechanism`] change, supplied by
/// the caller (Requirements 3.4, 3.7).
///
/// At this pure-logic layer the change flow does **not** run the vote itself: the
/// `Governance_Module`'s weighted tally against the chain's threshold is performed at
/// the integration layer (tasks 18.1 / 20.x), which collapses the result into one of
/// these two variants before invoking
/// [`EvaluationMechanismSlot::propose_change`]. Modelling the decision as an input
/// (rather than calling governance internals) keeps `mechanism` decoupled from the
/// separately authored governance engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceDecision {
    /// The change reached the chain's established governance threshold and may take
    /// effect (Requirement 3.4).
    ThresholdReached,
    /// The change did **not** reach the chain's governance threshold and must be
    /// rejected, preserving the existing config (Requirement 3.7).
    ThresholdNotReached,
}

impl GovernanceDecision {
    /// Builds a [`GovernanceDecision`] from a plain `passed` flag.
    ///
    /// `true` maps to [`GovernanceDecision::ThresholdReached`], `false` to
    /// [`GovernanceDecision::ThresholdNotReached`]. This is the convenience the
    /// integration layer uses once it has compared a `Governance_Module` tally's
    /// weighted approval against the chain's threshold.
    pub const fn from_passed(passed: bool) -> Self {
        if passed {
            GovernanceDecision::ThresholdReached
        } else {
            GovernanceDecision::ThresholdNotReached
        }
    }

    /// Returns `true` if the chain's governance threshold was reached.
    pub const fn threshold_reached(self) -> bool {
        matches!(self, GovernanceDecision::ThresholdReached)
    }
}

/// Returned when a governance-approved [`EvaluationMechanism`] change is applied,
/// flagging that the now-effective change must be anchored to L1 (Requirement 3.8).
///
/// This is the documented **L1-anchoring seam**: the pure-logic core performs no
/// settlement-layer write, it only records — via [`anchor_required`] being `true` —
/// that the integration layer (task 18.1) must anchor this effective change to
/// `L1_Settlement`. The applied config is included so the anchoring layer can record
/// exactly what took effect without re-reading the slot.
///
/// [`anchor_required`]: MechanismChangeReceipt::anchor_required
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechanismChangeReceipt {
    /// Always `true`: an effective change must be anchored to L1 (Requirement 3.8).
    /// The actual anchoring is wired in task 18.1.
    anchor_required: bool,
    /// The config that just took effect (what should be anchored to L1).
    applied: EvaluationMechanism,
}

impl MechanismChangeReceipt {
    /// Builds a receipt for an applied change (always flags `anchor_required = true`).
    fn for_applied(applied: EvaluationMechanism) -> Self {
        MechanismChangeReceipt {
            anchor_required: true,
            applied,
        }
    }

    /// Whether the now-effective change must be anchored to L1 (Requirement 3.8).
    ///
    /// Always `true` for a successful change; the real L1 write is task 18.1.
    pub fn anchor_required(&self) -> bool {
        self.anchor_required
    }

    /// The [`EvaluationMechanism`] that took effect and is to be anchored to L1.
    pub fn applied(&self) -> &EvaluationMechanism {
        &self.applied
    }
}

/// Per-chain holder for an [`EvaluationMechanism`] (Requirements 3.1, 3.6).
///
/// A chain stores its own independent mechanism config. An empty slot (`None`)
/// represents "no custom mechanism defined here" — the design's `null`, meaning the
/// chain inherits from the nearest ancestor that defines one (Requirement 3.2,
/// resolved by `Chain_Registry` in task 2.3).
///
/// [`try_set`](EvaluationMechanismSlot::try_set) implements the **validate-then-replace**
/// discipline required by Requirement 3.6: a rejected update returns
/// [`GmcError::MechanismConfigInvalid`] and leaves the previously stored valid config
/// untouched.
///
/// The **governance-threshold-gated change flow** (Requirements 3.4, 3.7, 3.8) is
/// layered on top by [`propose_change`](EvaluationMechanismSlot::propose_change) /
/// [`propose_change_from_parts`](EvaluationMechanismSlot::propose_change_from_parts):
/// a change is applied only when the caller-supplied [`GovernanceDecision`] reports
/// the chain's governance threshold was reached, and a successful change yields a
/// [`MechanismChangeReceipt`] flagging that the effective change must be anchored to
/// L1 (the actual anchoring is task 18.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvaluationMechanismSlot {
    current: Option<EvaluationMechanism>,
}

impl EvaluationMechanismSlot {
    /// Creates an empty slot (no custom mechanism defined; inherits per Requirement 3.2).
    pub const fn empty() -> Self {
        Self { current: None }
    }

    /// Creates a slot pre-populated with an already-validated mechanism.
    pub fn with_config(config: EvaluationMechanism) -> Self {
        Self {
            current: Some(config),
        }
    }

    /// Returns the currently stored mechanism, if this chain defines one.
    pub fn current(&self) -> Option<&EvaluationMechanism> {
        self.current.as_ref()
    }

    /// Returns `true` if this chain defines its own mechanism (i.e. does not inherit).
    pub fn is_defined(&self) -> bool {
        self.current.is_some()
    }

    /// Validates the proposed config and, **only on success**, replaces the stored one.
    ///
    /// On failure the previous valid config is preserved unchanged (Requirement 3.6).
    ///
    /// # Errors
    /// Returns [`GmcError::MechanismConfigInvalid`] when the proposed config is invalid;
    /// the stored config is left untouched.
    pub fn try_set(
        &mut self,
        acquisition_modes: impl IntoIterator<Item = AcquisitionMode>,
        consensus_threshold: Ratio,
        exclude_high_intimacy: bool,
    ) -> GmcResult<()> {
        // Build-and-validate first; `?` returns before any mutation on invalid input,
        // so a rejected update cannot disturb the previously stored valid config.
        let next = EvaluationMechanism::new(
            acquisition_modes,
            consensus_threshold,
            exclude_high_intimacy,
        )?;
        self.current = Some(next);
        Ok(())
    }

    /// Replaces the stored config with an already-validated mechanism.
    ///
    /// Provided for callers (e.g. the future task 5.2 governance flow) that have already
    /// constructed a valid [`EvaluationMechanism`].
    pub fn set_config(&mut self, config: EvaluationMechanism) {
        self.current = Some(config);
    }

    /// Governance-gated change to this chain's evaluation mechanism
    /// (Requirements 3.4, 3.7, 3.8).
    ///
    /// The change is applied — replacing the stored config — **only when both** of the
    /// following hold:
    ///
    /// 1. `new_config` is itself a valid [`EvaluationMechanism`] (it always is, by
    ///    construction — an invalid proposal can never be built; see
    ///    [`propose_change_from_parts`](Self::propose_change_from_parts) for the entry
    ///    point that validates raw inputs), and
    /// 2. `decision` reports the chain's governance threshold was reached
    ///    ([`GovernanceDecision::ThresholdReached`], Requirement 3.4).
    ///
    /// On success the stored config becomes `new_config` and a
    /// [`MechanismChangeReceipt`] is returned flagging that the effective change must
    /// be anchored to L1 (Requirement 3.8; the actual anchoring is task 18.1).
    ///
    /// # Errors
    ///
    /// Returns [`GmcError::GovernanceThresholdNotMet`] when `decision` is
    /// [`GovernanceDecision::ThresholdNotReached`]; the previously stored config is
    /// left **unchanged** (Requirement 3.7). Because the proposal is already a built
    /// [`EvaluationMechanism`], this method cannot fail with
    /// [`GmcError::MechanismConfigInvalid`] — validate raw input through
    /// [`propose_change_from_parts`](Self::propose_change_from_parts) instead.
    pub fn propose_change(
        &mut self,
        new_config: EvaluationMechanism,
        decision: GovernanceDecision,
    ) -> GmcResult<MechanismChangeReceipt> {
        // Requirement 3.7: a change that did not reach the governance threshold is
        // rejected before any mutation, so the existing config is preserved intact.
        if !decision.threshold_reached() {
            return Err(GmcError::GovernanceThresholdNotMet);
        }

        // Requirement 3.4: threshold reached -> the change takes effect.
        self.current = Some(new_config.clone());
        Ok(MechanismChangeReceipt::for_applied(new_config))
    }

    /// Governance-gated change from raw, un-validated parts
    /// (Requirements 3.3/3.6 validation + 3.4/3.7/3.8 gating).
    ///
    /// This is the entry point to use when the proposed config comes from un-trusted
    /// input. It enforces the change in a **validate-then-gate-then-replace** order so
    /// that a rejected change never disturbs the previously stored valid config
    /// (Requirement 3.6 / 3.7):
    ///
    /// 1. build-and-validate the proposal as an [`EvaluationMechanism`] (≥1 acquisition
    ///    mode, threshold in `(0, 1]`); an invalid proposal returns
    ///    [`GmcError::MechanismConfigInvalid`] and mutates nothing, then
    /// 2. apply the governance gate via [`propose_change`](Self::propose_change): a
    ///    below-threshold `decision` returns [`GmcError::GovernanceThresholdNotMet`]
    ///    and still mutates nothing.
    ///
    /// On success the config is replaced and a [`MechanismChangeReceipt`] is returned
    /// (see [`propose_change`](Self::propose_change)).
    ///
    /// # Errors
    ///
    /// - [`GmcError::MechanismConfigInvalid`] if the proposed config is invalid;
    /// - [`GmcError::GovernanceThresholdNotMet`] if the governance threshold was not
    ///   reached.
    ///
    /// In both cases the stored config is left unchanged.
    pub fn propose_change_from_parts(
        &mut self,
        acquisition_modes: impl IntoIterator<Item = AcquisitionMode>,
        consensus_threshold: Ratio,
        exclude_high_intimacy: bool,
        decision: GovernanceDecision,
    ) -> GmcResult<MechanismChangeReceipt> {
        // Step 1: validate the proposal first. `?` returns before any mutation on an
        // invalid config, so an invalid proposal cannot disturb the stored config.
        let next = EvaluationMechanism::new(
            acquisition_modes,
            consensus_threshold,
            exclude_high_intimacy,
        )?;
        // Step 2: apply the governance gate (which itself mutates only on success).
        self.propose_change(next, decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Decimal;

    fn ratio(s: &str) -> Ratio {
        Ratio::new(Decimal::from_str(s).expect("valid decimal")).expect("valid ratio")
    }

    // --- Construction: accept valid configs --------------------------------

    #[test]
    fn accepts_single_mode_and_in_range_threshold() {
        let mech =
            EvaluationMechanism::new([AcquisitionMode::ObjectiveMetering], ratio("0.66"), true)
                .expect("valid config should be accepted");
        assert_eq!(mech.acquisition_mode_count(), 1);
        assert!(mech.has_acquisition_mode(AcquisitionMode::ObjectiveMetering));
        assert!(!mech.has_acquisition_mode(AcquisitionMode::BountyTask));
        assert_eq!(mech.consensus_threshold(), ratio("0.66"));
    }

    #[test]
    fn accepts_combination_of_modes() {
        let mech = EvaluationMechanism::new(
            [
                AcquisitionMode::ObjectiveMetering,
                AcquisitionMode::BountyTask,
            ],
            ratio("0.5"),
            true,
        )
        .expect("two-mode config should be accepted");
        assert_eq!(mech.acquisition_mode_count(), 2);
        assert_eq!(
            mech.acquisition_modes().collect::<Vec<_>>(),
            vec![
                AcquisitionMode::ObjectiveMetering,
                AcquisitionMode::BountyTask
            ]
        );
    }

    #[test]
    fn duplicate_modes_are_deduplicated_but_still_valid() {
        let mech = EvaluationMechanism::new(
            [
                AcquisitionMode::BountyTask,
                AcquisitionMode::BountyTask,
                AcquisitionMode::BountyTask,
            ],
            ratio("0.75"),
            true,
        )
        .expect("config with duplicate modes should still be accepted");
        assert_eq!(mech.acquisition_mode_count(), 1);
        assert!(mech.has_acquisition_mode(AcquisitionMode::BountyTask));
    }

    // --- Threshold boundary behaviour (0, 1] -------------------------------

    #[test]
    fn accepts_threshold_at_upper_bound_one() {
        // 1.0 is the inclusive upper bound of (0, 1].
        let mech = EvaluationMechanism::new([AcquisitionMode::BountyTask], Ratio::ONE, true)
            .expect("threshold == 1 is the inclusive upper bound and must be accepted");
        assert_eq!(mech.consensus_threshold(), Ratio::ONE);
    }

    #[test]
    fn rejects_threshold_zero() {
        // 0 is excluded by the open lower bound of (0, 1].
        let err = EvaluationMechanism::new([AcquisitionMode::BountyTask], Ratio::ZERO, true)
            .expect_err("threshold == 0 must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
    }

    #[test]
    fn rejects_threshold_above_one_via_decimal_constructor() {
        // > 1 is unrepresentable as a Ratio, so exercise the decimal entry point which
        // performs the [0, 1] range check itself.
        let err = EvaluationMechanism::from_threshold_decimal(
            [AcquisitionMode::ObjectiveMetering],
            Decimal::from_str("1.5").unwrap(),
            true,
        )
        .expect_err("threshold > 1 must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
    }

    #[test]
    fn decimal_constructor_rejects_zero_threshold() {
        let err = EvaluationMechanism::from_threshold_decimal(
            [AcquisitionMode::ObjectiveMetering],
            Decimal::ZERO,
            true,
        )
        .expect_err("threshold == 0 via decimal must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
    }

    #[test]
    fn decimal_constructor_accepts_in_range_threshold() {
        let mech = EvaluationMechanism::from_threshold_decimal(
            [AcquisitionMode::ObjectiveMetering],
            Decimal::from_str("0.8").unwrap(),
            true,
        )
        .expect("in-range decimal threshold should be accepted");
        assert_eq!(mech.consensus_threshold(), ratio("0.8"));
    }

    // --- Missing acquisition mode ------------------------------------------

    #[test]
    fn rejects_empty_acquisition_modes() {
        let err = EvaluationMechanism::new(std::iter::empty(), ratio("0.66"), true)
            .expect_err("no acquisition mode declared must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
    }

    #[test]
    fn rejects_empty_modes_even_with_valid_threshold_via_decimal() {
        let err = EvaluationMechanism::from_threshold_decimal(
            std::iter::empty(),
            Decimal::from_str("0.7").unwrap(),
            true,
        )
        .expect_err("no acquisition mode declared must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
    }

    // --- High-intimacy exclusion default (Requirement 3.5) -----------------

    #[test]
    fn exclude_high_intimacy_defaults_to_true() {
        assert!(DEFAULT_EXCLUDE_HIGH_INTIMACY);
        let mech = EvaluationMechanism::with_default_exclusion(
            [AcquisitionMode::ObjectiveMetering],
            ratio("0.66"),
        )
        .expect("valid config");
        assert!(mech.exclude_high_intimacy());
    }

    #[test]
    fn exclude_high_intimacy_is_configurable() {
        let mech =
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.66"), false).unwrap();
        assert!(!mech.exclude_high_intimacy());
    }

    // --- Slot: independent storage + preserve-on-reject (Reqs 3.1, 3.6) ----

    #[test]
    fn empty_slot_is_undefined() {
        let slot = EvaluationMechanismSlot::empty();
        assert!(!slot.is_defined());
        assert!(slot.current().is_none());
    }

    #[test]
    fn slot_try_set_accepts_valid_config() {
        let mut slot = EvaluationMechanismSlot::empty();
        slot.try_set([AcquisitionMode::ObjectiveMetering], ratio("0.66"), true)
            .expect("valid config should be stored");
        assert!(slot.is_defined());
        assert_eq!(slot.current().unwrap().consensus_threshold(), ratio("0.66"));
    }

    #[test]
    fn slot_failed_update_preserves_previous_valid_config() {
        // Requirement 3.6: a rejected config must leave the prior valid config intact.
        let mut slot = EvaluationMechanismSlot::with_config(
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.7"), true).unwrap(),
        );

        // Attempt an invalid update (threshold == 0).
        let err = slot
            .try_set([AcquisitionMode::ObjectiveMetering], Ratio::ZERO, true)
            .expect_err("invalid update must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);

        // Previous valid config is unchanged.
        let current = slot.current().expect("previous config preserved");
        assert_eq!(current.consensus_threshold(), ratio("0.7"));
        assert!(current.has_acquisition_mode(AcquisitionMode::BountyTask));
        assert_eq!(current.acquisition_mode_count(), 1);
    }

    #[test]
    fn slot_failed_first_set_leaves_slot_undefined() {
        let mut slot = EvaluationMechanismSlot::empty();
        let err = slot
            .try_set(std::iter::empty(), ratio("0.66"), true)
            .expect_err("invalid first config must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
        assert!(!slot.is_defined());
        assert!(slot.current().is_none());
    }

    #[test]
    fn slot_successful_update_replaces_config() {
        let mut slot = EvaluationMechanismSlot::with_config(
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.7"), true).unwrap(),
        );
        slot.try_set(
            [
                AcquisitionMode::ObjectiveMetering,
                AcquisitionMode::BountyTask,
            ],
            ratio("0.9"),
            false,
        )
        .expect("valid update should replace the stored config");
        let current = slot.current().unwrap();
        assert_eq!(current.consensus_threshold(), ratio("0.9"));
        assert_eq!(current.acquisition_mode_count(), 2);
        assert!(!current.exclude_high_intimacy());
    }

    // --- Governance-gated change flow (Requirements 3.4, 3.7, 3.8) ----------

    #[test]
    fn governance_decision_from_passed_maps_both_ways() {
        assert_eq!(
            GovernanceDecision::from_passed(true),
            GovernanceDecision::ThresholdReached
        );
        assert_eq!(
            GovernanceDecision::from_passed(false),
            GovernanceDecision::ThresholdNotReached
        );
        assert!(GovernanceDecision::ThresholdReached.threshold_reached());
        assert!(!GovernanceDecision::ThresholdNotReached.threshold_reached());
    }

    #[test]
    fn propose_change_applies_when_threshold_reached() {
        // Requirement 3.4: a change that reached the governance threshold takes effect.
        let mut slot = EvaluationMechanismSlot::with_config(
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.7"), true).unwrap(),
        );
        let proposal = EvaluationMechanism::new(
            [
                AcquisitionMode::ObjectiveMetering,
                AcquisitionMode::BountyTask,
            ],
            ratio("0.85"),
            false,
        )
        .unwrap();

        let receipt = slot
            .propose_change(proposal.clone(), GovernanceDecision::ThresholdReached)
            .expect("threshold-reached change must be applied");

        // The stored config now reflects the change.
        let current = slot.current().expect("config still defined");
        assert_eq!(current, &proposal);
        assert_eq!(current.consensus_threshold(), ratio("0.85"));
        assert_eq!(current.acquisition_mode_count(), 2);
        assert!(!current.exclude_high_intimacy());

        // Requirement 3.8: the effective change is flagged for L1 anchoring, carrying
        // exactly what took effect.
        assert!(receipt.anchor_required());
        assert_eq!(receipt.applied(), &proposal);
    }

    #[test]
    fn propose_change_rejected_below_threshold_preserves_existing_config() {
        // Requirement 3.7: a change that did not reach the threshold is rejected and
        // the existing config is preserved unchanged.
        let original =
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.7"), true).unwrap();
        let mut slot = EvaluationMechanismSlot::with_config(original.clone());

        let proposal =
            EvaluationMechanism::new([AcquisitionMode::ObjectiveMetering], ratio("0.95"), false)
                .unwrap();

        let err = slot
            .propose_change(proposal, GovernanceDecision::ThresholdNotReached)
            .expect_err("below-threshold change must be rejected");
        assert_eq!(err, GmcError::GovernanceThresholdNotMet);

        // The previously stored config is completely unchanged.
        assert_eq!(slot.current(), Some(&original));
    }

    #[test]
    fn propose_change_from_parts_applies_valid_change_when_threshold_reached() {
        let mut slot = EvaluationMechanismSlot::empty();
        let receipt = slot
            .propose_change_from_parts(
                [AcquisitionMode::ObjectiveMetering],
                ratio("0.8"),
                true,
                GovernanceDecision::ThresholdReached,
            )
            .expect("valid + threshold-reached change must be applied");

        let current = slot.current().expect("config now defined");
        assert_eq!(current.consensus_threshold(), ratio("0.8"));
        assert!(current.has_acquisition_mode(AcquisitionMode::ObjectiveMetering));
        assert!(current.exclude_high_intimacy());
        assert!(receipt.anchor_required());
        assert_eq!(receipt.applied().consensus_threshold(), ratio("0.8"));
    }

    #[test]
    fn propose_change_from_parts_rejects_invalid_proposal_without_applying() {
        // An invalid proposal (no acquisition mode) is rejected with
        // MechanismConfigInvalid and the prior config is preserved — even when the
        // governance decision would otherwise allow the change.
        let original =
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.7"), true).unwrap();
        let mut slot = EvaluationMechanismSlot::with_config(original.clone());

        let err = slot
            .propose_change_from_parts(
                std::iter::empty(),
                ratio("0.9"),
                true,
                GovernanceDecision::ThresholdReached,
            )
            .expect_err("invalid proposal must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
        assert_eq!(slot.current(), Some(&original));

        // A zero threshold is likewise invalid and must not apply.
        let err = slot
            .propose_change_from_parts(
                [AcquisitionMode::ObjectiveMetering],
                Ratio::ZERO,
                true,
                GovernanceDecision::ThresholdReached,
            )
            .expect_err("zero-threshold proposal must be rejected");
        assert_eq!(err, GmcError::MechanismConfigInvalid);
        assert_eq!(slot.current(), Some(&original));
    }

    #[test]
    fn propose_change_from_parts_below_threshold_preserves_config_even_if_valid() {
        // The proposal is valid, but governance did not pass: reject with
        // GovernanceThresholdNotMet and preserve the prior config (Requirement 3.7).
        let original =
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.7"), true).unwrap();
        let mut slot = EvaluationMechanismSlot::with_config(original.clone());

        let err = slot
            .propose_change_from_parts(
                [AcquisitionMode::ObjectiveMetering],
                ratio("0.9"),
                false,
                GovernanceDecision::ThresholdNotReached,
            )
            .expect_err("below-threshold change must be rejected");
        assert_eq!(err, GmcError::GovernanceThresholdNotMet);
        assert_eq!(slot.current(), Some(&original));
    }

    #[test]
    fn propose_change_below_threshold_on_empty_slot_leaves_it_undefined() {
        // A first-time change that does not reach the threshold must not define the
        // slot (nothing to preserve, but still no mutation).
        let mut slot = EvaluationMechanismSlot::empty();
        let proposal =
            EvaluationMechanism::new([AcquisitionMode::BountyTask], ratio("0.6"), true).unwrap();

        let err = slot
            .propose_change(proposal, GovernanceDecision::ThresholdNotReached)
            .expect_err("below-threshold change must be rejected");
        assert_eq!(err, GmcError::GovernanceThresholdNotMet);
        assert!(!slot.is_defined());
        assert!(slot.current().is_none());
    }
}
