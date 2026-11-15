//! Blueprint Chapter 7 social relationship graph, deterministic decaying intimacy,
//! and Chapter 10.2–10.6 intimacy-tiered inheritance (`OQ-P2-GMC-6`, `OQ-P2-GMC-8`).
//!
//! All calculations in this module use `gmc-core`'s pure `i128` fixed-point
//! [`Decimal`] / [`Ratio`] (`SCALE = 1_000_000`) and [`crate::merit::exp_neg`].
//! Floating-point types (`f32`, `f64`) are forbidden so every node computes
//! bit-identical intimacy and inheritance outcomes across architectures.
//!
//! ## Core Guarantees
//!
//! 1. **Canonical Symmetry**: Endpoints `(a, b)` are normalized to `(min(a, b), max(a, b))`
//!    so `intimacy(A, B) == intimacy(B, A)` by construction.
//! 2. **Mandatory Pre-Event Registration (§7.3, §10.3)**: Any voter-exclusion or
//!    inheritance lookup requires bilateral confirmation and `registered_at <= event_at`;
//!    retroactive backdating is rejected with [`GmcError::RetroactiveRelationshipDisallowed`].
//! 3. **Bilateral-Only Interaction Accounting & Anti-Farming (§7.2, §11.3)**:
//!    Unilateral interactions (`A -> B` without reciprocal `B -> A`) yield **zero**
//!    intimacy gain. Effective bilateral interactions are capped per `24h` window
//!    ([`MAX_BILATERAL_INTERACTIONS_PER_WINDOW`]) with burst anomaly flagging, and
//!    isolated pairs with zero shared co-participation (`co_participation_count == 0`)
//!    receive [`ISOLATED_PAIR_DAMPING`] (`0.60`).
//! 4. **5-Tier Functional Mapping (§7.3, §10.2–10.6)**:
//!    - `should_exclude_voter(intimacy)` triggers strictly above `0.9`
//!      ([`crate::antifraud::INTIMACY_EXCLUSION_THRESHOLD`]).
//!    - `compute_inheritance` rejects `< 0.1` with
//!      [`GmcError::InsufficientIntimacyForInheritance`], applies a continuous,
//!      strictly monotonic `i128` retention curve over `[0.1, 1.0]` (`15%..=90%`) for
//!      personal `iFay` credit, and preserves `100%` (`1.0`) un-discounted continuity
//!      for `coFay` organizational/role succession (§10.6).

use std::collections::BTreeMap;

use crate::antifraud::INTIMACY_EXCLUSION_THRESHOLD;
use crate::error::{GmcError, GmcResult};
use crate::merit::{exp_neg, MeritBatch, MeritPocket};
use crate::types::{ChainId, Decimal, FayID, Ratio, Timestamp};

const fn const_ratio(raw: i128) -> Ratio {
    match Ratio::new(Decimal::from_raw(raw)) {
        Some(r) => r,
        None => panic!("const_ratio out of [0, 1]"),
    }
}

/// Rolling/tumbling anti-farming window length (`24 hours = 86,400 seconds`).
pub const INTERACTION_WINDOW_SECS: u64 = 86_400;

/// Maximum bilateral interactions within one [`INTERACTION_WINDOW_SECS`] window that
/// count toward intimacy (§11.3 anti-farming cap). Excess interactions flag
/// `burst_anomaly_detected` and add zero intimacy.
pub const MAX_BILATERAL_INTERACTIONS_PER_WINDOW: u32 = 10;

/// Damping multiplier (`0.60`) applied to interaction frequency + depth when two
/// identities have zero shared co-participation (`co_participation_count == 0`, §11.3).
pub const ISOLATED_PAIR_DAMPING: Decimal = Decimal::from_raw(600_000);

/// Minimum intimacy (`0.10`) required for natural-person (`iFay`) inheritance (§7.3, §10.3).
pub const MIN_INHERITANCE_INTIMACY: Ratio = const_ratio(100_000);

/// Intimacy threshold (`0.70`) at or above which voluntary voter recusal is recommended (§7.3).
pub const RECUSAL_RECOMMENDATION_THRESHOLD: Ratio = const_ratio(700_000);

/// Four relationship categories defined in Blueprint §7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelationshipType {
    /// Kinship / family bond (`血缘/亲属关系`).
    Kinship,
    /// Legal relationship such as guardianship, marriage, or statutory agency (`法律关系`).
    Legal,
    /// Organic social interaction relationship (`社会互动关系`).
    Social,
    /// Organizational / team affiliation (`组织关系`).
    Organizational,
}

impl RelationshipType {
    /// Base intimacy contribution (`Decimal` in `[0, 1]`) granted by bilateral
    /// on-chain relationship declaration.
    pub const fn declaration_weight(self) -> Decimal {
        match self {
            RelationshipType::Kinship => Decimal::from_raw(350_000),        // 0.35
            RelationshipType::Legal => Decimal::from_raw(300_000),          // 0.30
            RelationshipType::Organizational => Decimal::from_raw(250_000), // 0.25
            RelationshipType::Social => Decimal::from_raw(150_000),         // 0.15
        }
    }

    /// Characteristic inactivity decay duration `τ` in seconds (`y = elapsed / τ`).
    pub const fn decay_tau_secs(self) -> i64 {
        match self {
            RelationshipType::Kinship | RelationshipType::Legal => 365 * 86_400,
            RelationshipType::Social | RelationshipType::Organizational => 180 * 86_400,
        }
    }
}

/// Layered privacy commitment tier defined in Blueprint §7.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrivacyTier {
    /// Relationship existence and summary metrics are public on-chain (`关系存在性公开`).
    ExistencePublic,
    /// Exact intimacy score is protected behind a zero-knowledge commitment (`亲密度分数受保护`).
    ScoreZkCommitted,
    /// Relationship details are stored encrypted off-chain with an on-chain hash anchor (`关系细节完全私有`).
    DetailOffChainAnchored,
}

/// Five functional intimacy intervals defined in Blueprint §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntimacyTier {
    /// `[0.0, 0.1)`: normal voting permitted; personal inheritance forbidden.
    VeryLow,
    /// `[0.1, 0.4)`: normal voting permitted; high-discount personal inheritance (`15%..30%`).
    Low,
    /// `[0.4, 0.7)`: normal voting permitted; medium-discount personal inheritance (`30%..55%`).
    Medium,
    /// `[0.7, 0.9]`: recusal recommended; low-discount personal inheritance (`55%..=75%`).
    High,
    /// `(0.9, 1.0]`: mandatory voter exclusion; minimal-discount personal inheritance (`>75%..=90%`).
    VeryHigh,
}

/// Canonical unordered identity pair `(low, high)` with `low < high`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPair {
    low: FayID,
    high: FayID,
}

impl CanonicalPair {
    /// Normalizes `(a, b)` into canonical `(min(a, b), max(a, b))` order.
    /// Rejects self-loops (`a == b`) with [`GmcError::RelationshipNotConfirmed`].
    pub fn new(a: FayID, b: FayID) -> GmcResult<Self> {
        if a == b {
            return Err(GmcError::RelationshipNotConfirmed);
        }
        if a < b {
            Ok(CanonicalPair { low: a, high: b })
        } else {
            Ok(CanonicalPair { low: b, high: a })
        }
    }

    pub fn low(&self) -> &FayID {
        &self.low
    }

    pub fn high(&self) -> &FayID {
        &self.high
    }

    pub fn contains(&self, id: &FayID) -> bool {
        &self.low == id || &self.high == id
    }
}

/// On-chain social relationship edge and bilateral interaction accumulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipEdge {
    /// Canonical unordered endpoints `(low, high)`.
    pub pair: CanonicalPair,
    /// Declared relationship category.
    pub relationship_type: RelationshipType,
    /// Privacy commitment tier (§7.4).
    pub privacy_tier: PrivacyTier,
    /// On-chain timestamp when bilateral registration completed.
    pub registered_at: Timestamp,
    /// Whether `pair.low` has confirmed this relationship.
    pub confirmed_by_low: bool,
    /// Whether `pair.high` has confirmed this relationship.
    pub confirmed_by_high: bool,
    /// Optional 32-byte zero-knowledge commitment for `ScoreZkCommitted`.
    pub zk_score_commitment: Option<[u8; 32]>,
    /// Optional 32-byte off-chain encrypted detail hash anchor for `DetailOffChainAnchored`.
    pub offchain_detail_anchor: Option<[u8; 32]>,
    /// Unmatched unilateral interaction count initiated by `low -> high`.
    pub pending_from_low: u32,
    /// Accumulated depth (`Decimal`) of unmatched `low -> high` interactions.
    pub pending_depth_low: Decimal,
    /// Unmatched unilateral interaction count initiated by `high -> low`.
    pub pending_from_high: u32,
    /// Accumulated depth (`Decimal`) of unmatched `high -> low` interactions.
    pub pending_depth_high: Decimal,
    /// Total matched bilateral interactions counted within anti-farming caps.
    pub effective_interactions: u64,
    /// Cumulative average-paired depth across `effective_interactions` (`Decimal` sum).
    pub cumulative_depth: Decimal,
    /// Number of shared multi-party governance/ecosystem co-participations (§7.2, §11.3).
    pub co_participation_count: u64,
    /// Timestamp of the most recent counted bilateral interaction.
    pub last_bilateral_interaction_at: Option<Timestamp>,
    /// Start timestamp of the active `24h` anti-farming window.
    pub window_started_at: Timestamp,
    /// Count of matched bilateral interactions in the current `24h` window.
    pub window_bilateral_count: u32,
    /// Auditable flag raised if bilateral interactions exceeded
    /// [`MAX_BILATERAL_INTERACTIONS_PER_WINDOW`] within a single window (§11.3).
    pub burst_anomaly_detected: bool,
}

impl RelationshipEdge {
    /// Creates a bilaterally confirmed on-chain relationship registered at `registered_at`.
    pub fn new_bilateral(
        a: FayID,
        b: FayID,
        relationship_type: RelationshipType,
        privacy_tier: PrivacyTier,
        registered_at: Timestamp,
    ) -> GmcResult<Self> {
        let pair = CanonicalPair::new(a, b)?;
        Ok(RelationshipEdge {
            pair,
            relationship_type,
            privacy_tier,
            registered_at,
            confirmed_by_low: true,
            confirmed_by_high: true,
            zk_score_commitment: None,
            offchain_detail_anchor: None,
            pending_from_low: 0,
            pending_depth_low: Decimal::ZERO,
            pending_from_high: 0,
            pending_depth_high: Decimal::ZERO,
            effective_interactions: 0,
            cumulative_depth: Decimal::ZERO,
            co_participation_count: 0,
            last_bilateral_interaction_at: None,
            window_started_at: registered_at,
            window_bilateral_count: 0,
            burst_anomaly_detected: false,
        })
    }

    /// Creates a unilateral relationship proposal initiated by `initiator` toward `counterparty`.
    /// Until `confirm_by` is called by `counterparty`, the edge is unconfirmed and yields
    /// zero intimacy and cannot be used for inheritance or voter exclusion.
    pub fn new_proposed(
        initiator: FayID,
        counterparty: FayID,
        relationship_type: RelationshipType,
        privacy_tier: PrivacyTier,
        proposed_at: Timestamp,
    ) -> GmcResult<Self> {
        let pair = CanonicalPair::new(initiator.clone(), counterparty)?;
        let confirmed_by_low = pair.low() == &initiator;
        let confirmed_by_high = !confirmed_by_low;
        Ok(RelationshipEdge {
            pair,
            relationship_type,
            privacy_tier,
            registered_at: proposed_at,
            confirmed_by_low,
            confirmed_by_high,
            zk_score_commitment: None,
            offchain_detail_anchor: None,
            pending_from_low: 0,
            pending_depth_low: Decimal::ZERO,
            pending_from_high: 0,
            pending_depth_high: Decimal::ZERO,
            effective_interactions: 0,
            cumulative_depth: Decimal::ZERO,
            co_participation_count: 0,
            last_bilateral_interaction_at: None,
            window_started_at: proposed_at,
            window_bilateral_count: 0,
            burst_anomaly_detected: false,
        })
    }

    /// Completes bilateral confirmation by `confirmer` at `confirmed_at`.
    pub fn confirm_by(&mut self, confirmer: &FayID, confirmed_at: Timestamp) -> GmcResult<()> {
        if confirmer == self.pair.low() {
            if !self.confirmed_by_low && confirmed_at > self.registered_at {
                self.registered_at = confirmed_at;
                self.window_started_at = confirmed_at;
            }
            self.confirmed_by_low = true;
            Ok(())
        } else if confirmer == self.pair.high() {
            if !self.confirmed_by_high && confirmed_at > self.registered_at {
                self.registered_at = confirmed_at;
                self.window_started_at = confirmed_at;
            }
            self.confirmed_by_high = true;
            Ok(())
        } else {
            Err(GmcError::RelationshipNotConfirmed)
        }
    }

    /// Returns `true` iff both endpoints have confirmed the relationship on-chain.
    #[inline]
    pub fn is_bilaterally_confirmed(&self) -> bool {
        self.confirmed_by_low && self.confirmed_by_high
    }

    /// Enforces mandatory pre-event registration (`registered_at <= event_at`, §7.3, §10.3).
    /// Rejects unconfirmed edges with [`GmcError::RelationshipNotConfirmed`] and post-event
    /// edges with [`GmcError::RetroactiveRelationshipDisallowed`].
    pub fn verify_pre_event(&self, event_at: Timestamp) -> GmcResult<()> {
        if !self.is_bilaterally_confirmed() {
            return Err(GmcError::RelationshipNotConfirmed);
        }
        if self.registered_at > event_at {
            return Err(GmcError::RetroactiveRelationshipDisallowed);
        }
        Ok(())
    }

    /// Records a directed interaction from `initiator` to `counterparty` with `depth` in `(0, 1]`.
    ///
    /// - A single-sided interaction is buffered as pending and has **zero** effect on
    ///   `effective_interactions`, `cumulative_depth`, or `compute_intimacy` until the
    ///   counterparty submits a reciprocal interaction (§7.2).
    /// - When a reciprocal interaction completes a bilateral pair, the `24h` window cap
    ///   ([`MAX_BILATERAL_INTERACTIONS_PER_WINDOW`]) is checked; excess bursts set
    ///   `burst_anomaly_detected = true` without inflating intimacy (§11.3).
    ///
    /// Returns `Ok(true)` if a counted bilateral interaction was completed, or `Ok(false)`
    /// if the interaction remained pending or was capped by the anti-farming window.
    pub fn record_interaction(
        &mut self,
        initiator: &FayID,
        counterparty: &FayID,
        depth: Ratio,
        at: Timestamp,
    ) -> GmcResult<bool> {
        self.verify_pre_event(at)?;
        let depth_dec = depth.value();
        if !depth_dec.is_positive() {
            return Err(GmcError::FieldValidation);
        }

        let is_low_to_high = initiator == self.pair.low() && counterparty == self.pair.high();
        let is_high_to_low = initiator == self.pair.high() && counterparty == self.pair.low();
        if !is_low_to_high && !is_high_to_low {
            return Err(GmcError::RelationshipNotConfirmed);
        }

        if is_low_to_high {
            self.pending_from_low = self.pending_from_low.saturating_add(1);
            self.pending_depth_low = self
                .pending_depth_low
                .checked_add(depth_dec)
                .ok_or(GmcError::FieldValidation)?;
        } else {
            self.pending_from_high = self.pending_from_high.saturating_add(1);
            self.pending_depth_high = self
                .pending_depth_high
                .checked_add(depth_dec)
                .ok_or(GmcError::FieldValidation)?;
        }

        // Only when BOTH sides have contributed at least one unmatched interaction do we
        // pair them into a bilateral interaction.
        if self.pending_from_low == 0 || self.pending_from_high == 0 {
            return Ok(false);
        }

        // Consume one pending interaction from each side.
        let unit_low = self
            .pending_depth_low
            .checked_div(Decimal::from_int(self.pending_from_low as i64))
            .unwrap_or(Decimal::ZERO);
        let unit_high = self
            .pending_depth_high
            .checked_div(Decimal::from_int(self.pending_from_high as i64))
            .unwrap_or(Decimal::ZERO);
        self.pending_from_low -= 1;
        self.pending_depth_low = if self.pending_from_low == 0 {
            Decimal::ZERO
        } else {
            self.pending_depth_low
                .checked_sub(unit_low)
                .unwrap_or(Decimal::ZERO)
        };
        self.pending_from_high -= 1;
        self.pending_depth_high = if self.pending_from_high == 0 {
            Decimal::ZERO
        } else {
            self.pending_depth_high
                .checked_sub(unit_high)
                .unwrap_or(Decimal::ZERO)
        };

        // Advance the 24h anti-farming window if `INTERACTION_WINDOW_SECS` has elapsed.
        if at.saturating_elapsed_since(self.window_started_at) >= INTERACTION_WINDOW_SECS {
            self.window_started_at = at;
            self.window_bilateral_count = 0;
        }

        if self.window_bilateral_count >= MAX_BILATERAL_INTERACTIONS_PER_WINDOW {
            self.burst_anomaly_detected = true;
            return Ok(false);
        }

        let paired_depth = unit_low
            .checked_add(unit_high)
            .and_then(|sum| sum.checked_div(Decimal::from_int(2)))
            .unwrap_or(Decimal::ZERO);

        self.window_bilateral_count += 1;
        self.effective_interactions = self.effective_interactions.saturating_add(1);
        self.cumulative_depth = self
            .cumulative_depth
            .checked_add(paired_depth)
            .unwrap_or(self.cumulative_depth);
        let updated_ts = match self.last_bilateral_interaction_at {
            Some(prev) if prev > at => prev,
            _ => at,
        };
        self.last_bilateral_interaction_at = Some(updated_ts);
        Ok(true)
    }

    /// Records shared participation in multi-party activities/governance (`count_delta > 0`).
    pub fn record_co_participation(&mut self, count_delta: u64, at: Timestamp) -> GmcResult<()> {
        self.verify_pre_event(at)?;
        if count_delta == 0 {
            return Err(GmcError::FieldValidation);
        }
        self.co_participation_count = self.co_participation_count.saturating_add(count_delta);
        let updated_ts = match self.last_bilateral_interaction_at {
            Some(prev) if prev > at => prev,
            _ => at,
        };
        self.last_bilateral_interaction_at = Some(updated_ts);
        Ok(())
    }
}

/// Computes deterministic fixed-point intimacy in `[0, 1]` (`Ratio` with `SCALE = 1_000_000`)
/// for `edge` at `now` (§7.2).
///
/// Unconfirmed edges or queries strictly prior to `edge.registered_at` evaluate to `0`.
pub fn compute_intimacy(edge: &RelationshipEdge, now: Timestamp) -> Ratio {
    if !edge.is_bilaterally_confirmed() || now < edge.registered_at {
        return Ratio::ZERO;
    }

    // 1. Bilateral declaration base in [0.15, 0.35].
    let decl_score = edge.relationship_type.declaration_weight();

    // 2. Bilateral interaction frequency in [0, 0.25] (saturates at 50 bilateral interactions).
    let capped_freq = edge.effective_interactions.min(50) as i128;
    let freq_score = Decimal::from_raw(capped_freq * 5_000);

    // 3. Bilateral interaction depth in [0, 0.25], scaled by maturity min(n, 10) / 10.
    let depth_score = if edge.effective_interactions == 0 {
        Decimal::ZERO
    } else {
        let avg_depth = edge
            .cumulative_depth
            .checked_div(Decimal::from_int(
                edge.effective_interactions.min(i64::MAX as u64) as i64,
            ))
            .unwrap_or(Decimal::ZERO)
            .clamp(Decimal::ZERO, Decimal::ONE);
        let maturity_num = edge.effective_interactions.min(10) as i128;
        Decimal::from_raw((avg_depth.raw() * 250_000 * maturity_num) / (Decimal::SCALE * 10))
    };

    // 4. Isolated-pair anti-farming damping (§11.3): if the pair has zero shared
    // co-participation, damp interaction-derived score by `ISOLATED_PAIR_DAMPING` (0.60).
    let raw_interaction = freq_score
        .checked_add(depth_score)
        .unwrap_or(Decimal::from_raw(500_000));
    let damped_interaction = if edge.co_participation_count == 0 {
        raw_interaction
            .checked_mul(ISOLATED_PAIR_DAMPING)
            .unwrap_or(Decimal::ZERO)
    } else {
        raw_interaction
    };

    // 5. Co-participation score in [0, 0.15] (saturates at 15 shared activities).
    let capped_copart = edge.co_participation_count.min(15) as i128;
    let copart_score = Decimal::from_raw(capped_copart * 10_000);

    // Undecayed total clamped to [0, 1.0].
    let undecayed = decl_score
        .checked_add(damped_interaction)
        .and_then(|s| s.checked_add(copart_score))
        .unwrap_or(Decimal::ONE)
        .clamp(Decimal::ZERO, Decimal::ONE);

    // 6. Time decay via `merit::exp_neg(elapsed / tau)`.
    let anchor_ts = edge
        .last_bilateral_interaction_at
        .unwrap_or(edge.registered_at);
    let elapsed_secs = now.saturating_elapsed_since(anchor_ts);
    let elapsed_dec = Decimal::from_int(elapsed_secs.min(i64::MAX as u64) as i64);
    let tau_dec = Decimal::from_int(edge.relationship_type.decay_tau_secs());
    let decay_factor = match elapsed_dec.checked_div(tau_dec) {
        Some(y) => exp_neg(y),
        None => Decimal::ZERO,
    };

    let decayed = undecayed
        .checked_mul(decay_factor)
        .unwrap_or(Decimal::ZERO)
        .clamp(Decimal::ZERO, Decimal::ONE);

    Ratio::new(decayed).unwrap_or(Ratio::ZERO)
}

/// Maps an intimacy score into its Blueprint §7.3 five-tier classification.
pub const fn classify_intimacy_tier(intimacy: Ratio) -> IntimacyTier {
    let raw = intimacy.value().raw();
    if raw < 100_000 {
        IntimacyTier::VeryLow
    } else if raw < 400_000 {
        IntimacyTier::Low
    } else if raw < 700_000 {
        IntimacyTier::Medium
    } else if raw <= 900_000 {
        IntimacyTier::High
    } else {
        IntimacyTier::VeryHigh
    }
}

/// Mandatory voter exclusion predicate (`intimacy > 0.9`, Blueprint §7.3 & §11.1).
///
/// Uses the exact same strict inequality and [`INTIMACY_EXCLUSION_THRESHOLD`] (`900_000`)
/// as [`crate::antifraud::filter_voter_set`]: `0.9` is included, `0.900001` is excluded.
#[inline]
pub fn should_exclude_voter(intimacy: Ratio) -> bool {
    intimacy.value() > INTIMACY_EXCLUSION_THRESHOLD
}

/// Voluntary recusal recommendation predicate (`intimacy >= 0.7`, Blueprint §7.3).
#[inline]
pub fn should_recommend_recusal(intimacy: Ratio) -> bool {
    intimacy >= RECUSAL_RECOMMENDATION_THRESHOLD
}

/// Deterministic inheritance calculation output (`compute_inheritance`, Blueprint §10.2–10.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InheritanceOutcome {
    /// Intimacy tier governing this transfer (`VeryHigh` unused when `is_cofay_role == true`).
    pub tier: IntimacyTier,
    /// Retention multiplier applied (`Ratio::ONE` for `coFay` role continuity; `0.15..=0.90` for `iFay`).
    pub retention_ratio: Ratio,
    /// Retained `curMerit` transferred to the successor (`cur_merit * retention_ratio`).
    pub inherited_cur_merit: Decimal,
    /// Discounted amount extinguished during personal inheritance (`cur_merit - inherited_cur_merit`).
    pub discounted_merit: Decimal,
    /// Proportional lift applied to the successor's `minMerit` floor (`<= inherited_cur_merit`).
    pub min_merit_lift: Decimal,
}

/// Computes the deterministic retention ratio for personal (`iFay`) inheritance over
/// `[0.1, 1.0]` using continuous, strictly monotonic `i128` piecewise-linear interpolation:
///
/// - `[0.1, 0.4)` -> `[0.15, 0.30)`
/// - `[0.4, 0.7)` -> `[0.30, 0.55)`
/// - `[0.7, 0.9]` -> `[0.55, 0.75]`
/// - `(0.9, 1.0]` -> `(0.75, 0.90]`
fn personal_inheritance_retention(intimacy: Ratio) -> GmcResult<Ratio> {
    let raw = intimacy.value().raw();
    if raw < MIN_INHERITANCE_INTIMACY.value().raw() {
        return Err(GmcError::InsufficientIntimacyForInheritance);
    }
    let retention_raw = if raw < 400_000 {
        150_000 + ((raw - 100_000) * 150_000) / 300_000
    } else if raw < 700_000 {
        300_000 + ((raw - 400_000) * 250_000) / 300_000
    } else if raw <= 900_000 {
        550_000 + (raw - 700_000)
    } else {
        750_000 + ((raw - 900_000) * 150_000) / 100_000
    };
    let clamped = Decimal::from_raw(retention_raw.clamp(0, Decimal::SCALE));
    Ok(Ratio::new(clamped).unwrap_or(Ratio::ZERO))
}

/// Computes `MeriToken` inheritance from a source pocket `(cur_merit, min_merit)` given
/// `intimacy` and whether the succession is a `coFay` organizational/role handoff (§10.2–10.6).
///
/// - When `is_cofay_role == true` (§10.6): preserves `100%` (`1.0`) of both `cur_merit`
///   and `min_merit` with zero intimacy discount.
/// - When `is_cofay_role == false` (§10.2–10.5): rejects `intimacy < 0.1` with
///   [`GmcError::InsufficientIntimacyForInheritance`], applies monotonic `i128` retention
///   in `[0.15, 0.90]`, and lifts `minMerit` proportionally while guaranteeing
///   `min_merit_lift <= inherited_cur_merit`.
pub fn compute_inheritance(
    cur_merit: Decimal,
    min_merit: Decimal,
    intimacy: Ratio,
    is_cofay_role: bool,
) -> GmcResult<InheritanceOutcome> {
    if cur_merit.is_negative() || min_merit.is_negative() || cur_merit < min_merit {
        return Err(GmcError::InvalidMintAmount);
    }

    let tier = classify_intimacy_tier(intimacy);
    let retention_ratio = if is_cofay_role {
        Ratio::ONE
    } else {
        personal_inheritance_retention(intimacy)?
    };

    let factor = retention_ratio.value();
    let inherited_cur_merit = cur_merit
        .checked_mul(factor)
        .ok_or(GmcError::InvalidMintAmount)?;
    let discounted_merit = cur_merit
        .checked_sub(inherited_cur_merit)
        .unwrap_or(Decimal::ZERO);
    let raw_floor_lift = min_merit
        .checked_mul(factor)
        .ok_or(GmcError::InvalidMintAmount)?;
    let min_merit_lift = raw_floor_lift.min(inherited_cur_merit);

    Ok(InheritanceOutcome {
        tier,
        retention_ratio,
        inherited_cur_merit,
        discounted_merit,
        min_merit_lift,
    })
}

/// Applies a verified [`InheritanceOutcome`] to `heir_pocket`, minting the inherited batch
/// and lifting `heir_pocket.min_merit` within legal bounds (`curMerit >= minMerit`).
pub fn apply_inheritance_to_pocket(
    heir_pocket: &mut MeritPocket,
    outcome: &InheritanceOutcome,
    batch_id: impl Into<String>,
    source_chain_id: ChainId,
    influence_duration: Decimal,
    now: Timestamp,
) -> GmcResult<()> {
    if !outcome.inherited_cur_merit.is_positive() {
        return Ok(());
    }
    let batch = MeritBatch::with_influence_duration(
        batch_id,
        outcome.inherited_cur_merit,
        outcome.min_merit_lift,
        influence_duration,
        now,
        source_chain_id,
    )
    .ok_or(GmcError::InvalidMintAmount)?;

    let new_min = heir_pocket
        .min_merit
        .checked_add(outcome.min_merit_lift)
        .ok_or(GmcError::InvalidMintAmount)?;
    let cur_after = heir_pocket
        .cur_merit(now)
        .checked_add(outcome.inherited_cur_merit)
        .ok_or(GmcError::InvalidMintAmount)?;

    heir_pocket.add_batch(batch);
    heir_pocket.min_merit = new_min.min(cur_after).max(heir_pocket.min_merit);
    Ok(())
}

/// Deterministic on-chain social relationship graph keyed by [`CanonicalPair`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelationshipGraph {
    edges: BTreeMap<CanonicalPair, RelationshipEdge>,
}

impl RelationshipGraph {
    /// Creates an empty social relationship graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a bilaterally confirmed relationship edge on-chain.
    /// Rejects duplicate registration of an existing pair with [`GmcError::DomainConflict`].
    pub fn register_bilateral(
        &mut self,
        a: FayID,
        b: FayID,
        relationship_type: RelationshipType,
        privacy_tier: PrivacyTier,
        registered_at: Timestamp,
    ) -> GmcResult<CanonicalPair> {
        let edge = RelationshipEdge::new_bilateral(
            a,
            b,
            relationship_type,
            privacy_tier,
            registered_at,
        )?;
        let pair = edge.pair.clone();
        if self.edges.contains_key(&pair) {
            return Err(GmcError::DomainConflict);
        }
        self.edges.insert(pair.clone(), edge);
        Ok(pair)
    }

    /// Inserts or replaces an edge (used by deterministic snapshot restoration).
    pub fn upsert_edge(&mut self, edge: RelationshipEdge) {
        self.edges.insert(edge.pair.clone(), edge);
    }

    /// Looks up the edge between `a` and `b` in either argument order.
    pub fn get_edge(&self, a: &FayID, b: &FayID) -> Option<&RelationshipEdge> {
        let pair = CanonicalPair::new(a.clone(), b.clone()).ok()?;
        self.edges.get(&pair)
    }

    /// Mutable lookup for the edge between `a` and `b` in either argument order.
    pub fn get_edge_mut(&mut self, a: &FayID, b: &FayID) -> Option<&mut RelationshipEdge> {
        let pair = CanonicalPair::new(a.clone(), b.clone()).ok()?;
        self.edges.get_mut(&pair)
    }

    /// Ordered iterator over all registered edges (deterministic `CanonicalPair` order).
    pub fn edges(&self) -> impl Iterator<Item = (&CanonicalPair, &RelationshipEdge)> {
        self.edges.iter()
    }

    /// Number of edges in the graph.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Returns `true` if the graph contains no edges.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Records a directed interaction from `initiator` to `counterparty` on an existing
    /// pre-registered bilateral edge.
    pub fn record_interaction(
        &mut self,
        initiator: &FayID,
        counterparty: &FayID,
        depth: Ratio,
        at: Timestamp,
    ) -> GmcResult<bool> {
        let edge = self
            .get_edge_mut(initiator, counterparty)
            .ok_or(GmcError::NotRegistered)?;
        edge.record_interaction(initiator, counterparty, depth, at)
    }

    /// Evaluates intimacy for a governance or inheritance event occurring at `event_at`,
    /// strictly enforcing pre-event registration (`registered_at <= event_at`).
    pub fn verify_and_compute_intimacy(
        &self,
        a: &FayID,
        b: &FayID,
        event_at: Timestamp,
    ) -> GmcResult<Ratio> {
        let edge = self.get_edge(a, b).ok_or(GmcError::NotRegistered)?;
        edge.verify_pre_event(event_at)?;
        Ok(compute_intimacy(edge, event_at))
    }

    /// Evaluates intimacy between `a` and `b` for voter-exclusion screening at `vote_at`:
    /// returns `Ratio::ZERO` if no edge exists, or enforces pre-event check if registered
    /// before `vote_at` (post-vote registrations yield `Ratio::ZERO` for past votes and
    /// cannot retroactively invalidate prior quorums).
    pub fn voter_intimacy_at(&self, a: &FayID, b: &FayID, vote_at: Timestamp) -> Ratio {
        match self.get_edge(a, b) {
            Some(edge) if edge.verify_pre_event(vote_at).is_ok() => compute_intimacy(edge, vote_at),
            _ => Ratio::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> FayID {
        FayID::new(s)
    }

    fn ratio_raw(raw: i128) -> Ratio {
        Ratio::new(Decimal::from_raw(raw)).unwrap()
    }

    #[test]
    fn canonical_pair_is_symmetric_and_rejects_self_loop() {
        let a = id("ifay:ed25519:aaaa");
        let b = id("ifay:ed25519:bbbb");
        assert_eq!(
            CanonicalPair::new(a.clone(), b.clone()).unwrap(),
            CanonicalPair::new(b.clone(), a.clone()).unwrap()
        );
        assert_eq!(
            CanonicalPair::new(a.clone(), a),
            Err(GmcError::RelationshipNotConfirmed)
        );
    }

    #[test]
    fn retroactive_relationship_registration_is_rejected() {
        let a = id("ifay:ed25519:alice");
        let b = id("ifay:ed25519:bob");
        let edge = RelationshipEdge::new_bilateral(
            a,
            b,
            RelationshipType::Kinship,
            PrivacyTier::ExistencePublic,
            Timestamp::from_secs(2_000),
        )
        .unwrap();

        assert_eq!(
            edge.verify_pre_event(Timestamp::from_secs(1_999)),
            Err(GmcError::RetroactiveRelationshipDisallowed)
        );
        assert_eq!(edge.verify_pre_event(Timestamp::from_secs(2_000)), Ok(()));
    }

    #[test]
    fn unilateral_interactions_have_zero_intimacy_effect_until_reciprocated() {
        let a = id("ifay:ed25519:alice");
        let b = id("ifay:ed25519:bob");
        let mut edge = RelationshipEdge::new_bilateral(
            a.clone(),
            b.clone(),
            RelationshipType::Social,
            PrivacyTier::ExistencePublic,
            Timestamp::from_secs(1_000),
        )
        .unwrap();

        let base = compute_intimacy(&edge, Timestamp::from_secs(1_000));
        assert_eq!(base.value().raw(), 150_000); // 0.15 Social declaration weight

        // 5 unilateral spam messages from Alice -> Bob have ZERO intimacy effect!
        for i in 0..5 {
            let counted = edge
                .record_interaction(&a, &b, Ratio::ONE, Timestamp::from_secs(1_000 + i))
                .unwrap();
            assert!(!counted);
        }
        assert_eq!(edge.effective_interactions, 0);
        assert_eq!(compute_intimacy(&edge, Timestamp::from_secs(1_000)), base);

        // One reciprocal message from Bob -> Alice pairs one bilateral interaction.
        let counted = edge
            .record_interaction(&b, &a, Ratio::ONE, Timestamp::from_secs(1_010))
            .unwrap();
        assert!(counted);
        assert_eq!(edge.effective_interactions, 1);
        assert!(compute_intimacy(&edge, Timestamp::from_secs(1_010)) > base);
    }

    #[test]
    fn burst_window_cap_and_isolated_pair_damping_prevent_farming() {
        let a = id("ifay:ed25519:alice");
        let b = id("ifay:ed25519:bob");
        let mut edge = RelationshipEdge::new_bilateral(
            a.clone(),
            b.clone(),
            RelationshipType::Social,
            PrivacyTier::ScoreZkCommitted,
            Timestamp::from_secs(1_000),
        )
        .unwrap();

        // 15 bilateral pairs inside the same 24h window: first 10 count, next 5 trip burst anomaly.
        for i in 0..15 {
            let ts = Timestamp::from_secs(1_000 + i * 10);
            edge.record_interaction(&a, &b, Ratio::ONE, ts).unwrap();
            let counted = edge.record_interaction(&b, &a, Ratio::ONE, ts).unwrap();
            if i < MAX_BILATERAL_INTERACTIONS_PER_WINDOW as u64 {
                assert!(counted);
            } else {
                assert!(!counted);
            }
        }
        assert_eq!(
            edge.effective_interactions,
            MAX_BILATERAL_INTERACTIONS_PER_WINDOW as u64
        );
        assert!(edge.burst_anomaly_detected);

        // Without co-participation, isolated pair score is damped and stays well below 0.7/0.9.
        let isolated_score = compute_intimacy(&edge, Timestamp::from_secs(1_200));
        assert!(isolated_score.value().raw() <= 450_000);

        // Adding real multi-party co-participation lifts damping and adds co-participation credit.
        edge.record_co_participation(5, Timestamp::from_secs(1_200))
            .unwrap();
        let integrated_score = compute_intimacy(&edge, Timestamp::from_secs(1_200));
        assert!(integrated_score > isolated_score);
    }

    #[test]
    fn intimacy_decays_monotonically_over_inactivity() {
        let a = id("ifay:ed25519:alice");
        let b = id("ifay:ed25519:bob");
        let edge = RelationshipEdge::new_bilateral(
            a,
            b,
            RelationshipType::Kinship,
            PrivacyTier::ExistencePublic,
            Timestamp::from_secs(0),
        )
        .unwrap();

        let s0 = compute_intimacy(&edge, Timestamp::from_secs(0));
        let s_half_year = compute_intimacy(&edge, Timestamp::from_secs(180 * 86_400));
        let s_two_years = compute_intimacy(&edge, Timestamp::from_secs(730 * 86_400));
        assert!(s0 > s_half_year);
        assert!(s_half_year > s_two_years);
    }

    #[test]
    fn voter_exclusion_aligns_with_antifraud_boundary() {
        assert!(!should_exclude_voter(ratio_raw(900_000))); // 0.900000 included
        assert!(should_exclude_voter(ratio_raw(900_001))); // 0.900001 excluded
        assert!(should_recommend_recusal(ratio_raw(700_000)));
        assert!(!should_recommend_recusal(ratio_raw(699_999)));
    }

    #[test]
    fn inheritance_rejects_below_0_1_scales_monotonically_and_preserves_cofay_100_percent() {
        let cur = Decimal::from_int(1_000);
        let floor = Decimal::from_int(200);

        // Personal iFay inheritance < 0.1 rejected.
        assert_eq!(
            compute_inheritance(cur, floor, ratio_raw(99_999), false),
            Err(GmcError::InsufficientIntimacyForInheritance)
        );

        // Personal iFay inheritance across tiers is strictly monotonic and < 100%.
        let low = compute_inheritance(cur, floor, ratio_raw(100_000), false).unwrap();
        let med = compute_inheritance(cur, floor, ratio_raw(500_000), false).unwrap();
        let high = compute_inheritance(cur, floor, ratio_raw(800_000), false).unwrap();
        let vhigh = compute_inheritance(cur, floor, Ratio::ONE, false).unwrap();

        assert!(low.inherited_cur_merit < med.inherited_cur_merit);
        assert!(med.inherited_cur_merit < high.inherited_cur_merit);
        assert!(high.inherited_cur_merit < vhigh.inherited_cur_merit);
        assert_eq!(vhigh.retention_ratio.value().raw(), 900_000); // max 90% for personal credit
        assert!(vhigh.min_merit_lift <= vhigh.inherited_cur_merit);

        // coFay role succession preserves 100% even at intimacy 0!
        let cofay = compute_inheritance(cur, floor, Ratio::ZERO, true).unwrap();
        assert_eq!(cofay.retention_ratio, Ratio::ONE);
        assert_eq!(cofay.inherited_cur_merit, cur);
        assert_eq!(cofay.min_merit_lift, floor);
        assert_eq!(cofay.discounted_merit, Decimal::ZERO);
    }
}
