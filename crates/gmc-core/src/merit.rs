//! MeritPocket / Merit batch model: per-batch exponential decay and the
//! `minMerit` floor value (blueprint chapter 04, _Requirements 8.1, 8.4, 8.5_).
//!
//! This module owns the *data model* and *decay math* of the MeriToken economy:
//!
//! - [`MeritBatch`] — one minting event. It records the acquisition amount `V`
//!   (`> 0`), this batch's contribution `B` to the floor value, the decay
//!   coefficient `lambda` (`λ = k / influenceDuration`), the `influence_duration`
//!   (`> 0`), the on-chain acquisition time and the source chain id
//!   (_Requirement 8.1_).
//! - [`MeritPocket`] — the container bound to a [`FayID`]. It holds the floor value
//!   `min_merit` (initialised to `e ≈ 2.718281`) plus the list of active batches.
//!
//! ## Single-batch decay (_Requirement 8.4_, blueprint 4.4)
//!
//! Each batch decays *independently* per the blueprint formula
//!
//! ```text
//! MeriToken_i(t) = (V_i − B_i) · e^(−λ_i · t) + B_i
//! ```
//!
//! where `t` is the elapsed time (in seconds) since the batch was acquired. The
//! current total is the sum over all active batches:
//!
//! ```text
//! curMerit(t) = Σ_i MeriToken_i(t)
//! ```
//!
//! ## Deterministic `e^(−x)` approximation
//!
//! [`Decimal`] is a fixed-point integer type (`i128` scaled by `10^6`) with no
//! native `exp()`. Because the MeriToken state must reproduce **bit-identically**
//! across the L1 pallet and the L2 rollup, this module computes `e^(−y)` purely
//! with deterministic `i128` arithmetic — no `f64`, no platform math libraries.
//!
//! For `y ≥ 0` we compute the well-conditioned, strictly-increasing forward series
//!
//! ```text
//! e^y = Σ_{k≥0} y^k / k!
//! ```
//!
//! using a numerically stable recurrence `term_k = term_{k−1} · y / k` (this avoids
//! ever materialising a large `y^k` or `k!`), and then return the reciprocal
//! `e^(−y) = 1 / e^y`. Using the *forward* series and reciprocating (rather than the
//! alternating series for `e^(−y)` directly) avoids catastrophic cancellation and,
//! because `e^y` is strictly increasing in `y`, makes `e^(−y)` **non-increasing**
//! in `y` up to fixed-point truncation. Two clamps bound the work and the range:
//!
//! - `y ≤ 0` ⇒ returns `1` (the decay domain is `y = λ·t ≥ 0`; this is the `t = 0`
//!   identity).
//! - `y ≥ 30` ⇒ returns `0`. `e^(−30) ≈ 9.4e−14`, far below the `10^−6` resolution
//!   of [`Decimal`], so the batch has fully decayed to its floor `B_i`. This also
//!   keeps `e^y` well within `i128` range.
//!
//! The series is summed until a term truncates to zero at the fixed-point
//! resolution (guarded by [`MAX_EXP_ITERS`]). Every step uses the crate's checked
//! fixed-point ops, so the result is identical on every platform.
//!
//! ## Monotonicity & lower bound
//!
//! With `e^(−y)` non-increasing in `y` and `y = λ·t` non-decreasing in `t` (for
//! `λ ≥ 0`), each batch's value is non-increasing in `t`. Since `e^(−y) ∈ [0, 1]`
//! for `y ≥ 0`, the value stays within `[B_i, V_i]` and converges to `B_i` as
//! `t → ∞` — the per-batch floor.
//!
//! ## Seam for later tasks
//!
//! This file implements the pocket/batch data model, the decay math, the `curMerit`
//! summation (task 9.1) **and** the `minMerit` floor-update rule
//! `B' = (x + M)·B / M` together with the `curMerit ≥ minMerit` invariant helper
//! (task 9.2). The full `Minting_Service` pipeline — which orders the steps
//! "validate `amount > 0` → check quota → create batch → update `minMerit` →
//! accumulate quota" — is task 9.3 (`src/minting.rs`); it calls
//! [`MeritPocket::update_min_merit`] in that order. The [`E`] constant and the
//! [`MeritBatch::lambda_from_duration`] helper are provided here for those tasks to
//! reuse.

use crate::error::{GmcError, GmcResult};
use crate::types::{ChainId, Decimal, FayID, Timestamp};

/// Euler's number `e ≈ 2.718281`, truncated to [`Decimal`]'s 6 fractional digits.
///
/// This is the initial value of every [`MeritPocket::min_merit`] (_Requirement 8.2_,
/// blueprint 4.5: `minMerit` starts at `e`). The exact constant is
/// `2.718281828…`; truncated to 6 digits it is `2.718281`.
pub const E: Decimal = Decimal::from_raw(2_718_281);

/// The protocol decay constant `k` used to derive a batch's decay coefficient from
/// its influence duration: `λ = k / influenceDuration` (blueprint 4.4).
///
/// With `k = 1`, the influence factor `e^(−λ·t)` equals `e^(−1) ≈ 0.368` after one
/// full influence duration (`t = influenceDuration`). The constant is centralised
/// here so the whole protocol shares one tunable decay calibration.
pub const DECAY_CONSTANT_K: Decimal = Decimal::ONE;

/// Exponent threshold beyond which `e^(−y)` underflows [`Decimal`]'s resolution.
///
/// `e^(−30) ≈ 9.4e−14 < 10^−6`, so for `y ≥ 30` the decay factor is treated as
/// exactly `0` (the batch has reached its floor `B_i`). This also keeps the forward
/// series `e^y` comfortably within `i128`.
const EXP_NEG_ZERO_THRESHOLD: Decimal = Decimal::from_raw(30_000_000); // 30.0

/// Hard cap on the number of `e^y` series terms. The series terminates naturally
/// once a term truncates to zero at the fixed-point resolution; this cap is only a
/// safety guard so the loop is always bounded.
const MAX_EXP_ITERS: i64 = 1_000;

/// Deterministic fixed-point approximation of `e^(−y)` for the decay domain.
///
/// Returns a value in `[0, 1]` for `y ≥ 0`. See the module docs for the algorithm
/// and its determinism guarantees. Pure `i128` arithmetic only.
pub fn exp_neg(y: Decimal) -> Decimal {
    // Domain guard: decay uses y = λ·t ≥ 0. At y = 0 (t = 0) there is no decay.
    if y.raw() <= 0 {
        return Decimal::ONE;
    }
    // Underflow clamp: the batch has fully decayed to its floor.
    if y >= EXP_NEG_ZERO_THRESHOLD {
        return Decimal::ZERO;
    }

    // Forward series e^y = Σ y^k/k! via the stable recurrence term_k = term_{k-1}·y/k.
    let mut term = Decimal::ONE; // k = 0 term
    let mut sum = Decimal::ONE; // running Σ
    let mut k: i64 = 1;
    while k <= MAX_EXP_ITERS {
        let ratio = match y.checked_div(Decimal::from_int(k)) {
            Some(r) => r,
            None => break,
        };
        term = match term.checked_mul(ratio) {
            Some(t) => t,
            None => break,
        };
        if term.is_zero() {
            // Converged at the fixed-point resolution; further terms add nothing.
            break;
        }
        sum = match sum.checked_add(term) {
            Some(s) => s,
            None => break,
        };
        k += 1;
    }

    // e^(−y) = 1 / e^y. A non-positive sum is impossible here (sum ≥ 1), but fall
    // back to 0 defensively rather than panicking.
    Decimal::ONE.checked_div(sum).unwrap_or(Decimal::ZERO)
}

/// A single Merit acquisition batch (_Requirement 8.1_).
///
/// Created once per successful mint. The batch decays independently of every other
/// batch (_Requirement 8.4_) toward its own floor contribution `b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeritBatch {
    /// Stable identifier for this batch.
    pub batch_id: String,
    /// Initial Merit value `V` of this batch — equals the single mint amount and is
    /// expected to be strictly positive (_Requirement 8.1/8.3_).
    pub v: Decimal,
    /// This batch's contribution `B` to the pocket's floor value; the decay lower
    /// bound for this batch.
    pub b: Decimal,
    /// Decay coefficient `λ = k / influenceDuration` (`≥ 0`).
    pub lambda: Decimal,
    /// Influence duration of the contribution (`> 0`) — how long it stays relevant.
    pub influence_duration: Decimal,
    /// On-chain time at which the batch was acquired (_Requirement 8.1_).
    pub acquired_at: Timestamp,
    /// The chain that minted this batch.
    pub source_chain_id: ChainId,
}

impl MeritBatch {
    /// Builds a batch from an explicit decay coefficient `lambda`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        v: Decimal,
        b: Decimal,
        lambda: Decimal,
        influence_duration: Decimal,
        acquired_at: Timestamp,
        source_chain_id: ChainId,
    ) -> Self {
        MeritBatch {
            batch_id: batch_id.into(),
            v,
            b,
            lambda,
            influence_duration,
            acquired_at,
            source_chain_id,
        }
    }

    /// Builds a batch, deriving `lambda = k / influenceDuration` from
    /// [`DECAY_CONSTANT_K`]. Returns `None` if `influence_duration` is not strictly
    /// positive (`λ` would be undefined) — _Requirement 8.1_ requires a positive
    /// influence duration.
    pub fn with_influence_duration(
        batch_id: impl Into<String>,
        v: Decimal,
        b: Decimal,
        influence_duration: Decimal,
        acquired_at: Timestamp,
        source_chain_id: ChainId,
    ) -> Option<Self> {
        if !influence_duration.is_positive() {
            return None;
        }
        let lambda = Self::lambda_from_duration(influence_duration)?;
        Some(Self::new(
            batch_id,
            v,
            b,
            lambda,
            influence_duration,
            acquired_at,
            source_chain_id,
        ))
    }

    /// Computes the decay coefficient `λ = k / influenceDuration` for a positive
    /// influence duration. Returns `None` for a non-positive duration or on overflow.
    pub fn lambda_from_duration(influence_duration: Decimal) -> Option<Decimal> {
        if !influence_duration.is_positive() {
            return None;
        }
        DECAY_CONSTANT_K.checked_div(influence_duration)
    }

    /// Computes the deterministic decay factor `e^(−λ · elapsed)` at `now`.
    fn decay_factor_at(&self, now: Timestamp) -> Decimal {
        let elapsed_secs = now.saturating_elapsed_since(self.acquired_at);
        // Clamp the i64 conversion defensively; such magnitudes are astronomical.
        let elapsed = Decimal::from_int(elapsed_secs.min(i64::MAX as u64) as i64);

        // y = λ · t. On overflow treat the exponent as effectively infinite ⇒ factor 0.
        match self.lambda.checked_mul(elapsed) {
            Some(y) => exp_neg(y),
            None => Decimal::ZERO,
        }
    }

    /// Returns this batch's decayed Merit value at on-chain time `now`:
    ///
    /// ```text
    /// MeriToken_i(t) = (V_i − B_i) · e^(−λ_i · t) + B_i
    /// ```
    ///
    /// where `t = now − acquired_at` (saturating at zero for `now` before
    /// acquisition). The result is non-increasing in `now` and bounded below by
    /// `b`. On any arithmetic overflow (only reachable with unrealistically extreme
    /// inputs) it falls back to the floor `b`, the safe lower bound.
    pub fn merit_at(&self, now: Timestamp) -> Decimal {
        let factor = self.decay_factor_at(now);

        // (V − B) · factor + B, falling back to the floor B on overflow.
        self.v
            .checked_sub(self.b)
            .and_then(|amplitude| amplitude.checked_mul(factor))
            .and_then(|scaled| scaled.checked_add(self.b))
            .unwrap_or(self.b)
    }
}

/// The container of MeriToken for one identity (_Requirement 8.1_).
///
/// Holds the floor value `min_merit` (initialised to `e`) and the list of active
/// decay batches. `curMerit` is derived on demand from the batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeritPocket {
    /// The identity this pocket is bound to.
    pub fay_id: FayID,
    /// Floor value `minMerit`, initialised to `e ≈ 2.718281`. Only ever increases
    /// (outside punishment) via [`MeritPocket::update_min_merit`] (task 9.2).
    pub min_merit: Decimal,
    /// Active Merit batches; each decays independently (_Requirement 8.4_).
    pub batches: Vec<MeritBatch>,
}

impl MeritPocket {
    /// Creates an empty pocket for `fay_id` with `min_merit` initialised to `e`
    /// (_Requirement 8.2_, blueprint 4.5).
    pub fn new(fay_id: FayID) -> Self {
        MeritPocket {
            fay_id,
            min_merit: E,
            batches: Vec::new(),
        }
    }

    /// Appends a Merit batch to the pocket.
    ///
    /// This only records the batch; it does **not** update `min_merit`
    /// (see [`MeritPocket::update_min_merit`]) nor enforce quota (task 9.3).
    pub fn add_batch(&mut self, batch: MeritBatch) {
        self.batches.push(batch);
    }

    /// The current floor value `minMerit`.
    pub fn min_merit(&self) -> Decimal {
        self.min_merit
    }

    /// Computes `curMerit(t) = Σ_i MeriToken_i(t)` over all active batches at
    /// on-chain time `now` (_Requirement 8.4_).
    ///
    /// An empty pocket has `curMerit = 0`; the `curMerit ≥ minMerit` invariant is
    /// established once batches exist and can be checked with
    /// [`MeritPocket::invariant_holds`].
    pub fn cur_merit(&self, now: Timestamp) -> Decimal {
        let mut total = Decimal::ZERO;
        for batch in &self.batches {
            // Saturate defensively; realistic batch sums never overflow i128.
            total = total.checked_add(batch.merit_at(now)).unwrap_or(total);
        }
        total
    }

    /// Updates the floor value `minMerit` for a successful mint per the blueprint
    /// rule (_Requirement 8.2_, blueprint 4.5):
    ///
    /// ```text
    /// B' = (x + M) · B / M
    /// ```
    ///
    /// where
    /// - `B`  = the current `min_merit` (this pocket's floor before the mint),
    /// - `x`  = `mint_amount`, the amount being minted (must be `> 0`),
    /// - `M`  = `cur_merit_before`, the pocket's `curMerit` **at the mint time,
    ///   computed BEFORE the new batch is added**.
    ///
    /// On success the new floor is stored in `self.min_merit` and returned.
    ///
    /// ## Monotonicity (`B' ≥ B`)
    ///
    /// Rewriting, `B' = B · (1 + x / M)`. With `x > 0` and `M ≥ B ≥ 0` the factor
    /// `(1 + x/M) ≥ 1`, so `B' ≥ B` — the floor only ever increases (it never
    /// decreases outside punishment, which is out of scope here). The pre-mint
    /// `curMerit` satisfies `M ≥ B` exactly because the `curMerit ≥ minMerit`
    /// invariant held before this mint (see [`MeritPocket::invariant_holds`]); the
    /// minting pipeline (task 9.3) is responsible for passing the pre-mint
    /// `curMerit` so this precondition holds.
    ///
    /// ## Intended call order (task 9.3)
    ///
    /// The `Minting_Service` pipeline must:
    /// 1. validate `mint_amount > 0`,
    /// 2. check quota,
    /// 3. snapshot `M = pocket.cur_merit(now)` **before** mutating batches,
    /// 4. `pocket.add_batch(new_batch)` (the batch's `V` equals `mint_amount`),
    /// 5. `pocket.update_min_merit(mint_amount, M)`,
    /// 6. accumulate quota consumption.
    ///
    /// Snapshotting `M` before step 4 is essential: `M` is the *pre-mint* `curMerit`,
    /// and the rule's monotonicity proof relies on `M ≥ B`.
    ///
    /// ## Edge cases
    ///
    /// - **Bottom state (`M == B`)**: when the pocket sits exactly on its floor at
    ///   mint time, the rule collapses to `B' = (x + B)·B / B = x + B`, i.e. the
    ///   whole mint settles straight into the floor. This is handled by the general
    ///   formula but is also covered exactly by the `M == 0` branch below when the
    ///   floor itself is zero.
    /// - **`M == 0` (empty / freshly-created-with-zero-floor pocket)**: the general
    ///   formula would divide by zero. A zero pre-mint `curMerit` can only happen
    ///   when there are no decaying batches contributing value, in which case the
    ///   floor is also at its bottom; we define the first mint as *establishing* the
    ///   floor by settling the full amount into it: `B' = x + B`. This is the
    ///   continuous limit of the bottom-state case as `M → B → 0` and keeps the
    ///   "only increases" guarantee while avoiding division by zero. (A standard
    ///   pocket starts with `min_merit = E > 0`, so this branch is reached only when
    ///   a caller deliberately starts from a zero floor.)
    ///
    /// ## Errors
    ///
    /// Returns [`GmcError::InvalidMintAmount`] if `mint_amount <= 0` (the floor must
    /// never be updated for a non-positive mint — _Requirement 8.7_ keeps `minMerit`
    /// unchanged in that case). Returns [`GmcError::InvalidMintAmount`] as well on
    /// the (practically unreachable) arithmetic overflow of the fixed-point ops, so
    /// the floor is never left in a partially-updated state.
    pub fn update_min_merit(
        &mut self,
        mint_amount: Decimal,
        cur_merit_before: Decimal,
    ) -> GmcResult<Decimal> {
        // Requirement 8.7 / 8.2: a non-positive mint must not move the floor.
        if !mint_amount.is_positive() {
            return Err(GmcError::InvalidMintAmount);
        }

        let b = self.min_merit;

        // Edge case: M == 0 (no decaying value at mint time, e.g. a zero-floor
        // bottom state). The general formula divides by zero, so settle the full
        // amount into the floor: B' = x + B. This is the limit of the bottom-state
        // case and preserves monotonicity (B' = B + x ≥ B for x > 0).
        if cur_merit_before.is_zero() {
            let new_floor = b
                .checked_add(mint_amount)
                .ok_or(GmcError::InvalidMintAmount)?;
            self.min_merit = new_floor;
            return Ok(new_floor);
        }

        // General rule: B' = (x + M) · B / M, computed with checked fixed-point ops.
        // Any overflow leaves self.min_merit untouched and surfaces an error, so the
        // update stays atomic.
        let numerator_factor = mint_amount
            .checked_add(cur_merit_before)
            .ok_or(GmcError::InvalidMintAmount)?; // (x + M)
        let new_floor = numerator_factor
            .checked_mul(b)
            .and_then(|scaled| scaled.checked_div(cur_merit_before))
            .ok_or(GmcError::InvalidMintAmount)?; // (x + M) · B / M

        // Defensive monotonicity guard: the floor must never decrease. Given the
        // documented precondition M ≥ B this never triggers, but fixed-point
        // truncation in the divide could in principle shave a unit; clamp to the old
        // floor so `min_merit` is provably non-decreasing regardless.
        let new_floor = if new_floor < b { b } else { new_floor };

        self.min_merit = new_floor;
        Ok(new_floor)
    }

    /// Returns `true` iff the `curMerit ≥ minMerit` invariant holds at on-chain time
    /// `now` (_Requirement 8.5_).
    ///
    /// Each batch decays toward its own floor contribution `B_i`, so as `t → ∞`,
    /// `curMerit → Σ_i B_i`. Because [`MeritPocket::update_min_merit`] keeps
    /// `min_merit ≤ Σ_i B_i` (each mint adds at most its full amount to the floor
    /// while the batch's `B_i` carries that same settled value), the sum of batch
    /// floors dominates `min_merit`, and since every batch value is `≥ B_i` at all
    /// times, `curMerit(t) ≥ Σ_i B_i ≥ min_merit`. This helper lets the minting
    /// pipeline and tests assert the invariant at any concrete time point.
    pub fn invariant_holds(&self, now: Timestamp) -> bool {
        self.cur_merit(now) >= self.min_merit
    }

    /// Computes the active decaying surplus above `minMerit` that may be voluntarily
    /// consumed for priority or voting priority at on-chain time `now`.
    ///
    /// Consumed merit only ever reduces active decaying amplitude above batch floors `b_i`
    /// and never touches `min_merit` (which only decreases via formal community punishment).
    pub fn consumable_merit(&self, now: Timestamp) -> Decimal {
        let cur = self.cur_merit(now);
        let floor = self.min_merit;
        let above_floor = cur
            .checked_sub(floor)
            .unwrap_or(Decimal::ZERO)
            .max(Decimal::ZERO);

        let mut batch_surplus_sum = Decimal::ZERO;
        for batch in &self.batches {
            let s_i = batch
                .merit_at(now)
                .checked_sub(batch.b)
                .unwrap_or(Decimal::ZERO);
            if s_i.is_positive() {
                batch_surplus_sum = batch_surplus_sum
                    .checked_add(s_i)
                    .unwrap_or(batch_surplus_sum);
            }
        }

        above_floor.min(batch_surplus_sum)
    }

    /// Destroys/reduces `amount` of active decaying `MeriToken (μ)` surplus from this pocket
    /// for priority or voting priority consumption at on-chain time `now`.
    ///
    /// - Never transfers `MeriToken` to any other account (non-monetary iron law);
    /// - Preserves every batch's floor `b_i` and keeps `self.min_merit` strictly unchanged;
    /// - Guarantees `v'_i >= b_i` for every batch and `self.cur_merit(now) >= self.min_merit`.
    pub fn consume_priority(&mut self, amount: Decimal, now: Timestamp) -> GmcResult<Decimal> {
        if !amount.is_positive() {
            return Err(GmcError::InvalidMintAmount);
        }

        let before_cur = self.cur_merit(now);
        let consumable = self.consumable_merit(now);
        if amount > consumable {
            return Err(GmcError::InsufficientConsumableMerit);
        }

        // Collect active batches with strictly positive decaying surplus s_i = merit_at(now) - b_i > 0.
        let mut active: Vec<(usize, i128, i128)> = Vec::new();
        let mut batch_surplus_sum_raw: i128 = 0;
        for (idx, batch) in self.batches.iter().enumerate() {
            let s_i = batch
                .merit_at(now)
                .checked_sub(batch.b)
                .unwrap_or(Decimal::ZERO);
            if s_i.is_positive() {
                let old_amp_raw = batch.v.checked_sub(batch.b).unwrap_or(Decimal::ZERO).raw();
                let factor_raw = batch.decay_factor_at(now).raw();
                if old_amp_raw > 0 && factor_raw > 0 {
                    batch_surplus_sum_raw = batch_surplus_sum_raw
                        .checked_add(s_i.raw())
                        .ok_or(GmcError::InvalidMintAmount)?;
                    active.push((idx, old_amp_raw, factor_raw));
                }
            }
        }

        if batch_surplus_sum_raw < amount.raw() || batch_surplus_sum_raw <= 0 {
            return Err(GmcError::InsufficientConsumableMerit);
        }

        let remaining_surplus_raw = batch_surplus_sum_raw - amount.raw();

        // Check no overflow before mutating any batch so failure stays atomic.
        let mut planned_amps: Vec<(usize, i128)> = Vec::with_capacity(active.len());
        for &(idx, old_amp_raw, _) in &active {
            let new_amp_raw = if remaining_surplus_raw == 0 {
                0
            } else {
                old_amp_raw
                    .checked_mul(remaining_surplus_raw)
                    .map(|prod| prod / batch_surplus_sum_raw)
                    .ok_or(GmcError::InvalidMintAmount)?
                    .max(0)
            };
            planned_amps.push((idx, new_amp_raw));
        }

        for (idx, new_amp_raw) in planned_amps {
            let b_val = self.batches[idx].b;
            self.batches[idx].v = b_val
                .checked_add(Decimal::from_raw(new_amp_raw))
                .unwrap_or(b_val)
                .max(b_val);
        }

        // Handle 1-2 ulp fixed-point truncation defensively so `v'_i >= b_i` for every batch,
        // `cur_merit(now)` hits `before_cur - amount` cleanly, and `cur_merit(now) >= min_merit` ALWAYS holds.
        let target_cur = before_cur
            .checked_sub(amount)
            .unwrap_or(self.min_merit)
            .max(self.min_merit);

        if self.cur_merit(now) < target_cur {
            for &(idx, old_amp_raw, factor_raw) in &active {
                let cur_now = self.cur_merit(now);
                if cur_now >= target_cur {
                    break;
                }
                let shortfall_raw = target_cur.raw() - cur_now.raw();
                let b_val = self.batches[idx].b;
                let cur_amp_raw = (self.batches[idx].v.raw() - b_val.raw()).max(0);
                let cur_scaled_raw = (cur_amp_raw * factor_raw) / Decimal::SCALE;
                let max_scaled_raw = (old_amp_raw * factor_raw) / Decimal::SCALE;
                let gain_raw = shortfall_raw.min((max_scaled_raw - cur_scaled_raw).max(0));
                if gain_raw > 0 {
                    let des_s_raw = cur_scaled_raw + gain_raw;
                    let q = ((des_s_raw * Decimal::SCALE + factor_raw - 1) / factor_raw)
                        .clamp(cur_amp_raw, old_amp_raw);
                    self.batches[idx].v = b_val
                        .checked_add(Decimal::from_raw(q))
                        .unwrap_or(b_val)
                        .max(b_val);
                }
            }
        } else if self.cur_merit(now) > target_cur {
            for &(idx, old_amp_raw, factor_raw) in &active {
                let cur_now = self.cur_merit(now);
                if cur_now <= target_cur {
                    break;
                }
                let excess_raw = cur_now.raw() - target_cur.raw();
                let b_val = self.batches[idx].b;
                let cur_amp_raw = (self.batches[idx].v.raw() - b_val.raw()).max(0);
                let cur_scaled_raw = (cur_amp_raw * factor_raw) / Decimal::SCALE;
                let drop_raw = excess_raw.min(cur_scaled_raw);
                if drop_raw > 0 {
                    let des_s_raw = cur_scaled_raw - drop_raw;
                    let q = ((des_s_raw * Decimal::SCALE + factor_raw - 1) / factor_raw)
                        .clamp(0, old_amp_raw);
                    let prev_v = self.batches[idx].v;
                    self.batches[idx].v = b_val
                        .checked_add(Decimal::from_raw(q))
                        .unwrap_or(b_val)
                        .max(b_val);
                    if self.cur_merit(now) < self.min_merit {
                        self.batches[idx].v = prev_v;
                    }
                }
            }
        }

        debug_assert!(self.invariant_holds(now));
        Ok(self.cur_merit(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute-difference tolerance helper for the fixed-point exp approximation.
    fn approx_eq(a: Decimal, b: Decimal, tol: Decimal) -> bool {
        let diff = a.checked_sub(b).expect("no overflow in test diff");
        let abs = if diff.is_negative() {
            Decimal::ZERO.checked_sub(diff).unwrap()
        } else {
            diff
        };
        abs <= tol
    }

    fn ts(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn sample_batch(v: &str, b: &str, lambda: &str, acquired: u64) -> MeritBatch {
        MeritBatch::new(
            "batch",
            Decimal::from_str(v).unwrap(),
            Decimal::from_str(b).unwrap(),
            Decimal::from_str(lambda).unwrap(),
            Decimal::from_int(100),
            ts(acquired),
            ChainId::from("chain-1"),
        )
    }

    // --- exp_neg sanity ----------------------------------------------------

    #[test]
    fn exp_neg_at_zero_is_one() {
        assert_eq!(exp_neg(Decimal::ZERO), Decimal::ONE);
    }

    #[test]
    fn exp_neg_of_one_is_reciprocal_of_e() {
        // e^(-1) ≈ 0.367879
        let expected = Decimal::from_str("0.367879").unwrap();
        assert!(
            approx_eq(
                exp_neg(Decimal::ONE),
                expected,
                Decimal::from_str("0.001").unwrap()
            ),
            "exp_neg(1) = {}",
            exp_neg(Decimal::ONE)
        );
    }

    #[test]
    fn exp_neg_large_underflows_to_zero() {
        assert_eq!(exp_neg(Decimal::from_int(40)), Decimal::ZERO);
        // Just below the threshold the value is still numerically ~0 at 6 digits.
        assert!(exp_neg(Decimal::from_int(25)) <= Decimal::from_str("0.000001").unwrap());
    }

    #[test]
    fn exp_neg_is_non_increasing_in_y() {
        let mut prev = exp_neg(Decimal::ZERO);
        let tol = Decimal::from_str("0.0001").unwrap();
        for raw in 1..=200i128 {
            let y = Decimal::from_raw(raw * 100_000); // 0.1, 0.2, ... 20.0
            let cur = exp_neg(y);
            assert!(
                cur <= prev.checked_add(tol).unwrap(),
                "exp_neg not non-increasing at y={y}: {cur} > {prev}"
            );
            prev = cur;
        }
    }

    // --- min_merit initialisation (Requirement 8.2) ------------------------

    #[test]
    fn min_merit_initializes_to_e() {
        let pocket = MeritPocket::new(FayID::from("fay-1"));
        assert_eq!(pocket.min_merit(), E);
        assert_eq!(pocket.min_merit(), Decimal::from_str("2.718281").unwrap());
        assert!(pocket.batches.is_empty());
    }

    // --- single-batch decay (Requirements 8.1, 8.4) ------------------------

    #[test]
    fn single_batch_at_t0_equals_v() {
        // At t = 0 the decay factor is exactly 1, so MeriToken(0) == V exactly.
        let batch = sample_batch("100", "10", "0.05", 1_000);
        assert_eq!(batch.merit_at(ts(1_000)), Decimal::from_int(100));
    }

    #[test]
    fn merit_before_acquisition_is_v() {
        // now < acquired_at ⇒ elapsed saturates to 0 ⇒ value is V.
        let batch = sample_batch("100", "10", "0.05", 1_000);
        assert_eq!(batch.merit_at(ts(500)), Decimal::from_int(100));
    }

    #[test]
    fn decay_is_non_increasing_in_time() {
        let batch = sample_batch("100", "10", "0.05", 0);
        let tol = Decimal::from_str("0.0001").unwrap();
        let times = [0u64, 1, 5, 10, 30, 60, 120, 300, 600, 1_200, 6_000, 60_000];
        let mut prev = batch.merit_at(ts(times[0]));
        for &t in &times[1..] {
            let cur = batch.merit_at(ts(t));
            assert!(
                cur <= prev.checked_add(tol).unwrap(),
                "decay increased at t={t}: {cur} > {prev}"
            );
            prev = cur;
        }
    }

    #[test]
    fn decayed_value_never_below_b() {
        let batch = sample_batch("100", "10", "0.05", 0);
        let b = Decimal::from_int(10);
        for t in [0u64, 10, 100, 1_000, 10_000, 100_000, 1_000_000] {
            let value = batch.merit_at(ts(t));
            assert!(value >= b, "value {value} dropped below floor {b} at t={t}");
            assert!(
                value <= Decimal::from_int(100),
                "value {value} exceeded V at t={t}"
            );
        }
    }

    #[test]
    fn decay_approaches_b_as_time_grows() {
        let batch = sample_batch("100", "10", "0.05", 0);
        // After many influence durations the amplitude term has fully decayed.
        let far = batch.merit_at(ts(10_000_000));
        assert!(
            approx_eq(
                far,
                Decimal::from_int(10),
                Decimal::from_str("0.001").unwrap()
            ),
            "far-future value {far} did not converge to floor B=10"
        );
    }

    #[test]
    fn zero_amplitude_batch_is_constant_b() {
        // V == B ⇒ amplitude 0 ⇒ value is constant B at every t.
        let batch = sample_batch("10", "10", "0.05", 0);
        for t in [0u64, 100, 10_000] {
            assert_eq!(batch.merit_at(ts(t)), Decimal::from_int(10));
        }
    }

    // --- cur_merit summation (Requirement 8.4) -----------------------------

    #[test]
    fn cur_merit_sums_multiple_batches() {
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        let b1 = sample_batch("100", "10", "0.05", 0);
        let b2 = MeritBatch::new(
            "batch-2",
            Decimal::from_int(50),
            Decimal::from_int(5),
            Decimal::from_str("0.02").unwrap(),
            Decimal::from_int(200),
            ts(0),
            ChainId::from("chain-2"),
        );
        let now = ts(120);
        let expected = b1.merit_at(now).checked_add(b2.merit_at(now)).unwrap();
        pocket.add_batch(b1);
        pocket.add_batch(b2);
        assert_eq!(pocket.cur_merit(now), expected);
    }

    #[test]
    fn cur_merit_empty_pocket_is_zero() {
        let pocket = MeritPocket::new(FayID::from("fay-1"));
        assert_eq!(pocket.cur_merit(ts(1_000)), Decimal::ZERO);
    }

    #[test]
    fn cur_merit_at_t0_sums_to_total_v() {
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        pocket.add_batch(sample_batch("100", "10", "0.05", 0));
        pocket.add_batch(sample_batch("40", "4", "0.10", 0));
        // At t = 0 every batch equals its V, so curMerit == ΣV = 140.
        assert_eq!(pocket.cur_merit(ts(0)), Decimal::from_int(140));
    }

    // --- lambda helper -----------------------------------------------------

    #[test]
    fn lambda_from_duration_divides_k() {
        // λ = k / T with k = 1 ⇒ λ = 1/100 = 0.01.
        let lambda = MeritBatch::lambda_from_duration(Decimal::from_int(100)).unwrap();
        assert_eq!(lambda, Decimal::from_str("0.01").unwrap());
        assert_eq!(MeritBatch::lambda_from_duration(Decimal::ZERO), None);
        assert_eq!(
            MeritBatch::lambda_from_duration(Decimal::from_int(-5)),
            None
        );
    }

    #[test]
    fn with_influence_duration_rejects_non_positive() {
        assert!(MeritBatch::with_influence_duration(
            "b",
            Decimal::from_int(100),
            Decimal::from_int(10),
            Decimal::ZERO,
            ts(0),
            ChainId::from("c"),
        )
        .is_none());

        let batch = MeritBatch::with_influence_duration(
            "b",
            Decimal::from_int(100),
            Decimal::from_int(10),
            Decimal::from_int(50),
            ts(0),
            ChainId::from("c"),
        )
        .unwrap();
        // λ = 1/50 = 0.02
        assert_eq!(batch.lambda, Decimal::from_str("0.02").unwrap());
    }

    // --- minMerit floor update (Requirement 8.2, blueprint 4.5) ------------

    #[test]
    fn update_min_merit_rejects_non_positive_amount() {
        // Requirement 8.7 / 8.2: a non-positive mint must leave minMerit untouched.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        let before = pocket.min_merit();
        assert_eq!(
            pocket.update_min_merit(Decimal::ZERO, Decimal::from_int(10)),
            Err(GmcError::InvalidMintAmount)
        );
        assert_eq!(
            pocket.update_min_merit(Decimal::from_int(-5), Decimal::from_int(10)),
            Err(GmcError::InvalidMintAmount)
        );
        // Floor unchanged after both rejected updates.
        assert_eq!(pocket.min_merit(), before);
    }

    #[test]
    fn update_min_merit_m_zero_establishes_floor_as_b_plus_x() {
        // M == 0 edge case (empty pocket / zero pre-mint curMerit): B' = x + B.
        // A fresh pocket has min_merit = E and no batches ⇒ cur_merit(now) == 0.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        let x = Decimal::from_int(10);
        let new_floor = pocket.update_min_merit(x, Decimal::ZERO).unwrap();
        // B' = E + 10
        assert_eq!(new_floor, E.checked_add(x).unwrap());
        assert_eq!(pocket.min_merit(), new_floor);
    }

    #[test]
    fn update_min_merit_bottom_state_adds_x() {
        // Bottom state: M == B. The rule collapses to B' = (x + B)·B / B = x + B.
        // Use a clean integer floor so fixed-point division is exact.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        pocket.min_merit = Decimal::from_int(4); // B = 4
        let x = Decimal::from_int(6);
        let new_floor = pocket.update_min_merit(x, Decimal::from_int(4)).unwrap(); // M == B == 4
                                                                                   // B' = 6 + 4 = 10
        assert_eq!(new_floor, Decimal::from_int(10));
        assert_eq!(pocket.min_merit(), Decimal::from_int(10));
    }

    #[test]
    fn update_min_merit_general_rule_matches_formula() {
        // M > B general case: B' = (x + M)·B / M with clean divisors for exactness.
        // B = 5, M = 20, x = 60 ⇒ B' = (80)·5/20 = 400/20 = 20.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        pocket.min_merit = Decimal::from_int(5);
        let new_floor = pocket
            .update_min_merit(Decimal::from_int(60), Decimal::from_int(20))
            .unwrap();
        assert_eq!(new_floor, Decimal::from_int(20));
    }

    #[test]
    fn update_min_merit_is_monotonic_non_decreasing() {
        // For any x > 0 and M >= B, B' >= B (only increases, never decreases).
        for b_raw in [2i64, 5, 100] {
            for m_extra in [0i64, 1, 7, 50] {
                for x in [1i64, 3, 25, 500] {
                    let mut pocket = MeritPocket::new(FayID::from("fay-1"));
                    let b = Decimal::from_int(b_raw);
                    pocket.min_merit = b;
                    let m = Decimal::from_int(b_raw + m_extra); // M >= B
                    let new_floor = pocket.update_min_merit(Decimal::from_int(x), m).unwrap();
                    assert!(
                        new_floor >= b,
                        "B'={new_floor} < B={b} for M={m}, x={x} (must be non-decreasing)"
                    );
                }
            }
        }
    }

    #[test]
    fn min_merit_never_decreases_across_a_sequence_of_mints() {
        // Drive a sequence of mints and assert the floor is non-decreasing at each
        // step. We feed a pre-mint curMerit M >= current floor each time (the
        // documented precondition the minting pipeline guarantees).
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        let mut prev = pocket.min_merit();
        for x in [1i64, 5, 2, 40, 7, 100] {
            // Use M = current floor + a positive slack so M >= B holds.
            let m = pocket
                .min_merit()
                .checked_add(Decimal::from_int(3))
                .unwrap();
            let new_floor = pocket.update_min_merit(Decimal::from_int(x), m).unwrap();
            assert!(
                new_floor >= prev,
                "floor decreased: {new_floor} < {prev} after minting x={x}"
            );
            prev = new_floor;
        }
    }

    // --- curMerit >= minMerit invariant (Requirements 8.1, 8.4, 8.5) -------

    #[test]
    fn invariant_holds_when_batch_floors_cover_min_merit() {
        // Directly construct a pocket whose Σ B_i >= minMerit and verify the
        // invariant at several time points, including the far future where each
        // batch has converged to its own floor B_i.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        pocket.min_merit = Decimal::from_int(20);
        // Σ B_i = 15 + 10 = 25 >= 20.
        pocket.add_batch(sample_batch("100", "15", "0.001", 0));
        pocket.add_batch(sample_batch("50", "10", "0.001", 0));
        for t in [0u64, 100, 1_000, 10_000, 1_000_000, 100_000_000] {
            assert!(
                pocket.invariant_holds(ts(t)),
                "invariant curMerit >= minMerit violated at t={t}: cur={}, min={}",
                pocket.cur_merit(ts(t)),
                pocket.min_merit()
            );
        }
    }

    #[test]
    fn invariant_holds_through_a_simulated_mint_pipeline() {
        // Faithfully simulate the task 9.3 pipeline: snapshot pre-mint curMerit M,
        // update the floor, then add a batch whose floor contribution B_i equals the
        // floor increment. With the floor seeded by a backing batch (B = E), the
        // batch floors telescope to exactly minMerit, so curMerit(t) >= minMerit at
        // every t.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        // Backing batch for the initial floor E: a slowly-decaying batch with
        // B = E so that Σ B_i starts equal to minMerit = E.
        pocket.add_batch(MeritBatch::new(
            "reg-grant",
            Decimal::from_int(100), // V
            E,                      // B = initial floor
            Decimal::from_str("0.001").unwrap(),
            Decimal::from_int(1_000),
            ts(0),
            ChainId::from("chain-1"),
        ));

        // Helper: one mint following the documented call order.
        let mint = |pocket: &mut MeritPocket, id: &str, x: i64, now: u64| {
            let amount = Decimal::from_int(x);
            let m = pocket.cur_merit(ts(now)); // snapshot M BEFORE mutating
            let before = pocket.min_merit();
            let after = pocket.update_min_merit(amount, m).unwrap();
            let increment = after.checked_sub(before).unwrap();
            // B_i = floor increment (<= x because B <= M ⇒ B·x/M <= x).
            pocket.add_batch(MeritBatch::new(
                id,
                amount,
                increment,
                Decimal::from_str("0.001").unwrap(),
                Decimal::from_int(1_000),
                ts(now),
                ChainId::from("chain-1"),
            ));
        };

        mint(&mut pocket, "m1", 50, 100);
        mint(&mut pocket, "m2", 30, 500);
        mint(&mut pocket, "m3", 80, 1_500);

        // Invariant holds at a spread of time points, including the far future.
        for t in [0u64, 100, 500, 1_500, 5_000, 50_000, 1_000_000, 100_000_000] {
            assert!(
                pocket.invariant_holds(ts(t)),
                "invariant violated at t={t}: cur={}, min={}",
                pocket.cur_merit(ts(t)),
                pocket.min_merit()
            );
        }
    }

    #[test]
    fn invariant_far_future_converges_to_sum_of_floors() {
        // As t → ∞ each batch → B_i, so curMerit → Σ B_i; with Σ B_i == minMerit the
        // invariant holds with (near) equality up to the exp approximation.
        let mut pocket = MeritPocket::new(FayID::from("fay-1"));
        pocket.min_merit = Decimal::from_int(12); // Σ B_i below
        pocket.add_batch(sample_batch("100", "8", "0.01", 0));
        pocket.add_batch(sample_batch("40", "4", "0.01", 0)); // Σ B = 12
        let far = pocket.cur_merit(ts(50_000_000));
        assert!(
            approx_eq(
                far,
                Decimal::from_int(12),
                Decimal::from_str("0.001").unwrap()
            ),
            "far-future curMerit {far} did not converge to Σ B_i = 12"
        );
        assert!(pocket.invariant_holds(ts(50_000_000)));
    }

    // --- Priority / voting priority consumption ----------------------------

    #[test]
    fn consumable_merit_empty_and_welcome_pocket() {
        let mut pocket = MeritPocket::new(FayID::from("fay-ext-1"));
        assert_eq!(pocket.consumable_merit(ts(1_000)), Decimal::ZERO);

        // Welcome batch of 5 μ backed by floor E = 2.718281 μ
        pocket.add_batch(MeritBatch::new(
            "welcome",
            Decimal::from_int(5),
            E,
            Decimal::from_str("0.000002").unwrap(),
            Decimal::from_int(500_000),
            ts(1_000),
            ChainId::from("gmc-open-science"),
        ));
        assert_eq!(pocket.cur_merit(ts(1_000)), Decimal::from_int(5));
        assert_eq!(pocket.min_merit(), E);
        assert_eq!(
            pocket.consumable_merit(ts(1_000)),
            Decimal::from_str("2.281719").unwrap()
        );
    }

    #[test]
    fn consume_priority_exact_at_acquired_time_and_preserves_min_merit() {
        let mut pocket = MeritPocket::new(FayID::from("fay-ext-2"));
        let now = ts(10_000);
        pocket.add_batch(MeritBatch::new(
            "b1",
            Decimal::from_int(5),
            E,
            Decimal::from_str("0.000002").unwrap(),
            Decimal::from_int(500_000),
            now,
            ChainId::from("gmc-open-science"),
        ));
        let m_before = pocket.cur_merit(now);
        let floor_before = pocket.min_merit();
        let floor_after_mint = pocket
            .update_min_merit(Decimal::from_int(40), m_before)
            .unwrap();
        let b2_floor = floor_after_mint.checked_sub(floor_before).unwrap();
        pocket.add_batch(MeritBatch::new(
            "b2",
            Decimal::from_int(40),
            b2_floor,
            Decimal::from_str("0.000002").unwrap(),
            Decimal::from_int(500_000),
            now,
            ChainId::from("gmc-open-science"),
        ));

        let before_cur = pocket.cur_merit(now);
        assert_eq!(before_cur, Decimal::from_int(45));
        let preserved_floor = pocket.min_merit();

        let after_cur = pocket
            .consume_priority(Decimal::from_int(12), now)
            .expect("consume 12 mu priority");
        assert_eq!(after_cur, Decimal::from_int(33));
        assert_eq!(pocket.cur_merit(now), Decimal::from_int(33));
        assert_eq!(pocket.min_merit(), preserved_floor);
        assert_eq!(pocket.batches[0].b, E);
        assert_eq!(pocket.batches[1].b, b2_floor);
        assert!(pocket.invariant_holds(now));
    }

    #[test]
    fn consume_priority_rejects_invalid_and_excess_without_mutation() {
        let mut pocket = MeritPocket::new(FayID::from("fay-ext-3"));
        let now = ts(5_000);
        pocket.add_batch(MeritBatch::new(
            "b1",
            Decimal::from_int(10),
            E,
            Decimal::from_str("0.001").unwrap(),
            Decimal::from_int(1_000),
            now,
            ChainId::from("chain-1"),
        ));
        let snapshot = pocket.clone();

        assert_eq!(
            pocket.consume_priority(Decimal::ZERO, now),
            Err(GmcError::InvalidMintAmount)
        );
        assert_eq!(
            pocket.consume_priority(Decimal::from_int(-3), now),
            Err(GmcError::InvalidMintAmount)
        );
        // Consumable is 10 - 2.718281 = 7.281719; requesting 8 must fail atomically.
        assert_eq!(
            pocket.consume_priority(Decimal::from_int(8), now),
            Err(GmcError::InsufficientConsumableMerit)
        );
        assert_eq!(pocket, snapshot);
    }

    #[test]
    fn consume_priority_across_decayed_batches_and_subsequent_monotonic_decay() {
        let mut pocket = MeritPocket::new(FayID::from("fay-ext-4"));
        pocket.min_merit = Decimal::from_int(15);
        pocket.add_batch(MeritBatch::new(
            "b1",
            Decimal::from_int(80),
            Decimal::from_int(10),
            Decimal::from_str("0.002").unwrap(),
            Decimal::from_int(500),
            ts(0),
            ChainId::from("chain-1"),
        ));
        pocket.add_batch(MeritBatch::new(
            "b2",
            Decimal::from_int(45),
            Decimal::from_int(5),
            Decimal::from_str("0.001").unwrap(),
            Decimal::from_int(1_000),
            ts(100),
            ChainId::from("chain-2"),
        ));

        let now = ts(400);
        let before_cur = pocket.cur_merit(now);
        let floor_before = pocket.min_merit();
        let consume_amt = Decimal::from_str("17.35").unwrap();
        assert!(consume_amt <= pocket.consumable_merit(now));

        let after_cur = pocket.consume_priority(consume_amt, now).unwrap();
        let expected_cur = before_cur.checked_sub(consume_amt).unwrap();
        let raw_diff = (after_cur.raw() - expected_cur.raw()).abs();
        assert!(
            raw_diff <= 2,
            "expected deduction within <= 2 raw units: got {after_cur}, expected {expected_cur}"
        );
        assert_eq!(pocket.min_merit(), floor_before);

        // Verify subsequent time decay remains monotonic and converges to Σ b_i == min_merit = 15.
        let tol = Decimal::from_str("0.0001").unwrap();
        let mut prev = after_cur;
        for &future_t in &[400u64, 500, 800, 1_500, 5_000, 50_000, 5_000_000] {
            let cur = pocket.cur_merit(ts(future_t));
            assert!(
                cur <= prev.checked_add(tol).unwrap(),
                "post-consumption decay increased at t={future_t}: {cur} > {prev}"
            );
            assert!(pocket.invariant_holds(ts(future_t)));
            prev = cur;
        }
        assert!(approx_eq(
            pocket.cur_merit(ts(50_000_000)),
            Decimal::from_int(15),
            Decimal::from_str("0.001").unwrap()
        ));

        // Also verify full consumable exhaustion lands cleanly on min_merit.
        let rem = pocket.consumable_merit(ts(600));
        if rem.is_positive() {
            let floored = pocket.consume_priority(rem, ts(600)).unwrap();
            assert_eq!(floored, pocket.min_merit());
            assert_eq!(pocket.consumable_merit(ts(600)), Decimal::ZERO);
            assert!(pocket.invariant_holds(ts(600)));
        }
    }
}
