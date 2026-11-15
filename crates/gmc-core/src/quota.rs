//! Quota & refresh-period accounting (per-chain isolation, one-time vs periodic).
//!
//! This module owns the **data model** and **configuration validation** for the
//! per-chain minting quota described in the design's *Quota Accounting* section
//! (Requirements 4.1, 4.8). Each `Nested_Merit_Chain` carries an independent
//! [`QuotaConfig`] (how much may be minted and how the allowance refreshes) and an
//! independent [`QuotaLedger`] (how much has been minted so far this period).
//!
//! The data model & configuration validation (task 6.1):
//!
//! - [`TimeUnit`] / [`RefreshPeriod`] — the refresh-cadence model: a chain is either
//!   `OneTime` (a single non-renewing allowance) or `Periodic` with an explicit time
//!   unit and a strictly-positive interval value.
//! - [`QuotaConfig`] — a validating constructor that accepts a config *iff* the quota
//!   is a strictly-positive (finite) [`Decimal`] **and** the refresh period is valid;
//!   otherwise it returns [`GmcError::QuotaConfigInvalid`].
//! - [`QuotaLedger`] — the per-period accounting record, initialized with
//!   `minted_this_period = 0` and `exhausted = false`.
//!
//! Quota checking, consumption & per-chain isolation (**this task, 6.2**):
//!
//! - [`QuotaLedger::check_quota`] — answers "would a mint of `amount` be allowed?"
//!   without mutating anything. A mint is allowed *iff* the ledger is not exhausted
//!   **and** `minted_this_period + amount <= quota` (Requirements 4.2, 4.3).
//! - [`QuotaLedger::consume_quota`] — re-checks then, on success, accumulates `amount`
//!   into `minted_this_period` (Requirement 4.4). A rejected request leaves the
//!   counter **unchanged** (Requirement 4.3). A `OneTime` chain that fully consumes
//!   its quota is flagged [`exhausted`](QuotaLedger::is_exhausted) and thereafter
//!   rejects every request, never restoring quota (Requirements 4.2, 4.7).
//! - [`QuotaLedgerSet`] — an optional registry keyed by [`ChainId`] that holds one
//!   independent `(QuotaConfig, QuotaLedger)` pair per chain and routes
//!   check/consume to the right ledger, so consuming on one chain can never touch
//!   another chain's allowance (Requirement 4.6, per-chain isolation).
//!
//! Refresh-period rollover / reset (**this task, 6.3**):
//!
//! - [`RefreshPeriod::period_length_secs`] — the length of one period in whole
//!   seconds (`unit.seconds() × value`), or `None` for `OneTime`. The interval
//!   `value` is a [`Decimal`] but is interpreted as a whole count of units: any
//!   fractional part is truncated toward zero (the design expects an integer count).
//! - [`QuotaLedger::reset`] — the low-level primitive that starts a fresh period:
//!   sets `minted_this_period = 0` and `period_start = now`.
//! - [`QuotaLedger::reset_if_elapsed`] — the time-based rollover (Requirement 4.5):
//!   for a **non-one-time** (`Periodic`) chain, once a full `Refresh_Period` has
//!   elapsed since `period_start` it resets `minted_this_period` to 0 and advances
//!   `period_start` to the boundary of the period that now contains `now`. `OneTime`
//!   chains never refresh (no-op). Calling it again **within** the same period does
//!   nothing, so accumulation is preserved until a real boundary is crossed.
//! - [`QuotaLedgerSet::reset_if_elapsed`] — routes the rollover to a single chain's
//!   ledger, mirroring [`check`](QuotaLedgerSet::check)/[`consume`](QuotaLedgerSet::consume).
//!
//! > Note that [`consume_quota`](QuotaLedger::consume_quota) still only accumulates
//! > *within* the current period — it never resets. Callers advance periods by
//! > invoking `reset_if_elapsed` (typically at the start of a mint, with the current
//! > on-chain time) before checking/consuming quota.
//! >
//! > Note on "finite": [`Decimal`] is an `i128`-backed fixed-point type, so every
//! > representable value is inherently finite (there is no NaN/∞). The "finite"
//! > clause of Requirements 4.1/4.8 is therefore satisfied by construction, and the
//! > only positive-value check that remains meaningful is `quota > 0`.

use crate::error::{GmcError, GmcResult};
use crate::types::{ChainId, Decimal, Timestamp};

/// Explicit time unit for a [`RefreshPeriod::Periodic`] cadence.
///
/// The design constrains periodic refresh intervals to whole, human-meaningful units
/// (seconds / hours / days) rather than arbitrary durations, so that a chain's
/// refresh cadence is unambiguous when it is later evaluated for rollover (task 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimeUnit {
    /// One second.
    Second,
    /// One hour (3,600 seconds).
    Hour,
    /// One day (86,400 seconds).
    Day,
}

impl TimeUnit {
    /// Number of whole seconds in one of this unit.
    ///
    /// Provided as a seam for the refresh-period rollover logic (task 6.3); not used
    /// for config validation here.
    #[inline]
    pub const fn seconds(self) -> u64 {
        match self {
            TimeUnit::Second => 1,
            TimeUnit::Hour => 3_600,
            TimeUnit::Day => 86_400,
        }
    }
}

/// How a chain's minting allowance refreshes over time.
///
/// A chain is configured as exactly one of:
///
/// - [`RefreshPeriod::OneTime`] — a single, non-renewing allowance. Once exhausted
///   the chain never regains quota (enforced later by task 6.2 via
///   [`QuotaLedger::exhausted`]).
/// - [`RefreshPeriod::Periodic`] — a recurring allowance that resets every
///   `value` × `unit` of on-chain time. `value` **must be strictly positive**
///   (Requirements 4.1, 4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefreshPeriod {
    /// A single non-renewing allowance (no refresh).
    OneTime,
    /// A recurring allowance that refreshes every `value` × `unit`.
    Periodic {
        /// The time unit of the interval (second / hour / day).
        unit: TimeUnit,
        /// The interval magnitude; must be `> 0` for a valid config.
        value: Decimal,
    },
}

impl RefreshPeriod {
    /// Returns `true` if this refresh period is well-formed.
    ///
    /// [`RefreshPeriod::OneTime`] is always valid. [`RefreshPeriod::Periodic`] is
    /// valid *iff* its `value` is strictly positive (Requirements 4.1, 4.8). Because
    /// [`Decimal`] is fixed-point, validity reduces to the positivity check.
    #[inline]
    pub fn is_valid(&self) -> bool {
        match self {
            RefreshPeriod::OneTime => true,
            RefreshPeriod::Periodic { value, .. } => value.is_positive(),
        }
    }

    /// Returns `true` if this is the non-renewing [`RefreshPeriod::OneTime`] variant.
    #[inline]
    pub fn is_one_time(&self) -> bool {
        matches!(self, RefreshPeriod::OneTime)
    }

    /// Length of one refresh period in whole seconds, or `None` for
    /// [`RefreshPeriod::OneTime`].
    ///
    /// Computed as `unit.seconds() × value`. The interval `value` is a [`Decimal`]
    /// but a refresh cadence is a whole count of units (e.g. "every 30 days"), so the
    /// fractional part of `value` is **truncated toward zero** before multiplying.
    /// This keeps period boundaries on exact second counts and matches the design's
    /// expectation that `value` is a positive integer count of units.
    ///
    /// Returns `None` when:
    /// - the period is `OneTime` (it never refreshes); or
    /// - the (validated, positive) `value` truncates to `0` whole units — e.g. a
    ///   `Periodic { value: 0.5, .. }` that passed `is_valid()` but rounds down to
    ///   zero whole units, which cannot define a usable boundary; or
    /// - the multiplication would overflow `u64`.
    ///
    /// A `None` from a `Periodic` chain is treated by [`QuotaLedger::reset_if_elapsed`]
    /// as "no usable boundary" and therefore never triggers a reset.
    pub fn period_length_secs(&self) -> Option<u64> {
        match self {
            RefreshPeriod::OneTime => None,
            RefreshPeriod::Periodic { unit, value } => {
                // Truncate the fixed-point value toward zero to a whole unit count.
                // `value` is validated `> 0`, but a sub-unit value (e.g. 0.5) floors
                // to 0 and yields no usable boundary.
                let raw = value.raw();
                if raw <= 0 {
                    return None;
                }
                let whole_units = (raw / Decimal::ONE.raw()) as u64;
                if whole_units == 0 {
                    return None;
                }
                unit.seconds().checked_mul(whole_units)
            }
        }
    }
}

/// Validated per-chain quota configuration.
///
/// Holds the maximum amount mintable per period ([`quota`](QuotaConfig::quota)) and
/// the [`RefreshPeriod`] that governs how/whether that allowance renews. The only way
/// to build one is [`QuotaConfig::new`], which enforces the acceptance rule of
/// Requirements 4.1/4.8 — so any `QuotaConfig` value in hand is, by construction, a
/// valid configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaConfig {
    quota: Decimal,
    refresh_period: RefreshPeriod,
}

impl QuotaConfig {
    /// Builds a validated [`QuotaConfig`].
    ///
    /// Accepts **iff** `quota` is a strictly-positive (finite) [`Decimal`] *and*
    /// `refresh_period` is valid (`OneTime`, or `Periodic` with `value > 0`).
    /// Otherwise returns [`GmcError::QuotaConfigInvalid`] without producing any
    /// partial state (Requirements 4.1, 4.8).
    pub fn new(quota: Decimal, refresh_period: RefreshPeriod) -> GmcResult<QuotaConfig> {
        if !quota.is_positive() {
            return Err(GmcError::QuotaConfigInvalid);
        }
        if !refresh_period.is_valid() {
            return Err(GmcError::QuotaConfigInvalid);
        }
        Ok(QuotaConfig {
            quota,
            refresh_period,
        })
    }

    /// The maximum amount mintable within a single period (always `> 0`).
    #[inline]
    pub fn quota(&self) -> Decimal {
        self.quota
    }

    /// The configured refresh cadence.
    #[inline]
    pub fn refresh_period(&self) -> RefreshPeriod {
        self.refresh_period
    }

    /// Convenience: `true` if this chain uses a one-time, non-renewing allowance.
    #[inline]
    pub fn is_one_time(&self) -> bool {
        self.refresh_period.is_one_time()
    }
}

/// Per-chain, per-period quota accounting record.
///
/// Tracks how much has been minted in the current refresh period for a single chain.
/// Each chain owns its own ledger so that quota consumption is isolated across chains
/// (Requirement 4.6, enforced by the consumption logic in task 6.2).
///
/// A freshly constructed ledger starts a clean period: `minted_this_period = 0` and
/// `exhausted = false`. Mutating accounting operations (`consumeQuota`, `resetQuota`)
/// are deliberately **not** defined here — see the module-level note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaLedger {
    chain_id: ChainId,
    minted_this_period: Decimal,
    period_start: Timestamp,
    exhausted: bool,
}

impl QuotaLedger {
    /// Creates a fresh ledger for `chain_id` whose first period starts at
    /// `period_start`.
    ///
    /// Initializes `minted_this_period = 0` and `exhausted = false`.
    pub fn new(chain_id: ChainId, period_start: Timestamp) -> QuotaLedger {
        QuotaLedger {
            chain_id,
            minted_this_period: Decimal::ZERO,
            period_start,
            exhausted: false,
        }
    }

    /// The chain this ledger accounts for.
    #[inline]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Amount minted so far in the current period.
    #[inline]
    pub fn minted_this_period(&self) -> Decimal {
        self.minted_this_period
    }

    /// Start timestamp of the current period.
    #[inline]
    pub fn period_start(&self) -> Timestamp {
        self.period_start
    }

    /// Whether a one-time chain has exhausted its allowance (never recovers).
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Checks whether minting `amount` against this ledger is currently allowed,
    /// **without** mutating any state.
    ///
    /// A mint is allowed *iff* both hold:
    ///
    /// 1. the ledger is **not** [`exhausted`](QuotaLedger::is_exhausted) — a `OneTime`
    ///    chain whose allowance was fully consumed stays permanently closed
    ///    (Requirements 4.2, 4.7); and
    /// 2. `minted_this_period + amount <= config.quota()` — the running total for the
    ///    current period would not exceed the cap (Requirement 4.3).
    ///
    /// `amount` is expected to be the strictly-positive value already validated by the
    /// minting pipeline; this method does not re-derive it. A non-positive `amount`
    /// trivially satisfies the cap (it cannot push the total over `quota`) and so is
    /// reported as allowed here — guarding `amount > 0` is the minting service's job
    /// (Requirement 8.7), kept separate from quota accounting.
    ///
    /// On violation returns [`GmcError::QuotaExceeded`]; the ledger is read-only here
    /// so nothing changes either way (Requirement 4.3 — a rejected request is never
    /// counted).
    pub fn check_quota(&self, config: &QuotaConfig, amount: Decimal) -> GmcResult<()> {
        // (1) A one-time chain that has exhausted its allowance rejects everything,
        // and never restores quota (Requirements 4.2, 4.7).
        if self.exhausted {
            return Err(GmcError::QuotaExceeded);
        }
        // (2) The prospective running total must not exceed the cap. Use checked
        // addition so a pathological overflow is treated as "over quota" rather than
        // wrapping into a spuriously-allowed value (defensive; Decimal is i128-backed).
        match self.minted_this_period.checked_add(amount) {
            Some(prospective) if prospective <= config.quota() => Ok(()),
            _ => Err(GmcError::QuotaExceeded),
        }
    }

    /// Consumes `amount` of this period's allowance, accumulating it into
    /// `minted_this_period` on success.
    ///
    /// Re-validates via [`check_quota`](QuotaLedger::check_quota) first. On failure it
    /// returns [`GmcError::QuotaExceeded`] and leaves `minted_this_period`
    /// **unchanged** — a rejected request is never counted (Requirement 4.3). On
    /// success it adds `amount` to the running total (Requirement 4.4).
    ///
    /// For a [`RefreshPeriod::OneTime`] chain, once the running total reaches the cap
    /// (`minted_this_period == config.quota()`, i.e. the allowance is fully consumed)
    /// the ledger is flagged [`exhausted`](QuotaLedger::is_exhausted); from then on
    /// every request is rejected and no quota is ever restored (Requirements 4.2, 4.7).
    ///
    /// This method only ever **accumulates** within the current period — it never
    /// resets the counter. Refresh-period rollover is the responsibility of
    /// `resetQuota` (task 6.3).
    pub fn consume_quota(&mut self, config: &QuotaConfig, amount: Decimal) -> GmcResult<()> {
        // Re-check up front; on rejection we return without any mutation so the
        // counter is provably unchanged (Requirement 4.3).
        self.check_quota(config, amount)?;

        // Accumulate this period's minted total (Requirement 4.4). check_quota already
        // proved this addition does not overflow and stays within the cap.
        let new_total = self
            .minted_this_period
            .checked_add(amount)
            .ok_or(GmcError::QuotaExceeded)?;
        self.minted_this_period = new_total;

        // A one-time chain whose allowance is now fully consumed is permanently
        // exhausted and never recovers quota (Requirements 4.2, 4.7).
        if config.is_one_time() && self.minted_this_period >= config.quota() {
            self.exhausted = true;
        }

        Ok(())
    }

    /// Starts a fresh refresh period: sets `minted_this_period = 0` and
    /// `period_start = now`.
    ///
    /// This is the low-level reset primitive (the `resetQuota` of the design's *Quota
    /// Accounting* section, Requirement 4.5). It unconditionally clears this period's
    /// running total — callers decide *whether* a reset is due (see
    /// [`reset_if_elapsed`](QuotaLedger::reset_if_elapsed) for the time-based guard).
    ///
    /// It does **not** touch [`exhausted`](QuotaLedger::is_exhausted): a one-time
    /// chain never refreshes, so its exhausted flag is permanent. Periodic chains are
    /// never flagged exhausted, so the flag is irrelevant to them.
    pub fn reset(&mut self, now: Timestamp) {
        self.minted_this_period = Decimal::ZERO;
        self.period_start = now;
    }

    /// Rolls the ledger over to the current period if a full `Refresh_Period` has
    /// elapsed, resetting `minted_this_period` to 0 and advancing `period_start`
    /// (Requirement 4.5). Returns `true` if a reset happened.
    ///
    /// Behaviour by configuration:
    ///
    /// - **OneTime** (`config.is_one_time()`): never refreshes — returns `false` and
    ///   leaves the ledger untouched, so an exhausted one-time chain stays exhausted.
    /// - **Periodic**: let `len = config.refresh_period().period_length_secs()` and
    ///   `elapsed = now.saturating_elapsed_since(period_start)`. If `len` is available
    ///   and `elapsed >= len`, the current period has ended: `minted_this_period` is
    ///   reset to 0 and `period_start` is advanced to the start of the period that now
    ///   contains `now`, i.e. `period_start + k*len` where `k = elapsed / len` (the
    ///   number of whole periods that have passed). Aligning to the boundary (rather
    ///   than to `now`) keeps period starts on a stable cadence across long gaps.
    ///
    /// Calling this more than once within the same period is a no-op after the first
    /// crossing: once `period_start` is advanced, `elapsed < len` again, so the
    /// accumulated `minted_this_period` is preserved until the next real boundary.
    ///
    /// `now` earlier than `period_start` (clock skew) saturates `elapsed` to 0 and so
    /// never triggers a reset.
    pub fn reset_if_elapsed(&mut self, config: &QuotaConfig, now: Timestamp) -> bool {
        // One-time chains never refresh (Requirement 4.2/4.5): no-op.
        if config.is_one_time() {
            return false;
        }

        // A periodic chain needs a usable, strictly-positive period length to define a
        // boundary; without one we cannot roll over.
        let len = match config.refresh_period().period_length_secs() {
            Some(len) if len > 0 => len,
            _ => return false,
        };

        let elapsed = now.saturating_elapsed_since(self.period_start);
        if elapsed < len {
            // Still inside the current period — preserve accumulation (no reset).
            return false;
        }

        // Advance to the boundary of the period that now contains `now`:
        // period_start += k*len, where k = floor(elapsed / len) >= 1.
        let periods_elapsed = elapsed / len;
        let advance = periods_elapsed.saturating_mul(len);
        let new_start = Timestamp::from_secs(self.period_start.as_secs().saturating_add(advance));
        self.reset(new_start);
        true
    }
}

/// An optional per-chain registry of `(QuotaConfig, QuotaLedger)` pairs.
///
/// This is a thin convenience wrapper that makes **per-chain isolation**
/// (Requirement 4.6) structurally obvious: each [`ChainId`] maps to its *own*
/// independent config + ledger, and [`check`](QuotaLedgerSet::check) /
/// [`consume`](QuotaLedgerSet::consume) route to exactly one entry. Because the
/// entries share no state, consuming quota on one chain provably cannot change the
/// available allowance of any other chain.
///
/// The core accounting rules live on [`QuotaLedger`]; this type only owns routing and
/// lookup. It is intentionally minimal — callers that manage ledgers themselves can
/// ignore it and use [`QuotaLedger`] directly.
#[derive(Debug, Clone, Default)]
pub struct QuotaLedgerSet {
    entries: std::collections::BTreeMap<ChainId, (QuotaConfig, QuotaLedger)>,
}

impl QuotaLedgerSet {
    /// Creates an empty registry.
    pub fn new() -> QuotaLedgerSet {
        QuotaLedgerSet {
            entries: std::collections::BTreeMap::new(),
        }
    }

    /// Registers a chain with its validated `config`, starting a fresh ledger at
    /// `period_start`. Returns the previously-registered pair for `chain_id`, if any.
    pub fn register(
        &mut self,
        chain_id: ChainId,
        config: QuotaConfig,
        period_start: Timestamp,
    ) -> Option<(QuotaConfig, QuotaLedger)> {
        let ledger = QuotaLedger::new(chain_id.clone(), period_start);
        self.entries.insert(chain_id, (config, ledger))
    }

    /// Returns `true` if `chain_id` is registered.
    pub fn contains(&self, chain_id: &ChainId) -> bool {
        self.entries.contains_key(chain_id)
    }

    /// Borrows the ledger for `chain_id`, if registered.
    pub fn ledger(&self, chain_id: &ChainId) -> Option<&QuotaLedger> {
        self.entries.get(chain_id).map(|(_, ledger)| ledger)
    }

    /// Borrows the config for `chain_id`, if registered.
    pub fn config(&self, chain_id: &ChainId) -> Option<&QuotaConfig> {
        self.entries.get(chain_id).map(|(config, _)| config)
    }

    /// Amount minted so far this period for `chain_id`, if registered.
    pub fn minted_this_period(&self, chain_id: &ChainId) -> Option<Decimal> {
        self.ledger(chain_id).map(QuotaLedger::minted_this_period)
    }

    /// Checks whether minting `amount` on `chain_id` is allowed, without mutating
    /// anything. Returns [`GmcError::ParentNotFound`] semantics are *not* used here;
    /// an unknown chain returns [`GmcError::QuotaConfigInvalid`] since no validated
    /// quota configuration exists for it.
    pub fn check(&self, chain_id: &ChainId, amount: Decimal) -> GmcResult<()> {
        let (config, ledger) = self
            .entries
            .get(chain_id)
            .ok_or(GmcError::QuotaConfigInvalid)?;
        ledger.check_quota(config, amount)
    }

    /// Consumes `amount` on `chain_id`, routing to that chain's ledger only. A failure
    /// leaves every ledger (including this one) unchanged. An unknown chain returns
    /// [`GmcError::QuotaConfigInvalid`].
    pub fn consume(&mut self, chain_id: &ChainId, amount: Decimal) -> GmcResult<()> {
        let (config, ledger) = self
            .entries
            .get_mut(chain_id)
            .ok_or(GmcError::QuotaConfigInvalid)?;
        ledger.consume_quota(config, amount)
    }

    /// Rolls `chain_id`'s ledger over to the current period if its `Refresh_Period`
    /// has elapsed, returning whether a reset happened (Requirement 4.5). Routes to a
    /// single chain only, so it can never disturb another chain's accounting. An
    /// unknown chain returns [`GmcError::QuotaConfigInvalid`].
    pub fn reset_if_elapsed(&mut self, chain_id: &ChainId, now: Timestamp) -> GmcResult<bool> {
        let (config, ledger) = self
            .entries
            .get_mut(chain_id)
            .ok_or(GmcError::QuotaConfigInvalid)?;
        Ok(ledger.reset_if_elapsed(config, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    // --- QuotaConfig validation (Requirements 4.1, 4.8) ---------------------

    #[test]
    fn valid_quota_with_one_time_is_accepted() {
        let cfg = QuotaConfig::new(Decimal::from_int(100), RefreshPeriod::OneTime)
            .expect("positive quota + OneTime must be accepted");
        assert_eq!(cfg.quota(), Decimal::from_int(100));
        assert_eq!(cfg.refresh_period(), RefreshPeriod::OneTime);
        assert!(cfg.is_one_time());
    }

    #[test]
    fn valid_quota_with_periodic_is_accepted() {
        let period = RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: dec("30"),
        };
        let cfg = QuotaConfig::new(dec("1000.5"), period)
            .expect("positive quota + valid Periodic must be accepted");
        assert_eq!(cfg.quota(), dec("1000.5"));
        assert_eq!(cfg.refresh_period(), period);
        assert!(!cfg.is_one_time());
    }

    #[test]
    fn zero_quota_is_rejected() {
        assert_eq!(
            QuotaConfig::new(Decimal::ZERO, RefreshPeriod::OneTime),
            Err(GmcError::QuotaConfigInvalid)
        );
    }

    #[test]
    fn negative_quota_is_rejected() {
        assert_eq!(
            QuotaConfig::new(dec("-1"), RefreshPeriod::OneTime),
            Err(GmcError::QuotaConfigInvalid)
        );
    }

    #[test]
    fn periodic_with_zero_value_is_rejected() {
        let period = RefreshPeriod::Periodic {
            unit: TimeUnit::Hour,
            value: Decimal::ZERO,
        };
        assert_eq!(
            QuotaConfig::new(Decimal::from_int(100), period),
            Err(GmcError::QuotaConfigInvalid)
        );
    }

    #[test]
    fn periodic_with_negative_value_is_rejected() {
        let period = RefreshPeriod::Periodic {
            unit: TimeUnit::Second,
            value: dec("-5"),
        };
        assert_eq!(
            QuotaConfig::new(Decimal::from_int(100), period),
            Err(GmcError::QuotaConfigInvalid)
        );
    }

    // --- RefreshPeriod helpers ---------------------------------------------

    #[test]
    fn refresh_period_validity() {
        assert!(RefreshPeriod::OneTime.is_valid());
        assert!(RefreshPeriod::OneTime.is_one_time());

        let good = RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: Decimal::ONE,
        };
        assert!(good.is_valid());
        assert!(!good.is_one_time());

        let bad = RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: Decimal::ZERO,
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn time_unit_seconds() {
        assert_eq!(TimeUnit::Second.seconds(), 1);
        assert_eq!(TimeUnit::Hour.seconds(), 3_600);
        assert_eq!(TimeUnit::Day.seconds(), 86_400);
    }

    // --- QuotaLedger construction ------------------------------------------

    #[test]
    fn quota_ledger_initializes_clean_period() {
        let ledger = QuotaLedger::new(ChainId::from("env-chain"), Timestamp::from_secs(1_000));
        assert_eq!(ledger.chain_id().as_str(), "env-chain");
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(ledger.period_start(), Timestamp::from_secs(1_000));
        assert!(!ledger.is_exhausted());
    }

    // --- check_quota / consume_quota (Requirements 4.2, 4.3, 4.4, 4.7) ------

    fn periodic_cfg(quota: &str) -> QuotaConfig {
        QuotaConfig::new(
            dec(quota),
            RefreshPeriod::Periodic {
                unit: TimeUnit::Day,
                value: Decimal::ONE,
            },
        )
        .expect("valid periodic config")
    }

    fn one_time_cfg(quota: &str) -> QuotaConfig {
        QuotaConfig::new(dec(quota), RefreshPeriod::OneTime).expect("valid one-time config")
    }

    fn fresh_ledger() -> QuotaLedger {
        QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0))
    }

    #[test]
    fn mint_within_quota_succeeds_and_accumulates() {
        // Requirement 4.4: a successful mint accumulates into minted_this_period.
        let cfg = periodic_cfg("100");
        let mut ledger = fresh_ledger();

        assert!(ledger.check_quota(&cfg, dec("30")).is_ok());
        ledger.consume_quota(&cfg, dec("30")).expect("30 <= 100");
        assert_eq!(ledger.minted_this_period(), dec("30"));

        ledger
            .consume_quota(&cfg, dec("20"))
            .expect("30 + 20 <= 100");
        assert_eq!(ledger.minted_this_period(), dec("50"));
        assert!(!ledger.is_exhausted());
    }

    #[test]
    fn mint_exceeding_quota_is_rejected_and_counter_unchanged() {
        // Requirement 4.3: over-quota request is rejected and the counter is unchanged.
        let cfg = periodic_cfg("100");
        let mut ledger = fresh_ledger();
        ledger.consume_quota(&cfg, dec("80")).expect("80 <= 100");

        // 80 + 30 = 110 > 100 -> rejected.
        assert_eq!(
            ledger.check_quota(&cfg, dec("30")),
            Err(GmcError::QuotaExceeded)
        );
        assert_eq!(
            ledger.consume_quota(&cfg, dec("30")),
            Err(GmcError::QuotaExceeded)
        );
        // Counter must be unchanged by the rejected request.
        assert_eq!(ledger.minted_this_period(), dec("80"));

        // A request that still fits is accepted afterwards (no permanent lockout for
        // a periodic chain).
        ledger
            .consume_quota(&cfg, dec("20"))
            .expect("80 + 20 == 100");
        assert_eq!(ledger.minted_this_period(), dec("100"));
    }

    #[test]
    fn cumulative_mints_up_to_exactly_quota_then_next_rejected() {
        // Requirement 4.3: accumulation may reach the cap exactly; the next positive
        // mint is rejected.
        let cfg = periodic_cfg("100");
        let mut ledger = fresh_ledger();

        ledger.consume_quota(&cfg, dec("60")).expect("60 <= 100");
        ledger
            .consume_quota(&cfg, dec("40"))
            .expect("60 + 40 == 100");
        assert_eq!(ledger.minted_this_period(), dec("100"));

        // Exactly at the cap; any further positive amount is over quota.
        assert_eq!(
            ledger.consume_quota(&cfg, dec("0.000001")),
            Err(GmcError::QuotaExceeded)
        );
        assert_eq!(ledger.minted_this_period(), dec("100"));
        // A periodic chain at its cap is NOT flagged exhausted (only OneTime is).
        assert!(!ledger.is_exhausted());
    }

    #[test]
    fn one_time_chain_exhausts_at_quota_and_stays_exhausted() {
        // Requirements 4.2 & 4.7: a one-time chain that fully consumes its quota is
        // exhausted and rejects every subsequent request, never restoring quota.
        let cfg = one_time_cfg("50");
        let mut ledger = fresh_ledger();

        ledger.consume_quota(&cfg, dec("50")).expect("50 == 50");
        assert_eq!(ledger.minted_this_period(), dec("50"));
        assert!(ledger.is_exhausted());

        // Every later request is rejected, even tiny ones, and nothing changes.
        assert_eq!(
            ledger.check_quota(&cfg, dec("0.000001")),
            Err(GmcError::QuotaExceeded)
        );
        assert_eq!(
            ledger.consume_quota(&cfg, dec("0.000001")),
            Err(GmcError::QuotaExceeded)
        );
        assert_eq!(ledger.minted_this_period(), dec("50"));
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn one_time_chain_partial_consumption_does_not_exhaust() {
        // A one-time chain only becomes exhausted once the cap is reached; partial
        // consumption keeps the remaining allowance usable.
        let cfg = one_time_cfg("50");
        let mut ledger = fresh_ledger();

        ledger.consume_quota(&cfg, dec("30")).expect("30 <= 50");
        assert!(!ledger.is_exhausted());

        ledger
            .consume_quota(&cfg, dec("20"))
            .expect("30 + 20 == 50");
        assert!(ledger.is_exhausted());
    }

    // --- Per-chain isolation (Requirement 4.6) -----------------------------

    #[test]
    fn two_chains_ledgers_are_independent() {
        // Consuming on chain A must not change chain B's available allowance.
        let cfg_a = periodic_cfg("100");
        let cfg_b = periodic_cfg("100");
        let mut ledger_a = QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0));
        let mut ledger_b = QuotaLedger::new(ChainId::from("chain-b"), Timestamp::from_secs(0));

        ledger_a
            .consume_quota(&cfg_a, dec("100"))
            .expect("100 == 100");
        // chain A is now full / would reject more...
        assert_eq!(
            ledger_a.consume_quota(&cfg_a, dec("1")),
            Err(GmcError::QuotaExceeded)
        );
        // ...but chain B is entirely unaffected.
        assert_eq!(ledger_b.minted_this_period(), Decimal::ZERO);
        ledger_b
            .consume_quota(&cfg_b, dec("75"))
            .expect("75 <= 100");
        assert_eq!(ledger_b.minted_this_period(), dec("75"));
        assert_eq!(ledger_a.minted_this_period(), dec("100"));
    }

    #[test]
    fn ledger_set_routes_check_and_consume_per_chain() {
        // The optional registry makes isolation explicit: each chain has its own
        // (config, ledger) and consuming on one never touches another.
        let mut set = QuotaLedgerSet::new();
        let a = ChainId::from("chain-a");
        let b = ChainId::from("chain-b");
        set.register(a.clone(), one_time_cfg("50"), Timestamp::from_secs(0));
        set.register(b.clone(), periodic_cfg("200"), Timestamp::from_secs(0));

        // Exhaust chain A (one-time).
        set.consume(&a, dec("50")).expect("50 == 50");
        assert!(set.ledger(&a).unwrap().is_exhausted());
        assert_eq!(set.consume(&a, dec("1")), Err(GmcError::QuotaExceeded));

        // Chain B is independent and still fully available.
        assert_eq!(set.minted_this_period(&b), Some(Decimal::ZERO));
        set.consume(&b, dec("120")).expect("120 <= 200");
        assert_eq!(set.minted_this_period(&b), Some(dec("120")));
        assert_eq!(set.minted_this_period(&a), Some(dec("50")));
    }

    #[test]
    fn ledger_set_unknown_chain_is_rejected() {
        let set = QuotaLedgerSet::new();
        let unknown = ChainId::from("nope");
        assert_eq!(
            set.check(&unknown, dec("1")),
            Err(GmcError::QuotaConfigInvalid)
        );
        assert!(set.ledger(&unknown).is_none());
        assert!(!set.contains(&unknown));
    }

    // --- Refresh-period rollover / reset (Requirement 4.5) ------------------

    /// A periodic config with an explicit period length (`value` whole units).
    fn periodic_cfg_unit(quota: &str, unit: TimeUnit, value: &str) -> QuotaConfig {
        QuotaConfig::new(
            dec(quota),
            RefreshPeriod::Periodic {
                unit,
                value: dec(value),
            },
        )
        .expect("valid periodic config")
    }

    #[test]
    fn period_length_secs_computation() {
        // OneTime has no period length.
        assert_eq!(RefreshPeriod::OneTime.period_length_secs(), None);

        // length = unit.seconds() * whole(value)
        assert_eq!(
            RefreshPeriod::Periodic {
                unit: TimeUnit::Second,
                value: Decimal::ONE,
            }
            .period_length_secs(),
            Some(1)
        );
        assert_eq!(
            RefreshPeriod::Periodic {
                unit: TimeUnit::Day,
                value: dec("30"),
            }
            .period_length_secs(),
            Some(86_400 * 30)
        );
        assert_eq!(
            RefreshPeriod::Periodic {
                unit: TimeUnit::Hour,
                value: dec("2"),
            }
            .period_length_secs(),
            Some(7_200)
        );

        // Fractional unit counts truncate toward zero; a sub-unit value yields no
        // usable boundary.
        assert_eq!(
            RefreshPeriod::Periodic {
                unit: TimeUnit::Day,
                value: dec("1.9"),
            }
            .period_length_secs(),
            Some(86_400) // 1.9 -> 1 whole day
        );
        assert_eq!(
            RefreshPeriod::Periodic {
                unit: TimeUnit::Day,
                value: dec("0.5"),
            }
            .period_length_secs(),
            None // floors to 0 whole units
        );
    }

    #[test]
    fn periodic_chain_resets_after_period_elapses_and_accepts_new_mints() {
        // Requirement 4.5: once a full period elapses, minted_this_period resets to 0
        // and the chain can mint up to quota again.
        let cfg = periodic_cfg_unit("100", TimeUnit::Day, "1"); // 86,400s period
        let mut ledger = QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0));

        // Fill the period.
        ledger.consume_quota(&cfg, dec("100")).expect("100 == 100");
        assert_eq!(ledger.minted_this_period(), dec("100"));
        // No more room this period.
        assert_eq!(
            ledger.consume_quota(&cfg, dec("1")),
            Err(GmcError::QuotaExceeded)
        );

        // Cross the period boundary (exactly one day later).
        let did_reset = ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(86_400));
        assert!(did_reset);
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(ledger.period_start(), Timestamp::from_secs(86_400));

        // Fresh allowance: full quota mintable again.
        ledger
            .consume_quota(&cfg, dec("100"))
            .expect("fresh period");
        assert_eq!(ledger.minted_this_period(), dec("100"));
    }

    #[test]
    fn reset_within_same_period_is_noop() {
        // Calling reset_if_elapsed before a full period has elapsed must not reset.
        let cfg = periodic_cfg_unit("100", TimeUnit::Day, "1"); // 86,400s
        let mut ledger = QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0));
        ledger.consume_quota(&cfg, dec("40")).expect("40 <= 100");

        // Just before the boundary -> no reset, accumulation preserved.
        assert!(!ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(86_399)));
        assert_eq!(ledger.minted_this_period(), dec("40"));
        assert_eq!(ledger.period_start(), Timestamp::from_secs(0));

        // At t=0 (same instant) -> no reset.
        assert!(!ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(0)));
        assert_eq!(ledger.minted_this_period(), dec("40"));
    }

    #[test]
    fn reset_is_idempotent_within_new_period() {
        // After one rollover, a second call inside the new period does nothing.
        let cfg = periodic_cfg_unit("100", TimeUnit::Day, "1");
        let mut ledger = QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0));
        ledger.consume_quota(&cfg, dec("90")).expect("90 <= 100");

        // First crossing resets.
        assert!(ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(90_000)));
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        let start_after_reset = ledger.period_start();
        ledger.consume_quota(&cfg, dec("10")).expect("10 <= 100");

        // Second call within the same (new) period: no further reset, counter intact.
        assert!(!ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(90_100)));
        assert_eq!(ledger.minted_this_period(), dec("10"));
        assert_eq!(ledger.period_start(), start_after_reset);
    }

    #[test]
    fn reset_advances_period_start_to_boundary_across_multiple_periods() {
        // period_start advances to period_start + k*len (boundary alignment), where k
        // is the number of whole periods elapsed.
        let cfg = periodic_cfg_unit("100", TimeUnit::Day, "1"); // len = 86,400
        let mut ledger = QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0));
        ledger.consume_quota(&cfg, dec("50")).expect("50 <= 100");

        // 3.5 days later: k = 3 whole periods, boundary = 3 * 86,400 = 259,200.
        let now = Timestamp::from_secs(86_400 * 3 + 43_200);
        assert!(ledger.reset_if_elapsed(&cfg, now));
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(ledger.period_start(), Timestamp::from_secs(259_200));

        // The new period_start is on the cadence and is <= now, so we are inside it.
        assert!(ledger.period_start() <= now);
        assert!(!ledger.reset_if_elapsed(&cfg, now));
    }

    #[test]
    fn one_time_chain_never_resets_and_stays_exhausted() {
        // Requirement 4.5 only applies to non-one-time chains. A one-time chain never
        // refreshes: reset_if_elapsed is a no-op even far in the future, and an
        // exhausted chain remains exhausted with no restored quota.
        let cfg = one_time_cfg("50");
        let mut ledger = QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(0));
        ledger.consume_quota(&cfg, dec("50")).expect("50 == 50");
        assert!(ledger.is_exhausted());

        // Far in the future — still no reset for a one-time chain.
        assert!(!ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(10_000_000)));
        assert_eq!(ledger.minted_this_period(), dec("50"));
        assert_eq!(ledger.period_start(), Timestamp::from_secs(0));
        assert!(ledger.is_exhausted());

        // Still rejects everything.
        assert_eq!(
            ledger.consume_quota(&cfg, dec("1")),
            Err(GmcError::QuotaExceeded)
        );
    }

    #[test]
    fn reset_skew_backwards_now_is_noop() {
        // A `now` earlier than period_start (clock skew) saturates elapsed to 0 and
        // never triggers a reset.
        let cfg = periodic_cfg_unit("100", TimeUnit::Day, "1");
        let mut ledger =
            QuotaLedger::new(ChainId::from("chain-a"), Timestamp::from_secs(1_000_000));
        ledger.consume_quota(&cfg, dec("30")).expect("30 <= 100");
        assert!(!ledger.reset_if_elapsed(&cfg, Timestamp::from_secs(500_000)));
        assert_eq!(ledger.minted_this_period(), dec("30"));
        assert_eq!(ledger.period_start(), Timestamp::from_secs(1_000_000));
    }

    #[test]
    fn low_level_reset_clears_counter_and_sets_start() {
        let cfg = periodic_cfg("100");
        let mut ledger = fresh_ledger();
        ledger.consume_quota(&cfg, dec("75")).expect("75 <= 100");
        ledger.reset(Timestamp::from_secs(12_345));
        assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
        assert_eq!(ledger.period_start(), Timestamp::from_secs(12_345));
    }

    #[test]
    fn ledger_set_routes_reset_per_chain() {
        // reset_if_elapsed on one chain must not disturb another chain's ledger.
        let mut set = QuotaLedgerSet::new();
        let a = ChainId::from("chain-a");
        let b = ChainId::from("chain-b");
        set.register(
            a.clone(),
            periodic_cfg_unit("100", TimeUnit::Day, "1"),
            Timestamp::from_secs(0),
        );
        set.register(
            b.clone(),
            periodic_cfg_unit("100", TimeUnit::Day, "1"),
            Timestamp::from_secs(0),
        );
        set.consume(&a, dec("80")).expect("80 <= 100");
        set.consume(&b, dec("80")).expect("80 <= 100");

        // Roll chain A over a day later; chain B is untouched.
        assert_eq!(
            set.reset_if_elapsed(&a, Timestamp::from_secs(86_400)),
            Ok(true)
        );
        assert_eq!(set.minted_this_period(&a), Some(Decimal::ZERO));
        assert_eq!(set.minted_this_period(&b), Some(dec("80")));

        // Unknown chain is rejected.
        assert_eq!(
            set.reset_if_elapsed(&ChainId::from("nope"), Timestamp::from_secs(1)),
            Err(GmcError::QuotaConfigInvalid)
        );
    }
}
