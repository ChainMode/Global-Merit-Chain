//! Cold-start decaying initial Merit bootstrap & `opaqueRef` natural-person
//! governance weight normalization (`define-decaying-bootstrap-parameters` + ADR 0001).
//!
//! ## Core Constitutional Locks (GMChain ADR 0001)
//!
//! 1. **Zero Floor Contribution (`B_i = 0`)**: Every `BootstrapPurchased` batch is
//!    minted with `b = Decimal::ZERO` and **NEVER** invokes
//!    [`MeritPocket::update_min_merit`]. Without subsequent earned contributions, the
//!    purchased Merit decays monotonically to `0`.
//! 2. **Single Decay Formula Reuse**: Faster decay (`decay_multiplier >= 2`) is
//!    implemented by dividing the batch's `influence_duration` by `decay_multiplier`
//!    and calling [`MeritBatch::with_influence_duration`], reusing the single canonical
//!    `merit.rs` decay engine.
//! 3. **One-Way Non-Monetary Lock**: No fiat redemption, no transfer, and `GmcBase`
//!    continues to reject all `MonetaryRequest`s unconditionally.
//! 4. **Sybil-Proof `opaqueRef` Normalization**: Purchase caps and concave governance
//!    voting weights aggregate by `gmcref_` (`opaqueRef`) so splitting across multiple
//!    `iFay`s cannot amplify voting power or bypass caps.

use std::collections::BTreeMap;

use crate::error::{GmcError, GmcResult};
use crate::merit::{MeritBatch, MeritPocket};
use crate::types::{ChainId, Decimal, Timestamp};

/// Distinguishes earned contribution batches from cold-start bootstrap batches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeritBatchOrigin {
    /// Minted from verified domain contribution; settles a positive floor `B_i > 0`.
    EarnedContribution,
    /// Minted via one-way cold-start bootstrap; strictly `B_i = 0`, never raises `minMerit`.
    BootstrapPurchased,
}

/// Governance-tunable safety envelope for cold-start initial Merit bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// Maximum Merit (`μ`) granted in a single bootstrap operation.
    pub single_cap: Decimal,
    /// Lifetime cumulative Merit (`μ`) cap per natural person (`opaqueRef`).
    pub lifetime_cap: Decimal,
    /// Minimum cooldown in seconds between grants for the same `opaqueRef`.
    pub cooldown_secs: u64,
    /// Whether repeat grants after `cooldown_secs` (up to `lifetime_cap`) are allowed.
    pub allow_renewal: bool,
    /// Decay rate multiplier relative to baseline contribution batches (`MUST be >= 2`).
    pub decay_multiplier: u32,
}

impl BootstrapConfig {
    /// Conservative preset (ADR 0001): `50 μ` single & lifetime cap, no renewal, `3x` decay.
    pub fn conservative_baseline() -> Self {
        BootstrapConfig {
            single_cap: Decimal::from_int(50),
            lifetime_cap: Decimal::from_int(50),
            cooldown_secs: 365 * 86_400,
            allow_renewal: false,
            decay_multiplier: 3,
        }
    }

    /// Neutral preset (ADR 0001): `100 μ` single cap, `200 μ` lifetime cap, `365d` cooldown, `2x` decay.
    pub fn neutral_baseline() -> Self {
        BootstrapConfig {
            single_cap: Decimal::from_int(100),
            lifetime_cap: Decimal::from_int(200),
            cooldown_secs: 365 * 86_400,
            allow_renewal: true,
            decay_multiplier: 2,
        }
    }

    /// Validates all safety invariants of the bootstrap parameter envelope.
    pub fn validate(&self) -> GmcResult<()> {
        if !self.single_cap.is_positive()
            || !self.lifetime_cap.is_positive()
            || self.single_cap > self.lifetime_cap
            || self.decay_multiplier < 2
        {
            return Err(GmcError::BootstrapConfigInvalid);
        }
        Ok(())
    }
}

/// Request to mint a decaying `BootstrapPurchased` batch into a target [`MeritPocket`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapMintRequest {
    /// Unique batch identifier.
    pub batch_id: String,
    /// Blind natural-person commitment in GMChain namespace (`gmcref_<base32>`).
    pub opaque_ref: String,
    /// Requested Merit amount (`μ`, strictly positive and `<= single_cap`).
    pub amount: Decimal,
    /// Baseline influence duration in seconds before applying `decay_multiplier`.
    pub base_influence_duration_secs: i64,
    /// On-chain acquisition timestamp.
    pub acquired_at: Timestamp,
    /// Source chain identifier.
    pub source_chain_id: ChainId,
}

/// Receipt emitted upon a valid cold-start bootstrap grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapMintReceipt {
    /// Minted batch identifier.
    pub batch_id: String,
    /// Origin marker (always [`MeritBatchOrigin::BootstrapPurchased`]).
    pub origin: MeritBatchOrigin,
    /// Floor contribution (always [`Decimal::ZERO`]).
    pub floor_contribution: Decimal,
    /// Effective shortened influence duration (`base / decay_multiplier`).
    pub effective_influence_duration: Decimal,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OpaqueRefQuotaLedger {
    cumulative_granted: Decimal,
    last_acquired_at: Option<Timestamp>,
}

/// Cold-start bootstrap service enforcing `B_i = 0`, faster decay, per-`opaqueRef`
/// caps/cooldowns, and explicit one-way non-transferability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapMintService {
    config: BootstrapConfig,
    quotas_by_opaque_ref: BTreeMap<String, OpaqueRefQuotaLedger>,
    batch_origins: BTreeMap<String, MeritBatchOrigin>,
}

impl BootstrapMintService {
    /// Constructs a validated [`BootstrapMintService`].
    pub fn new(config: BootstrapConfig) -> GmcResult<Self> {
        config.validate()?;
        Ok(BootstrapMintService {
            config,
            quotas_by_opaque_ref: BTreeMap::new(),
            batch_origins: BTreeMap::new(),
        })
    }

    /// Grants decaying initial Merit with `B_i = 0` without touching `pocket.min_merit`.
    pub fn grant_initial_merit(
        &mut self,
        pocket: &mut MeritPocket,
        req: BootstrapMintRequest,
    ) -> GmcResult<BootstrapMintReceipt> {
        if req.batch_id.trim().is_empty()
            || !is_valid_gmcref(&req.opaque_ref)
            || req.base_influence_duration_secs <= 0
            || self.batch_origins.contains_key(&req.batch_id)
        {
            return Err(GmcError::FieldValidation);
        }
        if !req.amount.is_positive() {
            return Err(GmcError::InvalidMintAmount);
        }
        if req.amount > self.config.single_cap {
            return Err(GmcError::BootstrapCapExceeded);
        }

        let ledger = self
            .quotas_by_opaque_ref
            .get(&req.opaque_ref)
            .cloned()
            .unwrap_or_default();

        if let Some(last_ts) = ledger.last_acquired_at {
            if !self.config.allow_renewal {
                return Err(GmcError::BootstrapCooldownActive);
            }
            let elapsed = req.acquired_at.saturating_elapsed_since(last_ts);
            if elapsed < self.config.cooldown_secs {
                return Err(GmcError::BootstrapCooldownActive);
            }
        }

        let new_cumulative = ledger
            .cumulative_granted
            .checked_add(req.amount)
            .ok_or(GmcError::BootstrapCapExceeded)?;
        if new_cumulative > self.config.lifetime_cap {
            return Err(GmcError::BootstrapCapExceeded);
        }

        let base_dur = Decimal::from_int(req.base_influence_duration_secs);
        let mult = Decimal::from_int(i64::from(self.config.decay_multiplier));
        let effective_dur = base_dur
            .checked_div(mult)
            .filter(|d| d.is_positive())
            .ok_or(GmcError::BootstrapConfigInvalid)?;

        // Constitutional lock: B_i == 0, reusing MeritBatch::with_influence_duration.
        let batch = MeritBatch::with_influence_duration(
            req.batch_id.clone(),
            req.amount,
            Decimal::ZERO,
            effective_dur,
            req.acquired_at,
            req.source_chain_id,
        )
        .ok_or(GmcError::BootstrapConfigInvalid)?;

        // Append batch ONLY — NEVER call pocket.update_min_merit!
        pocket.add_batch(batch);

        self.quotas_by_opaque_ref.insert(
            req.opaque_ref,
            OpaqueRefQuotaLedger {
                cumulative_granted: new_cumulative,
                last_acquired_at: Some(req.acquired_at),
            },
        );
        self.batch_origins
            .insert(req.batch_id.clone(), MeritBatchOrigin::BootstrapPurchased);

        Ok(BootstrapMintReceipt {
            batch_id: req.batch_id,
            origin: MeritBatchOrigin::BootstrapPurchased,
            floor_contribution: Decimal::ZERO,
            effective_influence_duration: effective_dur,
        })
    }

    /// Returns the recorded [`MeritBatchOrigin`] of `batch_id`, if tracked here.
    pub fn batch_origin(&self, batch_id: &str) -> Option<MeritBatchOrigin> {
        self.batch_origins.get(batch_id).copied()
    }

    /// Explicit one-way enforcement point: converting Merit back to currency is forbidden.
    pub fn reject_redemption(&self, _batch_id: &str) -> GmcResult<()> {
        Err(GmcError::OperationNotAllowed)
    }

    /// Explicit one-way enforcement point: transferring Merit to another identity is forbidden.
    pub fn reject_transfer(&self, _batch_id: &str, _recipient: &str) -> GmcResult<()> {
        Err(GmcError::OperationNotAllowed)
    }
}

/// One `iFay`'s effective Merit slice participating in governance voting, anchored to
/// its Human Prime's blind `opaqueRef` (`gmcref_...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterIdentitySlice {
    /// Canonical `ifay_` identifier of the voting avatar.
    pub ifay_id: String,
    /// Blind natural-person `gmcref_` commitment in GMChain namespace.
    pub opaque_ref: String,
    /// Non-negative effective Merit (`curMerit`) contributed by this `iFay`.
    pub effective_merit: Decimal,
}

/// Computes Sybil-proof concave (`sqrt`) governance voting weight normalized per
/// natural-person `opaqueRef` (`gmcref_`).
///
/// Aggregating `effective_merit` by `opaqueRef` *before* evaluating the concave
/// fixed-point square root ensures splitting `M` across `N` `iFay`s yields the exact
/// same natural-person voting weight as holding `M` in a single `iFay`.
pub fn compute_normalized_governance_weight(
    slices: &[VoterIdentitySlice],
) -> GmcResult<BTreeMap<String, Decimal>> {
    let mut merit_by_opaque: BTreeMap<String, Decimal> = BTreeMap::new();
    for slice in slices {
        if !is_valid_gmcref(&slice.opaque_ref)
            || slice.ifay_id.trim().is_empty()
            || slice.effective_merit.is_negative()
        {
            return Err(GmcError::FieldValidation);
        }
        let acc = merit_by_opaque
            .get(&slice.opaque_ref)
            .copied()
            .unwrap_or(Decimal::ZERO);
        let updated = acc
            .checked_add(slice.effective_merit)
            .ok_or(GmcError::InvalidMintAmount)?;
        merit_by_opaque.insert(slice.opaque_ref.clone(), updated);
    }

    let mut weights = BTreeMap::new();
    for (opaque_ref, total_merit) in merit_by_opaque {
        weights.insert(opaque_ref, fixed_point_sqrt(total_merit));
    }
    Ok(weights)
}

fn is_valid_gmcref(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("gmcref_") else {
        return false;
    };
    rest.len() >= 16
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Deterministic integer square-root for fixed-point `Decimal` (`scale = 10^6`):
/// `sqrt(M) * 10^6 = isqrt(M_raw * 10^6)`.
fn fixed_point_sqrt(val: Decimal) -> Decimal {
    if val.raw() <= 0 {
        return Decimal::ZERO;
    }
    let scaled = (val.raw() as u128).saturating_mul(1_000_000);
    Decimal::from_raw(isqrt_u128(scaled) as i128)
}

fn isqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x0 = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    loop {
        let x1 = (x0 + n / x0) / 2;
        if x1 >= x0 {
            return x0;
        }
        x0 = x1;
    }
}
