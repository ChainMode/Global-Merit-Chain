//! Reusable `proptest` strategy generators for the `gmc-core` property tests.
//!
//! This is the **skeleton** delivered by task 1.3 (`_Requirements: 5.2_`). Each
//! generator returns a compiling `impl Strategy<Value = ...>` (or [`BoxedStrategy`])
//! over the `gmc-core` public types (task 1.2) plus a handful of lightweight,
//! plain-data request shapes defined here. The later property-test tasks
//! (2.4–2.9, 4.2, 5.3–5.4, 6.4–6.7, 8.4–8.7, 9.4–9.6, 11.x, 12.x, 15.3–15.5,
//! 16.3–16.4, 18.3, 19.3) consume these generators and map them onto the real
//! protocol APIs as those modules land.
//!
//! The generator categories mirror the design's testing strategy:
//!
//! 1. **Derivation-tree request sequences** — [`derivation_sequence`] (derive /
//!    re-parent ops over a small `ChainId` pool, so depth, cycle, self-parent,
//!    missing-field and `(parent, domain)`-uniqueness edge cases all arise).
//! 2. **Scoring weights & inflation indices** — [`dimension_weights`] (mixes
//!    `Σ == 1` and `Σ != 1` samples), [`dimension_weights_sum_one`], and
//!    [`inflation_index_in_range`] / [`inflation_index_any`] / [`inflation_index_entry`]
//!    (in-range and out-of-range per dimension).
//! 3. **Mint amounts / influence durations / time points** — [`mint_amount_any`]
//!    (includes `<= 0`), [`mint_amount_positive`], [`influence_duration`] (`> 0`),
//!    [`timestamp`], [`timestamp_sequence`], [`ascending_timestamps`].
//! 4. **Multi-chain interleaved quota minting** — [`interleaved_mint_sequence`].
//! 5. **Stakeholder pools with normalized intimacy** — [`stakeholder_pool`]
//!    (unique ids, intimacy in `[0, 1]`, naturally includes `> 0.9`).
//! 6. **Carbon-credit repeated declarations** — [`carbon_declaration_sequence`]
//!    (all declarations target the *same* voucher id).
//!
//! These are skeletons: ranges are chosen to cover both the valid input space and
//! its boundaries, but no protocol logic is asserted here. See `common/mod.rs` for
//! the `Feature: gmc-core-protocol, Property N: ...` labelling convention every
//! numbered property test must follow.

use gmc_core::types::{ChainId, Decimal, Dimension, DimensionWeights, FayID, Ratio, Timestamp};
use proptest::prelude::*;
use proptest::sample::subsequence;
use proptest::strategy::BoxedStrategy;

/// Raw scaling factor, equal to `10^Decimal::SCALE_DIGITS` (currently `10^6`).
///
/// Kept as a local constant because `Decimal`'s scale is an implementation detail of
/// that type; generators build raw values directly via [`Decimal::from_raw`].
const SCALE: i128 = 1_000_000;

/// Builds a fixed-point `Decimal` from a value expressed in hundredths (two-decimal
/// precision), e.g. `cents_to_decimal(105)` == `1.05`. Inflation indices in the
/// design are specified to two decimal places.
fn cents_to_decimal(cents: i128) -> Decimal {
    Decimal::from_raw(cents * (SCALE / 100))
}

/// Wraps a raw value known to lie within `[0, SCALE]` into a [`Ratio`].
fn ratio_from_raw(raw: i128) -> Ratio {
    Ratio::new(Decimal::from_raw(raw)).expect("raw value within [0, 1] interval")
}

// ---------------------------------------------------------------------------
// Primitive generators
// ---------------------------------------------------------------------------

/// A [`Ratio`] uniformly drawn from the full closed interval `[0, 1]`.
pub fn ratio() -> impl Strategy<Value = Ratio> {
    (0i128..=SCALE).prop_map(ratio_from_raw)
}

/// A [`ChainId`] drawn from a small fixed pool, so derivation sequences naturally
/// produce id collisions, self-references and duplicate `(parent, domain)` pairs.
pub fn chain_id() -> impl Strategy<Value = ChainId> {
    (0u32..16).prop_map(|n| ChainId::new(format!("chain-{n}")))
}

/// A [`FayID`] drawn from a small fixed pool.
pub fn fay_id() -> impl Strategy<Value = FayID> {
    (0u32..64).prop_map(|n| FayID::new(format!("fay-{n}")))
}

/// A domain identifier, including the empty-string edge case (which later maps to a
/// `MissingField` rejection in `Chain_Registry`).
pub fn domain() -> impl Strategy<Value = String> {
    prop_oneof![
        9 => (0u32..8).prop_map(|n| format!("domain-{n}")),
        1 => Just(String::new()),
    ]
}

/// One of the three scoring [`Dimension`]s.
pub fn dimension() -> impl Strategy<Value = Dimension> {
    prop_oneof![
        Just(Dimension::Thought),
        Just(Dimension::Training),
        Just(Dimension::Technique),
    ]
}

/// A [`Timestamp`] in seconds across a broad range.
pub fn timestamp() -> impl Strategy<Value = Timestamp> {
    (0u64..=4_000_000_000).prop_map(Timestamp::from_secs)
}

// ---------------------------------------------------------------------------
// 1. Derivation-tree request sequences
// ---------------------------------------------------------------------------

/// A single derivation-tree mutation request.
///
/// Skeleton plain-data shape consumed by `Chain_Registry` property tests once
/// task 2.x defines the concrete request types. `Derive` covers new-leaf creation;
/// `Reparent` covers the parent-pointer change that cycle detection must guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationOp {
    /// Create `proposed_id` under `parent_id` in `domain`.
    Derive {
        proposed_id: ChainId,
        parent_id: ChainId,
        domain: String,
    },
    /// Re-attach `chain_id` beneath `new_parent_id` (the cycle-risk operation).
    Reparent {
        chain_id: ChainId,
        new_parent_id: ChainId,
    },
}

/// A single derivation/re-parent operation over the shared `ChainId` pool.
pub fn derivation_op() -> impl Strategy<Value = DerivationOp> {
    prop_oneof![
        3 => (chain_id(), chain_id(), domain()).prop_map(|(proposed_id, parent_id, domain)| {
            DerivationOp::Derive { proposed_id, parent_id, domain }
        }),
        1 => (chain_id(), chain_id()).prop_map(|(chain_id, new_parent_id)| {
            DerivationOp::Reparent { chain_id, new_parent_id }
        }),
    ]
}

/// A sequence of `0..=max_len` derivation-tree operations.
pub fn derivation_sequence(max_len: usize) -> impl Strategy<Value = Vec<DerivationOp>> {
    proptest::collection::vec(derivation_op(), 0..=max_len)
}

// ---------------------------------------------------------------------------
// 2. Scoring weights & inflation indices
// ---------------------------------------------------------------------------

/// `n` positive [`Ratio`] weights whose raw values sum to exactly `SCALE` (i.e. the
/// ratios sum to exactly `1`). Each weight lies in `(0, 1]`.
fn weights_summing_to_one(n: usize) -> BoxedStrategy<Vec<Ratio>> {
    match n {
        0 => Just(Vec::new()).boxed(),
        1 => Just(vec![Ratio::ONE]).boxed(),
        2 => (1i128..SCALE)
            .prop_map(|cut| vec![ratio_from_raw(cut), ratio_from_raw(SCALE - cut)])
            .boxed(),
        _ => (1i128..=(SCALE - 2))
            .prop_flat_map(|a| (Just(a), (a + 1)..SCALE))
            .prop_map(|(a, b)| {
                vec![
                    ratio_from_raw(a),
                    ratio_from_raw(b - a),
                    ratio_from_raw(SCALE - b),
                ]
            })
            .boxed(),
    }
}

/// [`DimensionWeights`] over `1..=3` distinct dimensions whose ratios sum to exactly
/// `1`. Used for the "valid classification" side of scoring properties.
pub fn dimension_weights_sum_one() -> impl Strategy<Value = DimensionWeights> {
    (1usize..=3).prop_flat_map(|n| {
        (
            subsequence(Dimension::ALL.to_vec(), n..=n),
            weights_summing_to_one(n),
        )
            .prop_map(|(dims, weights)| {
                DimensionWeights::from_entries(dims.into_iter().zip(weights))
            })
    })
}

/// [`DimensionWeights`] over `1..=3` distinct dimensions with arbitrary ratios in
/// `[0, 1]` (the sum may or may not equal `1`). Used for the "weight-sum rejection"
/// side of scoring properties.
pub fn dimension_weights_arbitrary() -> impl Strategy<Value = DimensionWeights> {
    (1usize..=3).prop_flat_map(|n| {
        (
            subsequence(Dimension::ALL.to_vec(), n..=n),
            proptest::collection::vec(ratio(), n),
        )
            .prop_map(|(dims, ratios)| DimensionWeights::from_entries(dims.into_iter().zip(ratios)))
    })
}

/// Mixed weight maps: roughly half sum to exactly `1`, half are arbitrary. This is
/// the default generator for scoring properties that must hold for both accepted and
/// rejected weight configurations.
pub fn dimension_weights() -> impl Strategy<Value = DimensionWeights> {
    prop_oneof![dimension_weights_sum_one(), dimension_weights_arbitrary()]
}

/// An inflation index that is **within** the design's valid band for `dim`
/// (Thought `(1.00, 10.00]`, Training `[0.95, 1.05]`, Technique `[0.01, 1.00]`),
/// to two-decimal precision.
pub fn inflation_index_in_range(dim: Dimension) -> impl Strategy<Value = Decimal> {
    let (lo, hi) = match dim {
        Dimension::Thought => (101i128, 1000i128),
        Dimension::Training => (95i128, 105i128),
        Dimension::Technique => (1i128, 100i128),
    };
    (lo..=hi).prop_map(cents_to_decimal)
}

/// An inflation index drawn from a band that extends **beyond** the valid range for
/// `dim`, so both accepted and rejected values are exercised.
pub fn inflation_index_any(dim: Dimension) -> impl Strategy<Value = Decimal> {
    let (lo, hi) = match dim {
        Dimension::Thought => (0i128, 1100i128),
        Dimension::Training => (80i128, 120i128),
        Dimension::Technique => (0i128, 120i128),
    };
    (lo..=hi).prop_map(cents_to_decimal)
}

/// A `(Dimension, Decimal)` inflation-index entry whose value may be in or out of
/// range for that dimension.
pub fn inflation_index_entry() -> impl Strategy<Value = (Dimension, Decimal)> {
    dimension().prop_flat_map(|dim| inflation_index_any(dim).prop_map(move |v| (dim, v)))
}

// ---------------------------------------------------------------------------
// 3. Mint amounts, influence durations, time-point sequences
// ---------------------------------------------------------------------------

/// A mint amount that may be negative, zero, or positive (exercises the
/// `amount <= 0` rejection path in `Minting_Service`).
pub fn mint_amount_any() -> impl Strategy<Value = Decimal> {
    (-1_000_000_000i128..=1_000_000_000i128).prop_map(Decimal::from_raw)
}

/// A strictly positive mint amount (`> 0`).
pub fn mint_amount_positive() -> impl Strategy<Value = Decimal> {
    (1i128..=1_000_000_000i128).prop_map(Decimal::from_raw)
}

/// A non-negative base score for a single dimension (may be zero).
pub fn base_score() -> impl Strategy<Value = Decimal> {
    (0i128..=1_000_000_000i128).prop_map(Decimal::from_raw)
}

/// A strictly positive influence duration (`> 0`), as required by `MeritBatch`.
pub fn influence_duration() -> impl Strategy<Value = Decimal> {
    (1i128..=10_000_000_000i128).prop_map(Decimal::from_raw)
}

/// A sequence of `0..=max_len` arbitrary (unordered) timestamps.
pub fn timestamp_sequence(max_len: usize) -> impl Strategy<Value = Vec<Timestamp>> {
    proptest::collection::vec(timestamp(), 0..=max_len)
}

/// A non-decreasing sequence of `0..=max_len` timestamps, built by accumulating
/// non-negative deltas. Useful for decay / refresh-period evaluation at advancing
/// time points.
pub fn ascending_timestamps(max_len: usize) -> impl Strategy<Value = Vec<Timestamp>> {
    proptest::collection::vec(0u64..=10_000_000u64, 0..=max_len).prop_map(|deltas| {
        let mut now = 0u64;
        let mut out = Vec::with_capacity(deltas.len());
        for d in deltas {
            now = now.saturating_add(d);
            out.push(Timestamp::from_secs(now));
        }
        out
    })
}

// ---------------------------------------------------------------------------
// 4. Multi-chain interleaved quota minting sequences
// ---------------------------------------------------------------------------

/// A single mint request against a named chain.
///
/// Skeleton plain-data shape consumed by quota property tests once task 6.x defines
/// the concrete `MintRequest`. The small `ChainId` pool guarantees requests for
/// different chains interleave, exercising per-chain quota isolation.
#[derive(Debug, Clone, PartialEq)]
pub struct MintOp {
    pub chain_id: ChainId,
    pub amount: Decimal,
}

/// A sequence of `0..=max_len` interleaved mint requests across multiple chains.
pub fn interleaved_mint_sequence(max_len: usize) -> impl Strategy<Value = Vec<MintOp>> {
    let op =
        (chain_id(), mint_amount_any()).prop_map(|(chain_id, amount)| MintOp { chain_id, amount });
    proptest::collection::vec(op, 0..=max_len)
}

// ---------------------------------------------------------------------------
// 5. Stakeholder pools with normalized intimacy distributions
// ---------------------------------------------------------------------------

/// A stakeholder with a normalized intimacy (`[0, 1]`) relative to the contributor.
///
/// Skeleton plain-data shape consumed by `AntiFraud_Engine` voter-selection tests
/// (task 12.x). Ids are unique within a pool; intimacy spans `[0, 1]`, so values
/// above the `0.9` exclusion threshold occur naturally.
#[derive(Debug, Clone, PartialEq)]
pub struct Stakeholder {
    pub id: FayID,
    pub intimacy: Ratio,
}

/// A stakeholder pool of `0..=max_size` members with unique ids and intimacy in
/// `[0, 1]`.
pub fn stakeholder_pool(max_size: usize) -> impl Strategy<Value = Vec<Stakeholder>> {
    proptest::collection::vec(ratio(), 0..=max_size).prop_map(|intimacies| {
        intimacies
            .into_iter()
            .enumerate()
            .map(|(i, intimacy)| Stakeholder {
                id: FayID::new(format!("stakeholder-{i}")),
                intimacy,
            })
            .collect()
    })
}

/// A voter together with its `curMerit` value, for weighted-tally properties
/// (task 4.2 / 11.5). `curMerit` is non-negative.
#[derive(Debug, Clone, PartialEq)]
pub struct VoterWeight {
    pub id: FayID,
    pub cur_merit: Decimal,
}

/// A set of `1..=max_size` voters with unique ids and non-negative `curMerit`.
pub fn voter_weights(max_size: usize) -> impl Strategy<Value = Vec<VoterWeight>> {
    let size = max_size.max(1);
    proptest::collection::vec(0i128..=1_000_000_000i128, 1..=size).prop_map(|merits| {
        merits
            .into_iter()
            .enumerate()
            .map(|(i, raw)| VoterWeight {
                id: FayID::new(format!("voter-{i}")),
                cur_merit: Decimal::from_raw(raw),
            })
            .collect()
    })
}

// ---------------------------------------------------------------------------
// 6. Carbon-credit repeated-declaration sequences over one voucher id
// ---------------------------------------------------------------------------

/// A carbon-credit conversion declaration referencing a voucher.
///
/// Skeleton plain-data shape consumed by carbon-scenario tests (task 16.x). A whole
/// generated sequence targets the **same** `voucher_id` to exercise the
/// at-most-once conversion guard (`DoubleConversion`).
#[derive(Debug, Clone, PartialEq)]
pub struct CarbonDeclaration {
    pub voucher_id: String,
    pub contributor_id: FayID,
    /// Whether the attached evidence is independently replayable/verifiable.
    pub valid_evidence: bool,
}

/// A sequence of `1..=max_len` declarations, **all** referencing the same voucher id.
pub fn carbon_declaration_sequence(
    max_len: usize,
) -> impl Strategy<Value = Vec<CarbonDeclaration>> {
    let len = max_len.max(1);
    (
        0u32..4,
        proptest::collection::vec((fay_id(), any::<bool>()), 1..=len),
    )
        .prop_map(|(voucher, decls)| {
            let voucher_id = format!("voucher-{voucher}");
            decls
                .into_iter()
                .map(|(contributor_id, valid_evidence)| CarbonDeclaration {
                    voucher_id: voucher_id.clone(),
                    contributor_id,
                    valid_evidence,
                })
                .collect()
        })
}
