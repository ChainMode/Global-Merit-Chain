//! Core shared primitive types for the GMC (Global Merit Chain) pure-logic core.
//!
//! Per the design's *Data Models* section, every amount/ratio field uses a
//! **fixed-point decimal** representation to avoid floating-point error. This module
//! defines those shared primitives so later protocol modules (scoring, decay, quota,
//! minting, governance, …) all speak the same numeric and identity language:
//!
//! - [`Decimal`] — a fixed-point decimal (i128 scaled by [`Decimal::SCALE_DIGITS`]
//!   fractional digits). All "amount" math goes through this type.
//! - [`Ratio`] — a [`Decimal`] constrained to the closed interval `[0, 1]`; used for
//!   weights, consensus thresholds and normalized intimacy.
//! - [`ChainId`] / [`FayID`] — opaque string-backed identity newtypes.
//! - [`Timestamp`] — on-chain (block) time.
//! - [`Dimension`] / [`DimensionWeights`] — the three scoring dimensions
//!   (Thought / Training / Technique) and the 1..=3 weight map over them.
//!
//! This module is deliberately dependency-free (no `error` import): it provides only
//! shared primitives. Domain validation that maps to a specific machine-identifiable
//! error code lives in the protocol modules that own the rule (e.g. scoring task 8.1
//! maps a non-unit weight sum to [`crate::error::GmcError::WeightSumInvalid`]).

use core::fmt;
use std::collections::BTreeMap;

/// Fixed-point decimal backed by an `i128` scaled integer.
///
/// The stored raw value represents `raw / 10^SCALE_DIGITS`. Using a scaled integer
/// keeps all arithmetic deterministic and free of binary floating-point rounding
/// error, which matters because MeriToken amounts, ratios and inflation indices must
/// reproduce identically across the L1 pallet and the L2 rollup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Decimal(i128);

impl Decimal {
    /// Number of fractional decimal digits carried by the fixed-point representation.
    pub const SCALE_DIGITS: u32 = 6;

    /// `10^SCALE_DIGITS` — the scaling factor between the raw integer and its value.
    pub const SCALE: i128 = 1_000_000;

    /// The value `0`.
    pub const ZERO: Decimal = Decimal(0);

    /// The value `1`.
    pub const ONE: Decimal = Decimal(Self::SCALE);

    /// Builds a `Decimal` directly from its scaled (raw) integer representation.
    #[inline]
    pub const fn from_raw(raw: i128) -> Self {
        Decimal(raw)
    }

    /// Returns the underlying scaled (raw) integer.
    #[inline]
    pub const fn raw(self) -> i128 {
        self.0
    }

    /// Builds a `Decimal` from a whole integer value.
    #[inline]
    pub const fn from_int(value: i64) -> Self {
        Decimal(value as i128 * Self::SCALE)
    }

    /// Parses a decimal string such as `"1.05"`, `"-0.95"` or `"2.718281"`.
    ///
    /// Fractional digits beyond [`Decimal::SCALE_DIGITS`] are truncated. Returns
    /// `None` when the input is not a well-formed decimal number.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Decimal> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (negative, rest) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        if rest.is_empty() {
            return None;
        }

        let mut parts = rest.splitn(2, '.');
        let int_part = parts.next().unwrap_or("");
        let frac_part = parts.next().unwrap_or("");

        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }

        let int_val: i128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse().ok()?
        };

        // Pad or truncate the fractional part to exactly SCALE_DIGITS digits.
        let mut frac_val: i128 = 0;
        for i in 0..Self::SCALE_DIGITS as usize {
            let digit = frac_part
                .as_bytes()
                .get(i)
                .map(|b| (b - b'0') as i128)
                .unwrap_or(0);
            frac_val = frac_val * 10 + digit;
        }

        let raw = int_val.checked_mul(Self::SCALE)?.checked_add(frac_val)?;
        Some(Decimal(if negative { -raw } else { raw }))
    }

    /// Checked addition. Returns `None` on overflow.
    #[inline]
    pub fn checked_add(self, other: Decimal) -> Option<Decimal> {
        self.0.checked_add(other.0).map(Decimal)
    }

    /// Checked subtraction. Returns `None` on overflow.
    #[inline]
    pub fn checked_sub(self, other: Decimal) -> Option<Decimal> {
        self.0.checked_sub(other.0).map(Decimal)
    }

    /// Checked multiplication (fixed-point, truncating toward zero).
    ///
    /// Returns `None` if the intermediate product overflows `i128`.
    #[inline]
    pub fn checked_mul(self, other: Decimal) -> Option<Decimal> {
        let product = self.0.checked_mul(other.0)?;
        Some(Decimal(product / Self::SCALE))
    }

    /// Checked division (fixed-point, truncating toward zero).
    ///
    /// Returns `None` on division by zero or intermediate overflow.
    #[inline]
    pub fn checked_div(self, other: Decimal) -> Option<Decimal> {
        if other.0 == 0 {
            return None;
        }
        let scaled = self.0.checked_mul(Self::SCALE)?;
        Some(Decimal(scaled / other.0))
    }

    /// Returns `true` if the value is exactly zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if the value is strictly greater than zero.
    #[inline]
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// Returns `true` if the value is strictly less than zero.
    #[inline]
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let abs = self.0.unsigned_abs();
        let scale = Self::SCALE as u128;
        let int_part = abs / scale;
        let frac_part = abs % scale;
        if frac_part == 0 {
            write!(f, "{sign}{int_part}")
        } else {
            let mut frac_str =
                format!("{:0width$}", frac_part, width = Self::SCALE_DIGITS as usize);
            while frac_str.ends_with('0') {
                frac_str.pop();
            }
            write!(f, "{sign}{int_part}.{frac_str}")
        }
    }
}

/// A [`Decimal`] constrained to the closed interval `[0, 1]`.
///
/// Used for dimension weights, consensus/governance thresholds and normalized
/// intimacy. Construction rejects any value outside `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ratio(Decimal);

impl Ratio {
    /// The ratio `0`.
    pub const ZERO: Ratio = Ratio(Decimal::ZERO);

    /// The ratio `1` (i.e. 100%).
    pub const ONE: Ratio = Ratio(Decimal::ONE);

    /// Builds a `Ratio`, returning `None` if `value` lies outside `[0, 1]`.
    #[inline]
    pub const fn new(value: Decimal) -> Option<Ratio> {
        if value.raw() >= 0 && value.raw() <= Decimal::SCALE {
            Some(Ratio(value))
        } else {
            None
        }
    }

    /// Builds a `Ratio` from an integer percentage in `0..=100` (e.g. `66` -> 0.66).
    pub fn from_percent(percent: u8) -> Option<Ratio> {
        if percent > 100 {
            return None;
        }
        Decimal::from_int(percent as i64)
            .checked_div(Decimal::from_int(100))
            .and_then(Ratio::new)
    }

    /// Returns the underlying [`Decimal`] value.
    #[inline]
    pub const fn value(self) -> Decimal {
        self.0
    }

    /// Returns `true` if the ratio is exactly zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }
}

impl fmt::Display for Ratio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Opaque identifier of a functioning merit chain (`Nested_Merit_Chain` / `GMC_Base`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ChainId(String);

impl ChainId {
    /// Builds a `ChainId` from any string-like value.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        ChainId(id.into())
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if the identifier is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for ChainId {
    fn from(value: String) -> Self {
        ChainId(value)
    }
}

impl From<&str> for ChainId {
    fn from(value: &str) -> Self {
        ChainId(value.to_owned())
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque identity reference (a Fay identity in the GMC blueprint).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FayID(String);

impl FayID {
    /// Builds a `FayID` from any string-like value.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        FayID(id.into())
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if the identifier is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for FayID {
    fn from(value: String) -> Self {
        FayID(value)
    }
}

impl From<&str> for FayID {
    fn from(value: &str) -> Self {
        FayID(value.to_owned())
    }
}

impl fmt::Display for FayID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// On-chain (block) timestamp, expressed as a count of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Builds a `Timestamp` from a raw second count.
    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Timestamp(secs)
    }

    /// Returns the raw second count.
    #[inline]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Returns the non-negative number of seconds elapsed from `earlier` to `self`,
    /// saturating at zero when `earlier` is later than `self`.
    #[inline]
    pub const fn saturating_elapsed_since(self, earlier: Timestamp) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// The three GMC scoring dimensions (`requirements.md` Requirement 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dimension {
    /// Contributions that lead cognitive breakthroughs (research, invention).
    Thought,
    /// Contributions that rapidly disseminate / improve efficiency (e.g. training AI).
    Training,
    /// Contributions delivering value through skill or craft (service, performance).
    Technique,
}

impl Dimension {
    /// All three dimensions, in a stable order.
    pub const ALL: [Dimension; 3] = [
        Dimension::Thought,
        Dimension::Training,
        Dimension::Technique,
    ];
}

/// A weight map over the three scoring [`Dimension`]s.
///
/// Per the design's data model this holds 1..=3 entries whose [`Ratio`] values are
/// each in `(0, 1]` and are intended to sum to exactly `1`. This type only provides
/// the container plus the [`weight_sum`](DimensionWeights::weight_sum) helper; the
/// scoring engine (task 8.1) enforces the size and `Σ == 1` invariants, mapping
/// failures to [`crate::error::GmcError::DimensionUnmatched`] (Requirement 6.6) and
/// [`crate::error::GmcError::WeightSumInvalid`] (Requirement 6.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DimensionWeights {
    weights: BTreeMap<Dimension, Ratio>,
}

impl DimensionWeights {
    /// Creates an empty weight map.
    pub fn new() -> Self {
        DimensionWeights {
            weights: BTreeMap::new(),
        }
    }

    /// Builds a weight map from an iterator of `(Dimension, Ratio)` entries.
    pub fn from_entries(entries: impl IntoIterator<Item = (Dimension, Ratio)>) -> Self {
        DimensionWeights {
            weights: entries.into_iter().collect(),
        }
    }

    /// Inserts a dimension weight, returning the previous value if one existed.
    pub fn insert(&mut self, dimension: Dimension, ratio: Ratio) -> Option<Ratio> {
        self.weights.insert(dimension, ratio)
    }

    /// Returns the weight for `dimension`, if present.
    pub fn get(&self, dimension: Dimension) -> Option<Ratio> {
        self.weights.get(&dimension).copied()
    }

    /// Number of dimensions present (expected to be in `1..=3`).
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Returns `true` if no dimensions are present.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    /// Iterates over the dimensions present, in a stable order.
    pub fn dimensions(&self) -> impl Iterator<Item = Dimension> + '_ {
        self.weights.keys().copied()
    }

    /// Iterates over `(Dimension, Ratio)` entries, in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = (Dimension, Ratio)> + '_ {
        self.weights.iter().map(|(dim, ratio)| (*dim, *ratio))
    }

    /// Sum of all dimension ratios as a [`Decimal`]. Returns `None` on overflow.
    ///
    /// The scoring engine uses this to enforce `Σ == 1` (Requirement 6.7).
    pub fn weight_sum(&self) -> Option<Decimal> {
        let mut sum = Decimal::ZERO;
        for ratio in self.weights.values() {
            sum = sum.checked_add(ratio.value())?;
        }
        Some(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // --- Decimal: unit tests ------------------------------------------------

    #[test]
    fn decimal_from_int_and_raw_roundtrip() {
        assert_eq!(Decimal::from_int(5).raw(), 5 * Decimal::SCALE);
        assert_eq!(
            Decimal::from_raw(2_718_281),
            Decimal::from_str("2.718281").unwrap()
        );
    }

    #[test]
    fn decimal_arithmetic_is_fixed_point() {
        let half = Decimal::from_str("0.5").unwrap();
        let two = Decimal::from_int(2);
        // 0.5 + 0.5 == 1
        assert_eq!(half.checked_add(half), Some(Decimal::ONE));
        // 0.5 * 2 == 1, exactly (no float error)
        assert_eq!(half.checked_mul(two), Some(Decimal::ONE));
        // 1 / 2 == 0.5
        assert_eq!(Decimal::ONE.checked_div(two), Some(half));
        // 1 - 0.5 == 0.5
        assert_eq!(Decimal::ONE.checked_sub(half), Some(half));
    }

    #[test]
    fn decimal_div_by_zero_is_none() {
        assert_eq!(Decimal::ONE.checked_div(Decimal::ZERO), None);
    }

    #[test]
    fn decimal_sign_helpers() {
        assert!(Decimal::from_int(3).is_positive());
        assert!(Decimal::from_int(-3).is_negative());
        assert!(Decimal::ZERO.is_zero());
    }

    #[test]
    fn decimal_display_trims_trailing_zeros() {
        assert_eq!(Decimal::from_str("1.50").unwrap().to_string(), "1.5");
        assert_eq!(Decimal::from_int(2).to_string(), "2");
        assert_eq!(Decimal::from_str("-0.95").unwrap().to_string(), "-0.95");
    }

    #[test]
    fn decimal_from_str_rejects_garbage() {
        assert_eq!(Decimal::from_str(""), None);
        assert_eq!(Decimal::from_str("abc"), None);
        assert_eq!(Decimal::from_str("1.2.3"), None);
        assert_eq!(Decimal::from_str("-"), None);
    }

    #[test]
    fn decimal_ordering() {
        assert!(Decimal::from_str("0.95").unwrap() < Decimal::ONE);
        assert!(Decimal::from_int(10) > Decimal::ONE);
    }

    // --- Ratio: unit tests --------------------------------------------------

    #[test]
    fn ratio_accepts_boundaries() {
        assert!(Ratio::new(Decimal::ZERO).is_some());
        assert!(Ratio::new(Decimal::ONE).is_some());
        assert_eq!(
            Ratio::new(Decimal::from_str("0.66").unwrap())
                .unwrap()
                .value(),
            Decimal::from_str("0.66").unwrap()
        );
    }

    #[test]
    fn ratio_rejects_out_of_range() {
        assert!(Ratio::new(Decimal::from_str("-0.01").unwrap()).is_none());
        assert!(Ratio::new(Decimal::from_str("1.01").unwrap()).is_none());
    }

    #[test]
    fn ratio_from_percent() {
        assert_eq!(Ratio::from_percent(0), Some(Ratio::ZERO));
        assert_eq!(Ratio::from_percent(100), Some(Ratio::ONE));
        assert_eq!(
            Ratio::from_percent(66).unwrap().value(),
            Decimal::from_str("0.66").unwrap()
        );
        assert_eq!(Ratio::from_percent(101), None);
    }

    // --- Identity & timestamp ----------------------------------------------

    #[test]
    fn chain_and_fay_ids() {
        let c = ChainId::from("gmc-base");
        assert_eq!(c.as_str(), "gmc-base");
        assert!(!c.is_empty());
        assert!(ChainId::new(String::new()).is_empty());

        let f = FayID::new("fay-1");
        assert_eq!(f.to_string(), "fay-1");
    }

    #[test]
    fn timestamp_elapsed_saturates() {
        let t0 = Timestamp::from_secs(100);
        let t1 = Timestamp::from_secs(160);
        assert_eq!(t1.saturating_elapsed_since(t0), 60);
        assert_eq!(t0.saturating_elapsed_since(t1), 0);
    }

    // --- DimensionWeights ---------------------------------------------------

    #[test]
    fn dimension_weights_sum() {
        let weights = DimensionWeights::from_entries([
            (Dimension::Thought, Ratio::from_percent(70).unwrap()),
            (Dimension::Technique, Ratio::from_percent(30).unwrap()),
        ]);
        assert_eq!(weights.len(), 2);
        assert_eq!(weights.weight_sum(), Some(Decimal::ONE));
        assert_eq!(weights.get(Dimension::Thought), Ratio::from_percent(70));
        assert_eq!(weights.get(Dimension::Training), None);
    }

    #[test]
    fn dimension_weights_non_unit_sum_is_detectable() {
        // The container itself does not reject this; scoring task 8.1 does. Here we
        // only confirm the sum helper surfaces the discrepancy.
        let weights = DimensionWeights::from_entries([
            (Dimension::Thought, Ratio::from_percent(70).unwrap()),
            (Dimension::Technique, Ratio::from_percent(40).unwrap()),
        ]);
        assert_ne!(weights.weight_sum(), Some(Decimal::ONE));
    }

    // --- Property-based tests for the numeric primitives --------------------
    // These validate the fixed-point primitives themselves; they are NOT the
    // numbered design properties (Property 1-30), which live in dedicated tasks.

    proptest! {
        #[test]
        fn prop_decimal_add_is_commutative(a in -1_000_000_000_000i128..1_000_000_000_000i128,
                                           b in -1_000_000_000_000i128..1_000_000_000_000i128) {
            let da = Decimal::from_raw(a);
            let db = Decimal::from_raw(b);
            prop_assert_eq!(da.checked_add(db), db.checked_add(da));
        }

        #[test]
        fn prop_decimal_mul_by_one_is_identity(a in -1_000_000_000_000i128..1_000_000_000_000i128) {
            let da = Decimal::from_raw(a);
            prop_assert_eq!(da.checked_mul(Decimal::ONE), Some(da));
        }

        #[test]
        fn prop_decimal_order_matches_raw(a in -1_000_000_000_000i128..1_000_000_000_000i128,
                                          b in -1_000_000_000_000i128..1_000_000_000_000i128) {
            let da = Decimal::from_raw(a);
            let db = Decimal::from_raw(b);
            prop_assert_eq!(da.cmp(&db), a.cmp(&b));
        }

        #[test]
        fn prop_ratio_new_accepts_iff_in_unit_interval(raw in -2_000_000i128..2_000_000i128) {
            let d = Decimal::from_raw(raw);
            let in_range = raw >= 0 && raw <= Decimal::ONE.raw();
            prop_assert_eq!(Ratio::new(d).is_some(), in_range);
        }
    }
}
