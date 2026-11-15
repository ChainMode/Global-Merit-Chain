//! Invalid-mint unit tests for `Minting_Service` (task 9.6).
//!
//! **Validates: Requirements 8.7**
//!
//! Requirement 8.7 (design "Error Handling": 铸造 数量 ≤ 0 → `InvalidMintAmount`,
//! 拒绝，不创建批次，curMerit/minMerit 不变): a mint whose `amount <= 0` must
//!
//! - return [`GmcError::InvalidMintAmount`],
//! - create **no** batch,
//! - leave the pocket's `curMerit` (at every time point) and `minMerit` unchanged, and
//! - leave the quota ledger's consumption counter unchanged.
//!
//! These are plain `#[test]` example/edge-case tests (not numbered properties), so
//! they carry no `Feature: ... Property N` label.

use gmc_core::error::GmcError;
use gmc_core::merit::{MeritBatch, MeritPocket, E};
use gmc_core::minting::{MintRequest, MintingService};
use gmc_core::quota::{QuotaConfig, QuotaLedger, RefreshPeriod, TimeUnit};
use gmc_core::types::{ChainId, Decimal, FayID, Timestamp};

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(secs)
}

/// A periodic quota config with plenty of headroom, so the only thing that can reject
/// a mint here is the non-positive-amount check (not the quota).
fn cfg() -> QuotaConfig {
    QuotaConfig::new(
        Decimal::from_int(1_000),
        RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: Decimal::ONE,
        },
    )
    .expect("valid periodic config")
}

fn fresh_ledger() -> QuotaLedger {
    QuotaLedger::new(ChainId::from("chain-1"), ts(0))
}

/// A pocket whose initial floor `E` is *backed* by a slowly-decaying batch with
/// `B = E`. This gives the pocket a non-trivial, time-varying `curMerit` so the
/// "curMerit unchanged" assertion is meaningful at multiple time points.
fn backed_pocket() -> MeritPocket {
    let mut pocket = MeritPocket::new(FayID::from("fay-1"));
    pocket.add_batch(MeritBatch::new(
        "reg-grant",
        Decimal::from_int(100), // V
        E,                      // B = initial floor
        Decimal::from_str("0.001").expect("valid lambda"),
        Decimal::from_int(1_000),
        ts(0),
        ChainId::from("chain-1"),
    ));
    pocket
}

/// Time points at which `curMerit` is sampled before and after a rejected mint.
const SAMPLE_TIMES: [u64; 7] = [0, 100, 1_000, 10_000, 100_000, 1_000_000, 100_000_000];

/// Drives one rejected mint with `bad_amount` and asserts Requirement 8.7 in full:
/// the error code, no new batch, unchanged `minMerit`, unchanged `curMerit` at every
/// sampled time, unchanged quota consumption, and whole-state equality of both
/// collaborators (proving no partial write).
fn assert_rejects_and_leaves_state_unchanged(bad_amount: Decimal) {
    let service = MintingService::new();
    let config = cfg();
    let mut ledger = fresh_ledger();
    let mut pocket = backed_pocket();

    // Snapshot everything the mint could touch.
    let batches_before = pocket.batches.len();
    let floor_before = pocket.min_merit();
    let minted_before = ledger.minted_this_period();
    let cur_before: Vec<Decimal> = SAMPLE_TIMES
        .iter()
        .map(|&t| pocket.cur_merit(ts(t)))
        .collect();
    let pocket_snapshot = pocket.clone();
    let ledger_snapshot = ledger.clone();

    let err = service
        .mint(
            &mut pocket,
            &config,
            &mut ledger,
            MintRequest::new(
                "bad-mint",
                bad_amount,
                Decimal::from_int(1_000),
                ts(100),
                ChainId::from("chain-1"),
            ),
        )
        .expect_err("a non-positive amount must be rejected");

    // (1) Returns InvalidMintAmount (Requirement 8.7).
    assert_eq!(err, GmcError::InvalidMintAmount);

    // (2) No batch was created.
    assert_eq!(pocket.batches.len(), batches_before);

    // (3) minMerit is unchanged.
    assert_eq!(pocket.min_merit(), floor_before);

    // (4) curMerit is unchanged at every sampled time point.
    for (&t, &before) in SAMPLE_TIMES.iter().zip(cur_before.iter()) {
        assert_eq!(
            pocket.cur_merit(ts(t)),
            before,
            "curMerit changed at t={t} for amount {bad_amount}"
        );
    }

    // (5) Quota ledger consumption is unchanged.
    assert_eq!(ledger.minted_this_period(), minted_before);

    // (6) Whole-state equality: provably no partial write to either collaborator.
    assert_eq!(pocket, pocket_snapshot);
    assert_eq!(ledger, ledger_snapshot);
}

#[test]
fn mint_with_zero_amount_is_rejected_and_changes_nothing() {
    assert_rejects_and_leaves_state_unchanged(Decimal::ZERO);
}

#[test]
fn mint_with_negative_amount_is_rejected_and_changes_nothing() {
    assert_rejects_and_leaves_state_unchanged(Decimal::from_int(-5));
    // A sub-unit negative amount must be rejected just the same.
    assert_rejects_and_leaves_state_unchanged(Decimal::from_str("-0.000001").unwrap());
}

#[test]
fn rejected_mint_does_not_consume_quota_even_when_repeated() {
    // Repeated invalid mints never accumulate quota and never create batches: the
    // ledger counter stays at zero and the pocket keeps its single backing batch.
    let service = MintingService::new();
    let config = cfg();
    let mut ledger = fresh_ledger();
    let mut pocket = backed_pocket();

    for bad in [
        Decimal::ZERO,
        Decimal::from_int(-1),
        Decimal::from_int(-100),
    ] {
        let err = service
            .mint(
                &mut pocket,
                &config,
                &mut ledger,
                MintRequest::new(
                    "bad-mint",
                    bad,
                    Decimal::from_int(1_000),
                    ts(200),
                    ChainId::from("chain-1"),
                ),
            )
            .expect_err("a non-positive amount must be rejected");
        assert_eq!(err, GmcError::InvalidMintAmount);
    }

    assert_eq!(pocket.batches.len(), 1);
    assert_eq!(pocket.min_merit(), E);
    assert_eq!(ledger.minted_this_period(), Decimal::ZERO);
}
