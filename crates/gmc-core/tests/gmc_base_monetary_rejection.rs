//! Monetary-exchange / purchase-of-recognition rejection unit tests for `GMC_Base`
//! (task 13.2).
//!
//! **Validates: Requirements 11.8**
//!
//! Requirement 11.8 (design "Error Handling": 收到任何以货币注资兑换 MeriToken 或购买
//! 贡献认定的请求 → `OperationNotAllowed`，拒绝，不铸造任何 MeriToken，不变更任何认定结果):
//! any request that funds currency to exchange for / mint MeriToken, or that pays to
//! purchase a contribution-recognition result, must
//!
//! - return [`GmcError::OperationNotAllowed`],
//! - mint **no** MeriToken (no new Merit batch; `curMerit` / `minMerit` unchanged), and
//! - change **no** recognition result (the recorded top-level recognition categories
//!   are left byte-for-byte identical).
//!
//! These are plain `#[test]` example/edge-case tests (not numbered properties), so
//! they carry no `Feature: ... Property N` label.

use gmc_core::error::GmcError;
use gmc_core::gmc_base::{GmcBase, MonetaryRequest, MonetaryRequestKind};
use gmc_core::merit::{MeritBatch, MeritPocket, E};
use gmc_core::types::{ChainId, Decimal, FayID, Timestamp};

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(secs)
}

/// A `GMC_Base` root that already carries some recorded top-level recognition
/// categories, so the "no recognition result changes" assertion is meaningful (a
/// rejected request must neither add, remove nor alter any of them).
fn base_with_recognition() -> GmcBase {
    let mut base = GmcBase::new();
    base.record_top_level_category("academic");
    base.record_top_level_category("public-good");
    base.record_top_level_category("environment");
    base
}

/// A pocket holding already-minted MeriToken (one slowly-decaying backing batch) so a
/// rejected monetary request can be shown to mint nothing: the batch count stays put
/// and `curMerit` is unchanged at every sampled time point.
fn pocket_with_minted_meritoken() -> MeritPocket {
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

/// Time points at which `curMerit` is sampled before and after a rejected request.
const SAMPLE_TIMES: [u64; 7] = [0, 100, 1_000, 10_000, 100_000, 1_000_000, 100_000_000];

/// Every monetary-style request used across the tests. Per Requirement 11.8 the
/// rejection is unconditional, so we cover both request kinds and a spread of
/// requesters / target chains / offered funding (including absurd amounts).
fn disallowed_requests() -> Vec<MonetaryRequest> {
    vec![
        MonetaryRequest::fund_for_meritoken("gmc-base", "1000 USD"),
        MonetaryRequest::fund_for_meritoken("academic", "5 BTC"),
        MonetaryRequest::fund_for_meritoken("public-good", ""),
        MonetaryRequest::purchase_recognition("environment", "10000000 EUR"),
        MonetaryRequest::purchase_recognition("gmc-base", "a yacht"),
        MonetaryRequest::purchase_recognition("academic", "huge pile of money"),
    ]
}

#[test]
fn fund_for_meritoken_request_is_rejected_with_operation_not_allowed() {
    // Req 11.8: funding currency to exchange for / mint MeriToken is disallowed.
    let base = GmcBase::new();
    let req = MonetaryRequest::fund_for_meritoken("gmc-base", "1000 USD");
    assert_eq!(req.kind, MonetaryRequestKind::FundForMeriToken);
    assert_eq!(
        base.reject_monetary_request(&req),
        Err(GmcError::OperationNotAllowed)
    );
}

#[test]
fn purchase_recognition_request_is_rejected_with_operation_not_allowed() {
    // Req 11.8: paying to purchase a contribution-recognition result is disallowed.
    let base = GmcBase::new();
    let req = MonetaryRequest::purchase_recognition("academic", "5 BTC");
    assert_eq!(req.kind, MonetaryRequestKind::PurchaseRecognition);
    assert_eq!(
        base.reject_monetary_request(&req),
        Err(GmcError::OperationNotAllowed)
    );
}

#[test]
fn every_monetary_request_variant_is_rejected_regardless_of_amount() {
    // Req 11.8: rejection is unconditional — every kind, requester, target chain and
    // offered funding (including empty and absurd amounts) yields OperationNotAllowed.
    let base = base_with_recognition();
    for req in disallowed_requests() {
        assert_eq!(
            base.reject_monetary_request(&req),
            Err(GmcError::OperationNotAllowed),
            "request was not rejected: {req:?}"
        );
    }
}

#[test]
fn rejected_monetary_request_mints_no_meritoken() {
    // Req 11.8: a rejected monetary request mints no MeriToken. We hold a pocket of
    // already-minted MeriToken alongside the rejection and assert nothing is minted:
    // no new batch, and curMerit / minMerit unchanged at every sampled time point.
    let base = base_with_recognition();
    let pocket = pocket_with_minted_meritoken();

    let batches_before = pocket.batches.len();
    let floor_before = pocket.min_merit();
    let cur_before: Vec<Decimal> = SAMPLE_TIMES
        .iter()
        .map(|&t| pocket.cur_merit(ts(t)))
        .collect();
    let pocket_snapshot = pocket.clone();

    for req in disallowed_requests() {
        assert_eq!(
            base.reject_monetary_request(&req),
            Err(GmcError::OperationNotAllowed)
        );
    }

    // No MeriToken was minted: batch count, floor and curMerit are all untouched.
    assert_eq!(pocket.batches.len(), batches_before);
    assert_eq!(pocket.min_merit(), floor_before);
    for (&t, &before) in SAMPLE_TIMES.iter().zip(cur_before.iter()) {
        assert_eq!(
            pocket.cur_merit(ts(t)),
            before,
            "curMerit changed at t={t} after a rejected monetary request"
        );
    }
    // Whole-state equality: provably no partial write to the pocket.
    assert_eq!(pocket, pocket_snapshot);
}

#[test]
fn rejected_monetary_request_changes_no_recognition_result() {
    // Req 11.8: a rejected request changes no recognition result. Recognition results
    // are modelled by the recorded top-level recognition categories; a rejected
    // monetary request must neither add, remove nor alter any of them.
    let base = base_with_recognition();
    let before = base.clone();

    for req in disallowed_requests() {
        assert_eq!(
            base.reject_monetary_request(&req),
            Err(GmcError::OperationNotAllowed)
        );
    }

    // Recognition state is byte-for-byte identical after every rejected request.
    assert_eq!(base, before);
    assert_eq!(base.category_count(), 3);
    assert!(base.has_top_level_category("academic"));
    assert!(base.has_top_level_category("public-good"));
    assert!(base.has_top_level_category("environment"));
    let categories: Vec<&str> = base.top_level_categories().collect();
    assert_eq!(categories, vec!["academic", "environment", "public-good"]);
}

#[test]
fn repeated_monetary_requests_never_mint_or_change_recognition() {
    // Req 11.8: repeating the requests never accumulates any effect — neither a mint
    // nor a recognition change ever leaks through across many attempts.
    let base = base_with_recognition();
    let base_snapshot = base.clone();
    let pocket = pocket_with_minted_meritoken();
    let pocket_snapshot = pocket.clone();

    for _ in 0..50 {
        for req in disallowed_requests() {
            assert_eq!(
                base.reject_monetary_request(&req),
                Err(GmcError::OperationNotAllowed)
            );
        }
    }

    // Nothing minted and no recognition result changed after 50 rounds.
    assert_eq!(pocket, pocket_snapshot);
    assert_eq!(pocket.batches.len(), 1);
    assert_eq!(pocket.min_merit(), E);
    assert_eq!(base, base_snapshot);
}
