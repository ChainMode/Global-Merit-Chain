//! Post-hoc collusion clawback unit tests (task 12.5).
//!
//! **Validates: Requirements 11.6**
//!
//! Requirement 11.6: *IF the `AntiFraud_Engine` detects collusion vote-fraud after a
//! recognition has already passed, THEN it SHALL — per the existing penalty mechanism
//! — initiate retroactive penalties on all participants, **revoke that recognition
//! result**, **claw back the MeriToken minted by that recognition**, and **anchor the
//! handling result** to `L1_Settlement`.*
//!
//! `gmc-core` exposes no single `clawback()` function; Requirement 11.6 is realised by
//! **composing the existing pure-logic APIs** the way the integration layer would:
//!
//! - **Collusion detection** — [`antifraud::detect_anomaly`] /
//!   [`AntiFraudEngine::record_if_anomalous`] flag the colluding voters' anomalous
//!   approve-voting (Requirement 11.4 is the detector that feeds 11.6).
//! - **Mint reversal (回收 MeriToken)** — the fraudulent mint added exactly one
//!   [`MeritBatch`] to the contributor's [`MeritPocket`] and raised its `minMerit`
//!   floor. The clawback removes that batch and restores `minMerit` to its pre-mint
//!   value, returning the pocket **byte-for-byte** to its pre-mint state (a consistent
//!   rollback: `curMerit(t)` at every time `t` and `minMerit` are both restored).
//! - **Revoke the recognition (撤销认定结果)** — the recognition is the contribution
//!   record's `Passed` verdict; [`RecordingService::mark_evaluation_result`] with
//!   `passed = false` moves it to `Failed` ("认定未通过").
//! - **Retroactive penalties + anchoring (锚定处理结果)** — a [`PenaltyRecord`] is
//!   recorded on [`L1Settlement`] for *every* participant and the revoked-recognition
//!   outcome is anchored, advancing the L1 state root.
//!
//! These are plain `#[test]` example/scenario tests (not numbered properties), so they
//! carry no `Feature: ... Property N` label.

use gmc_core::antifraud::{detect_anomaly, AntiFraudEngine, VoteEvent};
use gmc_core::l1_settlement::{AnchorKind, L1Settlement, PenaltyRecord, VoteResultRecord};
use gmc_core::merit::{MeritBatch, MeritPocket, E};
use gmc_core::minting::{MintReceipt, MintRequest, MintingService};
use gmc_core::quota::{QuotaConfig, QuotaLedger, RefreshPeriod, TimeUnit};
use gmc_core::recording::{
    ContributionRequest, EvaluationStatus, EvidenceRef, RecordingService, RegistrationLookup,
};
use gmc_core::types::{ChainId, Decimal, FayID, Timestamp};

const DAY: u64 = 86_400;

/// Time points at which `curMerit` is sampled to prove the clawback restores the
/// decay curve, not just the floor.
const SAMPLE_TIMES: [u64; 7] = [0, 100, 1_000, 10_000, 100_000, 1_000_000, 100_000_000];

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(secs)
}

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).expect("valid decimal literal")
}

/// A periodic quota config with ample headroom, so the fraudulent mint succeeds (the
/// only thing under test here is the clawback, not quota rejection).
fn cfg() -> QuotaConfig {
    QuotaConfig::new(
        Decimal::from_int(10_000),
        RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: Decimal::ONE,
        },
    )
    .expect("valid periodic config")
}

fn fresh_ledger() -> QuotaLedger {
    QuotaLedger::new(ChainId::from("env-chain"), ts(0))
}

/// A contributor pocket whose initial floor `E` is *backed* by a slowly-decaying batch
/// with `B = E`, so the `curMerit ≥ minMerit` invariant is well-defined and the pocket
/// has a non-trivial, time-varying `curMerit` (mirrors the `minting.rs` pipeline tests).
fn backed_pocket() -> MeritPocket {
    let mut pocket = MeritPocket::new(FayID::from("fay-cheater"));
    pocket.add_batch(MeritBatch::new(
        "reg-grant",
        Decimal::from_int(100), // V
        E,                      // B = initial floor, so Σ B_i starts == minMerit
        dec("0.001"),
        Decimal::from_int(1_000),
        ts(0),
        ChainId::from("env-chain"),
    ));
    pocket
}

/// Builds a colluding voter's approve-vote history toward the recognition `target`:
/// five approvals inside the most-recent-30-day window (100% approve ratio, count
/// 5 ≥ 5), which [`detect_anomaly`] flags as anomalous (Requirement 11.4) — the signal
/// that a clawback is warranted (Requirement 11.6).
fn collusive_history(voter: &str, target: &str, now_day: u64) -> Vec<VoteEvent> {
    (1..=5)
        .map(|i| VoteEvent::new(FayID::new(voter), target, true, ts((now_day - i) * DAY)))
        .collect()
}

/// The clawback's **mint reversal** step (Requirement 11.6 "回收因该次认定铸造的
/// MeriToken"): removes the batch the fraudulent mint created and restores `minMerit`
/// to its pre-mint floor. Because the mint added exactly that one batch and only raised
/// the floor by `receipt.floor_increment`, this is a *consistent* rollback — the pocket
/// returns to its exact pre-mint state.
fn clawback_mint(pocket: &mut MeritPocket, receipt: &MintReceipt, floor_before: Decimal) {
    pocket.batches.retain(|b| b.batch_id != receipt.batch_id);
    pocket.min_merit = floor_before;
}

/// A registration lookup stub that always reports a matching valid registration, so a
/// linked contribution record (the "recognition" subject) can be created and later
/// revoked. (The standard register→record→grant wiring is covered elsewhere; here we
/// only need a recognition record to revoke.)
struct AlwaysRegistered;

impl RegistrationLookup for AlwaysRegistered {
    fn find_valid_registration(
        &self,
        _contributor_id: &FayID,
        _chain_id: &ChainId,
    ) -> Option<String> {
        Some("reg-collusion".to_owned())
    }
}

/// Drives the fraudulent recognition: records a contribution, marks it `Passed` (the
/// recognition that collusion pushed through), and mints the MeriToken it earned.
/// Returns the recording service, the record id, the mint receipt and the pre-mint
/// floor so the clawback can be exercised and verified.
fn perform_fraudulent_recognition(
    pocket: &mut MeritPocket,
    ledger: &mut QuotaLedger,
    amount: Decimal,
    now: Timestamp,
) -> (
    RecordingService,
    gmc_core::recording::ContributionId,
    MintReceipt,
    Decimal,
) {
    let service = MintingService::new();
    let config = cfg();

    // 1. Record the contribution and let the (colluded) recognition pass.
    let mut recording = RecordingService::new();
    let record_id = recording
        .record(
            ContributionRequest::new(
                FayID::new("fay-cheater"),
                ChainId::new("env-chain"),
                vec![EvidenceRef::new("ipfs://carbon-cid", "0xhash")],
                now,
            ),
            &AlwaysRegistered,
            false,
        )
        .expect("a matching valid registration allows recording");
    recording
        .mark_evaluation_result(&record_id, true)
        .expect("collusion pushes the recognition to Passed");
    assert_eq!(
        recording.get(&record_id).unwrap().evaluation_status(),
        EvaluationStatus::Passed,
        "precondition: the recognition passed before the fraud is detected"
    );

    // 2. The passed recognition mints MeriToken into the contributor's pocket.
    let floor_before = pocket.min_merit();
    let receipt = service
        .mint(
            pocket,
            &config,
            ledger,
            MintRequest::new(
                "collusion-grant",
                amount,
                Decimal::from_int(1_000),
                now,
                ChainId::from("env-chain"),
            ),
        )
        .expect("the fraudulent mint succeeds within quota");

    (recording, record_id, receipt, floor_before)
}

// ---------------------------------------------------------------------------
// 1. Mint reversal: the clawback is a consistent rollback of the mint.
// ---------------------------------------------------------------------------

#[test]
fn collusion_clawback_reverses_mint_to_exact_pre_mint_state() {
    let mut pocket = backed_pocket();
    let mut ledger = fresh_ledger();
    let now = ts(100 * DAY);
    let amount = Decimal::from_int(50);

    // Snapshot the contributor's pocket *before* the fraudulent recognition mints.
    let pocket_before = pocket.clone();
    let cur_before: Vec<Decimal> = SAMPLE_TIMES
        .iter()
        .map(|&t| pocket.cur_merit(ts(t)))
        .collect();
    let cur_at_now_before = pocket.cur_merit(now);

    let (_recording, _record_id, receipt, floor_before) =
        perform_fraudulent_recognition(&mut pocket, &mut ledger, amount, now);

    // Sanity: the mint genuinely happened — a batch was added, the floor rose, and
    // curMerit grew by exactly `amount` at the acquisition time.
    assert_eq!(pocket.batches.len(), pocket_before.batches.len() + 1);
    assert!(pocket.min_merit() >= floor_before);
    assert_eq!(receipt.minted_amount, amount);
    assert_eq!(
        pocket.cur_merit(now),
        cur_at_now_before.checked_add(amount).unwrap(),
        "the mint added its full value at the acquisition time"
    );

    // --- Clawback: reverse the mint (Requirement 11.6 回收 MeriToken). ---
    clawback_mint(&mut pocket, &receipt, floor_before);

    // The pocket is byte-for-byte back to its pre-mint state: no leftover batch and the
    // floor restored — a consistent rollback.
    assert_eq!(
        pocket, pocket_before,
        "clawback must restore the exact pre-mint pocket"
    );
    assert_eq!(pocket.min_merit(), pocket_before.min_merit());
    assert_eq!(pocket.batches.len(), pocket_before.batches.len());

    // curMerit is restored at every sampled time point (the decay curve, not just the
    // floor), and the curMerit ≥ minMerit invariant still holds.
    for (&t, &before) in SAMPLE_TIMES.iter().zip(cur_before.iter()) {
        assert_eq!(
            pocket.cur_merit(ts(t)),
            before,
            "curMerit not restored at t={t} after clawback"
        );
        assert!(
            pocket.invariant_holds(ts(t)),
            "invariant violated at t={t} after clawback"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The recognition result is revoked (Passed -> Failed).
// ---------------------------------------------------------------------------

#[test]
fn collusion_clawback_revokes_the_recognition_result() {
    let mut pocket = backed_pocket();
    let mut ledger = fresh_ledger();
    let now = ts(100 * DAY);

    let (mut recording, record_id, receipt, floor_before) =
        perform_fraudulent_recognition(&mut pocket, &mut ledger, Decimal::from_int(40), now);

    // --- Clawback: revoke the recognition (Requirement 11.6 撤销认定结果). ---
    recording
        .mark_evaluation_result(&record_id, false)
        .expect("revoking the recognition marks it Failed");
    clawback_mint(&mut pocket, &receipt, floor_before);

    // The recognition is no longer Passed: it is now Failed ("认定未通过"), while the
    // record itself is retained for audit.
    let record = recording
        .get(&record_id)
        .expect("record retained after revocation");
    assert_eq!(
        record.evaluation_status(),
        EvaluationStatus::Failed,
        "the colluded recognition must be revoked (Passed -> Failed)"
    );
    assert_eq!(
        recording.len(),
        1,
        "the revoked record is retained, not deleted"
    );
}

// ---------------------------------------------------------------------------
// 3. Retroactive penalties for all participants are anchored to L1.
// ---------------------------------------------------------------------------

#[test]
fn collusion_clawback_penalises_all_participants_and_anchors_outcome_to_l1() {
    let mut pocket = backed_pocket();
    let mut ledger = fresh_ledger();
    let now = ts(100 * DAY);

    let (mut recording, record_id, receipt, floor_before) =
        perform_fraudulent_recognition(&mut pocket, &mut ledger, Decimal::from_int(60), now);

    // The collusion participants: the contributor plus the colluding voters.
    let participants = [
        FayID::new("fay-cheater"),
        FayID::new("voter-a"),
        FayID::new("voter-b"),
    ];

    // Detect the collusion via the anti-fraud engine (Requirement 11.4 feeds 11.6):
    // each colluding voter's approve-spamming toward the recognition is flagged.
    let mut engine = AntiFraudEngine::new();
    for voter in ["voter-a", "voter-b"] {
        let history = collusive_history(voter, "recognition-collusion-grant", 100);
        assert!(
            detect_anomaly(
                &FayID::new(voter),
                "recognition-collusion-grant",
                &history,
                now
            )
            .is_some(),
            "{voter}'s collusive approval pattern must be detected as anomalous"
        );
        engine.record_if_anomalous(
            &FayID::new(voter),
            "recognition-collusion-grant",
            &history,
            now,
        );
    }
    assert_eq!(
        engine.pending_audit().len(),
        2,
        "both colluding voters flagged"
    );

    // --- Clawback handling: revoke + reverse mint + penalise + anchor to L1. ---
    recording
        .mark_evaluation_result(&record_id, false)
        .expect("revoke the recognition");
    clawback_mint(&mut pocket, &receipt, floor_before);

    let mut l1 = L1Settlement::new();
    let root_before = l1.state_root();
    let version_before = l1.version();

    // Retroactive penalty for every participant (Requirement 11.6 对所有参与者发起
    // 事后追溯惩罚) per the existing L1 penalty mechanism.
    for subject in &participants {
        l1.record_penalty(PenaltyRecord::new(
            subject.clone(),
            "collusion-clawback",
            now,
        ));
    }
    // Anchor the handling result: the recognition outcome, now revoked (passed=false).
    l1.store_vote_result(VoteResultRecord::new(
        "recognition-collusion-grant",
        "collusion vote-fraud clawback",
        false,
        now,
    ));

    // Every participant has an anchored penalty record.
    assert_eq!(l1.penalties().len(), participants.len());
    for subject in &participants {
        assert!(
            l1.penalties()
                .iter()
                .any(|p| &p.subject == subject && p.reason == "collusion-clawback"),
            "missing retroactive penalty for {subject}"
        );
    }

    // The revoked recognition outcome is anchored and queryable as not-passed.
    let outcome = l1
        .vote_result("recognition-collusion-grant")
        .expect("the clawback outcome is anchored to L1");
    assert!(
        !outcome.passed,
        "the anchored recognition outcome must be revoked"
    );

    // Anchoring advanced the L1 state root / version, and the audit log captured both
    // the penalties and the outcome anchoring.
    assert_ne!(
        l1.state_root(),
        root_before,
        "anchoring must advance the state root"
    );
    assert!(l1.version() > version_before);
    assert_eq!(
        l1.anchor_log()
            .iter()
            .filter(|e| e.kind == AnchorKind::Penalty)
            .count(),
        participants.len()
    );
    assert!(l1
        .anchor_log()
        .iter()
        .any(|e| e.kind == AnchorKind::RetroactiveOutcome));
}

// ---------------------------------------------------------------------------
// 4. End-to-end: the full Requirement 11.6 handling in one consistent flow.
// ---------------------------------------------------------------------------

#[test]
fn collusion_vote_fraud_full_clawback_is_consistent() {
    let mut pocket = backed_pocket();
    let mut ledger = fresh_ledger();
    let now = ts(100 * DAY);
    let amount = Decimal::from_int(80);

    let pocket_before = pocket.clone();

    // Fraudulent recognition mints MeriToken and consumes quota.
    let (mut recording, record_id, receipt, floor_before) =
        perform_fraudulent_recognition(&mut pocket, &mut ledger, amount, now);
    assert_eq!(
        ledger.minted_this_period(),
        amount,
        "the fraudulent mint consumed quota (confirming a real mint occurred)"
    );

    // Full clawback handling (Requirement 11.6): revoke, reverse mint, penalise, anchor.
    let mut l1 = L1Settlement::new();
    recording.mark_evaluation_result(&record_id, false).unwrap();
    clawback_mint(&mut pocket, &receipt, floor_before);
    l1.record_penalty(PenaltyRecord::new(
        FayID::new("fay-cheater"),
        "collusion-clawback",
        now,
    ));
    l1.store_vote_result(VoteResultRecord::new(
        "recognition-collusion-grant",
        "collusion vote-fraud clawback",
        false,
        now,
    ));

    // (a) MeriToken reversed: pocket restored to pre-mint state.
    assert_eq!(pocket, pocket_before);
    // (b) Recognition revoked.
    assert_eq!(
        recording.get(&record_id).unwrap().evaluation_status(),
        EvaluationStatus::Failed
    );
    // (c) Handling result anchored: penalty recorded + revoked outcome on L1.
    assert_eq!(l1.penalties().len(), 1);
    assert!(
        !l1.vote_result("recognition-collusion-grant")
            .unwrap()
            .passed
    );
    assert!(
        l1.version() >= 2,
        "both the penalty and the outcome were anchored"
    );
}
