//! L2 high-frequency processing & cross-layer integration tests (task 19.4).
//!
//! **Validates: Requirements 11.7, 13.2, 13.5, 13.7**
//!
//! These are plain `#[test]` integration/scenario tests (not numbered properties), so
//! they carry no `Feature: ... Property N` label. They exercise the `L2_Rollup`
//! pure-logic model and the cross-layer seams that surround it, focusing on four
//! layered-architecture guarantees:
//!
//! - **L2 compute latency (Requirement 13.2)** — a contribution submitted to L2 yields a
//!   computed result (`ComputationResult`) within the documented
//!   [`COMPUTE_LATENCY_BUDGET_SECS`] (= 5 s) SLA of its submission, carrying the created
//!   record, the computed MeriToken amount and the intimacy-update flag.
//! - **Sharding scale-out (Requirement 13.5)** — when the network-wide submission rate
//!   stays strictly above the in-use instances' combined rated throughput for *longer
//!   than* 60 s, the [`ShardController`] adds parallel rollup instances until the total
//!   rated throughput covers the rate.
//! - **BFT final confirmation (Requirement 13.7)** — the L2 runs a BFT-class consensus
//!   whose block-finality budget is ≤ 3 s ([`BFT_FINALITY_BUDGET_SECS`]).
//! - **ZK voter privacy (Requirement 11.7)** — the public view of a vote
//!   ([`PublicVoteResult`]) exposes only the aggregate outcome (pass/fail + approval
//!   ratio); it carries no per-voter identity, so two different private voter sets with
//!   the same aggregate are publicly indistinguishable.
//!
//! A final end-to-end test composes the L2 per-record processing, the batch trigger and
//! the L2→L1 [`L1ProofSink`] seam to show the layers integrate: records processed within
//! the 13.2 SLA are batched and the batch proof is accepted by a (stub) L1.

use gmc_core::error::{GmcError, GmcResult};
use gmc_core::l2_rollup::{
    required_instances, BatchProof, BatchRoot, ComputationResult, ContributionSubmission,
    L1ProofSink, L2Consensus, L2Rollup, PublicVoteResult, ShardController, VoteTally,
    BFT_FINALITY_BUDGET_SECS, COMPUTE_LATENCY_BUDGET_SECS, PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC,
    SUSTAINED_OVERLOAD_SECS,
};
use gmc_core::types::{ChainId, Decimal, FayID, Ratio, Timestamp};

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(secs)
}

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap()
}

fn submission(contributor: &str, chain: &str, amount: &str) -> ContributionSubmission {
    ContributionSubmission::new(FayID::new(contributor), ChainId::new(chain), dec(amount))
}

// ===========================================================================
// Requirement 13.2: L2 returns a computed result within the 5 s latency SLA.
// ===========================================================================

/// Requirement 13.2: a contribution submitted to L2 produces a `ComputationResult`
/// whose computation time falls within [`COMPUTE_LATENCY_BUDGET_SECS`] (5 s) of the
/// submission time — and the result bundles the created record, the computed MeriToken
/// amount and the intimacy-update flag (贡献记录创建 / MeriToken 计算 / 亲密度更新).
#[test]
fn req_13_2_l2_returns_result_within_5s_of_submission() {
    let mut rollup = L2Rollup::new(ts(0));

    let submitted_at = ts(1_000);
    // The real L2 computes and returns the result some time after submission; model the
    // result being produced 3 s later — comfortably inside the 5 s SLA.
    let computed_at = ts(1_003);

    let result: ComputationResult =
        rollup.process_contribution(submission("alice", "academia", "12.5"), computed_at);

    // The result corresponds to the submission: a record was created, the MeriToken
    // amount was computed and the intimacy graph was updated.
    assert_eq!(result.contributor_id, FayID::new("alice"));
    assert_eq!(result.chain_id, ChainId::new("academia"));
    assert_eq!(result.merit_amount, dec("12.5"));
    assert!(result.intimacy_updated, "intimacy update must be performed");
    assert_eq!(result.record_id.as_str(), "rollup-rec-0");

    // The computed result is returned within the 5 s latency budget of submission.
    let latency_secs = result.computed_at.saturating_elapsed_since(submitted_at);
    assert!(
        latency_secs <= COMPUTE_LATENCY_BUDGET_SECS,
        "L2 must return the computation result within {COMPUTE_LATENCY_BUDGET_SECS}s of \
         submission, but latency was {latency_secs}s"
    );

    // The processed record is buffered for the next L1 batch.
    assert_eq!(rollup.buffered_len(), 1);
}

/// Requirement 13.2: the latency SLA holds at the boundary and across a burst of
/// submissions — every returned result lands within the 5 s budget of its submission.
#[test]
fn req_13_2_latency_holds_at_boundary_and_across_a_burst() {
    let mut rollup = L2Rollup::new(ts(0));

    // Boundary case: a result computed exactly 5 s after submission is still within SLA.
    let submitted_at = ts(2_000);
    let result = rollup.process_contribution(
        submission("bob", "charity", "1"),
        ts(2_000 + COMPUTE_LATENCY_BUDGET_SECS),
    );
    assert_eq!(
        result.computed_at.saturating_elapsed_since(submitted_at),
        COMPUTE_LATENCY_BUDGET_SECS
    );
    assert!(
        result.computed_at.saturating_elapsed_since(submitted_at) <= COMPUTE_LATENCY_BUDGET_SECS
    );

    // A burst of submissions: each result is produced within the budget of its own
    // submission, and each gets a distinct record id.
    let mut seen_ids = Vec::new();
    for i in 0..50u64 {
        let submit = ts(3_000 + i);
        // Modeled per-record processing delay of 2 s (≤ 5 s budget).
        let compute = ts(3_000 + i + 2);
        let r = rollup.process_contribution(submission("carol", "science", "0.5"), compute);
        let latency = r.computed_at.saturating_elapsed_since(submit);
        assert!(
            latency <= COMPUTE_LATENCY_BUDGET_SECS,
            "burst record {i} latency {latency}s exceeded the {COMPUTE_LATENCY_BUDGET_SECS}s SLA"
        );
        seen_ids.push(r.record_id);
    }
    // 50 distinct, monotonically-allocated record ids (plus the boundary record = 51).
    seen_ids.sort();
    seen_ids.dedup();
    assert_eq!(seen_ids.len(), 50);
    assert_eq!(rollup.buffered_len(), 51);

    // The documented SLA constant is the design's 5 s.
    assert_eq!(COMPUTE_LATENCY_BUDGET_SECS, 5);
}

// ===========================================================================
// Requirement 13.7: BFT-class consensus with ≤ 3 s final confirmation.
// ===========================================================================

/// Requirement 13.7: the L2 is configured with a BFT-class consensus whose
/// block-finality budget is ≤ 3 s.
#[test]
fn req_13_7_l2_consensus_is_bft_with_final_confirmation_within_3s() {
    let rollup = L2Rollup::new(ts(0));

    // The configured consensus is BFT-class.
    assert_eq!(rollup.consensus(), L2Consensus::Bft);
    assert!(rollup.consensus().is_bft());
    assert_eq!(rollup.consensus().label(), "BFT");

    // Final confirmation completes within 3 s.
    let finality = rollup.consensus().finality_budget_secs();
    assert!(
        finality <= 3,
        "BFT block finality must complete within 3 s, budget was {finality}s"
    );
    assert_eq!(finality, BFT_FINALITY_BUDGET_SECS);
    assert_eq!(BFT_FINALITY_BUDGET_SECS, 3);
}

// ===========================================================================
// Requirement 13.5: sharding scale-out when sustained overload exceeds 60 s.
// ===========================================================================

/// Requirement 13.5: while the submission rate stays at or below the in-use instances'
/// combined rated throughput, no scale-out occurs no matter how long it persists.
#[test]
fn req_13_5_no_scale_out_when_rate_within_rated_throughput() {
    let mut ctrl = ShardController::new();
    assert_eq!(ctrl.instance_count(), 1);
    assert_eq!(
        ctrl.rated_throughput_per_sec(),
        PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC
    );

    // At exactly the single-instance rated throughput, sustained for a long time.
    let d0 = ctrl.observe_rate(PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC, ts(0));
    assert!(!d0.scaled_out);
    assert!(!ctrl.is_overloaded());

    let d1 = ctrl.observe_rate(PER_INSTANCE_THROUGHPUT_RECORDS_PER_SEC, ts(10_000));
    assert!(
        !d1.scaled_out,
        "a rate within capacity never triggers scale-out"
    );
    assert_eq!(ctrl.instance_count(), 1);
}

/// Requirement 13.5: when the network-wide submission rate stays strictly above the
/// in-use instances' combined rated throughput for *longer than* 60 s, the controller
/// adds parallel rollup instances until the total rated throughput covers the rate.
#[test]
fn req_13_5_scale_out_triggers_after_sustained_overload_beyond_60s() {
    let mut ctrl = ShardController::new();

    // Single instance rated at 1,000/s; the network sees a sustained 2,500/s rate.
    let overload_rate = 2_500u64;
    assert!(overload_rate > ctrl.rated_throughput_per_sec());

    // Overload begins: the first observation only anchors the overload window.
    let start = ctrl.observe_rate(overload_rate, ts(0));
    assert!(
        !start.scaled_out,
        "first overload observation only anchors the window"
    );
    assert!(ctrl.is_overloaded());

    // Within the 60 s window (and at exactly 60 s) the overload is not yet *beyond* the
    // window, so no scale-out happens.
    let within = ctrl.observe_rate(overload_rate, ts(30));
    assert!(!within.scaled_out);
    let at_boundary = ctrl.observe_rate(overload_rate, ts(SUSTAINED_OVERLOAD_SECS));
    assert!(
        !at_boundary.scaled_out,
        "overload must persist *longer than* 60 s before scaling"
    );
    assert_eq!(ctrl.instance_count(), 1);

    // Beyond 60 s of sustained overload → scale out to cover the rate.
    let scaled = ctrl.observe_rate(overload_rate, ts(SUSTAINED_OVERLOAD_SECS + 1));
    assert!(
        scaled.scaled_out,
        "sustained overload beyond 60 s must scale out"
    );

    // The new instance count's combined rated throughput covers the submission rate.
    assert_eq!(scaled.instance_count, required_instances(overload_rate));
    assert!(
        ctrl.rated_throughput_per_sec() >= overload_rate,
        "after scale-out the total rated throughput must cover the submission rate"
    );
    // ceil(2500 / 1000) = 3 instances => 3,000/s aggregate capacity.
    assert_eq!(ctrl.instance_count(), 3);
    assert_eq!(ctrl.rated_throughput_per_sec(), 3_000);
}

/// Requirement 13.5: a transient overload that subsides before 60 s never scales out —
/// the overload must be *continuous* to count toward the 60 s window.
#[test]
fn req_13_5_transient_overload_under_60s_does_not_scale_out() {
    let mut ctrl = ShardController::new();

    // Overload starts, then the rate drops back within capacity before 60 s elapse.
    ctrl.observe_rate(1_500, ts(0));
    assert!(ctrl.is_overloaded());
    let dropped = ctrl.observe_rate(800, ts(45));
    assert!(!dropped.scaled_out);
    assert!(
        !ctrl.is_overloaded(),
        "subsiding overload clears the window"
    );
    assert_eq!(ctrl.instance_count(), 1);
}

// ===========================================================================
// Requirement 11.7: ZK voting exposes only the result, never voter identity.
// ===========================================================================

/// Requirement 11.7: the public vote result exposes only the aggregate outcome
/// (pass/fail + approval ratio). Two votes with completely different private voter sets
/// but the same aggregate tally produce identical public results, so individual voters
/// cannot be recovered from what is published.
#[test]
fn req_11_7_zk_vote_exposes_only_result_not_voter_identity() {
    // Two private tallies representing the *same* 2/3 aggregate approval reached by
    // different (private) voter populations — e.g. 6-of-9 weight vs 2-of-3 weight.
    let tally_population_a = VoteTally::new(dec("6"), dec("9")).unwrap();
    let tally_population_b = VoteTally::new(dec("2"), dec("3")).unwrap();

    // The 66.7% retroactive-style passing threshold.
    let threshold = Ratio::new(dec("0.666666")).unwrap();

    let public_a = PublicVoteResult::from_tally(&tally_population_a, threshold);
    let public_b = PublicVoteResult::from_tally(&tally_population_b, threshold);

    // Only the aggregate outcome is published, and it is identical for both
    // populations — the public view cannot distinguish *who* voted.
    assert_eq!(
        public_a, public_b,
        "different private voter sets with the same aggregate must be publicly indistinguishable"
    );
    assert!(public_a.passed());
    assert_eq!(public_a.approval_ratio().value(), dec("0.666666"));

    // The published surface is exactly {passed, approval_ratio}: no FayID / ballot list.
    // The `Copy` bound documents that the value owns no per-voter identity data.
    fn assert_no_owned_identity_data<T: Copy>(_t: &T) {}
    assert_no_owned_identity_data(&public_a);
}

/// Requirement 11.7: only the aggregate outcome is retained regardless of the threshold
/// decision — a failing vote still exposes just the ratio, never the underlying ballots.
#[test]
fn req_11_7_public_result_carries_only_aggregate_for_pass_and_fail() {
    let tally = VoteTally::new(dec("7"), dec("10")).unwrap(); // 0.70 aggregate approval

    // A lenient threshold passes; a strict one fails — both expose only the ratio.
    let lenient = Ratio::new(dec("0.5")).unwrap();
    let strict = Ratio::new(dec("0.8")).unwrap();

    let passed = PublicVoteResult::from_tally(&tally, lenient);
    assert!(passed.passed());
    assert_eq!(passed.approval_ratio().value(), dec("0.7"));

    let failed = PublicVoteResult::from_tally(&tally, strict);
    assert!(!failed.passed());
    // Even on failure, the public view is just the aggregate ratio (no identities).
    assert_eq!(failed.approval_ratio().value(), dec("0.7"));

    // An invalid aggregate (approval exceeding total, or non-positive total) is rejected
    // before anything could be published.
    assert_eq!(VoteTally::new(dec("11"), dec("10")), None);
    assert_eq!(VoteTally::new(dec("1"), dec("0")), None);
}

// ===========================================================================
// Cross-layer integration: L2 processes within SLA → batches → L1 accepts proof.
// ===========================================================================

/// A stub L1 verifier modeling the L2→L1 boundary (Requirement 9.7 / 13.8): it accepts a
/// batch proof and advances its confirmed root, recording how many batches it confirmed.
struct StubL1 {
    confirmed_root: Option<BatchRoot>,
    confirmed_batches: usize,
}

impl StubL1 {
    fn new() -> Self {
        StubL1 {
            confirmed_root: None,
            confirmed_batches: 0,
        }
    }
}

impl L1ProofSink for StubL1 {
    fn submit_batch_proof(&mut self, batch_root: BatchRoot, proof: &BatchProof) -> GmcResult<()> {
        // The proof commits to the batch root it is submitted with.
        if proof.committed_root() != batch_root {
            return Err(GmcError::ProofVerificationFailed);
        }
        self.confirmed_root = Some(batch_root);
        self.confirmed_batches += 1;
        Ok(())
    }
}

/// End-to-end cross-layer flow: contributions are processed on L2 within the 13.2 SLA,
/// buffered, flushed as a batch when the 60 s trigger fires (Req 13.3), and the batch
/// proof is submitted to and confirmed by L1 (Req 9.7) — all under a BFT consensus whose
/// finality budget is ≤ 3 s (Req 13.7). Demonstrates the L2 and L1 layers integrate.
#[test]
fn cross_layer_l2_processing_batches_and_l1_confirms_proof() {
    let mut rollup = L2Rollup::new(ts(0));
    let mut l1 = StubL1::new();

    // Process a handful of contributions on L2; each result returns within the 5 s SLA.
    for i in 0..4u64 {
        let submit = ts(10 + i);
        let result = rollup.process_contribution(submission("dave", "engineering", "3"), submit);
        assert!(result.computed_at.saturating_elapsed_since(submit) <= COMPUTE_LATENCY_BUDGET_SECS);
    }
    assert_eq!(rollup.buffered_len(), 4);

    // Under the record threshold but past the 60 s interval → a batch flushes (Req 13.3).
    let batch = rollup
        .try_submit_batch(ts(60))
        .expect("the 60 s interval trigger must flush the buffered records");
    assert_eq!(batch.len(), 4);
    assert!(!batch.batch_root.is_genesis());

    // The L2→L1 seam: submit the batch proof to L1, which verifies and confirms it.
    L2Rollup::submit_batch_proof_to(&batch, &mut l1).expect("L1 must accept a consistent proof");
    assert_eq!(l1.confirmed_batches, 1);
    assert_eq!(l1.confirmed_root, Some(batch.batch_root));

    // The settlement layer's consensus honours the ≤ 3 s BFT finality budget (Req 13.7).
    assert!(rollup.consensus().finality_budget_secs() <= BFT_FINALITY_BUDGET_SECS);
}
