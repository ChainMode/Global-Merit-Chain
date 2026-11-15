//! Property 23 — 事后申报未达阈值则驳回 (a sub-threshold retroactive vote is rejected).
//!
//! This is the dedicated property-based test for **Property 23** of the
//! `gmc-core-protocol` design's *Correctness Properties* section (task 15.5).
//!
//! > **Property 23: 事后申报未达阈值则驳回** — *对任意* 事后申报投票及任意投票分布，
//! > 当最终加权赞成票数低于事后申报通过阈值时，该申报被标记为"驳回"且不触发任何
//! > MeriToken 铸造。
//!
//! **Validates: Requirements 10.5**
//!
//! ## How the property is exercised
//!
//! For **any** retroactive vote and **any** vote distribution we:
//!
//! 1. build an arbitrary electorate (≥ 2 voters, each with a strictly-positive
//!    `curMerit`) and an arbitrary approve/reject ballot per voter, then drive the real
//!    [`GovernanceModule`] weighted tally to obtain the **final weighted approval ratio**
//!    (Requirement 11.5 weighting). One voter is forced to reject so the approval ratio
//!    is strictly below `1`, leaving room for a retro threshold strictly above it;
//! 2. derive a chain `regular_threshold` whose retroactive threshold
//!    [`retro_threshold`] is guaranteed **strictly greater** than that approval ratio
//!    (so the property's antecedent "approval < retro" always holds — see the two
//!    branches below);
//! 3. submit a valid [`RetroactiveApplication`] (Pending) and
//!    [`resolve_vote`](RetroactiveReviewModule::resolve_vote) it with the tallied
//!    approval against `regular_threshold`.
//!
//! We then assert the declaration is marked [`ReviewStatus::Rejected`] and that **no
//! mint is triggered**. The retroactive module deliberately decouples minting: a mint
//! is only ever performed downstream once a declaration reaches
//! [`ReviewStatus::Approved`] (Requirement 10.6). A `Rejected` outcome — surfaced as
//! [`GmcError::RetroThresholdNotMet`] from `resolve_vote` — therefore mints nothing
//! (Requirement 10.5). Asserting the status is `Rejected` (never `Approved`) and the
//! returned error is exactly that rejection code captures "no MeriToken minted".

use gmc_core::error::GmcError;
use gmc_core::governance::{GovernanceModule, Voter};
use gmc_core::retroactive::{
    retro_threshold, EvidenceRef, RetroactiveApplication, RetroactiveReviewModule, ReviewStatus,
    RETRO_TWO_THIRDS_FLOOR,
};
use gmc_core::types::{ChainId, Decimal, FayID, Ratio, Timestamp};
use proptest::prelude::*;

/// An arbitrary electorate: `2..=max` voters, each with a strictly-positive `curMerit`
/// (so the total is positive and every voter carries non-zero weight), paired with an
/// arbitrary approve/reject ballot per voter.
fn electorate_and_ballots(max: usize) -> impl Strategy<Value = (Vec<i128>, Vec<bool>)> {
    let n = max.max(2);
    proptest::collection::vec(1i128..=1_000_000_000i128, 2..=n).prop_flat_map(|merits| {
        let len = merits.len();
        (Just(merits), proptest::collection::vec(any::<bool>(), len))
    })
}

/// Builds a complete, replayable retroactive declaration (intake always succeeds).
fn valid_application() -> RetroactiveApplication {
    RetroactiveApplication::new(
        FayID::new("contributor"),
        ChainId::new("carbon-reduction"),
        "Already-occurred contribution, independently verifiable.",
        Timestamp::from_secs(1_700_000_000),
        vec![EvidenceRef::new("ipfs://cid-evidence", "0xhash", true)],
    )
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 23: 事后申报未达阈值则驳回
    #[test]
    fn property_23_retro_rejection(
        (merits, mut approvals) in electorate_and_ballots(8),
    ) {
        // --- 1. Tally an arbitrary weighted vote distribution (Requirement 11.5). ---
        // Force the last (positive-merit) voter to reject, so the weighted approval is
        // strictly below 1 and a retro threshold strictly above it is always realisable.
        let last = approvals.len() - 1;
        approvals[last] = false;

        let voters: Vec<Voter> = merits
            .iter()
            .enumerate()
            .map(|(i, m)| Voter::new(FayID::new(format!("voter-{i}")), Decimal::from_raw(*m)))
            .collect();

        let mut gov = GovernanceModule::new();
        // The governance vote's own threshold is irrelevant here: we only consume the
        // tallied approval ratio, then apply the *retro* threshold below.
        let vote = gov
            .open_vote("property-23-retro", Ratio::ZERO, voters.clone())
            .expect("a strictly-positive-merit electorate has a positive total");
        for (voter, approve) in voters.iter().zip(approvals.iter()) {
            gov.cast_vote(vote, &voter.id, *approve).expect("each voter is eligible");
        }
        let approval = gov.tally(vote).expect("the vote exists").approval_ratio;

        // The forced rejector guarantees the approval ratio never reaches a full 1.
        prop_assert!(approval.value() < Decimal::ONE);

        // --- 2. Pick a regular threshold whose retro threshold is strictly above the
        //        approval ratio, so the property's antecedent (approval < retro) holds. ---
        let regular = if approval.value() < RETRO_TWO_THIRDS_FLOOR {
            // approval below the 2/3 floor: any regular below the floor yields
            // retro == floor (> approval). 0.5 sits below the 2/3 floor.
            Ratio::from_percent(50).expect("0.5 is a valid ratio")
        } else {
            // approval in [2/3, 1): take regular == approval, so retro == approval + ulp,
            // which is strictly greater than approval and still within [0, 1].
            Ratio::new(approval.value()).expect("approval is a valid ratio in [0, 1]")
        };

        let retro = retro_threshold(regular);
        // Antecedent established: the weighted approval is strictly below the retro
        // threshold for this generated vote.
        prop_assert!(approval.value() < retro.value());

        // --- 3. Submit a valid declaration and resolve its vote below threshold. ---
        let mut module = RetroactiveReviewModule::new();
        let id = module
            .submit(valid_application())
            .expect("a complete, replayable declaration is accepted as Pending");
        prop_assert_eq!(module.get(&id).unwrap().review_status(), ReviewStatus::Pending);

        let outcome = module.resolve_vote(&id, approval, regular, format!("vote-{}", vote.raw()));

        // (Requirement 10.5) Below the retro threshold => rejected, and nothing minted.
        // `resolve_vote` reports the rejection via RetroThresholdNotMet; minting is only
        // ever triggered downstream on an Approved status, so a Rejected outcome mints
        // no MeriToken.
        prop_assert_eq!(outcome, Err(GmcError::RetroThresholdNotMet));

        let declaration = module.get(&id).expect("declaration is stored");
        prop_assert_eq!(declaration.review_status(), ReviewStatus::Rejected);
        // Explicitly: the declaration never reaches the Approved mint-gate.
        prop_assert_ne!(declaration.review_status(), ReviewStatus::Approved);
    }
}
