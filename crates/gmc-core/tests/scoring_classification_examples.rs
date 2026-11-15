//! Example/unit tests for the `Scoring_Engine` three-dimensional classification
//! (task 8.7). These are concrete worked examples — **not** one of the numbered design
//! properties (Property 1–30), so they deliberately carry no `Feature: ... Property N`
//! label.
//!
//! They exercise [`ScoringEngine::classify`], the dimension-count + proportion validator
//! that every classification result must pass (Requirements 6.2–6.4 happy paths plus the
//! 6.6 / 6.7 error paths):
//!
//! - 科研 (research) → [`Dimension::Thought`]            (Requirement 6.2)
//! - AI 训练 (AI training) → [`Dimension::Training`]     (Requirement 6.3)
//! - 手艺 (craft / skill) → [`Dimension::Technique`]      (Requirement 6.4)
//! - 无法归入任一维度 → [`GmcError::DimensionUnmatched`]  (Requirement 6.6)
//! - 占比之和 ≠ 100% → [`GmcError::WeightSumInvalid`]      (Requirement 6.7)
//!
//! `classify` validates a *proposed* classification (the concrete Evaluation_Mechanism
//! that decides which dimension a contribution belongs to is wired in by a later
//! integration task). Each happy-path example therefore models a contribution that the
//! mechanism would place into a single dimension at 100% weight, and asserts the engine
//! accepts it and preserves exactly that dimension.

use gmc_core::error::GmcError;
use gmc_core::scoring::ScoringEngine;
use gmc_core::types::{Decimal, Dimension, DimensionWeights, Ratio};

/// Builds a single-dimension, full-weight (100%) classification, modelling a
/// contribution the Evaluation_Mechanism placed entirely in `dimension`.
fn full_weight(dimension: Dimension) -> DimensionWeights {
    DimensionWeights::from_entries([(dimension, Ratio::ONE)])
}

#[test]
fn research_contribution_classifies_into_thought() {
    // Req 6.2: a research / 科研 (e.g. scientific discovery, invention) contribution is
    // a cognitive-breakthrough contribution and belongs to the Thought dimension.
    let engine = ScoringEngine::new();
    let proposed = full_weight(Dimension::Thought);

    let accepted = engine
        .classify(proposed.clone())
        .expect("a full-weight Thought classification is valid");

    // The accepted classification is exactly the Thought dimension at 100%.
    assert_eq!(accepted, proposed);
    assert_eq!(accepted.get(Dimension::Thought), Some(Ratio::ONE));
    assert_eq!(accepted.get(Dimension::Training), None);
    assert_eq!(accepted.get(Dimension::Technique), None);
}

#[test]
fn ai_training_contribution_classifies_into_training() {
    // Req 6.3: an AI-training / 训练 contribution (rapidly disseminating existing
    // knowledge / improving efficiency, e.g. training a domain-specific AI model)
    // belongs to the Training dimension.
    let engine = ScoringEngine::new();
    let proposed = full_weight(Dimension::Training);

    let accepted = engine
        .classify(proposed.clone())
        .expect("a full-weight Training classification is valid");

    assert_eq!(accepted, proposed);
    assert_eq!(accepted.get(Dimension::Training), Some(Ratio::ONE));
    assert_eq!(accepted.get(Dimension::Thought), None);
    assert_eq!(accepted.get(Dimension::Technique), None);
}

#[test]
fn craft_contribution_classifies_into_technique() {
    // Req 6.4: a craft / 手艺 contribution (value delivered through skill — service,
    // performance, handicraft) belongs to the Technique dimension.
    let engine = ScoringEngine::new();
    let proposed = full_weight(Dimension::Technique);

    let accepted = engine
        .classify(proposed.clone())
        .expect("a full-weight Technique classification is valid");

    assert_eq!(accepted, proposed);
    assert_eq!(accepted.get(Dimension::Technique), Some(Ratio::ONE));
    assert_eq!(accepted.get(Dimension::Thought), None);
    assert_eq!(accepted.get(Dimension::Training), None);
}

#[test]
fn unclassifiable_contribution_is_dimension_unmatched() {
    // Req 6.6: a contribution that cannot be placed in any of the three dimensions
    // yields an empty classification, which the engine rejects with DimensionUnmatched
    // and mints nothing.
    let engine = ScoringEngine::new();
    let unclassifiable = DimensionWeights::new();

    assert_eq!(
        engine.classify(unclassifiable),
        Err(GmcError::DimensionUnmatched)
    );
}

#[test]
fn weights_not_summing_to_one_are_weight_sum_invalid() {
    // Req 6.7: a cross-dimension classification whose proportions do not sum to exactly
    // 100% (here 0.7 + 0.5 = 1.2) is rejected with WeightSumInvalid; no MeriToken minted.
    let engine = ScoringEngine::new();
    let over_one = DimensionWeights::from_entries([
        (
            Dimension::Thought,
            Ratio::new(Decimal::from_str("0.7").unwrap()).unwrap(),
        ),
        (
            Dimension::Technique,
            Ratio::new(Decimal::from_str("0.5").unwrap()).unwrap(),
        ),
    ]);

    assert_eq!(engine.classify(over_one), Err(GmcError::WeightSumInvalid));
}

#[test]
fn weights_summing_below_one_are_weight_sum_invalid() {
    // Req 6.7 (lower side): proportions summing to less than 100% (0.6 + 0.3 = 0.9) are
    // likewise rejected with WeightSumInvalid.
    let engine = ScoringEngine::new();
    let under_one = DimensionWeights::from_entries([
        (Dimension::Thought, Ratio::from_percent(60).unwrap()),
        (Dimension::Training, Ratio::from_percent(30).unwrap()),
    ]);

    assert_eq!(engine.classify(under_one), Err(GmcError::WeightSumInvalid));
}
