//! L1 anchoring & fee-free integration tests (task 18.4).
//!
//! **Validates: Requirements 2.6, 3.8, 5.1, 7.7, 8.6, 10.7, 13.1, 13.4**
//!
//! These are plain `#[test]` integration/scenario tests (not numbered properties), so
//! they carry no `Feature: ... Property N` label. They exercise the `L1_Settlement`
//! pure-logic model end-to-end, focusing on three settlement-layer guarantees:
//!
//! - **L1 storage responsibilities (Requirement 13.1)** — `L1_Settlement` stores the
//!   five enumerated record kinds: 功勋链注册记录 ([`ChainRegistrationRecord`]),
//!   身份注册记录 ([`IdentityRegistrationRecord`]), 治理投票结果
//!   ([`VoteResultRecord`]), 惩罚记录 ([`PenaltyRecord`]) and the 状态根
//!   ([`StateRoot`]).
//! - **Per-module anchoring (Requirements 2.6 / 3.8 / 5.1 / 7.7 / 8.6 / 10.7)** —
//!   anchoring each module's settled change advances the confirmed state (the
//!   monotonic `version` moves forward and the confirmed `state_root` changes), and the
//!   event is captured in the append-only audit log:
//!   - 2.6 chain-derivation creation record → [`L1Settlement::anchor_chain_creation`]
//!   - 3.8 evaluation-mechanism change      → [`L1Settlement::anchor_mechanism_change`]
//!   - 5.1 derivation-relationship root     → [`L1Settlement::anchor_derivation_state_root`]
//!   - 7.7 inflation-index change           → [`L1Settlement::anchor_inflation_index_change`]
//!   - 8.6 mint/L2 post-batch state root    → [`L1Settlement::update_state_root`]
//!   - 10.7 retroactive review outcome      → [`L1Settlement::anchor_retroactive_outcome`]
//! - **Fee-free settlement (Requirement 13.4)** — every on-chain transaction costs
//!   zero: the per-transaction fee is [`Decimal::ZERO`] and stays zero across an
//!   arbitrary sequence of anchoring transactions.

use gmc_core::l1_settlement::{
    AnchorKind, ChainRegistrationRecord, IdentityRegistrationRecord, L1Settlement, PenaltyRecord,
    StateRoot, VoteResultRecord,
};
use gmc_core::registry::OriginType;
use gmc_core::types::{ChainId, Decimal, FayID, Timestamp};

fn ts(secs: u64) -> Timestamp {
    Timestamp::from_secs(secs)
}

fn chain_record(id: &str, parent: &str, domain: &str) -> ChainRegistrationRecord {
    ChainRegistrationRecord::new(
        ChainId::new(id),
        Some(ChainId::new(parent)),
        domain,
        FayID::new("steward-1"),
        OriginType::StewardInitiated,
        ts(1_000),
    )
}

// ---------------------------------------------------------------------------
// Requirement 13.1: L1 stores the five required record kinds + the state root.
// ---------------------------------------------------------------------------

#[test]
fn l1_stores_all_required_record_types_and_state_root() {
    let mut l1 = L1Settlement::new();

    // 状态根 — present from genesis (Requirement 13.1).
    assert_eq!(l1.state_root(), StateRoot::GENESIS);

    // 功勋链注册记录 (Requirement 13.1 / 2.6).
    l1.anchor_chain_creation(chain_record("academic-chain", "gmc-base", "academic"));
    let chain = l1
        .chain_registration(&ChainId::new("academic-chain"))
        .expect("L1 stores the merit-chain registration record");
    assert_eq!(chain.parent_id, Some(ChainId::new("gmc-base")));
    assert_eq!(chain.domain, "academic");
    assert_eq!(chain.steward, FayID::new("steward-1"));
    assert_eq!(chain.origin, OriginType::StewardInitiated);
    assert_eq!(chain.created_at, ts(1_000));

    // 身份注册记录 (Requirement 13.1).
    l1.store_identity_registration(IdentityRegistrationRecord::new(
        FayID::new("fay-1"),
        ts(2_000),
    ));
    let identity = l1
        .identity_registration(&FayID::new("fay-1"))
        .expect("L1 stores the identity registration record");
    assert_eq!(identity.registered_at, ts(2_000));

    // 治理投票结果 (Requirement 13.1).
    l1.store_vote_result(VoteResultRecord::new(
        "vote-42",
        "mechanism-change:academic-chain",
        true,
        ts(3_000),
    ));
    let vote = l1
        .vote_result("vote-42")
        .expect("L1 stores the governance vote result");
    assert!(vote.passed);
    assert_eq!(vote.subject, "mechanism-change:academic-chain");

    // 惩罚记录 (Requirement 13.1).
    l1.record_penalty(PenaltyRecord::new(
        FayID::new("fay-cheater"),
        "collusion-clawback",
        ts(4_000),
    ));
    assert_eq!(l1.penalties().len(), 1);
    assert_eq!(l1.penalties()[0].subject, FayID::new("fay-cheater"));
    assert_eq!(l1.penalties()[0].reason, "collusion-clawback");

    // Every stored record kind is present at once; none clobbered another.
    assert_eq!(l1.chain_registration_count(), 1);
    assert!(l1
        .chain_registration(&ChainId::new("academic-chain"))
        .is_some());
    assert!(l1.identity_registration(&FayID::new("fay-1")).is_some());
    assert!(l1.vote_result("vote-42").is_some());
    assert_eq!(l1.penalties().len(), 1);
}

// ---------------------------------------------------------------------------
// Per-module anchoring: each settled change advances the confirmed L1 state.
// ---------------------------------------------------------------------------

/// Requirement 2.6: anchoring a chain-derivation creation record advances the confirmed
/// state and stores the full creation record (chain id / parent / domain / steward /
/// origin / time).
#[test]
fn req_2_6_chain_creation_anchor_advances_confirmed_state() {
    let mut l1 = L1Settlement::new();
    let root_before = l1.state_root();
    let version_before = l1.version();

    let new_root = l1.anchor_chain_creation(chain_record("env-chain", "gmc-base", "environment"));

    // The confirmed state advanced: version moved forward and the root changed.
    assert_eq!(l1.version(), version_before + 1);
    assert_ne!(new_root, root_before);
    assert_eq!(l1.state_root(), new_root);

    // The creation record is anchored and queryable.
    assert!(l1.chain_registration(&ChainId::new("env-chain")).is_some());

    // The anchoring event is captured in the audit log.
    let entry = l1.anchor_log().last().expect("an anchor entry was logged");
    assert_eq!(entry.kind, AnchorKind::ChainCreation);
    assert_eq!(entry.chain_id, Some(ChainId::new("env-chain")));
    assert_eq!(entry.resulting_root, new_root);
}

/// Requirement 3.8: anchoring an effective evaluation-mechanism change advances the
/// confirmed state.
#[test]
fn req_3_8_mechanism_change_anchor_advances_confirmed_state() {
    let mut l1 = L1Settlement::new();
    let root_before = l1.state_root();
    let version_before = l1.version();

    let new_root = l1.anchor_mechanism_change(ChainId::new("academic-chain"));

    assert_eq!(l1.version(), version_before + 1);
    assert_ne!(new_root, root_before);
    assert_eq!(l1.state_root(), new_root);

    let entry = l1.anchor_log().last().expect("an anchor entry was logged");
    assert_eq!(entry.kind, AnchorKind::MechanismChange);
    assert_eq!(entry.chain_id, Some(ChainId::new("academic-chain")));
}

/// Requirement 5.1: the `Chain_Registry` maintains the derivation-relationship state
/// root *through* `L1_Settlement` — anchoring it sets the confirmed root to that value.
#[test]
fn req_5_1_derivation_state_root_anchored_through_l1() {
    let mut l1 = L1Settlement::new();
    let version_before = l1.version();
    let derivation_root = StateRoot::from_bytes([42u8; 32]);

    let confirmed = l1.anchor_derivation_state_root(derivation_root);

    // L1 now confirms exactly the supplied derivation-relationship root.
    assert_eq!(confirmed, derivation_root);
    assert_eq!(l1.state_root(), derivation_root);
    assert_eq!(l1.version(), version_before + 1);

    let entry = l1.anchor_log().last().expect("an anchor entry was logged");
    assert_eq!(entry.kind, AnchorKind::DerivationStateRoot);
    assert_eq!(entry.resulting_root, derivation_root);
}

/// Requirement 7.7: anchoring an effective inflation-index change advances the confirmed
/// state.
#[test]
fn req_7_7_inflation_index_change_anchor_advances_confirmed_state() {
    let mut l1 = L1Settlement::new();
    let root_before = l1.state_root();
    let version_before = l1.version();

    let new_root = l1.anchor_inflation_index_change(ChainId::new("academic-chain"));

    assert_eq!(l1.version(), version_before + 1);
    assert_ne!(new_root, root_before);
    assert_eq!(l1.state_root(), new_root);

    let entry = l1.anchor_log().last().expect("an anchor entry was logged");
    assert_eq!(entry.kind, AnchorKind::InflationIndexChange);
    assert_eq!(entry.chain_id, Some(ChainId::new("academic-chain")));
}

/// Requirement 8.6: anchoring the MeriToken/L2 post-batch state root advances the
/// confirmed state to the supplied root.
#[test]
fn req_8_6_mint_state_root_anchor_advances_confirmed_state() {
    let mut l1 = L1Settlement::new();
    let version_before = l1.version();
    let mint_state_root = StateRoot::from_bytes([7u8; 32]);

    let confirmed = l1.update_state_root(mint_state_root);

    assert_eq!(confirmed, mint_state_root);
    assert_eq!(l1.state_root(), mint_state_root);
    assert_eq!(l1.version(), version_before + 1);

    let entry = l1.anchor_log().last().expect("an anchor entry was logged");
    assert_eq!(entry.kind, AnchorKind::StateRootUpdate);
    assert_eq!(entry.resulting_root, mint_state_root);
}

/// Requirement 10.7: anchoring a retroactive review outcome advances the confirmed state
/// and stores the outcome (审核状态与投票结果) so it is queryable.
#[test]
fn req_10_7_retroactive_outcome_anchor_advances_confirmed_state() {
    let mut l1 = L1Settlement::new();
    let root_before = l1.state_root();
    let version_before = l1.version();

    let new_root = l1.anchor_retroactive_outcome(VoteResultRecord::new(
        "retro-7",
        "retro:carbon-chain",
        true,
        ts(5_000),
    ));

    assert_eq!(l1.version(), version_before + 1);
    assert_ne!(new_root, root_before);
    assert_eq!(l1.state_root(), new_root);

    // The retroactive outcome is stored and reports the recorded vote result.
    let outcome = l1
        .vote_result("retro-7")
        .expect("the retroactive outcome is anchored to L1");
    assert!(outcome.passed);
    assert_eq!(outcome.subject, "retro:carbon-chain");

    let entry = l1.anchor_log().last().expect("an anchor entry was logged");
    assert_eq!(entry.kind, AnchorKind::RetroactiveOutcome);
    assert_eq!(entry.resulting_root, new_root);
}

/// Anchoring the six per-module settled changes in sequence advances the confirmed state
/// monotonically and to distinct roots, with the audit log recording each in order
/// (Requirements 2.6 / 3.8 / 5.1 / 7.7 / 8.6 / 10.7 composed end-to-end).
#[test]
fn per_module_anchors_each_advance_to_distinct_confirmed_roots() {
    let mut l1 = L1Settlement::new();

    let mut roots = vec![l1.state_root()];

    roots.push(l1.anchor_chain_creation(chain_record("c1", "gmc-base", "domain-1"))); // 2.6
    roots.push(l1.anchor_mechanism_change(ChainId::new("c1"))); // 3.8
    roots.push(l1.anchor_derivation_state_root(StateRoot::from_bytes([1u8; 32]))); // 5.1
    roots.push(l1.anchor_inflation_index_change(ChainId::new("c1"))); // 7.7
    roots.push(l1.update_state_root(StateRoot::from_bytes([2u8; 32]))); // 8.6
    roots.push(l1.anchor_retroactive_outcome(VoteResultRecord::new(
        "retro-1",
        "retro:c1",
        false,
        ts(6_000),
    ))); // 10.7

    // Six settled changes => six monotonic version bumps from genesis.
    assert_eq!(l1.version(), 6);

    // Every anchoring produced a confirmed root distinct from all the others (each
    // settled change moves the confirmed state forward to a fresh value).
    for (i, a) in roots.iter().enumerate() {
        for b in roots.iter().skip(i + 1) {
            assert_ne!(
                a, b,
                "each settled change must advance to a distinct confirmed root"
            );
        }
    }

    // The audit log records exactly the six anchoring kinds, in order.
    let kinds: Vec<AnchorKind> = l1.anchor_log().iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            AnchorKind::ChainCreation,
            AnchorKind::MechanismChange,
            AnchorKind::DerivationStateRoot,
            AnchorKind::InflationIndexChange,
            AnchorKind::StateRootUpdate,
            AnchorKind::RetroactiveOutcome,
        ]
    );
}

// ---------------------------------------------------------------------------
// Requirement 13.4: every on-chain transaction is fee-free.
// ---------------------------------------------------------------------------

#[test]
fn req_13_4_l1_is_configured_fee_free() {
    let l1 = L1Settlement::new();
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);
    assert!(l1.transaction_fee().is_zero());
    assert!(l1.is_fee_free());
    assert_eq!(L1Settlement::TRANSACTION_FEE, Decimal::ZERO);
}

/// Requirement 13.4: the per-transaction fee stays zero across an arbitrary sequence of
/// anchoring transactions — no anchoring transaction ever charges a fee.
#[test]
fn req_13_4_every_anchoring_transaction_is_fee_free() {
    let mut l1 = L1Settlement::new();

    // Before any transaction.
    assert!(l1.is_fee_free());
    assert!(l1.transaction_fee().is_zero());

    // Drive one of every anchoring transaction kind; assert fee-free after each.
    l1.anchor_chain_creation(chain_record("c1", "gmc-base", "domain-1"));
    assert!(
        l1.is_fee_free(),
        "chain-creation transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.store_identity_registration(IdentityRegistrationRecord::new(
        FayID::new("fay-1"),
        ts(2_000),
    ));
    assert!(
        l1.is_fee_free(),
        "identity-registration transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.anchor_mechanism_change(ChainId::new("c1"));
    assert!(
        l1.is_fee_free(),
        "mechanism-change transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.anchor_inflation_index_change(ChainId::new("c1"));
    assert!(
        l1.is_fee_free(),
        "inflation-index-change transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.anchor_derivation_state_root(StateRoot::from_bytes([1u8; 32]));
    assert!(
        l1.is_fee_free(),
        "derivation-root transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.update_state_root(StateRoot::from_bytes([2u8; 32]));
    assert!(
        l1.is_fee_free(),
        "state-root-update transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.anchor_retroactive_outcome(VoteResultRecord::new(
        "retro-1",
        "retro:c1",
        true,
        ts(6_000),
    ));
    assert!(
        l1.is_fee_free(),
        "retroactive-outcome transaction must be fee-free"
    );
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.store_vote_result(VoteResultRecord::new("vote-1", "subject", true, ts(7_000)));
    assert!(l1.is_fee_free(), "vote-result transaction must be fee-free");
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    l1.record_penalty(PenaltyRecord::new(FayID::new("fay-x"), "reason", ts(8_000)));
    assert!(l1.is_fee_free(), "penalty transaction must be fee-free");
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);

    // Many transactions settled, yet the cumulative fee charged is still zero.
    assert!(
        l1.version() >= 9,
        "all anchoring transactions advanced the settled state"
    );
    assert!(l1.is_fee_free());
    assert_eq!(l1.transaction_fee(), Decimal::ZERO);
}
