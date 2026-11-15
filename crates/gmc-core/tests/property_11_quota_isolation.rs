//! Property 11 — 配额逐链隔离 (per-chain quota isolation).
//!
//! This is the dedicated property-based test for **Property 11** of the
//! `gmc-core-protocol` design's *Correctness Properties* section (task 6.6).
//!
//! > **Property 11: 配额逐链隔离** — *对任意* 涉及多条链的交错铸造请求序列，任一条链的
//! > `mintedThisPeriod` 仅由对该链的铸造决定，对其它链的铸造不改变本链的可用配额。
//!
//! **Validates: Requirements 4.6**
//!
//! ## Approach
//!
//! Per [`gmc_core::quota::QuotaLedgerSet`], each [`ChainId`] maps to its *own*
//! `(QuotaConfig, QuotaLedger)` pair, and `consume` routes to exactly one entry. The
//! isolation claim is therefore: driving an **interleaved** multi-chain mint sequence
//! through one shared [`QuotaLedgerSet`] leaves each chain's `mintedThisPeriod` (and
//! its exhausted flag, i.e. its remaining available quota) **identical** to what it
//! would be if *only that chain's own* requests — in their original relative order —
//! had been applied to a standalone ledger.
//!
//! The single proptest below:
//!
//! 1. registers every chain in the generator's id pool with its own validated config,
//! 2. drives the whole interleaved sequence through the shared `QuotaLedgerSet`,
//! 3. for each chain, replays **only that chain's** ops (same relative order) against a
//!    fresh standalone [`QuotaLedger`] built from the *same* config, and
//! 4. asserts the shared set and the standalone reference agree on both
//!    `mintedThisPeriod` and `is_exhausted` for that chain.
//!
//! Agreement means inter-chain mints never touched the chain's accounting — exactly
//! the per-chain isolation of Requirement 4.6. No time advance / period rollover is
//! involved (isolation is purely about mint accounting), so `reset_if_elapsed` is not
//! exercised here.

mod common;

use common::generators;
use gmc_core::quota::{QuotaConfig, QuotaLedger, QuotaLedgerSet, RefreshPeriod, TimeUnit};
use gmc_core::types::{ChainId, Decimal, Timestamp};
use proptest::prelude::*;

/// The generator id pool (`generators::chain_id`) draws from `chain-0 ..= chain-15`,
/// so registering exactly these 16 chains guarantees every generated `MintOp` targets
/// a registered chain.
const POOL_SIZE: u32 = 16;

/// Fixed period start shared by every ledger. No rollover is triggered in this test.
const PERIOD_START: Timestamp = Timestamp::from_secs(1_000);

/// A deterministic, *valid* per-chain config that varies across the pool so the
/// property is exercised against both one-time and periodic chains and a spread of
/// quota caps. Both the shared set and the standalone reference use this same mapping,
/// which is what makes their results directly comparable.
fn config_for(index: u32) -> QuotaConfig {
    let quota = Decimal::from_int(((index % 5) as i64 + 1) * 200);
    let refresh = if index.is_multiple_of(2) {
        RefreshPeriod::OneTime
    } else {
        RefreshPeriod::Periodic {
            unit: TimeUnit::Day,
            value: Decimal::ONE,
        }
    };
    QuotaConfig::new(quota, refresh).expect("positive quota + valid refresh is a valid config")
}

/// `chain-n` id for a pool index.
fn pool_chain_id(index: u32) -> ChainId {
    ChainId::new(format!("chain-{index}"))
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 11: 配额逐链隔离
    #[test]
    fn property_11_quota_isolation(
        ops in generators::interleaved_mint_sequence(64),
    ) {
        // --- (1) Register every pool chain with its own independent config. ---
        let mut set = QuotaLedgerSet::new();
        for index in 0..POOL_SIZE {
            set.register(pool_chain_id(index), config_for(index), PERIOD_START);
        }

        // --- (2) Drive the full interleaved sequence through the shared set. ---
        // Each op routes to exactly one chain's ledger; accepted/rejected outcomes are
        // both fine — we care about the resulting per-chain accounting, not any single
        // request's verdict.
        for op in &ops {
            let _ = set.consume(&op.chain_id, op.amount);
        }

        // --- (3) & (4) For each chain, replay ONLY its own ops in original order
        //         against a fresh standalone ledger, then compare. ---
        for index in 0..POOL_SIZE {
            let chain_id = pool_chain_id(index);
            let config = config_for(index);

            let mut isolated = QuotaLedger::new(chain_id.clone(), PERIOD_START);
            for op in ops.iter().filter(|op| op.chain_id == chain_id) {
                let _ = isolated.consume_quota(&config, op.amount);
            }

            // The shared set must agree with the isolated replay: mints to *other*
            // chains never changed this chain's minted total ...
            let set_minted = set
                .minted_this_period(&chain_id)
                .expect("registered chain has a ledger");
            prop_assert_eq!(
                set_minted,
                isolated.minted_this_period(),
                "chain {} mintedThisPeriod must depend only on its own mints",
                chain_id
            );

            // ... nor its remaining available quota (the exhausted flag for a one-time
            // chain, which gates all future quota).
            let set_ledger = set.ledger(&chain_id).expect("registered chain has a ledger");
            prop_assert_eq!(
                set_ledger.is_exhausted(),
                isolated.is_exhausted(),
                "chain {} exhausted state must depend only on its own mints",
                chain_id
            );
        }
    }
}
