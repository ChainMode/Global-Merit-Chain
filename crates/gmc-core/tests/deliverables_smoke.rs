//! Deliverable smoke checks for one-time configuration requirements.
//!
//! These are plain `#[test]` smoke/unit checks — **NOT** property tests — so they carry
//! no `Feature: ... Property N` label. They verify the "deliverable" acceptance criteria
//! that the design explicitly routes to smoke tests rather than PBT:
//!
//! **One-time configuration (Requirements 1.1 / 13.4 / 13.6).** The root-node config
//! (`GMC_Base` is the fixed depth-0 root), L1 being fee-free, and L1 running
//! GRANDPA/BABE consensus are asserted through the crate's public API.
//!
//! # Why the design-document assertions were removed (2026-08-12)
//!
//! This file previously also asserted on prose inside a specification document
//! (Requirements 5.2 / 5.3 / 5.6: that the "技术选型评估" section names a baseline
//! candidate, a comparison candidate, a three-dimensional comparison table, and a
//! recommendation with rationale). Those four tests read the document at runtime —
//! originally from `.kiro/specs/`, later repointed to `openspec/specs/`.
//!
//! They were removed because that approach became structurally unsound:
//!
//! 1. **The file is deliberately not in git.** Per PO decision D-1/D-2 (2026-08-12),
//!    `openspec/` is a development-team-only asset and is gitignored in all repositories;
//!    `docs/` is the sole published artifact. A test in this public repository therefore
//!    cannot depend on `openspec/` content: it passes locally (where `openspec/` exists)
//!    but panics with "No such file or directory" in a fresh clone or in CI.
//! 2. **The constraint is already enforced where it belongs.** The same requirements are
//!    expressed as six requirements in `openspec/specs/technology-selection/spec.md`
//!    (candidate scope, three-dimensional comparison, recommendation rationale, and the
//!    obligation to record major technology decisions) and are checked by
//!    `openspec validate --all --strict` plus review — not by `cargo test`.
//! 3. **Asserting on document prose from an integration test is the wrong layer.**
//!    Whether a specification contains a Markdown table is a documentation-governance
//!    concern, not a property of this crate's code.
//!
//! Net effect: no constraint was lost, and `cargo test` no longer depends on files that
//! are absent from the repository. See OQ-P2-GMC-SMOKE in the migration contract.

use gmc_core::gmc_base::GmcBase;
use gmc_core::l1_settlement::{ConsensusConfig, L1Settlement};
use gmc_core::types::ChainId;

// --- Requirement 1.1: root-node configuration ----------------------------------

#[test]
fn gmc_base_is_the_fixed_depth_zero_root() {
    // Requirement 1.1: GMC_Base is the single depth-0 root under a fixed identifier.
    assert_eq!(
        GmcBase::ROOT_DEPTH,
        0,
        "GMC_Base must sit at derivation depth 0"
    );
    assert_eq!(
        GmcBase::root_chain_id(),
        ChainId::new("gmc-base"),
        "GMC_Base must expose the fixed root chain id"
    );
    assert_eq!(
        GmcBase::root_chain_id().as_str(),
        GmcBase::ROOT_CHAIN_ID,
        "root_chain_id() must agree with the ROOT_CHAIN_ID constant"
    );
}

// --- Requirement 13.4: L1 fee-free configuration -------------------------------

#[test]
fn l1_settlement_is_configured_fee_free() {
    // Requirement 13.4: L1 charges no transaction fee.
    let l1 = L1Settlement::new();
    assert!(
        l1.is_fee_free(),
        "L1_Settlement must be configured fee-free"
    );
    assert!(
        l1.transaction_fee().is_zero(),
        "the L1 per-transaction fee must be exactly zero"
    );
    assert!(
        L1Settlement::TRANSACTION_FEE.is_zero(),
        "the L1 TRANSACTION_FEE constant must be exactly zero"
    );
}

// --- Requirement 13.6: L1 GRANDPA/BABE consensus -------------------------------

#[test]
fn l1_settlement_uses_grandpa_babe_consensus() {
    // Requirement 13.6: L1 runs GRANDPA (finality) + BABE (block production).
    let l1 = L1Settlement::new();
    let consensus = l1.consensus_config();

    assert_eq!(
        consensus,
        ConsensusConfig::GrandpaBabe,
        "L1 consensus must be GRANDPA/BABE"
    );
    assert!(consensus.uses_grandpa(), "L1 must use GRANDPA finality");
    assert!(consensus.uses_babe(), "L1 must use BABE block production");
    assert_eq!(
        consensus.label(),
        "GRANDPA/BABE",
        "L1 consensus label must read GRANDPA/BABE"
    );
}
