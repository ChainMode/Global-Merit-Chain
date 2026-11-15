//! Deliverable smoke checks for one-time configuration and tracked blueprint
//! technology-selection deliverables.
//!
//! These are plain `#[test]` smoke/unit checks — **NOT** property tests — verifying:
//! 1. **One-time protocol configuration (Requirements 1.1 / 13.4 / 13.6)**:
//!    `GMC_Base` sits at derivation depth `0` under `"gmc-base"`, L1 settlement is
//!    strictly fee-free (`TRANSACTION_FEE == 0`), and the L1 settlement model declares
//!    `GRANDPA/BABE`.
//! 2. **Tracked technology-selection blueprint deliverables (Requirements 5.2 / 5.3 / 5.6)**:
//!    verifies against the repository's tracked architecture chapter
//!    (`docs/zh-CN/blueprint/12-技术架构.md`) that the baseline `Substrate` + `ZK Rollup`
//!    architecture, comparison candidates (`Ethereum` mainnet / L2 / `DAG`), comparison
//!    table covering Gas cost, throughput, and customizability, and selection rationale
//!    are all present in any clean clone.

use std::fs;
use std::path::PathBuf;

use gmc_core::gmc_base::GmcBase;
use gmc_core::l1_settlement::{ConsensusConfig, L1Settlement};
use gmc_core::types::ChainId;

fn read_tracked_architecture_blueprint() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/zh-CN/blueprint/12-技术架构.md");
    fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "tracked architecture blueprint must exist at {}: {err}",
            path.display()
        )
    })
}

// --- Requirement 1.1: root-node configuration ----------------------------------

#[test]
fn gmc_base_is_the_fixed_depth_zero_root() {
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

// --- Requirements 5.2 / 5.3 / 5.6: tracked blueprint technology selection ------

#[test]
fn blueprint_technology_selection_covers_baseline_comparisons_and_rationale() {
    let doc = read_tracked_architecture_blueprint();

    // Baseline architecture: Substrate L1 + ZK Rollup L2
    assert!(
        doc.contains("Substrate") && doc.contains("ZK Rollup"),
        "architecture blueprint must document Substrate + ZK Rollup baseline"
    );

    // Comparison candidates: Ethereum mainnet, Ethereum L2, DAG / Optimistic Rollup
    assert!(
        doc.contains("Ethereum 主网")
            && doc.contains("Ethereum L2")
            && doc.contains("Optimistic Rollup"),
        "architecture blueprint must compare alternative chain/rollup candidates"
    );

    // Comparison table & three core evaluation axes (zero Gas fee, TPS throughput, custom governance)
    assert!(
        doc.contains("| 方案 |")
            && doc.contains("Gas 费")
            && doc.contains("吞吐量")
            && doc.contains("可定制治理"),
        "architecture blueprint must evaluate transaction cost, throughput, and governance customizability"
    );

    // Explicit recommendation & layered BFT / GRANDPA consensus roles
    assert!(
        doc.contains("推荐") && doc.contains("BFT") && doc.contains("GRANDPA/BABE"),
        "architecture blueprint must state the recommended selection and consensus layering"
    );
}
