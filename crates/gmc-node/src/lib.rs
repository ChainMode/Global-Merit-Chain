//! # `gmc-node` — GMChain Multi-Node BFT Runtime & Meritora Desktop Workbench
//!
//! `gmc-node` sits above the zero-dependency pure-logic `gmc-core` and `gmc-identity`
//! crates, supplying real Ed25519 cryptography (`ed25519-dalek` with RFC 8032 KAT
//! startup verification), deterministic two-phase BFT consensus (`ValidatorSet`,
//! `QuorumCertificate`, non-monetary `EquivocationEvidence` validator ejection, and
//! bounded TCP peer-to-peer cluster messaging), crash-consistent disk persistence
//! (append-only SHA-256 WAL + atomic temp-file-and-rename snapshots), L2 rollup
//! batching into zero-fee L1 settlement (`TRANSACTION_FEE == 0`, `NODE_BLOCK_REWARD == 0`,
//! `VALIDATOR_REWARD == 0`), and the self-contained `Meritora Desktop` loopback UI.

pub mod consensus;
pub mod crypto;
pub mod error;
pub mod network;
pub mod rpc;
pub mod runtime;
pub mod store;
pub mod testnet;
pub mod workbench;
