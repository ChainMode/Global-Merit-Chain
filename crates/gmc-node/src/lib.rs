//! # `gmc-node` — GMChain Persistent Single-Node Testnet Runtime
//!
//! `gmc-node` sits above the zero-dependency pure-logic `gmc-core` and `gmc-identity`
//! crates, supplying real Ed25519 cryptography (`ed25519-dalek` with RFC 8032 KAT
//! startup verification), crash-consistent disk persistence (append-only SHA-256 WAL +
//! atomic temp-file-and-rename snapshots), L2 rollup batching into zero-fee L1
//! settlement (`TRANSACTION_FEE == 0`, `NODE_BLOCK_REWARD == 0`), and a bounded local
//! loopback control server (`127.0.0.1`, `<= 256 KiB` request ceiling).

pub mod crypto;
pub mod error;
pub mod rpc;
pub mod runtime;
pub mod store;
