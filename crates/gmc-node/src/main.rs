//! `gmc-node` CLI binary: local testnet initialization, inspection, deterministic block
//! production, end-to-end showcase (`demo`), and loopback control server (`serve`).

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;

use gmc_core::relationship::{compute_intimacy, PrivacyTier, RelationshipType};
use gmc_core::types::{ChainId, Decimal, Ratio, Timestamp};
use gmc_identity::identity_core::OperationPayload;
use gmc_identity::types::DeviceType;

use gmc_node::crypto::{keypair_from_seed, sign_ed25519_operation, OperatorKeyStore};
use gmc_node::error::{NodeError, NodeResult};
use gmc_node::rpc::start_control_server;
use gmc_node::runtime::{NodeConfig, NodeRuntime, DEFAULT_CHAIN_ID};

fn main() -> ExitCode {
    match run_cli(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: gmc-node <subcommand> --data-dir <dir> [options]\n\
         \n\
         Subcommands:\n\
           init           Initialize operator keystore (0600) and genesis snapshot\n\
           status         Print node status and canonical SHA-256 StateRoot\n\
           produce-block  Seal pending L2 records and produce a 0-fee / 0-reward block\n\
           demo           Run deterministic end-to-end GMChain lifecycle showcase\n\
           serve          Run bounded local loopback HTTP/JSON-RPC control server\n\
         \n\
         Options:\n\
           --data-dir <dir>       Node data directory (required)\n\
           --chain-id <id>        Chain identifier (default: {DEFAULT_CHAIN_ID})\n\
           --addr <ip:port>       Loopback bind address for `serve` (default: 127.0.0.1:0)\n\
           --timestamp <secs>     Explicit Unix timestamp in seconds\n\
           --max-requests <n>     Optional request count after which `serve` exits cleanly"
    );
}

fn run_cli(args: Vec<String>) -> NodeResult<()> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(());
    }

    let subcmd = args[0].as_str();
    let mut data_dir: Option<PathBuf> = None;
    let mut chain_id = DEFAULT_CHAIN_ID.to_string();
    let mut addr = "127.0.0.1:0".to_string();
    let mut timestamp_secs: u64 = 1_700_000_000;
    let mut max_requests: Option<usize> = None;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| NodeError::ConfigInvalid("missing --data-dir value".into()))?;
                data_dir = Some(PathBuf::from(val));
            }
            "--chain-id" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| NodeError::ConfigInvalid("missing --chain-id value".into()))?;
                chain_id = val.clone();
            }
            "--addr" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| NodeError::ConfigInvalid("missing --addr value".into()))?;
                addr = val.clone();
            }
            "--timestamp" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| NodeError::ConfigInvalid("missing --timestamp value".into()))?;
                timestamp_secs = val
                    .parse()
                    .map_err(|_| NodeError::ConfigInvalid("invalid --timestamp".into()))?;
            }
            "--max-requests" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    NodeError::ConfigInvalid("missing --max-requests value".into())
                })?;
                max_requests = Some(
                    val.parse()
                        .map_err(|_| NodeError::ConfigInvalid("invalid --max-requests".into()))?,
                );
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => {
                return Err(NodeError::ConfigInvalid(format!(
                    "unrecognized argument '{other}'"
                )));
            }
        }
        i += 1;
    }

    let Some(data_dir) = data_dir else {
        return Err(NodeError::ConfigInvalid(
            "--data-dir <dir> is required".into(),
        ));
    };

    let mut config = NodeConfig::new(&data_dir);
    config.chain_id = chain_id;

    match subcmd {
        "init" => {
            let mut node = NodeRuntime::init(config)?;
            let st = node.status();
            node.shutdown()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&st)
                    .map_err(|e| NodeError::Io(e.to_string()))?
            );
            Ok(())
        }
        "status" => {
            let node = NodeRuntime::open(config)?;
            let st = node.status();
            println!(
                "{}",
                serde_json::to_string_pretty(&st)
                    .map_err(|e| NodeError::Io(e.to_string()))?
            );
            Ok(())
        }
        "produce-block" => {
            let mut node = NodeRuntime::open(config)?;
            let receipt = node.produce_block(Timestamp::from_secs(timestamp_secs))?;
            node.shutdown()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt)
                    .map_err(|e| NodeError::Io(e.to_string()))?
            );
            Ok(())
        }
        "demo" => run_demo(config),
        "serve" => {
            config.control_addr = Some(addr.clone());
            let node = NodeRuntime::open(config)?;
            let shared = Arc::new(Mutex::new(node));
            let handle = start_control_server(shared, &addr, false, max_requests)?;
            println!(
                "{}",
                json!({
                    "listening_addr": handle.local_addr().to_string(),
                    "max_request_bytes": gmc_node::rpc::MAX_REQUEST_BYTES,
                })
            );
            if max_requests.is_some() {
                while !handle.is_stopped() {
                    thread::sleep(Duration::from_millis(10));
                }
            } else {
                loop {
                    thread::sleep(Duration::from_secs(3600));
                }
            }
            let _ = handle.shutdown()?;
            Ok(())
        }
        other => Err(NodeError::ConfigInvalid(format!(
            "unknown subcommand '{other}'"
        ))),
    }
}

fn run_demo(config: NodeConfig) -> NodeResult<()> {
    let mut node = if OperatorKeyStore::exists(&config.data_dir) {
        NodeRuntime::open(config.clone())?
    } else {
        NodeRuntime::init_with_seed(config.clone(), [0x11u8; 32])?
    };

    let t0 = Timestamp::from_secs(1_700_000_000);
    let (alice_sk, alice_vk) = keypair_from_seed(&[0xA1u8; 32]);
    let (_alice_dev_sk, alice_dev_vk) = keypair_from_seed(&[0xA2u8; 32]);
    let (_alice_rot_sk, alice_rot_vk) = keypair_from_seed(&[0xA3u8; 32]);
    let (_bob_sk, bob_vk) = keypair_from_seed(&[0xB1u8; 32]);

    let alice_id = node.register_ifay(&alice_vk, t0)?;
    let bob_id = node.register_ifay(&bob_vk, t0)?;

    // 1. Real Ed25519 SignedOperation: EnrollDevice + RotateKey (preserving IdentityId!)
    let enroll_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::EnrollDevice {
            device_key: alice_dev_vk,
            device_type: DeviceType::Phone,
        },
        1,
    )?;
    node.submit_signed_operation(enroll_op, t0)?;

    let rotate_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::RotateKey {
            new_key: alice_rot_vk,
        },
        2,
    )?;
    node.submit_signed_operation(rotate_op, Timestamp::from_secs(1_700_000_010))?;

    // 2. Bilateral social relationship & reciprocal interaction intimacy
    let alice_fay = alice_id.to_fay_id();
    let bob_fay = bob_id.to_fay_id();
    node.register_relationship(
        alice_fay.clone(),
        bob_fay.clone(),
        RelationshipType::Kinship,
        PrivacyTier::ExistencePublic,
        t0,
    )?;
    let depth = Ratio::new(Decimal::from_raw(800_000)).unwrap();
    node.record_interaction(&alice_fay, &bob_fay, depth, Timestamp::from_secs(1_700_000_020))?;
    node.record_interaction(&bob_fay, &alice_fay, depth, Timestamp::from_secs(1_700_000_025))?;
    let intimacy_raw = node
        .relationships()
        .get_edge(&alice_fay, &bob_fay)
        .map(|e| compute_intimacy(e, Timestamp::from_secs(1_700_000_030)).value().raw())
        .unwrap_or(0);

    // 3. L2 contribution ingestion -> zero-fee / zero-reward L1 block settlement
    let contrib = node.submit_contribution(
        &alice_id,
        ChainId::new("gmc-base"),
        Decimal::from_int(25),
        Decimal::from_int(86_400),
        Timestamp::from_secs(1_700_000_040),
    )?;
    let block = node.produce_block(Timestamp::from_secs(1_700_000_100))?;
    let root_before_restart = node.state_root_hex();
    node.shutdown()?;

    // 4. Reopen from disk and confirm deterministic StateRoot equivalence
    let reopened = NodeRuntime::open(config)?;
    let root_after_restart = reopened.state_root_hex();
    if root_before_restart != root_after_restart {
        return Err(NodeError::SnapshotInvalid(
            "demo restart state_root mismatch".into(),
        ));
    }

    let summary = json!({
        "demo": "ok",
        "alice_identity_id": alice_id.canonical(),
        "bob_identity_id": bob_id.canonical(),
        "bilateral_intimacy_scaled": intimacy_raw,
        "contribution_batch_id": contrib.batch_id,
        "block_height": block.block_height,
        "settled_records": block.settled_records,
        "fee_charged": "0",
        "node_block_reward": "0",
        "state_root_hex": root_after_restart,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|e| NodeError::Io(e.to_string()))?
    );
    Ok(())
}
