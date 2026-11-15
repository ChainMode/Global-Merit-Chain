//! Wave 4 TDD integration suite for `gmc-node`:
//! 1. Deterministic Ed25519 two-phase BFT consensus (`ValidatorSet`, `SignedConsensusVote`,
//!    `QuorumCertificate`, `EquivocationEvidence`, `VALIDATOR_REWARD == 0`);
//! 2. Multi-node TCP `BftClusterNode` (`4` validators, `1` offline/equivocating fault tolerance,
//!    `< 3000ms` finality budget, forged `state_root` rejection, cross-node `StateRoot` convergence);
//! 3. Loopback CORS + `OPTIONS 204` JSON-RPC (`gmc_status`, `gmc_validators`, `gmc_produceBlock`,
//!    `gmc_demoStep`) and self-contained bilingual `Meritora Desktop (Preview v0.2)` HTML (`GET /`);
//! 4. CLI `cluster-demo` and `workbench` subcommands.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};

use gmc_core::types::{ChainId, Decimal};

use gmc_node::consensus::{
    quorum_threshold, BftStep, BlockProposal, BlockTransaction, EquivocationEvidence,
    QuorumCertificate, SignedConsensusVote, ValidatorInfo, ValidatorSet, BFT_FINALITY_BUDGET_MS,
    VALIDATOR_REWARD,
};
use gmc_node::crypto::keypair_from_seed;
use gmc_node::error::NodeError;
use gmc_node::network::{BftClusterNode, BftWireMessage};
use gmc_node::rpc::start_control_server;
use gmc_node::runtime::{NodeConfig, NodeRuntime, NODE_BLOCK_REWARD, NODE_TRANSACTION_FEE};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "gmc-w4-it-{prefix}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        TempDirGuard(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_committee(count: usize) -> (Vec<([u8; 32], ValidatorInfo)>, ValidatorSet) {
    let prefixes = ["ifay", "cofay", "org", "ifay"];
    let mut members = Vec::with_capacity(count);
    let mut infos = Vec::with_capacity(count);
    for idx in 0..count {
        let seed = [(0x40 + idx as u8); 32];
        let (_sk, vk) = keypair_from_seed(&seed);
        let pubkey: [u8; 32] = vk.as_bytes().try_into().unwrap();
        let pfx = prefixes[idx % prefixes.len()];
        let validator_id = format!("{pfx}_validatornode{}", idx + 1);
        let info = ValidatorInfo::new(validator_id, pubkey).expect("valid validator info");
        members.push((seed, info.clone()));
        infos.push(info);
    }
    let set = ValidatorSet::new(infos).expect("valid validator set");
    (members, set)
}

#[test]
fn consensus_primitives_quorum_qc_and_equivocation_ejection() {
    // Constitutional non-monetary invariants
    assert_eq!(VALIDATOR_REWARD, 0);
    assert!(NODE_TRANSACTION_FEE.is_zero());
    assert!(NODE_BLOCK_REWARD.is_zero());
    assert_eq!(BFT_FINALITY_BUDGET_MS, 3_000);

    // Quorum formula: (2 * n) / 3 + 1
    assert_eq!(quorum_threshold(1), 1);
    assert_eq!(quorum_threshold(3), 3);
    assert_eq!(quorum_threshold(4), 3);
    assert_eq!(quorum_threshold(7), 5);

    // Plaintext Human Prime `hid_` MUST be rejected from ValidatorInfo
    let (_sk0, vk0) = keypair_from_seed(&[0x11; 32]);
    let pk0: [u8; 32] = vk0.as_bytes().try_into().unwrap();
    assert!(ValidatorInfo::new("hid_forbiddenhumanid", pk0).is_err());

    let (members, mut vset) = make_committee(4);
    assert_eq!(vset.active_count(), 4);
    assert_eq!(vset.quorum_threshold(), 3);

    // Deterministic round-robin proposer `(height + round) % active_count`
    assert_eq!(
        vset.proposer_for(1, 0).unwrap().validator_id,
        members[1].1.validator_id
    );
    assert_eq!(
        vset.proposer_for(1, 2).unwrap().validator_id,
        members[3].1.validator_id
    );
    assert_eq!(
        vset.proposer_for(2, 2).unwrap().validator_id,
        members[0].1.validator_id
    );

    let chain_id = "gmc-bft-unit-1";
    let block_hash_a = [0xAAu8; 32];
    let block_hash_b = [0xBBu8; 32];
    let state_root = [0xCCu8; 32];

    // Sign Precommit votes from 3 distinct active validators -> valid QC
    let vote0 = SignedConsensusVote::sign(
        &members[0].0,
        &members[0].1.validator_id,
        chain_id,
        1,
        0,
        BftStep::Precommit,
        block_hash_a,
        state_root,
    )
    .unwrap();
    let vote1 = SignedConsensusVote::sign(
        &members[1].0,
        &members[1].1.validator_id,
        chain_id,
        1,
        0,
        BftStep::Precommit,
        block_hash_a,
        state_root,
    )
    .unwrap();
    let vote2 = SignedConsensusVote::sign(
        &members[2].0,
        &members[2].1.validator_id,
        chain_id,
        1,
        0,
        BftStep::Precommit,
        block_hash_a,
        state_root,
    )
    .unwrap();

    // Duplicate votes from the same validator MUST NOT satisfy 3-of-4 quorum!
    let dup_qc = QuorumCertificate {
        chain_id: chain_id.into(),
        height: 1,
        round: 0,
        step: BftStep::Precommit,
        block_hash: block_hash_a,
        state_root,
        votes: vec![vote0.clone(), vote0.clone(), vote0.clone()],
    };
    assert!(dup_qc.verify(&vset, chain_id).is_err());

    // 2-of-4 votes MUST NOT satisfy quorum!
    let under_quorum_qc = QuorumCertificate {
        chain_id: chain_id.into(),
        height: 1,
        round: 0,
        step: BftStep::Precommit,
        block_hash: block_hash_a,
        state_root,
        votes: vec![vote0.clone(), vote1.clone()],
    };
    assert!(under_quorum_qc.verify(&vset, chain_id).is_err());

    // 3-of-4 distinct active validator votes MUST pass strict verification!
    let valid_qc = QuorumCertificate {
        chain_id: chain_id.into(),
        height: 1,
        round: 0,
        step: BftStep::Precommit,
        block_hash: block_hash_a,
        state_root,
        votes: vec![vote0, vote1, vote2],
    };
    valid_qc.verify(&vset, chain_id).expect("3/4 QC must verify");

    // EquivocationEvidence: validator 3 double-votes for block_hash_a and block_hash_b at (1, 0, Prevote)
    let eq_a = SignedConsensusVote::sign(
        &members[3].0,
        &members[3].1.validator_id,
        chain_id,
        1,
        0,
        BftStep::Prevote,
        block_hash_a,
        state_root,
    )
    .unwrap();
    let eq_b = SignedConsensusVote::sign(
        &members[3].0,
        &members[3].1.validator_id,
        chain_id,
        1,
        0,
        BftStep::Prevote,
        block_hash_b,
        state_root,
    )
    .unwrap();

    // Identical block hash is NOT equivocation
    let non_eq = EquivocationEvidence {
        vote_a: eq_a.clone(),
        vote_b: eq_a.clone(),
    };
    assert!(non_eq.verify(&vset, chain_id).is_err());

    // Distinct block hashes at same (height, round, step) immediately ejects validator 3 (`active = false`)
    let evidence = EquivocationEvidence {
        vote_a: eq_a,
        vote_b: eq_b,
    };
    let ejected_id = vset.apply_equivocation(&evidence, chain_id).unwrap();
    assert_eq!(ejected_id, members[3].1.validator_id);
    assert!(!vset.get(&ejected_id).unwrap().active);
    assert_eq!(vset.active_count(), 3);
}

#[test]
fn four_node_tcp_bft_cluster_fault_tolerance_equivocation_and_state_root_convergence() {
    let base_dir = TempDirGuard::new("tcp-cluster");
    let chain_id = "gmc-bft-cluster-it";
    let (members, vset) = make_committee(4);

    let mut nodes: Vec<BftClusterNode> = Vec::with_capacity(4);
    for (idx, (seed, info)) in members.iter().enumerate() {
        let node_dir = base_dir.path().join(format!("val-{idx}"));
        let mut cfg = NodeConfig::new(&node_dir);
        cfg.chain_id = chain_id.to_string();
        let node = BftClusterNode::spawn(
            cfg,
            *seed,
            info.validator_id.clone(),
            vset.clone(),
            "127.0.0.1:0",
        )
        .expect("spawn BftClusterNode");
        nodes.push(node);
    }

    let addrs: Vec<_> = nodes.iter().map(|n| n.local_addr()).collect();
    for (idx, node) in nodes.iter().enumerate() {
        let peers: Vec<_> = addrs
            .iter()
            .enumerate()
            .filter_map(|(j, a)| if j != idx { Some(*a) } else { None })
            .collect();
        node.set_peers(peers);
    }

    // Height 1 (4/4 validators online): register Alice, submit L2 contribution, commit via TCP BFT!
    let (_alice_sk, alice_vk) = keypair_from_seed(&[0xA1u8; 32]);
    let alice_id = gmc_identity::identity_id::derive_identity_id(
        &nodes[0].with_runtime(|rt| rt.identities().registry.clone()),
        &gmc_identity::types::SchemeTag::ed25519(),
        &alice_vk,
    )
    .unwrap();

    let h1_txs = vec![
        BlockTransaction::RegisterIfay {
            verifying_key_hex: hex::encode(alice_vk.as_bytes()),
            timestamp_secs: 1_700_000_010,
        },
        BlockTransaction::SubmitContribution {
            contributor_scheme_tag: alice_id.scheme_tag().as_str().to_string(),
            contributor_key_repr: alice_id.key_repr().to_string(),
            chain_id: ChainId::new("gmc-base").as_str().to_string(),
            merit_amount_raw: Decimal::from_int(30).raw(),
            influence_duration_raw: Decimal::from_int(86_400).raw(),
            timestamp_secs: 1_700_000_020,
        },
    ];

    let h1_proposer_id = vset.proposer_for(1, 0).unwrap().validator_id.clone();
    let h1_leader_idx = members
        .iter()
        .position(|(_, m)| m.validator_id == h1_proposer_id)
        .unwrap();

    // First verify that a forged proposal claiming a bogus `state_root` is rejected by honest nodes!
    let mut forged_proposal = nodes[h1_leader_idx]
        .build_signed_proposal(1, 0, 1_700_000_030, h1_txs.clone())
        .unwrap();
    forged_proposal.state_root = [0xFEu8; 32];
    forged_proposal = BlockProposal::resign_for_test(
        forged_proposal,
        &members[h1_leader_idx].0,
    )
    .unwrap();
    let root_before_forged = nodes[0].state_root_hex();
    nodes[h1_leader_idx]
        .broadcast_raw(BftWireMessage::Propose(forged_proposal))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(40));
    assert_eq!(nodes[0].block_height(), 0);
    assert_eq!(nodes[0].state_root_hex(), root_before_forged);

    // Now drive genuine Height 1 round across all 4 TCP validators (round = 1 so fresh round slot)
    let h1_r1_proposer_id = vset.proposer_for(1, 1).unwrap().validator_id.clone();
    let h1_r1_idx = members
        .iter()
        .position(|(_, m)| m.validator_id == h1_r1_proposer_id)
        .unwrap();

    let t_start_h1 = Instant::now();
    nodes[h1_r1_idx]
        .propose_block(1, 1, 1_700_000_030, h1_txs)
        .expect("propose height 1");
    for node in &nodes {
        node.wait_for_height(1, BFT_FINALITY_BUDGET_MS)
            .expect("all 4 nodes commit height 1 within budget");
    }
    let elapsed_h1_ms = t_start_h1.elapsed().as_millis() as u64;
    assert!(elapsed_h1_ms <= BFT_FINALITY_BUDGET_MS);

    let root_h1 = nodes[0].state_root_hex();
    for node in &nodes {
        assert_eq!(node.block_height(), 1);
        assert_eq!(node.state_root_hex(), root_h1);
        let qc = node.latest_qc().expect("height 1 QC persisted");
        assert_eq!(qc.height, 1);
        assert!(qc.votes.len() >= 3);
    }

    // Height 2: Faulty validator 3 goes offline for honest voting AND broadcasts an equivocation!
    // Pick a round at height 2 whose proposer is one of honest nodes 0..=2.
    let faulty_id = members[3].1.validator_id.clone();
    nodes[3].set_offline(true);
    let round_h2 = (0..4u32)
        .find(|&r| vset.proposer_for(2, r).unwrap().validator_id != faulty_id)
        .unwrap();
    let h2_leader_id = vset.proposer_for(2, round_h2).unwrap().validator_id.clone();
    let h2_leader_idx = members
        .iter()
        .position(|(_, m)| m.validator_id == h2_leader_id)
        .unwrap();

    let h2_txs = vec![BlockTransaction::SubmitContribution {
        contributor_scheme_tag: alice_id.scheme_tag().as_str().to_string(),
        contributor_key_repr: alice_id.key_repr().to_string(),
        chain_id: ChainId::new("gmc-base").as_str().to_string(),
        merit_amount_raw: Decimal::from_int(45).raw(),
        influence_duration_raw: Decimal::from_int(86_400).raw(),
        timestamp_secs: 1_700_000_080,
    }];

    let t_start_h2 = Instant::now();
    nodes[h2_leader_idx]
        .propose_block(2, round_h2, 1_700_000_100, h2_txs)
        .expect("propose height 2 with 3/4 online");

    for honest in &nodes[0..3] {
        honest
            .wait_for_height(2, BFT_FINALITY_BUDGET_MS)
            .expect("3/4 honest nodes reach quorum and commit height 2");
    }
    let elapsed_h2_ms = t_start_h2.elapsed().as_millis() as u64;
    assert!(elapsed_h2_ms <= BFT_FINALITY_BUDGET_MS);

    // Faulty validator 3 now sends two conflicting signed Prevotes over TCP -> honest nodes detect & eject!
    nodes[3]
        .inject_equivocation_over_tcp(2, round_h2, [0x11; 32], [0x22; 32], [0x33; 32])
        .expect("inject equivocation over TCP");

    for honest in &nodes[0..3] {
        honest
            .wait_for_ejection(&faulty_id, BFT_FINALITY_BUDGET_MS)
            .expect("honest node ejects equivocating validator");
    }

    let root_h2 = nodes[0].state_root_hex();
    assert_ne!(root_h2, root_h1);
    for honest in &nodes[0..3] {
        assert_eq!(honest.block_height(), 2);
        assert_eq!(honest.state_root_hex(), root_h2);
        assert_eq!(honest.active_validator_count(), 3);
        let qc2 = honest.latest_qc().unwrap();
        assert_eq!(qc2.height, 2);
        assert_eq!(qc2.votes.len(), 3, "Height 2 committed with exact 3/4 quorum");
    }

    for node in nodes {
        node.shutdown().unwrap();
    }
}

fn send_http_full(addr: std::net::SocketAddr, raw_req: &[u8]) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).expect("connect loopback");
    stream.write_all(raw_req).unwrap();
    stream.flush().unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    let (headers, body) = text.split_once("\r\n\r\n").unwrap();
    let code: u16 = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (code, headers.to_string(), body.to_string())
}

#[test]
fn loopback_cors_rpc_methods_workbench_ui_and_cli_subcommands() {
    let dir = TempDirGuard::new("workbench-rpc");
    let mut cfg = NodeConfig::new(dir.path());
    cfg.chain_id = "gmc-workbench-test".into();
    let node = NodeRuntime::init_workbench(cfg).expect("init workbench runtime with 4 validators");
    let shared = Arc::new(Mutex::new(node));

    // Strict loopback guard preserved
    assert!(matches!(
        start_control_server(Arc::clone(&shared), "0.0.0.0:0", false, None),
        Err(NodeError::NonLoopbackBindForbidden(_))
    ));

    let server = start_control_server(Arc::clone(&shared), "127.0.0.1:0", false, None).unwrap();
    let addr = server.local_addr();

    // 1. OPTIONS preflight returns 204 No Content + CORS headers
    let (code, headers, body) = send_http_full(
        addr,
        b"OPTIONS /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://meritora.org\r\nAccess-Control-Request-Method: POST\r\n\r\n",
    );
    assert_eq!(code, 204);
    assert!(body.is_empty());
    let headers_lc = headers.to_ascii_lowercase();
    assert!(headers_lc.contains("access-control-allow-origin: *"));
    assert!(headers_lc.contains("access-control-allow-methods: post, get, options"));
    assert!(headers_lc.contains("access-control-allow-headers: content-type"));

    // 2. GET / serves self-contained bilingual Meritora Desktop HTML (zero external CDN links!)
    let (code, headers, html) = send_http_full(
        addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(code, 200);
    assert!(headers.to_ascii_lowercase().contains("text/html"));
    assert!(headers.to_ascii_lowercase().contains("access-control-allow-origin: *"));
    assert!(html.contains("Meritora Desktop"));
    assert!(html.contains("Preview v0.2"));
    assert!(html.contains("FEE = 0"));
    assert!(html.contains("REWARD = 0"));
    assert!(html.contains("B_i = 0"));
    assert!(html.contains("中文") && html.contains("English"));
    assert!(!html.contains("<script src=\"http"), "must have zero external script CDNs");
    assert!(!html.contains("<link rel=\"stylesheet\" href=\"http"), "must have zero external CSS CDNs");

    // 3. JSON-RPC `gmc_status`, `gmc_validators`, `gmc_demoStep`, `gmc_produceBlock`
    let call_rpc = |method: &str, params: Value| -> Value {
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .unwrap();
        let req = format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        let mut raw = req.into_bytes();
        raw.extend_from_slice(&payload);
        let (code, hdrs, resp_body) = send_http_full(addr, &raw);
        assert_eq!(code, 200);
        assert!(hdrs.to_ascii_lowercase().contains("access-control-allow-origin: *"));
        serde_json::from_str(&resp_body).unwrap()
    };

    let st0 = call_rpc("gmc_status", json!({}));
    assert_eq!(st0["result"]["validator_count"], json!(4));
    assert_eq!(st0["result"]["quorum_threshold"], json!(3));
    assert_eq!(st0["result"]["node_transaction_fee"], json!("0"));
    assert_eq!(st0["result"]["node_block_reward"], json!("0"));
    assert_eq!(st0["result"]["validator_reward"], json!("0"));

    let vals0 = call_rpc("gmc_validators", json!({}));
    assert_eq!(vals0["result"]["active_count"], json!(4));
    assert_eq!(vals0["result"]["quorum_threshold"], json!(3));

    let demo_res = call_rpc("gmc_demoStep", json!({}));
    assert_eq!(demo_res["result"]["block_receipt"]["block_height"], json!(1));
    assert!(demo_res["result"]["latest_qc"]["vote_count"].as_u64().unwrap() >= 3);

    let blk2 = call_rpc("gmc_produceBlock", json!({ "timestamp_secs": 1_700_000_500u64 }));
    assert_eq!(blk2["result"]["block_height"], json!(2));
    assert_eq!(blk2["result"]["fee_charged_raw"], json!(0));
    assert_eq!(blk2["result"]["operator_reward_raw"], json!(0));
    assert_eq!(blk2["result"]["validator_reward_raw"], json!(0));

    server.shutdown().unwrap();

    // 4. CLI `cluster-demo` subprocess execution
    let bin = env!("CARGO_BIN_EXE_gmc-node");
    let cluster_dir = TempDirGuard::new("cli-cluster-demo");
    let out = Command::new(bin)
        .args([
            "cluster-demo",
            "--data-dir",
            cluster_dir.path().to_str().unwrap(),
            "--validators",
            "4",
        ])
        .output()
        .expect("run gmc-node cluster-demo");
    assert!(out.status.success(), "cluster-demo failed: {out:?}");
    let summary: Value = serde_json::from_slice(&out.stdout).expect("cluster-demo JSON output");
    assert_eq!(summary["cluster_demo"], json!("ok"));
    assert_eq!(summary["committed_height"], json!(2));
    assert_eq!(summary["active_validators_after"], json!(3));
    assert_eq!(summary["ejected_validators_count"], json!(1));
    assert_eq!(summary["validator_reward"], json!("0"));
    assert!(summary["height_2_finality_ms"].as_u64().unwrap() <= BFT_FINALITY_BUDGET_MS);
}
