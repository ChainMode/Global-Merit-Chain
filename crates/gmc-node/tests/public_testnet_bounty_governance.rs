//! End-to-end integration tests for the GMChain Public Testnet Kit (`gmc-node testnet`):
//! 1. Seeded 4-validator 2-phase BFT genesis + Explorer API with real-time `MeritPocket` decay;
//! 2. Contribution Bounty publishing + Deliverable submission;
//! 3. Stakeholder Voting with Automatic High-Intimacy Exclusion (`intimacy > 0.90` barred);
//! 4. Auto-minted decaying `MeriToken (μ)` batch + zero-fee BFT block settlement upon `>= 2/3` quorum;
//! 5. Merit-weighted Community Governance Proposals + crash-consistent WAL/snapshot `StateRoot` parity.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use gmc_node::rpc::start_control_server;
use gmc_node::runtime::{NodeConfig, NodeRuntime};

fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "gmc-public-testnet-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn http_json(addr: SocketAddr, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let payload_bytes = match body {
        Some(v) => serde_json::to_vec(v).unwrap(),
        None => Vec::new(),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload_bytes.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    if !payload_bytes.is_empty() {
        stream.write_all(&payload_bytes).unwrap();
    }
    stream.flush().unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let (head, raw_body) = resp.split_once("\r\n\r\n").expect("valid HTTP response");
    let status_line = head.lines().next().unwrap();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let parsed: Value = serde_json::from_str(raw_body).unwrap_or_else(|_| json!({ "raw": raw_body }));
    (code, parsed)
}

#[test]
fn public_testnet_full_bounty_intimacy_mint_and_governance_loop() {
    let data_dir = unique_temp_dir("full-loop");
    let config = NodeConfig::new(&data_dir);
    let node = NodeRuntime::open_public_testnet(config.clone()).expect("open seeded public testnet");

    let shared = Arc::new(Mutex::new(node));
    let handle = start_control_server(Arc::clone(&shared), "127.0.0.1:0", false, None)
        .expect("start loopback RPC");
    let addr = handle.local_addr();

    // 1. Inspect Explorer at +0d and +90d to verify 4-node BFT committee and exponential decay
    let (code0, explorer_0d) = http_json(addr, "GET", "/api/explorer?elapsed_days=0", None);
    assert_eq!(code0, 200);
    assert_eq!(explorer_0d["status"]["validator_count"], 4);
    assert_eq!(explorer_0d["status"]["quorum_threshold"], 3);
    assert_eq!(explorer_0d["status"]["node_transaction_fee"], "0");
    assert_eq!(explorer_0d["status"]["node_block_reward"], "0");
    assert_eq!(explorer_0d["status"]["validator_reward"], "0");

    let pockets_0d = explorer_0d["pockets"].as_array().unwrap();
    assert!(pockets_0d.len() >= 11, "expected >= 11 seeded participants");
    let alice_pocket_0d = pockets_0d
        .iter()
        .find(|p| p["display_name"] == "Alice Chen")
        .expect("Alice Chen pocket");
    let alice_fayid = alice_pocket_0d["fay_id"].as_str().unwrap().to_string();
    let alice_raw_0d = alice_pocket_0d["cur_merit_raw"].as_i64().unwrap();
    assert!(alice_fayid.starts_with("ifay_"));

    let civic_cofay = pockets_0d
        .iter()
        .find(|p| p["kind"] == "cofay")
        .expect("seeded coFay seat");
    assert!(civic_cofay["fay_id"].as_str().unwrap().starts_with("cofay_"));

    let (_, explorer_90d) = http_json(addr, "GET", "/api/explorer?elapsed_days=90", None);
    let alice_raw_90d = explorer_90d["pockets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["display_name"] == "Alice Chen")
        .unwrap()["cur_merit_raw"]
        .as_i64()
        .unwrap();
    let alice_floor_raw = explorer_90d["pockets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["display_name"] == "Alice Chen")
        .unwrap()["min_merit_floor_raw"]
        .as_i64()
        .unwrap();
    assert!(
        alice_raw_90d < alice_raw_0d && alice_raw_90d >= alice_floor_raw,
        "MeritPocket must decay monotonically toward minMerit floor"
    );

    // 2. Stage 1: Publish a new Contribution Bounty for Alice (`+75 μ`, 90d horizon)
    let (pub_code, pub_res) = http_json(
        addr,
        "POST",
        "/api/bounties",
        Some(&json!({
            "title": "Implement Deterministic ZK-Ready Batch Commitment Verifier",
            "domain_chain_id": "gmc-open-science",
            "assignee_id": alice_fayid,
            "reward_mu": 75,
            "horizon_days": 90
        })),
    );
    assert_eq!(pub_code, 200);
    let bounty_id = pub_res["bounty"]["bounty_id"].as_str().unwrap().to_string();
    let excluded = pub_res["bounty"]["excluded_insiders"].as_array().unwrap();
    assert_eq!(
        excluded.len(),
        2,
        "Bob Chen (Kinship > 0.90) and Dr. Lin Wei (Legal > 0.90) must be excluded"
    );
    let excluded_names: Vec<&str> = excluded
        .iter()
        .map(|e| e["display_name"].as_str().unwrap())
        .collect();
    assert!(excluded_names.contains(&"Bob Chen"));
    assert!(excluded_names.contains(&"Dr. Lin Wei"));

    // Submit deliverable
    let (deliv_code, deliv_res) = http_json(
        addr,
        "POST",
        "/api/bounties/deliver",
        Some(&json!({
            "bounty_id": bounty_id,
            "deliverable_summary": "All property-based fixed-point tests green.",
            "evidence_uri": "https://github.com/ChainMode/Global-Merit-Chain"
        })),
    );
    assert_eq!(deliv_code, 200);
    assert_eq!(deliv_res["bounty"]["status"], "voting");

    // 3. Stage 2: High-intimacy insider attempt MUST be rejected (`403 HIGH_INTIMACY_EXCLUDED`)
    let bob_fayid = excluded
        .iter()
        .find(|e| e["display_name"] == "Bob Chen")
        .unwrap()["canonical_fayid"]
        .as_str()
        .unwrap()
        .to_string();
    let (insider_code, insider_err) = http_json(
        addr,
        "POST",
        "/api/bounties/vote",
        Some(&json!({
            "bounty_id": bounty_id,
            "voter_id": bob_fayid,
            "approve": true
        })),
    );
    assert_eq!(insider_code, 403);
    assert!(
        insider_err["error"]
            .as_str()
            .unwrap()
            .contains("HIGH_INTIMACY_EXCLUDED"),
        "unexpected error: {insider_err}"
    );

    // 4. Independent stakeholders vote -> achieve `>= 2/3` MeriToken-weighted quorum -> Auto-mint!
    let eligible_internal_ids: Vec<String> = pub_res["bounty"]["eligible_voter_fay_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(eligible_internal_ids.len() >= 7);

    let ballots: Vec<Value> = eligible_internal_ids
        .iter()
        .take(8)
        .map(|vid| json!({ "voter_id": vid, "approve": true }))
        .collect();
    let (vote_code, vote_res) = http_json(
        addr,
        "POST",
        "/api/bounties/vote",
        Some(&json!({
            "bounty_id": bounty_id,
            "ballots": ballots
        })),
    );
    assert_eq!(vote_code, 200, "vote failed: {vote_res}");
    assert_eq!(vote_res["quorum_passed"], true);
    assert_eq!(vote_res["bounty"]["status"], "minted");
    assert!(vote_res["mint_receipt"]["batch_id"].is_string());
    assert_eq!(vote_res["block_receipt"]["fee_charged_raw"], 0);
    assert_eq!(vote_res["block_receipt"]["operator_reward_raw"], 0);
    assert_eq!(vote_res["block_receipt"]["validator_reward_raw"], 0);
    assert_eq!(vote_res["decay_curve_preview"].as_array().unwrap().len(), 5);

    // Verify Alice's MeritPocket jumped by +75 μ (`75_000_000` raw)
    let (_, explorer_after_mint) = http_json(addr, "GET", "/api/explorer?elapsed_days=0", None);
    let alice_after_raw = explorer_after_mint["pockets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["display_name"] == "Alice Chen")
        .unwrap()["cur_merit_raw"]
        .as_i64()
        .unwrap();
    assert_eq!(alice_after_raw, alice_raw_0d + 75_000_000);

    // 5. Stage 4: Create & pass a Merit-Weighted Community Governance Proposal via JSON-RPC 2.0
    let (rpc_code, rpc_create) = http_json(
        addr,
        "POST",
        "/rpc",
        Some(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "gmc_createProposal",
            "params": {
                "title": "GIP-03: Expand Public Testnet Benchmark Suite",
                "summary": "Adopt standardized 4-node BFT latency telemetry across community validators.",
                "domain_chain_id": "gmc-open-science",
                "threshold_raw": 500_000
            }
        })),
    );
    assert_eq!(rpc_code, 200);
    let prop_id = rpc_create["result"]["proposal"]["proposal_id"]
        .as_str()
        .unwrap()
        .to_string();

    let mut gov_ballots: Vec<Value> = eligible_internal_ids
        .iter()
        .map(|vid| json!({ "voter_id": vid, "approve": true }))
        .collect();
    gov_ballots.push(json!({ "voter_id": alice_fayid, "approve": true }));
    gov_ballots.push(json!({
        "voter_id": civic_cofay["fay_id"].as_str().unwrap(),
        "approve": true
    }));

    let (gov_code, gov_res) = http_json(
        addr,
        "POST",
        "/rpc",
        Some(&json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "gmc_voteProposal",
            "params": {
                "proposal_id": prop_id,
                "ballots": gov_ballots
            }
        })),
    );
    assert_eq!(gov_code, 200);
    assert_eq!(gov_res["result"]["passed"], true);
    assert_eq!(gov_res["result"]["proposal"]["status"], "passed");

    // 6. Clean shutdown + reopen verifies bit-identical StateRoot persistence
    let root_before_shutdown = hex::encode(handle.shutdown().expect("clean shutdown"));
    let mut reopened_cfg = config;
    reopened_cfg.chain_id = "gmchain-public-testnet-1".to_string();
    let reopened = NodeRuntime::open_public_testnet(reopened_cfg).expect("reopen public testnet");
    assert_eq!(reopened.state_root_hex(), root_before_shutdown);
    assert_eq!(reopened.testnet_state().bounties.len(), 2);
    assert_eq!(reopened.testnet_state().proposals.len(), 3);

    let _ = std::fs::remove_dir_all(&data_dir);
}
