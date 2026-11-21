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
    let parsed: Value =
        serde_json::from_str(raw_body).unwrap_or_else(|_| json!({ "raw": raw_body }));
    (code, parsed)
}

#[test]
fn public_testnet_full_bounty_intimacy_mint_and_governance_loop() {
    let data_dir = unique_temp_dir("full-loop");
    let config = NodeConfig::new(&data_dir);
    let node =
        NodeRuntime::open_public_testnet(config.clone()).expect("open seeded public testnet");

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
    assert!(civic_cofay["fay_id"]
        .as_str()
        .unwrap()
        .starts_with("cofay_"));

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

#[test]
fn external_fayger_registration_contribution_and_priority_consumption_loop() {
    let data_dir = unique_temp_dir("fayger-bridge");
    let config = NodeConfig::new(&data_dir);
    let node =
        NodeRuntime::open_public_testnet(config.clone()).expect("open seeded public testnet");

    let shared = Arc::new(Mutex::new(node));
    let handle = start_control_server(Arc::clone(&shared), "127.0.0.1:0", false, None)
        .expect("start loopback RPC");
    let addr = handle.local_addr();

    // 1. Register external FayGer iFay via JSON-RPC `gmc_registerExternalFay`
    let ext_fay_id = "fayger_ifay_user_001";
    let (reg_code, reg_rpc) = http_json(
        addr,
        "POST",
        "/rpc",
        Some(&json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "gmc_registerExternalFay",
            "params": {
                "fay_id": ext_fay_id,
                "display_name": "Jah's Personal iFay",
                "kind": "ifay",
                "role_label": "FayGer Sovereign Assistant (iFay)"
            }
        })),
    );
    assert_eq!(reg_code, 200);
    let reg_res = &reg_rpc["result"];
    assert_eq!(reg_res["ok"], true);
    assert_eq!(reg_res["already_registered"], false);
    assert_eq!(reg_res["fay_id"], ext_fay_id);
    assert!(reg_res["canonical_fayid"]
        .as_str()
        .unwrap()
        .starts_with("ifay_"));
    assert_eq!(reg_res["cur_merit_mu"], "5");
    assert_eq!(reg_res["cur_merit_raw"], 5_000_000i64);
    assert_eq!(reg_res["min_merit_floor_mu"], "2.718281");
    assert_eq!(reg_res["min_merit_floor_raw"], 2_718_281i64);
    assert_eq!(reg_res["consumable_merit_mu"], "2.281719");
    assert_eq!(reg_res["consumable_merit_raw"], 2_281_719i64);

    // Re-registering the same external FayID is idempotent (`already_registered: true`)
    let (dup_code, dup_res) = http_json(
        addr,
        "POST",
        "/api/fays/register",
        Some(&json!({
            "fay_id": ext_fay_id,
            "display_name": "Jah's Personal iFay"
        })),
    );
    assert_eq!(dup_code, 200);
    assert_eq!(dup_res["already_registered"], true);
    assert_eq!(dup_res["cur_merit_raw"], 5_000_000i64);

    // 2. Record contribution (+40 μ) via JSON-RPC `gmc_recordContribution`
    let (add_code, add_rpc) = http_json(
        addr,
        "POST",
        "/rpc",
        Some(&json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "gmc_recordContribution",
            "params": {
                "fay_id": ext_fay_id,
                "title": "Open-Source FayGer Multi-Agent Consensus Bridge",
                "domain_chain_id": "gmc-open-science",
                "amount_mu": 40,
                "horizon_days": 90,
                "summary": "Delivered deterministic fixed-point RPC integration."
            }
        })),
    );
    assert_eq!(add_code, 200);
    let add_res = &add_rpc["result"];
    assert_eq!(add_res["ok"], true);
    assert_eq!(add_res["fay_id"], ext_fay_id);
    assert_eq!(add_res["minted_mu"], "40");
    assert_eq!(add_res["cur_merit_mu"], "45");
    assert_eq!(add_res["cur_merit_raw"], 45_000_000i64);
    let floor_after_add_raw = add_res["min_merit_floor_raw"].as_i64().unwrap();
    let consumable_after_add_raw = add_res["consumable_merit_raw"].as_i64().unwrap();
    assert_eq!(
        45_000_000i64 - floor_after_add_raw,
        consumable_after_add_raw
    );
    assert!(
        consumable_after_add_raw > 12_000_000i64,
        "expected > 12 μ consumable, got {consumable_after_add_raw}"
    );

    // 3. Consume -12 μ for `voting_priority` on `prop-001` via `gmc_consumePriority`
    let (cons_code, cons_rpc) = http_json(
        addr,
        "POST",
        "/rpc",
        Some(&json!({
            "jsonrpc": "2.0",
            "id": 103,
            "method": "gmc_consumePriority",
            "params": {
                "fay_id": ext_fay_id,
                "priority_kind": "voting_priority",
                "amount_mu": 12,
                "reason": "Expedite open-science benchmark governance review on prop-001",
                "proposal_id": "prop-001",
                "approve": true
            }
        })),
    );
    assert_eq!(cons_code, 200);
    let cons_res = &cons_rpc["result"];
    assert_eq!(cons_res["ok"], true);
    assert_eq!(cons_res["fay_id"], ext_fay_id);
    assert_eq!(cons_res["priority_kind"], "voting_priority");
    assert_eq!(cons_res["consumed_mu"], "12");
    assert_eq!(cons_res["consumed_mu_raw"], 12_000_000i64);

    let before_cur_raw = cons_res["before_cur_merit_raw"].as_i64().unwrap();
    let after_cur_raw = cons_res["after_cur_merit_raw"].as_i64().unwrap();
    let min_floor_raw = cons_res["min_merit_floor_raw"].as_i64().unwrap();
    assert_eq!(before_cur_raw, 45_000_000i64);
    assert_eq!(after_cur_raw, before_cur_raw - 12_000_000i64);
    assert_eq!(min_floor_raw, floor_after_add_raw);
    assert_eq!(
        cons_res["consumable_merit_raw"].as_i64().unwrap(),
        consumable_after_add_raw - 12_000_000i64
    );

    // Also test REST `/api/merit/consume` with decimal string `"1.5"`
    let (rest_cons_code, rest_cons_res) = http_json(
        addr,
        "POST",
        "/api/merit/consume",
        Some(&json!({
            "fay_id": ext_fay_id,
            "priority_kind": "compute_priority",
            "amount_mu": "1.5",
            "reason": "Priority verification slot"
        })),
    );
    assert_eq!(rest_cons_code, 200);
    assert_eq!(rest_cons_res["after_cur_merit_raw"], 31_500_000i64);
    assert_eq!(rest_cons_res["min_merit_floor_raw"], floor_after_add_raw);

    // 4. Over-consumption above consumable surplus MUST be rejected with error & leave state untouched
    let (over_rpc_code, over_rpc) = http_json(
        addr,
        "POST",
        "/rpc",
        Some(&json!({
            "jsonrpc": "2.0",
            "id": 104,
            "method": "gmc_consumePriority",
            "params": {
                "fay_id": ext_fay_id,
                "priority_kind": "voting_priority",
                "amount_mu": 999,
                "reason": "Attempted over-consumption past minMerit floor"
            }
        })),
    );
    assert_eq!(over_rpc_code, 200);
    assert!(
        over_rpc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("InsufficientConsumableMerit"),
        "expected InsufficientConsumableMerit error, got: {over_rpc}"
    );

    let (over_http_code, over_http) = http_json(
        addr,
        "POST",
        "/api/merit/consume",
        Some(&json!({
            "fay_id": ext_fay_id,
            "priority_kind": "voting_priority",
            "amount_mu": "999.25",
            "reason": "Attempted REST over-consumption"
        })),
    );
    assert_eq!(over_http_code, 400);
    assert!(over_http["error"]
        .as_str()
        .unwrap()
        .contains("InsufficientConsumableMerit"));

    // 5. Verify Explorer snapshot reflects `external_fay_id`, `consumable_merit_mu`, `priority_consumptions`, and ballot on `prop-001`
    let (exp_code, exp_snap) = http_json(addr, "GET", "/api/explorer?elapsed_days=0", None);
    assert_eq!(exp_code, 200);
    let ext_pocket = exp_snap["pockets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["external_fay_id"] == ext_fay_id)
        .expect("external FayGer pocket in explorer");
    assert_eq!(ext_pocket["cur_merit_raw"], 31_500_000i64);
    assert_eq!(ext_pocket["min_merit_floor_raw"], floor_after_add_raw);
    assert_eq!(
        ext_pocket["consumable_merit_raw"],
        31_500_000i64 - floor_after_add_raw
    );
    assert_eq!(
        exp_snap["priority_consumptions"].as_array().unwrap().len(),
        2
    );

    let prop_001 = exp_snap["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["proposal_id"] == "prop-001")
        .expect("prop-001 present");
    assert_eq!(prop_001["ballots"].as_array().unwrap().len(), 1);
    assert_eq!(
        prop_001["ballots"][0]["voter_display_name"],
        "Jah's Personal iFay"
    );

    // 6. Clean shutdown & reopen preserves identical StateRoot and priority_consumptions
    let root_before_shutdown = hex::encode(handle.shutdown().expect("clean shutdown"));
    let mut reopened_cfg = config;
    reopened_cfg.chain_id = "gmchain-public-testnet-1".to_string();
    let reopened = NodeRuntime::open_public_testnet(reopened_cfg).expect("reopen public testnet");
    assert_eq!(reopened.state_root_hex(), root_before_shutdown);
    assert_eq!(reopened.testnet_state().priority_consumptions.len(), 2);

    let _ = std::fs::remove_dir_all(&data_dir);
}
