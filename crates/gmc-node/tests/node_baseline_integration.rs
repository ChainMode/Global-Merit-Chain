//! End-to-end integration tests for `gmc-node` (`establish-gmc-node-baseline`).
//!
//! Covers:
//! 1. Real `ed25519-dalek` RFC 8032 KAT self-test, all 8 wired `OperationPayload`
//!    variants (`CreateCoFay`, `AddDelegate`, `RevokeDelegate`, `EnrollDevice`,
//!    `RevokeDevice`, `RotateKey`, `ConfigureGuardians`, `RecoveryApproval`),
//!    `IdentityId` invariance, and strict `0600` operator key confidentiality;
//! 2. Cross-node deterministic SHA-256 `StateRoot` equivalence across independent
//!    nodes AND crash recovery from truncated trailing WAL frames + stale temp files;
//! 3. L2 (`1,000`-record and `60s` interval) -> L1 batch settlement, corrupted proof
//!    atomic rejection (`ProofVerificationFailed`), and Non-Monetary Iron Law
//!    (`NODE_BLOCK_REWARD == 0`, `TRANSACTION_FEE == 0`, `reject_monetary_request`);
//! 4. Mempool intake guard, loopback HTTP/JSON-RPC server (`<= 256 KiB` ceiling,
//!    unauthenticated mutation rejection), and `gmc-node` CLI binary execution.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use gmc_core::error::GmcError;
use gmc_core::gmc_base::MonetaryRequest;
use gmc_core::l2_rollup::BATCH_MAX_RECORDS;
use gmc_core::penalty::{AppealOutcome, Complaint, PenaltyBallot, PenaltySeverity};
use gmc_core::relationship::{PrivacyTier, RelationshipType};
use gmc_core::types::{ChainId, Decimal, Ratio, Timestamp};
use gmc_identity::device::DeviceId;
use gmc_identity::error::IdentityError;
use gmc_identity::identity_core::{Applied, OperationPayload};
use gmc_identity::ownership::{OwnerKind, OwnerRef};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{DeviceType, Signature};

use gmc_node::crypto::{
    keypair_from_seed, register_ed25519_scheme, run_ed25519_kat_internal,
    run_ed25519_kat_self_test, sign_ed25519_operation, OperatorKeyStore, OperatorKeypair,
};
use gmc_node::error::NodeError;
use gmc_node::rpc::{start_control_server, MAX_REQUEST_BYTES};
use gmc_node::runtime::{
    NodeConfig, NodeRuntime, WireSignedOperation, NODE_BLOCK_REWARD, NODE_TRANSACTION_FEE,
};
use gmc_node::store::{NodeStateStore, WAL_FRAME_MAGIC};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempNodeDir(PathBuf);

impl TempNodeDir {
    fn new(prefix: &str) -> Self {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("gmc-node-it-{prefix}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        TempNodeDir(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempNodeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_ed25519_all_wired_operations_and_operator_key_hygiene() {
    let mut registry = SchemeRegistry::default();
    register_ed25519_scheme(&mut registry);
    run_ed25519_kat_self_test(&registry).expect("RFC 8032 KAT self-test must pass");
    assert!(matches!(
        run_ed25519_kat_internal(&registry, "00".repeat(64).as_str()),
        Err(NodeError::KatSelfTestFailed(_))
    ));

    let dir = TempNodeDir::new("crypto-ops");
    let operator_seed = [0x5Au8; 32];
    let operator_secret_hex = hex::encode(operator_seed);

    let cfg = NodeConfig::new(dir.path());
    let mut node = NodeRuntime::init_with_seed(cfg.clone(), operator_seed).expect("init node");

    // Duplicate `init` MUST refuse to overwrite existing `operator.key`.
    assert!(matches!(
        NodeRuntime::init_with_seed(cfg.clone(), [0x99u8; 32]),
        Err(NodeError::KeyAlreadyExists(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(OperatorKeyStore::key_file_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "operator.key must carry strict 0600 permissions"
        );
    }

    // Check Debug redaction on OperatorKeypair.
    let kp = OperatorKeypair::from_seed(&registry, operator_seed).unwrap();
    let dbg_str = format!("{kp:?}");
    assert!(dbg_str.contains("<redacted>"));
    assert!(!dbg_str.contains(&operator_secret_hex));

    let t0 = Timestamp::from_secs(1_700_000_000);
    let (alice_sk, alice_vk) = keypair_from_seed(&[0x10u8; 32]);
    let (dev_sk, dev_vk) = keypair_from_seed(&[0x11u8; 32]);
    let (rot_sk, rot_vk) = keypair_from_seed(&[0x12u8; 32]);
    let (rec_sk, rec_vk) = keypair_from_seed(&[0x13u8; 32]);
    let (g1_sk, g1_vk) = keypair_from_seed(&[0x21u8; 32]);
    let (g2_sk, g2_vk) = keypair_from_seed(&[0x22u8; 32]);
    let (_g3_sk, g3_vk) = keypair_from_seed(&[0x23u8; 32]);
    let (_cofay_sk, cofay_vk) = keypair_from_seed(&[0x31u8; 32]);
    let (_del_sk, del_vk) = keypair_from_seed(&[0x32u8; 32]);

    let alice_id = node.register_ifay(&alice_vk, t0).unwrap();

    // 1. Tampered signature must be rejected atomically with zero nonce change.
    let mut bad_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::EnrollDevice {
            device_key: dev_vk.clone(),
            device_type: DeviceType::Phone,
        },
        1,
    )
    .unwrap();
    let mut sig_bytes = bad_op.signature.as_bytes().to_vec();
    sig_bytes[7] ^= 0x80;
    bad_op.signature = Signature::new(sig_bytes);
    let root_before = node.state_root();
    assert_eq!(
        node.submit_signed_operation(bad_op, t0),
        Err(NodeError::Identity(IdentityError::SignatureInvalid))
    );
    assert_eq!(node.state_root(), root_before);

    // 2. EnrollDevice (nonce 1) -> active device can sign CreateCoFay (nonce 2), then RevokeDevice (nonce 3).
    let enroll_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::EnrollDevice {
            device_key: dev_vk.clone(),
            device_type: DeviceType::Phone,
        },
        1,
    )
    .unwrap();
    let dev_id = DeviceId::derive(&dev_vk);
    assert_eq!(
        node.submit_signed_operation(enroll_op, t0).unwrap(),
        Applied::DeviceEnrolled(dev_id.clone())
    );

    // Enrolled device signs CreateCoFay owned by natural-person `hid_<alice_key_repr>`.
    let human_owner = OwnerRef::new(format!("hid_{}", alice_id.key_repr()), OwnerKind::Human);
    let create_cofay_op = sign_ed25519_operation(
        &dev_sk,
        &dev_vk,
        alice_id.clone(),
        OperationPayload::CreateCoFay {
            owner: human_owner,
            new_cofay_key: cofay_vk,
        },
        2,
    )
    .unwrap();
    let cofay_id = match node.submit_signed_operation(create_cofay_op, t0).unwrap() {
        Applied::CoFayCreated(id) => id,
        other => panic!("unexpected result: {other:?}"),
    };

    // AddDelegate + RevokeDelegate on coFay signed by human owner key `alice_sk`.
    let add_del = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        cofay_id.clone(),
        OperationPayload::AddDelegate {
            delegate: del_vk.clone(),
        },
        1,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(add_del, t0).unwrap(),
        Applied::DelegateAdded
    );
    let rev_del = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        cofay_id.clone(),
        OperationPayload::RevokeDelegate { delegate: del_vk },
        2,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(rev_del, t0).unwrap(),
        Applied::DelegateRevoked
    );

    // RevokeDevice (nonce 3) immediately disempowers `dev_sk`.
    let revoke_dev = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::RevokeDevice {
            device_id: dev_id.as_str().to_string(),
        },
        3,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(revoke_dev, t0).unwrap(),
        Applied::DeviceRevoked
    );
    let post_revoke_attempt = sign_ed25519_operation(
        &dev_sk,
        &dev_vk,
        alice_id.clone(),
        OperationPayload::RevokeDevice {
            device_id: dev_id.as_str().to_string(),
        },
        4,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(post_revoke_attempt, t0),
        Err(NodeError::Identity(IdentityError::UnauthorizedActor))
    );

    // 3. RotateKey (nonce 4): `IdentityId` stays strictly invariant; old key retired; new key signs ConfigureGuardians (nonce 5).
    let rotate_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::RotateKey {
            new_key: rot_vk.clone(),
        },
        4,
    )
    .unwrap();
    assert!(matches!(
        node.submit_signed_operation(rotate_op, t0).unwrap(),
        Applied::KeyRotated(_)
    ));
    assert_eq!(
        node.identities().identities.get(&alice_id).unwrap().id,
        alice_id
    );

    // Retired `alice_sk` must be rejected!
    let retired_attempt = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::ConfigureGuardians {
            guardians: vec![g1_vk.clone(), g2_vk.clone(), g3_vk.clone()],
            threshold: 2,
        },
        5,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(retired_attempt, t0),
        Err(NodeError::Identity(IdentityError::UnauthorizedActor))
    );

    // Rotated `rot_sk` succeeds on ConfigureGuardians (nonce 5).
    let cfg_guardians = sign_ed25519_operation(
        &rot_sk,
        &rot_vk,
        alice_id.clone(),
        OperationPayload::ConfigureGuardians {
            guardians: vec![g1_vk.clone(), g2_vk.clone(), g3_vk],
            threshold: 2,
        },
        5,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(cfg_guardians, t0).unwrap(),
        Applied::GuardiansConfigured
    );

    // 4. 2-of-3 Guardian RecoveryApproval (nonces 6 & 7) rotates active key to `rec_vk` while keeping `alice_id` invariant!
    let app1 = sign_ed25519_operation(
        &g1_sk,
        &g1_vk,
        alice_id.clone(),
        OperationPayload::RecoveryApproval {
            new_key: rec_vk.clone(),
            guardian_key: g1_vk.clone(),
        },
        6,
    )
    .unwrap();
    assert_eq!(
        node.submit_signed_operation(app1, t0).unwrap(),
        Applied::RecoveryApprovalRecorded {
            approvals: 1,
            threshold: 2
        }
    );
    let app2 = sign_ed25519_operation(
        &g2_sk,
        &g2_vk,
        alice_id.clone(),
        OperationPayload::RecoveryApproval {
            new_key: rec_vk.clone(),
            guardian_key: g2_vk.clone(),
        },
        7,
    )
    .unwrap();
    assert!(matches!(
        node.submit_signed_operation(app2, t0).unwrap(),
        Applied::RecoveryCompleted(_)
    ));

    // Recovered `rec_sk` is now the sole active key on the unchanged `alice_id`.
    let post_rec_enroll = sign_ed25519_operation(
        &rec_sk,
        &rec_vk,
        alice_id.clone(),
        OperationPayload::EnrollDevice {
            device_key: dev_vk,
            device_type: DeviceType::Computer,
        },
        8,
    )
    .unwrap();
    assert!(matches!(
        node.submit_signed_operation(post_rec_enroll, t0).unwrap(),
        Applied::DeviceEnrolled(_)
    ));

    node.produce_block(Timestamp::from_secs(1_700_000_100))
        .unwrap();

    // Verify operator secret seed hex NEVER appears in status JSON, snapshot.json, or wal.log!
    let status_json = serde_json::to_string(&node.status()).unwrap();
    let snap_raw =
        String::from_utf8_lossy(&fs::read(NodeStateStore::snapshot_path(dir.path())).unwrap())
            .into_owned();
    let wal_raw = hex::encode(fs::read(NodeStateStore::wal_path(dir.path())).unwrap());
    assert!(!status_json.contains(&operator_secret_hex));
    assert!(!snap_raw.contains(&operator_secret_hex));
    assert!(!wal_raw.contains(&operator_secret_hex));
}

#[test]
fn cross_node_state_root_determinism_and_wal_crash_recovery() {
    let dir_a = TempNodeDir::new("det-node-a");
    let dir_b = TempNodeDir::new("det-node-b");

    // Distinct operator keys (`0x11` vs `0x22`) on two independent nodes!
    let mut node_a =
        NodeRuntime::init_with_seed(NodeConfig::new(dir_a.path()), [0x11u8; 32]).unwrap();
    let mut node_b =
        NodeRuntime::init_with_seed(NodeConfig::new(dir_b.path()), [0x22u8; 32]).unwrap();
    assert_ne!(node_a.operator_node_id(), node_b.operator_node_id());
    assert_eq!(node_a.state_root(), node_b.state_root());

    let run_workload = |node: &mut NodeRuntime| {
        let t0 = Timestamp::from_secs(1_700_000_000);
        let (alice_sk, alice_vk) = keypair_from_seed(&[0xA1u8; 32]);
        let (_bob_sk, bob_vk) = keypair_from_seed(&[0xB1u8; 32]);
        let (_voter1_sk, voter1_vk) = keypair_from_seed(&[0xC1u8; 32]);
        let (_voter2_sk, voter2_vk) = keypair_from_seed(&[0xC2u8; 32]);
        let (_voter3_sk, voter3_vk) = keypair_from_seed(&[0xC3u8; 32]);
        let (_dev_sk, dev_vk) = keypair_from_seed(&[0xD1u8; 32]);

        let alice = node.register_ifay(&alice_vk, t0).unwrap();
        let bob = node.register_ifay(&bob_vk, t0).unwrap();
        let voter1 = node.register_ifay(&voter1_vk, t0).unwrap();
        let voter2 = node.register_ifay(&voter2_vk, t0).unwrap();
        let voter3 = node.register_ifay(&voter3_vk, t0).unwrap();

        let op = sign_ed25519_operation(
            &alice_sk,
            &alice_vk,
            alice.clone(),
            OperationPayload::EnrollDevice {
                device_key: dev_vk,
                device_type: DeviceType::Watch,
            },
            1,
        )
        .unwrap();
        node.submit_signed_operation(op, t0).unwrap();

        // Bilateral relationship + interactions
        let alice_fay = alice.to_fay_id();
        let bob_fay = bob.to_fay_id();
        node.register_relationship(
            alice_fay.clone(),
            bob_fay.clone(),
            RelationshipType::Social,
            PrivacyTier::ExistencePublic,
            t0,
        )
        .unwrap();
        let d = Ratio::new(Decimal::from_raw(750_000)).unwrap();
        node.record_interaction(&alice_fay, &bob_fay, d, Timestamp::from_secs(1_700_000_010))
            .unwrap();
        node.record_interaction(&bob_fay, &alice_fay, d, Timestamp::from_secs(1_700_000_015))
            .unwrap();

        // Contributions for Alice, Bob, Voter1, Voter2
        for (who, amt) in [(&alice, 30), (&bob, 40), (&voter1, 50), (&voter2, 50)] {
            node.submit_contribution(
                who,
                ChainId::new("gmc-base"),
                Decimal::from_int(amt),
                Decimal::from_int(86_400),
                Timestamp::from_secs(1_700_000_020),
            )
            .unwrap();
        }

        // Chapter 9 Severe Penalty on Bob's batch-1 + Appeal Overturn restoring minMerit & curMerit!
        let bob_pocket_before = node
            .identities()
            .binding
            .pocket_by_key(&bob_fay)
            .unwrap()
            .clone();

        node.file_complaint(Complaint {
            complaint_id: "cmp-1".into(),
            complainant: alice_fay.clone(),
            respondent: bob_fay.clone(),
            batch_id: "batch-1".into(),
            evidence_hash: "a".repeat(64),
            severity: PenaltySeverity::Severe,
            filed_at: Timestamp::from_secs(1_700_000_030),
        })
        .unwrap();

        let ballots = vec![
            PenaltyBallot {
                voter: voter1.to_fay_id(),
                cur_merit: Decimal::from_int(50),
                approve: true,
            },
            PenaltyBallot {
                voter: voter2.to_fay_id(),
                cur_merit: Decimal::from_int(50),
                approve: true,
            },
        ];
        assert!(node.resolve_admissibility("cmp-1", &ballots).unwrap());
        let exec = node
            .execute_penalty("cmp-1", &ballots, Timestamp::from_secs(1_700_000_035))
            .unwrap();
        assert!(exec.min_merit_after < exec.min_merit_before);

        node.submit_appeal("cmp-1", "b".repeat(64), Timestamp::from_secs(1_700_000_040))
            .unwrap();
        let mut appeal_ballots = ballots.clone();
        appeal_ballots.push(PenaltyBallot {
            voter: voter3.to_fay_id(),
            cur_merit: Decimal::from_int(50),
            approve: true,
        });
        let outcome = node
            .resolve_appeal(
                "cmp-1",
                &appeal_ballots,
                Timestamp::from_secs(1_700_000_045),
            )
            .unwrap();
        assert!(matches!(outcome, AppealOutcome::Overturned { .. }));
        let bob_pocket_restored = node.identities().binding.pocket_by_key(&bob_fay).unwrap();
        assert_eq!(bob_pocket_restored.min_merit, bob_pocket_before.min_merit);
        assert_eq!(bob_pocket_restored.batches, bob_pocket_before.batches);

        node.produce_block(Timestamp::from_secs(1_700_000_100))
            .unwrap();
    };

    run_workload(&mut node_a);
    run_workload(&mut node_b);
    assert_eq!(
        node_a.state_root(),
        node_b.state_root(),
        "two independent honest nodes replaying identical operations must reach identical StateRoot"
    );

    // Post-snapshot WAL frames (NOT snapshotted yet) + simulated mid-write crash!
    let (_carol_sk, carol_vk) = keypair_from_seed(&[0xE1u8; 32]);
    node_a
        .register_ifay(&carol_vk, Timestamp::from_secs(1_700_000_200))
        .unwrap();
    node_b
        .register_ifay(&carol_vk, Timestamp::from_secs(1_700_000_200))
        .unwrap();
    let expected_post_wal_root = node_b.state_root();

    // Drop `node_a` WITHOUT calling `shutdown()` (so `snapshot.json` is behind `wal.log`),
    // append a truncated partial WAL frame + a leftover `snapshot.json.tmp` to simulate power loss!
    drop(node_a);
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(NodeStateStore::wal_path(dir_a.path()))
            .unwrap();
        f.write_all(WAL_FRAME_MAGIC).unwrap();
        f.write_all(&999u64.to_be_bytes()).unwrap();
        f.write_all(&5000u32.to_be_bytes()).unwrap();
        f.write_all(&[0xAAu8; 19]).unwrap(); // truncated mid-header/payload!
        f.sync_all().unwrap();
    }
    fs::write(dir_a.path().join("snapshot.json.tmp"), b"{partial-crash").unwrap();

    let reopened_a = NodeRuntime::open(NodeConfig::new(dir_a.path())).unwrap();
    assert_eq!(
        reopened_a.state_root(),
        expected_post_wal_root,
        "crash recovery must discard truncated trailing WAL frame and replay committed WAL frames losslessly"
    );
    assert!(!dir_a.path().join("snapshot.json.tmp").exists());
    drop(reopened_a);

    // Corrupting a byte inside a committed mid-log WAL frame MUST fail closed with `WalCorrupted`.
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(NodeStateStore::wal_path(dir_a.path()))
            .unwrap();
        f.seek(SeekFrom::Start(52)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        b[0] ^= 0xFF;
        f.seek(SeekFrom::Start(52)).unwrap();
        f.write_all(&b).unwrap();
        f.sync_all().unwrap();
    }
    assert!(matches!(
        NodeRuntime::open(NodeConfig::new(dir_a.path())),
        Err(NodeError::WalCorrupted { .. })
    ));
}

#[test]
fn l2_to_l1_batch_triggers_corrupted_proof_rejection_and_non_monetary_iron_law() {
    let dir = TempNodeDir::new("l2-l1-nonmonetary");
    let mut node = NodeRuntime::init_with_seed(NodeConfig::new(dir.path()), [0x77u8; 32]).unwrap();

    // 1. Non-Monetary Iron Law checks
    assert!(NODE_BLOCK_REWARD.is_zero());
    assert!(NODE_TRANSACTION_FEE.is_zero());
    assert!(node.l1().is_fee_free());

    let t0 = Timestamp::from_secs(0);
    let op_vk = node.operator_verifying_key().clone();
    let op_ifay = node.register_ifay(&op_vk, t0).unwrap();
    let op_pocket_initial = node.identities().binding.pocket(&op_ifay).unwrap().clone();

    let root_before_monetary = node.state_root();
    assert_eq!(
        node.reject_monetary_request(&MonetaryRequest::fund_for_meritoken("gmc-base", "100 USD")),
        Err(GmcError::OperationNotAllowed)
    );
    assert_eq!(
        node.reject_monetary_request(&MonetaryRequest::purchase_recognition("gmc-base", "1 BTC")),
        Err(GmcError::OperationNotAllowed)
    );
    assert_eq!(node.state_root(), root_before_monetary);

    // 2. Buffer a contribution (< 60s from genesis), then submit a CORRUPTED batch commitment -> must reject atomically!
    let (_u_sk, u_vk) = keypair_from_seed(&[0x88u8; 32]);
    let contributor = node.register_ifay(&u_vk, t0).unwrap();
    let r1 = node
        .submit_contribution(
            &contributor,
            ChainId::new("gmc-base"),
            Decimal::from_int(15),
            Decimal::from_int(3600),
            Timestamp::from_secs(10),
        )
        .unwrap();
    assert_eq!(r1.auto_settled_batch_seq, None);
    assert_eq!(node.l2().buffered_len(), 1);

    let l1_root_before = node.l1().state_root();
    let node_root_before = node.state_root();
    let err = node
        .submit_pending_batch_with_commitment([0xEEu8; 32], Timestamp::from_secs(20))
        .unwrap_err();
    assert_eq!(err, NodeError::Core(GmcError::ProofVerificationFailed));
    assert_eq!(
        node.l1().state_root(),
        l1_root_before,
        "failed batch proof must retain previous L1 StateRoot"
    );
    assert_eq!(node.state_root(), node_root_before);
    assert_eq!(
        node.l2().buffered_len(),
        1,
        "failed batch proof must preserve buffered L2 records"
    );

    // 3. `60s` interval auto-trigger (`0 + 60`) seals batch 1 automatically!
    let r2 = node
        .submit_contribution(
            &contributor,
            ChainId::new("gmc-base"),
            Decimal::from_int(10),
            Decimal::from_int(3600),
            Timestamp::from_secs(60),
        )
        .unwrap();
    assert_eq!(r2.auto_settled_batch_seq, Some(1));
    assert_eq!(node.l2().buffered_len(), 0);
    assert_ne!(node.l1().state_root(), l1_root_before);

    // 4. `1,000`-record (`BATCH_MAX_RECORDS`) threshold auto-trigger within `< 60s`!
    for idx in 0..BATCH_MAX_RECORDS {
        let rcpt = node
            .submit_contribution(
                &contributor,
                ChainId::new("gmc-base"),
                Decimal::from_int(1),
                Decimal::from_int(3600),
                Timestamp::from_secs(65),
            )
            .unwrap();
        if idx + 1 < BATCH_MAX_RECORDS {
            assert_eq!(rcpt.auto_settled_batch_seq, None);
        } else {
            assert_eq!(rcpt.auto_settled_batch_seq, Some(2));
        }
    }
    assert_eq!(node.l2().buffered_len(), 0);

    // 5. Block production charges `0` fee and grants `0` operator reward!
    let blk = node.produce_block(Timestamp::from_secs(120)).unwrap();
    assert_eq!(blk.fee_charged_raw, 0);
    assert_eq!(blk.operator_reward_raw, 0);
    let op_pocket_after = node.identities().binding.pocket(&op_ifay).unwrap();
    assert_eq!(
        op_pocket_after, &op_pocket_initial,
        "producing blocks and settling batches MUST NOT mint MeriToken to node operator"
    );
}

fn send_raw_http(addr: std::net::SocketAddr, raw_req: &[u8]) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).expect("connect loopback rpc");
    stream.write_all(raw_req).expect("write http req");
    stream.flush().unwrap();
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).expect("read http resp");
    let resp_str = String::from_utf8(resp_bytes).expect("utf8 http resp");
    let (head, body) = resp_str.split_once("\r\n\r\n").expect("http header/body");
    let status_line = head.lines().next().unwrap();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let val: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
    (code, val)
}

#[test]
fn mempool_intake_loopback_http_jsonrpc_and_cli_binary() {
    let dir = TempNodeDir::new("rpc-and-cli");
    let mut node = NodeRuntime::init_with_seed(NodeConfig::new(dir.path()), [0x33u8; 32]).unwrap();

    let t0 = Timestamp::from_secs(1_700_000_000);
    let (alice_sk, alice_vk) = keypair_from_seed(&[0x44u8; 32]);
    let (_dev1_sk, dev1_vk) = keypair_from_seed(&[0x45u8; 32]);
    let (_dev2_sk, dev2_vk) = keypair_from_seed(&[0x46u8; 32]);
    let alice_id = node.register_ifay(&alice_vk, t0).unwrap();

    // Mempool intake guard: invalid signature rejected; valid staged op admitted; replay rejected.
    let valid_stage = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::EnrollDevice {
            device_key: dev1_vk,
            device_type: DeviceType::Phone,
        },
        1,
    )
    .unwrap();
    let mut invalid_stage = valid_stage.clone();
    invalid_stage.signature = Signature::new(vec![0u8; 64]);
    assert_eq!(
        node.stage_signed_operation(invalid_stage),
        Err(NodeError::Identity(IdentityError::SignatureInvalid))
    );
    assert_eq!(node.mempool_len(), 0);

    node.stage_signed_operation(valid_stage).unwrap();
    assert_eq!(node.mempool_len(), 1);
    let blk = node.produce_block(t0).unwrap();
    assert_eq!(blk.applied_mempool_ops, 1);
    assert_eq!(node.mempool_len(), 0);

    // Non-loopback bind MUST be forbidden by default.
    let shared = Arc::new(Mutex::new(node));
    assert!(matches!(
        start_control_server(Arc::clone(&shared), "0.0.0.0:0", false, None),
        Err(NodeError::NonLoopbackBindForbidden(_))
    ));

    // Loopback server on 127.0.0.1:0
    let server = start_control_server(Arc::clone(&shared), "127.0.0.1:0", false, None).unwrap();
    let addr = server.local_addr();

    // 1. GET /health
    let (code, body) = send_raw_http(
        addr,
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(code, 200);
    assert_eq!(body["ok"], json!(true));

    // 2. GET /status
    let (code, status_val) = send_raw_http(
        addr,
        b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(code, 200);
    let root_before = status_val["state_root_hex"].as_str().unwrap().to_string();
    assert!(!status_val.to_string().contains(&hex::encode([0x33u8; 32])));

    // 3. Unauthenticated / forged POST /submit_operation -> 401 Unauthorized, zero state change!
    let mut forged_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id.clone(),
        OperationPayload::EnrollDevice {
            device_key: dev2_vk.clone(),
            device_type: DeviceType::Robot,
        },
        2,
    )
    .unwrap();
    forged_op.signature = Signature::new(vec![0xABu8; 64]);
    let forged_json = serde_json::to_vec(&WireSignedOperation::from_signed(&forged_op)).unwrap();
    let forged_http = format!(
        "POST /submit_operation HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        forged_json.len()
    );
    let mut req_bytes = forged_http.into_bytes();
    req_bytes.extend_from_slice(&forged_json);
    let (code, _) = send_raw_http(addr, &req_bytes);
    assert_eq!(code, 401);
    assert_eq!(shared.lock().unwrap().state_root_hex(), root_before);

    // 4. Oversized body (`> 256 KiB`) -> 413 Payload Too Large before allocation, zero state change!
    let oversized_len = MAX_REQUEST_BYTES + 4096;
    let oversized_header = format!(
        "POST /submit_operation HTTP/1.1\r\nHost: localhost\r\nContent-Length: {oversized_len}\r\n\r\n{{}}"
    );
    let (code, body) = send_raw_http(addr, oversized_header.as_bytes());
    assert_eq!(code, 413);
    assert_eq!(body["error"], json!("request_too_large"));
    assert_eq!(shared.lock().unwrap().state_root_hex(), root_before);

    // 5. Valid signed POST /submit_operation -> 200 OK and StateRoot advances!
    let valid_http_op = sign_ed25519_operation(
        &alice_sk,
        &alice_vk,
        alice_id,
        OperationPayload::EnrollDevice {
            device_key: dev2_vk,
            device_type: DeviceType::Robot,
        },
        2,
    )
    .unwrap();
    let valid_json = serde_json::to_vec(&json!({
        "operation": WireSignedOperation::from_signed(&valid_http_op),
        "timestamp_secs": 1_700_000_050u64
    }))
    .unwrap();
    let valid_hdr = format!(
        "POST /submit_operation HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        valid_json.len()
    );
    let mut valid_req = valid_hdr.into_bytes();
    valid_req.extend_from_slice(&valid_json);
    let (code, body) = send_raw_http(addr, &valid_req);
    assert_eq!(code, 200);
    assert_eq!(body["kind"], json!("device_enrolled"));
    assert_ne!(body["state_root_hex"].as_str().unwrap(), root_before);

    // 6. JSON-RPC 2.0 `gmc_produceBlock`
    let rpc_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "gmc_produceBlock",
        "params": { "timestamp_secs": 1_700_000_090u64 }
    }))
    .unwrap();
    let rpc_hdr = format!(
        "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        rpc_body.len()
    );
    let mut rpc_req = rpc_hdr.into_bytes();
    rpc_req.extend_from_slice(&rpc_body);
    let (code, rpc_val) = send_raw_http(addr, &rpc_req);
    assert_eq!(code, 200);
    assert_eq!(rpc_val["result"]["block_height"], json!(2));

    let final_root = server.shutdown().unwrap();
    assert_eq!(
        hex::encode(final_root),
        rpc_val["result"]["state_root_hex"].as_str().unwrap()
    );

    // 7. CLI subprocess execution (`init`, duplicate `init` error, `status`, `produce-block`, `demo`)
    let bin = env!("CARGO_BIN_EXE_gmc-node");
    let cli_dir = TempNodeDir::new("cli-bin");
    let init_out = Command::new(bin)
        .args(["init", "--data-dir", cli_dir.path().to_str().unwrap()])
        .output()
        .expect("run gmc-node init");
    assert!(init_out.status.success(), "{init_out:?}");

    let dup_init = Command::new(bin)
        .args(["init", "--data-dir", cli_dir.path().to_str().unwrap()])
        .output()
        .expect("run duplicate gmc-node init");
    assert!(!dup_init.status.success());

    let status_out = Command::new(bin)
        .args(["status", "--data-dir", cli_dir.path().to_str().unwrap()])
        .output()
        .expect("run gmc-node status");
    assert!(status_out.status.success());
    let status_json: Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["transaction_fee"], json!("0"));
    assert_eq!(status_json["node_block_reward"], json!("0"));

    let blk_out = Command::new(bin)
        .args([
            "produce-block",
            "--data-dir",
            cli_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("run gmc-node produce-block");
    assert!(blk_out.status.success());

    let demo_dir = TempNodeDir::new("cli-demo");
    let demo_out = Command::new(bin)
        .args(["demo", "--data-dir", demo_dir.path().to_str().unwrap()])
        .output()
        .expect("run gmc-node demo");
    assert!(demo_out.status.success(), "{demo_out:?}");
    let demo_json: Value = serde_json::from_slice(&demo_out.stdout).unwrap();
    assert_eq!(demo_json["demo"], json!("ok"));
    assert_eq!(demo_json["fee_charged"], json!("0"));
    assert_eq!(demo_json["node_block_reward"], json!("0"));
}
