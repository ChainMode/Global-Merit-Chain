//! GMChain execution runtime (`NodeRuntime`): startup validation, mempool intake guard,
//! `IdentityState::apply` execution, L2 rollup batching, cryptographic `L1ProofSink`
//! settlement, deterministic two-phase BFT `QuorumCertificate` verification, zero-fee /
//! zero-reward block production (`VALIDATOR_REWARD == 0`), and graceful shutdown.

use std::collections::{BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use gmc_core::error::{GmcError, GmcResult};
use gmc_core::gmc_base::{GmcBase, MonetaryRequest};
use gmc_core::l1_settlement::{
    BatchProof as L1BatchProof, IdentityRegistrationRecord, L1Settlement, PenaltyRecord, StateRoot,
    VoteResultRecord,
};
use gmc_core::l2_rollup::{
    Batch, BatchProof as L2BatchProof, BatchRoot, ContributionSubmission, L1ProofSink, L2Rollup,
};
use gmc_core::merit::MeritBatch;
use gmc_core::penalty::{
    AppealOutcome, Complaint, PenaltyBallot, PenaltyEngine, PenaltyExecutionRecord,
};
use gmc_core::relationship::{PrivacyTier, RelationshipGraph, RelationshipType};
use gmc_core::types::{ChainId, Decimal, FayID, Ratio, Timestamp};
use gmc_identity::device::parse_device_type;
use gmc_identity::error::IdentityError;
use gmc_identity::fayid_interop::to_fayid_canonical;
use gmc_identity::identity_core::{Applied, IdentityState, OperationPayload, SignedOperation};
use gmc_identity::identity_id::IdentityId;
use gmc_identity::ownership::{OwnerKind, OwnerRef};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{IdentityKind, Nonce, SchemeTag, Signature, VerifyingKey};

use crate::consensus::{
    canonical_vote_bytes, BftStep, BlockProposal, BlockTransaction, EquivocationEvidence,
    QuorumCertificate, SignedConsensusVote, ValidatorSet, VALIDATOR_REWARD,
};
use crate::crypto::{
    keypair_from_seed, register_ed25519_scheme, run_ed25519_kat_self_test, Ed25519Verifier,
    OperatorKeyStore, OperatorKeypair, ED25519_SEED_LEN,
};
use crate::error::{NodeError, NodeResult};
use crate::store::{
    batch_trigger_to_str, compute_state_root, decode_relationship_graph, encode_buffered_record,
    encode_relationship_graph, str_to_privacy, str_to_rel_type, NodeStateStore,
    PersistedConsensusState, PersistedIdentityState, PersistedL1State, PersistedL2State,
    PersistedNodeState, PersistedPenaltyState, PersistedSealedBatch, SettledBatchCommitment,
};

/// Non-Monetary Iron Law: node block/batch production reward is strictly `0 μ`.
pub const NODE_BLOCK_REWARD: Decimal = Decimal::ZERO;
/// Fee-free L1 settlement constant (`0 μ` per transaction).
pub const NODE_TRANSACTION_FEE: Decimal = L1Settlement::TRANSACTION_FEE;
/// Default local testnet chain identifier.
pub const DEFAULT_CHAIN_ID: &str = "gmc-local-testnet-1";
/// Maximum pending signed operations staged in memory before block production.
pub const MAX_MEMPOOL_OPS: usize = 4_096;

const BATCH_COMMITMENT_DOMAIN: &[u8] = b"gmc-node:l2-batch-commitment:v1";

/// Startup configuration for [`NodeRuntime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    /// Persistent directory holding `keystore/operator.key`, `wal.log`, and `snapshot.json`.
    pub data_dir: PathBuf,
    /// Logical chain identifier anchored into `StateRoot`.
    pub chain_id: String,
    /// Deterministic genesis timestamp (`0` by default).
    pub genesis_time: Timestamp,
    /// Optional local control endpoint bind address (`127.0.0.1:<port>`).
    pub control_addr: Option<String>,
    /// Whether non-loopback control addresses are permitted (`false` by default).
    pub allow_non_loopback: bool,
}

impl NodeConfig {
    /// Creates a validated default local configuration rooted at `data_dir`.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        NodeConfig {
            data_dir: data_dir.into(),
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            genesis_time: Timestamp::from_secs(0),
            control_addr: None,
            allow_non_loopback: false,
        }
    }

    /// Validates startup configuration before touching disk or opening sockets.
    pub fn validate(&self) -> NodeResult<()> {
        if self.data_dir.as_os_str().is_empty() {
            return Err(NodeError::ConfigInvalid("data_dir must not be empty".into()));
        }
        if self.chain_id.trim().is_empty() {
            return Err(NodeError::ConfigInvalid("chain_id must not be empty".into()));
        }
        if let Some(addr_str) = &self.control_addr {
            let sock: SocketAddr = addr_str.parse().map_err(|e| {
                NodeError::ConfigInvalid(format!("invalid control_addr '{addr_str}': {e}"))
            })?;
            if !self.allow_non_loopback && !sock.ip().is_loopback() {
                return Err(NodeError::NonLoopbackBindForbidden(addr_str.clone()));
            }
        }
        Ok(())
    }
}

/// Computes the real SHA-256 cryptographic commitment over an L2 [`Batch`], binding its
/// sequence number, `BatchRoot`, timestamp, and ordered `BufferedRecord` entries.
pub fn compute_batch_commitment(batch: &Batch) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((BATCH_COMMITMENT_DOMAIN.len() as u64).to_be_bytes());
    h.update(BATCH_COMMITMENT_DOMAIN);
    h.update(batch.seq.to_be_bytes());
    h.update(batch.batch_root.as_bytes());
    h.update(batch.submitted_at.as_secs().to_be_bytes());
    h.update((batch.records.len() as u64).to_be_bytes());
    for rec in &batch.records {
        let rid = rec.record_id.as_str().as_bytes();
        h.update((rid.len() as u64).to_be_bytes());
        h.update(rid);
        let cid = rec.contributor_id.as_str().as_bytes();
        h.update((cid.len() as u64).to_be_bytes());
        h.update(cid);
        let ch = rec.chain_id.as_str().as_bytes();
        h.update((ch.len() as u64).to_be_bytes());
        h.update(ch);
        h.update(rec.merit_amount.raw().to_be_bytes());
        h.update(rec.ingested_at.as_secs().to_be_bytes());
    }
    h.finalize().into()
}

/// Pluggable L2 batch proof verifier seam (`OQ-1`: replaceable by succinct ZK SNARK/STARK).
pub trait BatchProofVerifier: Send + Sync {
    /// Verifies that `claimed_commitment` and `proof` validly attest to `batch`.
    fn verify_batch(
        &self,
        batch: &Batch,
        proof: &L2BatchProof,
        claimed_commitment: &[u8; 32],
    ) -> bool;
}

/// Default Milestone 1 deterministic SHA-256 batch commitment verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256BatchVerifier;

impl BatchProofVerifier for Sha256BatchVerifier {
    fn verify_batch(
        &self,
        batch: &Batch,
        proof: &L2BatchProof,
        claimed_commitment: &[u8; 32],
    ) -> bool {
        if proof.record_count() != batch.len() || proof.committed_root() != batch.batch_root {
            return false;
        }
        let expected = compute_batch_commitment(batch);
        &expected == claimed_commitment
    }
}

/// Concrete `L1ProofSink` implementation bridging `L2Rollup` into `L1Settlement::submit_batch_proof`.
struct NodeL1ProofSink<'a> {
    l1: &'a mut L1Settlement,
    batch: &'a Batch,
    claimed_commitment: [u8; 32],
    verifier: &'a dyn BatchProofVerifier,
}

impl L1ProofSink for NodeL1ProofSink<'_> {
    fn submit_batch_proof(
        &mut self,
        batch_root: BatchRoot,
        proof: &L2BatchProof,
    ) -> GmcResult<()> {
        // Map the cryptographic SHA-256 commitment onto L1's 32-byte StateRoot slot when
        // verified; pass an invalid `L1BatchProof` on mismatch so `L1Settlement` enforces
        // its Property 30 rejection guard and audit log.
        let target_l1_root = StateRoot::from_bytes(self.claimed_commitment);
        let is_valid = batch_root == self.batch.batch_root
            && self
                .verifier
                .verify_batch(self.batch, proof, &self.claimed_commitment);
        let l1_proof = if is_valid {
            L1BatchProof::valid_for(target_l1_root)
        } else {
            L1BatchProof::invalid_for(target_l1_root)
        };
        self.l1.submit_batch_proof(target_l1_root, l1_proof)?;
        Ok(())
    }
}

/// Public, secret-free node status summary returned by CLI `status`, HTTP `/status`, and `gmc_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub chain_id: String,
    pub node_id: String,
    pub operator_verifying_key_hex: String,
    pub block_height: u64,
    pub wal_seq: u64,
    pub state_root_hex: String,
    pub l1_state_root_hex: String,
    pub identity_count: usize,
    pub relationship_count: usize,
    pub penalty_case_count: usize,
    pub mempool_len: usize,
    pub l2_buffered_records: usize,
    pub pending_l2_records: usize,
    pub settled_batches: usize,
    pub validator_count: usize,
    pub total_validator_count: usize,
    pub ejected_validator_count: usize,
    pub quorum_threshold: usize,
    pub transaction_fee: String,
    pub node_transaction_fee: String,
    pub node_block_reward: String,
    pub validator_reward: String,
}

/// Receipt emitted by `produce_block` and `commit_bft_proposal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReceipt {
    pub block_height: u64,
    pub block_hash_hex: String,
    pub applied_mempool_ops: usize,
    pub settled_batch_seq: Option<u64>,
    pub settled_records: usize,
    pub state_root_hex: String,
    pub fee_charged_raw: i128,
    pub operator_reward_raw: i128,
    pub validator_reward_raw: u128,
    pub quorum_certificate: Value,
}

/// Receipt emitted by `submit_contribution`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionReceipt {
    pub batch_id: String,
    pub rollup_record_id: String,
    pub minted_amount_raw: i128,
    pub new_min_merit_raw: i128,
    pub auto_settled_batch_seq: Option<u64>,
    pub state_root_hex: String,
}

// ============================================================================
// Wire DTO for JSON-RPC / HTTP SignedOperation submission
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireOperationPayload {
    CreateCoFay {
        owner_id: String,
        owner_kind: String,
        new_cofay_key_hex: String,
    },
    EnrollDevice {
        device_key_hex: String,
        device_type: String,
    },
    RevokeDevice {
        device_id: String,
    },
    AddDelegate {
        delegate_key_hex: String,
    },
    RevokeDelegate {
        delegate_key_hex: String,
    },
    RotateKey {
        new_key_hex: String,
    },
    ConfigureGuardians {
        guardians_hex: Vec<String>,
        threshold: u32,
    },
    RecoveryApproval {
        new_key_hex: String,
        guardian_key_hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSignedOperation {
    pub target_scheme_tag: String,
    pub target_key_repr: String,
    pub nonce: Nonce,
    pub scheme_tag: String,
    pub verifying_key_hex: String,
    pub signature_hex: String,
    pub payload: WireOperationPayload,
}

impl WireSignedOperation {
    pub fn from_signed(op: &SignedOperation) -> Self {
        let payload = match &op.payload {
            OperationPayload::CreateCoFay {
                owner,
                new_cofay_key,
            } => WireOperationPayload::CreateCoFay {
                owner_id: owner.id.clone(),
                owner_kind: owner.kind.as_str().to_string(),
                new_cofay_key_hex: hex::encode(new_cofay_key.as_bytes()),
            },
            OperationPayload::EnrollDevice {
                device_key,
                device_type,
            } => WireOperationPayload::EnrollDevice {
                device_key_hex: hex::encode(device_key.as_bytes()),
                device_type: match device_type {
                    gmc_identity::types::DeviceType::Phone => "phone",
                    gmc_identity::types::DeviceType::Computer => "computer",
                    gmc_identity::types::DeviceType::Watch => "watch",
                    gmc_identity::types::DeviceType::Robot => "robot",
                    gmc_identity::types::DeviceType::CarHmi => "car-hmi",
                    gmc_identity::types::DeviceType::CloudSdk => "cloud-sdk",
                }
                .to_string(),
            },
            OperationPayload::RevokeDevice { device_id } => WireOperationPayload::RevokeDevice {
                device_id: device_id.clone(),
            },
            OperationPayload::AddDelegate { delegate } => WireOperationPayload::AddDelegate {
                delegate_key_hex: hex::encode(delegate.as_bytes()),
            },
            OperationPayload::RevokeDelegate { delegate } => WireOperationPayload::RevokeDelegate {
                delegate_key_hex: hex::encode(delegate.as_bytes()),
            },
            OperationPayload::RotateKey { new_key } => WireOperationPayload::RotateKey {
                new_key_hex: hex::encode(new_key.as_bytes()),
            },
            OperationPayload::ConfigureGuardians {
                guardians,
                threshold,
            } => WireOperationPayload::ConfigureGuardians {
                guardians_hex: guardians.iter().map(|g| hex::encode(g.as_bytes())).collect(),
                threshold: *threshold,
            },
            OperationPayload::RecoveryApproval {
                new_key,
                guardian_key,
            } => WireOperationPayload::RecoveryApproval {
                new_key_hex: hex::encode(new_key.as_bytes()),
                guardian_key_hex: hex::encode(guardian_key.as_bytes()),
            },
        };

        WireSignedOperation {
            target_scheme_tag: op.declared_target.scheme_tag().as_str().to_string(),
            target_key_repr: op.declared_target.key_repr().to_string(),
            nonce: op.nonce,
            scheme_tag: op.scheme_tag.as_str().to_string(),
            verifying_key_hex: hex::encode(op.verifying_key.as_bytes()),
            signature_hex: hex::encode(op.signature.as_bytes()),
            payload,
        }
    }

    pub fn into_signed(self) -> NodeResult<SignedOperation> {
        let decode_vk = |h: &str| -> NodeResult<VerifyingKey> {
            let bytes = hex::decode(h)
                .map_err(|e| NodeError::RpcInvalidRequest(format!("invalid key hex: {e}")))?;
            Ok(VerifyingKey::new(bytes))
        };
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| NodeError::RpcInvalidRequest(format!("invalid sig hex: {e}")))?;

        let payload = match self.payload {
            WireOperationPayload::CreateCoFay {
                owner_id,
                owner_kind,
                new_cofay_key_hex,
            } => {
                let kind = OwnerKind::parse_label(&owner_kind)?;
                OperationPayload::CreateCoFay {
                    owner: OwnerRef::new(owner_id, kind),
                    new_cofay_key: decode_vk(&new_cofay_key_hex)?,
                }
            }
            WireOperationPayload::EnrollDevice {
                device_key_hex,
                device_type,
            } => {
                let norm = device_type.replace('_', "-");
                let dt = parse_device_type(&norm)?;
                OperationPayload::EnrollDevice {
                    device_key: decode_vk(&device_key_hex)?,
                    device_type: dt,
                }
            }
            WireOperationPayload::RevokeDevice { device_id } => {
                OperationPayload::RevokeDevice { device_id }
            }
            WireOperationPayload::AddDelegate { delegate_key_hex } => {
                OperationPayload::AddDelegate {
                    delegate: decode_vk(&delegate_key_hex)?,
                }
            }
            WireOperationPayload::RevokeDelegate { delegate_key_hex } => {
                OperationPayload::RevokeDelegate {
                    delegate: decode_vk(&delegate_key_hex)?,
                }
            }
            WireOperationPayload::RotateKey { new_key_hex } => OperationPayload::RotateKey {
                new_key: decode_vk(&new_key_hex)?,
            },
            WireOperationPayload::ConfigureGuardians {
                guardians_hex,
                threshold,
            } => {
                let mut guardians = Vec::with_capacity(guardians_hex.len());
                for gh in &guardians_hex {
                    guardians.push(decode_vk(gh)?);
                }
                OperationPayload::ConfigureGuardians {
                    guardians,
                    threshold,
                }
            }
            WireOperationPayload::RecoveryApproval {
                new_key_hex,
                guardian_key_hex,
            } => OperationPayload::RecoveryApproval {
                new_key: decode_vk(&new_key_hex)?,
                guardian_key: decode_vk(&guardian_key_hex)?,
            },
        };

        Ok(SignedOperation::new(
            IdentityId::new(SchemeTag::new(self.target_scheme_tag), self.target_key_repr),
            payload,
            self.nonce,
            SchemeTag::new(self.scheme_tag),
            decode_vk(&self.verifying_key_hex)?,
            Signature::new(sig_bytes),
        ))
    }
}

fn operation_digest_hex(op: &SignedOperation) -> String {
    let mut h = Sha256::new();
    h.update(op.canonical_message());
    h.update((op.scheme_tag.as_str().len() as u64).to_be_bytes());
    h.update(op.scheme_tag.as_str().as_bytes());
    h.update((op.verifying_key.as_bytes().len() as u64).to_be_bytes());
    h.update(op.verifying_key.as_bytes());
    h.update((op.signature.as_bytes().len() as u64).to_be_bytes());
    h.update(op.signature.as_bytes());
    hex::encode(h.finalize())
}

// ============================================================================
// NodeRuntime
// ============================================================================

/// Crash-consistent GMChain runtime supporting both single-node local execution and
/// multi-node two-phase BFT consensus (`ValidatorSet` + `QuorumCertificate`).
pub struct NodeRuntime {
    config: NodeConfig,
    operator: OperatorKeypair,
    store: NodeStateStore,
    block_height: u64,
    applied_op_digests: BTreeSet<String>,
    mempool: VecDeque<SignedOperation>,
    mempool_digests: BTreeSet<String>,
    gmc_base: GmcBase,
    identities: IdentityState,
    relationships: RelationshipGraph,
    penalties: PenaltyEngine,
    l1: L1Settlement,
    settled_batches: Vec<SettledBatchCommitment>,
    l2: L2Rollup,
    sealed_batches: Vec<PersistedSealedBatch>,
    validator_set: ValidatorSet,
    committed_qcs: Vec<QuorumCertificate>,
    equivocations: Vec<EquivocationEvidence>,
    local_committee_seeds: Vec<(Zeroizing<[u8; ED25519_SEED_LEN]>, String)>,
    testnet: crate::testnet::PersistedTestnetState,
    batch_verifier: Box<dyn BatchProofVerifier>,
}

impl NodeRuntime {
    /// Initializes a brand-new node data directory with a random OS-seeded operator key
    /// (`0600`) and writes the initial genesis snapshot.
    ///
    /// Fails with [`NodeError::KeyAlreadyExists`] if `<data_dir>/keystore/operator.key`
    /// already exists.
    pub fn init(config: NodeConfig) -> NodeResult<Self> {
        config.validate()?;
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);
        run_ed25519_kat_self_test(&registry)?;

        let operator = OperatorKeyStore::init_random(&config.data_dir, &registry)?;
        Self::finish_open(config, operator, None, Vec::new(), true)
    }

    /// Deterministic variant of [`Self::init`] accepting an explicit 32-byte operator seed
    /// (for reproducible integration tests). Refuses to overwrite an existing key.
    pub fn init_with_seed(config: NodeConfig, seed: [u8; ED25519_SEED_LEN]) -> NodeResult<Self> {
        config.validate()?;
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);
        run_ed25519_kat_self_test(&registry)?;

        let operator = OperatorKeyStore::init_with_seed(&config.data_dir, &registry, seed)?;
        Self::finish_open(config, operator, None, Vec::new(), true)
    }

    /// Initializes or opens a multi-node BFT validator instance bound to `validator_set`.
    pub fn init_with_validators(
        config: NodeConfig,
        seed: [u8; ED25519_SEED_LEN],
        validator_set: ValidatorSet,
    ) -> NodeResult<Self> {
        config.validate()?;
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);
        run_ed25519_kat_self_test(&registry)?;

        let (operator, write_initial) = if OperatorKeyStore::exists(&config.data_dir) {
            (OperatorKeyStore::load(&config.data_dir, &registry)?, false)
        } else {
            (
                OperatorKeyStore::init_with_seed(&config.data_dir, &registry, seed)?,
                true,
            )
        };
        Self::finish_open(
            config,
            operator,
            Some(validator_set),
            Vec::new(),
            write_initial,
        )
    }

    /// Initializes a brand-new `Meritora Desktop` local workbench node backed by a
    /// deterministic 4-validator BFT committee (`N = 4`, quorum `3/4`).
    pub fn init_workbench(config: NodeConfig) -> NodeResult<Self> {
        config.validate()?;
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);
        run_ed25519_kat_self_test(&registry)?;

        let (pairs, validator_set) = ValidatorSet::deterministic_local_committee(4)?;
        let operator =
            OperatorKeyStore::init_with_seed(&config.data_dir, &registry, pairs[0].0)?;
        let seeds = pairs
            .into_iter()
            .map(|(s, info)| (Zeroizing::new(s), info.validator_id))
            .collect();
        Self::finish_open(config, operator, Some(validator_set), seeds, true)
    }

    /// Opens an existing `Meritora Desktop` workbench data directory or initializes one
    /// with a 4-validator local BFT committee if `<data_dir>/keystore/operator.key` is absent.
    pub fn open_workbench(config: NodeConfig) -> NodeResult<Self> {
        if !OperatorKeyStore::exists(&config.data_dir) {
            return Self::init_workbench(config);
        }
        let mut runtime = Self::open(config)?;
        let (pairs, expected_set) = ValidatorSet::deterministic_local_committee(4)?;
        let matches_local_committee = runtime.validator_set.total_count() == expected_set.total_count()
            && runtime
                .validator_set
                .validators()
                .iter()
                .zip(expected_set.validators().iter())
                .all(|(a, b)| a.validator_id == b.validator_id && a.pubkey == b.pubkey);
        if matches_local_committee {
            runtime.local_committee_seeds = pairs
                .into_iter()
                .map(|(s, info)| (Zeroizing::new(s), info.validator_id))
                .collect();
        }
        Ok(runtime)
    }

    /// Opens an already-initialized node data directory, executing the fixed startup
    /// sequence: config check -> Ed25519 KAT self-test -> keystore load -> WAL/snapshot recovery.
    pub fn open(config: NodeConfig) -> NodeResult<Self> {
        config.validate()?;
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);
        run_ed25519_kat_self_test(&registry)?;

        let operator = OperatorKeyStore::load(&config.data_dir, &registry)?;
        Self::finish_open(config, operator, None, Vec::new(), false)
    }

    fn finish_open(
        config: NodeConfig,
        operator: OperatorKeypair,
        initial_validator_set: Option<ValidatorSet>,
        local_committee_seeds: Vec<(Zeroizing<[u8; ED25519_SEED_LEN]>, String)>,
        write_initial_snapshot: bool,
    ) -> NodeResult<Self> {
        let (store, persisted) = NodeStateStore::open_and_recover(
            &config.data_dir,
            &config.chain_id,
            config.genesis_time.as_secs(),
        )?;

        if persisted.chain_id != config.chain_id {
            return Err(NodeError::ConfigInvalid(format!(
                "persisted chain_id '{}' does not match configured '{}'",
                persisted.chain_id, config.chain_id
            )));
        }

        let identities = persisted.identities.restore(&persisted.pockets)?;
        let relationships = decode_relationship_graph(&persisted.relationships)?;
        let penalties = persisted.penalties.restore()?;
        let (l1, settled_batches) = persisted.l1_records.restore()?;
        let (l2, sealed_batches) = persisted.l2_batches.restore();
        let applied_op_digests: BTreeSet<String> =
            persisted.applied_op_digests.iter().cloned().collect();

        let validator_set = if !persisted.consensus.validators.is_empty() {
            ValidatorSet::new(persisted.consensus.validators.clone())?
        } else if let Some(vset) = initial_validator_set {
            vset
        } else {
            let op_vid = to_fayid_canonical(operator.node_id(), IdentityKind::IFay)?;
            let op_pk: [u8; 32] = operator
                .verifying_key()
                .as_bytes()
                .try_into()
                .map_err(|_| NodeError::KeyFormatInvalid)?;
            ValidatorSet::single_operator(op_vid, op_pk)?
        };

        let runtime = NodeRuntime {
            config,
            operator,
            store,
            block_height: persisted.block_height,
            applied_op_digests,
            mempool: VecDeque::new(),
            mempool_digests: BTreeSet::new(),
            gmc_base: GmcBase::new(),
            identities,
            relationships,
            penalties,
            l1,
            settled_batches,
            l2,
            sealed_batches,
            validator_set,
            committed_qcs: persisted.consensus.committed_qcs,
            equivocations: persisted.consensus.equivocations,
            local_committee_seeds,
            testnet: persisted.testnet,
            batch_verifier: Box::new(Sha256BatchVerifier),
        };

        if write_initial_snapshot && runtime.store.last_wal_seq() == 0 {
            let snap = runtime.export_persisted_state();
            runtime.store.write_atomic_snapshot(&snap)?;
        }

        Ok(runtime)
    }

    // --- Read-only accessors ------------------------------------------------

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn operator_node_id(&self) -> &IdentityId {
        self.operator.node_id()
    }

    pub fn operator_verifying_key(&self) -> &VerifyingKey {
        self.operator.verifying_key()
    }

    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    pub fn identities(&self) -> &IdentityState {
        &self.identities
    }

    pub fn relationships(&self) -> &RelationshipGraph {
        &self.relationships
    }

    pub(crate) fn relationships_mut(&mut self) -> &mut RelationshipGraph {
        &mut self.relationships
    }

    pub fn testnet_state(&self) -> &crate::testnet::PersistedTestnetState {
        &self.testnet
    }

    pub(crate) fn testnet_state_mut(&mut self) -> &mut crate::testnet::PersistedTestnetState {
        &mut self.testnet
    }

    pub(crate) fn anchor_l1_vote_result(&mut self, record: VoteResultRecord) {
        self.l1.store_vote_result(record);
    }

    pub(crate) fn persist_testnet_wal(&mut self, event_tag: &str) -> NodeResult<[u8; 32]> {
        self.persist_wal(event_tag)
    }

    pub fn penalties(&self) -> &PenaltyEngine {
        &self.penalties
    }

    pub fn l1(&self) -> &L1Settlement {
        &self.l1
    }

    pub fn l2(&self) -> &L2Rollup {
        &self.l2
    }

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub fn committed_qcs(&self) -> &[QuorumCertificate] {
        &self.committed_qcs
    }

    pub fn latest_qc(&self) -> Option<&QuorumCertificate> {
        self.committed_qcs.last()
    }

    pub fn equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocations
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// Canonical 32-byte SHA-256 `StateRoot` committing to all durable node state.
    pub fn state_root(&self) -> [u8; 32] {
        compute_state_root(&self.export_persisted_state())
    }

    /// Lowercase hex encoding of [`Self::state_root`].
    pub fn state_root_hex(&self) -> String {
        hex::encode(self.state_root())
    }

    /// Builds a secret-free [`NodeStatus`] snapshot.
    pub fn status(&self) -> NodeStatus {
        debug_assert_eq!(VALIDATOR_REWARD, 0);
        let root = self.state_root_hex();
        let buffered = self.l2.buffered_len();
        NodeStatus {
            chain_id: self.config.chain_id.clone(),
            node_id: self.operator.node_id().canonical(),
            operator_verifying_key_hex: hex::encode(self.operator.verifying_key().as_bytes()),
            block_height: self.block_height,
            wal_seq: self.store.last_wal_seq(),
            state_root_hex: root,
            l1_state_root_hex: hex::encode(self.l1.state_root().as_bytes()),
            identity_count: self.identities.identities.len(),
            relationship_count: self.relationships.len(),
            penalty_case_count: self.penalties.cases().count(),
            mempool_len: self.mempool.len(),
            l2_buffered_records: buffered,
            pending_l2_records: buffered,
            settled_batches: self.settled_batches.len(),
            validator_count: self.validator_set.active_count(),
            total_validator_count: self.validator_set.total_count(),
            ejected_validator_count: self.validator_set.ejected_count(),
            quorum_threshold: self.validator_set.quorum_threshold(),
            transaction_fee: "0".to_string(),
            node_transaction_fee: "0".to_string(),
            node_block_reward: "0".to_string(),
            validator_reward: "0".to_string(),
        }
    }

    /// Unconditionally rejects monetary transfer/exchange/purchase requests via `GMC_Base`.
    pub fn reject_monetary_request(&self, request: &MonetaryRequest) -> GmcResult<()> {
        self.gmc_base.reject_monetary_request(request)
    }

    // --- State-mutating operations (all WAL-backed) -------------------------

    /// Registers a self-sovereign `iFay` under `ed25519`, binds its `MeritPocket`,
    /// anchors its `IdentityRegistrationRecord` on L1, and persists to WAL.
    pub fn register_ifay(
        &mut self,
        verifying_key: &VerifyingKey,
        now: Timestamp,
    ) -> NodeResult<IdentityId> {
        let existed = gmc_identity::identity_id::derive_identity_id(
            &self.identities.registry,
            &SchemeTag::ed25519(),
            verifying_key,
        )
        .map(|id| self.identities.identities.contains(&id))?;

        let id = self.identities.identities.create_ifay(
            &self.identities.registry,
            &mut self.identities.ownership,
            &mut self.identities.binding,
            &SchemeTag::ed25519(),
            verifying_key,
            now,
        )?;

        if !existed {
            self.l1
                .store_identity_registration(IdentityRegistrationRecord::new(
                    id.to_fay_id(),
                    now,
                ));
            self.persist_wal("register_ifay")?;
        }
        Ok(id)
    }

    /// Validates a [`SignedOperation`] at the intake gate before admitting it into the
    /// bounded mempool (`MAX_MEMPOOL_OPS`). Invalid signatures, unknown targets, stale
    /// nonces, or duplicates are rejected immediately without touching mempool or state.
    pub fn stage_signed_operation(&mut self, op: SignedOperation) -> NodeResult<String> {
        if self.mempool.len() >= MAX_MEMPOOL_OPS {
            return Err(NodeError::MempoolFull {
                max_ops: MAX_MEMPOOL_OPS,
            });
        }

        let digest = operation_digest_hex(&op);
        if self.applied_op_digests.contains(&digest) || self.mempool_digests.contains(&digest) {
            return Err(NodeError::DuplicateOperation);
        }

        // Dry-run full `IdentityState::apply` validation on a clone so every auth,
        // nonce, guardian, device, and ownership check passes before mempool admission.
        let mut dry_run = self.identities.clone();
        dry_run.apply(&op, &Ed25519Verifier, Timestamp::from_secs(0))?;

        // Also reject conflicting pending nonce for the same target already in mempool.
        if self
            .mempool
            .iter()
            .any(|m| m.declared_target == op.declared_target && m.nonce >= op.nonce)
        {
            return Err(NodeError::Identity(IdentityError::ReplayDetected));
        }

        self.mempool_digests.insert(digest.clone());
        self.mempool.push_back(op);
        Ok(digest)
    }

    /// Validates and immediately executes a [`SignedOperation`] through
    /// `IdentityState::apply(&Ed25519Verifier)`, anchoring any newly created `coFay` on
    /// L1 and appending a durable WAL frame.
    ///
    /// On any error, memory and disk state remain byte-for-byte unchanged.
    pub fn submit_signed_operation(
        &mut self,
        op: SignedOperation,
        now: Timestamp,
    ) -> NodeResult<Applied> {
        let digest = operation_digest_hex(&op);
        if self.applied_op_digests.contains(&digest) {
            return Err(NodeError::Identity(IdentityError::ReplayDetected));
        }

        let applied = self.identities.apply(&op, &Ed25519Verifier, now)?;
        if let Applied::CoFayCreated(ref cofay_id) = applied {
            self.l1
                .store_identity_registration(IdentityRegistrationRecord::new(
                    cofay_id.to_fay_id(),
                    now,
                ));
        }
        self.applied_op_digests.insert(digest);
        self.persist_wal("submit_signed_operation")?;
        Ok(applied)
    }

    /// Registers a bilaterally confirmed social relationship edge on-chain and persists to WAL.
    pub fn register_relationship(
        &mut self,
        a: FayID,
        b: FayID,
        relationship_type: RelationshipType,
        privacy_tier: PrivacyTier,
        registered_at: Timestamp,
    ) -> NodeResult<()> {
        self.relationships
            .register_bilateral(a, b, relationship_type, privacy_tier, registered_at)?;
        self.persist_wal("register_relationship")?;
        Ok(())
    }

    /// Records a directed interaction on a registered relationship edge and persists to WAL.
    pub fn record_interaction(
        &mut self,
        initiator: &FayID,
        counterparty: &FayID,
        depth: Ratio,
        at: Timestamp,
    ) -> NodeResult<bool> {
        let matched = self
            .relationships
            .record_interaction(initiator, counterparty, depth, at)?;
        self.persist_wal("record_interaction")?;
        Ok(matched)
    }

    /// Files a batch-bound complaint in `PenaltyEngine` and persists to WAL.
    pub fn file_complaint(&mut self, complaint: Complaint) -> NodeResult<()> {
        let complainant_cur = self
            .identities
            .binding
            .pocket_by_key(&complaint.complainant)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?
            .cur_merit(complaint.filed_at);
        let respondent_pocket = self
            .identities
            .binding
            .pocket_by_key(&complaint.respondent)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?;

        self.penalties
            .file_complaint(complaint, complainant_cur, respondent_pocket)?;
        self.persist_wal("file_complaint")?;
        Ok(())
    }

    /// Resolves Stage 1 stakeholder admissibility for `complaint_id` and persists to WAL.
    pub fn resolve_admissibility(
        &mut self,
        complaint_id: &str,
        ballots: &[PenaltyBallot],
    ) -> NodeResult<bool> {
        let admitted = self
            .penalties
            .resolve_admissibility(complaint_id, ballots)?;
        self.persist_wal("resolve_admissibility")?;
        Ok(admitted)
    }

    /// Executes a `>= 3/4` supermajority penalty against the respondent's `MeritPocket`,
    /// anchors a `PenaltyRecord` on L1, and persists to WAL.
    pub fn execute_penalty(
        &mut self,
        complaint_id: &str,
        ballots: &[PenaltyBallot],
        executed_at: Timestamp,
    ) -> NodeResult<PenaltyExecutionRecord> {
        let respondent = self
            .penalties
            .get_case(complaint_id)
            .ok_or(NodeError::Core(GmcError::ComplaintInvalid))?
            .complaint
            .respondent
            .clone();
        let pocket = self
            .identities
            .binding
            .pocket_by_key_mut(&respondent)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?;

        let record = self
            .penalties
            .execute_penalty(complaint_id, pocket, ballots, executed_at)?;
        self.l1.record_penalty(PenaltyRecord::new(
            respondent,
            format!("{}:{:?}", record.complaint_id, record.severity),
            executed_at,
        ));
        self.persist_wal("execute_penalty")?;
        Ok(record)
    }

    /// Submits an appeal within `appeal_window_secs` and persists to WAL.
    pub fn submit_appeal(
        &mut self,
        complaint_id: &str,
        counter_evidence_hash: impl Into<String>,
        submitted_at: Timestamp,
    ) -> NodeResult<()> {
        self.penalties
            .submit_appeal(complaint_id, counter_evidence_hash, submitted_at)?;
        self.persist_wal("submit_appeal")?;
        Ok(())
    }

    /// Resolves an appeal, atomically restoring the respondent's `MeritPocket` if
    /// overturned, anchoring the vote outcome on L1, and persisting to WAL.
    pub fn resolve_appeal(
        &mut self,
        complaint_id: &str,
        ballots: &[PenaltyBallot],
        resolved_at: Timestamp,
    ) -> NodeResult<AppealOutcome> {
        let respondent = self
            .penalties
            .get_case(complaint_id)
            .ok_or(NodeError::Core(GmcError::ComplaintInvalid))?
            .complaint
            .respondent
            .clone();
        let pocket = self
            .identities
            .binding
            .pocket_by_key_mut(&respondent)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?;

        let outcome = self
            .penalties
            .resolve_appeal(complaint_id, pocket, ballots, resolved_at)?;
        let overturned = matches!(outcome, AppealOutcome::Overturned { .. });
        self.l1.store_vote_result(VoteResultRecord::new(
            format!("appeal:{complaint_id}"),
            format!("penalty-appeal:{complaint_id}"),
            overturned,
            resolved_at,
        ));
        self.persist_wal("resolve_appeal")?;
        Ok(outcome)
    }

    /// Processes a contribution on L2: validates contributor & positive amount/duration,
    /// mints a `MeritBatch` into the contributor's `MeritPocket`, buffers on `L2Rollup`,
    /// auto-settles to L1 if the `1,000`-record or `60s` trigger fires, and persists to WAL.
    pub fn submit_contribution(
        &mut self,
        contributor: &IdentityId,
        chain_id: ChainId,
        merit_amount: Decimal,
        influence_duration: Decimal,
        now: Timestamp,
    ) -> NodeResult<ContributionReceipt> {
        if !merit_amount.is_positive() {
            return Err(NodeError::Core(GmcError::InvalidMintAmount));
        }
        let lambda = MeritBatch::lambda_from_duration(influence_duration)
            .ok_or(NodeError::Core(GmcError::InvalidMintAmount))?;
        if !self.identities.identities.contains(contributor) {
            return Err(NodeError::Core(GmcError::NotRegistered));
        }

        let fay_id = contributor.to_fay_id();
        let batch_id = format!("batch-{}", self.l2.next_record_seq());

        let new_min_merit = {
            let pocket = self
                .identities
                .binding
                .pocket_by_key_mut(&fay_id)
                .ok_or(NodeError::Core(GmcError::NotRegistered))?;

            let floor_increment = if pocket.batches.is_empty() {
                // Establish backing for initial pocket floor without reducing `min_merit`.
                merit_amount.min(pocket.min_merit)
            } else {
                let m = pocket.cur_merit(now);
                let old_floor = pocket.min_merit();
                let new_floor = pocket.update_min_merit(merit_amount, m)?;
                new_floor.checked_sub(old_floor).unwrap_or(Decimal::ZERO)
            };

            pocket.add_batch(MeritBatch::new(
                batch_id.clone(),
                merit_amount,
                floor_increment,
                lambda,
                influence_duration,
                now,
                chain_id.clone(),
            ));
            pocket.min_merit()
        };

        let comp = self.l2.process_contribution(
            ContributionSubmission::new(fay_id, chain_id, merit_amount),
            now,
        );

        let mut auto_settled_seq = None;
        if let Some(batch) = self.l2.preview_batch(now, false) {
            let commitment = compute_batch_commitment(&batch);
            self.verify_and_commit_l2_batch(&batch, commitment, now)?;
            auto_settled_seq = Some(batch.seq);
        }

        let root = self.persist_wal("submit_contribution")?;
        Ok(ContributionReceipt {
            batch_id,
            rollup_record_id: comp.record_id.as_str().to_string(),
            minted_amount_raw: merit_amount.raw(),
            new_min_merit_raw: new_min_merit.raw(),
            auto_settled_batch_seq: auto_settled_seq,
            state_root_hex: hex::encode(root),
        })
    }

    /// Submits an explicit L2 batch commitment to L1 verification (allowing tests to
    /// inject a corrupted commitment and verify atomic rejection: `ProofVerificationFailed`,
    /// retained `StateRoot`, and preserved buffered L2 records).
    pub fn submit_pending_batch_with_commitment(
        &mut self,
        claimed_commitment: [u8; 32],
        now: Timestamp,
    ) -> NodeResult<u64> {
        let Some(batch) = self.l2.preview_batch(now, true) else {
            return Err(NodeError::Core(GmcError::OperationNotAllowed));
        };
        let mut temp_l1 = self.l1.clone();
        {
            let mut sink = NodeL1ProofSink {
                l1: &mut temp_l1,
                batch: &batch,
                claimed_commitment,
                verifier: &*self.batch_verifier,
            };
            L2Rollup::submit_batch_proof_to(&batch, &mut sink)?;
        }
        // Verification passed -> commit both L1 and L2 atomically and persist WAL.
        self.l1 = temp_l1;
        self.record_committed_batch(&batch, claimed_commitment, now);
        self.persist_wal("settle_l2_batch")?;
        Ok(batch.seq)
    }

    /// Produces the next deterministic block:
    /// 1. Executes staged mempool operations in FIFO order;
    /// 2. Seals and settles any buffered L2 records onto L1 with `0 μ` transaction fee;
    /// 3. Mints **zero** operator/validator `MeriToken` (`NODE_BLOCK_REWARD == 0`, `VALIDATOR_REWARD == 0`);
    /// 4. Assembles and strictly verifies a BFT `QuorumCertificate` over `(height, round, block_hash, state_root)`;
    /// 5. Increments `block_height`, appends WAL, and writes an atomic `snapshot.json`.
    pub fn produce_block(&mut self, now: Timestamp) -> NodeResult<BlockReceipt> {
        debug_assert!(NODE_BLOCK_REWARD.is_zero());
        debug_assert!(NODE_TRANSACTION_FEE.is_zero());
        debug_assert_eq!(VALIDATOR_REWARD, 0);
        debug_assert!(self.l1.is_fee_free());

        let parent_root = self.state_root();
        let mut applied_mempool_ops = 0usize;
        while let Some(op) = self.mempool.pop_front() {
            let digest = operation_digest_hex(&op);
            self.mempool_digests.remove(&digest);
            if self.applied_op_digests.contains(&digest) {
                continue;
            }
            if let Ok(applied) = self.identities.apply(&op, &Ed25519Verifier, now) {
                if let Applied::CoFayCreated(ref cofay_id) = applied {
                    self.l1
                        .store_identity_registration(IdentityRegistrationRecord::new(
                            cofay_id.to_fay_id(),
                            now,
                        ));
                }
                self.applied_op_digests.insert(digest);
                applied_mempool_ops += 1;
            }
        }

        let mut settled_batch_seq = None;
        let mut settled_records = 0usize;
        if let Some(batch) = self.l2.preview_batch(now, true) {
            let commitment = compute_batch_commitment(&batch);
            self.verify_and_commit_l2_batch(&batch, commitment, now)?;
            settled_batch_seq = Some(batch.seq);
            settled_records = batch.len();
        }

        self.block_height += 1;
        let state_root = self.state_root();
        let proposer_id = self
            .validator_set
            .proposer_for(self.block_height, 0)?
            .validator_id
            .clone();
        let block_hash = BlockProposal::compute_block_hash(
            &self.config.chain_id,
            self.block_height,
            0,
            now.as_secs(),
            &parent_root,
            &[],
            &state_root,
            &proposer_id,
        )?;

        let votes = if !self.local_committee_seeds.is_empty() {
            let mut vs = Vec::new();
            for (seed, vid) in &self.local_committee_seeds {
                if self
                    .validator_set
                    .get(vid)
                    .map(|v| v.active)
                    .unwrap_or(false)
                {
                    vs.push(SignedConsensusVote::sign(
                        seed,
                        vid,
                        &self.config.chain_id,
                        self.block_height,
                        0,
                        BftStep::Precommit,
                        block_hash,
                        state_root,
                    )?);
                }
            }
            vs
        } else {
            let op_vid = to_fayid_canonical(self.operator.node_id(), IdentityKind::IFay)?;
            let msg = canonical_vote_bytes(
                &self.config.chain_id,
                self.block_height,
                0,
                BftStep::Precommit,
                &block_hash,
                &state_root,
            );
            let sig = self.operator.sign_bytes(&msg);
            let sig_arr: [u8; 64] = sig
                .as_bytes()
                .try_into()
                .map_err(|_| NodeError::KeyFormatInvalid)?;
            vec![SignedConsensusVote {
                validator_id: op_vid,
                chain_id: self.config.chain_id.clone(),
                height: self.block_height,
                round: 0,
                step: BftStep::Precommit,
                block_hash,
                state_root,
                signature: sig_arr,
            }]
        };

        let qc = QuorumCertificate {
            chain_id: self.config.chain_id.clone(),
            height: self.block_height,
            round: 0,
            step: BftStep::Precommit,
            block_hash,
            state_root,
            votes,
        };
        qc.verify(&self.validator_set, &self.config.chain_id)?;
        let qc_json = qc.to_summary_json(self.validator_set.quorum_threshold());
        self.committed_qcs.push(qc);

        let mut persisted = self.export_persisted_state();
        let root = self.store.append_wal("produce_block", &mut persisted)?;
        self.store.write_atomic_snapshot(&persisted)?;

        Ok(BlockReceipt {
            block_height: self.block_height,
            block_hash_hex: hex::encode(block_hash),
            applied_mempool_ops,
            settled_batch_seq,
            settled_records,
            state_root_hex: hex::encode(root),
            fee_charged_raw: NODE_TRANSACTION_FEE.raw(),
            operator_reward_raw: NODE_BLOCK_REWARD.raw(),
            validator_reward_raw: VALIDATOR_REWARD,
            quorum_certificate: qc_json,
        })
    }

    /// Deterministically previews the canonical SHA-256 `StateRoot` that would result from
    /// executing `transactions` and sealing pending L2 records at `(expected_height, timestamp_secs)`,
    /// without mutating `self` or writing to disk.
    pub fn preview_bft_state_root(
        &self,
        expected_height: u64,
        timestamp_secs: u64,
        transactions: &[BlockTransaction],
    ) -> NodeResult<[u8; 32]> {
        if expected_height != self.block_height + 1 {
            return Err(NodeError::ConsensusInvalid(format!(
                "expected proposal height {}, got {expected_height}",
                self.block_height + 1
            )));
        }

        let mut sandbox = ExecutionSandbox {
            chain_id: self.config.chain_id.clone(),
            genesis_time_secs: self.config.genesis_time.as_secs(),
            block_height: self.block_height,
            applied_op_digests: self.applied_op_digests.clone(),
            identities: self.identities.clone(),
            relationships: self.relationships.clone(),
            penalties: self.penalties.clone(),
            l1: self.l1.clone(),
            settled_batches: self.settled_batches.clone(),
            l2: self.l2.clone(),
            sealed_batches: self.sealed_batches.clone(),
            testnet: self.testnet.clone(),
        };
        sandbox.execute_proposal(
            transactions,
            Timestamp::from_secs(timestamp_secs),
            &*self.batch_verifier,
        )?;
        Ok(sandbox.state_root())
    }

    /// Commits a multi-node BFT [`BlockProposal`] together with its verified supermajority
    /// [`QuorumCertificate`], enforcing deterministic `StateRoot` agreement and zero-fee /
    /// zero-reward constitutional invariants.
    pub fn commit_bft_proposal(
        &mut self,
        proposal: &BlockProposal,
        qc: &QuorumCertificate,
    ) -> NodeResult<BlockReceipt> {
        debug_assert!(NODE_BLOCK_REWARD.is_zero());
        debug_assert!(NODE_TRANSACTION_FEE.is_zero());
        debug_assert_eq!(VALIDATOR_REWARD, 0);

        if proposal.height != self.block_height + 1 {
            return Err(NodeError::ConsensusInvalid(format!(
                "commit height {} != expected {}",
                proposal.height,
                self.block_height + 1
            )));
        }
        let current_root = self.state_root();
        if proposal.parent_state_root != current_root {
            return Err(NodeError::ConsensusInvalid(
                "proposal parent_state_root mismatch".into(),
            ));
        }

        proposal.verify(&self.validator_set, &self.config.chain_id)?;
        if qc.height != proposal.height
            || qc.round != proposal.round
            || qc.block_hash != proposal.block_hash
            || qc.state_root != proposal.state_root
        {
            return Err(NodeError::ConsensusInvalid(
                "QuorumCertificate does not match BlockProposal".into(),
            ));
        }
        qc.verify(&self.validator_set, &self.config.chain_id)?;

        // Dry-run in sandbox first so any transaction failure or state_root mismatch leaves `self` untouched!
        let mut sandbox = ExecutionSandbox {
            chain_id: self.config.chain_id.clone(),
            genesis_time_secs: self.config.genesis_time.as_secs(),
            block_height: self.block_height,
            applied_op_digests: self.applied_op_digests.clone(),
            identities: self.identities.clone(),
            relationships: self.relationships.clone(),
            penalties: self.penalties.clone(),
            l1: self.l1.clone(),
            settled_batches: self.settled_batches.clone(),
            l2: self.l2.clone(),
            sealed_batches: self.sealed_batches.clone(),
            testnet: self.testnet.clone(),
        };
        let (applied_ops, settled_batch_seq, settled_records) = sandbox.execute_proposal(
            &proposal.transactions,
            Timestamp::from_secs(proposal.timestamp_secs),
            &*self.batch_verifier,
        )?;
        let computed_root = sandbox.state_root();
        if computed_root != proposal.state_root {
            return Err(NodeError::ConsensusInvalid(format!(
                "proposal state_root {} != deterministic local state_root {}",
                hex::encode(proposal.state_root),
                hex::encode(computed_root)
            )));
        }

        // Swap verified post-state into `self`, persist QC + WAL + atomic snapshot.
        self.block_height = sandbox.block_height;
        self.applied_op_digests = sandbox.applied_op_digests;
        self.identities = sandbox.identities;
        self.relationships = sandbox.relationships;
        self.penalties = sandbox.penalties;
        self.l1 = sandbox.l1;
        self.settled_batches = sandbox.settled_batches;
        self.l2 = sandbox.l2;
        self.sealed_batches = sandbox.sealed_batches;
        let qc_json = qc.to_summary_json(self.validator_set.quorum_threshold());
        self.committed_qcs.push(qc.clone());

        let mut persisted = self.export_persisted_state();
        let root = self.store.append_wal("commit_bft_block", &mut persisted)?;
        self.store.write_atomic_snapshot(&persisted)?;

        Ok(BlockReceipt {
            block_height: self.block_height,
            block_hash_hex: hex::encode(proposal.block_hash),
            applied_mempool_ops: applied_ops,
            settled_batch_seq,
            settled_records,
            state_root_hex: hex::encode(root),
            fee_charged_raw: NODE_TRANSACTION_FEE.raw(),
            operator_reward_raw: NODE_BLOCK_REWARD.raw(),
            validator_reward_raw: VALIDATOR_REWARD,
            quorum_certificate: qc_json,
        })
    }

    /// Verifies cryptographic [`EquivocationEvidence`] and immediately ejects (`active = false`)
    /// the faulty validator, persisting the ejection to WAL and `snapshot.json`.
    pub fn apply_equivocation(&mut self, evidence: &EquivocationEvidence) -> NodeResult<String> {
        let ejected_id = self
            .validator_set
            .apply_equivocation(evidence, &self.config.chain_id)?;
        if !self.equivocations.contains(evidence) {
            self.equivocations.push(evidence.clone());
        }
        let mut persisted = self.export_persisted_state();
        self.store.append_wal("apply_equivocation", &mut persisted)?;
        self.store.write_atomic_snapshot(&persisted)?;
        Ok(ejected_id)
    }

    /// Interactive workbench helper (`gmc_demoStep`): registers sample `iFay` contributors
    /// and social edge on first invocation, records a deterministic `25 μ` contribution on L2,
    /// and (when `produce_block_now == true`) seals a zero-fee BFT block with a verified `QuorumCertificate`.
    pub fn demo_step(&mut self, produce_block_now: bool) -> NodeResult<Value> {
        let step_ts = Timestamp::from_secs(1_700_000_000 + (self.block_height + 1) * 60);
        let (_alice_sk, alice_vk) = keypair_from_seed(&[0xA1u8; 32]);
        let (_bob_sk, bob_vk) = keypair_from_seed(&[0xB1u8; 32]);

        let alice_id = self.register_ifay(&alice_vk, step_ts)?;
        let bob_id = self.register_ifay(&bob_vk, step_ts)?;
        let alice_fay = alice_id.to_fay_id();
        let bob_fay = bob_id.to_fay_id();
        if self.relationships.get_edge(&alice_fay, &bob_fay).is_none() {
            let _ = self.register_relationship(
                alice_fay.clone(),
                bob_fay.clone(),
                RelationshipType::Social,
                PrivacyTier::ExistencePublic,
                step_ts,
            );
            if let Some(depth) = Ratio::new(Decimal::from_raw(750_000)) {
                let _ = self.record_interaction(&alice_fay, &bob_fay, depth, step_ts);
                let _ = self.record_interaction(&bob_fay, &alice_fay, depth, step_ts);
            }
        }

        let contrib = self.submit_contribution(
            &alice_id,
            ChainId::new("gmc-base"),
            Decimal::from_int(25),
            Decimal::from_int(86_400),
            step_ts,
        )?;
        let block_receipt = if produce_block_now {
            Some(self.produce_block(step_ts)?)
        } else {
            None
        };
        let latest_qc = self
            .latest_qc()
            .map(|q| q.to_summary_json(self.validator_set.quorum_threshold()))
            .unwrap_or(Value::Null);

        Ok(json!({
            "demo_step": "ok",
            "contributor_id": alice_id.canonical(),
            "contribution": contrib,
            "block_receipt": block_receipt,
            "latest_qc": latest_qc,
            "status": self.status(),
        }))
    }

    /// Returns active/ejected validator roster and latest `QuorumCertificate` for `gmc_validators`.
    pub fn validators_summary(&self) -> Value {
        let quorum = self.validator_set.quorum_threshold();
        let validators: Vec<Value> = self
            .validator_set
            .validators()
            .iter()
            .map(|v| {
                json!({
                    "validator_id": v.validator_id,
                    "pubkey_hex": hex::encode(v.pubkey),
                    "active": v.active,
                })
            })
            .collect();
        let latest_qc = self
            .latest_qc()
            .map(|q| q.to_summary_json(quorum))
            .unwrap_or(Value::Null);
        json!({
            "chain_id": self.config.chain_id,
            "total_count": self.validator_set.total_count(),
            "active_count": self.validator_set.active_count(),
            "ejected_count": self.validator_set.ejected_count(),
            "quorum_threshold": quorum,
            "validator_reward": "0",
            "equivocations_count": self.equivocations.len(),
            "validators": validators,
            "latest_qc": latest_qc,
        })
    }

    /// Returns state transition audit log & snapshot export payload for `Meritora Desktop`.
    pub fn audit_log_summary(&self) -> Value {
        let persisted = self.export_persisted_state();
        let quorum = self.validator_set.quorum_threshold();
        let recent_qcs: Vec<Value> = self
            .committed_qcs
            .iter()
            .rev()
            .take(20)
            .map(|q| q.to_summary_json(quorum))
            .collect();
        json!({
            "chain_id": self.config.chain_id,
            "block_height": self.block_height,
            "wal_seq": self.store.last_wal_seq(),
            "state_root_hex": self.state_root_hex(),
            "l1_state_root_hex": persisted.l1_records.state_root_hex,
            "l1_anchor_log": persisted.l1_records.anchor_log,
            "settled_batches": persisted.l1_records.settled_batches,
            "recent_qcs": recent_qcs,
            "equivocations_count": self.equivocations.len(),
            "constitutional_invariants": {
                "node_transaction_fee": "0",
                "node_block_reward": "0",
                "validator_reward": "0",
                "initial_merit_baseline": "0",
            },
            "snapshot": persisted,
        })
    }

    /// Flushes an atomic `snapshot.json` before clean node shutdown so subsequent
    /// restarts recover in `O(1)` without needing to replay historical WAL frames.
    pub fn shutdown(&mut self) -> NodeResult<[u8; 32]> {
        let snap = self.export_persisted_state();
        self.store.write_atomic_snapshot(&snap)
    }

    // --- Internal helpers ---------------------------------------------------

    fn verify_and_commit_l2_batch(
        &mut self,
        batch: &Batch,
        commitment: [u8; 32],
        now: Timestamp,
    ) -> NodeResult<()> {
        {
            let mut sink = NodeL1ProofSink {
                l1: &mut self.l1,
                batch,
                claimed_commitment: commitment,
                verifier: &*self.batch_verifier,
            };
            L2Rollup::submit_batch_proof_to(batch, &mut sink)?;
        }
        self.record_committed_batch(batch, commitment, now);
        Ok(())
    }

    fn record_committed_batch(&mut self, batch: &Batch, commitment: [u8; 32], now: Timestamp) {
        let commitment_hex = hex::encode(commitment);
        let batch_root_hex = hex::encode(batch.batch_root.as_bytes());
        self.settled_batches.push(SettledBatchCommitment {
            seq: batch.seq,
            record_count: batch.len(),
            model_batch_root_hex: batch_root_hex.clone(),
            sha256_commitment_hex: commitment_hex.clone(),
            settled_at_secs: now.as_secs(),
        });
        self.sealed_batches.push(PersistedSealedBatch {
            seq: batch.seq,
            batch_root_hex,
            sha256_commitment_hex: commitment_hex,
            submitted_at_secs: batch.submitted_at.as_secs(),
            trigger: batch_trigger_to_str(batch.trigger).to_string(),
            records: batch.records.iter().map(encode_buffered_record).collect(),
        });
        self.l2.commit_previewed_batch(now);
    }

    fn export_persisted_state(&self) -> PersistedNodeState {
        let (identities, pockets) = PersistedIdentityState::from_state(&self.identities);
        PersistedNodeState {
            format_version: 1,
            chain_id: self.config.chain_id.clone(),
            wal_seq: self.store.last_wal_seq(),
            block_height: self.block_height,
            genesis_time_secs: self.config.genesis_time.as_secs(),
            applied_op_digests: self.applied_op_digests.iter().cloned().collect(),
            identities,
            pockets,
            relationships: encode_relationship_graph(&self.relationships),
            penalties: PersistedPenaltyState::from_engine(&self.penalties),
            l1_records: PersistedL1State::from_l1(&self.l1, &self.settled_batches),
            l2_batches: PersistedL2State::from_l2(&self.l2, &self.sealed_batches),
            consensus: PersistedConsensusState {
                validators: self.validator_set.validators().to_vec(),
                committed_qcs: self.committed_qcs.clone(),
                equivocations: self.equivocations.clone(),
            },
            testnet: self.testnet.clone(),
        }
    }

    fn persist_wal(&mut self, event_tag: &str) -> NodeResult<[u8; 32]> {
        let mut persisted = self.export_persisted_state();
        self.store.append_wal(event_tag, &mut persisted)
    }
}

/// Side-effect-free deterministic state transition sandbox used to preview and verify
/// multi-node BFT [`BlockProposal`] `state_root` claims before touching durable state.
struct ExecutionSandbox {
    chain_id: String,
    genesis_time_secs: u64,
    block_height: u64,
    applied_op_digests: BTreeSet<String>,
    identities: IdentityState,
    relationships: RelationshipGraph,
    penalties: PenaltyEngine,
    l1: L1Settlement,
    settled_batches: Vec<SettledBatchCommitment>,
    l2: L2Rollup,
    sealed_batches: Vec<PersistedSealedBatch>,
    testnet: crate::testnet::PersistedTestnetState,
}

impl ExecutionSandbox {
    fn execute_proposal(
        &mut self,
        transactions: &[BlockTransaction],
        block_time: Timestamp,
        verifier: &dyn BatchProofVerifier,
    ) -> NodeResult<(usize, Option<u64>, usize)> {
        let mut applied_ops = 0usize;
        for tx in transactions {
            match tx {
                BlockTransaction::RegisterIfay {
                    verifying_key_hex,
                    timestamp_secs,
                } => {
                    let vk_bytes = hex::decode(verifying_key_hex).map_err(|e| {
                        NodeError::ConsensusInvalid(format!("invalid RegisterIfay key hex: {e}"))
                    })?;
                    let vk = VerifyingKey::new(vk_bytes);
                    let now = Timestamp::from_secs(*timestamp_secs);
                    let existed = gmc_identity::identity_id::derive_identity_id(
                        &self.identities.registry,
                        &SchemeTag::ed25519(),
                        &vk,
                    )
                    .map(|id| self.identities.identities.contains(&id))?;
                    let id = self.identities.identities.create_ifay(
                        &self.identities.registry,
                        &mut self.identities.ownership,
                        &mut self.identities.binding,
                        &SchemeTag::ed25519(),
                        &vk,
                        now,
                    )?;
                    if !existed {
                        self.l1
                            .store_identity_registration(IdentityRegistrationRecord::new(
                                id.to_fay_id(),
                                now,
                            ));
                    }
                    applied_ops += 1;
                }
                BlockTransaction::SignedOperation {
                    operation,
                    timestamp_secs,
                } => {
                    let op = operation.clone().into_signed()?;
                    let digest = operation_digest_hex(&op);
                    if self.applied_op_digests.contains(&digest) {
                        return Err(NodeError::Identity(IdentityError::ReplayDetected));
                    }
                    let now = Timestamp::from_secs(*timestamp_secs);
                    let applied = self.identities.apply(&op, &Ed25519Verifier, now)?;
                    if let Applied::CoFayCreated(ref cofay_id) = applied {
                        self.l1
                            .store_identity_registration(IdentityRegistrationRecord::new(
                                cofay_id.to_fay_id(),
                                now,
                            ));
                    }
                    self.applied_op_digests.insert(digest);
                    applied_ops += 1;
                }
                BlockTransaction::RegisterRelationship {
                    a_fay_id,
                    b_fay_id,
                    relationship_type,
                    privacy_tier,
                    registered_at_secs,
                } => {
                    self.relationships.register_bilateral(
                        FayID::new(a_fay_id.clone()),
                        FayID::new(b_fay_id.clone()),
                        str_to_rel_type(relationship_type)?,
                        str_to_privacy(privacy_tier)?,
                        Timestamp::from_secs(*registered_at_secs),
                    )?;
                    applied_ops += 1;
                }
                BlockTransaction::RecordInteraction {
                    initiator_fay_id,
                    counterparty_fay_id,
                    depth_raw,
                    at_secs,
                } => {
                    let depth = Ratio::new(Decimal::from_raw(*depth_raw)).ok_or_else(|| {
                        NodeError::ConsensusInvalid("invalid interaction depth ratio".into())
                    })?;
                    self.relationships.record_interaction(
                        &FayID::new(initiator_fay_id.clone()),
                        &FayID::new(counterparty_fay_id.clone()),
                        depth,
                        Timestamp::from_secs(*at_secs),
                    )?;
                    applied_ops += 1;
                }
                BlockTransaction::SubmitContribution {
                    contributor_scheme_tag,
                    contributor_key_repr,
                    chain_id,
                    merit_amount_raw,
                    influence_duration_raw,
                    timestamp_secs,
                } => {
                    let contributor = IdentityId::new(
                        SchemeTag::new(contributor_scheme_tag.clone()),
                        contributor_key_repr.clone(),
                    );
                    let merit_amount = Decimal::from_raw(*merit_amount_raw);
                    let influence_duration = Decimal::from_raw(*influence_duration_raw);
                    let now = Timestamp::from_secs(*timestamp_secs);

                    if !merit_amount.is_positive() {
                        return Err(NodeError::Core(GmcError::InvalidMintAmount));
                    }
                    let lambda = MeritBatch::lambda_from_duration(influence_duration)
                        .ok_or(NodeError::Core(GmcError::InvalidMintAmount))?;
                    if !self.identities.identities.contains(&contributor) {
                        return Err(NodeError::Core(GmcError::NotRegistered));
                    }
                    let fay_id = contributor.to_fay_id();
                    let batch_id = format!("batch-{}", self.l2.next_record_seq());
                    {
                        let pocket = self
                            .identities
                            .binding
                            .pocket_by_key_mut(&fay_id)
                            .ok_or(NodeError::Core(GmcError::NotRegistered))?;
                        let floor_increment = if pocket.batches.is_empty() {
                            merit_amount.min(pocket.min_merit)
                        } else {
                            let m = pocket.cur_merit(now);
                            let old_floor = pocket.min_merit();
                            let new_floor = pocket.update_min_merit(merit_amount, m)?;
                            new_floor.checked_sub(old_floor).unwrap_or(Decimal::ZERO)
                        };
                        pocket.add_batch(MeritBatch::new(
                            batch_id,
                            merit_amount,
                            floor_increment,
                            lambda,
                            influence_duration,
                            now,
                            ChainId::new(chain_id.clone()),
                        ));
                    }
                    self.l2.process_contribution(
                        ContributionSubmission::new(
                            fay_id,
                            ChainId::new(chain_id.clone()),
                            merit_amount,
                        ),
                        now,
                    );
                    if let Some(batch) = self.l2.preview_batch(now, false) {
                        self.settle_batch(&batch, now, verifier)?;
                    }
                    applied_ops += 1;
                }
            }
        }

        let mut settled_batch_seq = None;
        let mut settled_records = 0usize;
        if let Some(batch) = self.l2.preview_batch(block_time, true) {
            self.settle_batch(&batch, block_time, verifier)?;
            settled_batch_seq = Some(batch.seq);
            settled_records = batch.len();
        }
        self.block_height += 1;
        Ok((applied_ops, settled_batch_seq, settled_records))
    }

    fn settle_batch(
        &mut self,
        batch: &Batch,
        now: Timestamp,
        verifier: &dyn BatchProofVerifier,
    ) -> NodeResult<()> {
        let commitment = compute_batch_commitment(batch);
        {
            let mut sink = NodeL1ProofSink {
                l1: &mut self.l1,
                batch,
                claimed_commitment: commitment,
                verifier,
            };
            L2Rollup::submit_batch_proof_to(batch, &mut sink)?;
        }
        let commitment_hex = hex::encode(commitment);
        let batch_root_hex = hex::encode(batch.batch_root.as_bytes());
        self.settled_batches.push(SettledBatchCommitment {
            seq: batch.seq,
            record_count: batch.len(),
            model_batch_root_hex: batch_root_hex.clone(),
            sha256_commitment_hex: commitment_hex.clone(),
            settled_at_secs: now.as_secs(),
        });
        self.sealed_batches.push(PersistedSealedBatch {
            seq: batch.seq,
            batch_root_hex,
            sha256_commitment_hex: commitment_hex,
            submitted_at_secs: batch.submitted_at.as_secs(),
            trigger: batch_trigger_to_str(batch.trigger).to_string(),
            records: batch.records.iter().map(encode_buffered_record).collect(),
        });
        self.l2.commit_previewed_batch(now);
        Ok(())
    }

    fn state_root(&self) -> [u8; 32] {
        let (identities, pockets) = PersistedIdentityState::from_state(&self.identities);
        let persisted = PersistedNodeState {
            format_version: 1,
            chain_id: self.chain_id.clone(),
            wal_seq: 0,
            block_height: self.block_height,
            genesis_time_secs: self.genesis_time_secs,
            applied_op_digests: self.applied_op_digests.iter().cloned().collect(),
            identities,
            pockets,
            relationships: encode_relationship_graph(&self.relationships),
            penalties: PersistedPenaltyState::from_engine(&self.penalties),
            l1_records: PersistedL1State::from_l1(&self.l1, &self.settled_batches),
            l2_batches: PersistedL2State::from_l2(&self.l2, &self.sealed_batches),
            consensus: PersistedConsensusState::default(),
            testnet: self.testnet.clone(),
        };
        compute_state_root(&persisted)
    }
}
