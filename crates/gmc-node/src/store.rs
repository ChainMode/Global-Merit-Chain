//! Crash-consistent disk persistence (`NodeStateStore`: append-only WAL + atomic
//! snapshot) and canonical deterministic SHA-256 `StateRoot` computation.
//!
//! `gmc-core` and `gmc-identity` intentionally carry zero serialization dependencies.
//! This module maps their ordered in-memory state into deterministic DTOs, persists
//! every state transition into a length-prefixed, SHA-256-checksummed Write-Ahead Log
//! (`wal.log`), writes atomic snapshots (`snapshot.json.tmp` -> `fsync` -> `rename`),
//! truncates incomplete trailing WAL frames left by power loss or crashes, and computes
//! the canonical SHA-256 `StateRoot` over `(Identities, Pockets, Relationships,
//! Penalties, L1Records, L2Batches)`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gmc_core::l1_settlement::{
    AnchorEntry, AnchorKind, ChainRegistrationRecord, IdentityRegistrationRecord, L1Settlement,
    PenaltyRecord, StateRoot, VoteResultRecord,
};
use gmc_core::l2_rollup::{BatchRoot, BatchTrigger, BufferedRecord, L2Rollup, RollupRecordId};
use gmc_core::merit::{MeritBatch, MeritPocket};
use gmc_core::penalty::{
    AppealSubmission, CaseStage, ComplainantStanding, Complaint, PenaltyCase, PenaltyEngine,
    PenaltyExecutionRecord, PenaltyPolicy, PenaltySeverity, PenaltySnapshot,
};
use gmc_core::registry::OriginType;
use gmc_core::relationship::{
    CanonicalPair, PrivacyTier, RelationshipEdge, RelationshipGraph, RelationshipType,
};
use gmc_core::types::{ChainId, Decimal, FayID, Ratio, Timestamp};
use gmc_identity::authority::{DelegateStatus, DelegateStore};
use gmc_identity::device::{DeviceCredential, DeviceId, DeviceRegistry, DeviceStatus};
use gmc_identity::identity_core::IdentityState;
use gmc_identity::identity_id::IdentityId;
use gmc_identity::identity_service::{Identity, IdentityService};
use gmc_identity::ownership::{OwnerKind, OwnerRef, OwnershipRegistry};
use gmc_identity::pocket::PocketBinding;
use gmc_identity::recovery::{GuardianConfig, RecoveryService, RecoverySession, RotationRecord};
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{DeviceType, IdentityKind, SchemeTag, VerifyingKey};

use crate::crypto::register_ed25519_scheme;
use crate::error::{NodeError, NodeResult};

/// 4-byte magic header prefixing every WAL frame (`"GMCW"`).
pub const WAL_FRAME_MAGIC: &[u8; 4] = b"GMCW";
/// Fixed header size of a WAL frame (`4` magic + `8` seq + `4` payload len + `32` sha256 = `48` bytes).
pub const WAL_HEADER_LEN: usize = 48;
/// Maximum WAL frame payload size (`64 MiB` defensive bound against corrupted length headers).
pub const MAX_WAL_FRAME_LEN: u32 = 64 * 1024 * 1024;
/// Canonical domain-separation tag for node SHA-256 `StateRoot` computation.
pub const STATE_ROOT_DOMAIN: &[u8] = b"gmc-node:canonical-state-root:v1";

const WAL_FILE_NAME: &str = "wal.log";
const SNAPSHOT_FILE_NAME: &str = "snapshot.json";
const SNAPSHOT_TMP_FILE_NAME: &str = "snapshot.json.tmp";

// ============================================================================
// Deterministic Persisted DTOs
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedNodeState {
    pub format_version: u32,
    pub chain_id: String,
    pub wal_seq: u64,
    pub block_height: u64,
    pub genesis_time_secs: u64,
    pub applied_op_digests: Vec<String>,
    pub identities: PersistedIdentityState,
    pub pockets: Vec<PersistedPocket>,
    pub relationships: Vec<PersistedRelationshipEdge>,
    pub penalties: PersistedPenaltyState,
    pub l1_records: PersistedL1State,
    pub l2_batches: PersistedL2State,
}

impl PersistedNodeState {
    pub fn empty(chain_id: impl Into<String>, genesis_time_secs: u64) -> Self {
        PersistedNodeState {
            format_version: 1,
            chain_id: chain_id.into(),
            wal_seq: 0,
            block_height: 0,
            genesis_time_secs,
            applied_op_digests: Vec::new(),
            identities: PersistedIdentityState::default(),
            pockets: Vec::new(),
            relationships: Vec::new(),
            penalties: PersistedPenaltyState::from_engine(&PenaltyEngine::default()),
            l1_records: PersistedL1State::from_l1(&L1Settlement::new(), &[]),
            l2_batches: PersistedL2State::from_l2(
                &L2Rollup::new(Timestamp::from_secs(genesis_time_secs)),
                &[],
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedIdentityState {
    pub records: Vec<PersistedIdentity>,
    pub owners: Vec<PersistedOwnerBinding>,
    pub delegates: Vec<PersistedDelegateEntry>,
    pub devices: Vec<PersistedDeviceCredential>,
    pub rotation_history: Vec<PersistedRotationHistory>,
    pub guardian_configs: Vec<PersistedGuardianConfig>,
    pub recovery_sessions: Vec<PersistedRecoverySession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedIdentity {
    pub scheme_tag: String,
    pub key_repr: String,
    pub kind: String,
    pub active_key_hex: String,
    pub retired_keys_hex: Vec<String>,
    pub applied_nonce: u64,
    pub created_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOwnerBinding {
    pub cofay_scheme_tag: String,
    pub cofay_key_repr: String,
    pub owner_id: String,
    pub owner_kind: String,
    pub owner_key_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedDelegateEntry {
    pub cofay_scheme_tag: String,
    pub cofay_key_repr: String,
    pub delegate_key_hex: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedDeviceCredential {
    pub device_id: String,
    pub identity_scheme_tag: String,
    pub identity_key_repr: String,
    pub device_key_hex: String,
    pub device_type: String,
    pub registered_at_secs: u64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRotationEntry {
    pub old_key_hex: String,
    pub new_key_hex: String,
    pub rotated_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRotationHistory {
    pub identity_scheme_tag: String,
    pub identity_key_repr: String,
    pub entries: Vec<PersistedRotationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedGuardianConfig {
    pub identity_scheme_tag: String,
    pub identity_key_repr: String,
    pub guardians_hex: Vec<String>,
    pub threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRecoverySession {
    pub identity_scheme_tag: String,
    pub identity_key_repr: String,
    pub new_key_hex: String,
    pub approvals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMeritBatch {
    pub batch_id: String,
    pub v_raw: i128,
    pub b_raw: i128,
    pub lambda_raw: i128,
    pub influence_duration_raw: i128,
    pub acquired_at_secs: u64,
    pub source_chain_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPocket {
    pub identity_scheme_tag: String,
    pub identity_key_repr: String,
    pub fay_id: String,
    pub min_merit_raw: i128,
    pub batches: Vec<PersistedMeritBatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRelationshipEdge {
    pub low_fay_id: String,
    pub high_fay_id: String,
    pub relationship_type: String,
    pub privacy_tier: String,
    pub registered_at_secs: u64,
    pub confirmed_by_low: bool,
    pub confirmed_by_high: bool,
    pub zk_score_commitment_hex: Option<String>,
    pub offchain_detail_anchor_hex: Option<String>,
    pub pending_from_low: u32,
    pub pending_depth_low_raw: i128,
    pub pending_from_high: u32,
    pub pending_depth_high_raw: i128,
    pub effective_interactions: u64,
    pub cumulative_depth_raw: i128,
    pub co_participation_count: u64,
    pub last_bilateral_interaction_at_secs: Option<u64>,
    pub window_started_at_secs: u64,
    pub window_bilateral_count: u32,
    pub burst_anomaly_detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPenaltyPolicy {
    pub min_complainant_merit_raw: i128,
    pub complaint_cooldown_secs: u64,
    pub max_dismissed_strikes: u32,
    pub admissibility_threshold_raw: i128,
    pub penalty_threshold_raw: i128,
    pub appeal_window_secs: u64,
    pub appeal_threshold_raw: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPenaltyExecution {
    pub complaint_id: String,
    pub respondent: String,
    pub batch_id: String,
    pub severity: String,
    pub executed_at_secs: u64,
    pub voter_count: usize,
    pub approve_merit_raw: i128,
    pub total_merit_raw: i128,
    pub cur_merit_before_raw: i128,
    pub cur_merit_after_raw: i128,
    pub min_merit_before_raw: i128,
    pub min_merit_after_raw: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPenaltyCase {
    pub complaint_id: String,
    pub complainant: String,
    pub respondent: String,
    pub batch_id: String,
    pub evidence_hash: String,
    pub severity: String,
    pub filed_at_secs: u64,
    pub stage: String,
    pub snapshot_min_merit_raw: Option<i128>,
    pub snapshot_batches: Option<Vec<PersistedMeritBatch>>,
    pub execution: Option<PersistedPenaltyExecution>,
    pub appeal_submitted_at_secs: Option<u64>,
    pub appeal_counter_evidence_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedComplainantStanding {
    pub complainant: String,
    pub last_filed_at_secs: Option<u64>,
    pub dismissed_strikes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPenaltyState {
    pub policy: PersistedPenaltyPolicy,
    pub cases: Vec<PersistedPenaltyCase>,
    pub complainants: Vec<PersistedComplainantStanding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettledBatchCommitment {
    pub seq: u64,
    pub record_count: usize,
    pub model_batch_root_hex: String,
    pub sha256_commitment_hex: String,
    pub settled_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedChainRegistration {
    pub chain_id: String,
    pub parent_id: Option<String>,
    pub domain: String,
    pub steward: String,
    pub origin: String,
    pub created_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedIdentityRegistration {
    pub fay_id: String,
    pub registered_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedVoteResult {
    pub vote_id: String,
    pub subject: String,
    pub passed: bool,
    pub anchored_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPenaltyAnchor {
    pub subject: String,
    pub reason: String,
    pub recorded_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedAnchorEntry {
    pub kind: String,
    pub chain_id: Option<String>,
    pub version: u64,
    pub resulting_root_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedL1State {
    pub state_root_hex: String,
    pub version: u64,
    pub chain_registrations: Vec<PersistedChainRegistration>,
    pub identity_registrations: Vec<PersistedIdentityRegistration>,
    pub vote_results: Vec<PersistedVoteResult>,
    pub penalties: Vec<PersistedPenaltyAnchor>,
    pub anchor_log: Vec<PersistedAnchorEntry>,
    pub settled_batches: Vec<SettledBatchCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBufferedRecord {
    pub record_id: String,
    pub contributor_id: String,
    pub chain_id: String,
    pub merit_amount_raw: i128,
    pub ingested_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSealedBatch {
    pub seq: u64,
    pub batch_root_hex: String,
    pub sha256_commitment_hex: String,
    pub submitted_at_secs: u64,
    pub trigger: String,
    pub records: Vec<PersistedBufferedRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedL2State {
    pub last_batch_at_secs: u64,
    pub next_batch_seq: u64,
    pub next_record_seq: u64,
    pub buffered_records: Vec<PersistedBufferedRecord>,
    pub sealed_batches: Vec<PersistedSealedBatch>,
}

// ============================================================================
// Conversion Implementations (Pure-Logic <-> Deterministic DTOs)
// ============================================================================

fn encode_batch(b: &MeritBatch) -> PersistedMeritBatch {
    PersistedMeritBatch {
        batch_id: b.batch_id.clone(),
        v_raw: b.v.raw(),
        b_raw: b.b.raw(),
        lambda_raw: b.lambda.raw(),
        influence_duration_raw: b.influence_duration.raw(),
        acquired_at_secs: b.acquired_at.as_secs(),
        source_chain_id: b.source_chain_id.as_str().to_string(),
    }
}

fn decode_batch(b: &PersistedMeritBatch) -> MeritBatch {
    MeritBatch::new(
        b.batch_id.clone(),
        Decimal::from_raw(b.v_raw),
        Decimal::from_raw(b.b_raw),
        Decimal::from_raw(b.lambda_raw),
        Decimal::from_raw(b.influence_duration_raw),
        Timestamp::from_secs(b.acquired_at_secs),
        ChainId::new(b.source_chain_id.clone()),
    )
}

fn device_type_to_str(dt: DeviceType) -> &'static str {
    match dt {
        DeviceType::Phone => "phone",
        DeviceType::Computer => "computer",
        DeviceType::Watch => "watch",
        DeviceType::Robot => "robot",
        DeviceType::CarHmi => "car_hmi",
        DeviceType::CloudSdk => "cloud_sdk",
    }
}

fn str_to_device_type(s: &str) -> NodeResult<DeviceType> {
    match s {
        "phone" => Ok(DeviceType::Phone),
        "computer" => Ok(DeviceType::Computer),
        "watch" => Ok(DeviceType::Watch),
        "robot" => Ok(DeviceType::Robot),
        "car_hmi" => Ok(DeviceType::CarHmi),
        "cloud_sdk" => Ok(DeviceType::CloudSdk),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown device_type: {other}"
        ))),
    }
}

fn rel_type_to_str(rt: RelationshipType) -> &'static str {
    match rt {
        RelationshipType::Kinship => "kinship",
        RelationshipType::Legal => "legal",
        RelationshipType::Social => "social",
        RelationshipType::Organizational => "organizational",
    }
}

fn str_to_rel_type(s: &str) -> NodeResult<RelationshipType> {
    match s {
        "kinship" => Ok(RelationshipType::Kinship),
        "legal" => Ok(RelationshipType::Legal),
        "social" => Ok(RelationshipType::Social),
        "organizational" => Ok(RelationshipType::Organizational),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown relationship_type: {other}"
        ))),
    }
}

fn privacy_to_str(pt: PrivacyTier) -> &'static str {
    match pt {
        PrivacyTier::ExistencePublic => "existence_public",
        PrivacyTier::ScoreZkCommitted => "score_zk_committed",
        PrivacyTier::DetailOffChainAnchored => "detail_offchain_anchored",
    }
}

fn str_to_privacy(s: &str) -> NodeResult<PrivacyTier> {
    match s {
        "existence_public" => Ok(PrivacyTier::ExistencePublic),
        "score_zk_committed" => Ok(PrivacyTier::ScoreZkCommitted),
        "detail_offchain_anchored" => Ok(PrivacyTier::DetailOffChainAnchored),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown privacy_tier: {other}"
        ))),
    }
}

fn severity_to_str(s: PenaltySeverity) -> &'static str {
    match s {
        PenaltySeverity::Minor => "minor",
        PenaltySeverity::Moderate => "moderate",
        PenaltySeverity::Severe => "severe",
        PenaltySeverity::Critical => "critical",
    }
}

fn str_to_severity(s: &str) -> NodeResult<PenaltySeverity> {
    match s {
        "minor" => Ok(PenaltySeverity::Minor),
        "moderate" => Ok(PenaltySeverity::Moderate),
        "severe" => Ok(PenaltySeverity::Severe),
        "critical" => Ok(PenaltySeverity::Critical),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown penalty severity: {other}"
        ))),
    }
}

fn stage_to_str(stage: CaseStage) -> &'static str {
    match stage {
        CaseStage::Filed => "filed",
        CaseStage::Dismissed => "dismissed",
        CaseStage::Admitted => "admitted",
        CaseStage::Executed => "executed",
        CaseStage::Appealed => "appealed",
        CaseStage::OverturnedOnAppeal => "overturned_on_appeal",
        CaseStage::AppealUpheld => "appeal_upheld",
    }
}

fn str_to_stage(s: &str) -> NodeResult<CaseStage> {
    match s {
        "filed" => Ok(CaseStage::Filed),
        "dismissed" => Ok(CaseStage::Dismissed),
        "admitted" => Ok(CaseStage::Admitted),
        "executed" => Ok(CaseStage::Executed),
        "appealed" => Ok(CaseStage::Appealed),
        "overturned_on_appeal" => Ok(CaseStage::OverturnedOnAppeal),
        "appeal_upheld" => Ok(CaseStage::AppealUpheld),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown case stage: {other}"
        ))),
    }
}

fn origin_to_str(origin: OriginType) -> &'static str {
    match origin {
        OriginType::VoteInitiated => "vote",
        OriginType::StewardInitiated => "steward",
        OriginType::InstitutionApplied => "institution",
    }
}

fn str_to_origin(s: &str) -> NodeResult<OriginType> {
    match s {
        "vote" => Ok(OriginType::VoteInitiated),
        "steward" => Ok(OriginType::StewardInitiated),
        "institution" => Ok(OriginType::InstitutionApplied),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown origin_type: {other}"
        ))),
    }
}

fn anchor_kind_to_str(kind: AnchorKind) -> &'static str {
    kind.tag()
}

fn str_to_anchor_kind(s: &str) -> NodeResult<AnchorKind> {
    match s {
        "chain-creation" => Ok(AnchorKind::ChainCreation),
        "mechanism-change" => Ok(AnchorKind::MechanismChange),
        "inflation-index-change" => Ok(AnchorKind::InflationIndexChange),
        "retroactive-outcome" => Ok(AnchorKind::RetroactiveOutcome),
        "identity-registration" => Ok(AnchorKind::IdentityRegistration),
        "penalty" => Ok(AnchorKind::Penalty),
        "derivation-state-root" => Ok(AnchorKind::DerivationStateRoot),
        "state-root-update" => Ok(AnchorKind::StateRootUpdate),
        "batch-proof-rejected" => Ok(AnchorKind::BatchProofRejected),
        other => Err(NodeError::SnapshotInvalid(format!(
            "unknown anchor_kind: {other}"
        ))),
    }
}

fn decode_hex_32(hex_str: &str) -> NodeResult<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| NodeError::SnapshotInvalid(format!("invalid 32-byte hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| NodeError::SnapshotInvalid("expected exact 32-byte digest".into()))
}

impl PersistedIdentityState {
    pub fn from_state(state: &IdentityState) -> (Self, Vec<PersistedPocket>) {
        let mut records = Vec::new();
        for (_, ident) in state.identities.iter() {
            records.push(PersistedIdentity {
                scheme_tag: ident.scheme_tag.as_str().to_string(),
                key_repr: ident.id.key_repr().to_string(),
                kind: match ident.kind {
                    IdentityKind::IFay => "ifay".to_string(),
                    IdentityKind::CoFay => "cofay".to_string(),
                },
                active_key_hex: hex::encode(ident.active_key.as_bytes()),
                retired_keys_hex: ident
                    .retired_keys
                    .iter()
                    .map(|k| hex::encode(k.as_bytes()))
                    .collect(),
                applied_nonce: ident.applied_nonce,
                created_at_secs: ident.created_at.as_secs(),
            });
        }

        let owner_keys: BTreeMap<IdentityId, String> = state
            .ownership
            .iter_owner_keys()
            .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
            .collect();
        let mut owners = Vec::new();
        for (cofay_id, owner_ref) in state.ownership.iter_owners() {
            owners.push(PersistedOwnerBinding {
                cofay_scheme_tag: cofay_id.scheme_tag().as_str().to_string(),
                cofay_key_repr: cofay_id.key_repr().to_string(),
                owner_id: owner_ref.id.clone(),
                owner_kind: owner_ref.kind.as_str().to_string(),
                owner_key_hex: owner_keys.get(cofay_id).cloned(),
            });
        }

        let mut delegates = Vec::new();
        for (cofay_id, set) in state.delegates.iter_sets() {
            for (_, rec) in set.records() {
                delegates.push(PersistedDelegateEntry {
                    cofay_scheme_tag: cofay_id.scheme_tag().as_str().to_string(),
                    cofay_key_repr: cofay_id.key_repr().to_string(),
                    delegate_key_hex: hex::encode(rec.key().as_bytes()),
                    active: rec.is_active(),
                });
            }
        }

        let mut devices = Vec::new();
        for (ident_id, cred) in state.devices.iter_all() {
            devices.push(PersistedDeviceCredential {
                device_id: cred.device_id().as_str().to_string(),
                identity_scheme_tag: ident_id.scheme_tag().as_str().to_string(),
                identity_key_repr: ident_id.key_repr().to_string(),
                device_key_hex: hex::encode(cred.device_key().as_bytes()),
                device_type: device_type_to_str(cred.device_type()).to_string(),
                registered_at_secs: cred.registered_at().as_secs(),
                active: cred.is_active(),
            });
        }

        let mut rotation_history = Vec::new();
        for (ident_id, hist) in state.recovery.iter_rotation_history() {
            rotation_history.push(PersistedRotationHistory {
                identity_scheme_tag: ident_id.scheme_tag().as_str().to_string(),
                identity_key_repr: ident_id.key_repr().to_string(),
                entries: hist
                    .iter()
                    .map(|r| PersistedRotationEntry {
                        old_key_hex: hex::encode(r.old_key.as_bytes()),
                        new_key_hex: hex::encode(r.new_key.as_bytes()),
                        rotated_at_secs: r.rotated_at.as_secs(),
                    })
                    .collect(),
            });
        }

        let mut guardian_configs = Vec::new();
        for (ident_id, cfg) in state.recovery.iter_guardian_configs() {
            guardian_configs.push(PersistedGuardianConfig {
                identity_scheme_tag: ident_id.scheme_tag().as_str().to_string(),
                identity_key_repr: ident_id.key_repr().to_string(),
                guardians_hex: cfg
                    .guardians
                    .iter()
                    .map(|k| hex::encode(k.as_bytes()))
                    .collect(),
                threshold: cfg.threshold,
            });
        }

        let mut recovery_sessions = Vec::new();
        for (_, session) in state.recovery.iter_sessions() {
            recovery_sessions.push(PersistedRecoverySession {
                identity_scheme_tag: session.ifay.scheme_tag().as_str().to_string(),
                identity_key_repr: session.ifay.key_repr().to_string(),
                new_key_hex: hex::encode(session.new_key.as_bytes()),
                approvals: session.approvals.iter().cloned().collect(),
            });
        }

        let mut pockets = Vec::new();
        for (ident_id, fay_id) in state.binding.iter_bindings() {
            if let Some(pocket) = state.binding.pocket_by_key(fay_id) {
                pockets.push(PersistedPocket {
                    identity_scheme_tag: ident_id.scheme_tag().as_str().to_string(),
                    identity_key_repr: ident_id.key_repr().to_string(),
                    fay_id: fay_id.as_str().to_string(),
                    min_merit_raw: pocket.min_merit.raw(),
                    batches: pocket.batches.iter().map(encode_batch).collect(),
                });
            }
        }

        (
            PersistedIdentityState {
                records,
                owners,
                delegates,
                devices,
                rotation_history,
                guardian_configs,
                recovery_sessions,
            },
            pockets,
        )
    }

    pub fn restore(&self, pockets: &[PersistedPocket]) -> NodeResult<IdentityState> {
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);

        let mut identities = IdentityService::new();
        for rec in &self.records {
            let scheme = SchemeTag::new(rec.scheme_tag.clone());
            let id = IdentityId::new(scheme.clone(), rec.key_repr.clone());
            let kind = match rec.kind.as_str() {
                "ifay" => IdentityKind::IFay,
                "cofay" => IdentityKind::CoFay,
                other => {
                    return Err(NodeError::SnapshotInvalid(format!(
                        "unknown identity kind: {other}"
                    )))
                }
            };
            let active_key = VerifyingKey::new(
                hex::decode(&rec.active_key_hex)
                    .map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
            );
            let mut retired_keys = Vec::with_capacity(rec.retired_keys_hex.len());
            for rk_hex in &rec.retired_keys_hex {
                retired_keys.push(VerifyingKey::new(
                    hex::decode(rk_hex).map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
                ));
            }
            identities.restore_identity(Identity {
                id,
                kind,
                scheme_tag: scheme,
                active_key,
                retired_keys,
                applied_nonce: rec.applied_nonce,
                created_at: Timestamp::from_secs(rec.created_at_secs),
            });
        }

        let mut ownership = OwnershipRegistry::new();
        for ow in &self.owners {
            let cofay_id = IdentityId::new(
                SchemeTag::new(ow.cofay_scheme_tag.clone()),
                ow.cofay_key_repr.clone(),
            );
            let owner_kind = OwnerKind::parse_label(&ow.owner_kind)
                .map_err(|e| NodeError::SnapshotInvalid(format!("{e:?}")))?;
            let owner_ref = OwnerRef::new(ow.owner_id.clone(), owner_kind);
            if let Some(ok_hex) = &ow.owner_key_hex {
                let ok = VerifyingKey::new(
                    hex::decode(ok_hex).map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
                );
                ownership
                    .set_owner_with_key(cofay_id, owner_ref, ok)
                    .map_err(|e| NodeError::SnapshotInvalid(format!("{e:?}")))?;
            } else {
                ownership
                    .set_owner(cofay_id, owner_ref)
                    .map_err(|e| NodeError::SnapshotInvalid(format!("{e:?}")))?;
            }
        }

        let mut delegates = DelegateStore::new();
        for del in &self.delegates {
            let cofay_id = IdentityId::new(
                SchemeTag::new(del.cofay_scheme_tag.clone()),
                del.cofay_key_repr.clone(),
            );
            let key = VerifyingKey::new(
                hex::decode(&del.delegate_key_hex)
                    .map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
            );
            let status = if del.active {
                DelegateStatus::Active
            } else {
                DelegateStatus::Revoked
            };
            delegates.restore_record(&cofay_id, key, status);
        }

        let mut devices = DeviceRegistry::new();
        for dev in &self.devices {
            let ident_id = IdentityId::new(
                SchemeTag::new(dev.identity_scheme_tag.clone()),
                dev.identity_key_repr.clone(),
            );
            let key = VerifyingKey::new(
                hex::decode(&dev.device_key_hex)
                    .map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
            );
            let dt = str_to_device_type(&dev.device_type)?;
            let status = if dev.active {
                DeviceStatus::Active
            } else {
                DeviceStatus::Revoked
            };
            devices.restore_credential(DeviceCredential::from_parts(
                DeviceId::from_string(dev.device_id.clone()),
                ident_id,
                key,
                dt,
                Timestamp::from_secs(dev.registered_at_secs),
                status,
            ));
        }

        let mut recovery = RecoveryService::new();
        for rh in &self.rotation_history {
            let ident_id = IdentityId::new(
                SchemeTag::new(rh.identity_scheme_tag.clone()),
                rh.identity_key_repr.clone(),
            );
            let mut entries = Vec::with_capacity(rh.entries.len());
            for e in &rh.entries {
                entries.push(RotationRecord {
                    old_key: VerifyingKey::new(
                        hex::decode(&e.old_key_hex)
                            .map_err(|err| NodeError::SnapshotInvalid(err.to_string()))?,
                    ),
                    new_key: VerifyingKey::new(
                        hex::decode(&e.new_key_hex)
                            .map_err(|err| NodeError::SnapshotInvalid(err.to_string()))?,
                    ),
                    rotated_at: Timestamp::from_secs(e.rotated_at_secs),
                });
            }
            recovery.restore_rotation_history(ident_id, entries);
        }
        for gc in &self.guardian_configs {
            let ident_id = IdentityId::new(
                SchemeTag::new(gc.identity_scheme_tag.clone()),
                gc.identity_key_repr.clone(),
            );
            let mut guardians = BTreeSet::new();
            for g_hex in &gc.guardians_hex {
                guardians.insert(VerifyingKey::new(
                    hex::decode(g_hex).map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
                ));
            }
            recovery.restore_guardian_config(GuardianConfig {
                ifay: ident_id,
                guardians,
                threshold: gc.threshold,
            });
        }
        for sess in &self.recovery_sessions {
            let ident_id = IdentityId::new(
                SchemeTag::new(sess.identity_scheme_tag.clone()),
                sess.identity_key_repr.clone(),
            );
            let new_key = VerifyingKey::new(
                hex::decode(&sess.new_key_hex)
                    .map_err(|e| NodeError::SnapshotInvalid(e.to_string()))?,
            );
            recovery.restore_session(RecoverySession {
                ifay: ident_id,
                new_key,
                approvals: sess.approvals.iter().cloned().collect(),
            });
        }

        let mut binding = PocketBinding::new();
        for p in pockets {
            let ident_id = IdentityId::new(
                SchemeTag::new(p.identity_scheme_tag.clone()),
                p.identity_key_repr.clone(),
            );
            let pocket = MeritPocket {
                fay_id: FayID::new(p.fay_id.clone()),
                min_merit: Decimal::from_raw(p.min_merit_raw),
                batches: p.batches.iter().map(decode_batch).collect(),
            };
            binding.restore_binding(ident_id, pocket);
        }

        Ok(IdentityState {
            registry,
            identities,
            ownership,
            delegates,
            binding,
            devices,
            recovery,
        })
    }
}

pub fn encode_relationship_graph(graph: &RelationshipGraph) -> Vec<PersistedRelationshipEdge> {
    graph
        .edges()
        .map(|(_, e)| PersistedRelationshipEdge {
            low_fay_id: e.pair.low().as_str().to_string(),
            high_fay_id: e.pair.high().as_str().to_string(),
            relationship_type: rel_type_to_str(e.relationship_type).to_string(),
            privacy_tier: privacy_to_str(e.privacy_tier).to_string(),
            registered_at_secs: e.registered_at.as_secs(),
            confirmed_by_low: e.confirmed_by_low,
            confirmed_by_high: e.confirmed_by_high,
            zk_score_commitment_hex: e.zk_score_commitment.map(hex::encode),
            offchain_detail_anchor_hex: e.offchain_detail_anchor.map(hex::encode),
            pending_from_low: e.pending_from_low,
            pending_depth_low_raw: e.pending_depth_low.raw(),
            pending_from_high: e.pending_from_high,
            pending_depth_high_raw: e.pending_depth_high.raw(),
            effective_interactions: e.effective_interactions,
            cumulative_depth_raw: e.cumulative_depth.raw(),
            co_participation_count: e.co_participation_count,
            last_bilateral_interaction_at_secs: e
                .last_bilateral_interaction_at
                .map(Timestamp::as_secs),
            window_started_at_secs: e.window_started_at.as_secs(),
            window_bilateral_count: e.window_bilateral_count,
            burst_anomaly_detected: e.burst_anomaly_detected,
        })
        .collect()
}

pub fn decode_relationship_graph(
    edges: &[PersistedRelationshipEdge],
) -> NodeResult<RelationshipGraph> {
    let mut graph = RelationshipGraph::new();
    for e in edges {
        let pair = CanonicalPair::new(
            FayID::new(e.low_fay_id.clone()),
            FayID::new(e.high_fay_id.clone()),
        )
        .map_err(|err| NodeError::SnapshotInvalid(format!("{err:?}")))?;
        let zk = match &e.zk_score_commitment_hex {
            Some(h) => Some(decode_hex_32(h)?),
            None => None,
        };
        let anchor = match &e.offchain_detail_anchor_hex {
            Some(h) => Some(decode_hex_32(h)?),
            None => None,
        };
        graph.upsert_edge(RelationshipEdge {
            pair,
            relationship_type: str_to_rel_type(&e.relationship_type)?,
            privacy_tier: str_to_privacy(&e.privacy_tier)?,
            registered_at: Timestamp::from_secs(e.registered_at_secs),
            confirmed_by_low: e.confirmed_by_low,
            confirmed_by_high: e.confirmed_by_high,
            zk_score_commitment: zk,
            offchain_detail_anchor: anchor,
            pending_from_low: e.pending_from_low,
            pending_depth_low: Decimal::from_raw(e.pending_depth_low_raw),
            pending_from_high: e.pending_from_high,
            pending_depth_high: Decimal::from_raw(e.pending_depth_high_raw),
            effective_interactions: e.effective_interactions,
            cumulative_depth: Decimal::from_raw(e.cumulative_depth_raw),
            co_participation_count: e.co_participation_count,
            last_bilateral_interaction_at: e
                .last_bilateral_interaction_at_secs
                .map(Timestamp::from_secs),
            window_started_at: Timestamp::from_secs(e.window_started_at_secs),
            window_bilateral_count: e.window_bilateral_count,
            burst_anomaly_detected: e.burst_anomaly_detected,
        });
    }
    Ok(graph)
}

impl PersistedPenaltyState {
    pub fn from_engine(engine: &PenaltyEngine) -> Self {
        let policy = PersistedPenaltyPolicy {
            min_complainant_merit_raw: engine.policy.min_complainant_merit.raw(),
            complaint_cooldown_secs: engine.policy.complaint_cooldown_secs,
            max_dismissed_strikes: engine.policy.max_dismissed_strikes,
            admissibility_threshold_raw: engine.policy.admissibility_threshold.value().raw(),
            penalty_threshold_raw: engine.policy.penalty_threshold.value().raw(),
            appeal_window_secs: engine.policy.appeal_window_secs,
            appeal_threshold_raw: engine.policy.appeal_threshold.value().raw(),
        };

        let cases = engine
            .cases()
            .map(|(_, c)| PersistedPenaltyCase {
                complaint_id: c.complaint.complaint_id.clone(),
                complainant: c.complaint.complainant.as_str().to_string(),
                respondent: c.complaint.respondent.as_str().to_string(),
                batch_id: c.complaint.batch_id.clone(),
                evidence_hash: c.complaint.evidence_hash.clone(),
                severity: severity_to_str(c.complaint.severity).to_string(),
                filed_at_secs: c.complaint.filed_at.as_secs(),
                stage: stage_to_str(c.stage).to_string(),
                snapshot_min_merit_raw: c.snapshot.as_ref().map(|s| s.pre_min_merit.raw()),
                snapshot_batches: c
                    .snapshot
                    .as_ref()
                    .map(|s| s.pre_batches.iter().map(encode_batch).collect()),
                execution: c.execution.as_ref().map(|ex| PersistedPenaltyExecution {
                    complaint_id: ex.complaint_id.clone(),
                    respondent: ex.respondent.as_str().to_string(),
                    batch_id: ex.batch_id.clone(),
                    severity: severity_to_str(ex.severity).to_string(),
                    executed_at_secs: ex.executed_at.as_secs(),
                    voter_count: ex.voter_count,
                    approve_merit_raw: ex.approve_merit.raw(),
                    total_merit_raw: ex.total_merit.raw(),
                    cur_merit_before_raw: ex.cur_merit_before.raw(),
                    cur_merit_after_raw: ex.cur_merit_after.raw(),
                    min_merit_before_raw: ex.min_merit_before.raw(),
                    min_merit_after_raw: ex.min_merit_after.raw(),
                }),
                appeal_submitted_at_secs: c.appeal.as_ref().map(|a| a.submitted_at.as_secs()),
                appeal_counter_evidence_hash: c
                    .appeal
                    .as_ref()
                    .map(|a| a.counter_evidence_hash.clone()),
            })
            .collect();

        let complainants = engine
            .complainant_standings()
            .map(|(fay_id, st)| PersistedComplainantStanding {
                complainant: fay_id.as_str().to_string(),
                last_filed_at_secs: st.last_filed_at.map(Timestamp::as_secs),
                dismissed_strikes: st.dismissed_strikes,
            })
            .collect();

        PersistedPenaltyState {
            policy,
            cases,
            complainants,
        }
    }

    pub fn restore(&self) -> NodeResult<PenaltyEngine> {
        let ratio_from_raw = |raw: i128| -> NodeResult<Ratio> {
            Ratio::new(Decimal::from_raw(raw))
                .ok_or_else(|| NodeError::SnapshotInvalid(format!("invalid ratio raw {raw}")))
        };
        let policy = PenaltyPolicy {
            min_complainant_merit: Decimal::from_raw(self.policy.min_complainant_merit_raw),
            complaint_cooldown_secs: self.policy.complaint_cooldown_secs,
            max_dismissed_strikes: self.policy.max_dismissed_strikes,
            admissibility_threshold: ratio_from_raw(self.policy.admissibility_threshold_raw)?,
            penalty_threshold: ratio_from_raw(self.policy.penalty_threshold_raw)?,
            appeal_window_secs: self.policy.appeal_window_secs,
            appeal_threshold: ratio_from_raw(self.policy.appeal_threshold_raw)?,
        };
        let mut engine = PenaltyEngine::new(policy);

        for c in &self.cases {
            let snapshot = match (c.snapshot_min_merit_raw, &c.snapshot_batches) {
                (Some(min_raw), Some(batches)) => Some(PenaltySnapshot {
                    pre_min_merit: Decimal::from_raw(min_raw),
                    pre_batches: batches.iter().map(decode_batch).collect(),
                }),
                _ => None,
            };
            let execution = match &c.execution {
                Some(ex) => Some(PenaltyExecutionRecord {
                    complaint_id: ex.complaint_id.clone(),
                    respondent: FayID::new(ex.respondent.clone()),
                    batch_id: ex.batch_id.clone(),
                    severity: str_to_severity(&ex.severity)?,
                    executed_at: Timestamp::from_secs(ex.executed_at_secs),
                    voter_count: ex.voter_count,
                    approve_merit: Decimal::from_raw(ex.approve_merit_raw),
                    total_merit: Decimal::from_raw(ex.total_merit_raw),
                    cur_merit_before: Decimal::from_raw(ex.cur_merit_before_raw),
                    cur_merit_after: Decimal::from_raw(ex.cur_merit_after_raw),
                    min_merit_before: Decimal::from_raw(ex.min_merit_before_raw),
                    min_merit_after: Decimal::from_raw(ex.min_merit_after_raw),
                }),
                None => None,
            };
            let appeal = match (
                c.appeal_submitted_at_secs,
                &c.appeal_counter_evidence_hash,
            ) {
                (Some(ts), Some(hash)) => Some(AppealSubmission {
                    submitted_at: Timestamp::from_secs(ts),
                    counter_evidence_hash: hash.clone(),
                }),
                _ => None,
            };
            engine.restore_case(PenaltyCase {
                complaint: Complaint {
                    complaint_id: c.complaint_id.clone(),
                    complainant: FayID::new(c.complainant.clone()),
                    respondent: FayID::new(c.respondent.clone()),
                    batch_id: c.batch_id.clone(),
                    evidence_hash: c.evidence_hash.clone(),
                    severity: str_to_severity(&c.severity)?,
                    filed_at: Timestamp::from_secs(c.filed_at_secs),
                },
                stage: str_to_stage(&c.stage)?,
                snapshot,
                execution,
                appeal,
            });
        }

        for st in &self.complainants {
            engine.restore_complainant_standing(
                FayID::new(st.complainant.clone()),
                ComplainantStanding {
                    last_filed_at: st.last_filed_at_secs.map(Timestamp::from_secs),
                    dismissed_strikes: st.dismissed_strikes,
                },
            );
        }

        Ok(engine)
    }
}

impl PersistedL1State {
    pub fn from_l1(l1: &L1Settlement, settled_batches: &[SettledBatchCommitment]) -> Self {
        PersistedL1State {
            state_root_hex: hex::encode(l1.state_root().as_bytes()),
            version: l1.version(),
            chain_registrations: l1
                .chain_registrations()
                .map(|(_, r)| PersistedChainRegistration {
                    chain_id: r.chain_id.as_str().to_string(),
                    parent_id: r.parent_id.as_ref().map(|p| p.as_str().to_string()),
                    domain: r.domain.clone(),
                    steward: r.steward.as_str().to_string(),
                    origin: origin_to_str(r.origin).to_string(),
                    created_at_secs: r.created_at.as_secs(),
                })
                .collect(),
            identity_registrations: l1
                .identity_registrations()
                .map(|(_, r)| PersistedIdentityRegistration {
                    fay_id: r.fay_id.as_str().to_string(),
                    registered_at_secs: r.registered_at.as_secs(),
                })
                .collect(),
            vote_results: l1
                .vote_results()
                .map(|(_, v)| PersistedVoteResult {
                    vote_id: v.vote_id.clone(),
                    subject: v.subject.clone(),
                    passed: v.passed,
                    anchored_at_secs: v.anchored_at.as_secs(),
                })
                .collect(),
            penalties: l1
                .penalties()
                .iter()
                .map(|p| PersistedPenaltyAnchor {
                    subject: p.subject.as_str().to_string(),
                    reason: p.reason.clone(),
                    recorded_at_secs: p.recorded_at.as_secs(),
                })
                .collect(),
            anchor_log: l1
                .anchor_log()
                .iter()
                .map(|a| PersistedAnchorEntry {
                    kind: anchor_kind_to_str(a.kind).to_string(),
                    chain_id: a.chain_id.as_ref().map(|c| c.as_str().to_string()),
                    version: a.version,
                    resulting_root_hex: hex::encode(a.resulting_root.as_bytes()),
                })
                .collect(),
            settled_batches: settled_batches.to_vec(),
        }
    }

    pub fn restore(&self) -> NodeResult<(L1Settlement, Vec<SettledBatchCommitment>)> {
        let mut chain_regs = BTreeMap::new();
        for r in &self.chain_registrations {
            let cid = ChainId::new(r.chain_id.clone());
            chain_regs.insert(
                cid.clone(),
                ChainRegistrationRecord::new(
                    cid,
                    r.parent_id.as_ref().map(|s| ChainId::new(s.clone())),
                    r.domain.clone(),
                    FayID::new(r.steward.clone()),
                    str_to_origin(&r.origin)?,
                    Timestamp::from_secs(r.created_at_secs),
                ),
            );
        }

        let mut ident_regs = BTreeMap::new();
        for r in &self.identity_registrations {
            let fid = FayID::new(r.fay_id.clone());
            ident_regs.insert(
                fid.clone(),
                IdentityRegistrationRecord::new(fid, Timestamp::from_secs(r.registered_at_secs)),
            );
        }

        let mut vote_results = BTreeMap::new();
        for v in &self.vote_results {
            vote_results.insert(
                v.vote_id.clone(),
                VoteResultRecord::new(
                    v.vote_id.clone(),
                    v.subject.clone(),
                    v.passed,
                    Timestamp::from_secs(v.anchored_at_secs),
                ),
            );
        }

        let penalties = self
            .penalties
            .iter()
            .map(|p| {
                PenaltyRecord::new(
                    FayID::new(p.subject.clone()),
                    p.reason.clone(),
                    Timestamp::from_secs(p.recorded_at_secs),
                )
            })
            .collect();

        let mut anchor_log = Vec::with_capacity(self.anchor_log.len());
        for a in &self.anchor_log {
            anchor_log.push(AnchorEntry {
                kind: str_to_anchor_kind(&a.kind)?,
                chain_id: a.chain_id.as_ref().map(|s| ChainId::new(s.clone())),
                version: a.version,
                resulting_root: StateRoot::from_bytes(decode_hex_32(&a.resulting_root_hex)?),
            });
        }

        let state_root = StateRoot::from_bytes(decode_hex_32(&self.state_root_hex)?);
        Ok((
            L1Settlement::from_persisted_parts(
                chain_regs,
                ident_regs,
                vote_results,
                penalties,
                anchor_log,
                state_root,
                self.version,
            ),
            self.settled_batches.clone(),
        ))
    }
}

pub fn encode_buffered_record(r: &BufferedRecord) -> PersistedBufferedRecord {
    PersistedBufferedRecord {
        record_id: r.record_id.as_str().to_string(),
        contributor_id: r.contributor_id.as_str().to_string(),
        chain_id: r.chain_id.as_str().to_string(),
        merit_amount_raw: r.merit_amount.raw(),
        ingested_at_secs: r.ingested_at.as_secs(),
    }
}

pub fn decode_buffered_record(r: &PersistedBufferedRecord) -> BufferedRecord {
    BufferedRecord::new(
        RollupRecordId::new(r.record_id.clone()),
        FayID::new(r.contributor_id.clone()),
        ChainId::new(r.chain_id.clone()),
        Decimal::from_raw(r.merit_amount_raw),
        Timestamp::from_secs(r.ingested_at_secs),
    )
}

pub fn batch_trigger_to_str(t: BatchTrigger) -> &'static str {
    match t {
        BatchTrigger::RecordThreshold => "record_threshold",
        BatchTrigger::IntervalElapsed => "interval_elapsed",
    }
}

impl PersistedL2State {
    pub fn from_l2(l2: &L2Rollup, sealed_batches: &[PersistedSealedBatch]) -> Self {
        PersistedL2State {
            last_batch_at_secs: l2.last_batch_at().as_secs(),
            next_batch_seq: l2.next_batch_seq(),
            next_record_seq: l2.next_record_seq(),
            buffered_records: l2.buffered().map(encode_buffered_record).collect(),
            sealed_batches: sealed_batches.to_vec(),
        }
    }

    pub fn restore(&self) -> (L2Rollup, Vec<PersistedSealedBatch>) {
        let buffer: VecDeque<BufferedRecord> = self
            .buffered_records
            .iter()
            .map(decode_buffered_record)
            .collect();
        (
            L2Rollup::from_persisted_parts(
                buffer,
                Timestamp::from_secs(self.last_batch_at_secs),
                self.next_batch_seq,
                self.next_record_seq,
            ),
            self.sealed_batches.clone(),
        )
    }

    pub fn decode_batch_root(hex_str: &str) -> NodeResult<BatchRoot> {
        Ok(BatchRoot::from_bytes(decode_hex_32(hex_str)?))
    }
}

// ============================================================================
// Canonical Deterministic SHA-256 StateRoot
// ============================================================================

fn hash_bytes(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn hash_str(h: &mut Sha256, s: &str) {
    hash_bytes(h, s.as_bytes());
}

fn hash_opt_str(h: &mut Sha256, opt: &Option<String>) {
    match opt {
        Some(s) => {
            h.update([1u8]);
            hash_str(h, s);
        }
        None => h.update([0u8]),
    }
}

fn hash_u64(h: &mut Sha256, v: u64) {
    h.update(v.to_be_bytes());
}

fn hash_u32(h: &mut Sha256, v: u32) {
    h.update(v.to_be_bytes());
}

fn hash_i128(h: &mut Sha256, v: i128) {
    h.update(v.to_be_bytes());
}

fn hash_bool(h: &mut Sha256, b: bool) {
    h.update([u8::from(b)]);
}

fn hash_merit_batch(h: &mut Sha256, b: &PersistedMeritBatch) {
    hash_str(h, &b.batch_id);
    hash_i128(h, b.v_raw);
    hash_i128(h, b.b_raw);
    hash_i128(h, b.lambda_raw);
    hash_i128(h, b.influence_duration_raw);
    hash_u64(h, b.acquired_at_secs);
    hash_str(h, &b.source_chain_id);
}

/// Computes the canonical 32-byte SHA-256 `StateRoot` over the semantic protocol state:
/// `(Identities, Pockets, Relationships, Penalties, L1Records, L2Batches)`.
///
/// Node-local persistence bookkeeping (`wal_seq`) is deliberately excluded so two
/// honest nodes executing the identical ordered state transitions reach the exact
/// byte-for-byte identical `StateRoot` regardless of snapshot frequency or restarts.
pub fn compute_state_root(state: &PersistedNodeState) -> [u8; 32] {
    let mut h = Sha256::new();
    hash_bytes(&mut h, STATE_ROOT_DOMAIN);
    hash_str(&mut h, &state.chain_id);
    hash_u64(&mut h, state.block_height);

    // 1. Identities
    hash_bytes(&mut h, b"section:identities");
    hash_u64(&mut h, state.identities.records.len() as u64);
    for r in &state.identities.records {
        hash_str(&mut h, &r.scheme_tag);
        hash_str(&mut h, &r.key_repr);
        hash_str(&mut h, &r.kind);
        hash_str(&mut h, &r.active_key_hex);
        hash_u64(&mut h, r.retired_keys_hex.len() as u64);
        for rk in &r.retired_keys_hex {
            hash_str(&mut h, rk);
        }
        hash_u64(&mut h, r.applied_nonce);
        hash_u64(&mut h, r.created_at_secs);
    }
    hash_u64(&mut h, state.identities.owners.len() as u64);
    for ow in &state.identities.owners {
        hash_str(&mut h, &ow.cofay_scheme_tag);
        hash_str(&mut h, &ow.cofay_key_repr);
        hash_str(&mut h, &ow.owner_id);
        hash_str(&mut h, &ow.owner_kind);
        hash_opt_str(&mut h, &ow.owner_key_hex);
    }
    hash_u64(&mut h, state.identities.delegates.len() as u64);
    for del in &state.identities.delegates {
        hash_str(&mut h, &del.cofay_scheme_tag);
        hash_str(&mut h, &del.cofay_key_repr);
        hash_str(&mut h, &del.delegate_key_hex);
        hash_bool(&mut h, del.active);
    }
    hash_u64(&mut h, state.identities.devices.len() as u64);
    for dev in &state.identities.devices {
        hash_str(&mut h, &dev.device_id);
        hash_str(&mut h, &dev.identity_scheme_tag);
        hash_str(&mut h, &dev.identity_key_repr);
        hash_str(&mut h, &dev.device_key_hex);
        hash_str(&mut h, &dev.device_type);
        hash_u64(&mut h, dev.registered_at_secs);
        hash_bool(&mut h, dev.active);
    }
    hash_u64(&mut h, state.identities.rotation_history.len() as u64);
    for rh in &state.identities.rotation_history {
        hash_str(&mut h, &rh.identity_scheme_tag);
        hash_str(&mut h, &rh.identity_key_repr);
        hash_u64(&mut h, rh.entries.len() as u64);
        for e in &rh.entries {
            hash_str(&mut h, &e.old_key_hex);
            hash_str(&mut h, &e.new_key_hex);
            hash_u64(&mut h, e.rotated_at_secs);
        }
    }
    hash_u64(&mut h, state.identities.guardian_configs.len() as u64);
    for gc in &state.identities.guardian_configs {
        hash_str(&mut h, &gc.identity_scheme_tag);
        hash_str(&mut h, &gc.identity_key_repr);
        hash_u64(&mut h, gc.guardians_hex.len() as u64);
        for g in &gc.guardians_hex {
            hash_str(&mut h, g);
        }
        hash_u32(&mut h, gc.threshold);
    }
    hash_u64(&mut h, state.identities.recovery_sessions.len() as u64);
    for rs in &state.identities.recovery_sessions {
        hash_str(&mut h, &rs.identity_scheme_tag);
        hash_str(&mut h, &rs.identity_key_repr);
        hash_str(&mut h, &rs.new_key_hex);
        hash_u64(&mut h, rs.approvals.len() as u64);
        for a in &rs.approvals {
            hash_str(&mut h, a);
        }
    }

    // 2. Pockets
    hash_bytes(&mut h, b"section:pockets");
    hash_u64(&mut h, state.pockets.len() as u64);
    for p in &state.pockets {
        hash_str(&mut h, &p.fay_id);
        hash_i128(&mut h, p.min_merit_raw);
        hash_u64(&mut h, p.batches.len() as u64);
        for b in &p.batches {
            hash_merit_batch(&mut h, b);
        }
    }

    // 3. Relationships
    hash_bytes(&mut h, b"section:relationships");
    hash_u64(&mut h, state.relationships.len() as u64);
    for rel in &state.relationships {
        hash_str(&mut h, &rel.low_fay_id);
        hash_str(&mut h, &rel.high_fay_id);
        hash_str(&mut h, &rel.relationship_type);
        hash_str(&mut h, &rel.privacy_tier);
        hash_u64(&mut h, rel.registered_at_secs);
        hash_bool(&mut h, rel.confirmed_by_low);
        hash_bool(&mut h, rel.confirmed_by_high);
        hash_opt_str(&mut h, &rel.zk_score_commitment_hex);
        hash_opt_str(&mut h, &rel.offchain_detail_anchor_hex);
        hash_u32(&mut h, rel.pending_from_low);
        hash_i128(&mut h, rel.pending_depth_low_raw);
        hash_u32(&mut h, rel.pending_from_high);
        hash_i128(&mut h, rel.pending_depth_high_raw);
        hash_u64(&mut h, rel.effective_interactions);
        hash_i128(&mut h, rel.cumulative_depth_raw);
        hash_u64(&mut h, rel.co_participation_count);
        match rel.last_bilateral_interaction_at_secs {
            Some(ts) => {
                h.update([1u8]);
                hash_u64(&mut h, ts);
            }
            None => h.update([0u8]),
        }
        hash_u64(&mut h, rel.window_started_at_secs);
        hash_u32(&mut h, rel.window_bilateral_count);
        hash_bool(&mut h, rel.burst_anomaly_detected);
    }

    // 4. Penalties
    hash_bytes(&mut h, b"section:penalties");
    hash_i128(&mut h, state.penalties.policy.min_complainant_merit_raw);
    hash_u64(&mut h, state.penalties.policy.complaint_cooldown_secs);
    hash_u32(&mut h, state.penalties.policy.max_dismissed_strikes);
    hash_i128(&mut h, state.penalties.policy.admissibility_threshold_raw);
    hash_i128(&mut h, state.penalties.policy.penalty_threshold_raw);
    hash_u64(&mut h, state.penalties.policy.appeal_window_secs);
    hash_i128(&mut h, state.penalties.policy.appeal_threshold_raw);
    hash_u64(&mut h, state.penalties.cases.len() as u64);
    for c in &state.penalties.cases {
        hash_str(&mut h, &c.complaint_id);
        hash_str(&mut h, &c.complainant);
        hash_str(&mut h, &c.respondent);
        hash_str(&mut h, &c.batch_id);
        hash_str(&mut h, &c.evidence_hash);
        hash_str(&mut h, &c.severity);
        hash_u64(&mut h, c.filed_at_secs);
        hash_str(&mut h, &c.stage);
        if let Some(ex) = &c.execution {
            h.update([1u8]);
            hash_u64(&mut h, ex.executed_at_secs);
            hash_i128(&mut h, ex.approve_merit_raw);
            hash_i128(&mut h, ex.total_merit_raw);
            hash_i128(&mut h, ex.cur_merit_after_raw);
            hash_i128(&mut h, ex.min_merit_after_raw);
        } else {
            h.update([0u8]);
        }
        hash_opt_str(&mut h, &c.appeal_counter_evidence_hash);
    }
    hash_u64(&mut h, state.penalties.complainants.len() as u64);
    for st in &state.penalties.complainants {
        hash_str(&mut h, &st.complainant);
        match st.last_filed_at_secs {
            Some(ts) => {
                h.update([1u8]);
                hash_u64(&mut h, ts);
            }
            None => h.update([0u8]),
        }
        hash_u32(&mut h, st.dismissed_strikes);
    }

    // 5. L1 Records
    hash_bytes(&mut h, b"section:l1_records");
    hash_str(&mut h, &state.l1_records.state_root_hex);
    hash_u64(&mut h, state.l1_records.version);
    hash_u64(&mut h, state.l1_records.chain_registrations.len() as u64);
    for r in &state.l1_records.chain_registrations {
        hash_str(&mut h, &r.chain_id);
        hash_opt_str(&mut h, &r.parent_id);
        hash_str(&mut h, &r.domain);
        hash_str(&mut h, &r.steward);
        hash_str(&mut h, &r.origin);
        hash_u64(&mut h, r.created_at_secs);
    }
    hash_u64(&mut h, state.l1_records.identity_registrations.len() as u64);
    for r in &state.l1_records.identity_registrations {
        hash_str(&mut h, &r.fay_id);
        hash_u64(&mut h, r.registered_at_secs);
    }
    hash_u64(&mut h, state.l1_records.vote_results.len() as u64);
    for v in &state.l1_records.vote_results {
        hash_str(&mut h, &v.vote_id);
        hash_str(&mut h, &v.subject);
        hash_bool(&mut h, v.passed);
        hash_u64(&mut h, v.anchored_at_secs);
    }
    hash_u64(&mut h, state.l1_records.penalties.len() as u64);
    for p in &state.l1_records.penalties {
        hash_str(&mut h, &p.subject);
        hash_str(&mut h, &p.reason);
        hash_u64(&mut h, p.recorded_at_secs);
    }
    hash_u64(&mut h, state.l1_records.settled_batches.len() as u64);
    for sb in &state.l1_records.settled_batches {
        hash_u64(&mut h, sb.seq);
        hash_u64(&mut h, sb.record_count as u64);
        hash_str(&mut h, &sb.model_batch_root_hex);
        hash_str(&mut h, &sb.sha256_commitment_hex);
        hash_u64(&mut h, sb.settled_at_secs);
    }

    // 6. L2 Batches
    hash_bytes(&mut h, b"section:l2_batches");
    hash_u64(&mut h, state.l2_batches.last_batch_at_secs);
    hash_u64(&mut h, state.l2_batches.next_batch_seq);
    hash_u64(&mut h, state.l2_batches.next_record_seq);
    hash_u64(&mut h, state.l2_batches.buffered_records.len() as u64);
    for br in &state.l2_batches.buffered_records {
        hash_str(&mut h, &br.record_id);
        hash_str(&mut h, &br.contributor_id);
        hash_str(&mut h, &br.chain_id);
        hash_i128(&mut h, br.merit_amount_raw);
        hash_u64(&mut h, br.ingested_at_secs);
    }
    hash_u64(&mut h, state.l2_batches.sealed_batches.len() as u64);
    for sb in &state.l2_batches.sealed_batches {
        hash_u64(&mut h, sb.seq);
        hash_str(&mut h, &sb.batch_root_hex);
        hash_str(&mut h, &sb.sha256_commitment_hex);
        hash_u64(&mut h, sb.submitted_at_secs);
        hash_str(&mut h, &sb.trigger);
    }

    h.finalize().into()
}

// ============================================================================
// Write-Ahead Log (`wal.log`) + Atomic Snapshot (`snapshot.json`) Store
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalPayload {
    seq: u64,
    event_tag: String,
    state_root_hex: String,
    post_state: PersistedNodeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotEnvelope {
    sha256_hex: String,
    state_root_hex: String,
    state: PersistedNodeState,
}

/// Crash-consistent persistence engine managing `<data_dir>/wal.log` and
/// `<data_dir>/snapshot.json`.
pub struct NodeStateStore {
    data_dir: PathBuf,
    wal_file: File,
    last_wal_seq: u64,
}

impl NodeStateStore {
    pub fn wal_path(data_dir: &Path) -> PathBuf {
        data_dir.join(WAL_FILE_NAME)
    }

    pub fn snapshot_path(data_dir: &Path) -> PathBuf {
        data_dir.join(SNAPSHOT_FILE_NAME)
    }

    /// Opens `<data_dir>`, recovers from `snapshot.json` + `wal.log`, discards any
    /// incomplete trailing WAL frame left by a mid-write crash, and returns
    /// `(Self, PersistedNodeState)`.
    pub fn open_and_recover(
        data_dir: &Path,
        default_chain_id: &str,
        genesis_time_secs: u64,
    ) -> NodeResult<(Self, PersistedNodeState)> {
        fs::create_dir_all(data_dir)?;

        // Clean up any leftover temp snapshot from a crash mid-snapshot-write.
        let tmp_path = data_dir.join(SNAPSHOT_TMP_FILE_NAME);
        if tmp_path.exists() {
            let _ = fs::remove_file(&tmp_path);
        }

        // 1. Load atomic snapshot if present.
        let snapshot_path = Self::snapshot_path(data_dir);
        let mut recovered = if snapshot_path.exists() {
            let raw = fs::read(&snapshot_path)?;
            let env: SnapshotEnvelope = serde_json::from_slice(&raw)
                .map_err(|e| NodeError::SnapshotInvalid(format!("json parse failed: {e}")))?;
            let state_json = serde_json::to_vec(&env.state)
                .map_err(|e| NodeError::SnapshotInvalid(format!("re-encode failed: {e}")))?;
            let digest = hex::encode(Sha256::digest(&state_json));
            if digest != env.sha256_hex {
                return Err(NodeError::SnapshotInvalid(
                    "snapshot sha256 checksum mismatch".into(),
                ));
            }
            let computed_root = hex::encode(compute_state_root(&env.state));
            if computed_root != env.state_root_hex {
                return Err(NodeError::SnapshotInvalid(
                    "snapshot state_root mismatch".into(),
                ));
            }
            env.state
        } else {
            PersistedNodeState::empty(default_chain_id, genesis_time_secs)
        };

        // 2. Scan and replay `wal.log`, truncating any partial trailing frame.
        let wal_path = Self::wal_path(data_dir);
        let mut wal_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&wal_path)?;

        let file_len = wal_file.metadata()?.len();
        let mut offset: u64 = 0;
        let mut expected_seq: u64 = 1;
        let mut last_valid_offset: u64 = 0;
        let mut last_seq_seen: u64 = recovered.wal_seq;

        wal_file.seek(SeekFrom::Start(0))?;
        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < WAL_HEADER_LEN as u64 {
                // Incomplete trailing frame header from crash mid-write -> truncate cleanly.
                wal_file.set_len(last_valid_offset)?;
                wal_file.sync_all()?;
                break;
            }

            let mut header = [0u8; WAL_HEADER_LEN];
            wal_file.read_exact(&mut header)?;

            if &header[0..4] != WAL_FRAME_MAGIC {
                return Err(NodeError::WalCorrupted {
                    offset,
                    reason: "invalid WAL frame magic".into(),
                });
            }

            let seq = u64::from_be_bytes(header[4..12].try_into().unwrap());
            let payload_len = u32::from_be_bytes(header[12..16].try_into().unwrap());
            let mut expected_hash = [0u8; 32];
            expected_hash.copy_from_slice(&header[16..48]);

            if payload_len > MAX_WAL_FRAME_LEN {
                return Err(NodeError::WalCorrupted {
                    offset,
                    reason: format!("frame payload length {payload_len} exceeds bound"),
                });
            }

            let frame_end = offset + WAL_HEADER_LEN as u64 + payload_len as u64;
            if frame_end > file_len {
                // Incomplete trailing frame payload from crash mid-write -> truncate cleanly.
                wal_file.set_len(last_valid_offset)?;
                wal_file.sync_all()?;
                break;
            }

            if seq != expected_seq {
                return Err(NodeError::WalCorrupted {
                    offset,
                    reason: format!("non-sequential WAL seq {seq}, expected {expected_seq}"),
                });
            }

            let mut payload_bytes = vec![0u8; payload_len as usize];
            wal_file.read_exact(&mut payload_bytes)?;

            let mut hasher = Sha256::new();
            hasher.update(seq.to_be_bytes());
            hasher.update(payload_len.to_be_bytes());
            hasher.update(&payload_bytes);
            let actual_hash: [u8; 32] = hasher.finalize().into();
            if actual_hash != expected_hash {
                return Err(NodeError::WalCorrupted {
                    offset,
                    reason: "WAL frame SHA-256 checksum mismatch".into(),
                });
            }

            let wal_payload: WalPayload =
                serde_json::from_slice(&payload_bytes).map_err(|e| NodeError::WalCorrupted {
                    offset,
                    reason: format!("WAL payload JSON invalid: {e}"),
                })?;

            let computed_root = hex::encode(compute_state_root(&wal_payload.post_state));
            if computed_root != wal_payload.state_root_hex || wal_payload.seq != seq {
                return Err(NodeError::WalCorrupted {
                    offset,
                    reason: "WAL payload state_root or seq mismatch".into(),
                });
            }

            if seq > recovered.wal_seq {
                recovered = wal_payload.post_state;
            }
            last_seq_seen = last_seq_seen.max(seq);
            expected_seq += 1;
            offset = frame_end;
            last_valid_offset = frame_end;
        }

        wal_file.seek(SeekFrom::End(0))?;
        Ok((
            NodeStateStore {
                data_dir: data_dir.to_path_buf(),
                wal_file,
                last_wal_seq: last_seq_seen,
            },
            recovered,
        ))
    }

    /// Current highest durable WAL sequence number.
    pub const fn last_wal_seq(&self) -> u64 {
        self.last_wal_seq
    }

    /// Appends a new durable WAL frame (`sync_data()` before returning) and updates
    /// `state.wal_seq` atomically. Returns the resulting canonical 32-byte `StateRoot`.
    pub fn append_wal(
        &mut self,
        event_tag: &str,
        state: &mut PersistedNodeState,
    ) -> NodeResult<[u8; 32]> {
        let next_seq = self.last_wal_seq + 1;
        state.wal_seq = next_seq;
        let root = compute_state_root(state);
        let root_hex = hex::encode(root);

        let wal_payload = WalPayload {
            seq: next_seq,
            event_tag: event_tag.to_string(),
            state_root_hex: root_hex,
            post_state: state.clone(),
        };
        let payload_bytes = serde_json::to_vec(&wal_payload)
            .map_err(|e| NodeError::Io(format!("WAL serialize failed: {e}")))?;
        let payload_len = u32::try_from(payload_bytes.len())
            .map_err(|_| NodeError::Io("WAL payload exceeds u32".into()))?;
        if payload_len > MAX_WAL_FRAME_LEN {
            return Err(NodeError::Io("WAL payload exceeds MAX_WAL_FRAME_LEN".into()));
        }

        let mut hasher = Sha256::new();
        hasher.update(next_seq.to_be_bytes());
        hasher.update(payload_len.to_be_bytes());
        hasher.update(&payload_bytes);
        let checksum: [u8; 32] = hasher.finalize().into();

        let mut frame = Vec::with_capacity(WAL_HEADER_LEN + payload_bytes.len());
        frame.extend_from_slice(WAL_FRAME_MAGIC);
        frame.extend_from_slice(&next_seq.to_be_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&checksum);
        frame.extend_from_slice(&payload_bytes);

        self.wal_file.seek(SeekFrom::End(0))?;
        self.wal_file.write_all(&frame)?;
        self.wal_file.sync_data()?;
        self.last_wal_seq = next_seq;
        Ok(root)
    }

    /// Atomically writes `snapshot.json` via `snapshot.json.tmp` + `sync_all()` + `rename`.
    pub fn write_atomic_snapshot(&self, state: &PersistedNodeState) -> NodeResult<[u8; 32]> {
        let root = compute_state_root(state);
        let state_json = serde_json::to_vec(state)
            .map_err(|e| NodeError::Io(format!("snapshot state serialize: {e}")))?;
        let sha256_hex = hex::encode(Sha256::digest(&state_json));
        let envelope = SnapshotEnvelope {
            sha256_hex,
            state_root_hex: hex::encode(root),
            state: state.clone(),
        };
        let env_bytes = serde_json::to_vec_pretty(&envelope)
            .map_err(|e| NodeError::Io(format!("snapshot envelope serialize: {e}")))?;

        let tmp_path = self.data_dir.join(SNAPSHOT_TMP_FILE_NAME);
        let final_path = Self::snapshot_path(&self.data_dir);
        {
            let mut tmp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            tmp_file.write_all(&env_bytes)?;
            tmp_file.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Ok(root)
    }
}
