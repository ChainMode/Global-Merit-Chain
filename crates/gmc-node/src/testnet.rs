//! GMChain Public Testnet genesis seeding, Contribution Bounty (`任务悬赏`) lifecycle,
//! Automatic High-Intimacy Stakeholder Voting Exclusion (`排除高亲密度亲友团反作弊过滤`),
//! Auto-Minted Decaying `MeriToken (μ)` batches, and Merit-Weighted Community Governance
//! Proposals (`社区治理提案`).
//!
//! Strictly uses `gmc-core` fixed-point `i128` (`Decimal` / `Ratio`, `SCALE = 1_000_000`)
//! arithmetic — zero `f32`/`f64` floating-point types anywhere.

use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use gmc_core::antifraud::{select_voters, Stakeholder, INTIMACY_EXCLUSION_THRESHOLD};
use gmc_core::error::GmcError;
use gmc_core::governance::{GovernanceModule, Voter};
use gmc_core::l1_settlement::VoteResultRecord;
use gmc_core::relationship::{compute_intimacy, PrivacyTier, RelationshipType};
use gmc_core::types::{ChainId, Decimal, FayID, Ratio, Timestamp};
use gmc_identity::fayid_interop::to_fayid_canonical;
use gmc_identity::identity_core::{Applied, OperationPayload};
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::ownership::{OwnerKind, OwnerRef};
use gmc_identity::types::{IdentityKind, SchemeTag, VerifyingKey};

use crate::crypto::{keypair_from_seed, sign_ed25519_operation};
use crate::error::{NodeError, NodeResult};
use crate::runtime::NodeRuntime;

/// Default public testnet chain identifier.
pub const PUBLIC_TESTNET_CHAIN_ID: &str = "gmchain-public-testnet-1";
/// Default public testnet genesis anchor timestamp (`2026-11-20T00:00:00Z` approx epoch).
pub const PUBLIC_TESTNET_GENESIS_SECS: u64 = 1_700_500_000;
/// `2/3` supermajority quorum ratio in fixed-point (`0.666667`, `SCALE = 1_000_000`).
pub const TWO_THIRDS_QUORUM_RAW: i128 = 666_667;

// ============================================================================
// Durable Persisted DTOs (stored in `PersistedNodeState.testnet`)
// ============================================================================

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedTestnetState {
    #[serde(default)]
    pub seeded_genesis: bool,
    #[serde(default)]
    pub base_timestamp_secs: u64,
    #[serde(default)]
    pub next_bounty_seq: u64,
    #[serde(default)]
    pub next_proposal_seq: u64,
    #[serde(default)]
    pub participants: Vec<PersistedParticipantMeta>,
    #[serde(default)]
    pub bounties: Vec<PersistedBounty>,
    #[serde(default)]
    pub proposals: Vec<PersistedGovernanceProposal>,
    #[serde(default)]
    pub priority_consumptions: Vec<PersistedPriorityConsumption>,
}

impl PersistedTestnetState {
    pub fn is_empty(&self) -> bool {
        !self.seeded_genesis
            && self.participants.is_empty()
            && self.bounties.is_empty()
            && self.proposals.is_empty()
            && self.priority_consumptions.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedParticipantMeta {
    pub scheme_tag: String,
    pub key_repr: String,
    pub fay_id: String,
    pub canonical_fayid: String,
    pub display_name: String,
    pub kind: String,
    pub role_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_fay_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPriorityConsumption {
    pub consumption_id: String,
    pub fay_id: String,
    pub canonical_fayid: String,
    pub display_name: String,
    pub priority_kind: String,
    pub reason: String,
    #[serde(default)]
    pub proposal_id: Option<String>,
    pub consumed_mu_raw: i128,
    pub consumed_mu: String,
    pub before_cur_merit_mu: String,
    pub after_cur_merit_mu: String,
    pub preserved_min_merit_mu: String,
    pub block_height: u64,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedExcludedInsider {
    pub fay_id: String,
    pub canonical_fayid: String,
    pub display_name: String,
    pub relationship_type: String,
    pub intimacy_raw: i128,
    pub intimacy_display: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBountyBallot {
    pub voter_fay_id: String,
    pub voter_canonical_fayid: String,
    pub voter_display_name: String,
    pub approve: bool,
    pub weight_merit_raw: i128,
    pub voted_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBounty {
    pub bounty_id: String,
    pub title: String,
    pub domain_chain_id: String,
    pub assignee_fay_id: String,
    pub assignee_canonical_fayid: String,
    pub assignee_display_name: String,
    pub reward_mu_raw: i128,
    pub horizon_days: u64,
    pub influence_duration_secs: u64,
    pub status: String,
    pub deliverable_summary: Option<String>,
    pub evidence_uri: Option<String>,
    pub created_at_secs: u64,
    pub excluded_insiders: Vec<PersistedExcludedInsider>,
    pub eligible_voter_fay_ids: Vec<String>,
    pub ballots: Vec<PersistedBountyBallot>,
    pub quorum_threshold_raw: i128,
    pub approval_ratio_raw: i128,
    pub minted_batch_id: Option<String>,
    pub minted_block_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedProposalBallot {
    pub voter_fay_id: String,
    pub voter_canonical_fayid: String,
    pub voter_display_name: String,
    pub approve: bool,
    pub decayed_merit_raw: i128,
    pub weight_ratio_raw: i128,
    pub voted_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedGovernanceProposal {
    pub proposal_id: String,
    pub title: String,
    pub summary: String,
    pub domain_chain_id: String,
    pub threshold_raw: i128,
    pub created_at_secs: u64,
    pub eval_timestamp_secs: u64,
    pub status: String,
    pub ballots: Vec<PersistedProposalBallot>,
    pub total_electorate_merit_raw: i128,
    pub approve_merit_raw: i128,
    pub reject_merit_raw: i128,
    pub approval_ratio_raw: i128,
    pub anchored_block_height: Option<u64>,
}

// ============================================================================
// Request DTOs for HTTP REST & JSON-RPC 2.0
// ============================================================================

#[derive(Debug, Default, Deserialize)]
pub struct ExplorerQueryParams {
    #[serde(default)]
    pub elapsed_days: u64,
    #[serde(default)]
    pub offset_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct PublishBountyRequest {
    pub title: String,
    #[serde(default = "default_domain_chain")]
    pub domain_chain_id: String,
    pub assignee_id: String,
    pub reward_mu: i64,
    #[serde(default = "default_horizon_days")]
    pub horizon_days: u64,
    #[serde(default)]
    pub deliverable_summary: Option<String>,
    #[serde(default)]
    pub evidence_uri: Option<String>,
}

fn default_domain_chain() -> String {
    "gmc-open-science".to_string()
}

const fn default_horizon_days() -> u64 {
    90
}

#[derive(Debug, Deserialize)]
pub struct SubmitDeliverableRequest {
    pub bounty_id: String,
    pub deliverable_summary: String,
    #[serde(default)]
    pub evidence_uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SingleBountyBallotInput {
    pub voter_id: String,
    pub approve: bool,
}

#[derive(Debug, Deserialize)]
pub struct VoteBountyRequest {
    pub bounty_id: String,
    #[serde(default)]
    pub voter_id: Option<String>,
    #[serde(default)]
    pub approve: Option<bool>,
    #[serde(default)]
    pub ballots: Vec<SingleBountyBallotInput>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProposalRequest {
    pub title: String,
    pub summary: String,
    #[serde(default = "default_domain_chain")]
    pub domain_chain_id: String,
    #[serde(default = "default_proposal_threshold_raw")]
    pub threshold_raw: i128,
    #[serde(default)]
    pub elapsed_days: u64,
}

const fn default_proposal_threshold_raw() -> i128 {
    TWO_THIRDS_QUORUM_RAW
}

#[derive(Debug, Clone, Deserialize)]
pub struct SingleProposalBallotInput {
    pub voter_id: String,
    pub approve: bool,
}

#[derive(Debug, Deserialize)]
pub struct VoteProposalRequest {
    pub proposal_id: String,
    #[serde(default)]
    pub voter_id: Option<String>,
    #[serde(default)]
    pub approve: Option<bool>,
    #[serde(default)]
    pub ballots: Vec<SingleProposalBallotInput>,
    #[serde(default)]
    pub elapsed_days: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterExternalFayRequest {
    #[serde(default)]
    pub pubkey_hex: Option<String>,
    #[serde(default)]
    pub fay_id: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub role_label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordContributionRequest {
    pub fay_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    pub title: String,
    #[serde(default = "default_domain_chain")]
    pub domain_chain_id: String,
    pub amount_mu: i64,
    #[serde(default = "default_horizon_days")]
    pub horizon_days: u64,
    #[serde(default)]
    pub summary: Option<String>,
}

/// Deterministic zero-floating-point amount deserializer accepting either a JSON
/// integer (`12`) or a fixed-point decimal string (`"12.5"`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DecimalAmountInput {
    Int(i64),
    Str(String),
}

impl DecimalAmountInput {
    pub fn to_decimal(&self) -> Result<Decimal, String> {
        match self {
            DecimalAmountInput::Int(v) => Ok(Decimal::from_int(*v)),
            DecimalAmountInput::Str(s) => Decimal::from_str(s)
                .ok_or_else(|| format!("invalid fixed-point decimal string '{s}'")),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ConsumePriorityRequest {
    pub fay_id: String,
    pub priority_kind: String,
    pub amount_mu: DecimalAmountInput,
    pub reason: String,
    #[serde(default)]
    pub proposal_id: Option<String>,
    #[serde(default)]
    pub approve: Option<bool>,
}

fn rel_type_label(rt: RelationshipType) -> &'static str {
    match rt {
        RelationshipType::Kinship => "kinship",
        RelationshipType::Legal => "legal",
        RelationshipType::Social => "social",
        RelationshipType::Organizational => "organizational",
    }
}

/// Maps user-facing horizon days (e.g. 30 / 90 / 180) onto `gmc-core` fixed-point
/// `influence_duration` (`SCALE = 1_000_000`) so `λ = 1 / influence_duration >= 1e-6`
/// never truncates to zero in 6-decimal fixed-point arithmetic.
fn calibrated_influence_duration_secs(horizon_days: u64) -> u64 {
    if horizon_days <= 30 {
        250_000 // λ = 4e-6 / sec (short-horizon fast decay)
    } else if horizon_days <= 90 {
        500_000 // λ = 2e-6 / sec (medium-horizon steady decay)
    } else {
        1_000_000 // λ = 1e-6 / sec (long-horizon gradual decay across 30d..180d+)
    }
}

fn format_decimal(d: Decimal) -> String {
    d.to_string()
}

// ============================================================================
// NodeRuntime Public Testnet Methods
// ============================================================================

impl NodeRuntime {
    /// Opens an existing Public Testnet data directory or initializes a brand-new 4-validator
    /// BFT Public Testnet seeded with `iFay` & `coFay` identities, social-intimacy edges
    /// (both `> 0.90` close-intimacy insiders and `<= 0.45` independent peers), initial
    /// decaying `MeritPocket` balances, a sample Contribution Bounty, and Community Governance Proposals.
    pub fn open_public_testnet(mut config: crate::runtime::NodeConfig) -> NodeResult<Self> {
        if config.chain_id == crate::runtime::DEFAULT_CHAIN_ID {
            config.chain_id = PUBLIC_TESTNET_CHAIN_ID.to_string();
        }
        let mut runtime = Self::open_workbench(config)?;
        if !runtime.testnet_state().seeded_genesis {
            runtime.seed_public_testnet_genesis()?;
        }
        Ok(runtime)
    }

    /// Seeds deterministic Public Testnet genesis state and commits Height #1 BFT block.
    #[allow(clippy::too_many_lines)]
    pub fn seed_public_testnet_genesis(&mut self) -> NodeResult<()> {
        if self.testnet_state().seeded_genesis {
            return Ok(());
        }

        let t_early = Timestamp::from_secs(PUBLIC_TESTNET_GENESIS_SECS - 6 * 86_400);
        let t_genesis = Timestamp::from_secs(PUBLIC_TESTNET_GENESIS_SECS);

        // 1. Register primary contributor Alice (iFay) + Steward (iFay) -> Civic Permit Desk (coFay)
        let (_alice_sk, alice_vk) = keypair_from_seed(&[0xC1u8; 32]);
        let (steward_sk, steward_vk) = keypair_from_seed(&[0xC2u8; 32]);
        let (_civic_cofay_sk, civic_cofay_vk) = keypair_from_seed(&[0xC3u8; 32]);

        let alice_id = self.register_ifay(&alice_vk, t_early)?;
        let steward_id = self.register_ifay(&steward_vk, t_early)?;

        let create_cofay_op = sign_ed25519_operation(
            &steward_sk,
            &steward_vk,
            steward_id.clone(),
            OperationPayload::CreateCoFay {
                owner: OwnerRef::new("org_civic-service-bureau", OwnerKind::Organization),
                new_cofay_key: civic_cofay_vk,
            },
            1,
        )?;
        let cofay_applied = self.submit_signed_operation(create_cofay_op, t_early)?;
        let civic_cofay_id = match cofay_applied {
            Applied::CoFayCreated(id) => id,
            _ => {
                return Err(NodeError::ConsensusInvalid(
                    "expected CoFayCreated during testnet genesis".into(),
                ))
            }
        };

        // 2. Register 2 close-intimacy insiders relative to Alice (`intimacy > 0.90`)
        let (_bob_sk, bob_vk) = keypair_from_seed(&[0xD1u8; 32]);
        let (_lin_sk, lin_vk) = keypair_from_seed(&[0xD2u8; 32]);
        let bob_id = self.register_ifay(&bob_vk, t_early)?;
        let lin_id = self.register_ifay(&lin_vk, t_early)?;

        // 3. Register 8 independent domain stakeholders (`>= 7` required by `MIN_VOTER_SET_SIZE`)
        let peer_specs: [([u8; 32], &str, &str, i64, u64); 8] = [
            (
                [0xE1u8; 32],
                "Dr. Maya Patel",
                "Open Science Reviewer #1",
                65,
                180,
            ),
            (
                [0xE2u8; 32],
                "Kenji Sato",
                "Distributed Systems Steward #2",
                55,
                180,
            ),
            (
                [0xE3u8; 32],
                "Elena Rostova",
                "Protocol Security Auditor #3",
                50,
                90,
            ),
            (
                [0xE4u8; 32],
                "Carlos Mendez",
                "Public Commons Curator #4",
                45,
                90,
            ),
            (
                [0xE5u8; 32],
                "Dr. Amara Okafor",
                "Reproducibility Fellow #5",
                40,
                180,
            ),
            (
                [0xE6u8; 32],
                "Hannah Weber",
                "Civic Data Maintainer #6",
                35,
                90,
            ),
            (
                [0xE7u8; 32],
                "Liam O'Connor",
                "Open Standards Maintainer #7",
                30,
                90,
            ),
            (
                [0xE8u8; 32],
                "Soo-Jin Park",
                "Independent Verification Node #8",
                28,
                180,
            ),
        ];

        let mut participants = vec![
            build_participant_meta(
                &alice_id,
                IdentityKind::IFay,
                "Alice Chen",
                "Open Science Protocol Contributor (iFay)",
            )?,
            build_participant_meta(
                &civic_cofay_id,
                IdentityKind::CoFay,
                "Civic Permit Desk",
                "Chartered Public Role Seat (coFay · org_service)",
            )?,
            build_participant_meta(
                &bob_id,
                IdentityKind::IFay,
                "Bob Chen",
                "Close Kinship Insider (Intimacy > 0.90)",
            )?,
            build_participant_meta(
                &lin_id,
                IdentityKind::IFay,
                "Dr. Lin Wei",
                "Co-Principal Lab Partner (Intimacy > 0.90)",
            )?,
        ];

        // Seed initial contributions so all participants have realistic `MeritPocket` standing
        self.submit_contribution(
            &alice_id,
            ChainId::new("gmc-open-science"),
            Decimal::from_int(32),
            Decimal::from_int(calibrated_influence_duration_secs(90) as i64),
            t_genesis,
        )?;
        self.submit_contribution(
            &civic_cofay_id,
            ChainId::new("gmc-public-infra"),
            Decimal::from_int(48),
            Decimal::from_int(calibrated_influence_duration_secs(180) as i64),
            t_genesis,
        )?;
        self.submit_contribution(
            &bob_id,
            ChainId::new("gmc-open-science"),
            Decimal::from_int(85),
            Decimal::from_int(calibrated_influence_duration_secs(180) as i64),
            t_genesis,
        )?;
        self.submit_contribution(
            &lin_id,
            ChainId::new("gmc-open-science"),
            Decimal::from_int(75),
            Decimal::from_int(calibrated_influence_duration_secs(180) as i64),
            t_genesis,
        )?;

        let mut peer_ids = Vec::new();
        for (seed, name, role, initial_mu, horizon_d) in peer_specs {
            let (_sk, vk) = keypair_from_seed(&seed);
            let pid = self.register_ifay(&vk, t_early)?;
            self.submit_contribution(
                &pid,
                ChainId::new("gmc-open-science"),
                Decimal::from_int(initial_mu),
                Decimal::from_int(calibrated_influence_duration_secs(horizon_d) as i64),
                t_genesis,
            )?;
            participants.push(build_participant_meta(
                &pid,
                IdentityKind::IFay,
                name,
                role,
            )?);
            peer_ids.push(pid);
        }

        // 4. Build genuine high-intimacy edges (`> 0.90`) for Bob (Kinship: ~0.99) & Dr. Lin (Legal: ~0.94)
        let alice_fay = alice_id.to_fay_id();
        let bob_fay = bob_id.to_fay_id();
        let lin_fay = lin_id.to_fay_id();
        let full_depth = Ratio::new(Decimal::ONE).unwrap();

        self.register_relationship(
            alice_fay.clone(),
            bob_fay.clone(),
            RelationshipType::Kinship,
            PrivacyTier::ExistencePublic,
            t_early,
        )?;
        self.register_relationship(
            alice_fay.clone(),
            lin_fay.clone(),
            RelationshipType::Legal,
            PrivacyTier::ExistencePublic,
            t_early,
        )?;

        // Accumulate 50 bilateral interactions across 5 daily 24h anti-farming windows + 15 shared co-participations
        for window_idx in 0..5u64 {
            let w_ts = Timestamp::from_secs(t_early.as_secs() + window_idx * 86_400 + 60);
            for step in 0..10u64 {
                let step_ts = Timestamp::from_secs(w_ts.as_secs() + step);
                self.relationships_mut()
                    .record_interaction(&alice_fay, &bob_fay, full_depth, step_ts)?;
                self.relationships_mut()
                    .record_interaction(&bob_fay, &alice_fay, full_depth, step_ts)?;
                self.relationships_mut()
                    .record_interaction(&alice_fay, &lin_fay, full_depth, step_ts)?;
                self.relationships_mut()
                    .record_interaction(&lin_fay, &alice_fay, full_depth, step_ts)?;
            }
        }
        if let Some(edge_bob) = self.relationships_mut().get_edge_mut(&alice_fay, &bob_fay) {
            edge_bob.record_co_participation(15, t_genesis)?;
        }
        if let Some(edge_lin) = self.relationships_mut().get_edge_mut(&alice_fay, &lin_fay) {
            edge_lin.record_co_participation(15, t_genesis)?;
        }

        // Also register low-intimacy organic social edges (`0.15 .. 0.32 <= 0.90`) with 3 peers
        for (idx, peer) in peer_ids.iter().take(3).enumerate() {
            let peer_fay = peer.to_fay_id();
            self.register_relationship(
                alice_fay.clone(),
                peer_fay.clone(),
                RelationshipType::Social,
                PrivacyTier::ExistencePublic,
                t_early,
            )?;
            let mod_depth =
                Ratio::new(Decimal::from_raw(400_000 + (idx as i128) * 100_000)).unwrap();
            self.relationships_mut()
                .record_interaction(&alice_fay, &peer_fay, mod_depth, t_genesis)?;
            self.relationships_mut()
                .record_interaction(&peer_fay, &alice_fay, mod_depth, t_genesis)?;
        }

        self.testnet_state_mut().seeded_genesis = true;
        self.testnet_state_mut().base_timestamp_secs = PUBLIC_TESTNET_GENESIS_SECS;
        self.testnet_state_mut().participants = participants;

        // 5. Publish 1 ready-to-vote sample Contribution Bounty & 2 Community Governance Proposals
        let alice_canonical = to_fayid_canonical(&alice_id, IdentityKind::IFay)?;
        let seeded_bounty = self.publish_bounty_internal(
            PublishBountyRequest {
                title: "Zero-Dependency BUF\\0 Seat Verifier & Open Dataset Benchmark".to_string(),
                domain_chain_id: "gmc-open-science".to_string(),
                assignee_id: alice_canonical,
                reward_mu: 60,
                horizon_days: 90,
                deliverable_summary: Some(
                    "Submitted reproducible benchmark suite + 20 Ed25519 JCS test vectors"
                        .to_string(),
                ),
                evidence_uri: Some(
                    "https://github.com/ChainMode/coFay/tree/main/vectors".to_string(),
                ),
            },
            false,
        )?;
        let _ = seeded_bounty;

        self.create_proposal_internal(
            CreateProposalRequest {
                title: "GIP-01: Calibrate Open-Science Replication Bounty Horizon to 90 Days".to_string(),
                summary: "Standardize empirical reproducibility bounties on gmc-open-science at a 90-day exponential decay horizon with zero transaction fees.".to_string(),
                domain_chain_id: "gmc-open-science".to_string(),
                threshold_raw: TWO_THIRDS_QUORUM_RAW,
                elapsed_days: 0,
            },
            false,
        )?;
        self.create_proposal_internal(
            CreateProposalRequest {
                title: "GIP-02: Ratify Public Civic Permit Desk (coFay) Audit Retention Standard".to_string(),
                summary: "Require chartered org_service coFay seats on gmc-public-infra to maintain 365-day hash-chained action logs.".to_string(),
                domain_chain_id: "gmc-public-infra".to_string(),
                threshold_raw: 500_000,
                elapsed_days: 0,
            },
            false,
        )?;

        // 6. Seal Genesis Height #1 with 4/4 BFT QuorumCertificate
        self.produce_block(t_genesis)?;
        Ok(())
    }

    fn eval_timestamp(&self, offset_secs: u64) -> Timestamp {
        let base = if self.testnet_state().base_timestamp_secs > 0 {
            self.testnet_state().base_timestamp_secs
        } else {
            PUBLIC_TESTNET_GENESIS_SECS
        };
        Timestamp::from_secs(base.saturating_add(offset_secs))
    }

    fn resolve_participant_by_any_id(
        &self,
        raw_id: &str,
    ) -> Option<(IdentityId, PersistedParticipantMeta)> {
        let trimmed = raw_id.trim();
        if trimmed.is_empty() {
            return None;
        }
        for meta in &self.testnet_state().participants {
            if meta.canonical_fayid == trimmed
                || meta.fay_id == trimmed
                || meta.external_fay_id.as_deref() == Some(trimmed)
            {
                return Some((
                    IdentityId::new(
                        SchemeTag::new(meta.scheme_tag.clone()),
                        meta.key_repr.clone(),
                    ),
                    meta.clone(),
                ));
            }
        }
        for (id, ident) in self.identities().identities.iter() {
            let fay_str = id.to_fay_id().as_str().to_string();
            let canon = to_fayid_canonical(id, ident.kind).unwrap_or_else(|_| id.canonical());
            if canon == trimmed || fay_str == trimmed || id.canonical() == trimmed {
                return Some((
                    id.clone(),
                    PersistedParticipantMeta {
                        scheme_tag: id.scheme_tag().as_str().to_string(),
                        key_repr: id.key_repr().to_string(),
                        fay_id: fay_str,
                        canonical_fayid: canon.clone(),
                        display_name: canon,
                        kind: match ident.kind {
                            IdentityKind::IFay => "ifay".into(),
                            IdentityKind::CoFay => "cofay".into(),
                        },
                        role_label: "Registered GMChain Identity".into(),
                        external_fay_id: None,
                    },
                ));
            }
        }
        None
    }

    /// Computes full Explorer & `MeritPocket` state at `base_timestamp + offset_secs`
    /// (`GET /api/explorer`, `gmc_explorer`).
    #[allow(clippy::too_many_lines)]
    pub fn explorer_snapshot(&self, params: &ExplorerQueryParams) -> Value {
        let total_offset_secs = params
            .offset_secs
            .saturating_add(params.elapsed_days.saturating_mul(86_400));
        let eval_ts = self.eval_timestamp(total_offset_secs);

        let mut total_network_merit = Decimal::ZERO;
        let mut pockets_raw = Vec::new();

        for (id, ident) in self.identities().identities.iter() {
            let fay = id.to_fay_id();
            let Some(pocket) = self.identities().binding.pocket_by_key(&fay) else {
                continue;
            };
            let cur = pocket.cur_merit(eval_ts);
            let consumable = pocket.consumable_merit(eval_ts);
            total_network_merit = total_network_merit
                .checked_add(cur)
                .unwrap_or(total_network_merit);

            let meta = self
                .testnet_state()
                .participants
                .iter()
                .find(|m| m.fay_id == fay.as_str())
                .cloned();
            let canonical_fayid = meta
                .as_ref()
                .map(|m| m.canonical_fayid.clone())
                .unwrap_or_else(|| {
                    to_fayid_canonical(id, ident.kind).unwrap_or_else(|_| id.canonical())
                });
            let display_name = meta
                .as_ref()
                .map(|m| m.display_name.clone())
                .unwrap_or_else(|| canonical_fayid.clone());
            let role_label = meta
                .as_ref()
                .map(|m| m.role_label.clone())
                .unwrap_or_else(|| "Participant".to_string());
            let external_fay_id = meta.as_ref().and_then(|m| m.external_fay_id.clone());
            let kind_str = match ident.kind {
                IdentityKind::IFay => "ifay",
                IdentityKind::CoFay => "cofay",
            };

            let batches_json: Vec<Value> = pocket
                .batches
                .iter()
                .map(|b| {
                    let cur_batch = b.merit_at(eval_ts);
                    json!({
                        "batch_id": b.batch_id,
                        "source_chain_id": b.source_chain_id.as_str(),
                        "initial_v_mu": format_decimal(b.v),
                        "floor_b_mu": format_decimal(b.b),
                        "current_mu": format_decimal(cur_batch),
                        "current_raw": cur_batch.raw(),
                        "influence_duration_secs": b.influence_duration.raw() / Decimal::SCALE,
                        "acquired_at_secs": b.acquired_at.as_secs(),
                    })
                })
                .collect();

            pockets_raw.push((
                cur,
                consumable,
                canonical_fayid,
                fay.as_str().to_string(),
                external_fay_id,
                display_name,
                kind_str,
                role_label,
                pocket.min_merit(),
                batches_json,
            ));
        }

        let pockets_json: Vec<Value> = pockets_raw
            .into_iter()
            .map(
                |(
                    cur,
                    consumable,
                    canonical_fayid,
                    fay_id,
                    external_fay_id,
                    display_name,
                    kind_str,
                    role_label,
                    min_merit,
                    batches,
                )| {
                    let voice_share = if total_network_merit.is_positive() {
                        cur.checked_div(total_network_merit)
                            .unwrap_or(Decimal::ZERO)
                    } else {
                        Decimal::ZERO
                    };
                    let mut obj = json!({
                        "fay_id": canonical_fayid,
                        "internal_fay_id": fay_id,
                        "display_name": display_name,
                        "kind": kind_str,
                        "role_label": role_label,
                        "cur_merit_mu": format_decimal(cur),
                        "cur_merit_raw": cur.raw(),
                        "consumable_merit_mu": format_decimal(consumable),
                        "consumable_merit_raw": consumable.raw(),
                        "min_merit_floor_mu": format_decimal(min_merit),
                        "min_merit_floor_raw": min_merit.raw(),
                        "governance_voice_ratio": format_decimal(voice_share),
                        "governance_voice_raw": voice_share.raw(),
                        "batches": batches,
                    });
                    if let Some(ext) = external_fay_id {
                        obj["external_fay_id"] = Value::String(ext);
                    }
                    obj
                },
            )
            .collect();

        let quorum = self.validator_set().quorum_threshold();
        let recent_blocks: Vec<Value> = self
            .committed_qcs()
            .iter()
            .rev()
            .take(15)
            .map(|qc| qc.to_summary_json(quorum))
            .collect();

        json!({
            "status": self.status(),
            "validators": self.validators_summary(),
            "eval_timestamp_secs": eval_ts.as_secs(),
            "elapsed_days": total_offset_secs / 86_400,
            "intimacy_exclusion_threshold": format_decimal(INTIMACY_EXCLUSION_THRESHOLD),
            "total_network_merit_mu": format_decimal(total_network_merit),
            "total_network_merit_raw": total_network_merit.raw(),
            "pockets": pockets_json,
            "recent_blocks": recent_blocks,
            "bounties": self.testnet_state().bounties,
            "proposals": self.testnet_state().proposals,
            "priority_consumptions": self.testnet_state().priority_consumptions,
        })
    }

    /// Stage 1: Publishes a Contribution Bounty (`任务悬赏`) and computes automatic
    /// high-intimacy voter exclusion (`intimacy > 0.90`) over `RelationshipGraph`.
    pub fn publish_bounty(&mut self, req: PublishBountyRequest) -> NodeResult<Value> {
        self.publish_bounty_internal(req, true)
    }

    fn publish_bounty_internal(
        &mut self,
        req: PublishBountyRequest,
        persist: bool,
    ) -> NodeResult<Value> {
        if req.title.trim().is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "bounty title must not be empty".into(),
            ));
        }
        if req.reward_mu <= 0 || req.reward_mu > 100_000 {
            return Err(NodeError::Core(GmcError::InvalidMintAmount));
        }
        let horizon_days = req.horizon_days.clamp(1, 3_650);
        let influence_duration_secs = calibrated_influence_duration_secs(horizon_days);

        let Some((assignee_ident, assignee_meta)) =
            self.resolve_participant_by_any_id(&req.assignee_id)
        else {
            return Err(NodeError::Core(GmcError::NotRegistered));
        };

        let now = self.eval_timestamp(0);
        let assignee_fay = assignee_ident.to_fay_id();

        let mut stakeholders_for_antifraud = Vec::new();
        let mut excluded_insiders = Vec::new();

        for (cand_id, cand_record) in self.identities().identities.iter() {
            if cand_id == &assignee_ident {
                continue;
            }
            let cand_fay = cand_id.to_fay_id();
            let pocket_merit = self
                .identities()
                .binding
                .pocket_by_key(&cand_fay)
                .map(|p| p.cur_merit(now))
                .unwrap_or(Decimal::ZERO);
            if !pocket_merit.is_positive() {
                continue;
            }

            let (intimacy_ratio, rel_label) =
                match self.relationships().get_edge(&assignee_fay, &cand_fay) {
                    Some(edge) => (
                        compute_intimacy(edge, now),
                        rel_type_label(edge.relationship_type).to_string(),
                    ),
                    None => (Ratio::ZERO, "none".to_string()),
                };

            let cand_canon = self
                .testnet_state()
                .participants
                .iter()
                .find(|m| m.fay_id == cand_fay.as_str())
                .map(|m| (m.canonical_fayid.clone(), m.display_name.clone()))
                .unwrap_or_else(|| {
                    let c = to_fayid_canonical(cand_id, cand_record.kind)
                        .unwrap_or_else(|_| cand_id.canonical());
                    (c.clone(), c)
                });

            let stakeholder = Stakeholder::new(cand_fay.clone(), intimacy_ratio);
            if stakeholder.is_high_intimacy() {
                excluded_insiders.push(PersistedExcludedInsider {
                    fay_id: cand_fay.as_str().to_string(),
                    canonical_fayid: cand_canon.0,
                    display_name: cand_canon.1,
                    relationship_type: rel_label,
                    intimacy_raw: intimacy_ratio.value().raw(),
                    intimacy_display: format_decimal(intimacy_ratio.value()),
                    reason: "EXCLUDED_HIGH_INTIMACY_ABOVE_0_90".to_string(),
                });
            }
            stakeholders_for_antifraud.push(stakeholder);
        }

        let next_seq = self.testnet_state().next_bounty_seq + 1;
        // Run `gmc_core::antifraud::select_voters` enforcing `intimacy <= 0.90` and `>= 7` independent voters!
        let selected_fays = select_voters(
            &stakeholders_for_antifraud,
            stakeholders_for_antifraud.len().max(7),
            0xB007_0000u64.wrapping_add(next_seq),
        )?;
        let eligible_voter_fay_ids: Vec<String> = selected_fays
            .into_iter()
            .map(|f| f.as_str().to_string())
            .collect();

        let bounty_id = format!("bounty-{next_seq:03}");
        let has_deliverable = req
            .deliverable_summary
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());

        let bounty = PersistedBounty {
            bounty_id: bounty_id.clone(),
            title: req.title.trim().to_string(),
            domain_chain_id: req.domain_chain_id,
            assignee_fay_id: assignee_fay.as_str().to_string(),
            assignee_canonical_fayid: assignee_meta.canonical_fayid,
            assignee_display_name: assignee_meta.display_name,
            reward_mu_raw: Decimal::from_int(req.reward_mu).raw(),
            horizon_days,
            influence_duration_secs,
            status: if has_deliverable {
                "voting".to_string()
            } else {
                "open".to_string()
            },
            deliverable_summary: req.deliverable_summary,
            evidence_uri: req.evidence_uri,
            created_at_secs: now.as_secs(),
            excluded_insiders,
            eligible_voter_fay_ids,
            ballots: Vec::new(),
            quorum_threshold_raw: TWO_THIRDS_QUORUM_RAW,
            approval_ratio_raw: 0,
            minted_batch_id: None,
            minted_block_height: None,
        };

        self.testnet_state_mut().next_bounty_seq = next_seq;
        self.testnet_state_mut().bounties.push(bounty.clone());
        if persist {
            self.persist_testnet_wal("publish_bounty")?;
        }

        Ok(json!({
            "ok": true,
            "bounty": bounty,
            "state_root_hex": self.state_root_hex(),
        }))
    }

    /// Attaches or updates deliverable summary/evidence on a Contribution Bounty and opens voting.
    pub fn submit_bounty_deliverable(
        &mut self,
        req: SubmitDeliverableRequest,
    ) -> NodeResult<Value> {
        if req.deliverable_summary.trim().is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "deliverable_summary must not be empty".into(),
            ));
        }
        let Some(bounty) = self
            .testnet_state_mut()
            .bounties
            .iter_mut()
            .find(|b| b.bounty_id == req.bounty_id)
        else {
            return Err(NodeError::RpcInvalidRequest(format!(
                "unknown bounty_id '{}'",
                req.bounty_id
            )));
        };
        if bounty.status == "minted" {
            return Err(NodeError::RpcInvalidRequest(
                "bounty has already reached quorum and minted MeriToken".into(),
            ));
        }
        bounty.deliverable_summary = Some(req.deliverable_summary.trim().to_string());
        if req.evidence_uri.is_some() {
            bounty.evidence_uri = req.evidence_uri;
        }
        bounty.status = "voting".to_string();
        let updated = bounty.clone();
        self.persist_testnet_wal("submit_bounty_deliverable")?;

        Ok(json!({
            "ok": true,
            "bounty": updated,
            "state_root_hex": self.state_root_hex(),
        }))
    }

    /// Stage 2 & Stage 3: Records `MeriToken`-weighted stakeholder votes on `bounty_id`,
    /// strictly blocking excluded high-intimacy insiders (`intimacy > 0.90`), computing
    /// `GovernanceModule` `2/3` quorum, and auto-minting a decaying `MeriToken (μ)` batch
    /// + sealing a 2-phase BFT block once `approval_ratio >= 2/3`!
    #[allow(clippy::too_many_lines)]
    pub fn vote_bounty(&mut self, req: VoteBountyRequest) -> NodeResult<Value> {
        let mut incoming = req.ballots;
        if let (Some(vid), Some(app)) = (req.voter_id, req.approve) {
            incoming.push(SingleBountyBallotInput {
                voter_id: vid,
                approve: app,
            });
        }
        if incoming.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "at least one ballot is required".into(),
            ));
        }

        let now = self.eval_timestamp(0);
        let bounty_idx = self
            .testnet_state()
            .bounties
            .iter()
            .position(|b| b.bounty_id == req.bounty_id)
            .ok_or_else(|| {
                NodeError::RpcInvalidRequest(format!("unknown bounty_id '{}'", req.bounty_id))
            })?;

        if self.testnet_state().bounties[bounty_idx].status == "minted" {
            return Err(NodeError::RpcInvalidRequest(
                "bounty is already minted".into(),
            ));
        }

        // Validate every incoming voter against the anti-collusion exclusion shield & eligible pool
        let mut resolved_ballots = Vec::new();
        for item in &incoming {
            let Some((voter_ident, voter_meta)) =
                self.resolve_participant_by_any_id(&item.voter_id)
            else {
                return Err(NodeError::Core(GmcError::NotRegistered));
            };
            let voter_fay_str = voter_ident.to_fay_id().as_str().to_string();
            let bounty_ref = &self.testnet_state().bounties[bounty_idx];

            if voter_fay_str == bounty_ref.assignee_fay_id {
                return Err(NodeError::RpcInvalidRequest(
                    "SELF_VOTE_FORBIDDEN: bounty assignee cannot vote on own deliverable".into(),
                ));
            }
            if let Some(excl) = bounty_ref
                .excluded_insiders
                .iter()
                .find(|e| e.fay_id == voter_fay_str)
            {
                return Err(NodeError::RpcInvalidRequest(format!(
                    "HIGH_INTIMACY_EXCLUDED: {} (intimacy={} > 0.90) is barred by anti-collusion filter",
                    excl.display_name, excl.intimacy_display
                )));
            }
            if !bounty_ref.eligible_voter_fay_ids.contains(&voter_fay_str) {
                return Err(NodeError::RpcInvalidRequest(format!(
                    "VOTER_NOT_IN_SAMPLED_ELECTORATE: {}",
                    voter_meta.canonical_fayid
                )));
            }

            let weight_merit = self
                .identities()
                .binding
                .pocket_by_key(&voter_ident.to_fay_id())
                .map(|p| p.cur_merit(now))
                .unwrap_or(Decimal::ZERO);

            resolved_ballots.push(PersistedBountyBallot {
                voter_fay_id: voter_fay_str,
                voter_canonical_fayid: voter_meta.canonical_fayid,
                voter_display_name: voter_meta.display_name,
                approve: item.approve,
                weight_merit_raw: weight_merit.raw(),
                voted_at_secs: now.as_secs(),
            });
        }

        // Merge ballots (replacing prior ballot if re-submitted before mint, or deduplicating)
        {
            let bounty_mut = &mut self.testnet_state_mut().bounties[bounty_idx];
            bounty_mut.status = "voting".to_string();
            for bal in resolved_ballots {
                if let Some(existing) = bounty_mut
                    .ballots
                    .iter_mut()
                    .find(|b| b.voter_fay_id == bal.voter_fay_id)
                {
                    *existing = bal;
                } else {
                    bounty_mut.ballots.push(bal);
                }
            }
        }

        // Tally weighted `GovernanceModule` over the sampled independent electorate
        let bounty_snapshot = self.testnet_state().bounties[bounty_idx].clone();
        let mut gov = GovernanceModule::new();
        let mut voters = Vec::new();
        for elig_fay in &bounty_snapshot.eligible_voter_fay_ids {
            let cur = self
                .identities()
                .binding
                .pocket_by_key(&FayID::new(elig_fay.clone()))
                .map(|p| p.cur_merit(now))
                .unwrap_or(Decimal::ZERO);
            voters.push(Voter::new(FayID::new(elig_fay.clone()), cur));
        }

        let threshold = Ratio::new(Decimal::from_raw(bounty_snapshot.quorum_threshold_raw))
            .ok_or_else(|| NodeError::ConsensusInvalid("invalid quorum ratio".into()))?;
        let vote_id = gov
            .open_vote(
                format!("bounty:{}", bounty_snapshot.bounty_id),
                threshold,
                voters,
            )
            .map_err(|e| NodeError::ConsensusInvalid(format!("governance open_vote: {e:?}")))?;

        for bal in &bounty_snapshot.ballots {
            gov.cast_vote(vote_id, &FayID::new(bal.voter_fay_id.clone()), bal.approve)
                .map_err(|e| NodeError::ConsensusInvalid(format!("governance cast_vote: {e:?}")))?;
        }
        let outcome = gov
            .tally(vote_id)
            .map_err(|e| NodeError::ConsensusInvalid(format!("governance tally: {e:?}")))?;

        self.testnet_state_mut().bounties[bounty_idx].approval_ratio_raw =
            outcome.approval_ratio.value().raw();

        let mut mint_receipt_json = Value::Null;
        let mut block_receipt_json = Value::Null;
        let mut decay_curve_json = Value::Null;

        if outcome.passed {
            // Auto-mint decaying MeriToken batch & commit 2-phase BFT block!
            let (assignee_ident, _) = self
                .resolve_participant_by_any_id(&bounty_snapshot.assignee_fay_id)
                .ok_or(NodeError::Core(GmcError::NotRegistered))?;

            let contrib_receipt = self.submit_contribution(
                &assignee_ident,
                ChainId::new(bounty_snapshot.domain_chain_id.clone()),
                Decimal::from_raw(bounty_snapshot.reward_mu_raw),
                Decimal::from_int(bounty_snapshot.influence_duration_secs as i64),
                now,
            )?;

            self.anchor_l1_vote_result(VoteResultRecord::new(
                format!("bounty-vote:{}", bounty_snapshot.bounty_id),
                bounty_snapshot.title.clone(),
                true,
                now,
            ));

            let block_receipt = self.produce_block(now)?;
            {
                let b_mut = &mut self.testnet_state_mut().bounties[bounty_idx];
                b_mut.status = "minted".to_string();
                b_mut.minted_batch_id = Some(contrib_receipt.batch_id.clone());
                b_mut.minted_block_height = Some(block_receipt.block_height);
            }
            self.persist_testnet_wal("bounty_quorum_auto_mint")?;

            // Compute exact fixed-point decay curve preview for UI Time-Slider (`+0d .. +365d`)
            if let Some(pocket) = self
                .identities()
                .binding
                .pocket_by_key(&assignee_ident.to_fay_id())
            {
                let curve: Vec<Value> = [0u64, 30, 90, 180, 365]
                    .into_iter()
                    .map(|days| {
                        let ts = Timestamp::from_secs(now.as_secs() + days * 86_400);
                        let m = pocket.cur_merit(ts);
                        json!({
                            "day_offset": days,
                            "cur_merit_mu": format_decimal(m),
                            "cur_merit_raw": m.raw(),
                            "min_merit_floor_mu": format_decimal(pocket.min_merit()),
                        })
                    })
                    .collect();
                decay_curve_json = Value::Array(curve);
            }

            mint_receipt_json = serde_json::to_value(&contrib_receipt).unwrap_or(Value::Null);
            block_receipt_json = serde_json::to_value(&block_receipt).unwrap_or(Value::Null);
        } else {
            self.persist_testnet_wal("vote_bounty")?;
        }

        let final_bounty = self.testnet_state().bounties[bounty_idx].clone();
        Ok(json!({
            "ok": true,
            "quorum_passed": outcome.passed,
            "approval_ratio": format_decimal(outcome.approval_ratio.value()),
            "approval_ratio_raw": outcome.approval_ratio.value().raw(),
            "quorum_threshold": format_decimal(outcome.threshold.value()),
            "bounty": final_bounty,
            "mint_receipt": mint_receipt_json,
            "block_receipt": block_receipt_json,
            "decay_curve_preview": decay_curve_json,
            "state_root_hex": self.state_root_hex(),
        }))
    }

    /// Stage 4a: Creates a Merit-Weighted Community Governance Proposal (`社区治理提案`).
    pub fn create_proposal(&mut self, req: CreateProposalRequest) -> NodeResult<Value> {
        self.create_proposal_internal(req, true)
    }

    fn create_proposal_internal(
        &mut self,
        req: CreateProposalRequest,
        persist: bool,
    ) -> NodeResult<Value> {
        if req.title.trim().is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "proposal title must not be empty".into(),
            ));
        }
        let threshold_raw = req.threshold_raw.clamp(100_000, 1_000_000);
        let eval_ts = self.eval_timestamp(req.elapsed_days.saturating_mul(86_400));

        let mut total_electorate = Decimal::ZERO;
        for (id, _) in self.identities().identities.iter() {
            if let Some(p) = self.identities().binding.pocket_by_key(&id.to_fay_id()) {
                total_electorate = total_electorate
                    .checked_add(p.cur_merit(eval_ts))
                    .unwrap_or(total_electorate);
            }
        }

        let seq = self.testnet_state().next_proposal_seq + 1;
        let proposal = PersistedGovernanceProposal {
            proposal_id: format!("prop-{seq:03}"),
            title: req.title.trim().to_string(),
            summary: req.summary.trim().to_string(),
            domain_chain_id: req.domain_chain_id,
            threshold_raw,
            created_at_secs: self.eval_timestamp(0).as_secs(),
            eval_timestamp_secs: eval_ts.as_secs(),
            status: "active".to_string(),
            ballots: Vec::new(),
            total_electorate_merit_raw: total_electorate.raw(),
            approve_merit_raw: 0,
            reject_merit_raw: 0,
            approval_ratio_raw: 0,
            anchored_block_height: None,
        };

        self.testnet_state_mut().next_proposal_seq = seq;
        self.testnet_state_mut().proposals.push(proposal.clone());
        if persist {
            self.persist_testnet_wal("create_proposal")?;
        }

        Ok(json!({
            "ok": true,
            "proposal": proposal,
            "state_root_hex": self.state_root_hex(),
        }))
    }

    /// Stage 4b: Casts `MeriToken`-weighted community governance ballot(s) on `proposal_id`
    /// using each participant's live decayed `curMerit(eval_ts)` share via `GovernanceModule`.
    #[allow(clippy::too_many_lines)]
    pub fn vote_proposal(&mut self, req: VoteProposalRequest) -> NodeResult<Value> {
        let mut incoming = req.ballots;
        if let (Some(vid), Some(app)) = (req.voter_id, req.approve) {
            incoming.push(SingleProposalBallotInput {
                voter_id: vid,
                approve: app,
            });
        }
        if incoming.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "at least one proposal ballot is required".into(),
            ));
        }

        let prop_idx = self
            .testnet_state()
            .proposals
            .iter()
            .position(|p| p.proposal_id == req.proposal_id)
            .ok_or_else(|| {
                NodeError::RpcInvalidRequest(format!("unknown proposal_id '{}'", req.proposal_id))
            })?;

        let eval_ts = match req.elapsed_days {
            Some(days) => self.eval_timestamp(days.saturating_mul(86_400)),
            None => {
                Timestamp::from_secs(self.testnet_state().proposals[prop_idx].eval_timestamp_secs)
            }
        };

        // Build full electorate at `eval_ts`
        let mut electorate_voters = Vec::new();
        let mut total_merit = Decimal::ZERO;
        for (id, _) in self.identities().identities.iter() {
            let fay = id.to_fay_id();
            if let Some(pocket) = self.identities().binding.pocket_by_key(&fay) {
                let cur = pocket.cur_merit(eval_ts);
                if cur.is_positive() {
                    total_merit = total_merit.checked_add(cur).unwrap_or(total_merit);
                    electorate_voters.push(Voter::new(fay, cur));
                }
            }
        }
        if !total_merit.is_positive() {
            return Err(NodeError::ConsensusInvalid(
                "total electorate merit is zero".into(),
            ));
        }

        // Resolve incoming ballots
        let mut new_ballots = Vec::new();
        for item in &incoming {
            let Some((voter_ident, voter_meta)) =
                self.resolve_participant_by_any_id(&item.voter_id)
            else {
                return Err(NodeError::Core(GmcError::NotRegistered));
            };
            let voter_fay = voter_ident.to_fay_id();
            let cur = self
                .identities()
                .binding
                .pocket_by_key(&voter_fay)
                .map(|p| p.cur_merit(eval_ts))
                .unwrap_or(Decimal::ZERO);
            if !cur.is_positive() {
                return Err(NodeError::RpcInvalidRequest(format!(
                    "{} holds 0 MeriToken at evaluation time",
                    voter_meta.canonical_fayid
                )));
            }
            let ratio = cur.checked_div(total_merit).unwrap_or(Decimal::ZERO);
            new_ballots.push(PersistedProposalBallot {
                voter_fay_id: voter_fay.as_str().to_string(),
                voter_canonical_fayid: voter_meta.canonical_fayid,
                voter_display_name: voter_meta.display_name,
                approve: item.approve,
                decayed_merit_raw: cur.raw(),
                weight_ratio_raw: ratio.raw(),
                voted_at_secs: eval_ts.as_secs(),
            });
        }

        // Merge & recompute weights at `eval_ts`
        {
            let prop_mut = &mut self.testnet_state_mut().proposals[prop_idx];
            prop_mut.eval_timestamp_secs = eval_ts.as_secs();
            prop_mut.total_electorate_merit_raw = total_merit.raw();
            for bal in new_ballots {
                if let Some(existing) = prop_mut
                    .ballots
                    .iter_mut()
                    .find(|b| b.voter_fay_id == bal.voter_fay_id)
                {
                    *existing = bal;
                } else {
                    prop_mut.ballots.push(bal);
                }
            }
            // Refresh all stored ballot weights against current `eval_ts`
            let mut refreshed = Vec::with_capacity(prop_mut.ballots.len());
            for mut b in prop_mut.ballots.clone() {
                let cur = self
                    .identities()
                    .binding
                    .pocket_by_key(&FayID::new(b.voter_fay_id.clone()))
                    .map(|p| p.cur_merit(eval_ts))
                    .unwrap_or(Decimal::ZERO);
                b.decayed_merit_raw = cur.raw();
                b.weight_ratio_raw = cur.checked_div(total_merit).unwrap_or(Decimal::ZERO).raw();
                refreshed.push(b);
            }
            self.testnet_state_mut().proposals[prop_idx].ballots = refreshed;
        }

        let prop_snap = self.testnet_state().proposals[prop_idx].clone();
        let threshold = Ratio::new(Decimal::from_raw(prop_snap.threshold_raw))
            .ok_or_else(|| NodeError::ConsensusInvalid("invalid proposal threshold".into()))?;
        let mut gov = GovernanceModule::new();
        let vote_id = gov
            .open_vote(prop_snap.proposal_id.clone(), threshold, electorate_voters)
            .map_err(|e| NodeError::ConsensusInvalid(format!("governance open_vote: {e:?}")))?;

        let mut approve_sum = Decimal::ZERO;
        let mut reject_sum = Decimal::ZERO;
        for b in &prop_snap.ballots {
            let m = Decimal::from_raw(b.decayed_merit_raw);
            if b.approve {
                approve_sum = approve_sum.checked_add(m).unwrap_or(approve_sum);
            } else {
                reject_sum = reject_sum.checked_add(m).unwrap_or(reject_sum);
            }
            gov.cast_vote(vote_id, &FayID::new(b.voter_fay_id.clone()), b.approve)
                .map_err(|e| NodeError::ConsensusInvalid(format!("governance cast_vote: {e:?}")))?;
        }
        let outcome = gov
            .tally(vote_id)
            .map_err(|e| NodeError::ConsensusInvalid(format!("governance tally: {e:?}")))?;

        let mut block_receipt_json = Value::Null;
        let was_already_passed = prop_snap.status == "passed";
        {
            let prop_mut = &mut self.testnet_state_mut().proposals[prop_idx];
            prop_mut.approve_merit_raw = approve_sum.raw();
            prop_mut.reject_merit_raw = reject_sum.raw();
            prop_mut.approval_ratio_raw = outcome.approval_ratio.value().raw();
            if outcome.passed {
                prop_mut.status = "passed".to_string();
            }
        }

        if outcome.passed && !was_already_passed {
            self.anchor_l1_vote_result(VoteResultRecord::new(
                format!("gov-proposal:{}", prop_snap.proposal_id),
                prop_snap.title.clone(),
                true,
                eval_ts,
            ));
            let receipt = self.produce_block(eval_ts)?;
            self.testnet_state_mut().proposals[prop_idx].anchored_block_height =
                Some(receipt.block_height);
            block_receipt_json = serde_json::to_value(&receipt).unwrap_or(Value::Null);
            self.persist_testnet_wal("proposal_passed_anchored")?;
        } else {
            self.persist_testnet_wal("vote_proposal")?;
        }

        let updated_prop = self.testnet_state().proposals[prop_idx].clone();
        Ok(json!({
            "ok": true,
            "passed": outcome.passed,
            "approval_ratio": format_decimal(outcome.approval_ratio.value()),
            "approval_ratio_raw": outcome.approval_ratio.value().raw(),
            "threshold": format_decimal(outcome.threshold.value()),
            "proposal": updated_prop,
            "block_receipt": block_receipt_json,
            "state_root_hex": self.state_root_hex(),
        }))
    }

    fn build_external_fay_response(
        &self,
        ident_id: &IdentityId,
        meta: &PersistedParticipantMeta,
        already_registered: bool,
        now: Timestamp,
    ) -> NodeResult<Value> {
        let fay = ident_id.to_fay_id();
        let pocket = self
            .identities()
            .binding
            .pocket_by_key(&fay)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?;
        let cur = pocket.cur_merit(now);
        let consumable = pocket.consumable_merit(now);
        let floor = pocket.min_merit();
        let external_or_canonical = meta
            .external_fay_id
            .clone()
            .unwrap_or_else(|| meta.canonical_fayid.clone());

        Ok(json!({
            "ok": true,
            "already_registered": already_registered,
            "fay_id": external_or_canonical,
            "canonical_fayid": meta.canonical_fayid,
            "display_name": meta.display_name,
            "cur_merit_mu": format_decimal(cur),
            "cur_merit_raw": cur.raw(),
            "consumable_merit_mu": format_decimal(consumable),
            "consumable_merit_raw": consumable.raw(),
            "min_merit_floor_mu": format_decimal(floor),
            "min_merit_floor_raw": floor.raw(),
            "block_height": self.block_height(),
            "state_root_hex": self.state_root_hex(),
        }))
    }

    /// Registers an external `FayGer` `iFay` or `coFay` on `GMChain`, binds its `MeritPocket`
    /// with an initial `5 μ` (`90d` horizon) welcome batch, and seals a BFT block
    /// (`POST /api/fays/register`, `gmc_registerExternalFay`).
    #[allow(clippy::too_many_lines)]
    pub fn register_external_fay(&mut self, req: RegisterExternalFayRequest) -> NodeResult<Value> {
        let display_name = req.display_name.trim().to_string();
        if display_name.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "display_name must not be empty".into(),
            ));
        }

        let clean_ext_fay_id = req
            .fay_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let now = self.eval_timestamp(0);

        if let Some(ref ext_id) = clean_ext_fay_id {
            if let Some((existing_id, existing_meta)) = self.resolve_participant_by_any_id(ext_id) {
                return self.build_external_fay_response(&existing_id, &existing_meta, true, now);
            }
        }

        let target_kind = if req
            .kind
            .as_deref()
            .is_some_and(|k| k.trim().eq_ignore_ascii_case("cofay"))
        {
            IdentityKind::CoFay
        } else {
            IdentityKind::IFay
        };

        let fallback_label = clean_ext_fay_id.as_deref().unwrap_or(&display_name);
        let vk = derive_or_parse_external_vk(req.pubkey_hex.as_deref(), fallback_label);
        let cand_id = derive_identity_id(&self.identities().registry, &SchemeTag::ed25519(), &vk)?;

        if self.identities().identities.contains(&cand_id) {
            let fay_str = cand_id.to_fay_id().as_str().to_string();
            let mut updated_meta = None;
            if let Some(existing_meta) = self
                .testnet_state_mut()
                .participants
                .iter_mut()
                .find(|m| m.fay_id == fay_str)
            {
                if existing_meta.external_fay_id.is_none() && clean_ext_fay_id.is_some() {
                    existing_meta.external_fay_id = clean_ext_fay_id.clone();
                }
                updated_meta = Some(existing_meta.clone());
            }
            if updated_meta.is_some() {
                self.persist_testnet_wal("bind_external_fay_alias")?;
            }
            let meta = match updated_meta {
                Some(m) => m,
                None => {
                    let (_, m) = self
                        .resolve_participant_by_any_id(&cand_id.canonical())
                        .ok_or(NodeError::Core(GmcError::NotRegistered))?;
                    m
                }
            };
            return self.build_external_fay_response(&cand_id, &meta, true, now);
        }

        let ident_id = match target_kind {
            IdentityKind::IFay => self.register_ifay(&vk, now)?,
            IdentityKind::CoFay => {
                let (steward_sk, steward_vk) = keypair_from_seed(&[0xC2u8; 32]);
                let steward_id = self.register_ifay(&steward_vk, now)?;
                let next_nonce = self
                    .identities()
                    .identities
                    .get(&steward_id)
                    .map(|rec| rec.applied_nonce + 1)
                    .unwrap_or(1);
                let slug: String = display_name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_lowercase()
                        } else {
                            '-'
                        }
                    })
                    .collect::<String>()
                    .trim_matches('-')
                    .to_string();
                let owner_id = if slug.is_empty() {
                    format!("org_fayger-seat-{next_nonce}")
                } else {
                    format!("org_{slug}-{next_nonce}")
                };
                let create_op = sign_ed25519_operation(
                    &steward_sk,
                    &steward_vk,
                    steward_id,
                    OperationPayload::CreateCoFay {
                        owner: OwnerRef::new(owner_id, OwnerKind::Organization),
                        new_cofay_key: vk,
                    },
                    next_nonce,
                )?;
                match self.submit_signed_operation(create_op, now)? {
                    Applied::CoFayCreated(cid) => cid,
                    _ => {
                        return Err(NodeError::ConsensusInvalid(
                            "expected CoFayCreated during external coFay registration".into(),
                        ))
                    }
                }
            }
        };

        // Seed initial welcome batch of 5 μ (90d horizon) so curMerit = 5.0 μ,
        // minMerit = 2.718281 μ, consumable = 2.281719 μ.
        self.submit_contribution(
            &ident_id,
            ChainId::new("gmc-open-science"),
            Decimal::from_int(5),
            Decimal::from_int(calibrated_influence_duration_secs(90) as i64),
            now,
        )?;

        let role_label = req
            .role_label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| match target_kind {
                IdentityKind::IFay => "External FayGer Identity (iFay)".to_string(),
                IdentityKind::CoFay => "External FayGer Role Seat (coFay)".to_string(),
            });

        let mut meta = build_participant_meta(&ident_id, target_kind, &display_name, &role_label)?;
        meta.external_fay_id = clean_ext_fay_id;
        self.testnet_state_mut().participants.push(meta.clone());

        self.produce_block(now)?;
        self.persist_testnet_wal("register_external_fay")?;

        self.build_external_fay_response(&ident_id, &meta, false, now)
    }

    /// Records a verified contribution for an external or native `iFay`/`coFay` after
    /// running the anti-collusion independent stakeholder filter (`intimacy <= 0.90`),
    /// minting a decaying `MeriToken (μ)` batch, anchoring on L1, and sealing a block
    /// (`POST /api/merit/add`, `gmc_recordContribution`).
    #[allow(clippy::too_many_lines)]
    pub fn record_contribution(&mut self, req: RecordContributionRequest) -> NodeResult<Value> {
        let fay_id_trimmed = req.fay_id.trim().to_string();
        if fay_id_trimmed.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "fay_id must not be empty".into(),
            ));
        }
        let title_trimmed = req.title.trim().to_string();
        if title_trimmed.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "title must not be empty".into(),
            ));
        }
        if req.amount_mu <= 0 || req.amount_mu > 100_000 {
            return Err(NodeError::Core(GmcError::InvalidMintAmount));
        }

        if self
            .resolve_participant_by_any_id(&fay_id_trimmed)
            .is_none()
        {
            let fallback_name = req
                .display_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&fay_id_trimmed)
                .to_string();
            self.register_external_fay(RegisterExternalFayRequest {
                pubkey_hex: None,
                fay_id: Some(fay_id_trimmed.clone()),
                display_name: fallback_name,
                kind: req.kind.clone(),
                role_label: None,
            })?;
        }

        let (contributor_ident, contributor_meta) = self
            .resolve_participant_by_any_id(&fay_id_trimmed)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?;

        let now = self.eval_timestamp(0);
        let contributor_fay = contributor_ident.to_fay_id();

        // Anti-collusion independent stakeholder check (`intimacy <= 0.90`, `>= 7` peers)
        let mut stakeholders_for_antifraud = Vec::new();
        for (cand_id, _) in self.identities().identities.iter() {
            if cand_id == &contributor_ident {
                continue;
            }
            let cand_fay = cand_id.to_fay_id();
            let pocket_merit = self
                .identities()
                .binding
                .pocket_by_key(&cand_fay)
                .map(|p| p.cur_merit(now))
                .unwrap_or(Decimal::ZERO);
            if !pocket_merit.is_positive() {
                continue;
            }
            let intimacy_ratio = match self.relationships().get_edge(&contributor_fay, &cand_fay) {
                Some(edge) => compute_intimacy(edge, now),
                None => Ratio::ZERO,
            };
            stakeholders_for_antifraud.push(Stakeholder::new(cand_fay, intimacy_ratio));
        }
        let _independent_voters = select_voters(
            &stakeholders_for_antifraud,
            stakeholders_for_antifraud.len().max(7),
            0xC0DE_0000u64.wrapping_add(self.l2().next_record_seq()),
        )?;

        let horizon_days = req.horizon_days.clamp(1, 3_650);
        let influence_duration_secs = calibrated_influence_duration_secs(horizon_days);
        let amount_dec = Decimal::from_int(req.amount_mu);
        let domain_chain = if req.domain_chain_id.trim().is_empty() {
            default_domain_chain()
        } else {
            req.domain_chain_id.trim().to_string()
        };

        let contrib_receipt = self.submit_contribution(
            &contributor_ident,
            ChainId::new(domain_chain),
            amount_dec,
            Decimal::from_int(influence_duration_secs as i64),
            now,
        )?;

        let vote_subject = match req.summary.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => format!("{title_trimmed}: {s}"),
            _ => title_trimmed,
        };
        self.anchor_l1_vote_result(VoteResultRecord::new(
            format!("fayger-contrib:{}", contrib_receipt.batch_id),
            vote_subject,
            true,
            now,
        ));

        let block_receipt = self.produce_block(now)?;
        self.persist_testnet_wal("record_contribution")?;

        let pocket = self
            .identities()
            .binding
            .pocket_by_key(&contributor_fay)
            .ok_or(NodeError::Core(GmcError::NotRegistered))?;
        let cur = pocket.cur_merit(now);
        let consumable = pocket.consumable_merit(now);
        let floor = pocket.min_merit();
        let external_or_canonical = contributor_meta
            .external_fay_id
            .clone()
            .unwrap_or_else(|| contributor_meta.canonical_fayid.clone());

        Ok(json!({
            "ok": true,
            "fay_id": external_or_canonical,
            "canonical_fayid": contributor_meta.canonical_fayid,
            "batch_id": contrib_receipt.batch_id,
            "minted_mu": format_decimal(amount_dec),
            "cur_merit_mu": format_decimal(cur),
            "cur_merit_raw": cur.raw(),
            "consumable_merit_mu": format_decimal(consumable),
            "consumable_merit_raw": consumable.raw(),
            "min_merit_floor_mu": format_decimal(floor),
            "min_merit_floor_raw": floor.raw(),
            "block_height": block_receipt.block_height,
            "state_root_hex": self.state_root_hex(),
        }))
    }

    /// Consumes (`消费/消减`) active decaying `MeriToken (μ)` surplus from an `iFay`/`coFay`
    /// pocket for priority or voting priority without transferring to any account and without
    /// ever reducing `minMerit` (`POST /api/merit/consume`, `gmc_consumePriority`).
    #[allow(clippy::too_many_lines)]
    pub fn consume_priority(&mut self, req: ConsumePriorityRequest) -> NodeResult<Value> {
        let fay_id_trimmed = req.fay_id.trim().to_string();
        if fay_id_trimmed.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "fay_id must not be empty".into(),
            ));
        }
        let priority_kind = req.priority_kind.trim().to_string();
        if priority_kind.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "priority_kind must not be empty".into(),
            ));
        }
        let reason = req.reason.trim().to_string();
        if reason.is_empty() {
            return Err(NodeError::RpcInvalidRequest(
                "reason must not be empty".into(),
            ));
        }

        let amount_dec = req
            .amount_mu
            .to_decimal()
            .map_err(NodeError::RpcInvalidRequest)?;
        if !amount_dec.is_positive() {
            return Err(NodeError::Core(GmcError::InvalidMintAmount));
        }

        let Some((ident_id, meta)) = self.resolve_participant_by_any_id(&fay_id_trimmed) else {
            return Err(NodeError::Core(GmcError::NotRegistered));
        };

        let now = self.eval_timestamp(0);
        let fay = ident_id.to_fay_id();

        let (before_cur, floor, after_cur, consumable_rem) = {
            let pocket = self
                .identities_mut()
                .binding
                .pocket_by_key_mut(&fay)
                .ok_or(NodeError::Core(GmcError::NotRegistered))?;
            let before = pocket.cur_merit(now);
            let floor_val = pocket.min_merit();
            pocket.consume_priority(amount_dec, now)?;
            let after = pocket.cur_merit(now);
            let rem = pocket.consumable_merit(now);
            debug_assert_eq!(pocket.min_merit(), floor_val);
            (before, floor_val, after, rem)
        };

        let clean_proposal_id = req
            .proposal_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // If `proposal_id` is supplied and exists, also record the participant's governance ballot!
        let mut newly_passed_prop_idx = None;
        if let Some(ref pid) = clean_proposal_id {
            if let Some(prop_idx) = self
                .testnet_state()
                .proposals
                .iter()
                .position(|p| p.proposal_id == *pid)
            {
                let approve_flag = req.approve.unwrap_or(true);
                let eval_ts = Timestamp::from_secs(
                    self.testnet_state().proposals[prop_idx].eval_timestamp_secs,
                );

                let mut electorate_voters = Vec::new();
                let mut total_merit = Decimal::ZERO;
                for (id, _) in self.identities().identities.iter() {
                    let cand_fay = id.to_fay_id();
                    if let Some(p) = self.identities().binding.pocket_by_key(&cand_fay) {
                        let c = p.cur_merit(eval_ts);
                        if c.is_positive() {
                            total_merit = total_merit.checked_add(c).unwrap_or(total_merit);
                            electorate_voters.push(Voter::new(cand_fay, c));
                        }
                    }
                }

                if total_merit.is_positive() {
                    let voter_cur = self
                        .identities()
                        .binding
                        .pocket_by_key(&fay)
                        .map(|p| p.cur_merit(eval_ts))
                        .unwrap_or(Decimal::ZERO);
                    let voter_ratio = voter_cur.checked_div(total_merit).unwrap_or(Decimal::ZERO);

                    let new_ballot = PersistedProposalBallot {
                        voter_fay_id: fay.as_str().to_string(),
                        voter_canonical_fayid: meta.canonical_fayid.clone(),
                        voter_display_name: meta.display_name.clone(),
                        approve: approve_flag,
                        decayed_merit_raw: voter_cur.raw(),
                        weight_ratio_raw: voter_ratio.raw(),
                        voted_at_secs: eval_ts.as_secs(),
                    };

                    {
                        let prop_mut = &mut self.testnet_state_mut().proposals[prop_idx];
                        prop_mut.total_electorate_merit_raw = total_merit.raw();
                        if let Some(existing) = prop_mut
                            .ballots
                            .iter_mut()
                            .find(|b| b.voter_fay_id == new_ballot.voter_fay_id)
                        {
                            *existing = new_ballot;
                        } else {
                            prop_mut.ballots.push(new_ballot);
                        }
                        let mut refreshed = Vec::with_capacity(prop_mut.ballots.len());
                        for mut b in prop_mut.ballots.clone() {
                            let cur_b = self
                                .identities()
                                .binding
                                .pocket_by_key(&FayID::new(b.voter_fay_id.clone()))
                                .map(|p| p.cur_merit(eval_ts))
                                .unwrap_or(Decimal::ZERO);
                            b.decayed_merit_raw = cur_b.raw();
                            b.weight_ratio_raw = cur_b
                                .checked_div(total_merit)
                                .unwrap_or(Decimal::ZERO)
                                .raw();
                            refreshed.push(b);
                        }
                        self.testnet_state_mut().proposals[prop_idx].ballots = refreshed;
                    }

                    let prop_snap = self.testnet_state().proposals[prop_idx].clone();
                    if let Some(threshold) = Ratio::new(Decimal::from_raw(prop_snap.threshold_raw))
                    {
                        let mut gov = GovernanceModule::new();
                        if let Ok(vote_id) = gov.open_vote(
                            prop_snap.proposal_id.clone(),
                            threshold,
                            electorate_voters,
                        ) {
                            let mut approve_sum = Decimal::ZERO;
                            let mut reject_sum = Decimal::ZERO;
                            for b in &prop_snap.ballots {
                                let m = Decimal::from_raw(b.decayed_merit_raw);
                                if b.approve {
                                    approve_sum = approve_sum.checked_add(m).unwrap_or(approve_sum);
                                } else {
                                    reject_sum = reject_sum.checked_add(m).unwrap_or(reject_sum);
                                }
                                let _ = gov.cast_vote(
                                    vote_id,
                                    &FayID::new(b.voter_fay_id.clone()),
                                    b.approve,
                                );
                            }
                            if let Ok(outcome) = gov.tally(vote_id) {
                                let was_already_passed = prop_snap.status == "passed";
                                let prop_mut = &mut self.testnet_state_mut().proposals[prop_idx];
                                prop_mut.approve_merit_raw = approve_sum.raw();
                                prop_mut.reject_merit_raw = reject_sum.raw();
                                prop_mut.approval_ratio_raw = outcome.approval_ratio.value().raw();
                                if outcome.passed {
                                    prop_mut.status = "passed".to_string();
                                    if !was_already_passed {
                                        newly_passed_prop_idx = Some(prop_idx);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(pidx) = newly_passed_prop_idx {
            let ptitle = self.testnet_state().proposals[pidx].title.clone();
            let pid = self.testnet_state().proposals[pidx].proposal_id.clone();
            self.anchor_l1_vote_result(VoteResultRecord::new(
                format!("gov-proposal:{pid}"),
                ptitle,
                true,
                now,
            ));
        }

        let seq = self.testnet_state().priority_consumptions.len() + 1;
        let consumption_id = format!("cons-{seq:03}");
        self.anchor_l1_vote_result(VoteResultRecord::new(
            format!("priority-consume:{consumption_id}"),
            format!(
                "{priority_kind}:{}:-{}mu:{reason}",
                meta.canonical_fayid,
                format_decimal(amount_dec)
            ),
            true,
            now,
        ));

        let block_receipt = self.produce_block(now)?;
        if let Some(pidx) = newly_passed_prop_idx {
            self.testnet_state_mut().proposals[pidx].anchored_block_height =
                Some(block_receipt.block_height);
        }

        let external_or_canonical = meta
            .external_fay_id
            .clone()
            .unwrap_or_else(|| meta.canonical_fayid.clone());
        let record = PersistedPriorityConsumption {
            consumption_id: consumption_id.clone(),
            fay_id: external_or_canonical.clone(),
            canonical_fayid: meta.canonical_fayid.clone(),
            display_name: meta.display_name,
            priority_kind: priority_kind.clone(),
            reason,
            proposal_id: clean_proposal_id,
            consumed_mu_raw: amount_dec.raw(),
            consumed_mu: format_decimal(amount_dec),
            before_cur_merit_mu: format_decimal(before_cur),
            after_cur_merit_mu: format_decimal(after_cur),
            preserved_min_merit_mu: format_decimal(floor),
            block_height: block_receipt.block_height,
            timestamp_secs: now.as_secs(),
        };
        self.testnet_state_mut()
            .priority_consumptions
            .push(record.clone());
        self.persist_testnet_wal("consume_priority")?;

        Ok(json!({
            "ok": true,
            "consumption_id": consumption_id,
            "fay_id": external_or_canonical,
            "canonical_fayid": meta.canonical_fayid,
            "priority_kind": priority_kind,
            "consumed_mu": format_decimal(amount_dec),
            "consumed_mu_raw": amount_dec.raw(),
            "before_cur_merit_mu": format_decimal(before_cur),
            "before_cur_merit_raw": before_cur.raw(),
            "after_cur_merit_mu": format_decimal(after_cur),
            "after_cur_merit_raw": after_cur.raw(),
            "consumable_merit_mu": format_decimal(consumable_rem),
            "consumable_merit_raw": consumable_rem.raw(),
            "min_merit_floor_mu": format_decimal(floor),
            "min_merit_floor_raw": floor.raw(),
            "block_height": block_receipt.block_height,
            "state_root_hex": self.state_root_hex(),
            "record": record,
        }))
    }
}

fn derive_or_parse_external_vk(pubkey_hex: Option<&str>, fallback_seed_tag: &str) -> VerifyingKey {
    if let Some(raw_hex) = pubkey_hex {
        let trimmed = raw_hex.trim();
        if trimmed.len() == 64 {
            if let Ok(bytes) = hex::decode(trimmed) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    if DalekVerifyingKey::from_bytes(&arr).is_ok() {
                        return VerifyingKey::new(bytes);
                    }
                }
            }
        }
    }
    let seed: [u8; 32] = Sha256::digest(fallback_seed_tag.as_bytes()).into();
    let (_sk, vk) = keypair_from_seed(&seed);
    vk
}

fn build_participant_meta(
    id: &IdentityId,
    kind: IdentityKind,
    display_name: &str,
    role_label: &str,
) -> NodeResult<PersistedParticipantMeta> {
    let canonical_fayid = to_fayid_canonical(id, kind)?;
    Ok(PersistedParticipantMeta {
        scheme_tag: id.scheme_tag().as_str().to_string(),
        key_repr: id.key_repr().to_string(),
        fay_id: id.to_fay_id().as_str().to_string(),
        canonical_fayid,
        display_name: display_name.to_string(),
        kind: match kind {
            IdentityKind::IFay => "ifay".into(),
            IdentityKind::CoFay => "cofay".into(),
        },
        role_label: role_label.to_string(),
        external_fay_id: None,
    })
}
