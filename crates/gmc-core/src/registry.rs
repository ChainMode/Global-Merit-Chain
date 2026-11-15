//! `Chain_Registry` — derivation tree, lifecycle, and `(parentId, domain)` uniqueness.
//!
//! This module implements the **data model** for the GMC derivation tree (design's
//! *Data Models → Chain_Registry 派生树* section) plus its `(parentId, domain)`
//! uniqueness index. It is the storage/accessor foundation that the later registry
//! tasks build on:
//!
//! - task 2.1 (this task): the [`NestedMeritChain`] record, the [`ChainRegistry`]
//!   container with the `(parentId, domain)` index, the `GMC_Base` depth-0 root, and
//!   the insert/lookup/accessor scaffolding.
//! - task 2.2: the `derive` validation algorithm (parent-exists → no-cycle →
//!   depth ≤ 16 → `(parent, domain)` unique) and the `detectCycle` guard.
//! - task 2.3: `getPath`, `setLifecycle`, and `resolveEvaluationMechanism`
//!   (inheritance up the derivation path).
//!
//! ## Field mapping (design Data Models)
//!
//! `NestedMeritChain` mirrors the design record `id / parentId / domain / path /
//! depth / stewards / originType / createdAt / lifecycle / evaluationMechanism /
//! config`. Two fields reference types owned by *other* protocol modules that are
//! authored concurrently (the `Evaluation_Mechanism` lives in `mechanism`, the quota
//! / inflation config in `quota` / `scoring`). To keep this crate compiling without a
//! premature cross-module dependency, those two fields are typed here as the local,
//! opaque placeholders [`EvaluationMechanismRef`] and [`ChainConfigRef`]. Tasks 2.3 /
//! 5.x / 6.x wire the concrete types in once those modules land.
//!
//! ## Requirements covered by task 2.1
//!
//! - **Requirement 1.1**: `GMC_Base` is the depth-0 root recording top-level
//!   contribution categories — see [`ChainRegistry::with_root`] / [`NestedMeritChain::root`].
//! - **Requirement 1.4**: every chain records its domain id, parent id and creation
//!   time — the corresponding [`NestedMeritChain`] fields.
//! - **Requirement 2.4**: every nested chain carries at least one Steward — enforced
//!   at construction by [`NestedMeritChain::new`].
//! - **Requirement 2.9** (uniqueness index foundation): the `(parentId, domain)`
//!   index in [`ChainRegistry`]; full ordered-validation `derive` is task 2.2.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{GmcError, GmcResult};
use crate::types::{ChainId, FayID, Timestamp};

/// Checks whether a candidate Steward [`FayID`] represents a natural-person Human ID.
///
/// Per FayID ADR 0001 / `realign-cofay-ownership-to-fayid`, a Steward holds personal
/// governance accountability and MUST be a natural person (`hid_*` or legacy test
/// human label), NEVER an `iFay`, `coFay`, `Organization`, `opaqueRef`, subkey, or
/// internal `fay1.` machine identity.
pub fn is_valid_human_steward_id(fay_id: &FayID) -> bool {
    let s = fay_id.as_str().trim();
    if s.is_empty() {
        return false;
    }
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "ifay_", "cofay_", "org_", "gmcref_", "dyn_", "vrf_", "grt_", "fay1.",
    ];
    !FORBIDDEN_PREFIXES
        .iter()
        .any(|prefix| s.starts_with(prefix))
}

/// Checks whether a candidate Organization ID string is well-formed for 1:1 subchain
/// binding (`org_<lowercase-slug-or-base32>`).
pub fn is_valid_organization_id(org_id: &str) -> bool {
    let Some(rest) = org_id.strip_prefix("org_") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// How a [`NestedMeritChain`] came into existence (design `originType`).
///
/// The `GMC_Base` root has no origin channel (it is genesis), which is represented
/// by `origin_type == None` on the chain record; every *derived* chain carries a
/// `Some(OriginType)`. The concrete create-path that records the right variant for
/// each channel (vote / steward / institution) is wired in task 20.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OriginType {
    /// Created because a creation proposal reached the chain's governance threshold
    /// (_Requirement 2.1_).
    VoteInitiated,
    /// Created by a qualified Steward submitting a creation request (_Requirement 2.2_).
    StewardInitiated,
    /// Created by an institution whose creation application passed review
    /// (_Requirement 2.3_).
    InstitutionApplied,
}

/// Lifecycle state of a functioning merit chain.
///
/// Chains are born [`Active`](Lifecycle::Active). The state-transition entry point
/// (`setLifecycle`) is task 2.3; this task only carries the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Lifecycle {
    /// Operational and accepting contributions.
    #[default]
    Active,
    /// Temporarily halted; may be reactivated.
    Suspended,
    /// Permanently retired.
    Archived,
}

/// Opaque placeholder for a chain's `Evaluation_Mechanism` reference.
///
/// The real `Evaluation_Mechanism` type is owned by the `mechanism` module (task 5.x),
/// authored concurrently. This minimal local stand-in lets [`NestedMeritChain`] carry
/// the `evaluationMechanism` field (where `None` means "inherit from an ancestor",
/// per _Requirement 3.2_) without a premature cross-module dependency. Tasks 2.3 / 5.x
/// replace it with the concrete type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvaluationMechanismRef(());

impl EvaluationMechanismRef {
    /// Builds the placeholder reference.
    pub const fn placeholder() -> Self {
        EvaluationMechanismRef(())
    }
}

/// Opaque placeholder for a chain's quota / refresh-period / inflation configuration.
///
/// The real `NestedMeritChainConfig` is owned by the `quota` (task 6.x) and `scoring`
/// (task 8.x) modules, authored concurrently. This local stand-in lets
/// [`NestedMeritChain`] carry the `config` field for now; later tasks wire the
/// concrete type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainConfigRef(());

impl ChainConfigRef {
    /// Builds the placeholder config.
    pub const fn placeholder() -> Self {
        ChainConfigRef(())
    }
}

/// A node in the GMC derivation tree (`GMC_Base` root or any `Nested_Merit_Chain`).
///
/// Mirrors the design's `NestedMeritChain` record. Fields are private with read-only
/// accessors so the invariants established at construction (non-empty stewards for
/// derived chains; `path` consistency) cannot be silently broken by callers; mutation
/// entry points (lifecycle, mechanism wiring) are added by tasks 2.3 / 5.x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedMeritChain {
    id: ChainId,
    /// `None` for the `GMC_Base` root; `Some(parent)` for every derived chain
    /// (_Requirement 1.4_).
    parent_id: Option<ChainId>,
    /// Domain identifier this chain owns (_Requirement 1.4_).
    domain: String,
    /// Ordered derivation path from `GMC_Base` down to (and including) this chain
    /// (_Requirement 1.3_). For the root this is `[root_id]`. The
    /// `len(path) == depth + 1` invariant is asserted by Property 1 (task 2.4).
    path: Vec<ChainId>,
    /// Hierarchy depth; `GMC_Base` is `0`, and derived chains are `parent.depth + 1`
    /// (_Requirement 1.7_, bounded by [`MAX_DEPTH`]).
    depth: u32,
    /// Stewards maintaining this chain; a derived chain has at least one
    /// (_Requirement 2.4_).
    stewards: Vec<FayID>,
    /// How this chain was created; `None` for the genesis root (_Requirement 2.1–2.3_).
    origin_type: Option<OriginType>,
    /// On-chain creation time (_Requirement 1.4_).
    created_at: Timestamp,
    /// Lifecycle state (_design Data Models_).
    lifecycle: Lifecycle,
    /// Custom evaluation mechanism; `None` means "inherit from the nearest ancestor
    /// that defines one" (_Requirement 3.2_; resolution is task 2.3).
    evaluation_mechanism: Option<EvaluationMechanismRef>,
    /// Quota / refresh-period / inflation configuration (placeholder; task 6.x/8.x).
    config: Option<ChainConfigRef>,
}

impl NestedMeritChain {
    /// Builds the `GMC_Base` root node at `depth = 0` with `path = [id]` and no parent
    /// (_Requirements 1.1, 1.4_).
    ///
    /// The root is genesis, so its `origin_type` is `None` (it was not created through
    /// any of the three derivation channels). Stewards are accepted as given; the
    /// "≥ 1 steward" rule of _Requirement 2.4_ targets *derived* `Nested_Merit_Chain`s
    /// and is enforced by [`NestedMeritChain::new`].
    pub fn root(
        id: ChainId,
        domain: impl Into<String>,
        stewards: Vec<FayID>,
        created_at: Timestamp,
    ) -> Self {
        let path = vec![id.clone()];
        NestedMeritChain {
            id,
            parent_id: None,
            domain: domain.into(),
            path,
            depth: 0,
            stewards,
            origin_type: None,
            created_at,
            lifecycle: Lifecycle::Active,
            evaluation_mechanism: None,
            config: None,
        }
    }

    /// Builds a derived `Nested_Merit_Chain`.
    ///
    /// The caller supplies the already-computed `depth` and `path` (the `derive`
    /// algorithm of task 2.2 derives them from the parent as `parent.depth + 1` and
    /// `parent.path + [id]`). This constructor enforces the only invariant that is
    /// fully a property of a single chain record at this stage: a derived chain must
    /// carry **at least one Steward** (_Requirement 2.4_); an empty steward set is
    /// rejected with [`GmcError::MissingField`] and nothing is constructed. The
    /// dedicated, channel-aware create path (with steward-qualification / institution
    /// review) is task 20.2.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ChainId,
        parent_id: ChainId,
        domain: impl Into<String>,
        depth: u32,
        path: Vec<ChainId>,
        stewards: Vec<FayID>,
        origin_type: OriginType,
        created_at: Timestamp,
    ) -> GmcResult<Self> {
        if stewards.is_empty() {
            return Err(GmcError::MissingField);
        }
        if !stewards.iter().all(is_valid_human_steward_id) {
            return Err(GmcError::StewardTypeNotAllowed);
        }
        Ok(NestedMeritChain {
            id,
            parent_id: Some(parent_id),
            domain: domain.into(),
            path,
            depth,
            stewards,
            origin_type: Some(origin_type),
            created_at,
            lifecycle: Lifecycle::Active,
            evaluation_mechanism: None,
            config: None,
        })
    }

    /// Attaches a custom evaluation-mechanism reference (builder-style).
    ///
    /// A chain with `None` here inherits its mechanism from the nearest ancestor that
    /// defines one (_Requirement 3.2_); inheritance resolution is task 2.3.
    pub fn with_evaluation_mechanism(mut self, mechanism: EvaluationMechanismRef) -> Self {
        self.evaluation_mechanism = Some(mechanism);
        self
    }

    /// Attaches a configuration reference (builder-style).
    pub fn with_config(mut self, config: ChainConfigRef) -> Self {
        self.config = Some(config);
        self
    }

    /// This chain's identifier.
    pub fn id(&self) -> &ChainId {
        &self.id
    }

    /// This chain's parent id, or `None` if it is the `GMC_Base` root.
    pub fn parent_id(&self) -> Option<&ChainId> {
        self.parent_id.as_ref()
    }

    /// The domain identifier this chain owns (_Requirement 1.4_).
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The ordered derivation path from `GMC_Base` to this chain (_Requirement 1.3_).
    pub fn path(&self) -> &[ChainId] {
        &self.path
    }

    /// Hierarchy depth (`GMC_Base == 0`).
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// The stewards maintaining this chain (_Requirement 2.4_).
    pub fn stewards(&self) -> &[FayID] {
        &self.stewards
    }

    /// How this chain was created, or `None` for the genesis root.
    pub fn origin_type(&self) -> Option<OriginType> {
        self.origin_type
    }

    /// On-chain creation time (_Requirement 1.4_).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Current lifecycle state.
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    /// This chain's own evaluation mechanism, or `None` if it inherits one.
    pub fn evaluation_mechanism(&self) -> Option<&EvaluationMechanismRef> {
        self.evaluation_mechanism.as_ref()
    }

    /// This chain's configuration reference, if set.
    pub fn config(&self) -> Option<&ChainConfigRef> {
        self.config.as_ref()
    }

    /// `true` if this is the `GMC_Base` root (no parent and depth 0).
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none() && self.depth == 0
    }

    /// Sets this chain's lifecycle state (`Active` / `Suspended` / `Archived`).
    ///
    /// This is the in-place mutation entry point for the `lifecycle` field; the
    /// id-addressed, registry-level wrapper is [`ChainRegistry::set_lifecycle`]
    /// (task 2.3). Lifecycle changes are the only mutation a single chain record
    /// admits at this stage — `id` / `parentId` / `path` / `depth` stay immutable so
    /// the derivation-tree invariants established at construction cannot drift.
    pub fn set_lifecycle(&mut self, state: Lifecycle) {
        self.lifecycle = state;
    }
}

/// Input to [`ChainRegistry::derive`] — a request to derive a new
/// `Nested_Merit_Chain` under an existing parent (design's `DeriveRequest`).
///
/// The request carries everything `derive` needs to run its ordered validation and,
/// on success, construct the new chain record. The derived chain's `depth` and `path`
/// are **not** supplied here: `derive` computes them from the parent (as
/// `parent.depth + 1` and `parent.path + [proposed_id]`) so they cannot be forged out
/// of sync with the tree (_Requirements 1.3, 1.7_).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveRequest {
    /// Identifier the new chain should take. For a normal "derive a fresh leaf"
    /// request this is a brand-new id; it also doubles as the subject of the
    /// re-parent cycle guard (_Requirement 1.5_).
    pub proposed_id: ChainId,
    /// The parent chain to derive under; must already exist in the registry
    /// (_Requirement 1.6_) and must be non-empty (_Requirement 2.5_).
    pub parent_id: ChainId,
    /// Domain identifier the new chain will own; must be non-empty (_Requirement 2.5_)
    /// and unique under `parent_id` (_Requirement 2.9_).
    pub domain: String,
    /// Stewards for the new chain; at least one is required (_Requirement 2.4_).
    pub stewards: Vec<FayID>,
    /// How this derivation was initiated (vote / steward / institution).
    pub origin_type: OriginType,
    /// On-chain creation time (_Requirement 1.4_).
    pub created_at: Timestamp,
    /// Optional Organization ID (`org_...`) bound 1:1 to this derived subchain.
    pub organization_id: Option<String>,
}

impl DeriveRequest {
    /// Builds a [`DeriveRequest`] from its parts.
    pub fn new(
        proposed_id: ChainId,
        parent_id: ChainId,
        domain: impl Into<String>,
        stewards: Vec<FayID>,
        origin_type: OriginType,
        created_at: Timestamp,
    ) -> Self {
        DeriveRequest {
            proposed_id,
            parent_id,
            domain: domain.into(),
            stewards,
            origin_type,
            created_at,
            organization_id: None,
        }
    }

    /// Binds a canonical `OrganizationID` (`org_...`) 1:1 to the derived subchain.
    pub fn with_organization_id(mut self, organization_id: impl Into<String>) -> Self {
        self.organization_id = Some(organization_id.into());
        self
    }
}

/// The GMC functioning-merit-chain registry: the derivation tree plus its
/// `(parentId, domain)` uniqueness index.
///
/// This is the storage/accessor foundation for the registry tasks. It stores every
/// [`NestedMeritChain`] keyed by id and maintains a secondary index from
/// `(parentId, domain)` to `ChainId` so that:
///
/// - duplicate `(parentId, domain)` combinations can be detected in O(log n)
///   (the foundation for the _Requirement 2.9_ `DomainConflict` rejection), and
/// - the ordered `derive` validation (task 2.2) and path/inheritance queries
///   (task 2.3) have a consistent store to build on.
///
/// The registry always contains exactly one `GMC_Base` root (established by
/// [`ChainRegistry::with_root`]).
#[derive(Debug, Clone)]
pub struct ChainRegistry {
    /// All chains keyed by their id (`BTreeMap` for deterministic iteration order).
    chains: BTreeMap<ChainId, NestedMeritChain>,
    /// `(parentId, domain) -> ChainId` uniqueness index. The root participates with
    /// `parentId == None`.
    domain_index: BTreeMap<(Option<ChainId>, String), ChainId>,
    /// The `GMC_Base` root id (depth 0).
    root_id: ChainId,
    /// Optional implementation-imposed storage/performance depth cap. Protocol default
    /// is `None` (no fixed depth cap, per `realign-cofay-ownership-to-fayid`).
    max_depth_limit: Option<u32>,
    /// `OrganizationID -> ChainId` 1:1 forward index.
    org_to_chain: BTreeMap<String, ChainId>,
    /// `ChainId -> OrganizationID` 1:1 reverse index.
    chain_to_org: BTreeMap<ChainId, String>,
    /// Per-chain delegated operational manager `iFay`s (orthogonal to human Stewards).
    chain_managers: BTreeMap<ChainId, BTreeSet<FayID>>,
}

impl ChainRegistry {
    /// Creates a registry seeded with the `GMC_Base` depth-0 root (_Requirement 1.1_).
    ///
    /// Returns [`GmcError::MissingField`] if `root` is not actually a root (i.e. it
    /// has a parent or a non-zero depth), so the registry's single-root invariant
    /// holds by construction.
    pub fn with_root(root: NestedMeritChain) -> GmcResult<Self> {
        if !root.is_root() {
            return Err(GmcError::MissingField);
        }
        let root_id = root.id().clone();
        let mut chains = BTreeMap::new();
        let mut domain_index = BTreeMap::new();
        domain_index.insert((None, root.domain().to_owned()), root_id.clone());
        chains.insert(root_id.clone(), root);
        Ok(ChainRegistry {
            chains,
            domain_index,
            root_id,
            max_depth_limit: None,
            org_to_chain: BTreeMap::new(),
            chain_to_org: BTreeMap::new(),
            chain_managers: BTreeMap::new(),
        })
    }

    /// Configures an optional implementation-side maximum derivation depth.
    ///
    /// By protocol rule (`realign-cofay-ownership-to-fayid`), `ChainRegistry` imposes
    /// **no** fixed depth ceiling by default (`None`). If a specific runtime sets an
    /// explicit bound here, exceeding it rejects with [`GmcError::DepthExceeded`] rather
    /// than silently truncating.
    pub fn with_optional_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth_limit = Some(max_depth);
        self
    }

    /// Returns the subchain bound 1:1 to `organization_id`, if any.
    pub fn chain_for_organization(&self, organization_id: &str) -> Option<&ChainId> {
        self.org_to_chain.get(organization_id)
    }

    /// Returns the `OrganizationID` bound 1:1 to `chain_id`, if any.
    pub fn organization_for_chain(&self, chain_id: &ChainId) -> Option<&str> {
        self.chain_to_org.get(chain_id).map(String::as_str)
    }

    /// Grants operational management authority on `chain_id` to an `iFay` manager
    /// without altering the chain's natural-person Steward list.
    pub fn grant_chain_manager(
        &mut self,
        chain_id: &ChainId,
        manager_ifay: FayID,
    ) -> GmcResult<()> {
        if !self.contains(chain_id) {
            return Err(GmcError::ParentNotFound);
        }
        if !manager_ifay.as_str().starts_with("ifay_") {
            return Err(GmcError::OperationNotAllowed);
        }
        self.chain_managers
            .entry(chain_id.clone())
            .or_default()
            .insert(manager_ifay);
        Ok(())
    }

    /// Checks whether `manager` holds operational management authority on `chain_id`.
    pub fn is_chain_manager(&self, chain_id: &ChainId, manager: &FayID) -> bool {
        self.chain_managers
            .get(chain_id)
            .is_some_and(|set| set.contains(manager))
    }

    /// The `GMC_Base` root id (depth 0).
    pub fn root_id(&self) -> &ChainId {
        &self.root_id
    }

    /// The `GMC_Base` root chain record.
    pub fn root(&self) -> &NestedMeritChain {
        self.chains
            .get(&self.root_id)
            .expect("root is established at construction and never removed")
    }

    /// Number of chains currently registered (always `>= 1`, counting the root).
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Always `false`: a registry always holds at least the `GMC_Base` root.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    /// Returns the chain with `id`, if present.
    pub fn get(&self, id: &ChainId) -> Option<&NestedMeritChain> {
        self.chains.get(id)
    }

    /// `true` if a chain with `id` is registered.
    pub fn contains(&self, id: &ChainId) -> bool {
        self.chains.contains_key(id)
    }

    /// Looks up a chain by its `(parentId, domain)` key, returning its id if present.
    ///
    /// Pass `parent_id = None` to look up against the root slot.
    pub fn lookup_by_domain(&self, parent_id: Option<&ChainId>, domain: &str) -> Option<&ChainId> {
        self.domain_index
            .get(&(parent_id.cloned(), domain.to_owned()))
    }

    /// `true` if the `(parentId, domain)` combination is already taken
    /// (the foundation for the _Requirement 2.9_ `DomainConflict` check).
    pub fn contains_domain(&self, parent_id: Option<&ChainId>, domain: &str) -> bool {
        self.lookup_by_domain(parent_id, domain).is_some()
    }

    /// Inserts an already-constructed chain, maintaining the `(parentId, domain)`
    /// uniqueness index.
    ///
    /// This is the low-level, index-maintaining store used by the `derive` algorithm
    /// (task 2.2) after it has run the full ordered validation. It is **atomic**: the
    /// conflict checks below run before any mutation, so a rejected insert leaves the
    /// registry completely unchanged (the design's "fail atomically, state unchanged"
    /// principle):
    ///
    /// - a duplicate `(parentId, domain)` combination is rejected with
    ///   [`GmcError::DomainConflict`] (_Requirement 2.9_);
    /// - re-inserting an existing chain id is also rejected with
    ///   [`GmcError::DomainConflict`] (kept consistent so the id ↔ index mapping never
    ///   diverges; the ordered derive-time guards are task 2.2).
    pub fn insert(&mut self, chain: NestedMeritChain) -> GmcResult<()> {
        let key = (chain.parent_id().cloned(), chain.domain().to_owned());
        if self.chains.contains_key(chain.id()) || self.domain_index.contains_key(&key) {
            return Err(GmcError::DomainConflict);
        }
        let id = chain.id().clone();
        self.domain_index.insert(key, id.clone());
        self.chains.insert(id, chain);
        Ok(())
    }

    /// Derives a new `Nested_Merit_Chain` under an existing parent, running the full
    /// ordered validation of the design's `derive` algorithm.
    ///
    /// The checks run in the **exact** order the design specifies, and any failure
    /// returns its mapped error while leaving the registry **completely unchanged**
    /// (no partial writes — the design's "validate up front, fail atomically" rule):
    ///
    /// 1. **Missing field** — an empty `parent_id` or `domain` is rejected with
    ///    [`GmcError::MissingField`] (_Requirement 2.5_).
    /// 2. **Parent exists** — a `parent_id` not present in the registry is rejected
    ///    with [`GmcError::ParentNotFound`] (_Requirement 1.6_).
    /// 3. **No cycle** — if honouring the request would make a chain its own ancestor
    ///    it is rejected with [`GmcError::CycleConflict`] (_Requirement 1.5_); see
    ///    [`ChainRegistry::detect_cycle`].
    /// 4. **Depth bound** — `new_depth = parent.depth + 1`; if it exceeds
    ///    [`MAX_DEPTH`] the request is rejected with [`GmcError::DepthExceeded`]
    ///    (_Requirement 1.7_).
    /// 5. **Uniqueness** — a duplicate `(parent_id, domain)` is rejected with
    ///    [`GmcError::DomainConflict`] (_Requirement 2.9_).
    ///
    /// On success the new chain is built via [`NestedMeritChain::new`] with
    /// `depth = parent.depth + 1` and `path = parent.path + [proposed_id]`, inserted
    /// through [`ChainRegistry::insert`] (which re-checks uniqueness atomically), and
    /// its id returned. The derivation relationship (parent / path / depth) is thereby
    /// recorded in the registry (_Requirement 1.2_).
    ///
    /// > L1 anchoring of the creation record (_Requirement 2.6_) is a later task
    /// > (18.1 / 20.2); this method intentionally leaves that seam to the
    /// > infrastructure layer and performs only the pure-logic validation + write.
    pub fn derive(&mut self, req: DeriveRequest) -> GmcResult<ChainId> {
        // 1. Missing field: parent id or domain empty (Requirement 2.5).
        if req.parent_id.is_empty() || req.domain.is_empty() {
            return Err(GmcError::MissingField);
        }

        // 2. Parent exists (Requirement 1.6).
        let parent = self.get(&req.parent_id).ok_or(GmcError::ParentNotFound)?;
        let new_depth = parent.depth() + 1;
        let mut new_path = parent.path().to_vec();
        new_path.push(req.proposed_id.clone());

        // 3. No cycle (Requirement 1.5). A brand-new leaf cannot itself form a cycle;
        //    the guard rejects any request where honouring it would make `parent_id`
        //    equal to `proposed_id` or a descendant of `proposed_id`.
        if self.detect_cycle(&req.parent_id, &req.proposed_id) {
            return Err(GmcError::CycleConflict);
        }

        // 4. Optional implementation-side depth bound (protocol imposes no fixed cap).
        if let Some(limit) = self.max_depth_limit {
            if new_depth > limit {
                return Err(GmcError::DepthExceeded);
            }
        }

        // 5. (parent, domain) uniqueness and chain-id uniqueness (Requirement 2.9).
        if self.contains(&req.proposed_id)
            || self.contains_domain(Some(&req.parent_id), &req.domain)
        {
            return Err(GmcError::DomainConflict);
        }

        // 6. Optional OrganizationID <-> subchain 1:1 binding validation (atomic pre-check).
        if let Some(ref org_id) = req.organization_id {
            if !is_valid_organization_id(org_id)
                || self.org_to_chain.contains_key(org_id)
                || self.chain_to_org.contains_key(&req.proposed_id)
            {
                return Err(GmcError::OrganizationBindingConflict);
            }
        }

        // All checks passed: build and atomically insert the new chain (Requirement 1.2).
        let chain = NestedMeritChain::new(
            req.proposed_id.clone(),
            req.parent_id,
            req.domain,
            new_depth,
            new_path,
            req.stewards,
            req.origin_type,
            req.created_at,
        )?;
        self.insert(chain)?;
        if let Some(org_id) = req.organization_id {
            self.org_to_chain
                .insert(org_id.clone(), req.proposed_id.clone());
            self.chain_to_org.insert(req.proposed_id.clone(), org_id);
        }
        Ok(req.proposed_id)
    }

    /// Cycle guard for the derivation tree (_Requirement 1.5_).
    ///
    /// Returns `true` if attaching a chain identified by `proposed_id` under
    /// `target_parent` would create a cycle, i.e. make some chain its own ancestor.
    /// That happens exactly when `target_parent` *is* `proposed_id`, or when
    /// `target_parent` already lives in `proposed_id`'s subtree (so making
    /// `proposed_id` a child of `target_parent` closes a loop).
    ///
    /// Deriving a brand-new leaf (a `proposed_id` not yet in the registry) can never
    /// form a cycle, so this returns `false` in that common case. The guard exists to
    /// reject any **re-parent** request that would move an existing chain underneath
    /// its own descendant. It is implemented by walking the ancestor chain of
    /// `target_parent` (via `path`/`parentId`) toward the root and checking whether
    /// `proposed_id` appears along the way.
    fn detect_cycle(&self, target_parent: &ChainId, proposed_id: &ChainId) -> bool {
        // Direct self-parent: a chain cannot be its own parent.
        if target_parent == proposed_id {
            return true;
        }
        // If `proposed_id` is not a known chain, it has no subtree, so no cycle.
        if !self.contains(proposed_id) {
            return false;
        }
        // Walk from `target_parent` up toward the root; if we encounter `proposed_id`
        // then `target_parent` is in `proposed_id`'s subtree and the edge would loop.
        let mut cursor = Some(target_parent.clone());
        while let Some(current) = cursor {
            if &current == proposed_id {
                return true;
            }
            cursor = self
                .get(&current)
                .and_then(|chain| chain.parent_id().cloned());
        }
        false
    }

    /// Iterates over all registered chains in deterministic id order.
    pub fn iter(&self) -> impl Iterator<Item = &NestedMeritChain> {
        self.chains.values()
    }

    /// Returns the stored, ordered derivation path from the `GMC_Base` root down to
    /// (and including) the chain `id` — the design's `getPath` (_Requirement 1.3_).
    ///
    /// The path is built once at construction / derivation time (`[root]` for the
    /// root, `parent.path + [id]` for a derived chain), so by construction it begins
    /// at `GMC_Base`, ends at the chain itself, and satisfies the
    /// `len(path) == depth + 1` invariant (asserted by Property 1, task 2.4). This
    /// accessor simply exposes that stored path; it performs no recomputation.
    ///
    /// Returns `None` for an `id` that is not registered.
    pub fn get_path(&self, id: &ChainId) -> Option<&[ChainId]> {
        self.chains.get(id).map(|chain| chain.path())
    }

    /// Sets the lifecycle state of the chain `id` (`Active` / `Suspended` /
    /// `Archived`) — the design's `setLifecycle`.
    ///
    /// On success the chain's `lifecycle` is updated in place and `Ok(())` is
    /// returned. An unknown `id` is rejected with [`GmcError::ParentNotFound`] (the
    /// closest existing "no such chain in the registry" code; there is no dedicated
    /// chain-not-found variant) and nothing is mutated — consistent with the design's
    /// "fail atomically, state unchanged" rule.
    pub fn set_lifecycle(&mut self, id: &ChainId, state: Lifecycle) -> GmcResult<()> {
        match self.chains.get_mut(id) {
            Some(chain) => {
                chain.set_lifecycle(state);
                Ok(())
            }
            None => Err(GmcError::ParentNotFound),
        }
    }

    /// Resolves the effective `Evaluation_Mechanism` for the chain `id`, following the
    /// design's inheritance rule (_Requirement 3.2_).
    ///
    /// If the chain defines its own mechanism (`evaluation_mechanism().is_some()`),
    /// that mechanism is returned directly. Otherwise the chain *inherits*: we walk
    /// **up** its derivation `path` toward the `GMC_Base` root, nearest ancestor first,
    /// and return the first ancestor that defines a mechanism. `None` is returned when
    /// neither the chain itself nor any ancestor along the path defines one (and also
    /// for an unknown `id`).
    ///
    /// The stored `path` is root-first (`[GMC_Base, …, id]`), so iterating it in
    /// reverse visits the chain itself first, then its parent, grandparent, … up to
    /// the root — exactly "nearest defining ancestor first".
    pub fn resolve_evaluation_mechanism(&self, id: &ChainId) -> Option<&EvaluationMechanismRef> {
        let path = self.get_path(id)?;
        // Walk from the chain itself up toward GMC_Base (path is root-first, so
        // reverse iteration is nearest-first) and return the first defined mechanism.
        path.iter()
            .rev()
            .find_map(|ancestor_id| self.get(ancestor_id)?.evaluation_mechanism())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a single-steward `GMC_Base` registry for use across tests.
    fn registry_with_root() -> ChainRegistry {
        let root = NestedMeritChain::root(
            ChainId::new("gmc-base"),
            "root",
            vec![FayID::new("founder")],
            Timestamp::from_secs(1_000),
        );
        ChainRegistry::with_root(root).expect("root is a valid depth-0 root")
    }

    /// Convenience: build a depth-1 child of the given parent with one steward.
    fn child_of(parent: &NestedMeritChain, id: &str, domain: &str) -> NestedMeritChain {
        let mut path = parent.path().to_vec();
        path.push(ChainId::new(id));
        NestedMeritChain::new(
            ChainId::new(id),
            parent.id().clone(),
            domain,
            parent.depth() + 1,
            path,
            vec![FayID::new("steward-1")],
            OriginType::StewardInitiated,
            Timestamp::from_secs(2_000),
        )
        .expect("child has at least one steward")
    }

    // --- GMC_Base root (Requirement 1.1) -----------------------------------

    #[test]
    fn gmc_base_root_is_at_depth_zero() {
        let registry = registry_with_root();
        let root = registry.root();
        assert!(root.is_root());
        assert_eq!(root.depth(), 0);
        assert_eq!(root.parent_id(), None);
        assert_eq!(root.origin_type(), None);
        // path starts and ends at the root itself, len == depth + 1.
        assert_eq!(root.path(), &[ChainId::new("gmc-base")]);
        assert_eq!(root.path().len() as u32, root.depth() + 1);
        assert_eq!(registry.root_id(), &ChainId::new("gmc-base"));
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
    }

    #[test]
    fn with_root_rejects_a_non_root_node() {
        // A node that has a parent / non-zero depth is not a valid registry root.
        let non_root = child_of(
            &NestedMeritChain::root(
                ChainId::new("gmc-base"),
                "root",
                vec![FayID::new("founder")],
                Timestamp::from_secs(1),
            ),
            "academic",
            "academia",
        );
        assert_eq!(
            ChainRegistry::with_root(non_root).unwrap_err(),
            GmcError::MissingField
        );
    }

    // --- Chain metadata recorded (Requirement 1.4) -------------------------

    #[test]
    fn derived_chain_records_domain_parent_and_creation_time() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        let child = child_of(registry.root(), "academic", "academia");
        registry.insert(child).expect("first insert succeeds");

        let stored = registry
            .get(&ChainId::new("academic"))
            .expect("chain stored");
        assert_eq!(stored.domain(), "academia");
        assert_eq!(stored.parent_id(), Some(&root_id));
        assert_eq!(stored.created_at(), Timestamp::from_secs(2_000));
        assert_eq!(stored.depth(), 1);
        assert_eq!(stored.lifecycle(), Lifecycle::Active);
        assert_eq!(stored.origin_type(), Some(OriginType::StewardInitiated));
        // path: GMC_Base -> academic, len == depth + 1.
        assert_eq!(
            stored.path(),
            &[ChainId::new("gmc-base"), ChainId::new("academic")]
        );
        assert_eq!(stored.path().len() as u32, stored.depth() + 1);
    }

    // --- (parent, domain) uniqueness index ---------------------------------

    #[test]
    fn lookup_by_parent_and_domain_finds_the_chain() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        let child = child_of(registry.root(), "academic", "academia");
        registry.insert(child).unwrap();

        assert_eq!(
            registry.lookup_by_domain(Some(&root_id), "academia"),
            Some(&ChainId::new("academic"))
        );
        assert!(registry.contains_domain(Some(&root_id), "academia"));
        // A different domain under the same parent is not indexed.
        assert!(!registry.contains_domain(Some(&root_id), "charity"));
        // The same domain string under a *different* parent is a distinct key.
        assert!(!registry.contains_domain(Some(&ChainId::new("academic")), "academia"));
    }

    #[test]
    fn duplicate_parent_domain_is_rejected_and_registry_unchanged() {
        let mut registry = registry_with_root();
        let first = child_of(registry.root(), "academic", "academia");
        registry.insert(first).unwrap();
        let len_before = registry.len();

        // Same (parent, domain) but a different id must be rejected (Requirement 2.9).
        let duplicate = child_of(registry.root(), "academic-2", "academia");
        assert_eq!(registry.insert(duplicate), Err(GmcError::DomainConflict));

        // Registry is unchanged: the rejected id never landed, count is stable.
        let root_id = registry.root_id().clone();
        assert_eq!(registry.len(), len_before);
        assert!(!registry.contains(&ChainId::new("academic-2")));
        // The original chain is still the one indexed under (root, "academia").
        assert_eq!(
            registry.lookup_by_domain(Some(&root_id), "academia"),
            Some(&ChainId::new("academic"))
        );
    }

    #[test]
    fn re_inserting_an_existing_id_is_rejected() {
        let mut registry = registry_with_root();
        let child = child_of(registry.root(), "academic", "academia");
        registry.insert(child.clone()).unwrap();
        let len_before = registry.len();

        // Re-inserting the same id (even with a fresh domain) is a conflict, and the
        // registry must stay consistent.
        let mut path = registry.root().path().to_vec();
        path.push(ChainId::new("academic"));
        let same_id_other_domain = NestedMeritChain::new(
            ChainId::new("academic"),
            registry.root_id().clone(),
            "different-domain",
            1,
            path,
            vec![FayID::new("steward-x")],
            OriginType::VoteInitiated,
            Timestamp::from_secs(3_000),
        )
        .unwrap();
        assert_eq!(
            registry.insert(same_id_other_domain),
            Err(GmcError::DomainConflict)
        );
        let root_id = registry.root_id().clone();
        assert_eq!(registry.len(), len_before);
        // The stale domain was never indexed.
        assert!(!registry.contains_domain(Some(&root_id), "different-domain"));
    }

    // --- At least one Steward (Requirement 2.4) ----------------------------

    #[test]
    fn derived_chain_requires_at_least_one_steward() {
        let registry = registry_with_root();
        let mut path = registry.root().path().to_vec();
        path.push(ChainId::new("no-steward"));
        let result = NestedMeritChain::new(
            ChainId::new("no-steward"),
            registry.root_id().clone(),
            "orphan",
            1,
            path,
            Vec::new(), // no stewards -> rejected
            OriginType::StewardInitiated,
            Timestamp::from_secs(2_000),
        );
        assert_eq!(result, Err(GmcError::MissingField));
    }

    #[test]
    fn derived_chain_with_stewards_is_constructed() {
        let registry = registry_with_root();
        let child = child_of(registry.root(), "academic", "academia");
        assert!(!child.stewards().is_empty());
        assert_eq!(child.stewards(), &[FayID::new("steward-1")]);
    }

    // --- placeholders & builders -------------------------------------------

    #[test]
    fn evaluation_mechanism_and_config_default_to_inherit() {
        let registry = registry_with_root();
        let child = child_of(registry.root(), "academic", "academia");
        // None == "inherit from nearest defining ancestor" (Requirement 3.2).
        assert_eq!(child.evaluation_mechanism(), None);
        assert_eq!(child.config(), None);

        let configured = child
            .with_evaluation_mechanism(EvaluationMechanismRef::placeholder())
            .with_config(ChainConfigRef::placeholder());
        assert_eq!(
            configured.evaluation_mechanism(),
            Some(&EvaluationMechanismRef::placeholder())
        );
        assert_eq!(configured.config(), Some(&ChainConfigRef::placeholder()));
    }

    #[test]
    fn iter_yields_all_chains_including_root() {
        let mut registry = registry_with_root();
        registry
            .insert(child_of(registry.root(), "academic", "academia"))
            .unwrap();
        registry
            .insert(child_of(registry.root(), "charity", "charity"))
            .unwrap();

        let ids: Vec<_> = registry.iter().map(|c| c.id().clone()).collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&ChainId::new("gmc-base")));
        assert!(ids.contains(&ChainId::new("academic")));
        assert!(ids.contains(&ChainId::new("charity")));
    }

    // --- derive: ordered validation algorithm (task 2.2) -------------------

    /// Convenience: a single-steward derive request under `parent_id`.
    fn derive_req(proposed: &str, parent: &ChainId, domain: &str) -> DeriveRequest {
        DeriveRequest::new(
            ChainId::new(proposed),
            parent.clone(),
            domain,
            vec![FayID::new("steward-1")],
            OriginType::StewardInitiated,
            Timestamp::from_secs(5_000),
        )
    }

    #[test]
    fn derive_success_records_depth_path_and_stores_chain() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();

        let id = registry
            .derive(derive_req("academic", &root_id, "academia"))
            .expect("valid derive succeeds");
        assert_eq!(id, ChainId::new("academic"));

        // The derivation relationship is recorded (Requirement 1.2): the new chain is
        // stored with depth = parent.depth + 1 and path = parent.path + [new].
        let stored = registry
            .get(&ChainId::new("academic"))
            .expect("chain stored");
        assert_eq!(stored.depth(), 1);
        assert_eq!(stored.parent_id(), Some(&root_id));
        assert_eq!(stored.domain(), "academia");
        assert_eq!(
            stored.path(),
            &[ChainId::new("gmc-base"), ChainId::new("academic")]
        );
        assert_eq!(stored.path().len() as u32, stored.depth() + 1);
        assert_eq!(registry.len(), 2);

        // A deeper derive composes the path correctly.
        let sub_id = registry
            .derive(derive_req("ai-research", &ChainId::new("academic"), "ai"))
            .expect("nested derive succeeds");
        let sub = registry.get(&sub_id).unwrap();
        assert_eq!(sub.depth(), 2);
        assert_eq!(
            sub.path(),
            &[
                ChainId::new("gmc-base"),
                ChainId::new("academic"),
                ChainId::new("ai-research")
            ]
        );
    }

    #[test]
    fn derive_missing_parent_id_or_domain_is_rejected_and_registry_unchanged() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        let len_before = registry.len();

        // Empty parent id -> MissingField (Requirement 2.5).
        let empty_parent = DeriveRequest::new(
            ChainId::new("x"),
            ChainId::new(""),
            "domain-x",
            vec![FayID::new("s")],
            OriginType::StewardInitiated,
            Timestamp::from_secs(5_000),
        );
        assert_eq!(registry.derive(empty_parent), Err(GmcError::MissingField));

        // Empty domain -> MissingField (Requirement 2.5).
        let empty_domain = derive_req("y", &root_id, "");
        assert_eq!(registry.derive(empty_domain), Err(GmcError::MissingField));

        // Nothing was written.
        assert_eq!(registry.len(), len_before);
        assert!(!registry.contains(&ChainId::new("x")));
        assert!(!registry.contains(&ChainId::new("y")));
    }

    #[test]
    fn derive_under_unknown_parent_is_rejected_and_registry_unchanged() {
        let mut registry = registry_with_root();
        let len_before = registry.len();

        // Parent not in the registry -> ParentNotFound (Requirement 1.6).
        let orphan = derive_req("orphan", &ChainId::new("ghost-parent"), "domain");
        assert_eq!(registry.derive(orphan), Err(GmcError::ParentNotFound));

        assert_eq!(registry.len(), len_before);
        assert!(!registry.contains(&ChainId::new("orphan")));
    }

    #[test]
    fn derive_has_no_fixed_depth_ceiling_by_default_and_honors_optional_impl_bound() {
        let mut registry = registry_with_root();
        let mut parent = registry.root_id().clone();

        // Protocol default: depth 17..=20 succeeds without arbitrary cap.
        for depth in 1..=20u32 {
            let id = format!("level-{depth}");
            let domain = format!("domain-{depth}");
            let new_id = registry
                .derive(derive_req(&id, &parent, &domain))
                .unwrap_or_else(|e| panic!("derive at depth {depth} should succeed: {e}"));
            assert_eq!(registry.get(&new_id).unwrap().depth(), depth);
            parent = new_id;
        }
        assert_eq!(registry.get(&parent).unwrap().depth(), 20);

        // Implementation-configured explicit bound rejects cleanly with DepthExceeded.
        let mut bounded = registry_with_root().with_optional_max_depth(3);
        let mut p = bounded.root_id().clone();
        for d in 1..=3u32 {
            p = bounded
                .derive(derive_req(&format!("b-{d}"), &p, &format!("dom-{d}")))
                .unwrap();
        }
        let len_before = bounded.len();
        assert_eq!(
            bounded.derive(derive_req("b-4", &p, "dom-4")),
            Err(GmcError::DepthExceeded)
        );
        assert_eq!(bounded.len(), len_before);
    }

    #[test]
    fn derive_duplicate_parent_domain_is_rejected_and_registry_unchanged() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        let len_before = registry.len();

        // Same (parent, domain), different id -> DomainConflict (Requirement 2.9).
        let duplicate = derive_req("academic-2", &root_id, "academia");
        assert_eq!(registry.derive(duplicate), Err(GmcError::DomainConflict));

        // The existing chain is preserved and the rejected id never landed.
        assert_eq!(registry.len(), len_before);
        assert!(!registry.contains(&ChainId::new("academic-2")));
        assert_eq!(
            registry.lookup_by_domain(Some(&root_id), "academia"),
            Some(&ChainId::new("academic"))
        );
    }

    #[test]
    fn derive_without_steward_is_rejected_and_registry_unchanged() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        let len_before = registry.len();

        // A derived chain must carry at least one Steward (Requirement 2.4); the
        // ordered checks pass but NestedMeritChain::new rejects the empty set, and the
        // registry stays unchanged.
        let no_steward = DeriveRequest::new(
            ChainId::new("no-steward"),
            root_id.clone(),
            "lonely",
            Vec::new(),
            OriginType::StewardInitiated,
            Timestamp::from_secs(5_000),
        );
        assert_eq!(registry.derive(no_steward), Err(GmcError::MissingField));
        assert_eq!(registry.len(), len_before);
        assert!(!registry.contains(&ChainId::new("no-steward")));
        assert!(!registry.contains_domain(Some(&root_id), "lonely"));
    }

    #[test]
    fn derive_rejects_self_parent_cycle_and_registry_unchanged() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        let len_before = registry.len();

        // A request whose proposed_id equals its own parent forms a trivial cycle
        // (Requirement 1.5).
        let self_parent = derive_req("academic", &ChainId::new("academic"), "other");
        assert_eq!(registry.derive(self_parent), Err(GmcError::CycleConflict));
        assert_eq!(registry.len(), len_before);
    }

    #[test]
    fn derive_rejects_reparent_into_own_subtree_and_registry_unchanged() {
        // Build root -> academic -> ai-research, then attempt to "re-parent" academic
        // under its own descendant ai-research. Honouring it would make academic its
        // own ancestor, so detect_cycle must reject it (Requirement 1.5) and leave the
        // registry unchanged.
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        registry
            .derive(derive_req("ai-research", &ChainId::new("academic"), "ai"))
            .unwrap();
        let len_before = registry.len();
        let academic_before = registry.get(&ChainId::new("academic")).cloned().unwrap();

        let reparent = derive_req("academic", &ChainId::new("ai-research"), "reparented");
        assert_eq!(registry.derive(reparent), Err(GmcError::CycleConflict));

        // Registry unchanged: count stable and the original "academic" record intact.
        assert_eq!(registry.len(), len_before);
        assert_eq!(
            registry.get(&ChainId::new("academic")).unwrap(),
            &academic_before
        );
        assert!(!registry.contains_domain(Some(&ChainId::new("ai-research")), "reparented"));
    }

    #[test]
    fn detect_cycle_allows_fresh_leaf_under_descendant_position() {
        // A brand-new (not-yet-registered) proposed_id can never form a cycle, even
        // when derived under a deep descendant.
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        // proposed_id "fresh" is new, parent is the existing "academic": no cycle.
        assert!(!registry.detect_cycle(&ChainId::new("academic"), &ChainId::new("fresh")));
        // And the corresponding derive succeeds.
        assert!(registry
            .derive(derive_req(
                "fresh",
                &ChainId::new("academic"),
                "fresh-domain"
            ))
            .is_ok());
    }

    // --- get_path / set_lifecycle / resolve_evaluation_mechanism (task 2.3) ---

    #[test]
    fn get_path_returns_ordered_root_to_chain_path() {
        // Build root -> academic -> ai-research and check getPath (Requirement 1.3).
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        registry
            .derive(derive_req("ai-research", &ChainId::new("academic"), "ai"))
            .unwrap();

        // Root path is just [root]; len == depth + 1.
        assert_eq!(registry.get_path(&root_id), Some(&[root_id.clone()][..]));

        // A depth-2 chain's path is ordered GMC_Base -> academic -> ai-research.
        let sub = registry.get(&ChainId::new("ai-research")).unwrap();
        let path = registry
            .get_path(&ChainId::new("ai-research"))
            .expect("path for a registered chain");
        assert_eq!(
            path,
            &[
                ChainId::new("gmc-base"),
                ChainId::new("academic"),
                ChainId::new("ai-research"),
            ]
        );
        // First element is the root, last is the chain itself, len == depth + 1.
        assert_eq!(path.first(), Some(&root_id));
        assert_eq!(path.last(), Some(&ChainId::new("ai-research")));
        assert_eq!(path.len() as u32, sub.depth() + 1);

        // Unknown id -> None.
        assert_eq!(registry.get_path(&ChainId::new("ghost")), None);
    }

    #[test]
    fn set_lifecycle_changes_state_and_errors_on_unknown_id() {
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        let academic = ChainId::new("academic");

        // Chains are born Active.
        assert_eq!(
            registry.get(&academic).unwrap().lifecycle(),
            Lifecycle::Active
        );

        // Active -> Suspended -> Archived all take effect.
        registry
            .set_lifecycle(&academic, Lifecycle::Suspended)
            .expect("known chain lifecycle update succeeds");
        assert_eq!(
            registry.get(&academic).unwrap().lifecycle(),
            Lifecycle::Suspended
        );
        registry
            .set_lifecycle(&academic, Lifecycle::Archived)
            .expect("known chain lifecycle update succeeds");
        assert_eq!(
            registry.get(&academic).unwrap().lifecycle(),
            Lifecycle::Archived
        );

        // Unknown id -> error, and nothing else changes.
        let len_before = registry.len();
        assert_eq!(
            registry.set_lifecycle(&ChainId::new("ghost"), Lifecycle::Suspended),
            Err(GmcError::ParentNotFound)
        );
        assert_eq!(registry.len(), len_before);
        assert_eq!(
            registry.get(&academic).unwrap().lifecycle(),
            Lifecycle::Archived
        );
    }

    /// Convenience: a single-steward child of `parent` carrying its own placeholder
    /// evaluation mechanism (i.e. a chain that *defines* a mechanism).
    fn child_with_mechanism(parent: &NestedMeritChain, id: &str, domain: &str) -> NestedMeritChain {
        child_of(parent, id, domain)
            .with_evaluation_mechanism(EvaluationMechanismRef::placeholder())
    }

    #[test]
    fn resolve_evaluation_mechanism_returns_own_when_defined() {
        // A chain that defines its own mechanism resolves to that mechanism directly,
        // not to any ancestor's (Requirement 3.2).
        let mut registry = registry_with_root();
        let own = child_with_mechanism(registry.root(), "academic", "academia");
        registry.insert(own).unwrap();

        let resolved = registry
            .resolve_evaluation_mechanism(&ChainId::new("academic"))
            .expect("a chain defining its own mechanism resolves to it");
        let own_ref = registry
            .get(&ChainId::new("academic"))
            .unwrap()
            .evaluation_mechanism()
            .unwrap();
        // It is exactly this chain's own stored mechanism (same storage location).
        assert!(std::ptr::eq(resolved, own_ref));
    }

    #[test]
    fn resolve_evaluation_mechanism_inherits_nearest_defining_ancestor() {
        // Build root(none) -> a(mech) -> b(mech) -> c(none). Resolving `c` must inherit
        // the NEAREST defining ancestor `b`, not the farther `a` (Requirement 3.2).
        let mut registry = registry_with_root();
        let a = child_with_mechanism(registry.root(), "a", "a-domain");
        registry.insert(a).unwrap();
        let b = child_with_mechanism(registry.get(&ChainId::new("a")).unwrap(), "b", "b-domain");
        registry.insert(b).unwrap();
        // `c` defines no mechanism of its own (plain child).
        let c = child_of(registry.get(&ChainId::new("b")).unwrap(), "c", "c-domain");
        registry.insert(c).unwrap();

        let resolved = registry
            .resolve_evaluation_mechanism(&ChainId::new("c"))
            .expect("c inherits from the nearest defining ancestor");
        let b_ref = registry
            .get(&ChainId::new("b"))
            .unwrap()
            .evaluation_mechanism()
            .unwrap();
        let a_ref = registry
            .get(&ChainId::new("a"))
            .unwrap()
            .evaluation_mechanism()
            .unwrap();
        // Nearest-first: resolves to `b`'s mechanism, not `a`'s (placeholders compare
        // equal by value, so identity via ptr::eq is what proves "nearest").
        assert!(std::ptr::eq(resolved, b_ref));
        assert!(!std::ptr::eq(resolved, a_ref));

        // `b` itself, defining its own mechanism, resolves to its own (not `a`'s).
        let resolved_b = registry
            .resolve_evaluation_mechanism(&ChainId::new("b"))
            .unwrap();
        assert!(std::ptr::eq(resolved_b, b_ref));
    }

    #[test]
    fn resolve_evaluation_mechanism_is_none_when_no_chain_on_path_defines_one() {
        // No chain along root -> academic -> ai-research defines a mechanism.
        let mut registry = registry_with_root();
        let root_id = registry.root_id().clone();
        registry
            .derive(derive_req("academic", &root_id, "academia"))
            .unwrap();
        registry
            .derive(derive_req("ai-research", &ChainId::new("academic"), "ai"))
            .unwrap();

        assert_eq!(
            registry.resolve_evaluation_mechanism(&ChainId::new("ai-research")),
            None
        );
        assert_eq!(registry.resolve_evaluation_mechanism(&root_id), None);
        // Unknown id resolves to None as well.
        assert_eq!(
            registry.resolve_evaluation_mechanism(&ChainId::new("ghost")),
            None
        );
    }
}
