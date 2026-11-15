//! `Retroactive_Review_Module` — retroactive declaration intake, evidence checks & voting.
//!
//! This module implements **tasks 15.1 + 15.2**:
//!
//! - **Task 15.1 (intake):** receiving a [`RetroactiveDeclaration`] for a contribution
//!   that already happened but was never registered up front, validating its required
//!   fields and the *replayability* of its evidence, and — only when those checks pass
//!   — storing it with review status [`ReviewStatus::Pending`].
//! - **Task 15.2 (threshold + voting):** applying the stricter retroactive pass
//!   threshold [`retro_threshold`] (`max(regular, 2/3)`, strictly above the regular
//!   threshold) and resolving an already-tallied stakeholder vote into
//!   [`ReviewStatus::Approved`] (mint downstream) or [`ReviewStatus::Rejected`] (no
//!   mint), with a placeholder seam to anchor the outcome to L1.
//!
//! It realises the design's `Retroactive_Review_Module` (see the design's *Components
//! and Interfaces* / *Data Models* sections and flow 3, "事后申报审核投票").
//!
//! ## Requirements covered
//!
//! Task 15.1 (intake):
//!
//! - **Requirement 10.1**: when a declaration carries a contributor id, a chain id, a
//!   description of the already-occurred contribution, an occurrence time, **and** a
//!   replayable evidence reference, a declaration record is created with review status
//!   "待审核" ([`ReviewStatus::Pending`]).
//! - **Requirement 10.2**: every declaration must carry **at least one** replayable
//!   evidence reference that points to an on-chain record or external verifiable
//!   record a reviewer can **independently access and verify**.
//! - **Requirement 10.8**: if no evidence reference passes replayability validation
//!   (none present, or none independently accessible/verifiable), the declaration is
//!   rejected with [`GmcError::EvidenceInvalid`] and is **not** pushed into the voting
//!   flow.
//!
//! Task 15.2 (threshold + voting):
//!
//! - **Requirement 10.3**: the retroactive threshold is
//!   `retro = max(regular, 2/3)` and **strictly greater** than the regular threshold
//!   (see [`retro_threshold`]).
//! - **Requirement 10.5**: when the weighted approval is below the retro threshold the
//!   declaration is marked [`ReviewStatus::Rejected`] and **no MeriToken is minted**.
//! - **Requirement 10.6**: when the weighted approval reaches the retro threshold the
//!   declaration is marked [`ReviewStatus::Approved`]; the actual three-dimension mint
//!   is performed **downstream** by the integration layer (`Scoring_Engine` +
//!   `Minting_Service`).
//! - **Requirement 10.7**: a placeholder seam
//!   ([`RetroactiveReviewModule::anchor_outcome`]) anchors the review status + vote
//!   result to L1 (real settlement write wired in task 18.1).
//!
//! ## Decoupling from `AntiFraud_Engine` / `Governance_Module` (Requirement 10.4)
//!
//! Requirement 10.4 (apply high-intimacy exclusion + curMerit weighting in the retro
//! vote) is realised by `AntiFraud_Engine::select_voters` (exclude intimacy > 0.9,
//! sample ≥ 7 stakeholders) and `Governance_Module` weighted voting (curMerit-weighted,
//! ZK-private). To avoid tight coupling and concurrent-edit risk, this module does
//! **not** import or drive those modules: it takes the **already-tallied** weighted
//! approval ratio as an input to
//! [`resolve_vote`](RetroactiveReviewModule::resolve_vote). The integration layer (task
//! 20.1) selects voters and tallies the ZK-private weighted vote, then calls
//! `resolve_vote`.
//!
//! ## Independence from `recording.rs`
//!
//! `recording.rs` defines its own minimal `EvidenceRef` (just `uri`/`hash`) for the
//! standard recording flow. The retroactive module needs the extra *replayability*
//! semantics (Requirement 10.2/10.8), so it defines its **own** [`EvidenceRef`] here
//! rather than importing across modules. The two are deliberately separate types.

use std::collections::BTreeMap;

use crate::error::{GmcError, GmcResult};
use crate::types::{ChainId, Decimal, FayID, Ratio, Timestamp};

/// A contribution-evidence reference attached to a [`RetroactiveDeclaration`].
///
/// Models the design data-model `EvidenceRef` for the retroactive-review module:
///
/// - `uri` — the locator of the evidence: an on-chain record reference, or an external
///   verifiable record (CID / URL).
/// - `hash` — the content hash a reviewer uses to **verify** the referenced material.
/// - `replayable` — whether a reviewer can **independently access and verify** the
///   evidence (Requirement 10.2). "Replayable" is exactly this property: an
///   independent reviewer can re-access the source and re-check it against the hash.
///
/// A reference only counts toward acceptance when it is [`is_replayable`] — see that
/// method for the precise rule.
///
/// [`is_replayable`]: EvidenceRef::is_replayable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    uri: String,
    hash: String,
    replayable: bool,
}

impl EvidenceRef {
    /// Builds an evidence reference from its locator, content hash and replayability.
    pub fn new(uri: impl Into<String>, hash: impl Into<String>, replayable: bool) -> Self {
        EvidenceRef {
            uri: uri.into(),
            hash: hash.into(),
            replayable,
        }
    }

    /// The locator (on-chain reference, or external CID/URL).
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The content hash used to verify the referenced material.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Whether the submitter flagged this reference as independently accessible/verifiable.
    pub fn replayable_flag(&self) -> bool {
        self.replayable
    }

    /// Whether this reference passes replayability validation (Requirement 10.2/10.8).
    ///
    /// A reference is replayable — i.e. a reviewer can **independently access and
    /// verify** it — only when **all** of the following hold:
    ///
    /// - it is flagged `replayable == true`,
    /// - it carries a non-empty `uri` (so the reviewer can actually *access* it), and
    /// - it carries a non-empty `hash` (so the reviewer can actually *verify* it).
    ///
    /// A reference missing its locator or hash cannot be independently checked, so it
    /// fails this rule even if flagged `replayable`.
    pub fn is_replayable(&self) -> bool {
        self.replayable && !self.uri.is_empty() && !self.hash.is_empty()
    }
}

/// Review lifecycle state of a [`RetroactiveDeclaration`] (design `reviewStatus`).
///
/// A freshly accepted declaration is [`Pending`](ReviewStatus::Pending) ("待审核").
/// Task 15.2's voting moves it to [`Approved`](ReviewStatus::Approved) (vote passed →
/// mint) or [`Rejected`](ReviewStatus::Rejected) (vote failed → no mint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReviewStatus {
    /// Accepted into review, awaiting the stakeholder vote (initial state, R10.1).
    Pending,
    /// Approved by the retroactive vote (task 15.2; mint gate, R10.6).
    Approved,
    /// Rejected — vote did not reach the retro threshold (task 15.2; R10.5).
    Rejected,
}

/// Opaque identifier of a stored [`RetroactiveDeclaration`].
///
/// Allocated by [`RetroactiveReviewModule::submit`] (`retro-<n>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclarationId(String);

impl DeclarationId {
    /// Builds a [`DeclarationId`] from any string-like value.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        DeclarationId(id.into())
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for DeclarationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Input to [`RetroactiveReviewModule::submit`] — a contributor's retroactive claim.
///
/// Mirrors the design data model `RetroactiveDeclaration`'s submitter-supplied fields.
/// The `id`, `review_status` and `vote_id` are assigned by the module on acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroactiveApplication {
    /// The contributor making the retroactive claim (required, non-empty — R10.1).
    pub contributor_id: FayID,
    /// The merit chain the contribution belongs to (required, non-empty — R10.1).
    pub chain_id: ChainId,
    /// Description of the already-occurred contribution (required, non-empty — R10.1).
    pub description: String,
    /// On-chain time at which the contribution occurred (required — R10.1). `Timestamp`
    /// is value-typed, so it is always present; no separate presence check is needed.
    pub occurred_at: Timestamp,
    /// Evidence references; at least one must be replayable (R10.2/10.8).
    pub evidence_refs: Vec<EvidenceRef>,
}

impl RetroactiveApplication {
    /// Builds a [`RetroactiveApplication`] from its parts.
    pub fn new(
        contributor_id: FayID,
        chain_id: ChainId,
        description: impl Into<String>,
        occurred_at: Timestamp,
        evidence_refs: Vec<EvidenceRef>,
    ) -> Self {
        RetroactiveApplication {
            contributor_id,
            chain_id,
            description: description.into(),
            occurred_at,
            evidence_refs,
        }
    }
}

/// A stored retroactive declaration record (design data model `RetroactiveDeclaration`).
///
/// Created by [`RetroactiveReviewModule::submit`] once intake + evidence validation
/// pass. Fields are private with read-only accessors so the review status can only be
/// advanced through the controlled flow (task 15.2's voting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroactiveDeclaration {
    id: DeclarationId,
    contributor_id: FayID,
    chain_id: ChainId,
    description: String,
    occurred_at: Timestamp,
    evidence_refs: Vec<EvidenceRef>,
    review_status: ReviewStatus,
    /// Set when task 15.2 resolves a vote for this declaration; `None` at intake.
    ///
    /// Held as an opaque `String` handle on purpose: this module must not depend on
    /// `governance.rs` internals (e.g. its `VoteId`). Task 15.2 records the
    /// already-tallied vote's handle here when [`resolve_vote`] is called.
    ///
    /// [`resolve_vote`]: RetroactiveReviewModule::resolve_vote
    vote_id: Option<String>,
    /// Whether this declaration's review status + vote result have been anchored to
    /// L1 (Requirement 10.7). A documented placeholder seam: the *real* settlement-
    /// layer write is wired in task 18.1, so here this is only flipped by
    /// [`RetroactiveReviewModule::anchor_outcome`] to mark "anchor requested".
    anchored: bool,
}

impl RetroactiveDeclaration {
    /// This declaration's identifier.
    pub fn id(&self) -> &DeclarationId {
        &self.id
    }

    /// The contributor who filed this declaration.
    pub fn contributor_id(&self) -> &FayID {
        &self.contributor_id
    }

    /// The merit chain this declaration targets.
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Description of the already-occurred contribution.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// On-chain time the contribution occurred.
    pub fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    /// The evidence references attached to this declaration.
    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }

    /// Current review status (initially [`ReviewStatus::Pending`], R10.1).
    pub fn review_status(&self) -> ReviewStatus {
        self.review_status
    }

    /// The associated vote handle, or `None` before task 15.2 resolves a vote.
    pub fn vote_id(&self) -> Option<&str> {
        self.vote_id.as_deref()
    }

    /// Whether this declaration's outcome has been anchored to L1 (Requirement 10.7).
    ///
    /// This is placeholder bookkeeping for the L1-anchoring seam: it is set by
    /// [`RetroactiveReviewModule::anchor_outcome`] and reflects only that anchoring was
    /// *requested*; the real settlement-layer write is wired in task 18.1.
    pub fn anchored(&self) -> bool {
        self.anchored
    }
}

/// The smallest fixed-point [`Decimal`] (6 fractional digits) that is **not below**
/// the exact two-thirds (`2/3 = 0.6666…`) lower bound the retroactive threshold must
/// clear (Requirement 10.3 — "不低于…三分之二（约 66.7%）").
///
/// The exact `2/3` is not representable in 6-dp fixed point: truncating division
/// yields `0.666666`, which is *strictly below* the real `2/3`. To guarantee the retro
/// threshold is genuinely **≥ 2/3** we round **up** to `0.666667`. The Property 22 test
/// (task 15.4) should compare against this same constant rather than recomputing
/// `2/3`, so the truncation direction is unambiguous.
pub const RETRO_TWO_THIRDS_FLOOR: Decimal = Decimal::from_raw(666_667);

/// One unit in the last place (ulp) of the fixed-point [`Decimal`] scale (`0.000001`).
///
/// This is the smallest representable positive increment; [`retro_threshold`] adds it
/// to a regular threshold that already meets or exceeds the `2/3` floor so the retro
/// threshold stays **strictly greater** than the regular one.
const RETRO_ULP: Decimal = Decimal::from_raw(1);

/// Computes the **retroactive** pass threshold from a chain's **regular** contribution
/// threshold (Requirement 10.3, design "事后申报流程要点").
///
/// Definition: `retro_threshold(regular) = max(RETRO_TWO_THIRDS_FLOOR, regular + ulp)`,
/// realised branch-wise:
///
/// - **`regular < 2/3`** → the threshold is the `2/3` floor
///   ([`RETRO_TWO_THIRDS_FLOOR`]). Since `regular` is strictly below the floor, the
///   floor is automatically strictly greater than `regular`.
/// - **`regular >= 2/3`** → `max(regular, 2/3) == regular`, which would *not* be
///   strictly greater than `regular`. To honour Requirement 10.3's "**严格高于**常规
///   阈值" (strictly higher) we bump by one [`RETRO_ULP`], i.e. `regular + 0.000001`.
///
/// This yields a value that simultaneously satisfies the three conditions the
/// Property 22 test (task 15.4) validates, for every regular threshold in the open
/// interval `(0, 1)`:
///
/// 1. `retro >= 2/3` (it is never below [`RETRO_TWO_THIRDS_FLOOR`]),
/// 2. `retro >= max(regular, 2/3)`, and
/// 3. `retro > regular` (strictly higher).
///
/// > **Boundary note.** A chain's `consensusThreshold` may be exactly `1` (Requirement
/// > 3.3 admits `(0, 1]`). No value in `[0, 1]` can be *strictly* greater than `1`, so
/// > there `retro` saturates at [`Ratio::ONE`] (strict-greater is unattainable). This
/// > degenerate point lies outside Property 22's `(0, 1)` domain, where the bump always
/// > stays within range (`0.999999 + ulp = 1.0`).
pub fn retro_threshold(regular: Ratio) -> Ratio {
    if regular.value() < RETRO_TWO_THIRDS_FLOOR {
        // regular strictly below the 2/3 floor: the floor is the retro threshold and is
        // strictly greater than regular by construction.
        Ratio::new(RETRO_TWO_THIRDS_FLOOR).expect("2/3 floor lies within [0, 1]")
    } else {
        // regular >= 2/3: bump by one ulp so retro is strictly greater than regular.
        // checked_add cannot overflow i128 here; if the bump would exceed 1 (only when
        // regular == 1, outside Property 22's domain) saturate at Ratio::ONE.
        match regular.value().checked_add(RETRO_ULP) {
            Some(bumped) => Ratio::new(bumped).unwrap_or(Ratio::ONE),
            None => Ratio::ONE,
        }
    }
}

/// The retroactive-declaration intake & review service (design `Retroactive_Review_Module`).
///
/// Task 15.1 implements its **intake**: [`submit`](RetroactiveReviewModule::submit)
/// validates required fields and evidence replayability, and on success stores a
/// [`RetroactiveDeclaration`] with status [`ReviewStatus::Pending`]. All mutating entry
/// points are **atomic**: validation runs before any write, so a rejected application
/// leaves the store unchanged and is never pushed into voting (R10.8).
///
/// Task 15.2 adds the **vote-resolution** step
/// ([`resolve_vote`](RetroactiveReviewModule::resolve_vote)): given an
/// already-tallied weighted approval ratio and the chain's regular threshold, it
/// applies the stricter retroactive threshold [`retro_threshold`] and advances the
/// declaration to [`ReviewStatus::Approved`] (vote passed → mint downstream, R10.6) or
/// [`ReviewStatus::Rejected`] (vote failed → mint nothing, R10.5).
///
/// > **Decoupling (Requirements 10.4 / 11.x).** This module does **not** import
/// > `AntiFraud_Engine` or `Governance_Module`. The integration layer (task 20.1) is
/// > responsible for selecting voters via `AntiFraud_Engine::select_voters` (exclude
/// > intimacy > 0.9, sample ≥ 7 stakeholders) and tallying via `Governance_Module`
/// > (curMerit-weighted, ZK-private) **before** calling
/// > [`resolve_vote`](RetroactiveReviewModule::resolve_vote) with the resulting
/// > `weighted_approval`. Keeping the tally an input avoids tight coupling and lets
/// > this L1 module stay pure logic.
///
/// > **Minting & anchoring seams.** The actual three-dimension mint on approval
/// > (R10.6) is invoked **downstream** by the integration layer (`Scoring_Engine` +
/// > `Minting_Service`) after a declaration reaches [`ReviewStatus::Approved`]; it is
/// > intentionally not driven here. Anchoring the review status + vote result to L1
/// > (R10.7) is a documented placeholder
/// > ([`anchor_outcome`](RetroactiveReviewModule::anchor_outcome)); the real settlement
/// > write is wired in task 18.1.
#[derive(Debug, Clone, Default)]
pub struct RetroactiveReviewModule {
    /// Stored declarations keyed by id (`BTreeMap` for deterministic order).
    declarations: BTreeMap<DeclarationId, RetroactiveDeclaration>,
    /// Monotonic sequence used to allocate fresh [`DeclarationId`]s.
    next_seq: u64,
}

impl RetroactiveReviewModule {
    /// Creates an empty retroactive-review module.
    pub fn new() -> Self {
        RetroactiveReviewModule {
            declarations: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Receives and validates a retroactive declaration.
    ///
    /// Validation order (all checks run before any write, so rejection is side-effect
    /// free and the application never enters voting):
    ///
    /// 1. **Required fields (Requirement 10.1):** `contributor_id`, `chain_id` and
    ///    `description` must be non-empty. (`occurred_at` is value-typed and therefore
    ///    always present.) A missing core field is rejected with
    ///    [`GmcError::FieldValidation`].
    /// 2. **Evidence replayability (Requirements 10.2, 10.8):** at least one evidence
    ///    reference must be [`EvidenceRef::is_replayable`] — flagged replayable with a
    ///    non-empty locator *and* hash so a reviewer can independently access and
    ///    verify it. If none qualifies (no evidence at all, or none replayable), the
    ///    application is rejected with [`GmcError::EvidenceInvalid`].
    ///
    /// On success a [`RetroactiveDeclaration`] is created with
    /// [`ReviewStatus::Pending`] and `vote_id = None` (R10.1), stored, and its
    /// [`DeclarationId`] returned. The id counter only advances on success.
    ///
    /// # Errors
    ///
    /// - [`GmcError::FieldValidation`] — a required core field is empty (R10.1).
    /// - [`GmcError::EvidenceInvalid`] — no replayable, independently verifiable
    ///   evidence reference is present (R10.2, R10.8). The application is **not** pushed
    ///   into the voting flow.
    pub fn submit(&mut self, application: RetroactiveApplication) -> GmcResult<DeclarationId> {
        // 1. Required-field validation (Requirement 10.1). occurred_at is value-typed
        //    (always present), so only the string-backed fields need a presence check.
        if application.contributor_id.is_empty()
            || application.chain_id.is_empty()
            || application.description.trim().is_empty()
        {
            return Err(GmcError::FieldValidation);
        }

        // 2. Evidence replayability validation (Requirements 10.2, 10.8): at least one
        //    reference must be independently accessible *and* verifiable. If not, reject
        //    with EvidenceInvalid and do NOT enter voting (no record is created).
        let has_replayable_evidence = application
            .evidence_refs
            .iter()
            .any(EvidenceRef::is_replayable);
        if !has_replayable_evidence {
            return Err(GmcError::EvidenceInvalid);
        }

        // All checks passed: allocate an id and store the Pending declaration (R10.1).
        let id = self.allocate_id();
        let declaration = RetroactiveDeclaration {
            id: id.clone(),
            contributor_id: application.contributor_id,
            chain_id: application.chain_id,
            description: application.description,
            occurred_at: application.occurred_at,
            evidence_refs: application.evidence_refs,
            review_status: ReviewStatus::Pending,
            vote_id: None,
            anchored: false,
        };
        self.declarations.insert(id.clone(), declaration);
        Ok(id)
    }

    /// Returns the stored declaration with `id`, if present.
    pub fn get(&self, id: &DeclarationId) -> Option<&RetroactiveDeclaration> {
        self.declarations.get(id)
    }

    /// Number of declarations currently stored.
    pub fn len(&self) -> usize {
        self.declarations.len()
    }

    /// `true` if no declarations are stored.
    pub fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }

    /// Iterates over all stored declarations in deterministic id order.
    pub fn iter(&self) -> impl Iterator<Item = &RetroactiveDeclaration> {
        self.declarations.values()
    }

    /// Resolves the stakeholder vote for declaration `id` against the **stricter**
    /// retroactive threshold (Requirements 10.3, 10.5, 10.6).
    ///
    /// `weighted_approval` is the **already-tallied** curMerit-weighted approval ratio
    /// produced by `Governance_Module` for this declaration's vote, and
    /// `regular_threshold` is the chain's regular contribution-recognition threshold
    /// (`Evaluation_Mechanism.consensusThreshold`). Both are supplied as inputs so this
    /// module stays decoupled from `Governance_Module` / `AntiFraud_Engine` (see the
    /// type-level docs): the integration layer (task 20.1) selects voters (exclude
    /// intimacy > 0.9, sample ≥ 7) and tallies the ZK-private weighted vote before
    /// calling this.
    ///
    /// The effective pass threshold is `retro = retro_threshold(regular_threshold)` —
    /// `max(2/3, regular)` and **strictly greater** than `regular` (Requirement 10.3).
    /// Then:
    ///
    /// - **`weighted_approval >= retro`** → the declaration is marked
    ///   [`ReviewStatus::Approved`] (Requirement 10.6). The actual three-dimension mint
    ///   is performed **downstream** by the integration layer (`Scoring_Engine` +
    ///   `Minting_Service`) once the declaration is approved; it is not triggered here.
    /// - **`weighted_approval < retro`** → the declaration is marked
    ///   [`ReviewStatus::Rejected`] and **no minting is triggered** (Requirement 10.5),
    ///   and [`GmcError::RetroThresholdNotMet`] is returned so the caller can surface a
    ///   rejection indication to the declarant.
    ///
    /// In **both** outcomes the supplied `vote_handle` is recorded on the declaration
    /// (so the resolved vote is traceable), and the declaration is left ready for L1
    /// anchoring of its status + result via
    /// [`anchor_outcome`](Self::anchor_outcome) (Requirement 10.7).
    ///
    /// The update is atomic: the status is only advanced from
    /// [`ReviewStatus::Pending`]; a declaration that was already resolved cannot be
    /// re-resolved.
    ///
    /// # Errors
    ///
    /// - [`GmcError::FieldValidation`] — no declaration with `id` exists, or it is not
    ///   in [`ReviewStatus::Pending`] (nothing is mutated).
    /// - [`GmcError::RetroThresholdNotMet`] — the weighted approval did not reach the
    ///   retro threshold; the declaration is marked [`ReviewStatus::Rejected`] and
    ///   mints nothing (Requirement 10.5).
    pub fn resolve_vote(
        &mut self,
        id: &DeclarationId,
        weighted_approval: Ratio,
        regular_threshold: Ratio,
        vote_handle: impl Into<String>,
    ) -> GmcResult<ReviewStatus> {
        // Unknown declaration → caller misuse; nothing to mutate.
        let declaration = self
            .declarations
            .get_mut(id)
            .ok_or(GmcError::FieldValidation)?;

        // Only a Pending declaration can be resolved; re-resolving is rejected so an
        // Approved/Rejected outcome is final and side-effect free on re-entry.
        if declaration.review_status != ReviewStatus::Pending {
            return Err(GmcError::FieldValidation);
        }

        // Stricter retroactive threshold: max(2/3, regular), strictly > regular (R10.3).
        let retro = retro_threshold(regular_threshold);

        // Record the resolved vote's handle regardless of outcome (traceability +
        // L1-anchoring seam, R10.7).
        declaration.vote_id = Some(vote_handle.into());

        // Pass condition: weighted approval ≥ retro threshold (fixed-point compare).
        if weighted_approval.value() >= retro.value() {
            // R10.6: approved → mint per the three-dimension model happens downstream.
            declaration.review_status = ReviewStatus::Approved;
            Ok(ReviewStatus::Approved)
        } else {
            // R10.5: below threshold → reject and mint nothing.
            declaration.review_status = ReviewStatus::Rejected;
            Err(GmcError::RetroThresholdNotMet)
        }
    }

    /// **Placeholder** for anchoring a declaration's review status + vote result to the
    /// L1 settlement layer (Requirement 10.7).
    ///
    /// Real L1 anchoring is wired in task 18.1; for now this only flips the
    /// declaration's [`anchored`](RetroactiveDeclaration::anchored) flag so the
    /// surrounding flow can be exercised. It performs no real settlement-layer write.
    ///
    /// # Errors
    ///
    /// [`GmcError::FieldValidation`] if no declaration with `id` exists.
    pub fn anchor_outcome(&mut self, id: &DeclarationId) -> GmcResult<()> {
        let declaration = self
            .declarations
            .get_mut(id)
            .ok_or(GmcError::FieldValidation)?;
        declaration.anchored = true;
        Ok(())
    }

    /// Allocates a fresh, deterministic [`DeclarationId`] (`retro-<n>`).
    fn allocate_id(&mut self) -> DeclarationId {
        let id = DeclarationId::new(format!("retro-{}", self.next_seq));
        self.next_seq += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replayable_ref() -> EvidenceRef {
        EvidenceRef::new("ipfs://cid-abc", "0xhash", true)
    }

    fn application_with(evidence: Vec<EvidenceRef>) -> RetroactiveApplication {
        RetroactiveApplication::new(
            FayID::new("alice"),
            ChainId::new("carbon-reduction"),
            "Planted 1,000 trees in 2023, verified by local registry.",
            Timestamp::from_secs(1_600_000_000),
            evidence,
        )
    }

    // --- Requirement 10.1 / 10.2: complete declaration accepted as Pending ---

    #[test]
    fn complete_declaration_with_replayable_evidence_is_accepted_as_pending() {
        let mut module = RetroactiveReviewModule::new();

        let id = module
            .submit(application_with(vec![replayable_ref()]))
            .expect("a complete, replayable declaration must be accepted");

        let declaration = module.get(&id).expect("declaration stored");
        assert_eq!(declaration.review_status(), ReviewStatus::Pending);
        assert_eq!(declaration.contributor_id(), &FayID::new("alice"));
        assert_eq!(declaration.chain_id(), &ChainId::new("carbon-reduction"));
        assert_eq!(
            declaration.occurred_at(),
            Timestamp::from_secs(1_600_000_000)
        );
        assert_eq!(declaration.evidence_refs().len(), 1);
        assert_eq!(module.len(), 1);
    }

    #[test]
    fn accepted_declaration_has_pending_status_and_no_vote_id() {
        // Task 15.1 leaves the voting seam open: vote_id is None until task 15.2.
        let mut module = RetroactiveReviewModule::new();
        let id = module
            .submit(application_with(vec![replayable_ref()]))
            .unwrap();

        let declaration = module.get(&id).unwrap();
        assert_eq!(declaration.review_status(), ReviewStatus::Pending);
        assert_eq!(declaration.vote_id(), None);
    }

    #[test]
    fn one_replayable_among_several_refs_is_enough() {
        // A non-replayable ref alongside a replayable one still passes (≥ 1 required).
        let mut module = RetroactiveReviewModule::new();
        let id = module
            .submit(application_with(vec![
                EvidenceRef::new("ipfs://cid-x", "0xh", false), // not replayable
                replayable_ref(),                               // replayable
            ]))
            .expect("at least one replayable ref must suffice");
        assert_eq!(
            module.get(&id).unwrap().review_status(),
            ReviewStatus::Pending
        );
    }

    // --- Requirement 10.1: missing required field rejected ---

    #[test]
    fn missing_contributor_id_is_rejected_and_nothing_created() {
        let mut module = RetroactiveReviewModule::new();
        let mut app = application_with(vec![replayable_ref()]);
        app.contributor_id = FayID::new("");

        let err = module
            .submit(app)
            .expect_err("empty contributor id must be rejected");
        assert_eq!(err, GmcError::FieldValidation);
        assert!(module.is_empty());
    }

    #[test]
    fn missing_chain_id_is_rejected() {
        let mut module = RetroactiveReviewModule::new();
        let mut app = application_with(vec![replayable_ref()]);
        app.chain_id = ChainId::new("");

        let err = module
            .submit(app)
            .expect_err("empty chain id must be rejected");
        assert_eq!(err, GmcError::FieldValidation);
        assert!(module.is_empty());
    }

    #[test]
    fn blank_description_is_rejected() {
        let mut module = RetroactiveReviewModule::new();
        let mut app = application_with(vec![replayable_ref()]);
        app.description = "   ".to_owned();

        let err = module
            .submit(app)
            .expect_err("blank description must be rejected");
        assert_eq!(err, GmcError::FieldValidation);
        assert!(module.is_empty());
    }

    // --- Requirement 10.8: no / non-replayable evidence → EvidenceInvalid ---

    #[test]
    fn no_evidence_ref_is_rejected_with_evidence_invalid_and_not_pushed_to_voting() {
        let mut module = RetroactiveReviewModule::new();

        let err = module
            .submit(application_with(vec![]))
            .expect_err("a declaration with no evidence must be rejected");

        assert_eq!(err, GmcError::EvidenceInvalid);
        // Not created, hence never pushed into the voting flow.
        assert!(module.is_empty());
    }

    #[test]
    fn non_replayable_evidence_ref_is_rejected() {
        let mut module = RetroactiveReviewModule::new();
        // Flagged not replayable: a reviewer cannot independently verify it.
        let err = module
            .submit(application_with(vec![EvidenceRef::new(
                "ipfs://cid",
                "0xhash",
                false,
            )]))
            .expect_err("non-replayable evidence must be rejected");
        assert_eq!(err, GmcError::EvidenceInvalid);
        assert!(module.is_empty());
    }

    #[test]
    fn replayable_flag_without_locator_or_hash_is_not_verifiable() {
        let mut module = RetroactiveReviewModule::new();

        // Flagged replayable but missing the locator → cannot be accessed.
        let err = module
            .submit(application_with(vec![EvidenceRef::new("", "0xhash", true)]))
            .expect_err("replayable flag with empty uri must be rejected");
        assert_eq!(err, GmcError::EvidenceInvalid);

        // Flagged replayable but missing the hash → cannot be verified.
        let err = module
            .submit(application_with(vec![EvidenceRef::new(
                "ipfs://cid",
                "",
                true,
            )]))
            .expect_err("replayable flag with empty hash must be rejected");
        assert_eq!(err, GmcError::EvidenceInvalid);

        assert!(module.is_empty());
    }

    // --- EvidenceRef::is_replayable rule ---

    #[test]
    fn is_replayable_requires_flag_uri_and_hash() {
        assert!(EvidenceRef::new("ipfs://cid", "0xhash", true).is_replayable());
        assert!(!EvidenceRef::new("ipfs://cid", "0xhash", false).is_replayable());
        assert!(!EvidenceRef::new("", "0xhash", true).is_replayable());
        assert!(!EvidenceRef::new("ipfs://cid", "", true).is_replayable());
    }

    // --- id allocation is unique/deterministic across declarations ---

    #[test]
    fn distinct_declarations_get_distinct_ids() {
        let mut module = RetroactiveReviewModule::new();
        let id1 = module
            .submit(application_with(vec![replayable_ref()]))
            .unwrap();
        let id2 = module
            .submit(application_with(vec![replayable_ref()]))
            .unwrap();
        assert_ne!(id1, id2);
        assert_eq!(module.len(), 2);
    }

    // =======================================================================
    // Task 15.2 — retro threshold + vote organisation (R10.3–10.7)
    // =======================================================================

    fn ratio(s: &str) -> Ratio {
        Ratio::new(Decimal::from_str(s).unwrap()).unwrap()
    }

    fn pending_declaration() -> (RetroactiveReviewModule, DeclarationId) {
        let mut module = RetroactiveReviewModule::new();
        let id = module
            .submit(application_with(vec![replayable_ref()]))
            .expect("intake should accept a complete, replayable declaration");
        (module, id)
    }

    // --- Requirement 10.3: retro_threshold = max(regular, 2/3), strictly > regular ---

    #[test]
    fn retro_threshold_regular_below_two_thirds_is_the_two_thirds_floor() {
        // regular < 2/3 → retro == 2/3 floor, which is strictly greater than regular.
        let regular = ratio("0.5");
        let retro = retro_threshold(regular);
        assert_eq!(retro.value(), RETRO_TWO_THIRDS_FLOOR);
        assert!(
            retro.value() > regular.value(),
            "retro must be strictly > regular"
        );
        assert!(
            retro.value() >= RETRO_TWO_THIRDS_FLOOR,
            "retro must be >= 2/3"
        );
    }

    #[test]
    fn retro_threshold_regular_equal_two_thirds_floor_is_bumped_strictly_higher() {
        // regular == 2/3 floor → max(regular, 2/3) == regular, so bump by one ulp.
        let regular = Ratio::new(RETRO_TWO_THIRDS_FLOOR).unwrap();
        let retro = retro_threshold(regular);
        assert!(
            retro.value() > regular.value(),
            "retro must be strictly > regular"
        );
        assert!(
            retro.value() >= RETRO_TWO_THIRDS_FLOOR,
            "retro must be >= 2/3"
        );
        // Exactly one ulp above the 2/3 floor.
        assert_eq!(retro.value(), Decimal::from_raw(666_668));
    }

    #[test]
    fn retro_threshold_regular_above_two_thirds_is_bumped_strictly_higher() {
        // regular > 2/3 → retro == regular + one ulp (strictly greater, still >= 2/3).
        let regular = ratio("0.8");
        let retro = retro_threshold(regular);
        assert!(
            retro.value() > regular.value(),
            "retro must be strictly > regular"
        );
        assert!(
            retro.value() >= RETRO_TWO_THIRDS_FLOOR,
            "retro must be >= 2/3"
        );
        assert_eq!(
            retro.value(),
            regular.value().checked_add(Decimal::from_raw(1)).unwrap()
        );
    }

    #[test]
    fn retro_threshold_two_thirds_floor_is_at_least_two_thirds() {
        // The 2/3 floor must be >= the exact real 2/3 (0.666666… ). Since 2*floor must
        // be >= 1.333333 (i.e. > 2/3 in fixed point), 0.666667 rounds up past 0.666666.
        let two_thirds_truncated = Decimal::from_int(2)
            .checked_div(Decimal::from_int(3))
            .unwrap(); // 0.666666 (truncated)
        assert!(RETRO_TWO_THIRDS_FLOOR > two_thirds_truncated);
    }

    // --- Requirement 10.6: weighted_approval >= retro → Approved (mint downstream) ---

    #[test]
    fn approval_at_or_above_retro_threshold_marks_approved() {
        let (mut module, id) = pending_declaration();
        // regular 0.5 → retro 2/3 floor (0.666667). 0.7 >= 0.666667 → Approved.
        let status = module
            .resolve_vote(&id, ratio("0.7"), ratio("0.5"), "vote-1")
            .expect("approval above retro threshold should pass");
        assert_eq!(status, ReviewStatus::Approved);

        let declaration = module.get(&id).unwrap();
        assert_eq!(declaration.review_status(), ReviewStatus::Approved);
        // The resolved vote handle is recorded for traceability / L1 anchoring.
        assert_eq!(declaration.vote_id(), Some("vote-1"));
    }

    #[test]
    fn approval_exactly_at_retro_threshold_is_inclusive_approved() {
        let (mut module, id) = pending_declaration();
        // regular 0.5 → retro == 2/3 floor (0.666667). Approval exactly at it passes.
        let retro = retro_threshold(ratio("0.5"));
        let approval = Ratio::new(retro.value()).unwrap();
        let status = module
            .resolve_vote(&id, approval, ratio("0.5"), "vote-eq")
            .expect("approval exactly at retro threshold passes (inclusive)");
        assert_eq!(status, ReviewStatus::Approved);
    }

    // --- Requirement 10.5: weighted_approval < retro → Rejected, no mint ---

    #[test]
    fn approval_below_retro_threshold_marks_rejected_and_mints_nothing() {
        let (mut module, id) = pending_declaration();
        // regular 0.5 → retro 2/3 floor (0.666667). 0.6 < 0.666667 → Rejected.
        let err = module
            .resolve_vote(&id, ratio("0.6"), ratio("0.5"), "vote-2")
            .expect_err("approval below retro threshold must be rejected");
        assert_eq!(err, GmcError::RetroThresholdNotMet);

        let declaration = module.get(&id).unwrap();
        assert_eq!(declaration.review_status(), ReviewStatus::Rejected);
        // No Approved state means the downstream mint is never triggered (R10.5).
        assert_ne!(declaration.review_status(), ReviewStatus::Approved);
        // The vote handle is still recorded for the rejected outcome.
        assert_eq!(declaration.vote_id(), Some("vote-2"));
    }

    #[test]
    fn approval_above_regular_but_below_retro_is_rejected() {
        // Demonstrates the stricter retro gate: 0.6 would pass a regular 0.5 vote but
        // not the retro threshold (2/3 floor).
        let (mut module, id) = pending_declaration();
        let err = module
            .resolve_vote(&id, ratio("0.6"), ratio("0.5"), "vote-strict")
            .unwrap_err();
        assert_eq!(err, GmcError::RetroThresholdNotMet);
        assert_eq!(
            module.get(&id).unwrap().review_status(),
            ReviewStatus::Rejected
        );
    }

    // --- resolve_vote validation: unknown / already-resolved declarations ---

    #[test]
    fn resolve_vote_on_unknown_declaration_errors() {
        let mut module = RetroactiveReviewModule::new();
        let err = module
            .resolve_vote(
                &DeclarationId::new("retro-404"),
                ratio("0.9"),
                ratio("0.5"),
                "v",
            )
            .expect_err("resolving an unknown declaration must error");
        assert_eq!(err, GmcError::FieldValidation);
    }

    #[test]
    fn resolve_vote_is_not_re_resolvable() {
        let (mut module, id) = pending_declaration();
        module
            .resolve_vote(&id, ratio("0.7"), ratio("0.5"), "vote-1")
            .unwrap();
        // A second resolution is rejected; the first outcome is final.
        let err = module
            .resolve_vote(&id, ratio("0.2"), ratio("0.5"), "vote-2")
            .expect_err("an already-resolved declaration cannot be re-resolved");
        assert_eq!(err, GmcError::FieldValidation);
        let declaration = module.get(&id).unwrap();
        assert_eq!(declaration.review_status(), ReviewStatus::Approved);
        assert_eq!(declaration.vote_id(), Some("vote-1"));
    }

    // --- Requirement 10.7: L1 anchoring seam ---

    #[test]
    fn anchor_outcome_marks_declaration_anchored() {
        let (mut module, id) = pending_declaration();
        assert!(!module.get(&id).unwrap().anchored());
        module
            .resolve_vote(&id, ratio("0.7"), ratio("0.5"), "vote-1")
            .unwrap();
        module
            .anchor_outcome(&id)
            .expect("anchoring a known declaration succeeds");
        assert!(module.get(&id).unwrap().anchored());
    }

    #[test]
    fn anchor_outcome_on_unknown_declaration_errors() {
        let mut module = RetroactiveReviewModule::new();
        let err = module
            .anchor_outcome(&DeclarationId::new("retro-404"))
            .expect_err("anchoring an unknown declaration must error");
        assert_eq!(err, GmcError::FieldValidation);
    }
}
