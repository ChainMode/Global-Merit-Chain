//! `Ownership_Registry` — coFay ownership paths, root-is-iFay, depth ≤ 16, cycle guards.
//!
//! This module implements the **data model** for the GMC identity ownership tree
//! (design's *Data Models → 归属注册表* section) and, mirroring `gmc-core`'s
//! `Chain_Registry`, splits the work across two tasks against the *same* shape:
//!
//! - task 9.1 (this task): the [`OwnershipNode`] record, the [`OwnershipRegistry`]
//!   container, root registration ([`OwnershipRegistry::register_root`]) and the
//!   read accessors (`owner_of` / `path_of` / `depth_of` / `contains` / `node`).
//! - task 9.2: the `attach` validation algorithm (owner-exists → no-cycle →
//!   depth ≤ 16 → record path) plus `would_cycle` and `ancestors_of`, mirroring
//!   `gmc-core`'s `Chain_Registry::derive` / `detect_cycle` and `MAX_DEPTH` guards.
//!
//! ## Field mapping (design *Data Models → 归属注册表*)
//!
//! [`OwnershipNode`] mirrors the design record `id / owner / depth / path`:
//!
//! - `owner` is `None` for a tree **root** (an iFay — self-sovereign, owns itself) and
//!   `Some(owner)` for a coFay (set by `attach`, task 9.2);
//! - `depth` is `0` for a root iFay and `owner.depth + 1` for a coFay (bounded by
//!   [`MAX_DEPTH`], enforced in task 9.2);
//! - `path` is the **root-first** ordered ownership path `[root iFay, …, this id]`,
//!   satisfying the `len(path) == depth + 1` invariant (a root's path is just `[id]`).
//!
//! The tree invariants the design states — every `path[0]` is an `IdentityKind::IFay`
//! root (Requirement 6.3) and the tree never forms a cycle (Requirement 6.5) — hold by
//! construction: roots are the only depth-0 nodes and carry `path = [id]`, and task
//! 9.2's `attach` extends an existing owner's path so a coFay's `path[0]` is exactly
//! its owner's root.

use std::collections::{BTreeMap, VecDeque};

use crate::error::IdentityResult;
use crate::identity_id::IdentityId;

/// Maximum ownership depth (with a root iFay counted as depth 0) the tree may reach.
///
/// Declared here alongside the data model to mirror `gmc-core`'s
/// [`MAX_DEPTH`](gmc_core::registry::MAX_DEPTH); the depth-bound *enforcement* during
/// `attach` (mapping a violation to
/// [`IdentityError::OwnershipDepthExceeded`](crate::error::IdentityError::OwnershipDepthExceeded))
/// is task 9.2.
pub const MAX_DEPTH: u32 = 16;

/// An ordered ownership path, **root-first**: `[root iFay, …, this id]`
/// (design *Data Models*: `OwnershipPath`, Requirement 6.2).
///
/// A root's path is the single-element `[root_id]`. By construction the first element
/// of any path is the tree's root iFay (Requirement 6.3) and `len(path) == depth + 1`.
pub type OwnershipPath = Vec<IdentityId>;

/// A node in the ownership tree — either a root iFay or a coFay
/// (design *Data Models*: `OwnershipNode`).
///
/// Fields are private with read-only accessors so the invariants established at
/// construction (`owner == None ⇔ depth == 0 ⇔ path == [id]` for a root, and
/// `len(path) == depth + 1` for every node) cannot be silently broken by callers.
/// Task 9.2's `attach` constructs coFay nodes through a module-internal constructor,
/// keeping `id` / `owner` / `depth` / `path` immutable once recorded so the
/// derivation-tree invariants cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipNode {
    /// This node's identity (design `id`).
    id: IdentityId,
    /// `None` for a root iFay (self-sovereign); `Some(owner)` for a coFay (design
    /// `owner`).
    owner: Option<IdentityId>,
    /// Ownership depth; root iFay = 0, coFay = `owner.depth + 1` (design `depth`,
    /// bounded by [`MAX_DEPTH`]).
    depth: u32,
    /// Root-first ordered ownership path with `len(path) == depth + 1` (design `path`).
    path: OwnershipPath,
}

impl OwnershipNode {
    /// Builds a tree **root** node for `id`: `owner = None`, `depth = 0`,
    /// `path = [id]` (design *Data Models*; Requirements 6.2, 6.3).
    ///
    /// Roots are the iFay anchors of every ownership path. The "`path[0]` is an iFay"
    /// invariant (Requirement 6.3) is owned by the caller registering iFays as roots;
    /// this constructor establishes the structural part (depth 0, single-element path).
    fn root(id: IdentityId) -> Self {
        let path = vec![id.clone()];
        OwnershipNode {
            id,
            owner: None,
            depth: 0,
            path,
        }
    }

    /// Builds a **coFay** node beneath `owner` with the already-validated `depth` and
    /// root-first `path` (design *Data Models*; the `attach` algorithm of task 9.2).
    ///
    /// Module-internal: only [`OwnershipRegistry::attach`] constructs coFay nodes, and
    /// only after it has run the full ordered validation (owner exists → no cycle →
    /// depth ≤ [`MAX_DEPTH`]) and computed `depth = owner.depth + 1` and
    /// `path = owner.path + [id]`. Keeping the constructor private preserves the
    /// `len(path) == depth + 1` and "`path[0]` is the owner's root iFay" invariants:
    /// a coFay can only ever be created consistently with its owner.
    fn cofay(id: IdentityId, owner: IdentityId, depth: u32, path: OwnershipPath) -> Self {
        OwnershipNode {
            id,
            owner: Some(owner),
            depth,
            path,
        }
    }

    /// This node's identity.
    #[inline]
    pub fn id(&self) -> &IdentityId {
        &self.id
    }

    /// This node's owner, or `None` if it is a root iFay (design `owner`).
    #[inline]
    pub fn owner(&self) -> Option<&IdentityId> {
        self.owner.as_ref()
    }

    /// This node's ownership depth (root iFay = 0).
    #[inline]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// This node's root-first ordered ownership path (design `path`, Requirement 6.2).
    #[inline]
    pub fn path(&self) -> &OwnershipPath {
        &self.path
    }

    /// `true` if this is a tree root (no owner, depth 0) — an iFay anchor.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.owner.is_none() && self.depth == 0
    }
}

/// The ownership registry: every [`OwnershipNode`] keyed by its [`IdentityId`]
/// (design *Data Models*: `OwnershipRegistry { nodes }`).
///
/// A `BTreeMap` is used (as in `gmc-core`'s `Chain_Registry`) so iteration order is
/// deterministic — a requirement of this layer's property tests. This task populates
/// the registry only with roots ([`OwnershipRegistry::register_root`]); task 9.2 adds
/// `attach` to grow coFay subtrees under existing nodes without reshaping this type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipRegistry {
    /// All ownership nodes keyed by id (`BTreeMap` for deterministic iteration order).
    nodes: BTreeMap<IdentityId, OwnershipNode>,
}

impl OwnershipRegistry {
    /// Creates an empty ownership registry.
    #[inline]
    pub fn new() -> Self {
        OwnershipRegistry {
            nodes: BTreeMap::new(),
        }
    }

    /// Registers `ifay` as a tree **root**: `owner = None`, `depth = 0`,
    /// `path = [ifay]` (design `registerRoot`; Requirements 6.2, 6.3).
    ///
    /// A root is the iFay anchor of an ownership path: it owns itself (self-sovereign),
    /// sits at depth 0, and its single-element path makes it the `path[0]` of every
    /// coFay later attached beneath it (Requirement 6.3).
    ///
    /// # Re-registering an already-present id (idempotent)
    ///
    /// This operation is **idempotent**: registering an id that is **already present**
    /// in the registry is a **no-op that returns `Ok(())`**, leaving the existing node
    /// **exactly as-is** (no field is overwritten). The chosen semantics avoid an
    /// "already exists" error the layer's [`IdentityError`](crate::error::IdentityError)
    /// vocabulary deliberately does not define, and they are well-defined here because
    /// `register_root` is the only way a node enters the registry in this task — so any
    /// present id is itself a root with the identical `(owner = None, depth = 0,
    /// path = [id])` shape, and re-registering it changes nothing. (Task 9.2's `attach`
    /// is responsible for rejecting attempts to *re-parent* or duplicate an existing
    /// node; it never routes through `register_root`.)
    ///
    /// Always returns `Ok(())` for this task's data-model scope; the
    /// [`IdentityResult`] signature matches the design's `registerRoot` so task 9.2 can
    /// add validating siblings (`attach`) with a uniform return type.
    pub fn register_root(&mut self, ifay: &IdentityId) -> IdentityResult<()> {
        // Idempotent: an already-present id is left untouched (see doc comment).
        self.nodes
            .entry(ifay.clone())
            .or_insert_with(|| OwnershipNode::root(ifay.clone()));
        Ok(())
    }

    /// Returns the owner of `id`, or `None` if `id` is a root iFay **or** is not
    /// registered (design `ownerOf`).
    ///
    /// Note both "registered root" and "absent" map to `None` here; use
    /// [`OwnershipRegistry::contains`] to distinguish them when that matters.
    #[inline]
    pub fn owner_of(&self, id: &IdentityId) -> Option<&IdentityId> {
        self.nodes.get(id).and_then(OwnershipNode::owner)
    }

    /// Returns the root-first ordered ownership path of `id`, or `None` if `id` is not
    /// registered (design `pathOf`; Requirement 6.2).
    #[inline]
    pub fn path_of(&self, id: &IdentityId) -> Option<&OwnershipPath> {
        self.nodes.get(id).map(OwnershipNode::path)
    }

    /// Returns the ownership depth of `id` (root iFay = 0), or `None` if `id` is not
    /// registered.
    #[inline]
    pub fn depth_of(&self, id: &IdentityId) -> Option<u32> {
        self.nodes.get(id).map(OwnershipNode::depth)
    }

    /// `true` if a node with `id` is registered (as a root in this task, or a coFay
    /// once task 9.2's `attach` lands).
    #[inline]
    pub fn contains(&self, id: &IdentityId) -> bool {
        self.nodes.contains_key(id)
    }

    /// Returns the full [`OwnershipNode`] for `id`, if registered.
    #[inline]
    pub fn node(&self, id: &IdentityId) -> Option<&OwnershipNode> {
        self.nodes.get(id)
    }

    /// Attaches `cofay` beneath `owner`, running the design's ordered `attach`
    /// validation (mirror of `gmc-core`'s `Chain_Registry::derive`).
    ///
    /// The checks run in the **fixed** order the design specifies, and any failure
    /// returns its mapped error while leaving the registry **completely unchanged**
    /// (no partial write — the layer's "validate up front, fail atomically, state
    /// unchanged" rule):
    ///
    /// 1. **Owner exists** — an `owner` not registered is rejected with
    ///    [`OwnerNotFound`](crate::error::IdentityError::OwnerNotFound) (_Requirement
    ///    6.4_).
    /// 2. **No cycle** — if honouring the request would make a node its own ancestor it
    ///    is rejected with [`OwnershipCycle`](crate::error::IdentityError::OwnershipCycle)
    ///    (_Requirement 6.5_); see [`OwnershipRegistry::would_cycle`].
    /// 3. **Depth bound** — `new_depth = owner.depth + 1`; if it exceeds [`MAX_DEPTH`]
    ///    (16) the request is rejected with
    ///    [`OwnershipDepthExceeded`](crate::error::IdentityError::OwnershipDepthExceeded)
    ///    (_Requirement 6.6_).
    ///
    /// On success the coFay is recorded with `owner = Some(owner)`,
    /// `depth = owner.depth + 1`, and the **root-first** path
    /// `path = path_of(owner) + [cofay]` — so `path[0]` is the owner's root iFay
    /// (_Requirements 6.2, 6.3_) and `len(path) == depth + 1`. The new path is cloned
    /// and returned.
    ///
    /// # Scope: initial attach **and** deep (subtree-recomputing) re-parent
    ///
    /// This handles BOTH the common case where `cofay` is not yet present (an initial
    /// leaf attach) AND re-parenting an already-present `cofay` (moving it under a new
    /// owner). The cycle guard (step 2) walks `new_owner`'s **live owner-pointer chain**
    /// (see [`OwnershipRegistry::would_cycle`]), so it rejects any move that would place
    /// `cofay` under itself or under one of its own descendants regardless of whether
    /// stored `path` fields are momentarily stale — owner pointers are always the source
    /// of truth.
    ///
    /// On a re-parent the recomputation is **deep**, not shallow: the moved node's own
    /// `owner` / `depth` / `path` are re-derived from the new owner, and **every
    /// descendant** of `cofay` (any node whose owner chain passes through it) has its
    /// `depth` / `path` recomputed in owner-before-child order
    /// (`d.depth = owner_of(d).depth + 1`, `d.path = owner_of(d).path + [d]`). Stored
    /// paths therefore never go stale after a move, which keeps both the cycle guard and
    /// `path_of` / `depth_of` accurate.
    ///
    /// The depth bound (step 3 / _Requirement 6.6_) is enforced across the **whole moved
    /// subtree**: the new subtree records are computed and the deepest new depth is
    /// validated **before** any mutation, so a re-parent that would push the moved node
    /// or any descendant beyond [`MAX_DEPTH`] is rejected with `OwnershipDepthExceeded`
    /// and leaves the registry byte-for-byte unchanged (atomic — compute, validate, then
    /// commit).
    pub fn attach(
        &mut self,
        cofay: &IdentityId,
        owner: &IdentityId,
    ) -> IdentityResult<OwnershipPath> {
        // 1. Owner exists (Requirement 6.4).
        let owner_node = self
            .nodes
            .get(owner)
            .ok_or(crate::error::IdentityError::OwnerNotFound)?;
        let owner_depth = owner_node.depth;
        let owner_path = owner_node.path.clone();

        // 2. No cycle (Requirement 6.5): self-parent or new owner inside cofay's subtree.
        // would_cycle follows the live owner-pointer chain, so it is sound even if any
        // stored path is momentarily stale.
        if self.would_cycle(cofay, owner) {
            return Err(crate::error::IdentityError::OwnershipCycle);
        }

        // The moved node's freshly-derived depth/path = owner.depth+1 / owner.path+[cofay].
        let new_depth = owner_depth + 1;
        let mut new_path = owner_path;
        new_path.push(cofay.clone());

        // Initial leaf attach: `cofay` has no subtree, so only the new node's depth must
        // satisfy the bound (Requirement 6.6). Insert atomically.
        if !self.nodes.contains_key(cofay) {
            if new_depth > MAX_DEPTH {
                return Err(crate::error::IdentityError::OwnershipDepthExceeded);
            }
            let node = OwnershipNode::cofay(
                cofay.clone(),
                owner.clone(),
                new_depth,
                new_path.clone(),
            );
            self.nodes.insert(cofay.clone(), node);
            return Ok(new_path);
        }

        // Re-parent of an existing node: re-derive the moved node AND every descendant,
        // in owner-before-child (breadth-first) order, computing the whole new subtree
        // BEFORE touching `self.nodes` so the operation stays atomic.
        //
        // The traversal reads the *current* owner pointers, which (apart from cofay's own
        // owner, the root of the walk) are unchanged by this move; since the existing
        // tree is acyclic and the cycle guard proved `owner` is outside cofay's subtree,
        // the walk visits each descendant exactly once and terminates.
        let mut updates: Vec<(IdentityId, IdentityId, u32, OwnershipPath)> = Vec::new();
        // id -> (new depth, new path) for already-computed nodes, to derive children.
        let mut computed: BTreeMap<IdentityId, (u32, OwnershipPath)> = BTreeMap::new();
        computed.insert(cofay.clone(), (new_depth, new_path.clone()));
        updates.push((cofay.clone(), owner.clone(), new_depth, new_path.clone()));

        let mut max_new_depth = new_depth;
        let mut queue: VecDeque<IdentityId> = VecDeque::new();
        queue.push_back(cofay.clone());
        while let Some(parent) = queue.pop_front() {
            let (parent_depth, parent_path) = computed
                .get(&parent)
                .expect("parent computed before its children")
                .clone();
            // Children of `parent`: nodes whose stored owner pointer is `parent`.
            // BTreeMap iteration is ordered, so the traversal is deterministic.
            let children: Vec<IdentityId> = self
                .nodes
                .values()
                .filter(|n| n.owner.as_ref() == Some(&parent))
                .map(|n| n.id.clone())
                .collect();
            for child in children {
                let child_depth = parent_depth + 1;
                let mut child_path = parent_path.clone();
                child_path.push(child.clone());
                if child_depth > max_new_depth {
                    max_new_depth = child_depth;
                }
                computed.insert(child.clone(), (child_depth, child_path.clone()));
                updates.push((child.clone(), parent.clone(), child_depth, child_path));
                queue.push_back(child);
            }
        }

        // 3. Depth bound across the WHOLE moved subtree (Requirement 6.6): if the deepest
        // re-derived node would exceed MAX_DEPTH, reject and leave the registry unchanged.
        if max_new_depth > MAX_DEPTH {
            return Err(crate::error::IdentityError::OwnershipDepthExceeded);
        }

        // All checks passed: commit the recomputed subtree (Requirements 6.2, 6.3). Each
        // node already exists, so this rewrites owner/depth/path in place.
        for (id, parent, depth, path) in updates {
            let node = self
                .nodes
                .get_mut(&id)
                .expect("subtree node was present when its update was computed");
            node.owner = Some(parent);
            node.depth = depth;
            node.path = path;
        }
        Ok(new_path)
    }

    /// Cycle guard for the ownership tree (_Requirement 6.5_), mirroring `gmc-core`'s
    /// `Chain_Registry::detect_cycle`.
    ///
    /// Returns `true` if attaching `cofay` beneath `new_owner` would create a cycle —
    /// i.e. make some node its own ancestor. That happens exactly when:
    ///
    /// - `new_owner == cofay` (a node cannot own itself, a self-parent edge); or
    /// - `cofay` is an **ancestor** of `new_owner` in the live ownership tree —
    ///   re-parenting `cofay` under a node in its own subtree would close a loop.
    ///
    /// The guard walks the **live owner-pointer chain** starting at `new_owner`,
    /// following `owner_of` upward until it reaches a root (`None`). It reports a cycle
    /// the moment it encounters `cofay` along that chain. Crucially this consults
    /// `owner_of` (the source of truth), **not** any stored `path` field: owner pointers
    /// are always accurate, so the guard stays sound even if some node's cached `path`
    /// is momentarily stale (e.g. mid-way through a subtree move). The walk is bounded
    /// by `self.len() + 1` steps as a safety net against an unexpected malformed loop.
    ///
    /// Attaching a brand-new leaf (a `cofay` not yet in the registry) can never form a
    /// cycle: it is on no node's owner chain, so the walk from `new_owner` never meets
    /// it. An unknown `new_owner` has no owner chain, hence no cycle.
    pub fn would_cycle(&self, cofay: &IdentityId, new_owner: &IdentityId) -> bool {
        // Direct self-parent: a node cannot be its own owner.
        if new_owner == cofay {
            return true;
        }
        // Follow new_owner's live owner pointers upward; a cycle exists iff `cofay`
        // appears as one of new_owner's ancestors. Bounded by len()+1 as a safety net.
        let step_limit = self.len() + 1;
        let mut cursor = new_owner.clone();
        let mut steps = 0usize;
        loop {
            match self.owner_of(&cursor) {
                // Reached a root without meeting `cofay`: no cycle.
                None => return false,
                Some(parent) => {
                    if parent == cofay {
                        return true;
                    }
                    steps += 1;
                    if steps > step_limit {
                        // Defensive: an unexpected loop in the owner pointers.
                        return true;
                    }
                    cursor = parent.clone();
                }
            }
        }
    }

    /// Returns the ancestors of `cofay`: the elements of its ownership path **except
    /// the node itself** (design `ancestorsOf`, _Requirement 6.2_), ordered root-first.
    ///
    /// For a root iFay (path `[id]`) this is empty; for a coFay at depth `d` it is the
    /// `d` ancestors `[root iFay, …, owner]`. Returns an empty vector for an
    /// unregistered `id` (it has no recorded path).
    pub fn ancestors_of(&self, cofay: &IdentityId) -> Vec<IdentityId> {
        match self.nodes.get(cofay) {
            // path is root-first and ends with the node itself; drop that last element.
            Some(node) => node
                .path
                .iter()
                .filter(|ancestor| *ancestor != cofay)
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Number of nodes currently registered.
    #[inline]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// `true` if no nodes are registered yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Iterates over all registered nodes in deterministic id order.
    pub fn iter(&self) -> impl Iterator<Item = &OwnershipNode> {
        self.nodes.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IdentityError;
    use crate::types::SchemeTag;

    /// Builds a distinct ed25519-tagged `IdentityId` from a `key_repr` label. The
    /// ownership model treats ids opaquely (only `Ord`/`Eq` matter), so a literal
    /// `key_repr` keeps the tests focused on tree structure rather than derivation.
    fn id(key_repr: &str) -> IdentityId {
        IdentityId::new(SchemeTag::ed25519(), key_repr)
    }

    // --- register_root: root shape (Requirements 6.2, 6.3) -----------------

    #[test]
    fn register_root_sets_owner_none_depth_zero_self_path() {
        let mut reg = OwnershipRegistry::new();
        let ifay = id("alice");

        assert!(reg.register_root(&ifay).is_ok());

        // owner = None (self-sovereign), depth = 0, path = [ifay] (root-first).
        assert_eq!(reg.owner_of(&ifay), None);
        assert_eq!(reg.depth_of(&ifay), Some(0));
        assert_eq!(reg.path_of(&ifay), Some(&vec![ifay.clone()]));
        // len(path) == depth + 1 invariant holds for a root.
        assert_eq!(reg.path_of(&ifay).unwrap().len() as u32, 0 + 1);
    }

    #[test]
    fn register_root_node_accessor_reports_root() {
        let mut reg = OwnershipRegistry::new();
        let ifay = id("root-node");
        reg.register_root(&ifay).unwrap();

        let node = reg.node(&ifay).expect("registered root");
        assert_eq!(node.id(), &ifay);
        assert_eq!(node.owner(), None);
        assert_eq!(node.depth(), 0);
        assert_eq!(node.path(), &vec![ifay.clone()]);
        assert!(node.is_root());
    }

    #[test]
    fn contains_tracks_registration() {
        let mut reg = OwnershipRegistry::new();
        let ifay = id("present");
        assert!(!reg.contains(&ifay));
        reg.register_root(&ifay).unwrap();
        assert!(reg.contains(&ifay));
    }

    #[test]
    fn multiple_roots_are_independent() {
        // Several iFays may each anchor their own ownership tree at depth 0.
        let mut reg = OwnershipRegistry::new();
        let a = id("ifay-a");
        let b = id("ifay-b");
        reg.register_root(&a).unwrap();
        reg.register_root(&b).unwrap();

        assert_eq!(reg.len(), 2);
        for root in [&a, &b] {
            assert_eq!(reg.owner_of(root), None);
            assert_eq!(reg.depth_of(root), Some(0));
            assert_eq!(reg.path_of(root), Some(&vec![root.clone()]));
        }
    }

    // --- register_root: idempotent re-registration -------------------------

    #[test]
    fn re_registering_is_idempotent_no_op() {
        // Documented choice: re-registering an already-present id is a no-op success
        // that leaves the existing node exactly as-is.
        let mut reg = OwnershipRegistry::new();
        let ifay = id("dup");

        assert!(reg.register_root(&ifay).is_ok());
        let before = reg.node(&ifay).cloned();

        // Second registration succeeds and changes nothing.
        assert!(reg.register_root(&ifay).is_ok());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.node(&ifay).cloned(), before);
        assert_eq!(reg.owner_of(&ifay), None);
        assert_eq!(reg.depth_of(&ifay), Some(0));
        assert_eq!(reg.path_of(&ifay), Some(&vec![ifay.clone()]));
    }

    // --- accessors on an unregistered id -----------------------------------

    #[test]
    fn accessors_return_none_for_unregistered_id() {
        let reg = OwnershipRegistry::new();
        let missing = id("ghost");

        assert!(!reg.contains(&missing));
        assert_eq!(reg.owner_of(&missing), None);
        assert_eq!(reg.path_of(&missing), None);
        assert_eq!(reg.depth_of(&missing), None);
        assert!(reg.node(&missing).is_none());
    }

    #[test]
    fn empty_registry_reports_empty() {
        let reg = OwnershipRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.iter().count(), 0);
    }

    // --- attach: success records owner / depth / path (Reqs 6.2, 6.3, 6.4) -

    #[test]
    fn attach_records_owner_depth_and_root_first_path() {
        let mut reg = OwnershipRegistry::new();
        let root = id("ifay-root");
        let cofay = id("cofay-1");
        reg.register_root(&root).unwrap();

        let path = reg.attach(&cofay, &root).expect("owner exists, no cycle, depth ok");

        // owner = Some(root), depth = owner.depth + 1 = 1.
        assert_eq!(reg.owner_of(&cofay), Some(&root));
        assert_eq!(reg.depth_of(&cofay), Some(1));
        // returned path == stored path == [root, cofay] (root-first).
        assert_eq!(path, vec![root.clone(), cofay.clone()]);
        assert_eq!(reg.path_of(&cofay), Some(&vec![root.clone(), cofay.clone()]));
        // path[0] is the root iFay (Requirement 6.3).
        assert_eq!(&path[0], &root);
        // len(path) == depth + 1 invariant.
        assert_eq!(path.len() as u32, reg.depth_of(&cofay).unwrap() + 1);
        // The coFay node is not a root.
        assert!(!reg.node(&cofay).unwrap().is_root());
    }

    #[test]
    fn attach_chains_extend_path_and_depth() {
        // root -> a -> b: each level extends the path and increments depth by 1.
        let mut reg = OwnershipRegistry::new();
        let root = id("r");
        let a = id("a");
        let b = id("b");
        reg.register_root(&root).unwrap();

        reg.attach(&a, &root).unwrap();
        let path_b = reg.attach(&b, &a).unwrap();

        assert_eq!(reg.depth_of(&a), Some(1));
        assert_eq!(reg.depth_of(&b), Some(2));
        assert_eq!(path_b, vec![root.clone(), a.clone(), b.clone()]);
        assert_eq!(&path_b[0], &root); // root iFay still first.
        assert_eq!(path_b.len() as u32, reg.depth_of(&b).unwrap() + 1);
    }

    // --- attach: OwnerNotFound (Requirement 6.4) ---------------------------

    #[test]
    fn attach_unknown_owner_is_owner_not_found_and_writes_nothing() {
        let mut reg = OwnershipRegistry::new();
        let missing_owner = id("ghost-owner");
        let cofay = id("cofay");

        assert_eq!(
            reg.attach(&cofay, &missing_owner),
            Err(IdentityError::OwnerNotFound)
        );
        // Nothing written: neither the cofay nor the (absent) owner exist.
        assert!(!reg.contains(&cofay));
        assert!(!reg.contains(&missing_owner));
        assert!(reg.is_empty());
    }

    // --- attach: OwnershipCycle (Requirement 6.5) --------------------------

    #[test]
    fn attach_self_parent_is_cycle() {
        let mut reg = OwnershipRegistry::new();
        let root = id("self");
        reg.register_root(&root).unwrap();

        // Attaching a node under itself forms a self-parent cycle.
        assert_eq!(reg.attach(&root, &root), Err(IdentityError::OwnershipCycle));
        // Re-parent of an existing coFay under itself is likewise rejected.
        let c = id("c");
        reg.attach(&c, &root).unwrap();
        assert_eq!(reg.attach(&c, &c), Err(IdentityError::OwnershipCycle));
    }

    #[test]
    fn attach_under_own_descendant_is_cycle_and_leaves_state_unchanged() {
        // root -> a -> b; re-parenting `a` under its own descendant `b` would loop.
        let mut reg = OwnershipRegistry::new();
        let root = id("root");
        let a = id("a");
        let b = id("b");
        reg.register_root(&root).unwrap();
        reg.attach(&a, &root).unwrap();
        reg.attach(&b, &a).unwrap();

        let before = reg.clone();
        assert_eq!(reg.attach(&a, &b), Err(IdentityError::OwnershipCycle));
        // Rejected re-parent leaves every node exactly as before (no partial write).
        assert_eq!(reg, before);
    }

    #[test]
    fn would_cycle_matches_self_and_subtree() {
        let mut reg = OwnershipRegistry::new();
        let root = id("root");
        let a = id("a");
        let b = id("b");
        reg.register_root(&root).unwrap();
        reg.attach(&a, &root).unwrap();
        reg.attach(&b, &a).unwrap();

        // self-parent.
        assert!(reg.would_cycle(&a, &a));
        // a is an ancestor of b (a on b's path) -> attaching a under b cycles.
        assert!(reg.would_cycle(&a, &b));
        // root is an ancestor of b -> attaching root under b cycles.
        assert!(reg.would_cycle(&root, &b));
        // attaching a fresh leaf under b is fine (no cycle).
        assert!(!reg.would_cycle(&id("fresh"), &b));
        // unknown owner -> no path, no cycle.
        assert!(!reg.would_cycle(&a, &id("nobody")));
    }

    // --- attach: OwnershipDepthExceeded (Requirement 6.6) ------------------

    #[test]
    fn attach_beyond_max_depth_is_rejected_and_writes_nothing() {
        // Build a chain root(0) -> n1(1) -> ... -> n16(16) at exactly MAX_DEPTH.
        let mut reg = OwnershipRegistry::new();
        let root = id("d0");
        reg.register_root(&root).unwrap();

        let mut owner = root.clone();
        for d in 1..=MAX_DEPTH {
            let node = id(&format!("d{d}"));
            reg.attach(&node, &owner).expect("within depth bound");
            assert_eq!(reg.depth_of(&node), Some(d));
            owner = node;
        }
        // `owner` is now the depth-16 leaf; attaching beneath it would be depth 17.
        let too_deep = id("d17");
        let before = reg.clone();
        assert_eq!(
            reg.attach(&too_deep, &owner),
            Err(IdentityError::OwnershipDepthExceeded)
        );
        // Nothing written and the rest of the tree is untouched.
        assert!(!reg.contains(&too_deep));
        assert_eq!(reg, before);
    }

    // --- ancestors_of (Requirement 6.2) ------------------------------------

    #[test]
    fn ancestors_of_returns_path_minus_self() {
        let mut reg = OwnershipRegistry::new();
        let root = id("root");
        let a = id("a");
        let b = id("b");
        reg.register_root(&root).unwrap();
        reg.attach(&a, &root).unwrap();
        reg.attach(&b, &a).unwrap();

        // Root has no ancestors.
        assert_eq!(reg.ancestors_of(&root), Vec::<IdentityId>::new());
        // a's ancestors = [root]; b's ancestors = [root, a] (root-first, self excluded).
        assert_eq!(reg.ancestors_of(&a), vec![root.clone()]);
        assert_eq!(reg.ancestors_of(&b), vec![root.clone(), a.clone()]);
        // ancestors == path minus the node itself.
        let mut path_b = reg.path_of(&b).unwrap().clone();
        path_b.pop();
        assert_eq!(reg.ancestors_of(&b), path_b);
        // Unknown id has no ancestors.
        assert_eq!(reg.ancestors_of(&id("ghost")), Vec::<IdentityId>::new());
    }

    // --- attach: re-parent recomputes the moved node's owner/depth/path ----

    #[test]
    fn attach_reparents_existing_cofay() {
        // root -> a, root -> b; move `a` to sit under `b`.
        let mut reg = OwnershipRegistry::new();
        let root = id("root");
        let a = id("a");
        let b = id("b");
        reg.register_root(&root).unwrap();
        reg.attach(&a, &root).unwrap();
        reg.attach(&b, &root).unwrap();
        assert_eq!(reg.depth_of(&a), Some(1));

        let new_path = reg.attach(&a, &b).expect("no cycle: b is not in a's subtree");

        // `a`'s own owner/depth/path are recomputed from the new owner `b`.
        assert_eq!(reg.owner_of(&a), Some(&b));
        assert_eq!(reg.depth_of(&a), Some(2));
        assert_eq!(new_path, vec![root.clone(), b.clone(), a.clone()]);
        assert_eq!(reg.path_of(&a), Some(&vec![root.clone(), b.clone(), a.clone()]));
        // No new node is created by a re-parent (still root, a, b).
        assert_eq!(reg.len(), 3);
    }

    // --- attach: deep re-parent soundness (Requirements 6.5, 6.6) ----------

    /// The exact minimal failing sequence from Property 10's recorded counterexample.
    /// After building id-5 -> id-11 (root), id-19 -> id-5, id-0 -> id-19, the final
    /// `Reparent{id-5 -> id-0}` would close the loop id-5 -> id-0 -> id-19 -> id-5, so
    /// it must be rejected with OwnershipCycle and leave the registry unchanged. The
    /// previous shallow guard wrongly accepted it because id-0's stored path was stale.
    #[test]
    fn deep_reparent_cycle_is_rejected_and_state_unchanged() {
        let mut reg = OwnershipRegistry::new();
        let id5 = id("id-5");
        let id10 = id("id-10");
        let id11 = id("id-11");
        let id0 = id("id-0");
        let id19 = id("id-19");

        // Drive the recorded sequence with the test's registration policy: an absent
        // owner enters as a root the first time it is needed.
        // Attach{id-10 -> id-5}: id-5 becomes a root, id-10 attaches beneath it.
        reg.register_root(&id5).unwrap();
        reg.attach(&id10, &id5).unwrap();
        // Attach{id-5 -> id-11}: id-11 becomes a root; id-5 re-parents under id-11.
        reg.register_root(&id11).unwrap();
        reg.attach(&id5, &id11).unwrap();
        // Attach{id-0 -> id-19}: id-19 becomes a root; id-0 attaches beneath it.
        reg.register_root(&id19).unwrap();
        reg.attach(&id0, &id19).unwrap();
        // Attach{id-19 -> id-5}: id-19 re-parents under id-5.
        reg.attach(&id19, &id5).unwrap();

        // Now the live tree is: id-11 -> id-5 -> {id-10, id-19 -> id-0}.
        // id-0's ancestor chain is id-0 -> id-19 -> id-5 -> id-11, so id-5 IS an
        // ancestor of id-0. Re-parenting id-5 under id-0 must be a cycle.
        assert!(reg.would_cycle(&id5, &id0));

        let before = reg.clone();
        assert_eq!(reg.attach(&id5, &id0), Err(IdentityError::OwnershipCycle));
        // Rejected: the registry is byte-for-byte unchanged (atomic failure).
        assert_eq!(reg, before);
    }

    #[test]
    fn deep_reparent_of_internal_node_updates_all_descendants() {
        // Build two trees:
        //   rootA(0) -> x(1) -> y(2) -> z(3)
        //   rootB(0)
        // Then re-parent the INTERNAL node `x` (which has descendants y, z) under rootB.
        // x and its whole subtree must have depth/path recomputed (no stale paths).
        let mut reg = OwnershipRegistry::new();
        let root_a = id("rootA");
        let root_b = id("rootB");
        let x = id("x");
        let y = id("y");
        let z = id("z");
        reg.register_root(&root_a).unwrap();
        reg.register_root(&root_b).unwrap();
        reg.attach(&x, &root_a).unwrap();
        reg.attach(&y, &x).unwrap();
        reg.attach(&z, &y).unwrap();
        assert_eq!(reg.depth_of(&z), Some(3));

        // Re-parent x (internal) under rootB: rootB -> x -> y -> z.
        let new_path_x = reg.attach(&x, &root_b).expect("rootB is not in x's subtree");
        assert_eq!(new_path_x, vec![root_b.clone(), x.clone()]);

        // x's own owner/depth/path are recomputed.
        assert_eq!(reg.owner_of(&x), Some(&root_b));
        assert_eq!(reg.depth_of(&x), Some(1));
        assert_eq!(reg.path_of(&x), Some(&vec![root_b.clone(), x.clone()]));

        // Descendants y and z are recomputed too (no stale paths/depths).
        assert_eq!(reg.owner_of(&y), Some(&x));
        assert_eq!(reg.depth_of(&y), Some(2));
        assert_eq!(
            reg.path_of(&y),
            Some(&vec![root_b.clone(), x.clone(), y.clone()])
        );
        assert_eq!(reg.owner_of(&z), Some(&y));
        assert_eq!(reg.depth_of(&z), Some(3));
        assert_eq!(
            reg.path_of(&z),
            Some(&vec![root_b.clone(), x.clone(), y.clone(), z.clone()])
        );

        // Every node still satisfies len(path) == depth + 1.
        for node in reg.iter() {
            assert_eq!(node.path().len() as u32, node.depth() + 1);
        }
        // No nodes created or removed by the re-parent.
        assert_eq!(reg.len(), 5);
    }

    #[test]
    fn deep_reparent_exceeding_depth_is_rejected_atomically() {
        // Build a chain rootA(0) -> n1(1) -> ... -> n15(15), where n15 is a leaf at
        // depth 15 and n1 is internal with a 14-deep subtree below it.
        // Re-parenting n1 (currently depth 1) under the depth-15 leaf `deep` would push
        // its deepest descendant past MAX_DEPTH (16) and must be rejected atomically.
        let mut reg = OwnershipRegistry::new();
        let root_a = id("rootA");
        reg.register_root(&root_a).unwrap();

        // chain: rootA -> c1 -> c2 -> ... -> c15  (c15 at depth 15)
        let mut owner = root_a.clone();
        let mut chain = Vec::new();
        for d in 1..=15u32 {
            let node = id(&format!("c{d}"));
            reg.attach(&node, &owner).unwrap();
            assert_eq!(reg.depth_of(&node), Some(d));
            chain.push(node.clone());
            owner = node;
        }
        let deep_leaf = chain.last().unwrap().clone(); // c15 at depth 15
        let c1 = chain[0].clone(); // depth 1, subtree c1..c15 (deepest relative offset 14)

        // Re-parent c1 under c15: c1 would become depth 16, c2 depth 17 > MAX_DEPTH.
        // Note c15 is NOT in c1's subtree? It is: c1 -> c2 -> ... -> c15, so this is
        // actually a cycle. Use an independent leaf instead to isolate the depth check.
        // Build a separate deep anchor so the move is acyclic but over-deep.
        let _ = deep_leaf;

        // Independent deep anchor tree: rootB -> b1 -> ... -> b15 (b15 at depth 15),
        // disjoint from the c-chain so moving the c-subtree under b15 forms no cycle.
        let root_b = id("rootB");
        reg.register_root(&root_b).unwrap();
        let mut bowner = root_b.clone();
        for d in 1..=15u32 {
            let node = id(&format!("b{d}"));
            reg.attach(&node, &bowner).unwrap();
            bowner = node;
        }
        let b15 = id("b15");
        assert_eq!(reg.depth_of(&b15), Some(15));

        // Moving c1 (subtree depth-span 14: c1..c15) under b15 (depth 15) would make
        // c1 depth 16 and c15 depth 30 — far past MAX_DEPTH. Must reject atomically.
        assert!(!reg.would_cycle(&c1, &b15), "b15 is in a disjoint tree, no cycle");
        let before = reg.clone();
        assert_eq!(
            reg.attach(&c1, &b15),
            Err(IdentityError::OwnershipDepthExceeded)
        );
        // The whole registry (both trees) is unchanged.
        assert_eq!(reg, before);
        // c1's subtree kept its original depths/paths.
        assert_eq!(reg.depth_of(&c1), Some(1));
        assert_eq!(reg.depth_of(&id("c15")), Some(15));
    }
}
