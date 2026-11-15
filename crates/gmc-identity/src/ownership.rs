//! `Ownership_Registry` — single-layer `coFay` ownership bound to a `Human` or
//! `Organization` reference (`realign-cofay-ownership-to-fayid`, FayID ADR 0001).
//!
//! ## Architectural Boundary
//!
//! 1. **Single-Layer Only**: Every `coFay` is owned by exactly one natural person
//!    (`Human`) or organization (`Organization`). `coFay`s **cannot** nest, and an
//!    `iFay` **cannot** own a `coFay`. There is no ownership tree, no `OwnershipPath`,
//!    no `depth`, and no `ancestors_of`.
//! 2. **Self-Contained Offline Validation**: `gmc-identity` stores only the owner's
//!    identifier string and [`OwnerKind`] tag (plus an optional verifying key when
//!    bound locally) and validates type consistency offline without rebuilding the
//!    `HumanID` / `OrganizationID` identity lifecycle (whose authority lives in `FayID`).

use std::collections::BTreeMap;

use crate::error::{IdentityError, IdentityResult};
use crate::identity_id::IdentityId;
use crate::types::VerifyingKey;

/// Permitted legal/governance owner classes for a `coFay` (FayID ADR 0001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnerKind {
    /// Natural-person Human Prime (`hid_...`).
    Human,
    /// Organization entity (`org_...`).
    Organization,
}

impl OwnerKind {
    /// Parses `"human"` or `"organization"` into [`OwnerKind`], rejecting any other
    /// label (such as `"ifay"` or `"cofay"`) with [`IdentityError::OwnerTypeNotAllowed`].
    pub fn parse_label(label: &str) -> IdentityResult<Self> {
        match label {
            "human" => Ok(OwnerKind::Human),
            "organization" => Ok(OwnerKind::Organization),
            _ => Err(IdentityError::OwnerTypeNotAllowed),
        }
    }

    /// Stable machine label (`"human"` / `"organization"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            OwnerKind::Human => "human",
            OwnerKind::Organization => "organization",
        }
    }
}

/// Single-layer owner reference stored on GMChain without rebuilding `FayID` lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerRef {
    /// Owner identifier string (e.g. `hid_<base32>` or `org_<slug-or-base32>`).
    pub id: String,
    /// Declared owner entity class (`Human` or `Organization`).
    pub kind: OwnerKind,
}

impl OwnerRef {
    /// Builds an [`OwnerRef`].
    pub fn new(id: impl Into<String>, kind: OwnerKind) -> Self {
        OwnerRef {
            id: id.into(),
            kind,
        }
    }

    /// Offline type-consistency check (executable even when `FayID` is unreachable):
    ///
    /// - Rejects empty/whitespace identifiers;
    /// - Rejects `ifay_`, `cofay_`, `gmcref_`, `dyn_`, `vrf_`, `grt_`, `ifay-`,
    ///   `cofay-`, and `fay1.` prefixes unconditionally;
    /// - Rejects `org_` / `org-` under `OwnerKind::Human`, and `hid_` / `human-` under
    ///   `OwnerKind::Organization`.
    pub fn validate(&self) -> IdentityResult<()> {
        let s = self.id.trim();
        if s.is_empty() {
            return Err(IdentityError::OwnerTypeNotAllowed);
        }
        const ALWAYS_FORBIDDEN: &[&str] = &[
            "ifay_", "cofay_", "gmcref_", "dyn_", "vrf_", "grt_", "ifay-", "cofay-", "fay1.",
        ];
        if ALWAYS_FORBIDDEN.iter().any(|p| s.starts_with(p)) {
            return Err(IdentityError::OwnerTypeNotAllowed);
        }
        match self.kind {
            OwnerKind::Human => {
                if s.starts_with("org_") || s.starts_with("org-") {
                    return Err(IdentityError::OwnerTypeNotAllowed);
                }
            }
            OwnerKind::Organization => {
                if s.starts_with("hid_") || s.starts_with("human-") {
                    return Err(IdentityError::OwnerTypeNotAllowed);
                }
            }
        }
        Ok(())
    }
}

/// Flat single-layer `coFay -> OwnerRef` registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipRegistry {
    owners: BTreeMap<IdentityId, OwnerRef>,
    owner_keys: BTreeMap<IdentityId, VerifyingKey>,
}

impl OwnershipRegistry {
    /// Creates an empty single-layer [`OwnershipRegistry`].
    #[inline]
    pub fn new() -> Self {
        OwnershipRegistry {
            owners: BTreeMap::new(),
            owner_keys: BTreeMap::new(),
        }
    }

    /// Number of `coFay` ownership records stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// `true` iff no `coFay` ownership records are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// `true` iff `cofay` has a recorded single-layer owner.
    #[inline]
    pub fn contains(&self, cofay: &IdentityId) -> bool {
        self.owners.contains_key(cofay)
    }

    /// Returns the single-layer [`OwnerRef`] of `cofay`, if registered.
    #[inline]
    pub fn owner_of(&self, cofay: &IdentityId) -> Option<&OwnerRef> {
        self.owners.get(cofay)
    }

    /// Returns an explicitly bound owner [`VerifyingKey`] for `cofay` (e.g. for slug-based
    /// `org_` owners), if any.
    #[inline]
    pub fn owner_key_of(&self, cofay: &IdentityId) -> Option<&VerifyingKey> {
        self.owner_keys.get(cofay)
    }

    /// Validates `owner` offline and records `cofay -> owner`. On validation failure,
    /// returns [`IdentityError::OwnerTypeNotAllowed`] and mutates nothing.
    pub fn set_owner(&mut self, cofay: IdentityId, owner: OwnerRef) -> IdentityResult<()> {
        owner.validate()?;
        self.owners.insert(cofay, owner);
        Ok(())
    }

    /// Validates `owner` offline and records both `cofay -> owner` and an explicit
    /// owner [`VerifyingKey`] (for slug-addressed organizations or custom schemes).
    pub fn set_owner_with_key(
        &mut self,
        cofay: IdentityId,
        owner: OwnerRef,
        owner_key: VerifyingKey,
    ) -> IdentityResult<()> {
        owner.validate()?;
        self.owners.insert(cofay.clone(), owner);
        self.owner_keys.insert(cofay, owner_key);
        Ok(())
    }

    /// Raw string entry point validating `kind_label` (`"human"` | `"organization"`)
    /// and delegating to [`Self::set_owner`].
    pub fn set_owner_raw(
        &mut self,
        cofay: IdentityId,
        owner_id: impl Into<String>,
        kind_label: &str,
    ) -> IdentityResult<()> {
        let kind = OwnerKind::parse_label(kind_label)?;
        self.set_owner(cofay, OwnerRef::new(owner_id, kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SchemeTag;

    fn id(label: &str) -> IdentityId {
        IdentityId::new(SchemeTag::ed25519(), label)
    }

    #[test]
    fn accepts_human_and_organization_and_rejects_ifay_and_cofay() {
        let mut reg = OwnershipRegistry::new();
        let c1 = id("cofay1");
        let h = OwnerRef::new("hid_abc234567234567234567", OwnerKind::Human);
        reg.set_owner(c1.clone(), h.clone()).unwrap();
        assert_eq!(reg.owner_of(&c1), Some(&h));

        assert_eq!(
            reg.set_owner_raw(id("cofay2"), "ifay_abc", "ifay"),
            Err(IdentityError::OwnerTypeNotAllowed)
        );
        assert_eq!(
            reg.set_owner_raw(id("cofay2"), "cofay_abc", "cofay"),
            Err(IdentityError::OwnerTypeNotAllowed)
        );
        assert_eq!(reg.len(), 1);
    }
}
