//! `FayID` canonical string interoperability, `OpaqueRef` privacy guard, and
//! monotonic subkey `RevocationRegistry` (`align-identity-with-fayid-authority` +
//! FayID ADR 0002).
//!
//! ## Dependency Boundary (Req 3.4 / Req 10.5)
//!
//! Consistent with `gmc-identity`'s strict architectural seam, this module performs
//! **zero** Merit balance or decay arithmetic (`gmc_core::bootstrap` owns `OpaqueRef`
//! Merit / governance-weight aggregation). Here we own:
//!
//! 1. Reversible, lossless mapping between `ed25519` [`IdentityId`] and FayID's
//!    canonical `<prefix>_<lowercase-rfc4648-base32-nopad>` strings (`ifay_`, `cofay_`);
//! 2. Strict offline entity-prefix classification (`hid_`, `ifay_`, `cofay_`, `org_`,
//!    `dyn_`, `vrf_`, `grt_`, `gmcref_`) without truncation or silent repair;
//! 3. [`OpaqueRef`] (`gmcref_...`) type-level privacy guard ensuring plaintext `hid_`
//!    Human IDs never enter GMChain attribution bindings;
//! 4. Monotonic [`RevocationRegistry`] for subkeys/credentials (`revoked` never reverts).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{IdentityError, IdentityResult};
use crate::identity_id::{parse_identity_id, IdentityId};
use crate::scheme::SchemeRegistry;
use crate::types::{IdentityKind, SchemeTag};

/// Canonical `FayID` v1 entity prefix classes (FayID ADR 0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FayIdEntityKind {
    /// `hid_` — Natural-person Human Prime root identity (never written on GMChain).
    Human,
    /// `ifay_` — Personal digital avatar identity.
    IFay,
    /// `cofay_` — Single-layer collective/functional identity.
    CoFay,
    /// `org_` — Organization entity (`org_<base32-or-slug>`).
    Organization,
    /// `dyn_` — Short-lived dynamic proof code.
    DynamicCode,
    /// `vrf_` — Anti-counterfeiting verification record.
    VerificationRecord,
    /// `grt_` — Authorization grant record.
    AuthorizationGrant,
    /// `gmcref_` — Blind namespace-scoped natural-person commitment on GMChain.
    OpaqueRef,
}

/// Parsed canonical `FayID` entity string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFayIdEntity {
    /// Resolved entity class.
    pub kind: FayIdEntityKind,
    /// Payload following `<prefix>_`.
    pub body: String,
}

/// Strict parser for canonical `<prefix>_<body>` strings (FayID ADR 0002).
///
/// Rejects uppercase characters, `=` padding, empty bodies, or unknown prefixes with
/// [`IdentityError::IdentityIdFormatInvalid`] — never silently repairing input.
pub fn parse_fayid_entity(raw: &str) -> IdentityResult<ParsedFayIdEntity> {
    let Some((prefix, body)) = raw.split_once('_') else {
        return Err(IdentityError::IdentityIdFormatInvalid);
    };
    if body.is_empty() {
        return Err(IdentityError::IdentityIdFormatInvalid);
    }

    let kind = match prefix {
        "hid" => FayIdEntityKind::Human,
        "ifay" => FayIdEntityKind::IFay,
        "cofay" => FayIdEntityKind::CoFay,
        "org" => FayIdEntityKind::Organization,
        "dyn" => FayIdEntityKind::DynamicCode,
        "vrf" => FayIdEntityKind::VerificationRecord,
        "grt" => FayIdEntityKind::AuthorizationGrant,
        "gmcref" => FayIdEntityKind::OpaqueRef,
        _ => return Err(IdentityError::IdentityIdFormatInvalid),
    };

    let valid_body = match kind {
        FayIdEntityKind::Organization => body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        _ => is_lowercase_base32_nopad(body),
    };
    if !valid_body {
        return Err(IdentityError::IdentityIdFormatInvalid);
    }

    Ok(ParsedFayIdEntity {
        kind,
        body: body.to_owned(),
    })
}

/// Converts an `ed25519` [`IdentityId`] + [`IdentityKind`] into its lossless canonical
/// FayID string (`ifay_<base32>` or `cofay_<base32>`).
pub fn to_fayid_canonical(id: &IdentityId, kind: IdentityKind) -> IdentityResult<String> {
    if id.scheme_tag() != &SchemeTag::ed25519() {
        return Err(IdentityError::SchemeUnsupported);
    }
    if id.key_repr().is_empty() || !is_lowercase_base32_nopad(id.key_repr()) {
        return Err(IdentityError::IdentityIdFormatInvalid);
    }
    let prefix = match kind {
        IdentityKind::IFay => "ifay",
        IdentityKind::CoFay => "cofay",
    };
    Ok(format!("{prefix}_{}", id.key_repr()))
}

/// Converts a canonical `ifay_<base32>` or `cofay_<base32>` string back into its
/// [`IdentityId`] + [`IdentityKind`], enforcing exact round-trip validity via `schemes`.
pub fn from_fayid_canonical(
    schemes: &SchemeRegistry,
    canonical_fayid: &str,
) -> IdentityResult<(IdentityId, IdentityKind)> {
    let parsed = parse_fayid_entity(canonical_fayid)?;
    let kind = match parsed.kind {
        FayIdEntityKind::IFay => IdentityKind::IFay,
        FayIdEntityKind::CoFay => IdentityKind::CoFay,
        _ => return Err(IdentityError::IdentityIdFormatInvalid),
    };
    let internal = format!("fay1.ed25519.{}", parsed.body);
    let id = parse_identity_id(schemes, &internal)?;
    Ok((id, kind))
}

/// Type-safe wrapper for a blind GMChain natural-person commitment (`gmcref_<base32>`).
///
/// Guarantees by construction that plaintext `hid_` Human IDs cannot be stored on-chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueRef(String);

impl OpaqueRef {
    /// Parses a `gmcref_<base32>` string, rejecting `hid_` or any other prefix.
    pub fn parse(s: &str) -> IdentityResult<Self> {
        let parsed = parse_fayid_entity(s)?;
        if parsed.kind != FayIdEntityKind::OpaqueRef || parsed.body.len() < 16 {
            return Err(IdentityError::IdentityIdFormatInvalid);
        }
        Ok(OpaqueRef(s.to_owned()))
    }

    /// Borrows the canonical `gmcref_...` string.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Privacy-preserving `iFay -> OpaqueRef` binding table (without storing `hid_` or
/// performing Merit arithmetic inside `gmc-identity`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpaqueRefBinding {
    ifay_to_opaque: BTreeMap<String, OpaqueRef>,
    opaque_to_ifays: BTreeMap<OpaqueRef, BTreeSet<String>>,
}

impl OpaqueRefBinding {
    /// Creates an empty [`OpaqueRefBinding`] table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Associates a canonical `ifay_...` avatar with its Human Prime's blind [`OpaqueRef`].
    pub fn bind_ifay(&mut self, ifay_canonical: &str, opaque_ref: OpaqueRef) -> IdentityResult<()> {
        let parsed = parse_fayid_entity(ifay_canonical)?;
        if parsed.kind != FayIdEntityKind::IFay {
            return Err(IdentityError::IdentityIdFormatInvalid);
        }
        if let Some(existing) = self.ifay_to_opaque.get(ifay_canonical) {
            if existing != &opaque_ref {
                return Err(IdentityError::IdentityMismatch);
            }
            return Ok(());
        }
        self.ifay_to_opaque
            .insert(ifay_canonical.to_owned(), opaque_ref.clone());
        self.opaque_to_ifays
            .entry(opaque_ref)
            .or_default()
            .insert(ifay_canonical.to_owned());
        Ok(())
    }

    /// Resolves the [`OpaqueRef`] bound to `ifay_canonical`.
    pub fn opaque_ref_of(&self, ifay_canonical: &str) -> Option<&OpaqueRef> {
        self.ifay_to_opaque.get(ifay_canonical)
    }

    /// Lists all `ifay_` avatars bound to `opaque_ref` in deterministic order.
    pub fn ifays_of(&self, opaque_ref: &OpaqueRef) -> Vec<&str> {
        self.opaque_to_ifays
            .get(opaque_ref)
            .map(|set| set.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

/// Monotonic subkey/credential revocation registry (`align-identity-with-fayid-authority`).
///
/// Once an identifier (`dyn_`, `grt_`, `ifay_`, `cofay_`) is marked revoked, it can
/// never transition back to un-revoked; `hid_` root Human IDs are rejected because
/// Human IDs are never stored on GMChain and v1 forbids revoking a root Human ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationRegistry {
    revoked_at_secs: BTreeMap<String, u64>,
}

impl RevocationRegistry {
    /// Creates an empty [`RevocationRegistry`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `entity_id` as permanently revoked at `timestamp_secs` (idempotent on
    /// repeat calls, preserving the original revocation timestamp).
    pub fn revoke(&mut self, entity_id: &str, timestamp_secs: u64) -> IdentityResult<()> {
        let parsed = parse_fayid_entity(entity_id)?;
        if matches!(
            parsed.kind,
            FayIdEntityKind::Human | FayIdEntityKind::OpaqueRef
        ) {
            return Err(IdentityError::OwnerTypeNotAllowed);
        }
        self.revoked_at_secs
            .entry(entity_id.to_owned())
            .or_insert(timestamp_secs);
        Ok(())
    }

    /// `true` iff `entity_id` has been revoked.
    pub fn is_revoked(&self, entity_id: &str) -> bool {
        self.revoked_at_secs.contains_key(entity_id)
    }

    /// Returns the first-recorded revocation timestamp for `entity_id`, if revoked.
    pub fn revoked_at(&self, entity_id: &str) -> Option<u64> {
        self.revoked_at_secs.get(entity_id).copied()
    }
}

fn is_lowercase_base32_nopad(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
