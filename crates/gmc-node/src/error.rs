//! Machine-identifiable error types for `gmc-node`.

use core::fmt;

use gmc_core::error::GmcError;
use gmc_identity::error::IdentityError;

/// Convenience result alias used across `gmc-node`.
pub type NodeResult<T> = Result<T, NodeError>;

/// Unified error vocabulary for node startup, cryptography, persistence, runtime
/// execution, and loopback control endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// Node startup configuration failed validation.
    ConfigInvalid(String),
    /// Mandatory startup Ed25519 Known-Answer Test (KAT) failed.
    KatSelfTestFailed(String),
    /// Attempting to initialize an operator keystore that already exists on disk.
    KeyAlreadyExists(String),
    /// Operator keystore does not exist (node has not been initialized yet).
    KeyNotFound(String),
    /// Key material failed byte-length or curve-point validation.
    KeyFormatInvalid,
    /// Underlying filesystem or network I/O failure.
    Io(String),
    /// Write-Ahead Log frame failed magic/checksum validation at `offset`.
    WalCorrupted {
        /// Byte offset of the corrupted frame in `wal.log`.
        offset: u64,
        /// Diagnostic reason without secret material.
        reason: String,
    },
    /// Snapshot JSON failed deserialization or SHA-256 integrity check.
    SnapshotInvalid(String),
    /// Pure-logic `gmc-core` protocol error.
    Core(GmcError),
    /// Pure-logic `gmc-identity` validation/authentication error.
    Identity(IdentityError),
    /// Identical or conflicting-nonce operation is already staged or applied.
    DuplicateOperation,
    /// Pending operation mempool reached its bounded capacity.
    MempoolFull {
        /// Maximum staged operations allowed in memory.
        max_ops: usize,
    },
    /// HTTP/JSON-RPC request exceeded `MAX_REQUEST_BYTES` (`256 KiB`).
    RequestTooLarge {
        /// Maximum accepted request body size in bytes.
        max_bytes: usize,
    },
    /// Malformed HTTP or JSON-RPC control request.
    RpcInvalidRequest(String),
    /// Attempted to bind the local control endpoint to a non-loopback address.
    NonLoopbackBindForbidden(String),
    /// BFT validator set, proposal, vote, QuorumCertificate, or EquivocationEvidence failed verification.
    ConsensusInvalid(String),
    /// Multi-node BFT round exceeded `BFT_FINALITY_BUDGET_MS` (`3,000 ms`).
    FinalityTimeout {
        /// Observed elapsed duration in milliseconds.
        elapsed_ms: u64,
        /// Configured finality budget in milliseconds.
        budget_ms: u64,
    },
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::ConfigInvalid(msg) => write!(f, "config_invalid: {msg}"),
            NodeError::KatSelfTestFailed(msg) => write!(f, "kat_self_test_failed: {msg}"),
            NodeError::KeyAlreadyExists(path) => write!(f, "key_already_exists: {path}"),
            NodeError::KeyNotFound(path) => write!(f, "key_not_found: {path}"),
            NodeError::KeyFormatInvalid => write!(f, "key_format_invalid"),
            NodeError::Io(msg) => write!(f, "io_error: {msg}"),
            NodeError::WalCorrupted { offset, reason } => {
                write!(f, "wal_corrupted at byte {offset}: {reason}")
            }
            NodeError::SnapshotInvalid(msg) => write!(f, "snapshot_invalid: {msg}"),
            NodeError::Core(err) => write!(f, "core_error: {err:?}"),
            NodeError::Identity(err) => write!(f, "identity_error: {err:?}"),
            NodeError::DuplicateOperation => write!(f, "duplicate_operation"),
            NodeError::MempoolFull { max_ops } => {
                write!(f, "mempool_full: limit {max_ops} reached")
            }
            NodeError::RequestTooLarge { max_bytes } => {
                write!(f, "request_too_large: exceeds {max_bytes} bytes")
            }
            NodeError::RpcInvalidRequest(msg) => write!(f, "rpc_invalid_request: {msg}"),
            NodeError::NonLoopbackBindForbidden(addr) => {
                write!(f, "non_loopback_bind_forbidden: {addr}")
            }
            NodeError::ConsensusInvalid(msg) => {
                write!(f, "consensus_invalid: {msg}")
            }
            NodeError::FinalityTimeout {
                elapsed_ms,
                budget_ms,
            } => {
                write!(
                    f,
                    "finality_timeout: elapsed {elapsed_ms}ms exceeds budget {budget_ms}ms"
                )
            }
        }
    }
}

impl std::error::Error for NodeError {}

impl From<GmcError> for NodeError {
    fn from(err: GmcError) -> Self {
        NodeError::Core(err)
    }
}

impl From<IdentityError> for NodeError {
    fn from(err: IdentityError) -> Self {
        NodeError::Identity(err)
    }
}

impl From<std::io::Error> for NodeError {
    fn from(err: std::io::Error) -> Self {
        NodeError::Io(err.to_string())
    }
}
