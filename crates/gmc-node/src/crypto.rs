//! Real Ed25519 cryptography (`ed25519-dalek`), RFC 8032 startup Known-Answer Tests,
//! and zeroized `0600` operator keystore management.
//!
//! `gmc-identity` deliberately defines scheme-agnostic `Signer` and `Verifier` traits
//! with zero cryptographic dependencies. This module supplies the concrete Ed25519
//! implementation injected at the node boundary, enforces strict non-malleable
//! verification (`verify_strict`), runs mandatory RFC 8032 KAT self-tests on startup,
//! and ensures operator secret seeds are zeroed on drop and never exposed via `Debug`,
//! serialization, logs, or control responses.

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey,
};
use zeroize::Zeroizing;

use gmc_identity::error::{IdentityError, IdentityResult};
use gmc_identity::identity_core::{canonical_encode_operation, OperationPayload, SignedOperation};
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::scheme::{SchemeDescriptor, SchemeRegistry};
use gmc_identity::signer::{Signer, Verifier};
use gmc_identity::types::{Nonce, SchemeTag, Signature, SigningKey, VerifyingKey};

use crate::error::{NodeError, NodeResult};

/// Exact byte length of an Ed25519 secret seed (`32` bytes).
pub const ED25519_SEED_LEN: usize = 32;
/// Exact byte length of an Ed25519 compressed Edwards-Y verifying key (`32` bytes).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Exact byte length of an Ed25519 signature (`64` bytes).
pub const ED25519_SIGNATURE_LEN: usize = 64;

const KEYSTORE_DIR_NAME: &str = "keystore";
const OPERATOR_KEY_FILE_NAME: &str = "operator.key";

// Official IETF RFC 8032 §7.1 Test Vector 1 (empty message)
const RFC8032_TV1_SK_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_TV1_PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_TV1_SIG_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// Official IETF RFC 8032 §7.1 Test Vector 2 (1-byte message 0x72)
const RFC8032_TV2_SK_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const RFC8032_TV2_PK_HEX: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const RFC8032_TV2_MSG: &[u8] = &[0x72];
const RFC8032_TV2_SIG_HEX: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

/// Ensures the canonical `ed25519` descriptor (`32`-byte keys, `64`-byte signatures)
/// is registered in `registry`. Idempotent if already present.
pub fn register_ed25519_scheme(registry: &mut SchemeRegistry) {
    if !registry.contains(&SchemeTag::ed25519()) {
        let _ = registry.register(SchemeDescriptor::ed25519());
    }
}

/// Concrete Ed25519 message signer implementing [`gmc_identity::signer::Signer`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed25519Signer;

impl Signer for Ed25519Signer {
    fn scheme_tag(&self) -> SchemeTag {
        SchemeTag::ed25519()
    }

    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> IdentityResult<Signature> {
        if sk.as_bytes().len() != ED25519_SEED_LEN {
            return Err(IdentityError::KeyFormatInvalid);
        }
        let mut seed_buf = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        seed_buf.copy_from_slice(sk.as_bytes());
        let signing_key = DalekSigningKey::from_bytes(&seed_buf);
        let sig = signing_key.sign(msg);
        Ok(Signature::new(sig.to_bytes().to_vec()))
    }
}

/// Concrete strict Ed25519 signature verifier implementing [`gmc_identity::signer::Verifier`].
///
/// Uses [`DalekVerifyingKey::verify_strict`] to reject small-order public keys and
/// non-canonical scalar `S` encodings, guaranteeing deterministic verification across nodes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn scheme_tag(&self) -> SchemeTag {
        SchemeTag::ed25519()
    }

    fn verify(&self, vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
        let Ok(vk_bytes): Result<[u8; ED25519_PUBLIC_KEY_LEN], _> = vk.as_bytes().try_into() else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; ED25519_SIGNATURE_LEN], _> = sig.as_bytes().try_into()
        else {
            return false;
        };
        let Ok(verifying_key) = DalekVerifyingKey::from_bytes(&vk_bytes) else {
            return false;
        };
        let signature = DalekSignature::from_bytes(&sig_bytes);
        verifying_key.verify_strict(msg, &signature).is_ok()
    }
}

/// Deterministically derives an Ed25519 `(SigningKey, VerifyingKey)` pair from a 32-byte seed.
pub fn keypair_from_seed(seed: &[u8; ED25519_SEED_LEN]) -> (SigningKey, VerifyingKey) {
    let dalek_sk = DalekSigningKey::from_bytes(seed);
    let dalek_vk = dalek_sk.verifying_key();
    (
        SigningKey::new(seed.to_vec()),
        VerifyingKey::new(dalek_vk.to_bytes().to_vec()),
    )
}

/// Builds and signs a canonical [`SignedOperation`] under `ed25519` using `signing_key`.
pub fn sign_ed25519_operation(
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    declared_target: IdentityId,
    payload: OperationPayload,
    nonce: Nonce,
) -> IdentityResult<SignedOperation> {
    let msg = canonical_encode_operation(&declared_target, &payload, nonce);
    let sig = Ed25519Signer.sign(signing_key, &msg)?;
    Ok(SignedOperation::new(
        declared_target,
        payload,
        nonce,
        SchemeTag::ed25519(),
        verifying_key.clone(),
        sig,
    ))
}

/// Runs mandatory Ed25519 Known-Answer Tests (RFC 8032 §7.1 Vectors 1 & 2,
/// `SchemeRegistry` descriptor checks, and tamper rejection).
///
/// Node startup MUST invoke this check and abort immediately if it returns `Err`.
pub fn run_ed25519_kat_self_test(registry: &SchemeRegistry) -> NodeResult<()> {
    run_ed25519_kat_internal(registry, RFC8032_TV1_SIG_HEX)
}

/// Internal KAT runner allowing fault-injection tests to supply a corrupted expected
/// signature hex and verify fail-closed startup abort.
pub fn run_ed25519_kat_internal(
    registry: &SchemeRegistry,
    expected_tv1_sig_hex: &str,
) -> NodeResult<()> {
    let descriptor = registry
        .resolve(&SchemeTag::ed25519())
        .map_err(|_| NodeError::KatSelfTestFailed("ed25519 missing from SchemeRegistry".into()))?;

    let check_vector =
        |label: &str, sk_hex: &str, pk_hex: &str, msg: &[u8], sig_hex: &str| -> NodeResult<()> {
            let sk_vec = hex::decode(sk_hex)
                .map_err(|e| NodeError::KatSelfTestFailed(format!("{label} sk hex: {e}")))?;
            let expected_pk = hex::decode(pk_hex)
                .map_err(|e| NodeError::KatSelfTestFailed(format!("{label} pk hex: {e}")))?;
            let expected_sig = hex::decode(sig_hex)
                .map_err(|e| NodeError::KatSelfTestFailed(format!("{label} sig hex: {e}")))?;

            let seed: [u8; 32] = sk_vec
                .try_into()
                .map_err(|_| NodeError::KatSelfTestFailed(format!("{label} invalid sk len")))?;
            let (sk, vk) = keypair_from_seed(&seed);

            descriptor
                .validate_verifying_key(vk.as_bytes())
                .map_err(|_| NodeError::KatSelfTestFailed(format!("{label} vk format invalid")))?;
            if vk.as_bytes() != expected_pk.as_slice() {
                return Err(NodeError::KatSelfTestFailed(format!(
                    "{label} derived public key mismatch"
                )));
            }

            let sig = Ed25519Signer
                .sign(&sk, msg)
                .map_err(|_| NodeError::KatSelfTestFailed(format!("{label} signing failed")))?;
            descriptor
                .validate_signature(sig.as_bytes())
                .map_err(|_| NodeError::KatSelfTestFailed(format!("{label} sig format invalid")))?;
            if sig.as_bytes() != expected_sig.as_slice() {
                return Err(NodeError::KatSelfTestFailed(format!(
                    "{label} deterministic signature mismatch"
                )));
            }

            if !Ed25519Verifier.verify(&vk, msg, &sig) {
                return Err(NodeError::KatSelfTestFailed(format!(
                    "{label} valid signature rejected"
                )));
            }

            // 1-bit signature tamper must be rejected.
            let mut tampered_sig_bytes = sig.as_bytes().to_vec();
            tampered_sig_bytes[0] ^= 0x01;
            let tampered_sig = Signature::new(tampered_sig_bytes);
            if Ed25519Verifier.verify(&vk, msg, &tampered_sig) {
                return Err(NodeError::KatSelfTestFailed(format!(
                    "{label} tampered signature accepted"
                )));
            }

            // Wrong message must be rejected.
            let mut wrong_msg = msg.to_vec();
            wrong_msg.push(0xFF);
            if Ed25519Verifier.verify(&vk, &wrong_msg, &sig) {
                return Err(NodeError::KatSelfTestFailed(format!(
                    "{label} tampered message accepted"
                )));
            }

            Ok(())
        };

    check_vector(
        "RFC8032-TV1",
        RFC8032_TV1_SK_HEX,
        RFC8032_TV1_PK_HEX,
        b"",
        expected_tv1_sig_hex,
    )?;
    check_vector(
        "RFC8032-TV2",
        RFC8032_TV2_SK_HEX,
        RFC8032_TV2_PK_HEX,
        RFC8032_TV2_MSG,
        RFC8032_TV2_SIG_HEX,
    )?;

    Ok(())
}

/// Non-exportable, zeroize-on-drop operator keypair held in memory by `gmc-node`.
///
/// Intentionally omits `Clone`, `Serialize`, and any accessor returning secret seed bytes.
/// `Debug` redacts the secret key unconditionally.
pub struct OperatorKeypair {
    seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
    verifying_key: VerifyingKey,
    node_id: IdentityId,
}

impl fmt::Debug for OperatorKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorKeypair")
            .field("node_id", &self.node_id.canonical())
            .field(
                "verifying_key_hex",
                &hex::encode(self.verifying_key.as_bytes()),
            )
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl OperatorKeypair {
    /// Builds an [`OperatorKeypair`] from a 32-byte seed, deriving its Ed25519
    /// [`VerifyingKey`] and deterministic [`IdentityId`].
    pub fn from_seed(registry: &SchemeRegistry, seed: [u8; ED25519_SEED_LEN]) -> NodeResult<Self> {
        let zeroized_seed = Zeroizing::new(seed);
        let dalek_sk = DalekSigningKey::from_bytes(&zeroized_seed);
        let vk = VerifyingKey::new(dalek_sk.verifying_key().to_bytes().to_vec());
        let node_id = derive_identity_id(registry, &SchemeTag::ed25519(), &vk)?;
        Ok(OperatorKeypair {
            seed: zeroized_seed,
            verifying_key: vk,
            node_id,
        })
    }

    /// Public operator [`VerifyingKey`].
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Deterministic operator node [`IdentityId`] derived from `(ed25519, verifying_key)`.
    pub fn node_id(&self) -> &IdentityId {
        &self.node_id
    }

    /// Signs arbitrary bytes with the zeroized operator key without exporting secret material.
    pub fn sign_bytes(&self, msg: &[u8]) -> Signature {
        let dalek_sk = DalekSigningKey::from_bytes(&self.seed);
        Signature::new(dalek_sk.sign(msg).to_bytes().to_vec())
    }

    /// Signs a [`SignedOperation`] as this operator without exposing secret key bytes.
    pub fn sign_operation(
        &self,
        declared_target: IdentityId,
        payload: OperationPayload,
        nonce: Nonce,
    ) -> SignedOperation {
        let msg = canonical_encode_operation(&declared_target, &payload, nonce);
        let sig = self.sign_bytes(&msg);
        SignedOperation::new(
            declared_target,
            payload,
            nonce,
            SchemeTag::ed25519(),
            self.verifying_key.clone(),
            sig,
        )
    }
}

/// Manages `<data_dir>/keystore/operator.key` with strict `0600` create-exclusive
/// permissions so an existing operator key is never silently overwritten.
pub struct OperatorKeyStore;

impl OperatorKeyStore {
    /// Canonical path `<data_dir>/keystore/operator.key`.
    pub fn key_file_path(data_dir: &Path) -> PathBuf {
        data_dir
            .join(KEYSTORE_DIR_NAME)
            .join(OPERATOR_KEY_FILE_NAME)
    }

    /// Returns `true` if `<data_dir>/keystore/operator.key` already exists.
    pub fn exists(data_dir: &Path) -> bool {
        Self::key_file_path(data_dir).exists()
    }

    /// Generates a fresh CSPRNG-seeded operator keypair via OS entropy (`/dev/urandom`)
    /// and writes it exclusively (`create_new(true)`, Unix mode `0600`).
    ///
    /// Fails with [`NodeError::KeyAlreadyExists`] if `operator.key` already exists.
    pub fn init_random(data_dir: &Path, registry: &SchemeRegistry) -> NodeResult<OperatorKeypair> {
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        fill_os_random_bytes(&mut *seed)?;
        Self::init_with_seed(data_dir, registry, *seed)
    }

    /// Persists a caller-supplied 32-byte seed exclusively (`create_new(true)`, Unix
    /// mode `0600`) and returns the resulting [`OperatorKeypair`].
    ///
    /// Refuses to overwrite an existing key file ([`NodeError::KeyAlreadyExists`]).
    pub fn init_with_seed(
        data_dir: &Path,
        registry: &SchemeRegistry,
        seed: [u8; ED25519_SEED_LEN],
    ) -> NodeResult<OperatorKeypair> {
        let keystore_dir = data_dir.join(KEYSTORE_DIR_NAME);
        fs::create_dir_all(&keystore_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&keystore_dir, fs::Permissions::from_mode(0o700));
        }

        let key_path = Self::key_file_path(data_dir);
        if key_path.exists() {
            return Err(NodeError::KeyAlreadyExists(
                key_path.to_string_lossy().into_owned(),
            ));
        }

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut file = match opts.open(&key_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(NodeError::KeyAlreadyExists(
                    key_path.to_string_lossy().into_owned(),
                ));
            }
            Err(e) => return Err(NodeError::Io(e.to_string())),
        };

        let zeroized_seed = Zeroizing::new(seed);
        file.write_all(&*zeroized_seed)?;
        file.sync_all()?;

        OperatorKeypair::from_seed(registry, *zeroized_seed)
    }

    /// Loads an existing operator keypair from `<data_dir>/keystore/operator.key`.
    pub fn load(data_dir: &Path, registry: &SchemeRegistry) -> NodeResult<OperatorKeypair> {
        let key_path = Self::key_file_path(data_dir);
        if !key_path.exists() {
            return Err(NodeError::KeyNotFound(
                key_path.to_string_lossy().into_owned(),
            ));
        }

        let mut file = File::open(&key_path)?;
        let mut raw = Zeroizing::new(Vec::with_capacity(ED25519_SEED_LEN));
        file.read_to_end(&mut raw)?;
        if raw.len() != ED25519_SEED_LEN {
            return Err(NodeError::KeyFormatInvalid);
        }
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        seed.copy_from_slice(&raw);
        OperatorKeypair::from_seed(registry, *seed)
    }
}

fn fill_os_random_bytes(dest: &mut [u8]) -> NodeResult<()> {
    #[cfg(unix)]
    {
        let mut f = File::open("/dev/urandom")?;
        f.read_exact(dest)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        return Err(NodeError::Io(
            "OS entropy source unavailable on non-Unix target".into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kat_self_test_passes_and_aborts_on_corrupted_expectation() {
        let mut registry = SchemeRegistry::default();
        register_ed25519_scheme(&mut registry);
        run_ed25519_kat_self_test(&registry).expect("RFC 8032 KAT must pass");

        // Corrupt 1 hex nibble in expected signature -> must fail closed.
        let mut bad_hex = RFC8032_TV1_SIG_HEX.to_string();
        bad_hex.replace_range(0..2, "00");
        let err = run_ed25519_kat_internal(&registry, &bad_hex).unwrap_err();
        assert!(matches!(err, NodeError::KatSelfTestFailed(_)));
    }

    #[test]
    fn operator_keypair_debug_redacts_secret_seed() {
        let registry = SchemeRegistry::default();
        let seed = [0x42u8; 32];
        let kp = OperatorKeypair::from_seed(&registry, seed).unwrap();
        let dbg = format!("{kp:?}");
        let secret_hex = hex::encode(seed);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&secret_hex));
    }
}
