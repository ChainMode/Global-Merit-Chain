# Security Policy

## Supported Versions

| Version / Branch | Status | Scope |
|---|---|---|
| `main` (`0.2.x`) | Supported | `gmc-core`, `gmc-identity`, `gmc-node` BFT testnet & `Meritora Desktop` preview |
| `< 0.2.0` | Unsupported | Early single-node / pre-BFT snapshots |

## GMChain Security Model Scope

We welcome security reports covering any component of the **GMChain (`公誉链`)** workspace:

1. **Ed25519 Strict Cryptographic Verification (`gmc-node::crypto` & `gmc-identity`)**:
   - Signature malleability, small-order public key bypasses, domain-separation collisions (`gmc.bft.vote.v1`), replay/nonce bypasses in `IdentityState::apply`, M-of-N guardian recovery threshold bypasses, or operator secret key (`0600`) leakage.
2. **Two-Phase BFT Consensus & Equivocation Ejection (`gmc-node::consensus` & `gmc-node::network`)**:
   - Quorum Certificate (`QuorumCertificate`) forgery below `(2 * N) / 3 + 1` active validators, split-brain `StateRoot` divergence across honest validators, bypass of `EquivocationEvidence` validator ejection, or unbounded frame / memory exhaustion (`> 256 KiB`) on peer TCP or loopback RPC sockets.
3. **Cross-Node Fixed-Point Determinism (`gmc-core`)**:
   - Any non-determinism, integer overflow/underflow, or `minMerit` monotonicity violation in `i128` (`SCALE = 1_000_000`) exponential decay, concave governance weighting, intimacy computation, or two-stage penalty/appeal restoration.
4. **FayID `gmcref_` Privacy & Human Prime Protection**:
   - Any path allowing plaintext `Human Prime` (`人类原型`) root identifiers (`hid_...`) to enter GMChain state, WAL frames, snapshots, or `ValidatorSet` records instead of blinded `OpaqueRef` (`gmcref_...`) commitments or accountable entity prefixes (`ifay_`, `cofay_`, `org_`).
5. **Zero-Fee & Non-Monetary Constitutional Invariants**:
   - Any path minting non-zero block/validator rewards (`NODE_BLOCK_REWARD = 0`, `VALIDATOR_REWARD = 0`), charging non-zero transaction fees (`TRANSACTION_FEE = 0`), or permitting monetary transfer, exchange, or stake-slashing of `MeriToken` (`美誉值`, `μ`).

## Reporting a Vulnerability

Please **do NOT open a public GitHub Issue or Pull Request** for undisclosed security vulnerabilities.

1. **Primary Channel — GitHub Private Vulnerability Reporting (Recommended)**:
   Submit a confidential advisory directly via **GitHub Security Advisories** on [`ChainMode/Global-Merit-Chain`](https://github.com/ChainMode/Global-Merit-Chain/security/advisories/new).
2. **Fallback Email Channels**:
   If GitHub Private Vulnerability Reporting is unavailable, email full reproduction details (affected crate/commit, minimal PoC or test vector, and impact assessment) to:
   - **`jah.g@ifay.ai`**
   - **`hello@meritora.org`**

## Response Targets

- **Initial acknowledgment**: within **72 hours**.
- **Triage & severity assessment**: within **7 business days**.
- **Coordinated fix & advisory publication**: scheduled with the reporter once a deterministic regression test and patch are verified across the workspace.
