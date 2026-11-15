# Contributing to Global Merit Chain (GMChain / 公誉链)

Thank you for contributing to **Global Merit Chain (`GMChain` / `公誉链`)** — the non-monetary social contribution accounting and governance layer of the iFay ecosystem.

## Repository Overview

| Path | Responsibility | Dependency Rule |
|---|---|---|
| `crates/gmc-core` | Deterministic fixed-point (`i128`, `SCALE = 1_000_000`) protocol core: chain derivation, `MeriToken` exponential decay & `minMerit` floor, anti-collusion voting, social intimacy & inheritance mapping, two-stage penalty/appeal, and L1/L2 settlement models | **Zero runtime dependencies** (`[dependencies]` must remain empty; `f32`/`f64` floats strictly forbidden) |
| `crates/gmc-identity` | Scheme-agnostic identity & account layer: `IdentityId` <-> `FayID` lossless interop, blinded `OpaqueRef` (`gmcref_`) privacy guard, single-layer `coFay` ownership, Host device credentials, key rotation, M-of-N guardian recovery, and `IdentityState::apply` | **Depends only on `gmc-core`** (zero external cryptography or I/O crates) |
| `crates/gmc-node` | Persistent node & multi-validator two-phase BFT runtime (`ed25519-dalek` strict verification, `ValidatorSet`, `QuorumCertificate`, `EquivocationEvidence` ejection, bounded TCP cluster, WAL + atomic snapshot store, loopback CORS JSON-RPC, and `Meritora Desktop` UI) | Audited foundational crates only |
| `desktop/` | Cross-platform launchers (`.command`, `.sh`, `.bat`) for `Meritora Desktop (Preview v0.2)` | Shell / Batch wrappers |
| `schema/` & `vectors/` | Machine-readable JSON Schemas and cross-implementation conformance test vectors | Deterministic JSON |
| `docs/` | Protocol specifications and architecture blueprint chapters (`docs/zh-CN/blueprint/` is the authoritative baseline) | Markdown (`CC BY 4.0`) |

## Prerequisites

- **Rust `1.80+`** (`rustup`, `cargo`, `clippy`, `rustfmt`)

## Build, Lint & Verification Commands

Every change must follow **Test-Driven Development (TDD)** (author or extend unit/property/integration tests first, confirm failure, implement the minimal deterministic solution, and pass all workspace gates with zero warnings):

```bash
# 1. Run all unit, property-based (proptest), conformance-vector, and BFT integration tests
cargo test --workspace

# 2. Enforce zero Clippy warnings across all crates, binaries, and test targets
cargo clippy --workspace --all-targets -- -D warnings

# 3. Smoke-test the 4-validator TCP BFT cluster (quorum commit + equivocation ejection)
cargo run -p gmc-node -- cluster-demo --data-dir ./tmp-cluster
rm -rf ./tmp-cluster
```

## Commit Convention & Developer Certificate of Origin (DCO 1.1)

### Conventional Commits

Format commit titles using Conventional Commits:
- `feat(node): ...`
- `fix(core): ...`
- `docs(blueprint): ...`
- `test(identity): ...`
- `chore(governance): ...`

### DCO 1.1 Sign-Off (`git commit -s`)

We use the **Developer Certificate of Origin Version 1.1 (DCO 1.1)** (`https://developercertificate.org/`) instead of a separate Contributor License Agreement (CLA). Every commit must carry a real-identity `Signed-off-by` trailer generated via `git commit -s`:

```text
Signed-off-by: Your Name <your.email@example.com>
```

By adding `Signed-off-by`, you certify that you created the contribution or have the right to submit it under the repository's open-source licenses.

## Dual-Track Inbound = Outbound Licensing

Contributions are accepted under the **inbound = outbound** principle matching our dual-track license structure:

- **Code, JSON Schemas, Test Vectors & Scripts** (`crates/`, `schema/`, `vectors/`, `desktop/`): licensed under the **[MIT License](LICENSE)** (`Copyright (c) 2025-2026 ChainMode contributors`).
- **Specification & Blueprint Documentation** (`docs/`): licensed under **[Creative Commons Attribution 4.0 International (`CC BY 4.0`)](LICENSE-DOCS)** (`Copyright (c) 2025-2026 ChainMode contributors`).

## Terminology & Constitutional Invariants

All code comments, APIs, UI strings, and documentation must strictly uphold the iFay / GMChain terminology and constitutional rules:

1. **`Human Prime` / `人类原型`**: Always refer to natural-person users as `Human Prime` (`人类原型`). Never refer to a human being as `Host` (in the iFay architecture, `Host` refers exclusively to terminal hardware devices or runtime applications). Plaintext `hid_` identifiers must never be written on-chain; use blinded `gmcref_` commitments (`OpaqueRef`).
2. **`GMChain` / `公誉链`**: Use `Global Merit Chain` / `GMChain` / `公誉链` consistently.
3. **Strictly Non-Monetary `MeriToken` (`美誉值`, `μ` / `MU`)**:
   - `MeriToken` is a non-transferable, non-tradable measure of verified social contribution — never a financial token, currency, or speculative asset.
   - Constitutional constants `TRANSACTION_FEE = 0`, `NODE_BLOCK_REWARD = 0`, `VALIDATOR_REWARD = 0`, and initial baseline `B_i = 0` are immutable; validator accountability relies on cryptographic `EquivocationEvidence` ejection rather than monetary stake deposits or financial slashing.

## Questions & Security Issues

- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) (never file public issues for security bugs).
- For community conduct standards, see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
