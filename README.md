# Global Merit Chain（GMChain / 公誉链）

[![Docs CI](https://github.com/ChainMode/Global-Merit-Chain/actions/workflows/docs-ci.yml/badge.svg)](https://github.com/ChainMode/Global-Merit-Chain/actions/workflows/docs-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Docs: CC BY 4.0](https://img.shields.io/badge/Docs-CC%20BY%204.0-lightgrey.svg)](./LICENSE-DOCS)
[![Website: ifay.ai](https://img.shields.io/badge/Website-ifay.ai-blue)](https://ifay.ai)
[![Meritora](https://img.shields.io/badge/Meritora-meritora--site.vercel.app-0f766e)](https://meritora-site.vercel.app)

**GMChain** (**Global Merit Chain** / **公誉链**) is the zero-fee, strictly non-monetary social contribution ledger and BFT governance infrastructure of the **iFay** ecosystem, where **MeriToken** (`美誉值`, unit `μ` / `Merit Unit`) measures real societal contribution and is never cashable, speculative, or transferable.

**GMChain（公誉链）** 是 iFay 生态系统的社会贡献度量与治理基础设施。GMChain 并非金融交易市场：**MeriToken（美誉值，最小计量单位 `μ` / `MU`）严格非货币**——不可套现、不可投机、不可转让、不可与法币双向兑换，且节点与验证者出块、投票均不产生任何 `MeriToken` 奖励、交易手续费或质押罚没（`NODE_TRANSACTION_FEE = 0`、`NODE_BLOCK_REWARD = 0`、`VALIDATOR_REWARD = 0`、初始美誉值基线 `B_i = 0`）。长期话语权完全由持续真实的社会贡献决定，并通过指数批次衰减与历史贡献底值（`minMerit`）保持动态平衡。

## 工作区架构（Workspace Crates）

| Crate | 定位 | 运行时依赖约束 |
|---|---|---|
| `crates/gmc-core` | 纯逻辑协议内核：功勋链派生树、配额刷新、三维评分、`MeriToken` 指数衰减与底值单调性、受约束单向冷启动引导、反刷票与加权投票、社会关系图谱与亲密度引擎（含继承留存映射）、两阶段惩罚与限时申诉引擎、L1/L2 结算纯逻辑模型 | **零运行时依赖**（`[dependencies]` 为空）；全量采用确定性 `i128` 定点十进制算术（`SCALE = 1_000_000`），严禁 `f32`/`f64` 浮点数 |
| `crates/gmc-identity` | 纯逻辑身份与账户层：`IdentityId` 派生与 `FayID` 规范字符串双向无损互操作、`OpaqueRef`（`gmcref_`）人类原型（Human Prime）盲承诺守卫、`coFay` 单层归属与两类代表授权、宿主（Host）终端设备凭证、密钥轮换与守护人 M-of-N 社交恢复、唯一已签名操作入口 `IdentityState::apply`（全量路由 8 类操作载荷） | **零外部运行时依赖**（仅依赖 `gmc-core`）；密码学运算通过 `Signer` / `Verifier` trait 注入 |
| `crates/gmc-node` | 多节点确定性两阶段 BFT 运行时与 `Meritora Desktop` 本地工作台（库与 `gmc-node` CLI）：真实 `ed25519-dalek` 严格验签与启动 RFC 8032 KAT 自检、许可制可问责验证者集（`ValidatorSet`）、两阶段 BFT 法定人数证书（`QuorumCertificate`）与非货币双签证据驱逐（`EquivocationEvidence`）、有界 TCP 点对点集群传输、长度前缀 + SHA-256 帧校验追加写日志（`wal.log`）与原子快照（`snapshot.json`）、本地回环 CORS JSON-RPC 2.0 控制面及内置双语图形工作台 | 仅封装离线缓存的基础密码学与序列化库（`ed25519-dalek`、`sha2`、`blake3`、`serde`、`serde_json`、`hex`、`zeroize`） |

其他仓库目录：
- `docs/`：多语言设计蓝图与协议规范文档（`docs/zh-CN/blueprint/` 为中文权威基准）。
- `scripts/`：一键公共测试网与实时 HTTP RPC / Explorer 启动套件（`./scripts/start-testnet.sh`，默认监听 `http://127.0.0.1:8546`）。
- `desktop/`：`Meritora Desktop (Preview v0.2)` 跨平台本地启动器（macOS `.command` / Linux `.sh` / Windows `.bat`）。
- `schema/` 与 `vectors/`：跨实现确定性一致性 JSON Schema 与标准测试向量。

## 一键启动公共测试网套件（`start-testnet.sh` / `gmc-node testnet`）

单条命令拉起预置 4 验证者两阶段 BFT 委员会、创世 `iFay` / `coFay` 席位、双边社交亲密度图谱（自动排除 `intimacy > 0.90` 亲友团反作弊过滤）、贡献任务悬赏与社区治理提案的实时测试网节点（默认绑定 `http://127.0.0.1:8546`，可直接与 `Meritora` 在线工作台 `/workbench` 联调）：

```bash
./scripts/start-testnet.sh
# 或直接调用 gmc-node CLI：
cargo run -p gmc-node -- testnet --data-dir ./testnet-data --addr 127.0.0.1:8546
```

实时 HTTP Explorer / Bounty / Governance REST 与 JSON-RPC 2.0 端点：
- `GET /api/explorer?elapsed_days=0`（或 JSON-RPC `gmc_explorer`）：实时检视区块、`QuorumCertificate`、4 验证者状态及各主体随时间指数衰减的 `MeritPocket`（`μ` 与 `minMerit` 底值）；
- `POST /api/bounties`（`gmc_publishBounty`）与 `POST /api/bounties/deliver`（`gmc_submitDeliverable`）：发布设定目标美誉值 `μ` 与衰减周期天数的任务悬赏并提交交付物；
- `POST /api/bounties/vote`（`gmc_voteBounty`）：执行干系人加权投票，自动拦截高亲密度者（`intimacy > 0.90`）并在达成 `>= 2/3` 法定门槛时零手续费自动铸造带衰减期限的 `MeriToken (μ)` 批次、出块落盘；
- `POST /api/proposals`（`gmc_createProposal`）与 `POST /api/proposals/vote`（`gmc_voteProposal`）：按参与者实时衰减后的 `MeriToken` 占比对社区治理提案加权投票并锚定 L1 结果。

## 构建与质量校验

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## 多节点 BFT 集群快速体验（`cluster-demo`）

单条命令在本地回环（`127.0.0.1:0` 动态端口）拉起真实的 **4 验证者 TCP 两阶段 BFT 集群**（`N = 4`，法定门槛 `3/4`，最终性预算 `<= 3000ms`），自动完成：
1. **Height 1（4/4 在线）**：`iFay` 注册 + L2 贡献批次零手续费结算与 `QuorumCertificate` 签名聚合；
2. **Height 2（1 节点离线 + 双签故障注入）**：3/4 诚实验证者达成超多数法定人数推进区块高度，并通过 TCP 捕获双签证据（`EquivocationEvidence`）即时剔除作恶验证者，严格校验所有诚实节点 `StateRoot` 逐字节一致：

```bash
cargo run -p gmc-node -- cluster-demo --data-dir ./tmp-cluster --validators 4
```

## `Meritora Desktop` 预览版启动指南（Workbench UI）

启动本地 4 验证者委员会支持的图形化工作台与 CORS JSON-RPC 端点（默认监听 `http://127.0.0.1:8787`，零外部 CDN 依赖，支持中/英双语切换、实时 `StateRoot` 与 `QuorumCertificate` 检视、一键演示贡献出块与 JSON 快照导出）：

```bash
cargo run -p gmc-node -- workbench --data-dir ./meritora-desktop-data --addr 127.0.0.1:8787
```

或直接使用 [`desktop/`](desktop/README.md) 目录下的跨平台原生启动器：
- **macOS**：双击 `desktop/Meritora-Desktop.command` 或运行 `./desktop/meritora-desktop.sh`
- **Linux**：运行 `./desktop/meritora-desktop.sh`
- **Windows**：双击或运行 `desktop\Meritora-Desktop.bat`

也可将本机节点绑定在 `127.0.0.1:8545` 以供浏览器端 [https://meritora-site.vercel.app](https://meritora-site.vercel.app) 在线工作台直连查询：

```bash
cargo run -p gmc-node -- workbench --data-dir ./meritora-desktop-data --addr 127.0.0.1:8545
```

## `gmc-node` 单节点运维子命令

```bash
# 初始化节点数据目录（生成 0600 权限运营者密钥并写入创世快照）
cargo run -p gmc-node -- init --data-dir /tmp/gmc-demo-node

# 查看节点状态、BFT 法定门槛与规范 SHA-256 StateRoot
cargo run -p gmc-node -- status --data-dir /tmp/gmc-demo-node

# 运行确定性端到端身份、亲密度、贡献与出块生命周期演示
cargo run -p gmc-node -- demo --data-dir /tmp/gmc-demo-node

# 手动触发零手续费、零验证者奖励的区块结算
cargo run -p gmc-node -- produce-block --data-dir /tmp/gmc-demo-node

# 启动仅监听本地回环的 HTTP / JSON-RPC 控制服务
cargo run -p gmc-node -- serve --data-dir /tmp/gmc-demo-node --addr 127.0.0.1:8545
```

## 双轨开源许可声明（Dual-Track Licensing）

本仓库采用 **双轨开源许可模型（Dual-Track Licensing）**：
- **源码、JSON Schema、测试向量与启动脚本**（`crates/`、`schema/`、`vectors/`、`desktop/` 等）：采用 **[MIT License](LICENSE)**。
- **协议规范与架构蓝图叙述文档**（`docs/` 目录下全部文档与图表）：采用 **[Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE-DOCS)**。

Copyright (c) 2025-2026 ChainMode contributors. 详见 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md) 与 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
