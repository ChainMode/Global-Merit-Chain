# Global Merit Chain（GMChain / 公誉链）

**GMChain（公誉链）** 是 iFay 生态系统的社会贡献度量与治理基础设施。GMChain 并非金融交易市场：**MeriToken（美誉值，最小计量单位 `μ` / `MU`）严格非货币**——不可套现、不可投机、不可转让、不可与法币双向兑换，且节点出块不产生任何 `MeriToken` 挖矿奖励或交易手续费分成（`NODE_BLOCK_REWARD = 0`，`TRANSACTION_FEE = 0`）。长期话语权完全由持续真实的社会贡献决定，并通过指数批次衰减与历史贡献底值（`minMerit`）保持动态平衡。

## 工作区架构（Workspace Crates）

| Crate | 定位 | 运行时依赖约束 |
|---|---|---|
| `crates/gmc-core` | 纯逻辑协议内核：功勋链派生树、配额刷新、三维评分、`MeriToken` 指数衰减与底值单调性、受约束单向冷启动引导、反刷票与加权投票、社会关系图谱与亲密度引擎（含继承留存映射）、两阶段惩罚与限时申诉引擎、L1/L2 结算纯逻辑模型 | **零运行时依赖**（`[dependencies]` 为空）；全量采用确定性 `i128` 定点十进制算术（`SCALE = 1_000_000`），严禁 `f32`/`f64` 浮点数 |
| `crates/gmc-identity` | 纯逻辑身份与账户层：`IdentityId` 派生与 `FayID` 规范字符串双向无损互操作、`OpaqueRef`（`gmcref_`）人类原型盲承诺守卫、`coFay` 单层归属与两类代表授权、宿主（Host）终端设备凭证、密钥轮换与守护人 M-of-N 社交恢复、唯一已签名操作入口 `IdentityState::apply`（全量路由 8 类操作载荷） | **零外部运行时依赖**（仅依赖 `gmc-core`）；密码学运算通过 `Signer` / `Verifier` trait 注入 |
| `crates/gmc-node` | 单节点持久化测试网基线（库与 `gmc-node` CLI）：真实 `ed25519-dalek` 签名/严格验签与启动 RFC 8032 KAT 自检、`zeroize` 运营者密钥保护、长度前缀 + SHA-256 帧校验追加写日志（`wal.log`）与原子快照（`snapshot.json`）、确定性规范 SHA-256 `StateRoot`、L2→L1 批次承诺结算、零手续费/零出块奖励非货币守卫，以及本地回环（`127.0.0.1`，请求上限 `256 KiB`）HTTP/JSON-RPC 运维控制面 | 仅封装离线缓存的基础密码学与序列化库（`ed25519-dalek`、`sha2`、`blake3`、`serde`、`serde_json`、`hex`、`zeroize`） |

其他仓库目录：
- `docs/`：多语言设计蓝图文档（`docs/zh-CN/blueprint/` 为中文权威基准）。
- `schema/` 与 `vectors/`：跨实现确定性一致性 JSON Schema 与标准测试向量（归属模型、社会关系亲密度与继承映射、两阶段惩罚与申诉恢复）。

## 构建与离线验证

```bash
cargo test --workspace --offline
```

## `gmc-node` 快速上手（CLI Quickstart）

初始化本地节点数据目录（生成 `0600` 权限运营者密钥并写入创世状态）：

```bash
cargo run -p gmc-node --offline -- init --data-dir /tmp/gmc-demo-node
```

查看当前节点健康状态、区块高度、结算版本与规范 SHA-256 `StateRoot`：

```bash
cargo run -p gmc-node --offline -- status --data-dir /tmp/gmc-demo-node
```

运行内置确定性端到端演示流水线（真实 Ed25519 已签名操作、双向社会关系与亲密度计算、贡献批次铸造、L2→L1 批次承诺结算与零手续费/零奖励区块生成）：

```bash
cargo run -p gmc-node --offline -- demo --data-dir /tmp/gmc-demo-node
```

手动触发一次零手续费、零运营者奖励的 L1 区块结算并刷新快照：

```bash
cargo run -p gmc-node --offline -- produce-block --data-dir /tmp/gmc-demo-node
```

启动仅监听本地回环地址（`127.0.0.1`）的最小运维 HTTP / JSON-RPC 控制服务（支持 `GET /health`、`GET /status`、`POST /submit_operation` 与 `POST /rpc`）：

```bash
cargo run -p gmc-node --offline -- serve --data-dir /tmp/gmc-demo-node --addr 127.0.0.1:0
```
