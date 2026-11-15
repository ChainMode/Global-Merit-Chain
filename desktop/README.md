# Meritora Desktop (Preview v0.2)

**Meritora Desktop** 是 **GMChain（公誉链）** 的本地图形化 BFT 节点工作台预览版，直接由 `gmc-node` 在本地回环地址（`127.0.0.1:8787`）上提供零外部 CDN 依赖的中英双语交互界面与 JSON-RPC 2.0 控制服务。

## 核心能力（Capabilities）

- **实时状态看板**：区块高度（Block Height）、规范 SHA-256 `StateRoot`、活跃 BFT 验证者委员会与法定人数（`3/4` Quorum）、待结算 L2 贡献记录数。
- **非货币性宪法徽章**：严格验证并展示 `FEE = 0 · REWARD = 0 · B_i = 0`（零交易手续费、零出块/验证者奖励、零初始美誉值基线）。
- **交互式 BFT 操作**：
  - 查看 `FayID` 问责验证者列表（`ifay_` / `cofay_` / `org_`）与最新 `QuorumCertificate`（`gmc_validators`）；
  - 一键触发确定性贡献登记与零手续费 BFT 出块结算（`gmc_demoStep` / `gmc_produceBlock`）；
  - 浏览状态转换与 L1 锚定审计日志（`gmc_auditLog`），并导出完整 JSON 状态快照。
- **离线与隐私安全**：仅绑定本地回环接口（`127.0.0.1`），不包含任何第三方脚本、样式或字体请求；`Human Prime`（人类原型）根身份始终受盲化 `gmcref_` 承诺保护，绝不落链。

## 快速启动（Launchers）

前置条件：已安装 `Rust 1.80+`（含 `cargo`）。

### macOS

双击运行 `desktop/Meritora-Desktop.command`，或在终端执行：

```bash
./desktop/Meritora-Desktop.sh
```

> 注：脚本文件名为 `./desktop/meritora-desktop.sh`（大小写不敏感文件系统下通用，Linux 请使用全小写路径 `./desktop/meritora-desktop.sh`）。

### Linux

```bash
./desktop/meritora-desktop.sh
```

### Windows

双击运行 `desktop\Meritora-Desktop.bat`，或在终端执行：

```bat
desktop\Meritora-Desktop.bat
```

### 直接通过 Cargo CLI 启动

```bash
cargo run -p gmc-node -- workbench --data-dir ./meritora-desktop-data --addr 127.0.0.1:8787
```

启动后在浏览器访问 `http://127.0.0.1:8787` 即可使用。默认节点数据保存在仓库根目录下的 `./meritora-desktop-data`（可通过环境变量 `GMC_DESKTOP_DATA_DIR` 与 `GMC_DESKTOP_ADDR` 自定义）。
