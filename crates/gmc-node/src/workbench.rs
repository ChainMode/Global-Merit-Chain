//! Self-contained bilingual (`中文` / `English`) `Meritora Desktop (Preview v0.2)`
//! graphical workbench UI served directly from `gmc-node` over local loopback (`127.0.0.1`).
//!
//! Zero external CDN scripts, stylesheets, or font requests: works 100% offline against
//! the local JSON-RPC 2.0 endpoint (`POST /rpc`).

/// Complete self-contained HTML/CSS/JS document for `Meritora Desktop (Preview v0.2)`.
pub const MERITORA_DESKTOP_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Meritora Desktop (Preview v0.2) · GMChain Workbench</title>
  <style>
    :root {
      --bg-top: #eef6ff;
      --bg-mid: #f7fbff;
      --bg-bottom: #e6f1fc;
      --glass: rgba(255, 255, 255, 0.78);
      --glass-strong: rgba(255, 255, 255, 0.92);
      --border: rgba(14, 116, 204, 0.16);
      --ink: #0f2942;
      --muted: #4b6785;
      --accent: #0284c7;
      --accent-hover: #0369a1;
      --accent-soft: rgba(2, 132, 199, 0.10);
      --emerald: #059669;
      --emerald-soft: rgba(5, 150, 105, 0.12);
      --amber: #d97706;
      --danger: #dc2626;
      --shadow: 0 16px 40px rgba(15, 41, 66, 0.08);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(circle at 12% 8%, rgba(56, 189, 248, 0.22), transparent 36%),
        radial-gradient(circle at 88% 14%, rgba(14, 165, 233, 0.18), transparent 40%),
        linear-gradient(180deg, var(--bg-top) 0%, var(--bg-mid) 52%, var(--bg-bottom) 100%);
      padding: 28px 20px 56px;
    }
    .shell {
      max-width: 1160px;
      margin: 0 auto;
    }
    header.topbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 20px 24px;
      background: var(--glass-strong);
      border: 1px solid var(--border);
      border-radius: 20px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .orb {
      width: 44px;
      height: 44px;
      border-radius: 14px;
      background: linear-gradient(135deg, #38bdf8 0%, #0284c7 58%, #0f2942 100%);
      box-shadow: 0 8px 20px rgba(2, 132, 199, 0.28);
      display: grid;
      place-items: center;
      color: #fff;
      font-weight: 700;
      font-size: 18px;
    }
    .brand h1 {
      margin: 0;
      font-size: 20px;
      letter-spacing: -0.01em;
    }
    .brand p {
      margin: 3px 0 0;
      font-size: 13px;
      color: var(--muted);
    }
    .header-right {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
    }
    .const-badge {
      padding: 7px 13px;
      border-radius: 999px;
      background: var(--emerald-soft);
      color: var(--emerald);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 600;
      border: 1px solid rgba(5, 150, 105, 0.24);
    }
    .lang-toggle {
      padding: 8px 14px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .lang-toggle:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .cards {
      margin-top: 20px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(245px, 1fr));
      gap: 16px;
    }
    .card {
      padding: 20px;
      background: var(--glass);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }
    .card-label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
    }
    .card-value {
      margin-top: 8px;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .card-mono {
      margin-top: 8px;
      font-family: var(--mono);
      font-size: 13px;
      line-height: 1.45;
      word-break: break-all;
      color: var(--ink);
      background: rgba(255, 255, 255, 0.72);
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid rgba(14, 116, 204, 0.12);
    }
    .card-sub {
      margin-top: 8px;
      font-size: 12.5px;
      color: var(--muted);
    }
    .toolbar {
      margin-top: 20px;
      padding: 16px 20px;
      background: var(--glass-strong);
      border: 1px solid var(--border);
      border-radius: 18px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      box-shadow: var(--shadow);
    }
    .btn-group {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    button.action {
      padding: 10px 16px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      font-weight: 600;
      font-size: 13.5px;
      cursor: pointer;
      transition: transform 0.1s ease, background 0.15s ease, border-color 0.15s ease;
    }
    button.action:hover {
      border-color: var(--accent);
      background: var(--accent-soft);
    }
    button.action.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    button.action.primary:hover {
      background: var(--accent-hover);
    }
    .toast {
      font-size: 13px;
      color: var(--muted);
      font-family: var(--mono);
    }
    .grid-two {
      margin-top: 20px;
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 18px;
    }
    @media (max-width: 900px) {
      .grid-two { grid-template-columns: 1fr; }
    }
    .panel {
      padding: 20px 22px;
      background: var(--glass);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
    }
    .panel h2 {
      margin: 0 0 14px;
      font-size: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 9px 8px;
      border-bottom: 1px solid rgba(14, 116, 204, 0.10);
    }
    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
    }
    .pill {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 11.5px;
      font-weight: 600;
    }
    .pill.active {
      background: var(--emerald-soft);
      color: var(--emerald);
    }
    .pill.ejected {
      background: rgba(220, 38, 38, 0.12);
      color: var(--danger);
    }
    pre.codebox {
      margin: 0;
      padding: 12px 14px;
      border-radius: 12px;
      background: rgba(15, 41, 66, 0.94);
      color: #e0f2fe;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.5;
      max-height: 290px;
      overflow: auto;
    }
    footer {
      margin-top: 24px;
      text-align: center;
      font-size: 12.5px;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="orb">μ</div>
        <div>
          <h1>Meritora Desktop <span style="font-weight:500;color:var(--accent)">(Preview v0.2)</span></h1>
          <p id="subtitle">公誉链本地 BFT 节点工作台 · GMChain Local BFT Node Workbench</p>
        </div>
      </div>
      <div class="header-right">
        <span class="const-badge" title="Non-Monetary Constitutional Invariants">FEE = 0 · REWARD = 0 · B_i = 0</span>
        <button class="lang-toggle" id="langBtn" type="button">中文 / English</button>
      </div>
    </header>

    <section class="cards">
      <div class="card">
        <div class="card-label" data-i18n="lbl_height">区块高度 · Block Height</div>
        <div class="card-value" id="valHeight">0</div>
        <div class="card-sub"><span data-i18n="lbl_chain">链 ID</span>: <code id="valChain">-</code> · WAL #<span id="valWal">0</span></div>
      </div>

      <div class="card">
        <div class="card-label" data-i18n="lbl_root">规范状态根 · Canonical SHA-256 StateRoot</div>
        <div class="card-mono" id="valStateRoot">loading...</div>
        <div class="card-sub"><span data-i18n="lbl_pending">待结算 L2 记录</span>: <strong id="valPending">0</strong> · <span data-i18n="lbl_identities">FayID 实体</span>: <strong id="valIdentities">0</strong></div>
      </div>

      <div class="card">
        <div class="card-label" data-i18n="lbl_bft">活跃 BFT 验证者与法定人数 · Active Validators &amp; Quorum</div>
        <div class="card-value" id="valValidators">3/4</div>
        <div class="card-sub"><span data-i18n="lbl_quorum">法定门槛 (2f+1)</span>: <strong id="valQuorum">3</strong> · <span data-i18n="lbl_ejected">双签驱逐</span>: <strong id="valEjected">0</strong></div>
      </div>

      <div class="card">
        <div class="card-label" data-i18n="lbl_const">非货币性宪法不变量 · Non-Monetary Constitution</div>
        <div class="card-value" style="color:var(--emerald);font-size:22px">0 μ Fee · 0 μ Reward</div>
        <div class="card-sub" data-i18n="lbl_const_desc">美誉值 (MeriToken) 严禁转账、交易或质押罚没；FayID 盲化 gmcref_ 保护人类原型隐私。</div>
      </div>
    </section>

    <section class="toolbar">
      <div class="btn-group">
        <button class="action primary" id="btnDemoStep" type="button" data-i18n="btn_demo">⚡ 提交演示贡献并出块 (gmc_demoStep)</button>
        <button class="action" id="btnProduceBlock" type="button" data-i18n="btn_block">🧱 零手续费 BFT 出块 (gmc_produceBlock)</button>
        <button class="action" id="btnRefresh" type="button" data-i18n="btn_refresh">🔄 刷新验证者与状态</button>
        <button class="action" id="btnExport" type="button" data-i18n="btn_export">💾 导出 JSON 快照</button>
      </div>
      <div class="toast" id="rpcToast">RPC: 127.0.0.1 · ready</div>
    </section>

    <section class="grid-two">
      <div class="panel">
        <h2>
          <span data-i18n="hdr_validators">BFT 验证者委员会 (FayID 问责集)</span>
          <span style="font-size:12px;color:var(--muted);font-family:var(--mono)">Ed25519 · gmc.bft.vote.v1</span>
        </h2>
        <table>
          <thead>
            <tr>
              <th data-i18n="th_vid">验证者 FayID</th>
              <th data-i18n="th_pk">Ed25519 公钥指纹</th>
              <th data-i18n="th_status">状态</th>
            </tr>
          </thead>
          <tbody id="validatorRows">
            <tr><td colspan="3">...</td></tr>
          </tbody>
        </table>

        <h2 style="margin-top:20px">
          <span data-i18n="hdr_qc">最新法定人数证书 · Latest QuorumCertificate</span>
        </h2>
        <pre class="codebox" id="qcBox">{}</pre>
      </div>

      <div class="panel">
        <h2>
          <span data-i18n="hdr_audit">状态转换与 L1 锚定审计日志 · Audit Log</span>
        </h2>
        <pre class="codebox" id="auditBox" style="max-height:430px">{}</pre>
      </div>
    </section>

    <footer id="footerNote">
      Meritora Desktop (Preview v0.2) · Local Loopback Only (127.0.0.1) · Dual-Track MIT + CC BY 4.0
    </footer>
  </div>

  <script>
    (function () {
      const dict = {
        zh: {
          sub: "公誉链本地 BFT 节点工作台 · 零外部依赖离线安全界面",
          lbl_height: "区块高度 · Block Height",
          lbl_chain: "链 ID",
          lbl_root: "规范状态根 · Canonical SHA-256 StateRoot",
          lbl_pending: "待结算 L2 记录",
          lbl_identities: "FayID 实体",
          lbl_bft: "活跃 BFT 验证者与法定人数",
          lbl_quorum: "法定门槛 (2f+1)",
          lbl_ejected: "双签驱逐",
          lbl_const: "非货币性宪法不变量",
          lbl_const_desc: "美誉值 (MeriToken) 严禁转账、交易或质押罚没；FayID 盲化 gmcref_ 保护人类原型隐私。",
          btn_demo: "⚡ 提交演示贡献并出块 (gmc_demoStep)",
          btn_block: "🧱 零手续费 BFT 出块 (gmc_produceBlock)",
          btn_refresh: "🔄 刷新验证者与状态",
          btn_export: "💾 导出 JSON 快照",
          hdr_validators: "BFT 验证者委员会 (ifay_ / cofay_ / org_)",
          th_vid: "验证者 FayID",
          th_pk: "Ed25519 公钥指纹",
          th_status: "状态",
          hdr_qc: "最新法定人数证书 · Latest QuorumCertificate",
          hdr_audit: "状态转换与 L1 锚定审计日志 · Audit Log",
          st_active: "活跃 Active",
          st_ejected: "已驱逐 Ejected"
        },
        en: {
          sub: "GMChain Local BFT Node Workbench · Zero-CDN Self-Contained Loopback UI",
          lbl_height: "Block Height",
          lbl_chain: "Chain ID",
          lbl_root: "Canonical SHA-256 StateRoot",
          lbl_pending: "Pending L2 Records",
          lbl_identities: "FayID Entities",
          lbl_bft: "Active BFT Validators & Quorum",
          lbl_quorum: "Quorum (2f+1)",
          lbl_ejected: "Ejected",
          lbl_const: "Non-Monetary Constitutional Invariants",
          lbl_const_desc: "MeriToken (μ) forbids transfer, exchange, or monetary slashing; blinded gmcref_ protects Human Prime privacy.",
          btn_demo: "⚡ Run Demo Contribution + BFT Block (gmc_demoStep)",
          btn_block: "🧱 Produce Zero-Fee BFT Block (gmc_produceBlock)",
          btn_refresh: "🔄 Refresh Validators & State",
          btn_export: "💾 Export JSON Snapshot",
          hdr_validators: "BFT Validator Committee (ifay_ / cofay_ / org_)",
          th_vid: "Validator FayID",
          th_pk: "Ed25519 Public Key",
          th_status: "Status",
          hdr_qc: "Latest QuorumCertificate",
          hdr_audit: "State Transition & L1 Anchor Audit Log",
          st_active: "Active",
          st_ejected: "Ejected"
        }
      };

      let lang = "zh";
      let latestSnapshotPayload = null;
      let rpcSeq = 1;

      function applyLang() {
        const t = dict[lang];
        document.getElementById("subtitle").textContent = t.sub;
        document.querySelectorAll("[data-i18n]").forEach(function (el) {
          const k = el.getAttribute("data-i18n");
          if (t[k]) el.textContent = t[k];
        });
      }

      async function rpcCall(method, params) {
        const res = await fetch("/rpc", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: rpcSeq++,
            method: method,
            params: params || {}
          })
        });
        const data = await res.json();
        if (data.error) {
          throw new Error(data.error.message || "RPC error");
        }
        return data.result;
      }

      function setToast(msg) {
        document.getElementById("rpcToast").textContent = msg;
      }

      async function refreshAll() {
        try {
          const [st, vals, audit] = await Promise.all([
            rpcCall("gmc_status", {}),
            rpcCall("gmc_validators", {}),
            rpcCall("gmc_auditLog", {})
          ]);
          latestSnapshotPayload = audit;

          document.getElementById("valHeight").textContent = String(st.block_height);
          document.getElementById("valChain").textContent = st.chain_id;
          document.getElementById("valWal").textContent = String(st.wal_seq);
          document.getElementById("valStateRoot").textContent = st.state_root_hex;
          document.getElementById("valPending").textContent = String(st.pending_l2_records);
          document.getElementById("valIdentities").textContent = String(st.identity_count);
          document.getElementById("valValidators").textContent =
            vals.quorum_threshold + "/" + vals.active_count + " (N=" + vals.total_count + ")";
          document.getElementById("valQuorum").textContent = String(vals.quorum_threshold);
          document.getElementById("valEjected").textContent = String(vals.ejected_count);

          const tbody = document.getElementById("validatorRows");
          tbody.innerHTML = "";
          const t = dict[lang];
          (vals.validators || []).forEach(function (v) {
            const tr = document.createElement("tr");
            const tdId = document.createElement("td");
            tdId.style.fontFamily = "var(--mono)";
            tdId.textContent = v.validator_id;
            const tdPk = document.createElement("td");
            tdPk.style.fontFamily = "var(--mono)";
            tdPk.textContent = v.pubkey_hex.slice(0, 16) + "…" + v.pubkey_hex.slice(-8);
            const tdSt = document.createElement("td");
            const span = document.createElement("span");
            span.className = "pill " + (v.active ? "active" : "ejected");
            span.textContent = v.active ? t.st_active : t.st_ejected;
            tdSt.appendChild(span);
            tr.appendChild(tdId);
            tr.appendChild(tdPk);
            tr.appendChild(tdSt);
            tbody.appendChild(tr);
          });

          document.getElementById("qcBox").textContent = JSON.stringify(
            vals.latest_qc || { note: "No block committed yet — click gmc_demoStep to seal Height 1" },
            null,
            2
          );
          document.getElementById("auditBox").textContent = JSON.stringify(
            {
              block_height: audit.block_height,
              state_root_hex: audit.state_root_hex,
              l1_state_root_hex: audit.l1_state_root_hex,
              constitutional_invariants: audit.constitutional_invariants,
              settled_batches: audit.settled_batches,
              l1_anchor_log: audit.l1_anchor_log
            },
            null,
            2
          );
          setToast("Synced height #" + st.block_height + " · fee=" + st.node_transaction_fee + " · reward=" + st.validator_reward);
        } catch (err) {
          setToast("RPC error: " + err.message);
        }
      }

      document.getElementById("langBtn").addEventListener("click", function () {
        lang = lang === "zh" ? "en" : "zh";
        applyLang();
        refreshAll();
      });

      document.getElementById("btnRefresh").addEventListener("click", function () {
        refreshAll();
      });

      document.getElementById("btnDemoStep").addEventListener("click", async function () {
        setToast("Submitting demo contribution & sealing BFT block...");
        try {
          await rpcCall("gmc_demoStep", {});
          await refreshAll();
        } catch (err) {
          setToast("gmc_demoStep failed: " + err.message);
        }
      });

      document.getElementById("btnProduceBlock").addEventListener("click", async function () {
        setToast("Producing 0-fee BFT block...");
        try {
          const nowSecs = Math.floor(Date.now() / 1000);
          await rpcCall("gmc_produceBlock", { timestamp_secs: nowSecs });
          await refreshAll();
        } catch (err) {
          setToast("gmc_produceBlock failed: " + err.message);
        }
      });

      document.getElementById("btnExport").addEventListener("click", async function () {
        if (!latestSnapshotPayload) {
          await refreshAll();
        }
        if (!latestSnapshotPayload) return;
        const blob = new Blob([JSON.stringify(latestSnapshotPayload, null, 2)], {
          type: "application/json"
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download =
          (latestSnapshotPayload.chain_id || "gmchain") +
          "-height-" +
          (latestSnapshotPayload.block_height || 0) +
          "-snapshot.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setToast("Exported deterministic JSON snapshot");
      });

      applyLang();
      refreshAll();
    })();
  </script>
</body>
</html>
"#;
