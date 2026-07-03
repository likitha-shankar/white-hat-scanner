"use strict";
// Live web UI for the White Hat engine. Enter a folder path (Mode 2) or an
// https:// URL (Mode 1); the page renders the ranked findings. Read-only demo.
//   node demo/server.js   ->   http://localhost:7777
const http = require("http");
const path = require("path");
const { analyze, scanUrl } = require("../src/index");

const PORT = process.env.PORT || 7777;
const DEFAULT = path.join(__dirname, "..", "tests", "fixtures", "vuln");
const SEV = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
const COLOR = { Critical: "#e51400", High: "#f7630c", Medium: "#d7a500", Low: "#3794ff", Informational: "#888" };

const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

function proofHtml(f) {
  if (f.proof && f.proof.kind === "runnable")
    return `Runnable proof: <b>${f.proven ? "fired ✓" : "not fired"}</b>` + (f.proofOutput ? `<pre>${esc(f.proofOutput)}</pre>` : "");
  if (f.proof && f.proof.steps)
    return "Reproduction:<ol>" + f.proof.steps.map((s) => `<li>${esc(s)}</li>`).join("") + "</ol>";
  return "";
}

function diffHtml(rem) {
  if (!rem) return "";
  const del = String(rem.before || "").split("\n").map((l) => `<span class="del">- ${esc(l)}</span>`).join("\n");
  const add = String(rem.after || "").split("\n").map((l) => `<span class="add">+ ${esc(l)}</span>`).join("\n");
  return `<pre class="diff">${del}\n${add}</pre>`;
}

function card(f, i) {
  const c = COLOR[f.severity] || "#888";
  return `<div class="card" style="border-left-color:${c}">
    <div class="head"><span class="badge" style="background:${c}">${esc(f.severity)}</span>
      <b>WHT-${String(i + 1).padStart(3, "0")} · ${esc(f.class)}</b>
      ${f.known ? '<span class="known">known</span>' : ""}</div>
    <div class="loc">${esc(f.rel)}${f.line ? ":" + f.line : ""}${f.unit ? "  · " + esc(f.unit) : ""}</div>
    <div class="sum">${esc(f.summary)}</div>
    <div class="impact">${esc(f.attackerImpact)}</div>
    <div class="proof">${proofHtml(f)}</div>
    ${diffHtml(f.remediation)}
  </div>`;
}

function section(title, list, note) {
  const sorted = [...list].sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  return `<h2>${title} (${list.length})</h2>${note ? `<p class="note">${note}</p>` : ""}` +
    (sorted.length ? sorted.map(card).join("") : '<p class="note">None.</p>');
}

function page(target, result, err) {
  let body;
  if (err) body = `<div class="err">Error: ${esc(err)}</div>`;
  else if (!result) body = "";
  else {
    const s = result.stats || {};
    const summary = s.mode === "url"
      ? `Scanned <b>${esc(s.url)}</b> — ${s.requests} requests`
      : `Scanned <b>${s.files}</b> files across <b>${s.units}</b> units`;
    body =
      `<div class="summary">${summary} · <b>${result.confirmed.length}</b> confirmed · <b>${result.unconfirmed.length}</b> unconfirmed</div>` +
      section("✅ Confirmed", result.confirmed) +
      section("❓ Unconfirmed", result.unconfirmed, "Detection matched but proof not automatically established — verify manually.") +
      `<h2>👍 Positive Observations (${(result.positives || []).length})</h2>` +
      ((result.positives || []).length
        ? "<ul>" + result.positives.map((p) => `<li>${esc(p.label)} — <code>${esc(p.rel)}</code></li>`).join("") + "</ul>"
        : '<p class="note">None.</p>');
  }
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>White Hat</title><style>
    body{font-family:system-ui,sans-serif;max-width:900px;margin:0 auto;padding:24px;color:#1f2328;background:#fafbfc}
    h1{margin:0 0 4px} .tag{color:#666;margin-bottom:16px}
    form{display:flex;gap:8px;margin-bottom:20px}
    input{flex:1;padding:8px;border:1px solid #ccc;border-radius:6px;font-size:14px}
    button{padding:8px 16px;border:0;border-radius:6px;background:#0969da;color:#fff;cursor:pointer;font-size:14px}
    .summary{background:#eef;padding:10px 14px;border-radius:6px;margin-bottom:12px}
    .card{background:#fff;border:1px solid #e1e4e8;border-left:4px solid #888;border-radius:6px;padding:12px 14px;margin:10px 0}
    .head{display:flex;align-items:center;gap:8px} .badge{color:#fff;font-size:11px;font-weight:700;padding:2px 7px;border-radius:10px}
    .known{background:#ffd33d;color:#000;font-size:10px;padding:1px 6px;border-radius:8px}
    .loc{color:#666;font-family:ui-monospace,monospace;font-size:12px;margin:4px 0} .sum{font-weight:600;margin:2px 0}
    .impact{color:#555;margin:4px 0;font-size:13px} .proof{font-size:12px;color:#444;margin:6px 0}
    pre{background:#f6f8fa;padding:8px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap}
    pre.diff{border:1px solid #e1e4e8} .del{color:#b31d28;display:block} .add{color:#22863a;display:block}
    .note{color:#888} .err{background:#ffe0e0;padding:12px;border-radius:6px;color:#900}
    code{background:#eee;padding:1px 5px;border-radius:4px} ol{margin:4px 0}
  </style></head><body>
    <h1>🛡️ White Hat</h1><div class="tag">Dual-mode security analysis — enter a folder path (Mode 2) or an https:// URL (Mode 1)</div>
    <form method="get"><input name="target" value="${esc(target)}" placeholder="folder path or https:// URL"><button>Scan</button></form>
    ${body}
  </body></html>`;
}

http.createServer(async (req, res) => {
  if (req.url === "/favicon.ico") { res.writeHead(204); return res.end(); }
  const u = new URL(req.url, `http://localhost:${PORT}`);
  const target = (u.searchParams.get("target") || "").trim() || DEFAULT;
  let result = null, err = null;
  try {
    if (/^https?:\/\//i.test(target)) { result = await scanUrl(target); }
    else { result = analyze(target, path.join(require("os").tmpdir(), "wh-demo-mem.md")); }
    if (result && result.error) { err = result.error; result = null; }
  } catch (e) { err = e.message; }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(page(target, result, err));
}).listen(PORT, () => console.log(`White Hat demo → http://localhost:${PORT}`));
