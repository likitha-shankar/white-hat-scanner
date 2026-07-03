"use strict";
// Live web UI for the White Hat engine. Enter a folder path (Mode 2) or an
// https:// URL (Mode 1); the page renders the ranked findings. Read-only demo.
//   node demo/server.js   ->   http://localhost:7777
const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const net = require("net");
const dns = require("dns").promises;
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);
const { analyze, scanUrl } = require("../src/index");

const PORT = process.env.PORT || 7777;
// Bind localhost in local (unrestricted) mode so arbitrary file read / URL
// scanning is never reachable from the network. Public hosting runs DEMO_SAFE=1,
// which is path/SSRF-guarded, so it binds all interfaces to accept traffic.
const HOST = process.env.HOST || (process.env.DEMO_SAFE === "1" ? "0.0.0.0" : "127.0.0.1");
const FIX = (name) => path.join(__dirname, "..", "tests", "fixtures", name);
const DEFAULT = FIX("vuln");

// DEMO_SAFE=1 (public hosting): no arbitrary filesystem paths. Users provide
// source via a PUBLIC GitHub repo (shallow-cloned, scanned, deleted). Mode-1 URL
// scanning is off unless DEMO_ALLOW_URL=1 (open-scanner abuse risk), and even
// then it is SSRF-guarded to public hosts only.
const SAFE = process.env.DEMO_SAFE === "1";
const ALLOW_URL = process.env.DEMO_ALLOW_URL === "1";
const ALLOWED = { vuln: FIX("vuln"), gqltrpc: FIX("gqltrpc"), interproc: FIX("interproc"), frameworks: FIX("frameworks"), clean: FIX("clean") };
const memPath = () => path.join(os.tmpdir(), "wh-demo-mem.md");

function resolveTarget(raw) {
  if (!SAFE) return (raw && raw.trim()) || DEFAULT;
  const key = (raw || "vuln").replace(/[^a-z]/gi, "").toLowerCase();
  return ALLOWED[key] || ALLOWED.vuln;
}

const isGithubRepo = (raw) => /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+?(\.git)?\/?$/.test((raw || "").trim());

// Shallow-clone a public GitHub repo, scan it, then delete it. execFile (no
// shell) + a validated github.com URL means no command injection.
async function scanGithub(repoUrl) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wh-clone-"));
  try {
    await execFileP("git", ["clone", "--depth", "1", "--single-branch", "--quiet", repoUrl.replace(/\/$/, ""), dir], { timeout: 30000 });
    return analyze(dir, memPath());
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// SSRF guard: allow only public http(s) hosts (block localhost/private/metadata).
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  const l = ip.toLowerCase();
  if (l === "::1" || l === "::") return true;
  if (l.startsWith("::ffff:")) return isPrivateIp(l.split(":").pop());
  return l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80");
}
async function isPublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return false; }
  if (!/^https?:$/.test(u.protocol)) return false;
  if (/^(localhost|.*\.local|.*\.internal)$/i.test(u.hostname)) return false;
  try {
    const addrs = await dns.lookup(u.hostname, { all: true });
    return addrs.length > 0 && addrs.every((a) => !isPrivateIp(a.address));
  } catch { return false; }
}
const SEV = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
const COLOR = { Critical: "#e51400", High: "#f7630c", Medium: "#d7a500", Low: "#3794ff", Informational: "#888" };

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

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
  else if (!result) body = `<p class="note">Paste a public GitHub repo (<code>github.com/owner/repo</code>) or pick a sample above, then hit Scan. No target is analyzed until you choose one.</p>`;
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
    .presets{margin:0 0 16px;color:#666} .presets a{margin-right:6px}
  </style></head><body>
    <h1>🛡️ White Hat</h1><div class="tag">${SAFE
      ? `Scan a <b>public GitHub repo</b> (Mode 2)${ALLOW_URL ? " or a <b>public URL</b> (Mode 1)" : ""}, or try a sample below.`
      : "Enter a folder path (Mode 2) or an https:// URL (Mode 1)."}</div>
    <form method="get"><input name="target" value="${esc(target)}" placeholder="${SAFE
      ? `github.com/owner/repo${ALLOW_URL ? " — or https:// URL" : ""}`
      : "folder path or https:// URL"}"><button>Scan</button></form>
    <div class="presets">Samples: ${["vuln", "gqltrpc", "interproc", "frameworks", "clean"].map((k) => `<a href="/?target=${k}">${k}</a>`).join(" · ")}</div>
    ${body}
  </body></html>`;
}

http.createServer(async (req, res) => {
  if (req.url === "/favicon.ico") { res.writeHead(204); return res.end(); }
  const u = new URL(req.url, `http://localhost:${PORT}`);
  const raw = u.searchParams.get("target");
  const display = (raw && raw.trim()) || "";
  let result = null, err = null;
  // No target -> blank landing (form + samples). Only scan when the user picks one.
  if (display) try {
    if (!SAFE) {
      // local: unrestricted
      const t = display || DEFAULT;
      result = /^https?:\/\//i.test(t) ? await scanUrl(t) : analyze(t, memPath());
    } else if (isGithubRepo(raw)) {
      result = await scanGithub(display); // Mode 2 on a public repo
    } else if (/^https?:\/\//i.test(display)) {
      if (!ALLOW_URL) err = "URL scanning is disabled on this public demo (open-scanner abuse risk). Run it locally, or the operator can set DEMO_ALLOW_URL=1.";
      else if (!(await isPublicUrl(display))) err = "Blocked: only public http(s) hosts are allowed (no localhost / private / metadata addresses).";
      else result = await scanUrl(display);
    } else {
      result = analyze(resolveTarget(raw), memPath()); // bundled fixture
    }
    if (result && result.error) { err = result.error; result = null; }
  } catch (e) { err = "Scan failed: " + e.message; }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(page(display, result, err));
}).listen(PORT, HOST, () => console.log(`White Hat demo → http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`));
