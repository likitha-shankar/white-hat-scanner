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

const SAMPLES = [
  ["vuln", "⚠️ Vulnerable demo app"],
  ["frameworks", "NestJS / Next.js app"],
  ["gqltrpc", "GraphQL / tRPC API"],
  ["interproc", "Bug spread across files"],
  ["clean", "✅ Secure app"],
];

const FINDS = [
  ["💉", "SQL &amp; command injection", "Attackers reading your database or running commands on your server."],
  ["🔑", "Hardcoded secrets", "API keys, tokens and passwords accidentally committed in the code."],
  ["🚪", "Broken access control", "One user able to read or change another user's data (IDOR)."],
  ["🔐", "Weak crypto &amp; JWT flaws", "Crackable password hashing and forgeable login tokens."],
  ["📂", "Path traversal", "Tricking the server into reading files it shouldn't."],
  ["⏱️", "Race conditions", "Double-spend and oversold-inventory bugs under load."],
];

function section(title, list, note) {
  const sorted = [...list].sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  return `<h3 class="sec">${title} <span class="count">${list.length}</span></h3>${note ? `<p class="note">${note}</p>` : ""}` +
    (sorted.length ? sorted.map(card).join("") : '<p class="note">None found.</p>');
}

function resultsHtml(target, result, err) {
  if (err) return `<div class="err">${esc(err)}</div>`;
  if (!result) return "";
  const s = result.stats || {};
  const scanned = s.mode === "url"
    ? `Scanned <b>${esc(s.url)}</b> (${s.requests} requests)`
    : `Scanned <b>${s.files}</b> files${target ? " in <b>" + esc(target) + "</b>" : ""}`;
  const nConf = result.confirmed.length, nRev = result.unconfirmed.length;
  const tone = nConf ? "bad" : "good";
  const headline = nConf
    ? `${nConf} confirmed ${nConf === 1 ? "vulnerability" : "vulnerabilities"} found`
    : "No confirmed vulnerabilities";
  return `<div class="banner ${tone}"><b>${headline}</b><span>${scanned} · ${nRev} to review</span></div>
    ${section("Confirmed vulnerabilities", result.confirmed)}
    ${section("Needs manual review", result.unconfirmed, "Matched a risky pattern, but the tool could not automatically prove it — a human should check these.")}
    <h3 class="sec">Good practices found <span class="count">${(result.positives || []).length}</span></h3>
    ${(result.positives || []).length
      ? "<ul class='pos'>" + result.positives.map((p) => `<li>${esc(p.label)} — <code>${esc(p.rel)}</code></li>`).join("") + "</ul>"
      : '<p class="note">None detected.</p>'}`;
}

function page(target, result, err) {
  const scanned = result || err;
  const canUrl = SAFE ? ALLOW_URL : true;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>White Hat — find security bugs in your code</title>
  <meta name="description" content="Paste a GitHub repo and White Hat reads the code, traces how user input reaches dangerous operations, and proves the real vulnerabilities.">
  <style>
    :root{--fg:#1f2328;--mut:#57606a;--line:#d0d7de;--bg:#fff;--accent:#0969da}
    *{box-sizing:border-box} body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;color:var(--fg);background:#fff;line-height:1.5}
    a{color:var(--accent)} .wrap{max-width:880px;margin:0 auto;padding:0 20px}
    nav{display:flex;align-items:center;gap:10px;padding:14px 0;border-bottom:1px solid var(--line)}
    nav .brand{font-weight:700} nav .sp{flex:1} nav a{color:var(--mut);text-decoration:none;font-size:14px}
    .hero{background:linear-gradient(180deg,#f6f8ff,#fff);border-bottom:1px solid var(--line);padding:44px 0 34px;text-align:center}
    .hero h1{font-size:34px;line-height:1.15;margin:0 0 12px;letter-spacing:-.5px}
    .hero p.sub{font-size:17px;color:var(--mut);max-width:620px;margin:0 auto 22px}
    form{display:flex;gap:8px;max-width:560px;margin:0 auto}
    input{flex:1;padding:12px 14px;border:1px solid var(--line);border-radius:8px;font-size:15px}
    input:focus{outline:2px solid var(--accent);border-color:var(--accent)}
    button{padding:12px 20px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
    button:hover{background:#0860ca}
    .chips{margin:16px 0 0;font-size:13px;color:var(--mut)} .chips a{display:inline-block;margin:4px;padding:5px 11px;background:#fff;border:1px solid var(--line);border-radius:20px;text-decoration:none;color:var(--fg)}
    .chips a:hover{border-color:var(--accent)}
    section{padding:36px 0} h2{font-size:22px;margin:0 0 18px;text-align:center}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
    .f{border:1px solid var(--line);border-radius:10px;padding:16px} .f .ic{font-size:22px} .f b{display:block;margin:6px 0 3px} .f span{color:var(--mut);font-size:14px}
    .steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;counter-reset:s}
    .step{border:1px solid var(--line);border-radius:10px;padding:16px;position:relative}
    .step:before{counter-increment:s;content:counter(s);display:inline-flex;width:26px;height:26px;align-items:center;justify-content:center;background:var(--accent);color:#fff;border-radius:50%;font-size:13px;font-weight:700;margin-bottom:8px}
    .step b{display:block;margin-bottom:4px} .step span{color:var(--mut);font-size:14px}
    .results{border-top:1px solid var(--line);background:#fafbfc} .results .wrap{padding:24px 20px}
    .banner{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:14px 16px;border-radius:10px;margin-bottom:18px}
    .banner.bad{background:#ffebe9;border:1px solid #ff818266} .banner.good{background:#dafbe1;border:1px solid #4ac26b66}
    .banner span{color:var(--mut);font-size:14px}
    h3.sec{font-size:16px;margin:22px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}
    .count{background:#eaeef2;color:var(--mut);border-radius:20px;padding:1px 9px;font-size:13px;margin-left:4px}
    .card{background:#fff;border:1px solid var(--line);border-left:4px solid #888;border-radius:8px;padding:12px 14px;margin:10px 0}
    .head{display:flex;align-items:center;gap:8px;flex-wrap:wrap} .badge{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
    .known{background:#ffd33d;color:#000;font-size:10px;padding:1px 6px;border-radius:8px}
    .loc{color:var(--mut);font-family:ui-monospace,monospace;font-size:12px;margin:4px 0} .sum{font-weight:600;margin:2px 0}
    .impact{color:#444;margin:4px 0;font-size:13px} .proof{font-size:12px;color:#555;margin:6px 0}
    pre{background:#f6f8fa;padding:8px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap}
    pre.diff{border:1px solid var(--line)} .del{color:#b31d28;display:block} .add{color:#22863a;display:block}
    .note{color:var(--mut)} .err{background:#ffebe9;border:1px solid #ff8182;padding:14px;border-radius:8px;color:#8b1a10}
    code{background:#eef1f4;padding:1px 5px;border-radius:4px;font-size:12px} ul.pos li{margin:3px 0}
    footer{border-top:1px solid var(--line);padding:24px 0;color:var(--mut);font-size:13px;text-align:center}
  </style></head><body>
  <div class="wrap"><nav><span class="brand">🛡️ White Hat</span><span class="sp"></span>
    <a href="https://github.com/likitha-shankar/white-hat-scanner">GitHub ↗</a></nav></div>

  <header class="hero"><div class="wrap">
    <h1>Find security bugs in your code<br>before attackers do</h1>
    <p class="sub">White Hat reads your source code, traces how user input flows into dangerous operations, and <b>proves</b> the real vulnerabilities — with the exact fix. Paste a public GitHub repo to try it.</p>
    <form method="get" action="/">
      <input name="target" value="${esc(target)}" autofocus placeholder="${canUrl ? "github.com/owner/repo  or  https://a-website.com" : "https://github.com/owner/repo"}">
      <button>Scan${SAFE ? "" : ""}</button>
    </form>
    <div class="chips">Or try a sample: ${SAMPLES.map(([k, label]) => `<a href="/?target=${k}#results">${label}</a>`).join("")}</div>
    ${canUrl ? '<p class="note" style="font-size:12px;margin-top:12px">Tip: paste a live website URL to check its security headers, cookies and exposed files.</p>' : ""}
  </div></header>

  ${scanned ? `<div class="results"><div class="wrap" id="results">${resultsHtml(target, result, err)}</div></div>` : ""}

  <div class="wrap">
  <section><h2>What it checks for</h2><div class="grid">
    ${FINDS.map(([ic, t, d]) => `<div class="f"><div class="ic">${ic}</div><b>${t}</b><span>${d}</span></div>`).join("")}
  </div></section>

  <section><h2>How it works</h2><div class="steps">
    <div class="step"><b>You paste a repo</b><span>A public GitHub URL, or one of the sample apps above. Nothing is stored.</span></div>
    <div class="step"><b>It traces the data</b><span>The engine follows untrusted input across functions and files to every risky operation.</span></div>
    <div class="step"><b>You get proven bugs</b><span>Real vulnerabilities, ranked by severity, each with a plain-English impact and the exact fix.</span></div>
  </div></section>
  </div>

  <footer><div class="wrap">White Hat · open-source security scanner ·
    <a href="https://github.com/likitha-shankar/white-hat-scanner">source on GitHub</a> ·
    read-only, nothing you scan is stored</div></footer>
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
