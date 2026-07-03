"use strict";
// Side panel: persists across navigation, shows the active tab's findings ranked
// by severity, updates live as the service worker pushes results.
const out = document.getElementById("out");
const statusEl = document.getElementById("status");
const SEV = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
let curTab = null;

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function card(f) {
  return `<div class="card ${esc(f.severity)}">
    <span class="badge b-${esc(f.severity)}">${esc(f.severity)}</span> <b>${esc(f.cls)}</b>
    <div>${esc(f.summary)}</div>
    <div class="muted">${esc(f.impact)}</div>
    <div class="evi">${esc(f.evidence)}</div>
    <div class="fix"><b>Fix:</b> ${esc(f.fix)}</div>
  </div>`;
}

function render(url, findings) {
  findings = (findings || []).slice().sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  const crit = findings.filter((f) => f.severity === "Critical" || f.severity === "High").length;
  statusEl.textContent = url ? `${url} — ${findings.length} findings (${crit} high/critical)` : "No page scanned yet.";
  out.innerHTML = findings.length ? findings.map(card).join("") : '<div class="muted">No issues observed.</div>';
}

function load() {
  chrome.tabs.query({ active: true, currentWindow: true }, (t) => {
    if (!t[0]) return;
    curTab = t[0].id;
    chrome.runtime.sendMessage({ type: "getFindings", tabId: curTab }, (resp) => {
      if (chrome.runtime.lastError) { statusEl.textContent = "Open a page and reload to scan."; return; }
      if (resp) render(resp.url, resp.findings);
    });
  });
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "update" && msg.tabId === curTab) render(msg.url, msg.findings);
});
chrome.tabs.onActivated.addListener(load);
chrome.tabs.onUpdated.addListener((id, info) => { if (id === curTab && info.status === "complete") load(); });
document.getElementById("rescan").onclick = () => { if (curTab != null) chrome.runtime.sendMessage({ type: "rescan", tabId: curTab }); };

load();
