"use strict";
// Service worker: captures real response headers per tab (passive), runs the
// header/cookie/CORS/path checks, merges DOM findings from the content script,
// and pushes the aggregate to the side panel.
importScripts("rules.js");

const tabs = {}; // tabId -> { url, headers, setCookies, domFindings, findings }

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});

// Capture top-level response headers as the browser receives them.
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.type !== "main_frame") return;
    const headers = {};
    const setCookies = [];
    for (const h of d.responseHeaders || []) {
      const n = h.name.toLowerCase();
      if (n === "set-cookie") setCookies.push(h.value);
      else headers[n] = h.value;
    }
    tabs[d.tabId] = { url: d.url, headers, setCookies, domFindings: [], findings: [] };
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders", "extraHeaders"]
);

function dedup(arr) {
  const seen = new Set();
  return arr.filter((f) => {
    const k = f.cls + "|" + f.evidence;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

async function backgroundChecks(t) {
  const isHttps = t.url.startsWith("https:");
  let out = WH.headerFindings(t.url, t.headers, isHttps).concat(WH.cookieFindings(t.url, t.setCookies, isHttps));

  // CORS: the extension fetch is cross-origin; read what the server allows.
  try {
    const res = await fetch(t.url, { credentials: "omit" });
    const c = WH.corsFinding(t.url, res.headers.get("access-control-allow-origin"),
      res.headers.get("access-control-allow-credentials"), WH.PROBE_ORIGIN);
    if (c) out.push(c);
  } catch (_) {}

  // Targeted sensitive-path probe (read-only GET, curated list).
  let origin;
  try { origin = new URL(t.url).origin; } catch { return out; }
  for (const def of WH.SENSITIVE_PATHS) {
    try {
      const res = await fetch(origin + def[0]);
      if (res.status === 200) {
        const body = (await res.text()).slice(0, 5000);
        const f = WH.pathFinding(origin + def[0], res.status, body, def);
        if (f) out.push(f);
      }
    } catch (_) {}
  }
  return out;
}

async function refresh(tabId) {
  const t = tabs[tabId];
  if (!t) return;
  const bg = await backgroundChecks(t);
  t.findings = dedup([...(t.domFindings || []), ...bg]);
  chrome.runtime.sendMessage({ type: "update", tabId, url: t.url, findings: t.findings }).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "dom" && sender.tab) {
    const id = sender.tab.id;
    tabs[id] = tabs[id] || { url: msg.url, headers: {}, setCookies: [] };
    tabs[id].domFindings = msg.findings || [];
    refresh(id);
  } else if (msg.type === "getFindings") {
    const t = tabs[msg.tabId];
    reply({ url: t && t.url, findings: (t && t.findings) || [] });
    if (t) refresh(msg.tabId);
  } else if (msg.type === "rescan") {
    refresh(msg.tabId);
  }
  return false;
});

chrome.tabs.onRemoved.addListener((id) => delete tabs[id]);
