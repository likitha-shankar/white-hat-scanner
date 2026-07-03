"use strict";
// Mode 1 — black-box URL surface scanner. Passive: reads what a normal browser
// session exposes plus a targeted header/asset probe. No exploitation, no
// payloads, no brute force. Every finding carries the observed request/response
// as proof.
const { PROVIDER } = require("../detectors/secrets");

const UA = "white-hat-scanner/0.1 (passive surface probe)";
const PROBE_ORIGIN = "https://white-hat-probe.example";

// Curated sensitive paths — a targeted probe, not enumeration.
const SENSITIVE_PATHS = [
  ["/.env", "Critical", /=|SECRET|KEY|PASSWORD|TOKEN/i, "Environment file with secrets"],
  ["/.git/config", "High", /\[core\]|remote|url =/i, "Git repository config exposed"],
  ["/.git/HEAD", "High", /ref:\s*refs\//i, "Git metadata exposed (source recoverable)"],
  ["/config.json", "Medium", /[{]/, "Application config exposed"],
  ["/swagger.json", "Low", /swagger|openapi/i, "API schema exposed"],
  ["/api/docs", "Low", /swagger|redoc|openapi/i, "API docs exposed"],
  ["/.well-known/security.txt", null, null, null], // positive if present
  ["/actuator/env", "High", /profiles|propertySources/i, "Spring Actuator env exposed"],
  ["/debug", "Medium", /debug|trace|stack/i, "Debug endpoint reachable"],
  ["/metrics", "Low", /# HELP|process_/i, "Prometheus metrics exposed"],
  ["/server-status", "Medium", /Apache Server Status/i, "Apache server-status exposed"],
];

async function fetchSafe(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeout || 8000);
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: ctrl.signal,
      headers: { "User-Agent": UA, ...(opts.headers || {}) },
      method: opts.method || "GET",
    });
    const body = opts.noBody ? "" : (await res.text()).slice(0, 1_500_000);
    return { ok: true, status: res.status, headers: res.headers, body, finalUrl: res.url };
  } catch (e) {
    return { ok: false, error: e.name === "AbortError" ? "timeout" : e.message };
  } finally {
    clearTimeout(t);
  }
}

function mk(cls, severity, summary, impact, evidence, remediation, steps) {
  return {
    detectorId: "mode1",
    class: cls,
    severity,
    unit: "http-surface",
    rel: evidence.where,
    line: 0,
    summary,
    attackerImpact: impact,
    evidence: evidence.text,
    remediation,
    proof: { kind: "repro", steps },
    section: "confirmed",
  };
}

// ---- header / cookie / cors checks -----------------------------------------
function checkHeaders(url, h, isHttps, findings) {
  const get = (k) => h.get(k);
  const req = `GET ${url}`;

  const HEADERS = [
    ["content-security-policy", "Content-Security-Policy", "Medium",
      "No CSP — the browser has no allowlist for scripts, so any injected/3rd-party script runs freely (XSS amplification).",
      "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'"],
    ["x-content-type-options", "X-Content-Type-Options", "Low",
      "Without nosniff the browser may MIME-sniff responses and execute non-script files as scripts.",
      "X-Content-Type-Options: nosniff"],
    ["referrer-policy", "Referrer-Policy", "Low",
      "Full URLs (with tokens/paths) may leak to third parties via the Referer header.",
      "Referrer-Policy: strict-origin-when-cross-origin"],
    ["permissions-policy", "Permissions-Policy", "Informational",
      "No Permissions-Policy — powerful features (camera, geolocation) are not explicitly restricted.",
      "Permissions-Policy: geolocation=(), camera=(), microphone=()"],
  ];
  for (const [key, name, sev, impact, fix] of HEADERS) {
    if (!get(key))
      findings.push(mk("Missing Security Header", sev, `${name} header not set`, impact,
        { where: url, text: `Response to \`${req}\` has no ${name} header` },
        { before: `(no ${name} header)`, after: fix, contract: "Response header only — no behavior change for legitimate clients." },
        [req, `Response headers do not include ${name}`]));
  }

  // clickjacking: XFO or CSP frame-ancestors
  const csp = get("content-security-policy") || "";
  if (!get("x-frame-options") && !/frame-ancestors/i.test(csp))
    findings.push(mk("Clickjacking Exposure", "Medium", "No X-Frame-Options or frame-ancestors",
      "The page can be framed by any site, enabling clickjacking (UI redress) to trick users into actions.",
      { where: url, text: `\`${req}\` — neither X-Frame-Options nor CSP frame-ancestors present` },
      { before: "(framing not restricted)", after: "X-Frame-Options: DENY  (or CSP frame-ancestors 'none')", contract: "Response header only." },
      [req, "No framing protection in response headers"]));

  // HSTS only meaningful over https
  if (isHttps && !get("strict-transport-security"))
    findings.push(mk("Missing Security Header", "Medium", "Strict-Transport-Security not set",
      "Without HSTS a network attacker can downgrade the first request to HTTP and strip TLS (SSL stripping).",
      { where: url, text: `HTTPS response to \`${req}\` has no HSTS header` },
      { before: "(no HSTS)", after: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload", contract: "Response header only." },
      [req, "HTTPS response without Strict-Transport-Security"]));

  // server version disclosure
  for (const k of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) {
    const v = get(k);
    if (v && /\d/.test(v))
      findings.push(mk("Version Disclosure", "Informational", `${k} reveals software version`,
        "Exposed version strings let an attacker look up known CVEs for that exact version.",
        { where: url, text: `\`${req}\` → ${k}: ${v}` },
        { before: `${k}: ${v}`, after: `(remove or genericize the ${k} header)`, contract: "Response header only." },
        [req, `${k}: ${v}`]));
  }
}

function checkCookies(url, h, isHttps, findings) {
  const cookies = typeof h.getSetCookie === "function" ? h.getSetCookie() : (h.get("set-cookie") ? [h.get("set-cookie")] : []);
  for (const c of cookies) {
    const name = c.split("=")[0].trim();
    const low = c.toLowerCase();
    const sessionish = /sess|sid|token|auth|jwt/i.test(name);
    const problems = [];
    if (!/httponly/.test(low)) problems.push(["HttpOnly", "readable by JavaScript (XSS can steal it)"]);
    if (isHttps && !/secure/.test(low)) problems.push(["Secure", "sent over plaintext HTTP if downgraded"]);
    if (!/samesite/.test(low)) problems.push(["SameSite", "sent on cross-site requests (CSRF exposure)"]);
    for (const [flag, why] of problems) {
      findings.push(mk("Insecure Cookie", sessionish ? "Medium" : "Low", `Cookie \`${name}\` missing ${flag}`,
        `The cookie is ${why}.`,
        { where: url, text: `Set-Cookie: ${c}` },
        { before: `Set-Cookie: ${name}=…`, after: `Set-Cookie: ${name}=…; HttpOnly; Secure; SameSite=Lax`, contract: "Cookie attributes only — same value delivered." },
        [`GET ${url}`, `Set-Cookie header lacks ${flag}`]));
    }
  }
}

async function checkCors(url, findings) {
  const res = await fetchSafe(url, { headers: { Origin: PROBE_ORIGIN }, noBody: true });
  if (!res.ok) return;
  const acao = res.headers.get("access-control-allow-origin");
  const acac = res.headers.get("access-control-allow-credentials");
  if (!acao) return;
  if (acao === PROBE_ORIGIN || (acao === "*" && acac === "true"))
    findings.push(mk("Permissive CORS", "High", "CORS reflects arbitrary Origin (with credentials)",
      "The server echoes any Origin (or allows * with credentials), letting a malicious site read authenticated responses on the victim's behalf.",
      { where: url, text: `Origin: ${PROBE_ORIGIN} → Access-Control-Allow-Origin: ${acao}${acac ? "; Allow-Credentials: " + acac : ""}` },
      { before: `Access-Control-Allow-Origin: ${acao}`, after: "Reflect only an allowlist of trusted origins; never combine * with credentials.", contract: "Restricts cross-origin reads; same-origin unaffected." },
      [`GET ${url}  (Origin: ${PROBE_ORIGIN})`, `Access-Control-Allow-Origin: ${acao}`]));
  else if (acao === "*")
    findings.push(mk("Permissive CORS", "Low", "CORS allows any origin (*)",
      "Any site can read non-credentialed responses. Low risk unless the data is sensitive.",
      { where: url, text: `Access-Control-Allow-Origin: *` },
      { before: "Access-Control-Allow-Origin: *", after: "Restrict to a trusted origin allowlist if responses are sensitive.", contract: "Header only." },
      [`GET ${url}`, "Access-Control-Allow-Origin: *"]));
}

// ---- html / bundle analysis -------------------------------------------------
function checkHtml(url, body, isHttps, findings) {
  // mixed content
  if (isHttps) {
    const mixed = [...body.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]).slice(0, 5);
    if (mixed.length)
      findings.push(mk("Mixed Content", "Medium", "HTTPS page loads HTTP resources",
        "Plaintext sub-resources can be intercepted or modified in transit, undermining the page's TLS.",
        { where: url, text: `HTTP resource on HTTPS page: ${mixed[0]}` },
        { before: mixed[0], after: mixed[0].replace(/^http:/, "https:"), contract: "Same resource over TLS." },
        [`GET ${url}`, `Body references ${mixed.length} http:// resource(s), e.g. ${mixed[0]}`]));
  }
  // login form over http
  if (!isHttps && /<input[^>]+type\s*=\s*["']?password/i.test(body))
    findings.push(mk("Credentials Over HTTP", "High", "Password field served over HTTP",
      "Login credentials are transmitted in plaintext and can be captured by any network observer.",
      { where: url, text: `Password input present on non-HTTPS page ${url}` },
      { before: "http:// login page", after: "Serve the login page and its POST target over HTTPS only; redirect HTTP→HTTPS.", contract: "Same form over TLS." },
      [`GET ${url}`, "type=password input on an http:// page"]));

  // token in URL
  if (/[?&](token|jwt|session|sessionid|access_token|api_key|apikey|password|pwd)=/i.test(url))
    findings.push(mk("Sensitive Data in URL", "High", "Session/secret value in URL query string",
      "Tokens in URLs leak via browser history, Referer headers, server logs, and proxies.",
      { where: url, text: `Query string carries a sensitive parameter: ${url}` },
      { before: url, after: "Move the value into a POST body or an HttpOnly cookie; never a query param.", contract: "Same auth, off the URL." },
      [`Observed URL: ${url}`, "Sensitive parameter in query string"]));

  // collect same-origin script srcs
  const scripts = [...body.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
  return scripts;
}

function scanBundle(bundleUrl, body, findings) {
  for (const [name, re] of PROVIDER) {
    const m = body.match(re);
    if (m) {
      const raw = m[0].length > 12 ? m[0].slice(0, 6) + "…" + m[0].slice(-2) : m[0];
      findings.push(mk("Secret in JS Bundle", "Critical", `${name} exposed in client bundle`,
        "A credential shipped in client-side JavaScript is readable by anyone loading the page.",
        { where: bundleUrl, text: `${bundleUrl} contains ${name} (\`${raw}\`)` },
        { before: `hardcoded ${name} in bundle`, after: "Remove the secret from client code; proxy the call through a backend that holds the secret server-side.", contract: "Secret leaves the client; API contract preserved via backend proxy." },
        [`GET ${bundleUrl}`, `Bundle body matches ${name} pattern`]));
      break; // one per bundle is enough signal
    }
  }
  // exposed source map
  const sm = body.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
  if (sm) return sm[1];
  return null;
}

async function scanUrl(rawUrl, opts = {}) {
  let url;
  try {
    url = new URL(rawUrl).toString();
  } catch {
    return { error: `invalid URL: ${rawUrl}` };
  }
  const findings = [];
  const positives = [];
  const main = await fetchSafe(url, opts);
  if (!main.ok) return { error: `could not fetch ${url}: ${main.error}` };

  const finalUrl = main.finalUrl || url;
  const isHttps = new URL(finalUrl).protocol === "https:";
  let probes = 1;

  checkHeaders(finalUrl, main.headers, isHttps, findings);
  checkCookies(finalUrl, main.headers, isHttps, findings);
  await checkCors(finalUrl, findings); probes++;
  const scripts = checkHtml(finalUrl, main.body, isHttps, findings);

  // directory listing
  if (/<title>\s*Index of \//i.test(main.body) || /Directory listing for/i.test(main.body))
    findings.push(mk("Directory Listing", "Medium", "Directory listing enabled",
      "The server lists directory contents, exposing files not meant to be discoverable.",
      { where: finalUrl, text: `${finalUrl} returns an auto-generated index page` },
      { before: "autoindex on", after: "Disable directory listing (autoindex off / Options -Indexes).", contract: "Files still served by exact path; listing hidden." },
      [`GET ${finalUrl}`, "Response body is a directory index"]));

  // bundles (same-origin, capped)
  const origin = new URL(finalUrl).origin;
  const bundleUrls = scripts
    .map((s) => { try { return new URL(s, finalUrl).toString(); } catch { return null; } })
    .filter((u) => u && u.startsWith(origin))
    .slice(0, 8);
  for (const b of bundleUrls) {
    const res = await fetchSafe(b, opts); probes++;
    if (!res.ok || res.status !== 200) continue;
    const mapUrl = scanBundle(b, res.body, findings);
    const mapTarget = mapUrl ? new URL(mapUrl, b).toString() : b + ".map";
    const mres = await fetchSafe(mapTarget, { ...opts, noBody: true }); probes++;
    if (mres.ok && mres.status === 200)
      findings.push(mk("Source Map Exposed", "Medium", "JavaScript source map is publicly accessible",
        "The .map file reconstructs original source (pre-minification), revealing internal logic, comments, and paths.",
        { where: mapTarget, text: `${mapTarget} returns 200` },
        { before: `${mapTarget} (200)`, after: "Do not deploy .map files to production, or restrict them to internal IPs.", contract: "App runs identically without shipped source maps." },
        [`GET ${mapTarget}`, `HTTP ${mres.status}`]));
  }

  // sensitive path probe
  for (const [p, sev, sig, label] of SENSITIVE_PATHS) {
    const target = origin + p;
    const res = await fetchSafe(target, opts); probes++;
    if (!res.ok) continue;
    if (p === "/.well-known/security.txt") {
      if (res.status === 200) positives.push({ label: "security.txt present (vuln disclosure policy)", rel: target });
      continue;
    }
    if (res.status === 200 && (!sig || sig.test(res.body)))
      findings.push(mk("Sensitive Path Exposed", sev, label,
        "This path should not be publicly reachable; it exposes internal data or artifacts to anyone.",
        { where: target, text: `GET ${target} → 200 (${label})` },
        { before: `${p} is publicly reachable`, after: `Block ${p} at the web server / remove it from the deployment.`, contract: "Path no longer served publicly." },
        [`GET ${target}`, `HTTP 200; body matches ${label}`]));
  }

  // verbose error probe (single non-existent path)
  const errRes = await fetchSafe(origin + "/whitehat-probe-" + Date.now(), opts); probes++;
  if (errRes.ok && /(?:\bat\b .+\(.+:\d+:\d+\)|Traceback \(most recent call last\)|SQLSTATE|ORA-\d+|System\.\w+Exception|stack trace)/.test(errRes.body))
    findings.push(mk("Verbose Error Disclosure", "Medium", "Error response leaks a stack trace / internals",
      "Stack traces reveal frameworks, file paths, and versions that help an attacker target the stack.",
      { where: origin, text: `A non-existent path returned an error page containing a stack trace / internal identifiers` },
      { before: "verbose error page in production", after: "Return a generic error page in production; log details server-side only.", contract: "Same status code; detail removed from the client response." },
      [`GET ${origin}/<nonexistent>`, "Response body contains a stack trace / DB error"]));

  // credit HTTPS + present headers
  if (isHttps) positives.push({ label: "Served over HTTPS", rel: finalUrl });
  for (const [k, name] of [["strict-transport-security", "HSTS"], ["content-security-policy", "CSP"]])
    if (main.headers.get(k)) positives.push({ label: `${name} configured`, rel: finalUrl });

  const confirmed = findings.filter((f) => f.section === "confirmed");
  const unconfirmed = findings.filter((f) => f.section !== "confirmed");
  return { confirmed, unconfirmed, positives, stats: { mode: "url", url: finalUrl, requests: probes } };
}

module.exports = { scanUrl };
