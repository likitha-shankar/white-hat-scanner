"use strict";
// Pure Mode 1 detection rules — no browser/node APIs at load time, so the same
// file runs in the MV3 service worker (importScripts), the content script, and a
// node self-test.
// ponytail: the secret patterns + sensitive paths are duplicated from
// src/mode1 / src/detectors/secrets.js. Two small tables aren't worth a bundler;
// if this drifts, extract a shared JSON and load it in both runtimes.
(function () {
  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };

  function mk(cls, severity, summary, impact, evidence, fix, proof) {
    return { cls, severity, summary, impact, evidence, fix, proof: proof || [] };
  }

  const SECURITY_HEADERS = [
    ["content-security-policy", "Content-Security-Policy", "Medium",
      "No CSP — the browser has no script allowlist, so injected/3rd-party scripts run freely.",
      "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'"],
    ["x-content-type-options", "X-Content-Type-Options", "Low",
      "Without nosniff the browser may MIME-sniff and execute non-script responses as scripts.",
      "X-Content-Type-Options: nosniff"],
    ["referrer-policy", "Referrer-Policy", "Low",
      "Full URLs (tokens/paths) may leak to third parties via Referer.",
      "Referrer-Policy: strict-origin-when-cross-origin"],
    ["permissions-policy", "Permissions-Policy", "Informational",
      "Powerful features (camera, geolocation) are not explicitly restricted.",
      "Permissions-Policy: geolocation=(), camera=(), microphone=()"],
  ];

  function headerFindings(url, headers, isHttps) {
    const out = [];
    const req = `GET ${url}`;
    for (const [key, name, sev, impact, fix] of SECURITY_HEADERS) {
      if (!headers[key]) out.push(mk("Missing Security Header", sev, `${name} not set`, impact,
        `Response to ${req} has no ${name} header`, fix, [req, `no ${name} in response`]));
    }
    const csp = headers["content-security-policy"] || "";
    if (!headers["x-frame-options"] && !/frame-ancestors/i.test(csp))
      out.push(mk("Clickjacking Exposure", "Medium", "No X-Frame-Options or frame-ancestors",
        "The page can be framed by any site (clickjacking / UI redress).",
        `${req} — no framing protection`, "X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
        [req, "no X-Frame-Options / frame-ancestors"]));
    if (isHttps && !headers["strict-transport-security"])
      out.push(mk("Missing Security Header", "Medium", "Strict-Transport-Security not set",
        "Without HSTS a network attacker can downgrade to HTTP (SSL stripping).",
        `HTTPS response to ${req} has no HSTS`, "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        [req, "HTTPS without HSTS"]));
    for (const k of ["server", "x-powered-by", "x-aspnet-version"]) {
      const v = headers[k];
      if (v && /\d/.test(v))
        out.push(mk("Version Disclosure", "Informational", `${k} reveals version`,
          "Exposed version strings map directly to known CVEs.",
          `${req} → ${k}: ${v}`, `Remove or genericize the ${k} header`, [req, `${k}: ${v}`]));
    }
    return out;
  }

  function cookieFindings(url, setCookies, isHttps) {
    const out = [];
    for (const c of setCookies || []) {
      const name = c.split("=")[0].trim();
      const low = c.toLowerCase();
      const sessionish = /sess|sid|token|auth|jwt/i.test(name);
      const missing = [];
      if (!/httponly/.test(low)) missing.push(["HttpOnly", "readable by JavaScript (XSS can steal it)"]);
      if (isHttps && !/secure/.test(low)) missing.push(["Secure", "sent over plaintext HTTP if downgraded"]);
      if (!/samesite/.test(low)) missing.push(["SameSite", "sent on cross-site requests (CSRF exposure)"]);
      for (const [flag, why] of missing)
        out.push(mk("Insecure Cookie", sessionish ? "Medium" : "Low", `Cookie ${name} missing ${flag}`,
          `The cookie is ${why}.`, `Set-Cookie: ${c}`, `Add ${flag} to the cookie`, [`GET ${url}`, `Set-Cookie lacks ${flag}`]));
    }
    return out;
  }

  function corsFinding(url, acao, acac, probeOrigin) {
    if (!acao) return null;
    if (acao === probeOrigin || (acao === "*" && acac === "true"))
      return mk("Permissive CORS", "High", "CORS reflects arbitrary Origin (with credentials)",
        "The server echoes any Origin (or * with credentials), letting a malicious site read authenticated responses.",
        `Origin ${probeOrigin} → Access-Control-Allow-Origin: ${acao}`, "Allowlist trusted origins; never combine * with credentials",
        [`GET ${url} (cross-origin)`, `Access-Control-Allow-Origin: ${acao}`]);
    if (acao === "*")
      return mk("Permissive CORS", "Low", "CORS allows any origin (*)",
        "Any site can read non-credentialed responses.", "Access-Control-Allow-Origin: *",
        "Restrict to an allowlist if responses are sensitive", [`GET ${url}`, "Access-Control-Allow-Origin: *"]);
    return null;
  }

  function domFindings(doc, url, isHttps) {
    const out = [];
    const html = doc.documentElement ? doc.documentElement.outerHTML : "";
    if (isHttps) {
      const m = html.match(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/i);
      if (m) out.push(mk("Mixed Content", "Medium", "HTTPS page loads HTTP resources",
        "Plaintext sub-resources can be intercepted/modified, undermining TLS.",
        `HTTP resource on HTTPS page: ${m[1]}`, m[1].replace(/^http:/, "https:"), [url, `loads ${m[1]}`]));
    }
    if (!isHttps && doc.querySelector('input[type="password"]'))
      out.push(mk("Credentials Over HTTP", "High", "Password field served over HTTP",
        "Credentials are transmitted in plaintext, capturable by any network observer.",
        `Password input on non-HTTPS page ${url}`, "Serve login + POST target over HTTPS only", [url, "type=password on http page"]));
    if (/[?&](token|jwt|session|sessionid|access_token|api_key|apikey|password|pwd)=/i.test(url))
      out.push(mk("Sensitive Data in URL", "High", "Session/secret value in URL query string",
        "Tokens in URLs leak via history, Referer, logs, and proxies.",
        `Query string carries a sensitive parameter: ${url}`, "Move the value to a POST body or HttpOnly cookie", [url, "sensitive query parameter"]));
    return out;
  }

  const SECRET_PATTERNS = [
    ["AWS access key ID", /\bAKIA[0-9A-Z]{16}\b/],
    ["Google API key", /\bAIza[0-9A-Za-z\-_]{35}\b/],
    ["Slack token", /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/],
    ["Stripe secret key", /\bsk_(live|test)_[0-9A-Za-z]{16,}\b/],
    ["GitHub token", /\bgh[pousr]_[0-9A-Za-z]{36,}\b/],
    ["Private key block", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
    ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ];

  function scanScript(text, where) {
    const out = [];
    for (const [name, re] of SECRET_PATTERNS) {
      const m = text.match(re);
      if (m) {
        const raw = m[0].length > 12 ? m[0].slice(0, 6) + "…" + m[0].slice(-2) : m[0];
        out.push(mk("Secret in JS Bundle", "Critical", `${name} exposed in client bundle`,
          "A credential shipped in client JavaScript is readable by anyone loading the page.",
          `${where} contains ${name} (${raw})`, "Remove the secret; proxy the call through a backend", [`GET ${where}`, `matches ${name}`]));
        break;
      }
    }
    return out;
  }

  function sourceMapUrl(text) {
    const m = text.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
    return m ? m[1] : null;
  }

  const SENSITIVE_PATHS = [
    ["/.env", "Critical", /=|SECRET|KEY|PASSWORD|TOKEN/i, "Environment file with secrets"],
    ["/.git/config", "High", /\[core\]|url =/i, "Git repository config exposed"],
    ["/.git/HEAD", "High", /ref:\s*refs\//i, "Git metadata exposed (source recoverable)"],
    ["/config.json", "Medium", /[{]/, "Application config exposed"],
  ];

  function pathFinding(fullUrl, status, body, def) {
    const [, sev, sig, label] = def;
    if (status === 200 && (!sig || sig.test(body)))
      return mk("Sensitive Path Exposed", sev, label,
        "This path should not be publicly reachable; it exposes internal data to anyone.",
        `GET ${fullUrl} → 200 (${label})`, `Block this path at the web server / remove from deployment`, [`GET ${fullUrl}`, "HTTP 200"]);
    return null;
  }

  const WH = {
    SEV_ORDER, mk, headerFindings, cookieFindings, corsFinding, domFindings,
    scanScript, sourceMapUrl, SENSITIVE_PATHS, pathFinding, PROBE_ORIGIN: "https://white-hat-probe.example",
  };
  if (typeof globalThis !== "undefined") globalThis.WH = WH;
  if (typeof module !== "undefined") module.exports = WH;
})();
