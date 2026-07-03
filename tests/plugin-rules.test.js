"use strict";
// Self-check for the browser plugin's pure detection rules (rules.js runs in node
// too). The DOM/network parts are exercised by loading rules directly.
const { test } = require("node:test");
const assert = require("node:assert");
const WH = require("../browser-plugin/rules");

test("missing headers are flagged; present headers are not", () => {
  const bare = WH.headerFindings("https://x/", {}, true).map((f) => f.summary);
  assert.ok(bare.some((s) => /Content-Security-Policy/.test(s)), "CSP missing not flagged");
  assert.ok(bare.some((s) => /Strict-Transport-Security/.test(s)), "HSTS missing not flagged");

  const full = WH.headerFindings("https://x/", {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin",
    "permissions-policy": "geolocation=()",
    "x-frame-options": "DENY",
    "strict-transport-security": "max-age=1",
  }, true);
  assert.strictEqual(full.length, 0, "secure headers still flagged: " + full.map((f) => f.summary));
});

test("cookie flags: session cookie missing HttpOnly/Secure/SameSite", () => {
  const f = WH.cookieFindings("https://x/", ["sid=abc; Path=/"], true);
  const flags = f.map((x) => x.summary).join(" ");
  assert.ok(/HttpOnly/.test(flags) && /Secure/.test(flags) && /SameSite/.test(flags));
  assert.strictEqual(WH.cookieFindings("https://x/", ["sid=abc; HttpOnly; Secure; SameSite=Lax"], true).length, 0);
});

test("CORS reflection is High, wildcard is Low, none is null", () => {
  assert.strictEqual(WH.corsFinding("https://x/", WH.PROBE_ORIGIN, "true", WH.PROBE_ORIGIN).severity, "High");
  assert.strictEqual(WH.corsFinding("https://x/", "*", null, WH.PROBE_ORIGIN).severity, "Low");
  assert.strictEqual(WH.corsFinding("https://x/", null, null, WH.PROBE_ORIGIN), null);
});

test("secret in script + source map url + sensitive path", () => {
  const s = WH.scanScript('const k="AKIAIOSFODNN7EXAMPLE";', "https://x/app.js");
  assert.strictEqual(s[0].severity, "Critical");
  assert.strictEqual(WH.sourceMapUrl("code\n//# sourceMappingURL=app.js.map"), "app.js.map");
  const env = WH.pathFinding("https://x/.env", 200, "SECRET_KEY=1", WH.SENSITIVE_PATHS[0]);
  assert.strictEqual(env.severity, "Critical");
  assert.strictEqual(WH.pathFinding("https://x/.env", 404, "", WH.SENSITIVE_PATHS[0]), null);
});
