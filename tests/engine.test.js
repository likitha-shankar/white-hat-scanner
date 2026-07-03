"use strict";
// Self-check: the engine must fire on the vulnerable fixture and stay quiet on
// the clean one. Runs the real pipeline (parse -> detect -> prove). No mocks.
const { test } = require("node:test");
const assert = require("node:assert");
const os = require("os");
const path = require("path");
const fs = require("fs");
const { analyze } = require("../src/index");

function tmpMem() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wh-")), "mem.md");
}

test("vulnerable fixture: every detector class is found", () => {
  const r = analyze(path.join(__dirname, "fixtures", "vuln"), tmpMem());
  const classes = new Set([...r.confirmed, ...r.unconfirmed].map((f) => f.class));
  for (const cls of [
    "Hardcoded Secret",
    "SQL Injection",
    "Command Injection",
    "Weak Hash Algorithm",
    "Insecure Randomness",
    "Non-constant-time Comparison",
    "Path Traversal",
    "Broken Object-Level Authorization",
    "JWT Implementation Error",
    "Race Condition (TOCTOU)",
  ]) {
    assert.ok(classes.has(cls), `expected detector class not found: ${cls}`);
  }
});

test("JWT and race condition are reported (unconfirmed, architectural)", () => {
  const r = analyze(path.join(__dirname, "fixtures", "vuln"), tmpMem());
  const jwtF = [...r.confirmed, ...r.unconfirmed].filter((f) => f.class === "JWT Implementation Error");
  const summaries = jwtF.map((f) => f.summary).join(" | ");
  assert.ok(/algorithms/i.test(summaries), "expected verify-without-algorithms JWT finding");
  assert.ok(/expiry/i.test(summaries), "expected no-expiry JWT finding");
  assert.ok(/decode/i.test(summaries), "expected decode-for-auth JWT finding");
  assert.ok(r.unconfirmed.some((f) => f.class === "Race Condition (TOCTOU)"), "expected TOCTOU race finding");
});

test("path traversal is CONFIRMED via taint; BOLA is UNCONFIRMED (architectural)", () => {
  const r = analyze(path.join(__dirname, "fixtures", "vuln"), tmpMem());
  assert.ok(r.confirmed.some((f) => f.class === "Path Traversal"), "path traversal should be confirmed");
  assert.ok(
    r.unconfirmed.some((f) => f.class === "Broken Object-Level Authorization"),
    "BOLA should be reported as unconfirmed (manual verify)"
  );
  assert.ok(!r.confirmed.some((f) => f.class === "Broken Object-Level Authorization"), "BOLA must not be auto-confirmed");
});

test("vulnerable fixture: injection + secret + crypto are CONFIRMED (proven)", () => {
  const r = analyze(path.join(__dirname, "fixtures", "vuln"), tmpMem());
  const confirmed = new Set(r.confirmed.map((f) => f.class));
  assert.ok(confirmed.has("SQL Injection"), "SQLi should be confirmed via taint");
  assert.ok(confirmed.has("Command Injection"), "cmd injection should be confirmed via taint");
  assert.ok(confirmed.has("Hardcoded Secret"), "provider secret should be confirmed via regex proof");
  assert.ok(confirmed.has("Weak Hash Algorithm"), "md5 should be confirmed via runnable proof");
});

test("clean fixture: no confirmed findings, positives detected", () => {
  const r = analyze(path.join(__dirname, "fixtures", "clean"), tmpMem());
  assert.strictEqual(r.confirmed.length, 0, "clean code produced confirmed findings: " +
    JSON.stringify(r.confirmed.map((f) => f.class)));
  assert.ok(r.positives.length > 0, "expected positive observations in clean code");
});

test("memory file is written and re-loaded as known patterns", () => {
  const mem = tmpMem();
  analyze(path.join(__dirname, "fixtures", "vuln"), mem);
  assert.ok(fs.existsSync(mem), "memory file not written");
  const second = analyze(path.join(__dirname, "fixtures", "vuln"), mem);
  assert.ok(second.confirmed.some((f) => f.known), "second run should mark known patterns");
});
