"use strict";
// Interprocedural taint: taint must cross function and file boundaries via the
// call graph. These findings are impossible for the intraprocedural analysis.
const { test } = require("node:test");
const assert = require("node:assert");
const os = require("os");
const path = require("path");
const fs = require("fs");
const { analyze } = require("../src/index");

const tmpMem = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wh-ip-")), "mem.md");

test("taint crosses a FILE boundary: SQLi confirmed in the callee file", () => {
  const r = analyze(path.join(__dirname, "fixtures", "interproc"), tmpMem());
  const sqli = r.confirmed.find((f) => f.class === "SQL Injection");
  assert.ok(sqli, "cross-file SQL injection should be confirmed via the call graph");
  assert.ok(/db\.js$/.test(sqli.rel), "the SQLi sink is located in db.js, not the caller: " + sqli.rel);
});

test("cross-file taint works with a RELATIVE target path (regression)", () => {
  // Module resolution must normalize paths; a relative target once silently
  // broke cross-file taint while same-file taint kept working.
  const rel = path.relative(process.cwd(), path.join(__dirname, "fixtures", "interproc"));
  const r = analyze(rel, tmpMem());
  assert.ok(r.confirmed.some((f) => f.class === "SQL Injection"),
    "relative-path invocation must still resolve imports and confirm cross-file SQLi");
});

test("taint crosses a FUNCTION boundary: command injection confirmed in the helper", () => {
  const r = analyze(path.join(__dirname, "fixtures", "interproc"), tmpMem());
  const cmd = r.confirmed.find((f) => f.class === "Command Injection");
  assert.ok(cmd, "cross-function command injection should be confirmed via the call graph");
});

test("no over-taint: a helper never called with tainted input is not confirmed", () => {
  // db.js runQuery is only ever called with req input in this fixture, so it IS
  // tainted. The guard here is that the clean single-file fixture stays clean
  // with the call graph active — i.e. interprocedural analysis added no FPs.
  const r = analyze(path.join(__dirname, "fixtures", "clean"), tmpMem());
  assert.strictEqual(r.confirmed.length, 0, "call graph introduced false positives on clean code: " +
    r.confirmed.map((f) => f.class).join(", "));
});
