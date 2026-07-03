"use strict";
// Framework-aware taint sources: NestJS parameter decorators (@Body/@Param/…)
// and Next.js/Web request calls (await request.json(), searchParams.get()).
const { test } = require("node:test");
const assert = require("node:assert");
const os = require("os");
const path = require("path");
const fs = require("fs");
const { analyze } = require("../src/index");

const tmpMem = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wh-fw-")), "mem.md");

test("NestJS decorators and Next.js request calls are taint sources", () => {
  const r = analyze(path.join(__dirname, "fixtures", "frameworks"), tmpMem());
  const sqli = r.confirmed.filter((f) => f.class === "SQL Injection");
  const files = new Set(sqli.map((f) => path.basename(f.rel)));

  assert.ok(files.has("nest.controller.ts"), "NestJS @Param/@Body sources not detected");
  assert.ok(files.has("route.js"), "Next.js request.json()/searchParams sources not detected");

  // find(@Param), create(@Body), POST(request.json), GET(searchParams.get) = 4.
  // The parameterized safe() method must NOT appear.
  assert.strictEqual(sqli.length, 4, "expected exactly 4 SQLi (no FP on the parameterized method): " +
    sqli.map((f) => f.rel + ":" + f.line).join(", "));
});
