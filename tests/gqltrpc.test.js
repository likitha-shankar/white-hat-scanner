"use strict";
// Schema-aware sources: GraphQL resolver args, tRPC input, TypeGraphQL @Arg.
const { test } = require("node:test");
const assert = require("node:assert");
const os = require("os");
const path = require("path");
const fs = require("fs");
const { analyze } = require("../src/index");

const tmpMem = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wh-gt-")), "mem.md");

test("GraphQL / tRPC / TypeGraphQL inputs are taint sources", () => {
  const r = analyze(path.join(__dirname, "fixtures", "gqltrpc"), tmpMem());
  const sqli = r.confirmed.filter((f) => f.class === "SQL Injection");
  const byFile = (name) => sqli.filter((f) => path.basename(f.rel) === name).length;

  assert.strictEqual(byFile("graphql.resolvers.js"), 3, "GraphQL resolver args (user/search/del)");
  assert.strictEqual(byFile("trpc.router.js"), 3, "tRPC input (getUser/find + helper via runRaw)");
  assert.strictEqual(byFile("typegraphql.resolver.ts"), 1, "TypeGraphQL @Arg (user only; safe() parameterized)");
  assert.strictEqual(sqli.length, 7, "no over-taint: exactly 7 SQLi, safe() not flagged");
});

test("inline tRPC resolver taints a helper it calls (taint flows OUT of the resolver)", () => {
  const r = analyze(path.join(__dirname, "fixtures", "gqltrpc"), tmpMem());
  const helper = r.confirmed.find((f) =>
    f.class === "SQL Injection" && /logs WHERE msg/.test((f.remediation && f.remediation.before) || ""));
  assert.ok(helper, "runRaw() helper sink must be confirmed via taint from the inline tRPC resolver");
});
