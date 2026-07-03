"use strict";
// TOCTOU race conditions in async handlers. A read (findOne/exists/count) followed
// by a write (create/save/update/increment) on the same logical resource, with no
// transaction or row lock between them. Two concurrent requests both pass the
// check before either writes — the payment/inventory/coupon double-spend class.
//
// Architectural + concurrency-dependent -> Unconfirmed with a repro path.
const { loc, lineSpan, snippet } = require("../parse");

const READ_SINKS = new Set(["findOne", "findById", "findByPk", "findUnique", "findFirst", "exists", "count", "countDocuments"]);
// Non-atomic writes. findOneAndUpdate/upsert are atomic conditional writes (the
// fix) — excluded here and treated as a guard below.
const WRITE_SINKS = new Set([
  "save", "create", "insert", "insertOne", "insertMany", "update", "updateOne", "updateMany",
  "increment", "decrement", "destroy",
]);
// Presence of any of these in the function => concurrency is guarded; suppress.
const GUARD = /transaction|\$transaction|startSession|withTransaction|\.lock\(|for update|acquirelock|withlock|mutex|serializable|findoneandupdate|\bupsert\b/i;

function callName(callee) {
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") return callee.property.name;
  if (callee.type === "Identifier") return callee.name;
  return null;
}

function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
}

function hasAwait(fnPath) {
  let found = false;
  fnPath.traverse({ AwaitExpression() { found = true; } });
  return found;
}

function scan(unitFile, ast, h) {
  const { code } = unitFile;
  const findings = [];

  h.traverse(ast, {
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ClassMethod|ObjectMethod"(fnPath) {
      if (!fnPath.node.async && !hasAwait(fnPath)) return; // needs a concurrency context

      // Guard on code only — a comment mentioning "transaction" must not suppress.
      const fnSrc = stripComments(snippet(code, fnPath.node));
      if (GUARD.test(fnSrc)) return;

      let firstRead = null;
      const writes = [];
      fnPath.traverse({
        CallExpression(p) {
          const name = callName(p.node.callee);
          if (!name) return;
          const line = (p.node.loc && p.node.loc.start.line) || 0;
          if (READ_SINKS.has(name) && !firstRead) firstRead = { node: p.node, line, name };
          else if (WRITE_SINKS.has(name)) writes.push({ node: p.node, line, name });
        },
      });
      if (!firstRead) return;
      // a write that happens after the read in source order = check-then-act
      const act = writes.find((w) => w.line >= firstRead.line);
      if (!act) return;
      findings.push(build(unitFile, firstRead, act));
    },
  });
  return findings;
}

function build(unitFile, read, act) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, read.node);
  return {
    detectorId: "raceCondition",
    class: "Race Condition (TOCTOU)",
    severity: "High",
    confirmedOverride: false, // concurrency-dependent — verify under load
    unit, rel, ...loc(read.node),
    summary: `Check-then-act: ${read.name}() then ${act.name}() with no transaction or lock`,
    attackerImpact:
      "Two concurrent requests both pass the read/check before either write commits, so a limit is bypassed — coupon redeemed twice, balance over-withdrawn, inventory oversold, duplicate account created.",
    evidence: `${rel}:${read.line} reads (${read.name}) then ${rel}:${act.line} writes (${act.name}) — no atomic wrapping`,
    remediation: {
      before: span.text,
      after:
        "// Make check-and-act atomic. Either a transaction with a row lock:\n" +
        "await db.transaction(async (tx) => {\n" +
        "  const row = await Model.findOne({ id }, { lock: tx.LOCK.UPDATE, transaction: tx });\n" +
        "  if (row.balance < amount) throw new Error('insufficient');\n" +
        "  await row.decrement('balance', { by: amount, transaction: tx });\n" +
        "});\n" +
        "// …or a single atomic conditional update:\n" +
        "// UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
      contract:
        "Serializing the check and act (lock or atomic conditional write) yields the same result for a single request. Complexity unchanged; the atomic UPDATE is one round trip. Only interleaved concurrent execution is now prevented.",
    },
    proof: {
      kind: "repro",
      steps: [
        `Fire N concurrent identical requests hitting ${rel}:${read.line}.`,
        `All N pass the ${read.name}() check before any ${act.name}() commits (no lock/transaction).`,
        "Observe the guarded limit exceeded (e.g. coupon used N times, balance negative).",
      ],
    },
  };
}

module.exports = { id: "raceCondition", scan };
