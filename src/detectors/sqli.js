"use strict";
// SQL injection: a query sink receives a string built from tainted input via
// concatenation or template interpolation. Confirmed when the built string
// provably carries tainted data (param or req.*) in the enclosing function.
const { loc, lineSpan, taintedNames, exprIsTainted, isRequestMember } = require("../parse");

const SINK_METHODS = new Set(["query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe"]);

function sinkName(callee) {
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") return callee.property.name;
  if (callee.type === "Identifier") return callee.name;
  return null;
}

// A string-building expression that mixes literal SQL with dynamic parts.
function builtStrings(node, out) {
  if (!node) return;
  if (node.type === "TemplateLiteral" && node.expressions.length) out.push(node);
  else if (node.type === "BinaryExpression" && node.operator === "+") out.push(node);
}

function scan(unitFile, ast, h) {
  const { unit, rel, code } = unitFile;
  const findings = [];
  const taintCache = new WeakMap();

  h.traverse(ast, {
    CallExpression(path) {
      const name = sinkName(path.node.callee);
      if (!name || !SINK_METHODS.has(name)) return;
      const arg = path.node.arguments[0];
      const built = [];
      builtStrings(arg, built);
      if (!built.length) return;

      const fnPath = path.getFunctionParent();
      let tainted = new Set();
      if (fnPath) {
        if (!taintCache.has(fnPath.node)) taintCache.set(fnPath.node, taintedNames(fnPath));
        tainted = taintCache.get(fnPath.node);
      }
      const expr = built[0];
      const confirmed = exprIsTainted(expr, tainted) || containsReqMember(expr);
      findings.push(build(unitFile, path.node, expr, confirmed));
    },
  });
  return findings;
}

function containsReqMember(node) {
  if (!node) return false;
  if (isRequestMember(node)) return true;
  if (node.type === "TemplateLiteral") return node.expressions.some(containsReqMember);
  if (node.type === "BinaryExpression") return containsReqMember(node.left) || containsReqMember(node.right);
  if (node.type === "MemberExpression") return containsReqMember(node.object);
  return false;
}

function build(unitFile, node, expr, confirmed) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "sqli",
    class: "SQL Injection",
    severity: "Critical",
    confirmedOverride: confirmed, // engine promotes/demotes to Unconfirmed section
    unit,
    rel,
    ...loc(node),
    summary: "Query built by string concatenation/interpolation reaches a database sink",
    attackerImpact:
      "An attacker crafts input containing SQL syntax that alters the query — reading arbitrary tables, bypassing auth checks, or destroying data (DROP/DELETE).",
    evidence: `${rel}:${loc(node).line} — dynamic string passed to a query sink`,
    remediation: {
      before: span.text,
      // Auto-rewriting arbitrary SQL is unsafe; present the parameterized shape
      // for the developer to fill. Placeholders (?) replace each tainted part.
      after:
        "// Replace interpolation with bound parameters:\n" +
        "db.query('SELECT ... WHERE col = ?', [taintedValue]);",
      contract:
        "Parameterized queries return the same rows for the same legitimate inputs. Output contract and complexity unchanged; only untrusted values move from the SQL string into bound parameters, which the driver escapes.",
    },
    proof: {
      kind: "repro",
      steps: [
        `Send a request whose tainted value is \`' OR '1'='1\` (or \`'; DROP TABLE users;--\`).`,
        `The value is interpolated into the SQL string at ${rel}:${loc(node).line} without escaping.`,
        "Observe the query returns unintended rows / executes an injected statement.",
      ],
    },
  };
}

module.exports = { id: "sqli", scan };
