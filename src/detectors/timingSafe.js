"use strict";
// Non-constant-time comparison of secrets. Using === on a token/HMAC/signature
// leaks how many leading bytes matched via timing, enabling byte-by-byte forgery.
const { loc, lineSpan } = require("../parse");

const SECRET_ID = /(token|secret|signature|sig|hmac|digest|hash|apikey|api[_-]?key|password|otp|csrf|mac)/i;

function nameOf(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && node.property.type === "Identifier") return node.property.name;
  return "";
}

function scan(unitFile, ast, h) {
  const { unit, rel, code } = unitFile;
  const findings = [];
  h.traverse(ast, {
    BinaryExpression(path) {
      const op = path.node.operator;
      if (op !== "===" && op !== "!==" && op !== "==" && op !== "!=") return;
      const ln = nameOf(path.node.left), rn = nameOf(path.node.right);
      const secretSide = SECRET_ID.test(ln) || SECRET_ID.test(rn);
      if (!secretSide) return;
      // both sides dynamic (not comparing to a literal length/undefined)
      const lit = path.node.left.type === "StringLiteral" || path.node.right.type === "StringLiteral" ||
        path.node.left.type === "NumericLiteral" || path.node.right.type === "NumericLiteral";
      if (lit) return;
      findings.push(build(unitFile, path.node, ln, rn));
    },
  });
  return findings;
}

function build(unitFile, node, ln, rn) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "timingSafe",
    class: "Non-constant-time Comparison",
    severity: "Medium",
    confirmedOverride: false, // heuristic on names → verify manually
    unit, rel, ...loc(node),
    summary: `Secret compared with ${node.operator} (\`${ln || "?"}\` vs \`${rn || "?"}\`)`,
    attackerImpact:
      "=== short-circuits at the first differing byte, so response timing reveals prefix length. An attacker recovers the secret byte-by-byte over many requests.",
    evidence: `${rel}:${loc(node).line} — ${node.operator} comparison involving a secret-named value`,
    remediation: {
      before: span.text,
      after: span.text.replace(/([\w.\[\]]+)\s*[!=]==?\s*([\w.\[\]]+)/,
        "crypto.timingSafeEqual(Buffer.from($1), Buffer.from($2))"),
      applyable: true, // uses the real operands captured from source
      contract:
        "timingSafeEqual returns the same boolean equality for equal-length buffers but in constant time. Wrap in a length check first. Truth value unchanged for legitimate inputs; only the timing side-channel closes.",
    },
    proof: {
      kind: "repro",
      steps: [
        `The comparison at ${rel}:${loc(node).line} uses ${node.operator} on a secret.`,
        "Measure response time across candidate values differing in the first byte.",
        "The correct first byte responds measurably slower; iterate to recover the full secret.",
      ],
    },
  };
}

module.exports = { id: "timingSafe", scan };
