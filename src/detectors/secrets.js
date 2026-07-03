"use strict";
// Hardcoded secrets / credentials in source. Provider-format matches are
// Confirmed (proof = the literal matches a real credential shape). Generic
// secret-named assignments are reported Unconfirmed to avoid false positives.
const { loc, lineSpan } = require("../parse");

// [name, regex, confirmed?] — provider patterns are high-precision => confirmed.
const PROVIDER = [
  ["AWS access key ID", /\bAKIA[0-9A-Z]{16}\b/, true],
  ["Google API key", /\bAIza[0-9A-Za-z\-_]{35}\b/, true],
  ["Slack token", /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, true],
  ["Stripe secret key", /\bsk_(live|test)_[0-9A-Za-z]{16,}\b/, true],
  ["GitHub token", /\bgh[pousr]_[0-9A-Za-z]{36,}\b/, true],
  ["Private key block", /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, true],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, true],
];

const SECRET_NAME = /(secret|passwd|password|pwd|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)/i;
const PLACEHOLDER = /^(your|example|changeme|placeholder|xxx+|test|dummy|<.*>|\$\{.*\})/i;

function scan(unitFile, ast, h) {
  const { code, rel, unit } = unitFile;
  const findings = [];
  h.traverse(ast, {
    StringLiteral(path) {
      const val = path.node.value;
      if (!val || val.length < 8) return;

      for (const [name, re, confirmed] of PROVIDER) {
        if (re.test(val)) {
          findings.push(build(unitFile, path.node, name, val, confirmed ? "runnable" : "repro", re));
          return;
        }
      }
      // generic: string assigned to a secret-named identifier / property.
      // Real credentials have no whitespace — reject prose (rule descriptions,
      // messages) that merely happen to sit under a "secret"-named key.
      if (val.length >= 8 && !/\s/.test(val) && !PLACEHOLDER.test(val) && looksAssignedToSecret(path)) {
        findings.push(build(unitFile, path.node, "Secret-named literal", val, "repro", null));
      }
    },
  });
  return findings;
}

function looksAssignedToSecret(path) {
  const p = path.parent;
  if (p.type === "VariableDeclarator" && p.id.type === "Identifier") return SECRET_NAME.test(p.id.name);
  if (p.type === "AssignmentExpression" && p.left.type === "Identifier") return SECRET_NAME.test(p.left.name);
  // only when the literal is the VALUE — a secret-named KEY is not a secret
  if (p.type === "ObjectProperty" && p.value === path.node && p.key) {
    const k = p.key.name || p.key.value;
    return typeof k === "string" && SECRET_NAME.test(k);
  }
  return false;
}

function build(unitFile, node, kind, value, proofKind, re) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  const raw = value.length > 12 ? value.slice(0, 6) + "…" + value.slice(-2) : value;
  const before = span.text;
  const after = before.replace(/(['"`]).*\1/, "process.env.SECRET_NAME");
  return {
    detectorId: "secrets",
    class: "Hardcoded Secret",
    severity: kind === "Secret-named literal" ? "Medium" : "Critical",
    unit,
    rel,
    ...loc(node),
    summary: `${kind} committed in source`,
    attackerImpact:
      "Anyone with read access to the repo (or a leaked bundle) obtains a live credential and can authenticate as the application to the corresponding service.",
    evidence: `${rel}:${loc(node).line} — literal matching ${kind} (\`${raw}\`)`,
    remediation: {
      before,
      after,
      applyable: true, // real line transform (literal -> env), safe to auto-apply
      contract:
        "Value now read from environment at runtime. Output identical when env var is set; only the secret's source changes. No control-flow or complexity change.",
    },
    proof:
      proofKind === "runnable"
        ? { kind: "runnable", check: "regex", pattern: re.source, flags: re.flags, value }
        : {
            kind: "repro",
            steps: [
              `Open ${rel} at line ${loc(node).line}.`,
              "Confirm the literal is a real credential (not a placeholder) by using it against the target service.",
              "Rotate immediately and move to a secret manager / env var.",
            ],
          },
  };
}

module.exports = { id: "secrets", scan, PROVIDER };
