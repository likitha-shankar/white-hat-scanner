"use strict";
// JWT implementation errors. Architectural — reported Unconfirmed with repro
// paths (like BOLA). Covers the classes junior devs miss:
//   - verify() without an explicit `algorithms` allowlist  -> alg-confusion / "none"
//   - `none` / `alg:none` explicitly permitted             -> forge any token
//   - sign() with no expiry (no expiresIn, no exp claim)    -> tokens never die
//   - decode() used where verify() is required             -> unverified claims
//   - hardcoded string secret passed to sign()/verify()    -> secret in source
const { loc, lineSpan } = require("../parse");

function jwtCall(callee) {
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    const obj = callee.object.type === "Identifier" ? callee.object.name : "";
    if (/jwt|jsonwebtoken|jose/i.test(obj)) return callee.property.name;
  }
  return null;
}

function objProps(node) {
  const props = new Map();
  if (node && node.type === "ObjectExpression") {
    for (const p of node.properties) {
      if (p.type === "ObjectProperty" && (p.key.name || p.key.value) != null)
        props.set(p.key.name || p.key.value, p.value);
    }
  }
  return props;
}

function mentionsNone(node) {
  if (!node) return false;
  if (node.type === "StringLiteral") return node.value.toLowerCase() === "none";
  if (node.type === "ArrayExpression") return node.elements.some(mentionsNone);
  return false;
}

function scan(unitFile, ast, h) {
  const findings = [];
  h.traverse(ast, {
    CallExpression(path) {
      const method = jwtCall(path.node.callee);
      if (!method) return;
      const args = path.node.arguments;

      if (method === "verify") {
        const opts = objProps(args[2]);
        // explicit "none" anywhere in options
        if (mentionsNone(opts.get("algorithms")) || mentionsNone(opts.get("algorithm")))
          findings.push(mk(unitFile, path.node, "none-alg"));
        else if (!opts.has("algorithms"))
          findings.push(mk(unitFile, path.node, "no-algorithms"));
        if (args[1] && args[1].type === "StringLiteral") findings.push(mk(unitFile, path.node, "literal-secret"));
      } else if (method === "sign") {
        const opts = objProps(args[2]);
        const payload = objProps(args[0]);
        if (!opts.has("expiresIn") && !payload.has("exp")) findings.push(mk(unitFile, path.node, "no-expiry"));
        if (mentionsNone(opts.get("algorithm"))) findings.push(mk(unitFile, path.node, "none-alg"));
        if (args[1] && args[1].type === "StringLiteral") findings.push(mk(unitFile, path.node, "literal-secret"));
      } else if (method === "decode") {
        findings.push(mk(unitFile, path.node, "decode"));
      }
    },
  });
  return findings;
}

const KINDS = {
  "no-algorithms": {
    severity: "High",
    summary: "jwt.verify() called without an explicit `algorithms` allowlist",
    impact:
      "Without a pinned algorithm, an attacker can swap the token's alg header — e.g. RS256→HS256 (algorithm confusion) or alg:none — and forge tokens the server accepts.",
    after: "jwt.verify(token, key, { algorithms: ['RS256'] }); // pin the expected algorithm",
    steps: [
      "Take a valid token; change its header `alg` to `none` (or HS256 signed with the public key).",
      "Submit it — verify() has no allowlist, so it accepts the attacker-chosen algorithm.",
      "Authenticate as any user with a forged token.",
    ],
  },
  "none-alg": {
    severity: "Critical",
    summary: "JWT `none` algorithm permitted",
    impact: "The `none` algorithm means unsigned tokens are accepted — an attacker forges any claims with no key.",
    after: "// Never allow 'none'. Pin a real algorithm:\njwt.verify(token, key, { algorithms: ['RS256'] });",
    steps: [
      "Craft a token with header {alg:'none'} and arbitrary payload, empty signature.",
      "Submit it; the server accepts unsigned tokens.",
      "Impersonate any user / escalate role at will.",
    ],
  },
  "no-expiry": {
    severity: "Medium",
    summary: "jwt.sign() issues a token with no expiry (no expiresIn / exp)",
    impact: "A leaked token is valid forever — no rotation, no revocation window. Stolen tokens never stop working.",
    after: "jwt.sign(payload, key, { expiresIn: '15m' }); // short-lived; pair with refresh tokens",
    steps: [
      "Obtain a signed token from this endpoint.",
      "Inspect it — there is no `exp` claim.",
      "Reuse it indefinitely; it is never rejected for age.",
    ],
  },
  "decode": {
    severity: "High",
    summary: "jwt.decode() used — decode does NOT verify the signature",
    impact:
      "decode() returns claims without checking the signature. If these claims drive auth decisions, an attacker edits the payload freely.",
    after: "const claims = jwt.verify(token, key, { algorithms: ['RS256'] }); // verify, don't decode",
    steps: [
      "Take any token; edit its payload (e.g. role:'admin') and re-base64 without re-signing.",
      "The code path uses decode(), which skips signature verification.",
      "The tampered claims are trusted.",
    ],
  },
  "literal-secret": {
    severity: "High",
    summary: "JWT secret passed as a hardcoded string literal",
    impact: "A signing/verification secret committed in source lets anyone with repo/bundle access mint valid tokens.",
    after: "jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m', algorithm: 'HS256' });",
    steps: [
      "Read the literal secret from source at the flagged line.",
      "Sign a token with arbitrary claims using that secret.",
      "The server verifies it as authentic.",
    ],
  },
};

function mk(unitFile, node, kind) {
  const { code, rel, unit } = unitFile;
  const k = KINDS[kind];
  const span = lineSpan(code, node);
  return {
    detectorId: "jwt",
    class: "JWT Implementation Error",
    severity: k.severity,
    confirmedOverride: false, // architectural — verify in context
    unit, rel, ...loc(node),
    summary: k.summary,
    attackerImpact: k.impact,
    evidence: `${rel}:${loc(node).line} — ${k.summary}`,
    remediation: {
      before: span.text,
      after: k.after,
      contract:
        "Change is additive/hardening: pins algorithm, adds expiry, or verifies signature. Legitimate tokens issued/accepted as before; only forged, unsigned, or stale tokens are rejected. No output-contract or complexity change on the valid path.",
    },
    proof: { kind: "repro", steps: k.steps },
  };
}

module.exports = { id: "jwt", scan };
