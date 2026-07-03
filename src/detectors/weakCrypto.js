"use strict";
// Weak cryptographic primitives: MD5/SHA1 for hashing, ECB mode ciphers,
// Math.random() for security values. Hash/ECB findings carry a runnable proof —
// the harness actually invokes the primitive to confirm it's live as written.
const { loc, lineSpan } = require("../parse");

const WEAK_HASH = new Set(["md5", "sha1"]);

function calleePath(callee) {
  // crypto.createHash / createHash (destructured) / require('crypto').createHash
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") return callee.property.name;
  if (callee.type === "Identifier") return callee.name;
  return null;
}

function firstStr(node) {
  const a = node.arguments[0];
  return a && a.type === "StringLiteral" ? a.value : null;
}

function scan(unitFile, ast, h) {
  const { unit, rel, code } = unitFile;
  const findings = [];

  h.traverse(ast, {
    CallExpression(path) {
      const name = calleePath(path.node.callee);
      if (name === "createHash") {
        const algo = (firstStr(path.node) || "").toLowerCase();
        if (WEAK_HASH.has(algo)) findings.push(weakHash(unitFile, path.node, algo));
      } else if (name === "createCipheriv" || name === "createCipher") {
        const algo = (firstStr(path.node) || "").toLowerCase();
        if (name === "createCipher") findings.push(ecb(unitFile, path.node, "createCipher (deprecated, key-derived IV)"));
        else if (algo.includes("ecb")) findings.push(ecb(unitFile, path.node, algo));
      }
    },
    MemberExpression(path) {
      // Math.random() feeding a security-named target
      if (
        path.node.object.type === "Identifier" && path.node.object.name === "Math" &&
        path.node.property.type === "Identifier" && path.node.property.name === "random"
      ) {
        const decl = path.findParent((p) => p.isVariableDeclarator() || p.isAssignmentExpression());
        const target = decl && (decl.node.id || decl.node.left);
        const nm = target && target.type === "Identifier" ? target.name : "";
        if (/token|secret|otp|nonce|session|key|password|reset/i.test(nm)) {
          findings.push(insecureRandom(unitFile, path.node, nm));
        }
      }
    },
  });
  return findings;
}

function weakHash(unitFile, node, algo) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "weakCrypto",
    class: "Weak Hash Algorithm",
    severity: "High",
    unit, rel, ...loc(node),
    summary: `${algo.toUpperCase()} used for hashing`,
    attackerImpact:
      `${algo.toUpperCase()} is fast and broken — an attacker cracks stolen password hashes with GPU/rainbow tables in seconds, or forges collisions.`,
    evidence: `${rel}:${loc(node).line} — crypto.createHash('${algo}')`,
    remediation: {
      before: span.text,
      after: span.text.replace(/createHash\((['"`])(md5|sha1)\1\)[\s\S]*/i,
        "// Password hashing: use a slow KDF\n// await bcrypt.hash(password, 12)  // or scrypt / argon2"),
      contract:
        "For passwords the primitive must change to a salted slow KDF (bcrypt/scrypt/argon2); verification path switches to compare(). Same authentication decision for correct passwords; only the stored representation and compute cost change.",
    },
    proof: { kind: "runnable", check: "weak-hash", algo },
  };
}

function ecb(unitFile, node, algo) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "weakCrypto",
    class: "Insecure Cipher Mode",
    severity: "High",
    unit, rel, ...loc(node),
    summary: `Insecure cipher configuration (${algo})`,
    attackerImpact:
      "ECB mode encrypts identical plaintext blocks to identical ciphertext, leaking structure and enabling block shuffling/replay.",
    evidence: `${rel}:${loc(node).line} — ${algo}`,
    remediation: {
      before: span.text,
      after: "// Use an authenticated mode with a random IV per message:\n" +
        "crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));",
      contract:
        "GCM produces ciphertext of the same plaintext plus an auth tag; decryption path adds tag verification. Same plaintext recovered for legitimate messages; tampering now detected. Complexity unchanged.",
    },
    proof: { kind: "runnable", check: "ecb", algo },
  };
}

function insecureRandom(unitFile, node, nm) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "weakCrypto",
    class: "Insecure Randomness",
    severity: "High",
    confirmedOverride: true,
    unit, rel, ...loc(node),
    summary: `Math.random() used for security value \`${nm}\``,
    attackerImpact:
      "Math.random() is a non-cryptographic PRNG; its output is predictable, letting an attacker guess tokens/OTPs/session identifiers.",
    evidence: `${rel}:${loc(node).line} — Math.random() assigned to \`${nm}\``,
    remediation: {
      before: span.text,
      after: span.text.replace(/Math\.random\(\)[\s\S]*/,
        "crypto.randomBytes(32).toString('hex'); // CSPRNG"),
      applyable: true, // real line transform preserving the assignment target
      contract:
        "crypto.randomBytes draws from the OS CSPRNG. Same value shape (string/number) with unpredictable entropy; no control-flow change.",
    },
    proof: {
      kind: "repro",
      steps: [
        `\`${nm}\` is derived from Math.random() at ${rel}:${loc(node).line}.`,
        "Collect several emitted values; Math.random()'s state is recoverable, so future values are predictable.",
        "Predict the next token/OTP and use it before the legitimate holder.",
      ],
    },
  };
}

module.exports = { id: "weakCrypto", scan };
