"use strict";
// white_hat_memory.md — confirmed vulnerability *classes* persisted across runs.
// On later runs these are checked first (findings of a known class float to the
// top of the report, flagged "known pattern"), and the run reports faster hits.
const fs = require("fs");

const SIGNATURE = {
  "Hardcoded Secret": "String literal matching a provider credential format or assigned to a secret-named identifier.",
  "SQL Injection": "Tainted value reaching .query/.execute via template/`+` concatenation.",
  "Command Injection": "Tainted value reaching exec/execSync as a built command string.",
  "Path Traversal": "Tainted value used as a path in an fs sink or res.sendFile without normalization.",
  "Broken Object-Level Authorization": "Object sink (findById/update/delete) on a client-supplied id with no req.user/session reference in the handler.",
  "JWT Implementation Error": "jwt.verify without algorithms allowlist, none-alg, no expiry, decode-for-auth, or literal secret.",
  "Race Condition (TOCTOU)": "Read sink (findOne/exists/count) then non-atomic write in an async handler with no transaction or lock.",
  "Weak Hash Algorithm": "crypto.createHash('md5'|'sha1').",
  "Insecure Cipher Mode": "createCipheriv with an -ecb algorithm, or deprecated createCipher.",
  "Insecure Randomness": "Math.random() assigned to a security-named value.",
  "Non-constant-time Comparison": "=== / !== on a token/HMAC/signature-named value.",
};

const LANG = "JavaScript/TypeScript (Node)";
const WHY_MISSED = {
  "SQL Injection": "Requires intraprocedural taint tracking; grep-style scanners flag every .query().",
  "Command Injection": "Same — needs taint from param/req to the shell sink, not just the sink name.",
  "Path Traversal": "Needs taint from req to an fs path; scanners flag every readFile or none.",
  "Broken Object-Level Authorization": "No injectable signature — it's the ABSENCE of an ownership check, invisible to pattern matching.",
  "JWT Implementation Error": "Correct-looking API calls; the flaw is a missing option (algorithms/expiresIn) or verify-vs-decode confusion.",
  "Race Condition (TOCTOU)": "Each statement is correct in isolation; the bug is the gap between read and write under concurrency.",
  "Non-constant-time Comparison": "Semantically identical to any ===; only the secret-typed operand makes it a flaw.",
};

function load(path) {
  const known = new Map();
  let text = "";
  try {
    text = fs.readFileSync(path, "utf8");
  } catch {
    return known;
  }
  for (const block of text.split(/\n(?=## )/)) {
    const m = block.match(/^##\s+(.+)/);
    if (m) known.set(m[1].trim(), block.trim());
  }
  return known;
}

// Merge confirmed finding classes into the memory file (update, not duplicate).
function update(path, confirmed) {
  const known = load(path);
  const classes = new Set(confirmed.map((f) => f.class));
  for (const cls of classes) {
    const block =
      `## ${cls}\n` +
      `${SIGNATURE[cls] || "Confirmed vulnerability pattern."}\n` +
      `${LANG}\n` +
      `Why scanners miss it: ${WHY_MISSED[cls] || "Low-signal to pattern matching; needs AST/semantic context."}\n` +
      `Key signature: ${SIGNATURE[cls] || cls}`;
    known.set(cls, block);
  }
  const header =
    "# White Hat Memory\n" +
    "Confirmed vulnerability patterns. Checked first on subsequent runs.\n";
  const body = [...known.values()].join("\n\n");
  fs.writeFileSync(path, `${header}\n${body}\n`);
  return classes;
}

module.exports = { load, update };
