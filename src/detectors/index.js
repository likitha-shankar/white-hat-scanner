"use strict";
// Detector registry. Add a module here and it joins every scan.
const detectors = [
  require("./secrets"),
  require("./sqli"),
  require("./commandInjection"),
  require("./pathTraversal"),
  require("./authz"),
  require("./jwt"),
  require("./raceCondition"),
  require("./weakCrypto"),
  require("./timingSafe"),
];

// Positive observations: patterns worth keeping / replicating elsewhere.
// Cheap source-text signals — not exhaustive, just credit where due.
const GOOD = [
  ["Parameterized queries", /\.(query|execute)\s*\([^)]*\?[^)]*,\s*\[/],
  ["Password hashing with bcrypt/argon2/scrypt", /\b(bcrypt|argon2|scrypt)\b/],
  ["Constant-time comparison", /timingSafeEqual/],
  ["CSPRNG for tokens", /crypto\.randomBytes/],
  ["Security headers via helmet", /\bhelmet\s*\(/],
  ["Input validation library", /\b(zod|joi|yup|express-validator|class-validator)\b/],
  ["Parameterized ORM (no raw)", /\b(prisma|knex)\b/],
];

function positives(all) {
  const seen = new Map(); // label -> example location
  for (const f of all) {
    for (const [label, re] of GOOD) {
      if (seen.has(label)) continue;
      if (re.test(f.code)) seen.set(label, f.rel);
    }
  }
  return [...seen].map(([label, rel]) => ({ label, rel }));
}

module.exports = { detectors, positives };
