"use strict";
// Repo walker + chunker. Groups files into logical analysis units so findings
// carry architectural context and cross-unit passes share one findings state.
const fs = require("fs");
const path = require("path");

const CODE_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "coverage", ".next",
  "out", "vendor", ".cache", "tmp", "__snapshots__",
]);

// Heuristic classifier: which logical unit a file belongs to. Cheap and
// path/name based — good enough to route findings; not load-bearing for detection.
const UNIT_RULES = [
  ["auth", /(auth|login|session|jwt|passport|oauth|token|password)/i],
  ["routing", /(route|router|controller|endpoint|api|handler|middleware)/i],
  ["database", /(model|schema|repository|dao|query|migration|entity|prisma|sequelize|mongoose)/i],
  ["crypto", /(crypt|cipher|hash|hmac|sign|secret|key)/i],
  ["integration", /(client|integration|external|webhook|gateway|provider|sdk)/i],
  ["jobs", /(job|queue|worker|cron|task|consumer|scheduler)/i],
];

function classify(relPath) {
  for (const [unit, re] of UNIT_RULES) if (re.test(relPath)) return unit;
  return "business";
}

function walk(root) {
  const files = [];
  (function rec(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) rec(full);
      } else if (CODE_EXT.has(path.extname(e.name))) {
        // skip generated / test noise from primary detection but keep tests visible
        files.push(full);
      }
    }
  })(root);
  return files;
}

// Returns { units: Map<unitName, [ {file, rel, code} ]>, all: [...] }
function chunk(root) {
  const files = walk(root);
  const units = new Map();
  const all = [];
  for (const file of files) {
    let code;
    try {
      code = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (code.length > 2_000_000) continue; // skip absurdly large/minified blobs
    const rel = path.relative(root, file);
    const unit = classify(rel);
    const entry = { file, rel, code, unit };
    all.push(entry);
    if (!units.has(unit)) units.set(unit, []);
    units.get(unit).push(entry);
  }
  return { units, all };
}

module.exports = { walk, chunk, classify };
