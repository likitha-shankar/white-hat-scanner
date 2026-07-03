#!/usr/bin/env node
"use strict";
// White Hat — Mode 2 white-box static analysis engine.
// Usage: white-hat <path> [--report out.md] [--memory white_hat_memory.md] [--json]
const fs = require("fs");
const path = require("path");
const { chunk } = require("./walk");
const parse = require("./parse");
const { detectors, positives } = require("./detectors");
const { prove } = require("./prove");
const report = require("./report");
const memory = require("./memory");
const callgraph = require("./callgraph");
const { scanUrl } = require("./mode1/scan");

function parseArgs(argv) {
  const args = { target: null, url: null, report: null, memory: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--report") args.report = argv[++i];
    else if (a === "--memory") args.memory = argv[++i];
    else if (a === "--url") args.url = argv[++i];
    else if (a === "--json") args.json = true;
    else if (!a.startsWith("-")) args.target = a;
  }
  // bare http(s):// argument is treated as a URL scan
  if (!args.url && args.target && /^https?:\/\//i.test(args.target)) {
    args.url = args.target;
    args.target = null;
  }
  args.target = args.target || process.cwd();
  args.memory = args.memory || path.join(args.target, "white_hat_memory.md");
  return args;
}

function analyze(target, memPath) {
  const { units, all } = chunk(target);
  const known = memory.load(memPath);
  const raw = [];

  // Pass 1: parse everything (detectors + the call graph share these ASTs).
  const parsed = [];
  for (const file of all) {
    try {
      file.ast = parse.parseCode(file.code);
      parsed.push(file);
    } catch {
      /* unparseable file — skip, don't crash the run */
    }
  }

  // Interprocedural taint: build the whole-program call graph, then hand the
  // per-function taint sets to the detectors via parse's global override.
  let taint = null;
  try {
    taint = callgraph.build(parsed);
  } catch (e) {
    process.stderr.write(`callgraph failed (falling back to intraprocedural): ${e.message}\n`);
  }
  parse.setGlobalTaint(taint);

  // Pass 2: run detectors with the enriched taint in effect.
  for (const file of parsed) {
    for (const det of detectors) {
      let hits = [];
      try {
        hits = det.scan(file, file.ast, parse) || [];
      } catch (e) {
        process.stderr.write(`detector ${det.id} failed on ${file.rel}: ${e.message}\n`);
      }
      for (const h of hits) {
        h.known = known.has(h.class);
        raw.push(h);
      }
    }
  }
  parse.setGlobalTaint(null);

  const proven = raw.map(prove);
  const confirmed = proven.filter((f) => f.section === "confirmed");
  const unconfirmed = proven.filter((f) => f.section === "unconfirmed");
  const knownClasses = memory.update(memPath, confirmed);

  return {
    confirmed,
    unconfirmed,
    positives: positives(all),
    knownClasses,
    stats: { files: all.length, units: units.size },
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  let result;
  if (args.url) {
    result = await scanUrl(args.url);
    if (result.error) {
      process.stderr.write(result.error + "\n");
      process.exit(2);
    }
  } else {
    if (!fs.existsSync(args.target)) {
      process.stderr.write(`path not found: ${args.target}\n`);
      process.exit(2);
    }
    result = analyze(args.target, args.memory);
  }

  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    return;
  }
  const md = report.render(result);
  if (args.report) {
    fs.writeFileSync(args.report, md);
    process.stdout.write(`Report written to ${args.report}\n`);
  } else {
    process.stdout.write(md);
  }
  // non-zero exit if any confirmed critical/high — useful in CI
  const gate = result.confirmed.some((f) => f.severity === "Critical" || f.severity === "High");
  process.exit(gate ? 1 : 0);
}

if (require.main === module) main();
module.exports = { analyze, parseArgs, scanUrl };
