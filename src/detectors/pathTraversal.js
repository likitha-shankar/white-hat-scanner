"use strict";
// Path traversal: tainted input reaches a filesystem/file-serving sink as (part
// of) the path. `../` sequences escape the intended directory. Confirmed when
// the path argument provably carries tainted data in the enclosing function.
const { loc, lineSpan, taintedNames, exprIsTainted, isRequestMember } = require("../parse");

// method name -> index of the path argument
const FS_SINKS = new Map([
  ["readFile", 0], ["readFileSync", 0], ["writeFile", 0], ["writeFileSync", 0],
  ["appendFile", 0], ["appendFileSync", 0], ["createReadStream", 0], ["createWriteStream", 0],
  ["unlink", 0], ["unlinkSync", 0], ["readdir", 0], ["readdirSync", 0],
  ["open", 0], ["openSync", 0], ["stat", 0], ["statSync", 0], ["rm", 0], ["rmSync", 0],
]);
// response file-serving sinks
const RES_SINKS = new Map([["sendFile", 0], ["download", 0]]);

function sinkInfo(callee) {
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
    const name = callee.property.name;
    const objName = callee.object.type === "Identifier" ? callee.object.name : "";
    if (FS_SINKS.has(name)) return { arg: FS_SINKS.get(name), name };
    // res.sendFile / res.download — require a response-ish receiver
    if (RES_SINKS.has(name) && /^(res|response|reply)$/.test(objName)) return { arg: RES_SINKS.get(name), name };
    return null;
  }
  if (callee.type === "Identifier" && FS_SINKS.has(callee.name)) return { arg: FS_SINKS.get(callee.name), name: callee.name };
  return null;
}

// Dynamically-constructed path: concatenation, interpolation, or path.join/resolve.
function isBuilt(node) {
  if (!node) return false;
  if (node.type === "BinaryExpression" && node.operator === "+") return true;
  if (node.type === "TemplateLiteral" && node.expressions.length) return true;
  if (node.type === "CallExpression") {
    const c = node.callee;
    const nm = c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : (c.name || "");
    return nm === "join" || nm === "resolve";
  }
  return false;
}

function scan(unitFile, ast, h) {
  const findings = [];
  const taintCache = new WeakMap();

  h.traverse(ast, {
    CallExpression(path) {
      const info = sinkInfo(path.node.callee);
      if (!info) return;
      const arg = path.node.arguments[info.arg];
      if (!arg) return;
      // a plain string literal path is not attacker-controlled
      if (arg.type === "StringLiteral") return;

      const fnPath = path.getFunctionParent();
      let tainted = new Set();
      if (fnPath) {
        if (!taintCache.has(fnPath.node)) taintCache.set(fnPath.node, taintedNames(fnPath));
        tainted = taintCache.get(fnPath.node);
      }
      const confirmed = exprIsTainted(arg, tainted) || isRequestMember(arg);
      // Untainted bare identifiers (e.g. a guarded, normalized path) are too
      // noisy to flag. Report only if tainted, or if the path is dynamically
      // built (concat / template / path.join|resolve) and worth a manual look.
      if (!confirmed && !isBuilt(arg)) return;
      findings.push(build(unitFile, path.node, info.name, confirmed));
    },
  });
  return findings;
}

function build(unitFile, node, sink, confirmed) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "pathTraversal",
    class: "Path Traversal",
    severity: "High",
    confirmedOverride: confirmed,
    unit, rel, ...loc(node),
    summary: `Tainted input used as a path in ${sink}()`,
    attackerImpact:
      "An attacker supplies `../../etc/passwd` (or an absolute path) to read or write files outside the intended directory — leaking secrets/config or overwriting code.",
    evidence: `${rel}:${loc(node).line} — tainted value reaches ${sink}() as a path`,
    remediation: {
      before: span.text,
      after:
        "// Confine to a base dir and reject traversal:\n" +
        "const base = path.resolve('uploads');\n" +
        "const target = path.resolve(base, path.basename(userPath));\n" +
        "if (!target.startsWith(base + path.sep)) throw new Error('invalid path');",
      contract:
        "path.basename strips directory components; the resolve+prefix check rejects escapes. Legitimate in-directory filenames resolve to the same file; only paths escaping the base are refused. No complexity change.",
    },
    proof: {
      kind: "repro",
      steps: [
        "Supply the tainted path value as `../../../../etc/passwd` (or an absolute path).",
        `The value reaches ${sink}() at ${rel}:${loc(node).line} without normalization or a base-dir check.`,
        "Observe a file outside the intended directory is read/written/served.",
      ],
    },
  };
}

module.exports = { id: "pathTraversal", scan };
