"use strict";
// Babel-based AST layer. Kept behind this module so the parser is swappable
// (tree-sitter for polyglot later) without touching detectors.
const parser = require("@babel/parser");
const _traverse = require("@babel/traverse").default;

const PLUGINS = [
  "typescript",
  "jsx",
  "classProperties",
  "decorators-legacy",
  "optionalChaining",
  "nullishCoalescingOperator",
  "topLevelAwait",
];

// Parse as ESM, fall back to script for CommonJS-only edge cases.
function parseCode(code) {
  try {
    return parser.parse(code, { sourceType: "module", errorRecovery: true, plugins: PLUGINS });
  } catch (_) {
    return parser.parse(code, { sourceType: "script", errorRecovery: true, plugins: PLUGINS });
  }
}

function traverse(ast, visitor) {
  _traverse(ast, visitor);
}

// Source text of a node (for evidence + before/after diffs).
function snippet(code, node) {
  if (node.start == null || node.end == null) return "";
  return code.slice(node.start, node.end);
}

function loc(node) {
  const l = node.loc && node.loc.start;
  return l ? { line: l.line, column: l.column + 1 } : { line: 0, column: 0 };
}

// Full physical line(s) covering a node — the "before" block for a diff.
function lineSpan(code, node) {
  const lines = code.split("\n");
  const start = (node.loc && node.loc.start.line) || 1;
  const end = (node.loc && node.loc.end.line) || start;
  return { text: lines.slice(start - 1, end).join("\n"), startLine: start, endLine: end };
}

// ---- taint sources ----------------------------------------------------------
// External input recognized as a taint source across frameworks:
//  - member access on a request object: req/request/ctx.query/.body/.params/…
//    (Express, Koa, Fastify, Next.js pages API)
//  - request body-parsing calls: request.json()/.text()/.formData(), and
//    searchParams.get()/getAll() (Next.js App Router / Web Request)
//  - parameters carrying a NestJS input decorator: @Body/@Param/@Query/@Headers/…
const REQ_NAMES = new Set(["req", "request", "ctx", "context", "event"]);
const REQ_PROPS = new Set([
  "query", "body", "params", "headers", "cookies", "url", "searchParams", "nextUrl",
]);
// NestJS + TypeGraphQL parameter decorators that bind untrusted input.
const INPUT_DECORATORS = new Set([
  "Body", "Param", "Query", "Headers", "Req", "Request", "Ip", "Session",
  "UploadedFile", "UploadedFiles", "RawBody", "HostParam", "Cookies", "Cookie",
  "Arg", "Args", // TypeGraphQL resolver argument decorators
]);
// Request methods whose return value is untrusted input.
const REQ_BODY_CALLS = new Set(["json", "text", "formData", "arrayBuffer", "blob"]);

function baseObject(node) {
  let obj = node;
  while (obj && obj.type === "MemberExpression") obj = obj.object;
  return obj;
}

function isRequestMember(node) {
  if (!node || node.type !== "MemberExpression") return false;
  const obj = baseObject(node);
  if (obj && obj.type === "Identifier" && REQ_NAMES.has(obj.name)) {
    // require a known request property somewhere in the chain
    let n = node;
    while (n && n.type === "MemberExpression") {
      if (n.property && n.property.type === "Identifier" && REQ_PROPS.has(n.property.name)) return true;
      n = n.object;
    }
  }
  return false;
}

// request.json() / .text() / .formData(), and searchParams.get()/getAll().
function isRequestSourceCall(node) {
  if (node.type !== "CallExpression") return false;
  const c = node.callee;
  if (!c || c.type !== "MemberExpression" || c.property.type !== "Identifier") return false;
  const prop = c.property.name;
  const base = baseObject(c);
  const reqBase = base && base.type === "Identifier" && REQ_NAMES.has(base.name);
  if (REQ_BODY_CALLS.has(prop) && reqBase) return true;
  if ((prop === "get" || prop === "getAll") && isRequestMember(c.object)) return true; // params.get('x')
  return false;
}

// Parameter names carrying a NestJS input decorator -> taint sources.
function decoratedParamNames(fnNode) {
  const out = [];
  for (const p of fnNode.params || []) {
    const decos = p.decorators || (p.type === "TSParameterProperty" && p.parameter && p.parameter.decorators) || [];
    if (!decos || !decos.length) continue;
    const hit = decos.some((d) => {
      const e = d.expression;
      if (!e) return false;
      if (e.type === "Identifier") return INPUT_DECORATORS.has(e.name);
      if (e.type === "CallExpression" && e.callee.type === "Identifier") return INPUT_DECORATORS.has(e.callee.name);
      return false;
    });
    if (!hit) continue;
    const id = p.type === "Identifier" ? p : p.type === "AssignmentPattern" ? p.left
      : p.type === "TSParameterProperty" ? p.parameter : null;
    if (id && id.type === "Identifier") out.push(id.name);
  }
  return out;
}

// When a whole-program interprocedural pass has run, it publishes a taint set
// per function node here; detectors reading taintedNames() transparently get the
// enriched (cross-function/cross-file) set instead of the local-only one.
let GLOBAL_TAINT = null;
function setGlobalTaint(map) { GLOBAL_TAINT = map; }

// Collect names bound to tainted values inside one function body.
// Seed ONLY from request sources (req.*/ctx.* via isRequestMember), never from
// bare parameters — a library/CLI function param is not an external trust
// boundary, and treating it as one flags every fs/db call in normal code.
function taintedNames(fnPath) {
  if (GLOBAL_TAINT && GLOBAL_TAINT.has(fnPath.node)) return GLOBAL_TAINT.get(fnPath.node);
  const tainted = new Set(decoratedParamNames(fnPath.node));
  fnPath.traverse({
    VariableDeclarator(p) {
      const id = p.node.id;
      if (id.type === "Identifier" && exprIsTainted(p.node.init, tainted)) tainted.add(id.name);
    },
    AssignmentExpression(p) {
      const l = p.node.left;
      if (l.type === "Identifier" && exprIsTainted(p.node.right, tainted)) tainted.add(l.name);
    },
  });
  return tainted;
}

// Does an expression carry tainted data given the current tainted name set?
function exprIsTainted(node, tainted) {
  if (!node) return false;
  switch (node.type) {
    case "Identifier":
      return tainted.has(node.name);
    case "MemberExpression":
      if (isRequestMember(node)) return true;
      return exprIsTainted(node.object, tainted);
    case "BinaryExpression":
      return exprIsTainted(node.left, tainted) || exprIsTainted(node.right, tainted);
    case "TemplateLiteral":
      return node.expressions.some((e) => exprIsTainted(e, tainted));
    case "AwaitExpression":
      return exprIsTainted(node.argument, tainted); // await request.json()
    case "CallExpression":
      if (isRequestSourceCall(node)) return true;
      return node.arguments.some((a) => exprIsTainted(a, tainted));
    default:
      return false;
  }
}

module.exports = {
  parseCode,
  traverse,
  snippet,
  loc,
  lineSpan,
  isRequestMember,
  isRequestSourceCall,
  decoratedParamNames,
  taintedNames,
  exprIsTainted,
  setGlobalTaint,
};
