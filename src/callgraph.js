"use strict";
// Whole-program interprocedural taint. Builds a call graph across files (resolving
// import/export + same-file names), then runs a monotone worklist fixpoint:
// "a tainted call argument taints the callee's matching parameter." The result is
// a per-function taint set (WeakMap<fnNode, Set<name>>) consumed by parse.js.
//
// Deliberate ceilings (documented, not hidden):
//  - Call resolution is name + relative-import based. Bare/npm imports are opaque.
//    Ambiguous names (2+ defs, no unique target) are skipped, not guessed.
//  - Context-insensitive: if a helper is EVER called with tainted input, its
//    sinks are treated as reachable with taint (a true positive — it IS reachable).
//  - No points-to / aliasing / dynamic dispatch. Closures propagate only via the
//    nearest named-function ancestor.
const path = require("path");
const { traverse, exprIsTainted, decoratedParamNames } = require("./parse");

const FN_TYPES = new Set([
  "FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ClassMethod", "ObjectMethod",
]);
const isFn = (n) => n && FN_TYPES.has(n.type);

function paramNames(fnNode) {
  return (fnNode.params || []).map((p) => {
    if (p.type === "Identifier") return p.name;
    if (p.type === "AssignmentPattern" && p.left.type === "Identifier") return p.left.name;
    return null; // destructured / rest — cannot seed this position
  });
}

// ---- pure intra-scope taint (no Babel paths; safe to call post-traversal) ----
const SKIP_KEYS = new Set(["loc", "start", "end", "leadingComments", "trailingComments", "innerComments", "range", "extra"]);
function eachChild(node, fn) {
  for (const k in node) {
    if (SKIP_KEYS.has(k)) continue;
    const v = node[k];
    if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === "string") fn(c); }
    else if (v && typeof v.type === "string") fn(v);
  }
}
// Walk a function body without descending into nested function scopes.
function walkScope(fnNode, visit) {
  const body = fnNode.body;
  if (!body) return;
  (function rec(node) {
    eachChild(node, (c) => {
      visit(c);
      if (!isFn(c)) rec(c);
    });
  })(body);
}

function computeTaint(fnNode, seed, extra) {
  // Seed with interprocedural taint + NestJS/TypeGraphQL-decorated params +
  // structural framework sources (GraphQL args, tRPC input).
  const tainted = new Set([...seed, ...decoratedParamNames(fnNode), ...(extra || [])]);
  let changed = true;
  while (changed) {
    changed = false;
    walkScope(fnNode, (n) => {
      if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init &&
        !tainted.has(n.id.name) && exprIsTainted(n.init, tainted)) { tainted.add(n.id.name); changed = true; }
      else if (n.type === "AssignmentExpression" && n.left.type === "Identifier" &&
        !tainted.has(n.left.name) && exprIsTainted(n.right, tainted)) { tainted.add(n.left.name); changed = true; }
    });
  }
  return tainted;
}

// ---- module resolution (relative only) --------------------------------------
function resolveModule(fromAbs, source, absSet) {
  if (!source.startsWith(".")) return null;
  const base = path.resolve(path.dirname(fromAbs), source);
  const cands = [base, base + ".js", base + ".ts", base + ".jsx", base + ".tsx", base + ".mjs", base + ".cjs",
    path.join(base, "index.js"), path.join(base, "index.ts")];
  for (const c of cands) if (absSet.has(c)) return c;
  return null;
}

function build(files) {
  // Normalize to absolute so module resolution (path.resolve) matches the file
  // keys even when the scan target was a relative path. Idempotent.
  for (const f of files) f.file = path.resolve(f.file);
  const absSet = new Set(files.map((f) => f.file));
  const defsByFile = new Map();   // abs -> [{name, node, params}]
  const importsByFile = new Map(); // abs -> Map(local -> {source, imported})
  const exportsByFile = new Map(); // abs -> Map(exportName -> node)
  const nameIndex = new Map();     // name -> [node]
  const defNodeSet = new Set();
  const defMeta = new Map();       // node -> {params, file}

  const addDef = (file, name, node) => {
    if (!name || !isFn(node)) return;
    const params = paramNames(node);
    defsByFile.get(file).push({ name, node, params });
    defNodeSet.add(node);
    defMeta.set(node, { params, file });
    if (!nameIndex.has(name)) nameIndex.set(name, []);
    nameIndex.get(name).push(node);
  };

  // Pass A: defs, imports, exports.
  for (const f of files) {
    defsByFile.set(f.file, []);
    const imports = new Map();
    const exports = new Map();
    importsByFile.set(f.file, imports);
    exportsByFile.set(f.file, exports);
    const localByName = () => defsByFile.get(f.file);

    traverse(f.ast, {
      FunctionDeclaration(p) { if (p.node.id) addDef(f.file, p.node.id.name, p.node); },
      VariableDeclarator(p) { if (p.node.id.type === "Identifier" && isFn(p.node.init)) addDef(f.file, p.node.id.name, p.node.init); },
      ClassMethod(p) { if (p.node.key.type === "Identifier") addDef(f.file, p.node.key.name, p.node); },
      ObjectMethod(p) { if (p.node.key.type === "Identifier") addDef(f.file, p.node.key.name, p.node); },
      ObjectProperty(p) { if (p.node.key.type === "Identifier" && isFn(p.node.value)) addDef(f.file, p.node.key.name, p.node.value); },
      ImportDeclaration(p) {
        const src = p.node.source.value;
        for (const s of p.node.specifiers) {
          if (s.type === "ImportDefaultSpecifier") imports.set(s.local.name, { source: src, imported: "default" });
          else if (s.type === "ImportNamespaceSpecifier") imports.set(s.local.name, { source: src, imported: "*" });
          else if (s.type === "ImportSpecifier") imports.set(s.local.name, { source: src, imported: s.imported.name || s.imported.value });
        }
      },
      CallExpression(p) {
        // const x = require('./y')  /  const {a} = require('./y')
        const c = p.node.callee;
        if (c.type === "Identifier" && c.name === "require" && p.node.arguments[0] && p.node.arguments[0].type === "StringLiteral") {
          const src = p.node.arguments[0].value;
          const decl = p.parentPath && p.parentPath.node;
          if (decl && decl.type === "VariableDeclarator") {
            if (decl.id.type === "Identifier") imports.set(decl.id.name, { source: src, imported: "*" });
            else if (decl.id.type === "ObjectPattern") {
              for (const pr of decl.id.properties)
                if (pr.type === "ObjectProperty" && pr.key.type === "Identifier" && pr.value.type === "Identifier")
                  imports.set(pr.value.name, { source: src, imported: pr.key.name });
            }
          }
        }
      },
      ExportNamedDeclaration(p) {
        if (p.node.declaration && p.node.declaration.type === "FunctionDeclaration" && p.node.declaration.id)
          exports.set(p.node.declaration.id.name, p.node.declaration);
        for (const s of p.node.specifiers || []) {
          const local = s.local && s.local.name;
          const def = localByName().find((d) => d.name === local);
          if (def) exports.set((s.exported.name || s.exported.value), def.node);
        }
      },
      ExportDefaultDeclaration(p) {
        const d = p.node.declaration;
        if (isFn(d)) { exports.set("default", d); if (d.id) addDef(f.file, d.id.name, d); }
        else if (d.type === "Identifier") {
          const def = localByName().find((x) => x.name === d.name);
          if (def) exports.set("default", def.node);
        }
      },
      AssignmentExpression(p) {
        // module.exports = fn | {a,b} ; exports.x = fn ; module.exports.x = fn
        const { left, right } = p.node;
        const isME = left.type === "MemberExpression";
        const txt = isME ? memberText(left) : "";
        if (txt === "module.exports" || txt === "exports") {
          if (right.type === "Identifier") { const d = localByName().find((x) => x.name === right.name); if (d) exports.set("default", d.node); }
          else if (isFn(right)) exports.set("default", right);
          else if (right.type === "ObjectExpression") {
            for (const pr of right.properties)
              if (pr.type === "ObjectProperty" && pr.key.type === "Identifier") {
                if (pr.value.type === "Identifier") { const d = localByName().find((x) => x.name === pr.value.name); if (d) exports.set(pr.key.name, d.node); }
                else if (isFn(pr.value)) { addDef(f.file, pr.key.name, pr.value); exports.set(pr.key.name, pr.value); }
              }
          }
        } else if (txt.startsWith("exports.") || txt.startsWith("module.exports.")) {
          const name = txt.split(".").pop();
          if (right.type === "Identifier") { const d = localByName().find((x) => x.name === right.name); if (d) exports.set(name, d.node); }
          else if (isFn(right)) { addDef(f.file, name, right); exports.set(name, right); }
        }
      },
    });
  }

  // Pass B: structural framework sources (GraphQL resolver args, tRPC input).
  // Keyed by function node -> Set of parameter/binding names that are untrusted.
  // Built before call collection so inline resolvers count as taint propagators.
  const fwSources = new Map();
  const addFw = (fnNode, names) => {
    if (!fnNode || !names.length) return;
    if (!fwSources.has(fnNode)) fwSources.set(fnNode, new Set());
    for (const n of names) fwSources.get(fnNode).add(n);
  };
  for (const f of files) {
    traverse(f.ast, {
      // GraphQL: resolver field under a Query/Mutation/Subscription map.
      "ObjectProperty|ObjectMethod"(p) {
        const key = p.node.key;
        const kn = key && (key.name || key.value);
        if (!/^(Query|Mutation|Subscription)$/.test(kn || "")) return;
        const map = p.node.type === "ObjectMethod" ? null : p.node.value;
        if (!map || map.type !== "ObjectExpression") return;
        for (const field of map.properties) {
          const fn = field.type === "ObjectMethod" ? field
            : field.type === "ObjectProperty" && isFn(field.value) ? field.value : null;
          if (fn) addFw(fn, argNames(fn.params[1])); // 2nd positional param = args
        }
      },
      // tRPC: .query/.mutation/.subscription callback on an input/procedure chain.
      CallExpression(p) {
        const c = p.node.callee;
        if (c.type !== "MemberExpression" || c.property.type !== "Identifier") return;
        if (!/^(query|mutation|subscription)$/.test(c.property.name)) return;
        if (!isTrpcChain(c.object)) return;
        const fn = p.node.arguments[p.node.arguments.length - 1];
        if (fn && isFn(fn)) addFw(fn, trpcInputNames(fn.params[0]));
      },
    });
  }

  // A function is a taint-carrying graph node if it is a named def OR a framework
  // source (inline resolver). Calls are attributed to the nearest such ancestor.
  const isCarrier = (node) => defNodeSet.has(node) || fwSources.has(node);

  // Pass C: call sites, attributed to nearest carrier function.
  const calls = []; // {file, callerNode, callee:{kind,...}, args}
  for (const f of files) {
    traverse(f.ast, {
      CallExpression(p) {
        const c = p.node.callee;
        let callee = null;
        if (c.type === "Identifier") callee = { kind: "id", name: c.name };
        else if (c.type === "MemberExpression" && c.property.type === "Identifier")
          callee = { kind: "member", obj: c.object.type === "Identifier" ? c.object.name : null, prop: c.property.name };
        if (!callee) return;
        let a = p.getFunctionParent();
        while (a && !isCarrier(a.node)) a = a.getFunctionParent();
        calls.push({ file: f.file, callerNode: a ? a.node : null, callee, args: p.node.arguments });
      },
    });
  }

  // Resolve each call to a callee def node (or null).
  const resolveExport = (fromAbs, source, exportName) => {
    const target = resolveModule(fromAbs, source, absSet);
    if (!target) return null;
    const em = exportsByFile.get(target);
    if (!em) return null;
    return em.get(exportName) || em.get("default") || null;
  };
  const resolve = (file, callee) => {
    const imports = importsByFile.get(file);
    if (callee.kind === "id") {
      const imp = imports.get(callee.name);
      if (imp) return resolveExport(file, imp.source, imp.imported === "*" ? "default" : imp.imported);
      const local = (defsByFile.get(file) || []).filter((d) => d.name === callee.name);
      if (local.length === 1) return local[0].node;
      const g = nameIndex.get(callee.name);
      if (g && g.length === 1) return g[0].node;
      return null;
    }
    // member call
    if (callee.obj) {
      const imp = imports.get(callee.obj);
      if (imp) return resolveExport(file, imp.source, callee.prop);
    }
    const same = (defsByFile.get(file) || []).filter((d) => d.name === callee.prop);
    if (same.length === 1) return same[0].node;
    const g = nameIndex.get(callee.prop);
    if (g && g.length === 1) return g[0].node;
    return null;
  };

  const callsByCaller = new Map(); // callerNode -> [{resolved, args}]
  for (const call of calls) {
    if (!call.callerNode) continue;
    call.resolved = resolve(call.file, call.callee);
    if (!callsByCaller.has(call.callerNode)) callsByCaller.set(call.callerNode, []);
    callsByCaller.get(call.callerNode).push(call);
  }

  // Fixpoint: propagate taint through parameters. Callers include both named defs
  // and framework-source functions (so inline resolvers taint their helpers).
  const seeds = new Map(); // defNode -> Set<paramName>
  const seedOf = (n) => seeds.get(n) || new Set();
  const worklist = [...new Set([...defNodeSet, ...fwSources.keys()])];
  const queued = new Set(worklist);
  let guard = 0;
  while (worklist.length && guard++ < 100000) {
    const fn = worklist.shift();
    queued.delete(fn);
    const t = computeTaint(fn, seedOf(fn), fwSources.get(fn));
    for (const call of callsByCaller.get(fn) || []) {
      const g = call.resolved;
      if (!g) continue;
      const gp = (defMeta.get(g) || {}).params || [];
      call.args.forEach((arg, i) => {
        if (i < gp.length && gp[i] && exprIsTainted(arg, t)) {
          const s = seeds.get(g) || new Set();
          if (!s.has(gp[i])) {
            s.add(gp[i]); seeds.set(g, s);
            if (!queued.has(g)) { worklist.push(g); queued.add(g); }
          }
        }
      });
    }
  }

  // Final per-function taint. Include framework-source functions even when they
  // are anonymous (inline tRPC/GraphQL resolvers aren't named defs) so detectors
  // reading getFunctionParent() get the enriched set.
  const out = new WeakMap();
  const allFns = new Set([...defNodeSet, ...fwSources.keys()]);
  for (const fn of allFns) out.set(fn, computeTaint(fn, seedOf(fn), fwSources.get(fn)));
  return out;
}

// 2nd positional resolver arg: `args` identifier or a destructured pattern.
function argNames(param) {
  if (!param) return [];
  if (param.type === "Identifier") return [param.name];
  if (param.type === "AssignmentPattern" && param.left.type === "Identifier") return [param.left.name];
  if (param.type === "ObjectPattern") return destructuredNames(param);
  return [];
}

// tRPC resolver param `{ input, ctx }` -> the `input`/`rawInput` bindings.
function trpcInputNames(param) {
  if (!param || param.type !== "ObjectPattern") return [];
  const out = [];
  for (const pr of param.properties) {
    if (pr.type === "ObjectProperty" && pr.key.type === "Identifier" &&
      (pr.key.name === "input" || pr.key.name === "rawInput") && pr.value.type === "Identifier")
      out.push(pr.value.name);
  }
  return out;
}

function destructuredNames(pattern) {
  const out = [];
  for (const pr of pattern.properties || []) {
    if (pr.type === "ObjectProperty" && pr.value.type === "Identifier") out.push(pr.value.name);
    else if (pr.type === "RestElement" && pr.argument.type === "Identifier") out.push(pr.argument.name);
  }
  return out;
}

// A member chain qualifies as tRPC when it contains a `.input(...)` call or a
// `*procedure` receiver — precise enough to avoid flagging Mongoose `.query()`.
function isTrpcChain(node) {
  let n = node;
  while (n) {
    if (n.type === "CallExpression" && n.callee.type === "MemberExpression" &&
      n.callee.property.type === "Identifier" && n.callee.property.name === "input") return true;
    if (n.type === "Identifier" && /procedure$/i.test(n.name)) return true;
    if (n.type === "CallExpression") n = n.callee;
    else if (n.type === "MemberExpression") n = n.object;
    else break;
  }
  return false;
}

function memberText(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && node.property.type === "Identifier")
    return memberText(node.object) + "." + node.property.name;
  return "";
}

module.exports = { build };
