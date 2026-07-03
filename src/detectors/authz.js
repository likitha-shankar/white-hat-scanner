"use strict";
// Broken Object-Level Authorization (BOLA/IDOR): a handler fetches or mutates an
// object using a client-supplied resource id, with no reference to the
// authenticated user anywhere in the handler — so any user can access any id.
//
// Inherently architectural: reported Unconfirmed with a reproduction path. The
// heuristic is deliberately loose on the flaw side and conservative on the
// suppression side (any owner/session reference in the handler clears it).
const { loc, lineSpan, taintedNames, exprIsTainted } = require("../parse");

// Object-level data-access sinks (fetch/update/delete by id). `query` is left to
// the SQLi detector — this is about object lookups.
// ORM finder/mutator family. Kept specific — bare update/get/delete/save collide
// with crypto streams, Maps, and Promises, so they're excluded.
const OBJ_SINKS = new Set([
  "findById", "findByPk", "findOne", "findUnique", "findByIdAndUpdate", "findByIdAndDelete",
  "findOneAndUpdate", "findOneAndDelete", "updateOne", "deleteOne", "destroy",
]);

// Authenticated-identity signals. Presence anywhere in the handler => assume the
// ownership check exists; suppress the finding (conservative, low false positive).
const OWNER_REQ_PROP = new Set(["user", "session", "auth", "account", "principal", "currentuser", "identity", "jwt"]);
const OWNER_NAME = /^(user_?id|owner_?id|current_?user_?id|auth_?user_?id|account_?id)$/i;

function sinkName(callee) {
  if (callee.type === "MemberExpression" && callee.property.type === "Identifier") return callee.property.name;
  if (callee.type === "Identifier") return callee.name;
  return null;
}

function isFunctionNode(node) {
  return /Function|ClassMethod|ObjectMethod/.test(node.type);
}

function scan(unitFile, ast, h) {
  const findings = [];

  h.traverse(ast, {
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ClassMethod|ObjectMethod"(fnPath) {
      // only analyze request handlers — a param named like req/request/ctx
      const params = fnPath.node.params || [];
      const isHandler = params.some(
        (p) => p.type === "Identifier" && /^(req|request|ctx|context)$/i.test(p.name)
      );
      if (!isHandler) return;

      const tainted = taintedNames(fnPath);
      let hasOwnerRef = false;
      const sinks = [];

      fnPath.traverse({
        MemberExpression(p) {
          const obj = p.node.object, prop = p.node.property;
          if (
            obj.type === "Identifier" && /^(req|request|ctx|context)$/i.test(obj.name) &&
            prop.type === "Identifier" && OWNER_REQ_PROP.has(prop.name.toLowerCase())
          ) hasOwnerRef = true;
        },
        Identifier(p) {
          if (OWNER_NAME.test(p.node.name)) hasOwnerRef = true;
        },
        CallExpression(p) {
          const name = sinkName(p.node.callee);
          if (!name || !OBJ_SINKS.has(name)) return;
          const usesClientId = p.node.arguments.some((a) => exprIsTainted(a, tainted));
          if (usesClientId) sinks.push(p.node);
        },
      });

      if (hasOwnerRef || !sinks.length) return;
      for (const node of sinks) findings.push(build(unitFile, node, sinkName(node.callee)));
    },
  });
  return findings;
}

function build(unitFile, node, sink) {
  const { code, rel, unit } = unitFile;
  const span = lineSpan(code, node);
  return {
    detectorId: "authz",
    class: "Broken Object-Level Authorization",
    severity: "High",
    confirmedOverride: false, // architectural — verify the ownership check manually
    unit, rel, ...loc(node),
    summary: `${sink}() uses a client-supplied id with no authenticated-user check in the handler`,
    attackerImpact:
      "An authenticated attacker changes the id in the request to any value and reads or modifies another user's object (IDOR) — enumerate ids to dump or tamper with all records.",
    evidence: `${rel}:${loc(node).line} — ${sink}() on a client-controlled id; no req.user/session reference in this handler`,
    remediation: {
      before: span.text,
      after:
        "// Scope the lookup to the authenticated owner:\n" +
        "const obj = await Model.findOne({ _id: req.params.id, ownerId: req.user.id });\n" +
        "if (!obj) return res.status(404).end(); // hide existence from non-owners",
      contract:
        "Adding the owner predicate returns the same object for the legitimate owner and null for everyone else. Output contract unchanged for authorized access; complexity unchanged (same indexed lookup). Only cross-user access is removed.",
    },
    proof: {
      kind: "repro",
      steps: [
        "Authenticate as user A and note a request that returns A's object by id.",
        `Replay it changing the id to an object owned by user B (reaches ${sink}() at ${rel}:${loc(node).line}).`,
        "Observe B's object is returned/modified — the handler never checks the requester owns the id.",
      ],
    },
  };
}

module.exports = { id: "authz", scan };
