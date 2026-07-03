"use strict";
// Handlers whose sinks live in OTHER functions/files. Intraprocedural taint
// misses these entirely; the call graph must carry taint across the boundary.
const { runQuery } = require("./db");
const { exec } = require("child_process");

// cross-FILE: req input -> runQuery() in db.js -> SQL sink there
function getUser(req, res) {
  const id = req.query.id;
  return res.json(runQuery(id));
}

// cross-FUNCTION (same file): req input -> runShell() -> command sink there
function search(req, res) {
  runShell(req.body.term);
}
function runShell(term) {
  exec("grep " + term + " /var/log/app.log");
}

module.exports = { getUser, search };
