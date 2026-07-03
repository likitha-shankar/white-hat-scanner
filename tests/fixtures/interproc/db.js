"use strict";
// The SQL sink is here, one file away from the request source in routes.js.
const db = require("./conn");

function runQuery(userId) {
  return db.query("SELECT * FROM users WHERE id = " + userId);
}

module.exports = { runQuery };
