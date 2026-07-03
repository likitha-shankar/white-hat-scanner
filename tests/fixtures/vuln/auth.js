"use strict";
// Vulnerable JWT usage fixture.
const jwt = require("jsonwebtoken");

function issue(user) {
  // no expiry + hardcoded secret
  return jwt.sign({ id: user.id, role: user.role }, "hardcoded-jwt-secret");
}

function check(req, res, next) {
  // no algorithms allowlist -> alg-confusion / none
  const claims = jwt.verify(req.headers.token, process.env.KEY);
  req.user = claims;
  next();
}

function peek(token) {
  // decode does not verify signature
  return jwt.decode(token);
}

module.exports = { issue, check, peek };
