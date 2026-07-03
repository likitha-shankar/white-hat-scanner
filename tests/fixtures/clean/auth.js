"use strict";
// Safe JWT usage — algorithm pinned, expiry set, secret from env, verify (not decode).
const jwt = require("jsonwebtoken");

function issue(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "15m", algorithm: "HS256" });
}

function check(req, res, next) {
  const claims = jwt.verify(req.headers.token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
  req.user = claims;
  next();
}

module.exports = { issue, check };
