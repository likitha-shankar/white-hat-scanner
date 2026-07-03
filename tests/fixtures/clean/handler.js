"use strict";
// Clean fixture — should produce zero confirmed findings and positive observations.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const { execFile } = require("child_process");
const db = require("./db");
const Order = require("./order");

async function getUser(req, res) {
  const id = req.query.id;
  // Parameterized query
  const rows = await db.query("SELECT * FROM users WHERE id = ?", [id]);

  // No shell interpolation
  execFile("ls", ["-la", "/var/data"], (e, out) => res.send(out));

  // Slow KDF for passwords
  const pwHash = await bcrypt.hash(req.body.password, 12);

  // CSPRNG token
  const token = crypto.randomBytes(32).toString("hex");

  // Constant-time comparison
  const a = Buffer.from(req.headers["x-sig"] || "");
  const b = Buffer.from(rows[0].storedSignature || "");
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);

  res.json({ ok, pwHash, token });
}

// Safe file serving: confined to a base dir, basename-stripped.
function download(req, res) {
  const base = path.resolve("uploads");
  const target = path.resolve(base, path.basename(req.query.file || ""));
  if (!target.startsWith(base + path.sep)) return res.status(400).end();
  fs.readFile(target, (e, buf) => res.send(buf));
}

// Owner-scoped lookup: id constrained to the authenticated user.
function getOrder(req, res) {
  const order = Order.findOne({ _id: req.params.id, ownerId: req.user.id });
  res.json(order);
}

module.exports = { getUser, download, getOrder };
