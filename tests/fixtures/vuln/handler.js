"use strict";
// Intentionally vulnerable fixture — exercises every detector. Not real code.
const crypto = require("crypto");
const fs = require("fs");
const { exec } = require("child_process");
const db = require("./db");
const Order = require("./order");

const stripeKey = "sk_live_ABCDEFGHIJKLMNOP1234567"; // secret: provider format
const awsKey = "AKIAIOSFODNN7EXAMPLE"; // secret: AWS format

async function getUser(req, res) {
  const id = req.query.id;
  // SQL injection: tainted id interpolated into query
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);

  // Command injection: tainted dir reaches shell sink
  exec(`ls -la ${req.body.dir}`, (e, out) => res.send(out));

  // Weak hash for password
  const pwHash = crypto.createHash("md5").update(req.body.password).digest("hex");

  // Insecure randomness for a security token
  const token = Math.random().toString(36).slice(2);

  // Non-constant-time secret comparison
  const signature = req.headers["x-sig"];
  if (signature === rows[0].storedSignature) {
    res.json({ ok: true, pwHash, token });
  }
}

// Path traversal: tainted filename concatenated into an fs read.
function download(req, res) {
  const name = req.query.file;
  fs.readFile("/var/data/" + name, (e, buf) => res.send(buf));
}

// BOLA: client-supplied id fetched with no authenticated-user check.
function getOrder(req, res) {
  const order = Order.findById(req.params.id);
  res.json(order);
}

module.exports = { getUser, download, getOrder, stripeKey, awsKey };
