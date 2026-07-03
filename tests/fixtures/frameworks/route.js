"use strict";
// Next.js App Router handler. Input arrives via `await request.json()` and
// `request.nextUrl.searchParams.get(...)` — call-based sources, not req.body.
const { db } = require("./db");

async function POST(request) {
  const body = await request.json();
  // SQLi via awaited request.json()
  return db.query("SELECT * FROM t WHERE x = '" + body.x + "'");
}

async function GET(request) {
  const q = request.nextUrl.searchParams.get("q");
  // SQLi via searchParams.get()
  return db.query("SELECT * FROM t WHERE name LIKE '" + q + "'");
}

module.exports = { POST, GET };
