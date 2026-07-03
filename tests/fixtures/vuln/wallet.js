"use strict";
// Vulnerable check-then-act fixture (TOCTOU).
const Wallet = require("./wallet-model");

async function withdraw(req, res) {
  const w = await Wallet.findOne({ userId: req.user.id });
  if (w.balance >= req.body.amount) {
    w.balance -= req.body.amount;
    await w.save(); // no transaction/lock — two concurrent requests both pass the check
  }
  res.json({ ok: true, balance: w.balance });
}

module.exports = { withdraw };
