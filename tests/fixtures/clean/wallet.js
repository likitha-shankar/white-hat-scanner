"use strict";
// Safe check-then-act — wrapped in a transaction with a row lock.
const db = require("./db");
const Wallet = require("./wallet-model");

async function withdraw(req, res) {
  await db.transaction(async (tx) => {
    const w = await Wallet.findOne({ userId: req.user.id }, { transaction: tx, lock: tx.LOCK.UPDATE });
    if (w.balance >= req.body.amount) {
      await w.decrement("balance", { by: req.body.amount, transaction: tx });
    }
  });
  res.json({ ok: true });
}

module.exports = { withdraw };
