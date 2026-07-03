"use strict";
// tRPC router. Input arrives as the destructured `input` of a .query/.mutation
// callback on a procedure/input chain.
const { publicProcedure, router } = require("./trpc");
const { z } = require("zod");
const { db } = require("./db");

// Sink lives in a helper — taint must flow OUT of the inline resolver into it.
function runRaw(q) {
  return db.query("SELECT * FROM logs WHERE msg = '" + q + "'");
}

const appRouter = router({
  getUser: publicProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      return db.query("SELECT * FROM users WHERE id = " + input.id);
    }),
  find: publicProcedure.query(({ input }) => db.query("SELECT * FROM t WHERE x = " + input.x)),
  via: publicProcedure.query(({ input }) => runRaw(input.q)),
});

module.exports = { appRouter };
