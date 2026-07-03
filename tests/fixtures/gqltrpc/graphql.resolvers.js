"use strict";
// Vanilla GraphQL resolver map. The 2nd positional arg (args) is user input.
const { db } = require("./db");

const resolvers = {
  Query: {
    user: (parent, args, ctx) => db.query("SELECT * FROM users WHERE id = " + args.id),
    search: (_, { term }) => db.query("SELECT * FROM t WHERE name LIKE '" + term + "'"),
  },
  Mutation: {
    del: (root, args) => db.query("DELETE FROM t WHERE id = " + args.id),
  },
};

module.exports = { resolvers };
