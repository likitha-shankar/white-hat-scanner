import { Resolver, Query, Arg } from "type-graphql";
import { db } from "./db";

// TypeGraphQL: input via @Arg decorator (handled by decorator-aware sources).
@Resolver()
export class UserResolver {
  @Query()
  user(@Arg("id") id: string) {
    return db.query("SELECT * FROM users WHERE id = " + id);
  }

  @Query()
  safe(@Arg("id") id: string) {
    return db.query("SELECT * FROM users WHERE id = ?", [id]); // parameterized — no FP
  }
}
