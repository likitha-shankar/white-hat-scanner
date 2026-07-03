import { Controller, Get, Post, Body, Param } from "@nestjs/common";
import { db } from "./db";

// NestJS: request input arrives via parameter decorators, not a `req` object.
// Intraprocedural/req-name analysis is blind to these; decorator-aware taint
// must treat the decorated params as sources.
@Controller("users")
export class UsersController {
  @Get(":id")
  find(@Param("id") id: string) {
    // SQLi via @Param
    return db.query("SELECT * FROM users WHERE id = " + id);
  }

  @Post()
  create(@Body() dto: any) {
    // SQLi via @Body (through a property access)
    return db.query("INSERT INTO users (name) VALUES ('" + dto.name + "')");
  }

  @Get("safe/:id")
  safe(@Param("id") id: string) {
    // decorated source but parameterized — must NOT be flagged
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
  }
}
