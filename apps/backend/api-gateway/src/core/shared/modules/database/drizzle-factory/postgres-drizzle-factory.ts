import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import type { DrizzleFactory } from "./drizzle-factory";

export class PostgresDrizzleFactory implements DrizzleFactory {
  constructor(readonly databaseUrlResolver: () => string) {}

  public createDrizzle<TSchema extends Record<string, unknown>>(schema: TSchema) {
    const client = postgres(this.databaseUrlResolver());
    return drizzle({ client, casing: "snake_case", schema });
  }
}
