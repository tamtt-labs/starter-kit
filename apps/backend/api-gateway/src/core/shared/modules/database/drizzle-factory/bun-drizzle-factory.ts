import { drizzle } from "drizzle-orm/bun-sql";
import type { DrizzleFactory } from "./drizzle-factory";

export class BunDrizzleFactory implements DrizzleFactory {
  constructor(readonly databaseUrlResolver: () => string) {}

  public createDrizzle<TSchema extends Record<string, unknown>>(schema: TSchema) {
    const client = new Bun.SQL({ url: this.databaseUrlResolver(), adapter: "postgres" });
    return drizzle({ client, casing: "snake_case", schema });
  }
}
