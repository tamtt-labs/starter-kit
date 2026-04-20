import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";

export abstract class DrizzleFactory {
  abstract databaseUrlResolver(): string;
  abstract createDrizzle<TSchema extends Record<string, unknown>>(
    schema: TSchema,
  ): PgDatabase<PgQueryResultHKT, TSchema>;
}
