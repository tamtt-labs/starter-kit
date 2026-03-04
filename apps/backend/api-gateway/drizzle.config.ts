import { defineConfig } from "drizzle-kit";

/**
 * Drizzle ORM configuration for Neon PostgreSQL database
 *
 * @see https://orm.drizzle.team/docs/drizzle-config-file
 * @see https://orm.drizzle.team/llms.txt
 */
export default defineConfig({
  out: "./database/migrations",
  schema: "./src/**/*.schema.ts",
  dialect: "postgresql",
  casing: "snake_case",
  dbCredentials: {
    url: Bun.env.DATABASE_URL,
  },
  migrations: {
    table: "migration",
    schema: "public",
  },
});
