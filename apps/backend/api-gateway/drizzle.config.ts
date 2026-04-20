import { defineConfig } from "drizzle-kit";

if (!Bun.env.WRITE_DATABASE_URL) {
  throw new Error("Environment variable WRITE_DATABASE_URL is not set");
}

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
    url: Bun.env.WRITE_DATABASE_URL,
  },
  migrations: {
    table: "migration",
    schema: "public",
  },
});
