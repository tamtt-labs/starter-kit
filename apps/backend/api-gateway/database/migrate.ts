import { drizzle } from "drizzle-orm/bun-sql";
import { migrate } from "drizzle-orm/bun-sql/migrator";

if (!Bun.env.WRITE_DATABASE_URL) {
  throw new Error("Environment variable WRITE_DATABASE_URL is not set");
}

const database = drizzle(Bun.env.WRITE_DATABASE_URL);

migrate(database, { migrationsFolder: "./database/migrations" });
