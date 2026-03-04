import { drizzle } from "drizzle-orm/bun-sql";
import { migrate } from "drizzle-orm/bun-sql/migrator";

const database = drizzle(Bun.env.DATABASE_URL);

migrate(database, { migrationsFolder: "./database/migrations" });
