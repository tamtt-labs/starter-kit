import { DatabaseService } from "./database.service";

import { drizzle } from "drizzle-orm/bun-sql";
import { migrate } from "drizzle-orm/bun-sql/migrator";

export class SqlDatabaseService implements DatabaseService {
  private databaseMap: Map<string, ReturnType<typeof drizzle>> = new Map();

  public async connect(databaseUrl: string): Promise<void> {
    const database = this.databaseMap.get(databaseUrl) ?? drizzle(databaseUrl);
    await database.$client.connect();
    this.databaseMap.set(databaseUrl, database);
  }

  public async disconnect(databaseUrl: string): Promise<void> {
    const database = this.databaseMap.get(databaseUrl);
    if (database) {
      await database.$client.close();
      this.databaseMap.delete(databaseUrl);
    }
  }

  public async migrate(databaseUrl: string, migrationsFolder: string): Promise<void> {
    await this.connect(databaseUrl);
    const database = this.databaseMap.get(databaseUrl);
    if (database) {
      await migrate(database, {
        migrationsFolder,
        migrationsSchema: "public",
        migrationsTable: "migration",
      });
    }
  }
}
