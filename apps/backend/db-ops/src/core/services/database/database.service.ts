export abstract class DatabaseService {
  abstract connect(databaseUrl: string): Promise<void>;
  abstract disconnect(databaseUrl: string): Promise<void>;
  abstract migrate(databaseUrl: string, migrationsFolder: string): Promise<void>;
}
