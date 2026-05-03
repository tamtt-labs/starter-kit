import type { ICommandHandler } from "@tamtt-labs/cqrs";

import type { DatabaseEnum } from "@/core/enums/database.enum";
import type { ConfigService } from "@/core/services/config/config.service";
import type { DatabaseService } from "@/core/services/database/database.service";

export class RunMigrationsCommand {
  constructor(public readonly databases: DatabaseEnum[]) {}
}

export class RunMigrationsCommandHandler implements ICommandHandler<RunMigrationsCommand> {
  public readonly command = RunMigrationsCommand;

  constructor(
    private readonly configService: ConfigService,
    private readonly databaseService: DatabaseService,
  ) {}

  async execute(command: RunMigrationsCommand) {
    for (const database of command.databases) {
      const databaseName = this.configService.getDatabaseName(database);
      console.log(`[${databaseName}] - Migrating ...`);
      try {
        const databaseUrl = this.configService.getDatabaseUrl(database);
        const migrationsFolder = this.configService.getMigrationsFolder(database);
        await this.databaseService.connect(databaseUrl);
        await this.databaseService.migrate(databaseUrl, migrationsFolder);
        await this.databaseService.disconnect(databaseUrl);
        console.log(`[${databaseName}] - Migration completed`);
      } catch (error) {
        console.error(`[${databaseName}] - Migration error`, error);
      }
    }
  }
}
