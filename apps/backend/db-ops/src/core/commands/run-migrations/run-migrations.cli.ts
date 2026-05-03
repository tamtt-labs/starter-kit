import { DatabaseEnum } from "@/core/enums/database.enum";
import { ICommandLine } from "@/core/interfaces/command-line.interface";
import { Type } from "@sinclair/typebox";
import type { CommandBus } from "@tamtt-labs/cqrs";
import { TypeboxSchemaValidator } from "@tamtt-labs/ddd";
import { Command as Cli } from "commander";
import { RunMigrationsCommand } from "./run-migrations.command";

interface CliArgs {
  database: DatabaseEnum[];
}

export class RunMigrationsCli extends ICommandLine<CliArgs> {
  constructor(private readonly commandBus: CommandBus) {
    super();
  }

  public register(cli: Cli): void {
    cli
      .command("migrate")
      .description("Run database migrations")
      .option("-d, --database <database>", "Database to migrate", this.parseRepeatable, [])
      .action(async (options) => {
        const args = this.parseArgs(options);
        await this.commandBus.execute(new RunMigrationsCommand(args.database));
      });
  }

  public parseArgs(args: unknown) {
    return new TypeboxSchemaValidator<CliArgs>({
      database: Type.Array(Type.Enum(DatabaseEnum)),
    }).validate(args);
  }
}
