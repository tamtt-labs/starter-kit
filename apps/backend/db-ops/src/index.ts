import { Cqrs, ICommandHandler } from "@tamtt-labs/cqrs";
import { SqlDatabaseService } from "./core/services/database/sql-database.service";
import { ConfigService } from "./core/services/config/config.service";
import { RunMigrationsCommandHandler } from "./core/commands/run-migrations/run-migrations.command";
import { Command as Cli } from "commander";
import type { ICommandLine } from "./core/interfaces/command-line.interface";
import { RunMigrationsCli } from "./core/commands/run-migrations/run-migrations.cli";

const cli = new Cli().name("db-ops").description("Database operations CLI");
const cqrs = new Cqrs();

const databaseService = new SqlDatabaseService();
const configService = new ConfigService();

const commandHandlers: ICommandHandler[] = [
  new RunMigrationsCommandHandler(configService, databaseService),
  // define command handler here ...
];

const commandLines: ICommandLine[] = [
  new RunMigrationsCli(cqrs.commandBus),
  // define command-line here ...
];

cqrs.register({ commands: commandHandlers });
commandLines.forEach((command) => command.register(cli));

cli.parse();
