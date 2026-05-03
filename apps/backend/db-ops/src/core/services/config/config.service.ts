import { Type as t } from "@sinclair/typebox";
import { TypeboxConfigService } from "@tamtt-labs/ddd";

import "./env.d.ts";
import { DatabaseEnum } from "@/core/enums/database.enum.js";

export class ConfigService extends TypeboxConfigService<Bun.Env> {
  constructor() {
    super({
      TZ: t.Optional(t.String()),
      NODE_ENV: t.Union([
        t.Literal("development"),
        t.Literal("production"),
        t.Literal("staging"),
        t.Literal("test"),
      ]),

      // Databases
      GATEWAY_DATABASE_URL: t.String(),
    });
  }

  public getDatabaseUrl(database: DatabaseEnum): string {
    switch (database) {
      case DatabaseEnum.GATEWAY: {
        return this.get("GATEWAY_DATABASE_URL");
      }
    }
  }

  public getMigrationsFolder(database: DatabaseEnum): string {
    return `migrations/db-${database.toLocaleLowerCase()}`;
  }

  public getDatabaseName(database: DatabaseEnum): string {
    return `db-${database.toLocaleLowerCase()}`;
  }
}
