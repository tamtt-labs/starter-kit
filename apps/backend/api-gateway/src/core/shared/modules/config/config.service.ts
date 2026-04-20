import { TypeboxConfigService } from "@tamtt-labs/ddd";
import { t } from "elysia";
import type { AppEnv, AppRuntimeEnv, SourceEnv, SourceEnvFactory } from "./app-env/app-env";

export class ConfigService extends TypeboxConfigService<AppEnv, AppRuntimeEnv> {
  constructor(sourceStaticEnv: SourceEnv, sourceRuntimeEnv: SourceEnvFactory) {
    super(
      {
        properties: {
          TZ: t.Optional(t.String()),
          NODE_ENV: t.Union([
            t.Literal("development"),
            t.Literal("production"),
            t.Literal("staging"),
            t.Literal("test"),
          ]),

          // Application
          APP_PORT: t.Number(),
          APP_NAME: t.String(),
          APP_ORIGIN: t.String(),

          // BetterAuth
          AUTH_SECRET: t.String(),
          AUTH_SESSION_EXPIRES_IN: t.Optional(t.Number()),
          AUTH_SESSION_CACHE_MAX_AGE: t.Optional(t.Number()),
          AUTH_OTP_EXPIRES_IN: t.Optional(t.Number()),
        },
        source: sourceStaticEnv,
      },
      {
        properties: {
          // Database
          READ_DATABASE_URL: t.String(),
          WRITE_DATABASE_URL: t.String(),
        },
        sourceFactory: sourceRuntimeEnv,
      },
    );
  }
}
