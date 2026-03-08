import { TypeboxConfigService } from "@tamtt-labs/ddd";
import { t } from "elysia";
import "./env.d.ts";

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

      // Application
      APP_PORT: t.Number(),
      APP_NAME: t.String(),
      APP_ORIGIN: t.String(),

      // BetterAuth
      AUTH_SECRET: t.String(),
      AUTH_SESSION_EXPIRES_IN: t.Number(),
      AUTH_SESSION_CACHE_MAX_AGE: t.Number(),
      AUTH_OTP_EXPIRES_IN: t.Number(),

      // Database
      DATABASE_URL: t.String(),
    });
  }
}
