import { TypeboxConfigService } from "@tamtt-labs/ddd";
import { t } from "elysia";

export class ConfigService extends TypeboxConfigService<Bun.Env> {
  constructor() {
    super({
      TZ: t.Optional(t.String()).default("UTC"),
      PORT: t.Number(),
      NODE_ENV: t.Union([
        t.Literal("development"),
        t.Literal("production"),
        t.Literal("staging"),
        t.Literal("test"),
      ]),

      // BetterAuth
      BETTER_AUTH_SECRET: t.String(),
      BETTER_AUTH_URL: t.String(),

      // Authentication
      AUTHENTICATION_SESSION_EXPIRES_IN: t.Number(),
      AUTHENTICATION_COOKIE_CACHE_MAX_AGE: t.Number(),
    });
  }
}
