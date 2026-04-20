import type { SourceEnv, SourceEnvFactory } from "./app-env";
import "./bun-env.d.ts";

export const BunEnv: SourceEnv = {
  TZ: Bun.env.TZ,
  NODE_ENV: Bun.env.NODE_ENV,

  APP_PORT: Bun.env.APP_PORT,
  APP_NAME: Bun.env.APP_NAME,
  APP_ORIGIN: Bun.env.APP_ORIGIN,

  AUTH_SECRET: Bun.env.AUTH_SECRET,
  AUTH_SESSION_EXPIRES_IN: Bun.env.AUTH_SESSION_EXPIRES_IN,
  AUTH_SESSION_CACHE_MAX_AGE: Bun.env.AUTH_SESSION_CACHE_MAX_AGE,
  AUTH_OTP_EXPIRES_IN: Bun.env.AUTH_OTP_EXPIRES_IN,
};

export const BunRuntimeEnv: SourceEnvFactory = () => ({
  READ_DATABASE_URL: Bun.env.READ_DATABASE_URL,
  WRITE_DATABASE_URL: Bun.env.WRITE_DATABASE_URL,
});
