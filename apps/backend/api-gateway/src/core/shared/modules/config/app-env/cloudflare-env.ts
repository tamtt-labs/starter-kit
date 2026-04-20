import { env } from "cloudflare:workers";
import type { SourceEnv, SourceEnvFactory } from "./app-env";

const cloudflareEnv = env as any;

export const CloudflareEnv: SourceEnv = {
  TZ: cloudflareEnv.TZ,
  NODE_ENV: cloudflareEnv.NODE_ENV,

  APP_NAME: cloudflareEnv.APP_NAME,
  APP_PORT: cloudflareEnv.APP_PORT,
  APP_ORIGIN: cloudflareEnv.APP_ORIGIN,

  AUTH_SECRET: cloudflareEnv.AUTH_SECRET,
  AUTH_SESSION_EXPIRES_IN: cloudflareEnv.AUTH_SESSION_EXPIRES_IN,
  AUTH_SESSION_CACHE_MAX_AGE: cloudflareEnv.AUTH_SESSION_CACHE_MAX_AGE,
  AUTH_OTP_EXPIRES_IN: cloudflareEnv.AUTH_OTP_EXPIRES_IN,
};

export const CloudflareRuntimeEnv: SourceEnvFactory = () => ({
  READ_DATABASE_URL: cloudflareEnv.HYPERDRIVE_READ?.connectionString,
  WRITE_DATABASE_URL: cloudflareEnv.HYPERDRIVE_WRITE?.connectionString,
});
