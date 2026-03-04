declare module "bun" {
  interface Env {
    APP_PORT: number;
    APP_NAME: string;
    APP_ORIGIN: string;

    AUTH_SECRET: string;
    AUTH_OTP_EXPIRES_IN: number;
    AUTH_SESSION_EXPIRES_IN: number;
    AUTH_SESSION_CACHE_MAX_AGE: number;

    DATABASE_URL: string;
  }
}
