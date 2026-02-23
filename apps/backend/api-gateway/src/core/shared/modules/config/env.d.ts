declare module "bun" {
  interface Env {
    PORT: number;

    BETTER_AUTH_SECRET: string;
    BETTER_AUTH_URL: string;

    AUTHENTICATION_SESSION_EXPIRES_IN: number;
    AUTHENTICATION_COOKIE_CACHE_MAX_AGE: number;
  }
}
