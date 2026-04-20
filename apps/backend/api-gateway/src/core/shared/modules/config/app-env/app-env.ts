export interface AppEnv {
  TZ?: string;
  NODE_ENV: "development" | "production" | "staging" | "test";

  APP_PORT: number;
  APP_NAME: string;
  APP_ORIGIN: string;

  AUTH_SECRET: string;
  AUTH_SESSION_EXPIRES_IN?: number;
  AUTH_SESSION_CACHE_MAX_AGE?: number;
  AUTH_OTP_EXPIRES_IN?: number;
}

export type SourceEnv = Partial<{
  [Key in keyof (AppEnv & AppRuntimeEnv)]: string;
}>;

export interface AppRuntimeEnv {
  READ_DATABASE_URL: string;
  WRITE_DATABASE_URL: string;
}

export type SourceEnvFactory = () => SourceEnv;
