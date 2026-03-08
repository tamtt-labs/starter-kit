export interface IConfigService<TEnv extends Bun.Env> {
  get<T extends keyof TEnv>(key: T): TEnv[T];
  isProduction(): boolean;
  isDevelopment(): boolean;
  isStaging(): boolean;
  isTest(): boolean;
}
