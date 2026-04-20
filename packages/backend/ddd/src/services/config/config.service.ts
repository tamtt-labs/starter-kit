export type ConfigServiceKey<TStaticEnv, TRuntimeEnv> = keyof TStaticEnv | keyof TRuntimeEnv;

export type ConfigServiceValue<
  TStaticEnv,
  TRuntimeEnv,
  K extends ConfigServiceKey<TStaticEnv, TRuntimeEnv>,
> = K extends keyof TStaticEnv
  ? K extends keyof TRuntimeEnv
    ? TStaticEnv[K] | TRuntimeEnv[K]
    : TStaticEnv[K]
  : K extends keyof TRuntimeEnv
    ? TRuntimeEnv[K]
    : never;

export interface IConfigService<TStaticEnv, TRuntimeEnv> {
  get<K extends ConfigServiceKey<TStaticEnv, TRuntimeEnv>>(
    key: K,
  ): ConfigServiceValue<TStaticEnv, TRuntimeEnv, K>;
  isProduction(): boolean;
  isDevelopment(): boolean;
  isStaging(): boolean;
  isTest(): boolean;
}
