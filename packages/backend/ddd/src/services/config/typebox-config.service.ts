import { Type, type TSchema } from "@sinclair/typebox";
import { TypeCompiler } from "@sinclair/typebox/compiler";
import { Value } from "@sinclair/typebox/value";
import type { ConfigServiceKey, ConfigServiceValue, IConfigService } from "./config.service";

type EnvProperties<TEnv> = Record<keyof TEnv, TSchema>;

type Source<TEnv> = Partial<{
  [Key in keyof TEnv]: string;
}>;

type StaticConfig<TEnv> = {
  properties: EnvProperties<TEnv>;
  source: Source<TEnv>;
};

type RuntimeConfig<TEnv> = {
  properties: EnvProperties<TEnv>;
  sourceFactory: () => Source<TEnv>;
};

export class TypeboxConfigService<TStaticEnv, TRuntimeEnv = {}> implements IConfigService<
  TStaticEnv,
  TRuntimeEnv
> {
  private readonly staticEnv: TStaticEnv;

  constructor(
    private readonly staticConfig: StaticConfig<TStaticEnv>,
    private readonly runtimeConfig?: RuntimeConfig<TRuntimeEnv>,
  ) {
    this.staticEnv = this.parseStaticEnv();
  }

  public get<K extends ConfigServiceKey<TStaticEnv, TRuntimeEnv>>(
    key: K,
  ): ConfigServiceValue<TStaticEnv, TRuntimeEnv, K> {
    return (this.staticEnv[key as keyof TStaticEnv] ??
      this.parseRuntimeEnv()[key as keyof TRuntimeEnv]) as ConfigServiceValue<
      TStaticEnv,
      TRuntimeEnv,
      K
    >;
  }

  private parseStaticEnv(): TStaticEnv {
    return this.parseEnv(this.staticConfig.properties, this.staticConfig.source);
  }

  private parseRuntimeEnv(): TRuntimeEnv {
    return this.runtimeConfig
      ? this.parseEnv(this.runtimeConfig.properties, this.runtimeConfig.sourceFactory())
      : ({} as TRuntimeEnv);
  }

  private parseEnv<TEnv>(
    properties: EnvProperties<TEnv>,
    source: Record<string, string | undefined>,
  ): TEnv {
    const envSchema = Type.Object(properties);
    const compiler = TypeCompiler.Compile(envSchema);

    const parsedEnv = Value.Parse(
      ["Clone", "Clean", "Default", "Decode", "Convert"],
      envSchema,
      source,
    );

    const isValid = compiler.Check(parsedEnv);
    if (isValid) {
      return parsedEnv as unknown as TEnv;
    }

    const errors = [...compiler.Errors(parsedEnv)].reduce((errors, e) => {
      const path = e.path.substring(1);
      return { ...errors, [path]: e.message };
    }, {});

    throw new Error(`Invalid environment variables:\n${JSON.stringify(errors, null, 2)}`);
  }

  public isProduction() {
    return this.get("NODE_ENV" as ConfigServiceKey<TStaticEnv, TRuntimeEnv>) === "production";
  }

  public isDevelopment() {
    return this.get("NODE_ENV" as ConfigServiceKey<TStaticEnv, TRuntimeEnv>) === "development";
  }

  public isStaging() {
    return this.get("NODE_ENV" as ConfigServiceKey<TStaticEnv, TRuntimeEnv>) === "staging";
  }

  public isTest() {
    return this.get("NODE_ENV" as ConfigServiceKey<TStaticEnv, TRuntimeEnv>) === "test";
  }
}
