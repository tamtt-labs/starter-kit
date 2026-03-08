import { Type, type TSchema } from "@sinclair/typebox";
import { TypeCompiler } from "@sinclair/typebox/compiler";
import { Value } from "@sinclair/typebox/value";
import type { IConfigService } from "./config.service";

type EnvProperties<TEnv extends Bun.Env> = Record<keyof TEnv, TSchema>;
type EnvRaw<TEnv extends Bun.Env> = Record<keyof TEnv, string | undefined>;

export class TypeboxConfigService<TEnv extends Bun.Env> implements IConfigService<TEnv> {
  private readonly parsedEnv: TEnv;

  constructor(
    private readonly properties: EnvProperties<TEnv>,
    private readonly sourceEnv?: EnvRaw<TEnv>,
  ) {
    this.parsedEnv = this.parseEnv();
  }

  public get<T extends keyof TEnv>(key: T): TEnv[T] {
    return this.parsedEnv[key];
  }

  private parseEnv(): TEnv {
    const envSchema = Type.Object(this.properties);
    const compiler = TypeCompiler.Compile(envSchema);

    const parsedEnv = Value.Parse(
      ["Clone", "Clean", "Default", "Decode", "Convert"],
      envSchema,
      this.sourceEnv ?? Bun.env,
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
    return this.get("NODE_ENV") === "production";
  }

  public isDevelopment() {
    return this.get("NODE_ENV") === "development";
  }

  public isStaging() {
    return this.get("NODE_ENV") === "staging";
  }

  public isTest() {
    return this.get("NODE_ENV") === "test";
  }
}
