import { type TSchema } from "@sinclair/typebox";

import type { IConfigService } from "./config.service";

import { TypeboxSchemaValidator } from "../schema-validator";

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
    const validator = new TypeboxSchemaValidator<TEnv>(this.properties);
    const result = validator.safeValidate(this.sourceEnv ?? Bun.env);
    switch (result.success) {
      case true:
        return result.data;
      case false:
        throw new Error(`Invalid environment variables:\n${result.error.message}`);
    }
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
