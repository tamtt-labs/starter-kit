import { Type } from "@sinclair/typebox";
import { describe, expect, it } from "bun:test";
import { TypeboxConfigService } from "./typebox-config.service";

declare module "bun" {
  interface Env {
    PORT: number;
  }
}

describe(TypeboxConfigService.name, () => {
  const envProperties = {
    NODE_ENV: Type.Enum({
      development: "development",
      production: "production",
      test: "test",
    }),
    PORT: Type.Number(),
    TZ: Type.Optional(Type.String()),
  };

  describe("constructor", () => {
    it("should parse the environment variables", () => {
      const env = {
        NODE_ENV: "development",
        PORT: "3000",
        TZ: undefined,
      };

      const configService = new TypeboxConfigService(envProperties, env);

      expect(configService).toBeDefined();
    });

    it("should throw an error if the environment variables are invalid", () => {
      const env = {
        NODE_ENV: "invalid",
        PORT: "3000",
        TZ: undefined,
      };

      expect(() => new TypeboxConfigService(envProperties, env)).toThrow();
    });
  });

  describe("get", () => {
    it("should return the environment variable", () => {
      const env = {
        NODE_ENV: "development",
        PORT: "3000",
        TZ: undefined,
      };

      const configService = new TypeboxConfigService(envProperties, env);

      expect(configService.get("NODE_ENV")).toBe("development");
      expect(configService.get("PORT")).toBe(3000);
    });
  });
});
