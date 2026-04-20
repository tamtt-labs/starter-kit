import { Type } from "@sinclair/typebox";
import { describe, expect, it } from "bun:test";
import { TypeboxConfigService } from "./typebox-config.service";

interface StaticEnv {
  NODE_ENV: string;
  PORT: number;
  TZ?: string;
}

const staticEnvProperties = {
  NODE_ENV: Type.Enum({
    development: "development",
    production: "production",
    test: "test",
  }),
  PORT: Type.Number(),
  TZ: Type.Optional(Type.String()),
};

interface RuntimeEnv {
  READ_DATABASE_URL: string;
  WRITE_DATABASE_URL: string;
}

const runtimeEnvProperties = {
  READ_DATABASE_URL: Type.String(),
  WRITE_DATABASE_URL: Type.String(),
};

describe(TypeboxConfigService.name, () => {
  describe("constructor", () => {
    it("should parse the environment variables", () => {
      const staticSourceEnv = {
        NODE_ENV: "development",
        PORT: "3000",
        TZ: undefined,
      };

      const configService = new TypeboxConfigService({
        properties: staticEnvProperties,
        source: staticSourceEnv,
      });

      expect(configService).toBeDefined();
    });

    it("should throw an error if the environment variables are invalid", () => {
      const staticSourceEnv = {
        NODE_ENV: "invalid",
        PORT: "3000",
        TZ: undefined,
      };

      expect(
        () =>
          new TypeboxConfigService({
            properties: staticEnvProperties,
            source: staticSourceEnv,
          }),
      ).toThrow();
    });
  });

  describe("get", () => {
    it("should return the environment variable", () => {
      const staticSourceEnv = {
        NODE_ENV: "development",
        PORT: "3000",
        TZ: undefined,
      };

      const configService = new TypeboxConfigService({
        properties: staticEnvProperties,
        source: staticSourceEnv,
      });

      expect(configService.get("NODE_ENV")).toBe("development");
      expect(configService.get("PORT")).toBe(3000);
    });

    it("should return the runtime environment variable", () => {
      const staticSourceEnv = {
        NODE_ENV: "development",
        PORT: "3000",
        TZ: undefined,
      };

      const runtimeSourceEnv = {
        READ_DATABASE_URL: "read-database-url",
        WRITE_DATABASE_URL: "write-database-url",
      };

      const configService = new TypeboxConfigService(
        {
          properties: staticEnvProperties,
          source: staticSourceEnv,
        },
        {
          properties: runtimeEnvProperties,
          sourceFactory: () => runtimeSourceEnv,
        },
      );

      expect(configService.get("NODE_ENV")).toBe(staticSourceEnv.NODE_ENV);
      expect(configService.get("READ_DATABASE_URL")).toBe(runtimeSourceEnv.READ_DATABASE_URL);
      expect(configService.get("WRITE_DATABASE_URL")).toBe(runtimeSourceEnv.WRITE_DATABASE_URL);
    });
  });
});
