import { fromTypes, openapi } from "@elysiajs/openapi";
import Elysia from "elysia";
import { betterAuthOpenApi } from "../auth/better-auth";
import { configService } from "../config/config.module";

export const ApiDocsModule = new Elysia({ name: "ApiDocsModule" }).use(
  openapi({
    references: fromTypes(
      configService.isDevelopment() || configService.isTest() ? "src/index.ts" : "dist/index.d.ts",
    ),
    documentation: {
      components: await betterAuthOpenApi.components,
      paths: await betterAuthOpenApi.getPaths(),
    },
  }),
);
