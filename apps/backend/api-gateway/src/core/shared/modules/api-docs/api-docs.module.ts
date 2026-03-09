import { fromTypes, openapi } from "@elysiajs/openapi";
import Elysia from "elysia";
import { BetterAuthModule } from "../auth/better-auth.module";
import { configService } from "../config/config.module";

export const ApiDocsModule = new Elysia({ name: "ApiDocsModule" })
  .use(BetterAuthModule)
  .use(async ({ decorator }) =>
    openapi({
      references: fromTypes(
        configService.isDevelopment() || configService.isTest()
          ? "src/index.ts"
          : "dist/index.d.ts",
      ),
      documentation: {
        components: await decorator.betterAuthOpenApi.components,
        paths: await decorator.betterAuthOpenApi.getPaths(),
      },
    }),
  );
