import { Elysia } from "elysia";
import { ApiDocsModule } from "./shared/modules/api-docs/api-docs.module";
import { AuthModule } from "./shared/modules/auth/auth.module";
import { CorsModule } from "./shared/modules/cors/cors.module";

export const AppModule = new Elysia().use(CorsModule).use(ApiDocsModule).use(AuthModule);
