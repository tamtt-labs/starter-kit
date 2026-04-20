import { Elysia } from "elysia";
import { CorsModule } from "./shared/modules/cors/cors.module";

export const AppModule = new Elysia().use(CorsModule);
