import { Elysia } from "elysia";
import { AuthModule } from "./shared/modules/auth/auth.module";

export const AppModule = new Elysia().use(AuthModule);

export type App = typeof AppModule;
