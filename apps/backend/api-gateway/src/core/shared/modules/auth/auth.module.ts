import Elysia from "elysia";
import { BetterAuthModule } from "./better-auth.module";

export const AuthModule = new Elysia({ name: "AuthModule" })
  .use(BetterAuthModule)
  .mount("/", BetterAuthModule.decorator.betterAuth.handler);
