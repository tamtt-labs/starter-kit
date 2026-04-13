import Elysia from "elysia";
import { BetterAuthModule } from "./better-auth.module";

export type * as SimpleWebAuthn from "@simplewebauthn/server";
export type * as Zod from "zod/v4";

export const AuthModule = new Elysia({ name: "AuthModule" })
  .use(BetterAuthModule)
  .mount("/", BetterAuthModule.decorator.betterAuth.handler);
