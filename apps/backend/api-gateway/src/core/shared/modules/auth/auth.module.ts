import Elysia from "elysia";
import { betterAuth } from "./better-auth";

export type * as SimpleWebAuthn from "@simplewebauthn/server";

export const AuthModule = new Elysia({ name: "AuthModule" })
  .decorate({ betterAuth })
  .mount("/", betterAuth.handler);
