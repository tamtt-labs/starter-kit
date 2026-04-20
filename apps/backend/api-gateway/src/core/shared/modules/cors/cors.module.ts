import { cors } from "@elysiajs/cors";
import Elysia, { type AnyElysia } from "elysia";
import { ConfigModule } from "../config/config.module";

export const CorsModule = new Elysia({ name: "CorsModule" })
  .use(ConfigModule)
  .use(({ decorator }) =>
    cors({
      origin: decorator.configService.get("APP_ORIGIN"),
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      credentials: true,
      allowedHeaders: ["Content-Type", "Authorization"],
    }),
  ) as AnyElysia;
