import { cors } from "@elysiajs/cors";
import Elysia from "elysia";
import { configService } from "../config/config.module";

export const CorsModule = new Elysia({ name: "CorsModule" }).use(
  cors({
    origin: configService.get("APP_ORIGIN"),
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
