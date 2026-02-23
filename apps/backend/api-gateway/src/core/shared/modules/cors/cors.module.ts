import { cors } from "@elysiajs/cors";
import Elysia from "elysia";

export const CorsModule = new Elysia({ name: Symbol("CorsModule").toString() }).use(
  cors({
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
