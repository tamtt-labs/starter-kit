import Elysia from "elysia";
import { CloudflareEnv, CloudflareRuntimeEnv } from "./app-env/cloudflare-env";
import { ConfigService } from "./config.service";

export const configService = new ConfigService(CloudflareEnv, CloudflareRuntimeEnv);

export const ConfigModule = new Elysia({ name: "ConfigModule" }).decorate({ configService });
