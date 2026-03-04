import Elysia from "elysia";
import { ConfigService } from "./config.service";

export const configService = new ConfigService();

export const ConfigModule = new Elysia({ name: "ConfigModule" }).decorate({ configService });
