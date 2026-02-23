import Elysia from "elysia";
import { ConfigService } from "./config.service";

export const ConfigModule = new Elysia({ name: Symbol("ConfigModule").toString() }).decorate(
  "configService",
  new ConfigService(),
);
