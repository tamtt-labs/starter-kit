import { configService } from "../config/config.module";
import { Drizzle } from "./drizzle";
import { PostgresDrizzleFactory } from "./drizzle-factory/postgres-drizzle-factory";

export const DrizzleReadModule = Drizzle.createModule({
  drizzleFactory: new PostgresDrizzleFactory(() => configService.get("READ_DATABASE_URL")),
  name: "DrizzleReadModule",
});

export const DrizzleWriteModule = Drizzle.createModule({
  drizzleFactory: new PostgresDrizzleFactory(() => configService.get("WRITE_DATABASE_URL")),
  name: "DrizzleWriteModule",
});
