import { configService } from "../config/config.module";
import { Drizzle } from "./drizzle";

export const database = {
  read: new Bun.SQL({
    url: configService.get("DATABASE_URL"),
    adapter: "postgres",
  }),
  write: new Bun.SQL({
    url: configService.get("DATABASE_URL"),
    adapter: "postgres",
  }),
};

export const DrizzleReadModule = Drizzle.createModule({
  client: database.read,
  name: "DrizzleReadModule",
});

export const DrizzleWriteModule = Drizzle.createModule({
  client: database.write,
  name: "DrizzleWriteModule",
});
