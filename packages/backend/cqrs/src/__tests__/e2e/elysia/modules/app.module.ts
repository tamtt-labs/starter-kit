import Elysia from "elysia";
import { CqrsModule } from "./cqrs.module";
import { ErrorModule } from "./error.module";
import { HeroModule } from "./hero.module";
import { NoopModule } from "./noop.module";

export const AppModule = new Elysia()
  .use(CqrsModule)
  .use(ErrorModule)
  .use(HeroModule)
  .use(NoopModule);
