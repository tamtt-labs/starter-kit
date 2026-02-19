import Elysia from "elysia";
import { ErrorModule } from "./error.module";
import { HeroModule } from "./hero.module";
import { NoopModule } from "./noop.module";

export const AppModule = new Elysia().use(ErrorModule).use(HeroModule).use(NoopModule);
