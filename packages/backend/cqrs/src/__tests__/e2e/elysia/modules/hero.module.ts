import { DropAncientItemHandler } from "@/__tests__/src/hero/commands/drop-accent-item.command";
import { KillDragonHandler } from "@/__tests__/src/hero/commands/kill-dragon.command";
import { Hero } from "@/__tests__/src/hero/entities/hero.aggregate-root";
import { HeroKilledDragonHandler } from "@/__tests__/src/hero/events/hero-killed-dragon/hero-killed-dragon.event-handler";
import { GetHeroesHandler } from "@/__tests__/src/hero/queries/get-heroes.query";
import { HeroRepository } from "@/__tests__/src/hero/repositories/hero.repository";
import { HeroGameSagas } from "@/__tests__/src/hero/sagas/hero-game.saga";
import { Cqrs } from "@/adapters/elysia";
import Elysia from "elysia";
import { CqrsModule } from "./cqrs.module";

const HeroRepositoryPlugin = new Elysia().decorate("heroRepository", new HeroRepository());

export const HeroModule = new Elysia()
  .use(HeroRepositoryPlugin)
  .use(CqrsModule)
  .use((app) =>
    Cqrs.register({
      commands: [
        new KillDragonHandler(app.decorator.heroRepository, app.decorator.eventPublisher),
        new DropAncientItemHandler(app.decorator.heroRepository, app.decorator.eventPublisher),
      ],
      queries: [new GetHeroesHandler(app.decorator.heroRepository)],
      events: [new HeroKilledDragonHandler()],
      sagas: [new HeroGameSagas()],
      aggregateRoots: [Hero],
    })(app),
  );
