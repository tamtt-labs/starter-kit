import {
  DropAncientItemCommand,
  DropAncientItemHandler,
} from "@/__tests__/src/hero/commands/drop-accent-item.command";
import {
  KillDragonCommand,
  KillDragonHandler,
} from "@/__tests__/src/hero/commands/kill-dragon.command";
import { HeroFoundItemEvent } from "@/__tests__/src/hero/events/hero-found-item/hero-found-item.event";
import { HeroFoundItemHandler } from "@/__tests__/src/hero/events/hero-found-item/hero-found-item.event-handler";
import { HeroKilledDragonEvent } from "@/__tests__/src/hero/events/hero-killed-dragon/hero-killed-dragon.event";
import { HeroKilledDragonHandler } from "@/__tests__/src/hero/events/hero-killed-dragon/hero-killed-dragon.event-handler";
import { GetHeroesQuery } from "@/__tests__/src/hero/queries/get-heroes.query";
import { HERO_ID } from "@/__tests__/src/hero/repositories/hero.repository";
import { ANCIENT_ITEM_ID } from "@/__tests__/src/hero/sagas/hero-game.saga";
import { NoopHandler } from "@/__tests__/src/noop/noop.event-handler";
import { waitImmediate } from "@/__tests__/utils/wait-immediate";
import { beforeAll, describe, expect, it, spyOn, type Mock } from "bun:test";
import { AppModule } from "./modules/app.module";

describe("Basic flows", () => {
  describe('when "KillDragonCommand" command is dispatched', () => {
    let killDragonExecuteSpy: Mock<KillDragonHandler["execute"]>;
    let heroKilledDragonHandleSpy: Mock<HeroKilledDragonHandler["handle"]>;
    let noopEventHandleSpy: Mock<NoopHandler["handle"]>;
    let dropAncientExecuteSpy: Mock<DropAncientItemHandler["execute"]>;
    let heroFoundItemSpy: Mock<HeroFoundItemHandler["handle"]>;
    let command: KillDragonCommand;

    beforeAll(async () => {
      const killDragonHandler = new KillDragonHandler(
        AppModule.decorator.heroRepository,
        AppModule.decorator.eventPublisher,
      );
      const dropAncientItemHandler = new DropAncientItemHandler(
        AppModule.decorator.heroRepository,
        AppModule.decorator.eventPublisher,
      );
      const heroKilledDragonHandler = new HeroKilledDragonHandler();
      const heroFoundItemHandler = new HeroFoundItemHandler();
      const noopHandler = new NoopHandler();

      dropAncientExecuteSpy = spyOn(dropAncientItemHandler, "execute");
      heroFoundItemSpy = spyOn(heroFoundItemHandler, "handle");
      killDragonExecuteSpy = spyOn(killDragonHandler, "execute");
      heroKilledDragonHandleSpy = spyOn(heroKilledDragonHandler, "handle");
      noopEventHandleSpy = spyOn(noopHandler, "handle");

      AppModule.decorator.commandBus.register(dropAncientItemHandler);
      AppModule.decorator.eventBus.register(heroFoundItemHandler);
      AppModule.decorator.commandBus.register(killDragonHandler);
      AppModule.decorator.eventBus.register(heroKilledDragonHandler);
      AppModule.decorator.eventBus.register(noopHandler);

      const commandBus = AppModule.decorator.commandBus;
      const heroId = HERO_ID;
      const dragonId = "dragonId";

      command = new KillDragonCommand(heroId, dragonId);
      await commandBus.execute(command);
      await waitImmediate();
    });

    it("should execute command handler", () => {
      expect(killDragonExecuteSpy).toHaveBeenCalledWith(command);
    });

    it('should handle "HeroKillDragonEvent" event', () => {
      const event = new HeroKilledDragonEvent(command.heroId, command.dragonId);
      expect(heroKilledDragonHandleSpy).toHaveBeenCalledWith(event);
    });

    it('should not trigger "NoopHandler" event', () => {
      expect(noopEventHandleSpy).not.toHaveBeenCalled();
    });

    describe("when saga triggered", () => {
      it('should dispatch "DropAncientItemCommand" and execute its command handler', () => {
        expect(dropAncientExecuteSpy).toHaveBeenCalledWith(
          new DropAncientItemCommand(HERO_ID, ANCIENT_ITEM_ID),
        );
      });

      it('should handle "HeroFoundItemEvent" event', () => {
        expect(heroFoundItemSpy).toHaveBeenCalledWith(
          new HeroFoundItemEvent(HERO_ID, ANCIENT_ITEM_ID),
        );
      });
    });
  });

  describe('when "GetHeroesQuery" query is executed', () => {
    it("should return all heroes", async () => {
      const queryBus = AppModule.decorator.queryBus;
      const heroes = await queryBus.execute(new GetHeroesQuery());
      expect(heroes).toEqual([expect.objectContaining({ id: HERO_ID })]);
    });
  });
});
