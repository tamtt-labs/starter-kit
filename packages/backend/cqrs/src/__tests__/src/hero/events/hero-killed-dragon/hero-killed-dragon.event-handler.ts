import type { IEventHandler } from "@/interfaces";
import { HeroKilledDragonEvent } from "./hero-killed-dragon.event";

export class HeroKilledDragonHandler implements IEventHandler<HeroKilledDragonEvent> {
  readonly event = HeroKilledDragonEvent;

  handle(event: HeroKilledDragonEvent) {
    console.log("🚀 ~ HeroKilledDragonHandler ~ handle ~ event:", event.constructor.name);
  }
}
