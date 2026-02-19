import type { IEventHandler } from "@/interfaces";
import { HeroFoundItemEvent } from "./hero-found-item.event";

export class HeroFoundItemHandler implements IEventHandler<HeroFoundItemEvent> {
  readonly event = HeroFoundItemEvent;

  handle(event: HeroFoundItemEvent) {
    console.log("🚀 ~ HeroFoundItemHandler ~ handle ~ event:", event.constructor.name);
  }
}
