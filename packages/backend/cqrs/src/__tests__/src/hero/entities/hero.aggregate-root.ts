import { AggregateRoot } from "@/aggregate-root";
import { HeroFoundItemEvent } from "../events/hero-found-item/hero-found-item.event";
import { HeroKilledDragonEvent } from "../events/hero-killed-dragon/hero-killed-dragon.event";

export class Hero extends AggregateRoot {
  constructor(private readonly id: string) {
    super();
  }

  killEnemy(enemyId: string) {
    // logic ...
    this.apply(new HeroKilledDragonEvent(this.id, enemyId));
  }

  addItem(itemId: string) {
    // logic ...
    this.apply(new HeroFoundItemEvent(this.id, itemId));
  }
}
