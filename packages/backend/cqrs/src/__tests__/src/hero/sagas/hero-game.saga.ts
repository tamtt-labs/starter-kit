import type { ICommand, ISagaProvider } from "@/interfaces";
import { ofType } from "@/operators";
import { Observable, map } from "rxjs";
import { DropAncientItemCommand } from "../commands/drop-accent-item.command";
import { HeroKilledDragonEvent } from "../events/hero-killed-dragon/hero-killed-dragon.event";

export const ANCIENT_ITEM_ID = "12456789";

export class HeroGameSagas implements ISagaProvider {
  readonly saga = this.dragonKilled;

  dragonKilled(events$: Observable<any>): Observable<ICommand> {
    return events$.pipe(
      ofType(HeroKilledDragonEvent),
      map((event) => {
        console.log("🚀 ~ HeroGameSagas ~ dragonKilled ~ event:", event.constructor.name);
        return new DropAncientItemCommand(event.heroId, ANCIENT_ITEM_ID);
      }),
    );
  }
}
