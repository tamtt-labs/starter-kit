import type { AggregateRoot } from "../aggregate-root";
import type { IEvent, Type } from "../interfaces";

import { EventBus } from "../event-bus";

export const mergeContext = (eventBus: EventBus, aggregateRoots: Type<AggregateRoot>[] = []) => {
  for (const item of aggregateRoots) {
    item.prototype.publish = function (event: IEvent) {
      eventBus.publish(event, item);
    };

    item.prototype.publishAll = function (events: IEvent[]) {
      eventBus.publishAll(events, item);
    };
  }
};
