import type { AggregateRoot } from "../aggregate-root";
import { EventBus } from "../event-bus";
import type { IEvent, Type } from "../interfaces";

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
