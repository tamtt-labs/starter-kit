import { AggregateRoot } from "./aggregate-root";
import { EventBus } from "./event-bus";
import type { IEvent } from "./interfaces";

interface Constructor<T> {
  new (...args: any[]): T;
}

/**
 * @publicApi
 */
export class EventPublisher<EventBase extends IEvent = IEvent> {
  constructor(private readonly eventBus: EventBus<EventBase>) {}

  /**
   * Merge the event publisher into the provided class.
   * This is required to make `publish` and `publishAll` available on the `AggregateRoot` class.
   * @param metatype The class to merge into.
   * @param asyncContext The async context (if scoped).
   */
  mergeClassContext<T extends Constructor<AggregateRoot<EventBase>>>(metatype: T): T {
    const eventBus = this.eventBus;
    return class extends metatype {
      override publish(event: EventBase) {
        eventBus.publish(event, this);
      }
      override publishAll(events: EventBase[]) {
        eventBus.publishAll(events, this);
      }
    };
  }

  /**
   * Merge the event publisher into the provided object.
   * This is required to make `publish` and `publishAll` available on the `AggregateRoot` class instance.
   * @param object The object to merge into.
   * @param asyncContext The async context (if scoped).
   */
  mergeObjectContext<T extends AggregateRoot<EventBase>>(object: T): T {
    const eventBus = this.eventBus;
    object.publish = (event: EventBase) => {
      eventBus.publish(event, object);
    };

    object.publishAll = (events: EventBase[]) => {
      eventBus.publishAll(events, object);
    };
    return object;
  }
}
