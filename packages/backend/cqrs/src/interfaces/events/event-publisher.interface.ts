import type { IEvent } from "./event.interface";

export interface IEventPublisher<EventBase extends IEvent = IEvent> {
  /**
   * Publishes an event.
   * @param event The event to publish.
   * @param dispatcherContext Dispatcher context or undefined.
   */
  publish<TEvent extends EventBase>(event: TEvent, dispatcherContext?: unknown): any;

  /**
   * Publishes multiple events.
   * @param events The events to publish.
   * @param dispatcherContext Dispatcher context or undefined.
   */
  publishAll?<TEvent extends EventBase>(events: TEvent[], dispatcherContext?: unknown): any;
}
