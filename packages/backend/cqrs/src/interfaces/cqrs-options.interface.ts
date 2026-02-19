import type { ICommandPublisher } from "./commands/command-publisher.interface";
import type { IEventPublisher } from "./events/event-publisher.interface";
import type { IUnhandledExceptionPublisher } from "./exceptions/unhandled-exception-publisher.interface";
import type { IQueryPublisher } from "./queries/query-publisher.interface";

/**
 * Options for the Cqrs.
 *
 * @publicApi
 */
export interface CqrsOptions {
  /**
   * Command publisher to use for publishing commands.
   * @default DefaultCommandPubSub
   */
  commandPublisher?: ICommandPublisher;
  /**
   * Event publisher to use for publishing events.
   * @default DefaultPubSub
   */
  eventPublisher?: IEventPublisher;
  /**
   * Query publisher to use for publishing queries.
   * @default DefaultQueryPubSub
   */
  queryPublisher?: IQueryPublisher;
  /**
   * Unhandled exception publisher to use for publishing unhandled exceptions.
   * @default DefaultUnhandledExceptionPubSub
   */
  unhandledExceptionPublisher?: IUnhandledExceptionPublisher;
  /**
   * Whether to rethrow unhandled exceptions.
   * @default false
   */
  rethrowUnhandled?: boolean;
}
