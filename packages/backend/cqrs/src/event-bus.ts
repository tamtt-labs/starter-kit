import { Subscription, defer, of } from "rxjs";
import { catchError, filter, mergeMap } from "rxjs/operators";
import { CommandBus } from "./command-bus";
import { DefaultPubSub } from "./helpers/default-pubsub";
import type {
  CqrsOptions,
  ICommand,
  IEvent,
  IEventBus,
  IEventHandler,
  IEventPublisher,
  ISaga,
  ISagaProvider,
  Type,
  UnhandledExceptionInfo,
} from "./interfaces";
import { UnhandledExceptionBus } from "./unhandled-exception-bus";
import { ObservableBus } from "./utils";

/**
 * @publicApi
 */
export class EventBus<EventBase extends IEvent = IEvent>
  extends ObservableBus<EventBase>
  implements IEventBus<EventBase>
{
  protected readonly subscriptions: Subscription[];

  private _publisher: IEventPublisher<EventBase>;

  constructor(
    private readonly commandBus: CommandBus,
    private readonly unhandledExceptionBus: UnhandledExceptionBus,
    private readonly options?: CqrsOptions,
  ) {
    super();
    this.subscriptions = [];

    if (this.options?.eventPublisher) {
      this._publisher = this.options.eventPublisher;
    } else {
      this._publisher = new DefaultPubSub<EventBase>(this.subject$);
    }
  }

  /**
   * Returns the publisher.
   * Default publisher is `DefaultPubSub` (in memory).
   */
  get publisher(): IEventPublisher<EventBase> {
    return this._publisher;
  }

  /**
   * Sets the publisher.
   * Default publisher is `DefaultPubSub` (in memory).
   * @param _publisher The publisher to set.
   */
  set publisher(_publisher: IEventPublisher<EventBase>) {
    this._publisher = _publisher;
  }

  destroy() {
    this.subscriptions.forEach((subscription) => subscription.unsubscribe());
  }

  /**
   * Publishes an event.
   * @param event The event to publish.
   */
  publish<TEvent extends EventBase>(event: TEvent): any;
  /**
   * Publishes an event.
   * @param event The event to publish.
   * @param dispatcherContext Dispatcher context
   */
  publish<TEvent extends EventBase, TContext = unknown>(
    event: TEvent,
    dispatcherContext: TContext,
  ): any;
  publish<TEvent extends EventBase, TContext = unknown>(
    event: TEvent,
    dispatcherContext?: TContext,
  ): any {
    return this._publisher.publish(event, dispatcherContext);
  }

  /**
   * Publishes multiple events.
   * @param events The events to publish.
   */
  publishAll<TEvent extends EventBase>(events: TEvent[]): any;
  /**
   * Publishes multiple events.
   * @param events The events to publish.
   * @param dispatcherContext Dispatcher context
   */
  publishAll<TEvent extends EventBase, TContext = unknown>(
    events: TEvent[],
    dispatcherContext: TContext,
  ): any;
  publishAll<TEvent extends EventBase, TContext = unknown>(
    events: TEvent[],
    dispatcherContext?: TContext,
  ): any {
    if (this._publisher.publishAll) {
      return this._publisher.publishAll(events, dispatcherContext);
    }

    return (events || []).map((event) => this._publisher.publish(event, dispatcherContext));
  }

  bind(event: Type<EventBase>, handler: IEventHandler<EventBase>) {
    const stream$ = this.ofEvent(event);

    const deferred = (event: EventBase) => () => {
      return Promise.resolve(handler.handle.bind(handler)(event));
    };

    const subscription = stream$
      .pipe(
        mergeMap((event) =>
          defer(deferred(event)).pipe(
            catchError((error) => {
              if (this.options?.rethrowUnhandled) {
                throw error;
              }
              const unhandledError = this.mapToUnhandledErrorInfo(event, error);
              this.unhandledExceptionBus.publish(unhandledError);
              console.error(
                `"${handler.constructor.name}" has thrown an unhandled exception.`,
                error,
              );
              return of();
            }),
          ),
        ),
      )
      .subscribe();
    this.subscriptions.push(subscription);
  }

  registerSagas(...providers: ISagaProvider[]) {
    for (const provider of providers) {
      const sagas = Array.isArray(provider.saga) ? provider.saga : [provider.saga];

      for (const saga of sagas) {
        const boundSaga = saga.bind(provider) as ISaga<EventBase>;
        this.registerSaga(boundSaga);
      }
    }
  }

  register(...handlers: IEventHandler<EventBase>[]) {
    handlers.forEach((handler) => this.registerHandler(handler));
  }

  protected registerHandler(handler: IEventHandler<EventBase>) {
    const events = Array.isArray(handler.event) ? handler.event : [handler.event];
    events.forEach((event) => this.bind(event, handler));
  }

  protected ofEvent(targetEvent: Type<EventBase>) {
    return this.subject$.pipe(filter((event) => event instanceof targetEvent));
  }

  protected registerSaga(saga: ISaga<EventBase>) {
    const stream$ = saga(this);
    const subscription = stream$
      .pipe(
        filter((e) => !!e),
        catchError((error) => {
          if (this.options?.rethrowUnhandled) {
            throw error;
          }

          const unhandledError = this.mapToUnhandledErrorInfo(saga.name, error);
          this.unhandledExceptionBus.publish(unhandledError);
          console.error(`Saga "${saga.name}" has thrown an unhandled exception.`, error);
          return of();
        }),
        mergeMap((command) =>
          defer(() => this.commandBus.execute(command)).pipe(
            catchError((error) => {
              if (this.options?.rethrowUnhandled) {
                throw error;
              }

              const unhandledError = this.mapToUnhandledErrorInfo(command, error);
              this.unhandledExceptionBus.publish(unhandledError);
              console.error(
                `Command handler which execution was triggered by Saga has thrown an unhandled exception.`,
                error,
              );
              return of();
            }),
          ),
        ),
      )
      .subscribe();

    this.subscriptions.push(subscription);
  }

  private mapToUnhandledErrorInfo(
    eventOrCommand: IEvent | ICommand | string,
    exception: unknown,
  ): UnhandledExceptionInfo {
    return {
      cause: eventOrCommand,
      exception,
    };
  }
}
