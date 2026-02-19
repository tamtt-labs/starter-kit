import { Observable, filter } from "rxjs";
import { DefaultUnhandledExceptionPubSub } from "./helpers/default-unhandled-exception-pubsub";
import type {
  CqrsOptions,
  ICommand,
  IEvent,
  IUnhandledExceptionPublisher,
  Type,
  UnhandledExceptionInfo,
} from "./interfaces";
import { ObservableBus } from "./utils/observable-bus";

/**
 * A bus that publishes unhandled exceptions.
 * @template Cause The type of the cause of the exception.
 */
export class UnhandledExceptionBus<Cause = IEvent | ICommand> extends ObservableBus<
  UnhandledExceptionInfo<Cause>
> {
  private _publisher: IUnhandledExceptionPublisher<Cause>;

  constructor(private readonly options?: CqrsOptions) {
    super();

    if (this.options?.unhandledExceptionPublisher) {
      this._publisher = this.options
        .unhandledExceptionPublisher as IUnhandledExceptionPublisher<Cause>;
    } else {
      this._publisher = new DefaultUnhandledExceptionPubSub<Cause>(this.subject$);
    }
  }

  /**
   * Filter values depending on their instance type (comparison is made
   * using native `instanceof`).
   *
   * @param types List of types to filter by.
   * @return A stream only emitting the filtered exceptions.
   */
  static ofType<TCause = IEvent | ICommand, TException = unknown>(...types: Type<TException>[]) {
    const isInstanceOf = (
      info: UnhandledExceptionInfo<TCause, unknown>,
    ): info is UnhandledExceptionInfo<TCause, TException> =>
      types.some((classType) => info.exception instanceof classType);

    return (
      source: Observable<UnhandledExceptionInfo<TCause, unknown>>,
    ): Observable<UnhandledExceptionInfo<TCause, TException>> => source.pipe(filter(isInstanceOf));
  }

  /**
   * Gets the publisher of the bus.
   */
  get publisher(): IUnhandledExceptionPublisher<Cause> {
    return this._publisher;
  }

  /**
   * Sets the publisher of the bus.
   */
  set publisher(_publisher: IUnhandledExceptionPublisher<Cause>) {
    this._publisher = _publisher;
  }

  /**
   * Publishes an unhandled exception.
   * @param info The exception information.
   */
  publish(info: UnhandledExceptionInfo<Cause>) {
    return this._publisher.publish(info);
  }
}
