import { Query } from "./classes/query";
import { QueryHandlerNotFoundException } from "./exceptions";
import { DefaultQueryPubSub } from "./helpers/default-query-pubsub";
import type { IQuery, IQueryBus, IQueryHandler, IQueryPublisher, Type } from "./interfaces";
import type { CqrsOptions } from "./interfaces/cqrs-options.interface";
import { ObservableBus } from "./utils/observable-bus";

export type QueryProvider<QueryBase extends IQuery = IQuery> = {
  query: Type<QueryBase>;
  handler: IQueryHandler<QueryBase>;
};

/**
 * @publicApi
 */
export class QueryBus<QueryBase extends IQuery = IQuery>
  extends ObservableBus<QueryBase>
  implements IQueryBus<QueryBase>
{
  private handlers = new Map<Type<QueryBase>, IQueryHandler<QueryBase>["execute"]>();
  private _publisher: IQueryPublisher<QueryBase>;

  constructor(private readonly options?: CqrsOptions) {
    super();

    if (this.options?.queryPublisher) {
      this._publisher = this.options.queryPublisher;
    } else {
      this._publisher = new DefaultQueryPubSub<QueryBase>(this.subject$);
    }
  }

  /**
   * Returns the publisher.
   */
  get publisher(): IQueryPublisher<QueryBase> {
    return this._publisher;
  }

  /**
   * Sets the publisher.
   * Default publisher is `DefaultQueryPubSub` (in memory).
   * @param _publisher The publisher to set.
   */
  set publisher(_publisher: IQueryPublisher<QueryBase>) {
    this._publisher = _publisher;
  }

  /**
   * Executes a query.
   * @param query The query to execute.
   */
  execute<TResult>(query: Query<TResult>): Promise<TResult>;
  /**
   * Executes a query.
   * @param query The query to execute.
   */
  execute<T extends QueryBase, TResult = any>(query: T): Promise<TResult>;
  execute<T extends QueryBase, TResult = any>(query: T): Promise<TResult> {
    const queryType = query.constructor as Type<QueryBase>;
    const executeFn = this.handlers.get(queryType);
    if (!executeFn) {
      throw new QueryHandlerNotFoundException(queryType.name);
    }
    this._publisher.publish(query);
    return executeFn(query as T & Query<unknown>) as Promise<TResult>;
  }

  register(...handlers: IQueryHandler<QueryBase>[]) {
    handlers.forEach((handler) => this.registerHandler(handler));
  }

  protected registerHandler(handler: IQueryHandler<QueryBase>) {
    if (this.handlers.has(handler.query)) {
      console.warn(
        `Query handler [${handler.query.name}] is already registered. Overriding previously registered handler.`,
      );
    }

    this.handlers.set(handler.query, handler.execute.bind(handler));
  }
}
