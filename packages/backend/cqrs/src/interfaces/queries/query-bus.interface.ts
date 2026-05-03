import type { IQuery } from "./query.interface";

import { Query } from "../../classes/query";

/**
 * Represents a query bus.
 *
 * @publicApi
 */
export interface IQueryBus<QueryBase extends IQuery = IQuery> {
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
}
