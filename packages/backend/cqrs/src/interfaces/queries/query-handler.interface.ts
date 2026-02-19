import { Query } from "../../classes";
import type { Type } from "../type.interface";
import type { IQuery } from "./query.interface";

/**
 * Represents a query handler.
 *
 * @publicApi
 */
type QueryHandlerResult<TQuery extends IQuery, TResult> =
  TQuery extends Query<infer InferredQueryResult> ? InferredQueryResult : TResult;

export abstract class IQueryHandler<TQuery extends IQuery = any, TResult = any> {
  /**
   * Executes a query.
   * @param query The query to execute.
   */
  abstract execute(query: TQuery): Promise<QueryHandlerResult<TQuery, TResult>>;
  abstract readonly query: Type<TQuery>;
}
