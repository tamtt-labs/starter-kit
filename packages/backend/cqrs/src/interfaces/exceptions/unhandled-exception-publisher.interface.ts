import type { ICommand } from "../commands/command.interface";
import type { IEvent } from "../events/event.interface";
import type { UnhandledExceptionInfo } from "./unhandled-exception-info.interface";

export interface IUnhandledExceptionPublisher<CauseBase = IEvent | ICommand, ExceptionBase = any> {
  /**
   * Publishes an unhandled exception.
   * @param info The exception information.
   */
  publish(info: UnhandledExceptionInfo<CauseBase, ExceptionBase>): any;
}
