import { Command } from "../../classes";
import type { Type } from "../type.interface";
import type { ICommand } from "./command.interface";

/**
 * Represents a command handler.
 * Command handlers are used to execute commands.
 *
 * @publicApi
 */
type CommandHandlerResult<TCommand extends ICommand, TResult> =
  TCommand extends Command<infer InferredCommandResult> ? InferredCommandResult : TResult;

export abstract class ICommandHandler<TCommand extends ICommand = any, TResult = any> {
  /**
   * Executes a command.
   * @param command The command to execute.
   */
  abstract execute(command: TCommand): Promise<CommandHandlerResult<TCommand, TResult>>;
  /**
   * The command type that this handler handles.
   */
  abstract readonly command: Type<TCommand>;
}
