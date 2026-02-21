import { Command } from "./classes";
import { CommandHandlerNotFoundException } from "./exceptions/command-not-found.exception";
import { DefaultCommandPubSub } from "./helpers/default-command-pubsub";
import type {
  CqrsOptions,
  ICommand,
  ICommandBus,
  ICommandHandler,
  ICommandPublisher,
  Type,
} from "./interfaces";
import { ObservableBus } from "./utils/observable-bus";

export type CommandProvider<CommandBase extends ICommand = ICommand> = {
  command: Type<CommandBase>;
  handler: ICommandHandler<CommandBase>;
};
/**
 * @publicApi
 */
export class CommandBus<CommandBase extends ICommand = ICommand>
  extends ObservableBus<CommandBase>
  implements ICommandBus<CommandBase>
{
  private handlers = new Map<Type<CommandBase>, ICommandHandler<CommandBase>["execute"]>();
  private _publisher: ICommandPublisher<CommandBase>;

  constructor(private readonly options?: CqrsOptions) {
    super();

    if (this.options?.commandPublisher) {
      this._publisher = this.options.commandPublisher;
    } else {
      this._publisher = new DefaultCommandPubSub<CommandBase>(this.subject$);
    }
  }

  /**
   * Returns the publisher.
   * Default publisher is `DefaultCommandPubSub` (in memory).
   */
  get publisher(): ICommandPublisher<CommandBase> {
    return this._publisher;
  }

  /**
   * Sets the publisher.
   * Default publisher is `DefaultCommandPubSub` (in memory).
   * @param _publisher The publisher to set.
   */
  set publisher(_publisher: ICommandPublisher<CommandBase>) {
    this._publisher = _publisher;
  }

  /**
   * Executes a command.
   * @param command The command to execute.
   * @returns A promise that, when resolved, will contain the result returned by the command's handler.
   */
  execute<R = void>(command: Command<R>): Promise<R>;
  /**
   * Executes a command.
   * @param command The command to execute.
   * @returns A promise that, when resolved, will contain the result returned by the command's handler.
   */
  execute<T extends CommandBase, R = any>(command: T): Promise<R>;
  execute<T extends CommandBase, R = any>(command: T): Promise<R> {
    const commandType = command.constructor as Type<CommandBase>;
    const executeFn = this.handlers.get(commandType);
    if (!executeFn) {
      throw new CommandHandlerNotFoundException(commandType.name);
    }
    this._publisher.publish(command);
    return executeFn(command as T & Command<unknown>);
  }

  register(...handlers: ICommandHandler<CommandBase>[]) {
    handlers.forEach((handler) => this.registerHandler(handler));
  }

  protected registerHandler(handler: ICommandHandler<CommandBase>) {
    if (this.handlers.has(handler.command)) {
      console.warn(
        `Command handler [${handler.command.name}] is already registered. Overriding previously registered handler.`,
      );
    }

    this.handlers.set(handler.command, handler.execute.bind(handler));
  }
}
