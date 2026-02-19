import type { EventBus } from "@/event-bus";
import type { ICommandHandler } from "@/interfaces";
import { UnhandledExceptionEvent } from "./unhandled-exception.event";

export class UnhandledExceptionCommand {
  constructor(public readonly failAt: "command" | "event" | "saga") {}
}

export class UnhandledExceptionCommandHandler implements ICommandHandler<UnhandledExceptionCommand> {
  readonly command = UnhandledExceptionCommand;

  constructor(private readonly eventBus: EventBus) {}

  async execute(command: UnhandledExceptionCommand) {
    if (command.failAt === "command") {
      throw new Error(`Unhandled exception in ${command.failAt}`);
    } else {
      this.eventBus.publish(new UnhandledExceptionEvent(command.failAt));
    }
  }
}
