import type { IEventHandler } from "@/interfaces";
import { UnhandledExceptionEvent } from "./unhandled-exception.event";

export class UnhandledExceptionEventHandler implements IEventHandler<UnhandledExceptionEvent> {
  readonly event = UnhandledExceptionEvent;

  async handle(event: UnhandledExceptionEvent) {
    if (event.failAt === "event") {
      throw new Error(`Unhandled exception in ${event.failAt}`);
    }
  }
}
