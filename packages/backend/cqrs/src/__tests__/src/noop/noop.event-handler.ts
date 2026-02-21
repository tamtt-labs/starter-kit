import type { IEventHandler } from "@/interfaces";
import { NoopEvent } from "./noop.event";

export class NoopHandler implements IEventHandler<NoopEvent> {
  readonly event = NoopEvent;

  handle(event: NoopEvent) {
    console.log("🚀 ~ NoopHandler ~ handle ~ event:", event.constructor.name);
  }
}
