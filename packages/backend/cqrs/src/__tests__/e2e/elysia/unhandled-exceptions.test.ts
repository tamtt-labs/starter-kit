import { UnhandledExceptionCommand } from "@/__tests__/src/error/unhandled-exception.command";
import { UnhandledExceptionEvent } from "@/__tests__/src/error/unhandled-exception.event";
import { describe, expect, it } from "bun:test";
import { take } from "rxjs";
import { AppModule } from "./modules/app.module";

describe("Unhandled exceptions", () => {
  const commandBus = AppModule.decorator.commandBus;
  const unhandledExceptionBus = AppModule.decorator.unhandledExceptionBus;

  describe("when exception is thrown from command handler", () => {
    it("should rethrow the exception", async () => {
      const command = new UnhandledExceptionCommand("command");
      expect(commandBus.execute(command)).rejects.toThrow(
        new Error(`Unhandled exception in ${command.failAt}`),
      );
    });
  });

  describe("when exception is thrown from event handler", () => {
    it("should forward exception to UnhandledExceptionBus", (done) => {
      const command = new UnhandledExceptionCommand("event");

      unhandledExceptionBus.pipe(take(1)).subscribe((exceptionInfo) => {
        expect(exceptionInfo.exception).toEqual(
          new Error(`Unhandled exception in ${command.failAt}`),
        );
        expect(exceptionInfo.cause).toBeInstanceOf(UnhandledExceptionEvent);
        done();
      });

      commandBus.execute(command).catch((err) => done(err));
    });
  });

  describe("when exception is thrown from saga", () => {
    it("should forward exception to UnhandledExceptionBus", (done) => {
      const command = new UnhandledExceptionCommand("saga");

      unhandledExceptionBus.pipe(take(1)).subscribe((exceptionInfo) => {
        expect(exceptionInfo.exception).toEqual(
          new Error(`Unhandled exception in ${command.failAt}`),
        );
        expect(exceptionInfo.cause).toContain("onError");
        done();
      });

      commandBus.execute(command).catch((err) => done(err));
    });
  });
});
