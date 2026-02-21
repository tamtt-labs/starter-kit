import { Command, Query } from "@/classes";
import type { ICommandHandler } from "@/interfaces";
import { describe, expect, it } from "bun:test";
import { AppModule } from "./modules/app.module";

describe("Generics", () => {
  const commandBus = AppModule.decorator.commandBus;
  const queryBus = AppModule.decorator.queryBus;

  describe("Commands", () => {
    describe('when "Command" utility class is used', () => {
      it("should infer return type", async () => {
        const command = new Command<string>();

        try {
          await commandBus.execute(command).then((value) => {
            value as string;

            // @ts-expect-error
            value as number;
          });
        } catch (err) {
          // Do nothing
        } finally {
          expect(true).toBeTruthy();
        }
      });
    });

    describe("when any other class is used", () => {
      it("should fallback to any return type", async () => {
        class MyCommand {}

        const command = new MyCommand();

        try {
          await commandBus.execute(command).then((value) => {
            value as string;
            value as number;
          });
        } catch (err) {
          // Do nothing
        } finally {
          expect(true).toBeTruthy();
        }
      });

      it("should use the 2nd generic parameter as return type", async () => {
        class MyCommand {}

        const command = new MyCommand();

        try {
          await commandBus.execute<MyCommand, string>(command).then((value) => {
            value as string;

            // @ts-expect-error
            value as number;
          });
        } catch (err) {
          // Do nothing
        } finally {
          expect(true).toBeTruthy();
        }
      });
    });
  });

  describe("Queries", () => {
    describe('when "Query" utility class is used', () => {
      it("should infer return type", async () => {
        const query = new Query<string>();

        try {
          await queryBus.execute(query).then((value) => {
            value as string;

            // @ts-expect-error
            value as number;
          });
        } catch (err) {
          // Do nothing
        } finally {
          expect(true).toBeTruthy();
        }
      });
    });

    describe("when any other class is used", () => {
      it("should fallback to any return type", async () => {
        class MyQuery {}

        const query = new MyQuery();

        try {
          await queryBus.execute(query).then((value) => {
            value as string;
            value as number;
          });
        } catch (err) {
          // Do nothing
        } finally {
          expect(true).toBeTruthy();
        }
      });

      it("should use the 2nd generic parameter as return type", async () => {
        class MyQuery {}

        const query = new MyQuery();

        try {
          await queryBus.execute<MyQuery, string>(query).then((value) => {
            value as string;

            // @ts-expect-error
            value as number;
          });
        } catch (err) {
          // Do nothing
        } finally {
          expect(true).toBeTruthy();
        }
      });
    });
  });

  describe("Command handlers", () => {
    it("should infer return type", async () => {
      class Test extends Command<{
        value: string;
      }> {}

      class ValidHandler implements ICommandHandler<Test> {
        readonly command = Test;

        execute(_command: Test): Promise<{ value: string }> {
          throw new Error("Method not implemented.");
        }
      }

      class InvalidHandler implements ICommandHandler<Test> {
        readonly command = Test;

        // @ts-expect-error
        execute(_command: Test): Promise<{ value: number }> {
          throw new Error("Method not implemented.");
        }
      }

      try {
        commandBus.register(new ValidHandler(), new InvalidHandler());

        await commandBus.execute(new Test()).then((value) => {
          // oxlint-disable-next-line no-unused-expressions
          value.value as string;

          // @ts-expect-error
          // oxlint-disable-next-line no-unused-expressions
          value as number;
        });
      } catch (err) {
        // Do nothing
      } finally {
        expect(true).toBeTruthy();
      }
    });
  });
});
