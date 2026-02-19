import { ErrorsSagas } from "@/__tests__/src/error/error.saga";
import { UnhandledExceptionCommandHandler } from "@/__tests__/src/error/unhandled-exception.command";
import { UnhandledExceptionEventHandler } from "@/__tests__/src/error/unhandled-exception.event-handler";
import { Cqrs } from "@/adapters/elysia";
import Elysia from "elysia";
import { CqrsModule } from "./cqrs.module";

const UnhandledExceptionCommandPlugin = new Elysia()
  .use(CqrsModule)
  .use((app) =>
    Cqrs.registerCommands(new UnhandledExceptionCommandHandler(app.decorator.eventBus))(app),
  );

const UnhandledExceptionEventPlugin = new Elysia()
  .use(CqrsModule)
  .use(Cqrs.registerEvents(new UnhandledExceptionEventHandler()));

const ErrorsSagasPlugin = new Elysia().use(CqrsModule).use(Cqrs.registerSagas(new ErrorsSagas()));

export const ErrorModule = new Elysia()
  .use(CqrsModule)
  .use(UnhandledExceptionCommandPlugin)
  .use(UnhandledExceptionEventPlugin)
  .use(ErrorsSagasPlugin);
