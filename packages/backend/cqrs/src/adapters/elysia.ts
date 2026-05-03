import type { AggregateRoot } from "@/aggregate-root";
import { Cqrs as CqrsCore, type CqrsRegistration } from "../cqrs";
import { Elysia } from "elysia";
import type {
  CqrsOptions,
  ICommandHandler,
  IEventHandler,
  IQueryHandler,
  ISagaProvider,
  Type,
} from "../interfaces";

export class Cqrs {
  static createModule(options?: CqrsOptions & { name?: string }) {
    const cqrsCore = new CqrsCore(options);

    const cqrsModule = new Elysia({ name: options?.name ?? "CqrsModule" })
      .decorate({
        commandBus: cqrsCore.commandBus,
        eventBus: cqrsCore.eventBus,
        eventPublisher: cqrsCore.eventPublisher,
        queryBus: cqrsCore.queryBus,
        unhandledExceptionBus: cqrsCore.unhandledExceptionBus,
      })
      .onStop((app) => app.decorator.eventBus.destroy());

    const register = (cqrsRegistration: CqrsRegistration) => {
      return <T>(app: T) => {
        assertElysia(app);
        cqrsCore.register(cqrsRegistration);
        return app.use(cqrsModule);
      };
    };

    const registerCommands = (...commands: ICommandHandler[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        cqrsCore.registerCommands(...commands);
        return app.use(cqrsModule);
      };
    };

    const registerEvents = (...events: IEventHandler[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        cqrsCore.registerEvents(...events);
        return app.use(cqrsModule);
      };
    };

    const registerQueries = (...queries: IQueryHandler[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        cqrsCore.registerQueries(...queries);
        return app.use(cqrsModule);
      };
    };

    const registerSagas = (...sagas: ISagaProvider[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        cqrsCore.registerSagas(...sagas);
        return app.use(cqrsModule);
      };
    };

    const registerAggregateRoots = (...aggregateRoots: Type<AggregateRoot>[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        cqrsCore.registerAggregateRoots(...aggregateRoots);
        return app.use(cqrsModule);
      };
    };

    return Object.assign(cqrsModule, {
      register,
      registerCommands,
      registerEvents,
      registerQueries,
      registerSagas,
      registerAggregateRoots,
    });
  }
}

const assertElysia: (app: unknown) => asserts app is Elysia = (app) => {
  const isElysia = app instanceof Elysia;
  if (!isElysia) {
    throw new Error("App is not an Elysia instance");
  }
};
