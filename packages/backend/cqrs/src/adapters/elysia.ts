import type { AggregateRoot } from "@/aggregate-root";
import { CommandBus } from "@/command-bus";
import { EventBus } from "@/event-bus";
import { EventPublisher } from "@/event-publisher";
import { QueryBus } from "@/query-bus";
import { UnhandledExceptionBus } from "@/unhandled-exception-bus";
import { mergeContext } from "@/utils";
import { Elysia } from "elysia";
import type {
  CqrsOptions,
  ICommandHandler,
  IEventHandler,
  IQueryHandler,
  ISagaProvider,
  Type,
} from "../interfaces";

type CqrsRegistration = {
  commands?: ICommandHandler[];
  events?: IEventHandler[];
  queries?: IQueryHandler[];
  sagas?: ISagaProvider[];
  aggregateRoots?: Type<AggregateRoot>[];
};

export class Cqrs {
  static createModule(options?: CqrsOptions & { name?: string }) {
    const commandBus = new CommandBus(options);
    const unhandledExceptionBus = new UnhandledExceptionBus(options);
    const eventBus = new EventBus(commandBus, unhandledExceptionBus, options);
    const eventPublisher = new EventPublisher(eventBus);
    const queryBus = new QueryBus(options);

    const cqrsModule = new Elysia({ name: options?.name ?? "CqrsModule" })
      .decorate({
        commandBus,
        eventBus,
        eventPublisher,
        queryBus,
        unhandledExceptionBus,
      })
      .onStop((app) => app.decorator.eventBus.destroy());

    const register = ({ commands, events, queries, sagas, aggregateRoots }: CqrsRegistration) => {
      return <T>(app: T) => {
        assertElysia(app);
        return app.use(cqrsModule).decorate((decorator) => {
          decorator.commandBus.register(...(commands ?? []));
          decorator.eventBus.register(...(events ?? []));
          decorator.queryBus.register(...(queries ?? []));
          decorator.eventBus.registerSagas(...(sagas ?? []));
          mergeContext(decorator.eventBus, aggregateRoots);
          return decorator;
        });
      };
    };

    const registerCommands = (...commands: ICommandHandler[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        return app.use(cqrsModule).decorate((decorator) => {
          decorator.commandBus.register(...(commands ?? []));
          return decorator;
        });
      };
    };

    const registerEvents = (...events: IEventHandler[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        return app.use(cqrsModule).decorate((decorator) => {
          decorator.eventBus.register(...(events ?? []));
          return decorator;
        });
      };
    };

    const registerQueries = (...queries: IQueryHandler[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        return app.use(cqrsModule).decorate((decorator) => {
          decorator.queryBus.register(...(queries ?? []));
          return decorator;
        });
      };
    };

    const registerSagas = (...sagas: ISagaProvider[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        return app.use(cqrsModule).decorate((decorator) => {
          decorator.eventBus.registerSagas(...(sagas ?? []));
          return decorator;
        });
      };
    };

    const registerAggregateRoots = (...aggregateRoots: Type<AggregateRoot>[]) => {
      return <T>(app: T) => {
        assertElysia(app);
        return app.use(cqrsModule).decorate((decorator) => {
          mergeContext(decorator.eventBus, aggregateRoots);
          return decorator;
        });
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
