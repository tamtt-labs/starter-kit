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

type CqrsModule = ReturnType<typeof Cqrs.createModule>;

type CqrsRegistration = {
  commands?: ICommandHandler[];
  events?: IEventHandler[];
  queries?: IQueryHandler[];
  sagas?: ISagaProvider[];
  aggregateRoots?: Type<AggregateRoot>[];
};

type CqrsModuleInjectedElysia = {
  decorator: {
    commandBus: CommandBus;
    eventBus: EventBus;
    eventPublisher: EventPublisher;
    queryBus: QueryBus;
    unhandledExceptionBus: UnhandledExceptionBus;
  };
};

export class Cqrs {
  static createModule(options?: CqrsOptions & { name?: string }) {
    const commandBus = new CommandBus(options);
    const unhandledExceptionBus = new UnhandledExceptionBus(options);
    const eventBus = new EventBus(commandBus, unhandledExceptionBus, options);
    const eventPublisher = new EventPublisher(eventBus);
    const queryBus = new QueryBus(options);

    return new Elysia({ name: options?.name ?? "CqrsModule" })
      .decorate({
        commandBus,
        eventBus,
        eventPublisher,
        queryBus,
        unhandledExceptionBus,
      })
      .onStop((app) => app.decorator.eventBus.destroy());
  }

  static register({ commands, events, queries, sagas, aggregateRoots }: CqrsRegistration) {
    return <T extends CqrsModuleInjectedElysia>(app: T) => {
      assertCqrsModuleInjected(app);
      return app.decorate((decorator) => {
        decorator.commandBus.register(...(commands ?? []));
        decorator.eventBus.register(...(events ?? []));
        decorator.queryBus.register(...(queries ?? []));
        decorator.eventBus.registerSagas(...(sagas ?? []));
        mergeContext(decorator.eventBus, aggregateRoots);
        return decorator;
      });
    };
  }

  static registerCommands(...commands: ICommandHandler[]) {
    return <T extends CqrsModuleInjectedElysia>(app: T) => {
      assertCqrsModuleInjected(app);
      return app.decorate((decorator) => {
        assertCqrsModuleInjected(app);
        decorator.commandBus.register(...(commands ?? []));
        return decorator;
      });
    };
  }

  static registerEvents(...events: IEventHandler[]) {
    return <T extends CqrsModuleInjectedElysia>(app: T) => {
      assertCqrsModuleInjected(app);
      return app.decorate((decorator) => {
        decorator.eventBus.register(...(events ?? []));
        return decorator;
      });
    };
  }

  static registerQueries(...queries: IQueryHandler[]) {
    return <T extends CqrsModuleInjectedElysia>(app: T) => {
      assertCqrsModuleInjected(app);
      return app.decorate((decorator) => {
        assertCqrsModuleInjected(app);
        decorator.queryBus.register(...(queries ?? []));
        return decorator;
      });
    };
  }

  static registerSagas(...sagas: ISagaProvider[]) {
    return <T extends CqrsModuleInjectedElysia>(app: T) => {
      assertCqrsModuleInjected(app);
      return app.decorate((decorator) => {
        assertCqrsModuleInjected(app);
        decorator.eventBus.registerSagas(...(sagas ?? []));
        return decorator;
      });
    };
  }

  static registerAggregateRoots(...aggregateRoots: Type<AggregateRoot>[]) {
    return <T extends CqrsModuleInjectedElysia>(app: T) => {
      assertCqrsModuleInjected(app);
      return app.decorate((decorator) => {
        assertCqrsModuleInjected(app);
        mergeContext(decorator.eventBus, aggregateRoots);
        return decorator;
      });
    };
  }
}

function assertCqrsModuleInjected(app: unknown): asserts app is CqrsModule {
  const isCqrsModuleInjected =
    app instanceof Elysia &&
    "commandBus" in app.decorator &&
    "eventBus" in app.decorator &&
    "eventPublisher" in app.decorator &&
    "queryBus" in app.decorator &&
    "unhandledExceptionBus" in app.decorator;

  if (!isCqrsModuleInjected) {
    throw new Error(
      "CqrsModule must be created with Cqrs.createModule() and injected to the Elysia app",
    );
  }
}
