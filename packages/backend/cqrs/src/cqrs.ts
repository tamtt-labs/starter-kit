import { CommandBus } from "@/command-bus";
import type {
  CqrsOptions,
  ICommandHandler,
  IEventHandler,
  IQueryHandler,
  ISagaProvider,
  Type,
} from "./interfaces";
import { QueryBus } from "./query-bus";
import { UnhandledExceptionBus } from "./unhandled-exception-bus";
import { EventBus } from "./event-bus";
import { EventPublisher } from "./event-publisher";
import type { AggregateRoot } from "./aggregate-root";
import { mergeContext } from "./utils";

export type CqrsRegistration = {
  commands?: ICommandHandler[];
  events?: IEventHandler[];
  queries?: IQueryHandler[];
  sagas?: ISagaProvider[];
  aggregateRoots?: Type<AggregateRoot>[];
};

export class Cqrs {
  public readonly queryBus: QueryBus;
  public readonly eventBus: EventBus;
  public readonly commandBus: CommandBus;
  public readonly eventPublisher: EventPublisher;
  public readonly unhandledExceptionBus: UnhandledExceptionBus;

  constructor(options?: CqrsOptions) {
    this.commandBus = new CommandBus(options);
    this.queryBus = new QueryBus(options);
    this.unhandledExceptionBus = new UnhandledExceptionBus(options);
    this.eventBus = new EventBus(this.commandBus, this.unhandledExceptionBus, options);
    this.eventPublisher = new EventPublisher(this.eventBus);
  }

  public register({ commands, events, queries, sagas, aggregateRoots }: CqrsRegistration) {
    this.commandBus.register(...(commands ?? []));
    this.eventBus.register(...(events ?? []));
    this.queryBus.register(...(queries ?? []));
    this.eventBus.registerSagas(...(sagas ?? []));
    mergeContext(this.eventBus, aggregateRoots);
  }

  public registerCommands(...commands: ICommandHandler[]) {
    this.commandBus.register(...commands);
  }

  public registerEvents(...events: IEventHandler[]) {
    this.eventBus.register(...events);
  }

  public registerQueries(...queries: IQueryHandler[]) {
    this.queryBus.register(...queries);
  }

  public registerSagas(...sagas: ISagaProvider[]) {
    this.eventBus.registerSagas(...sagas);
  }

  public registerAggregateRoots(...aggregateRoots: Type<AggregateRoot>[]) {
    mergeContext(this.eventBus, aggregateRoots);
  }
}
