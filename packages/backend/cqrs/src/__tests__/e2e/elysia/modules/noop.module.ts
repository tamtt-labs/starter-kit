import { NoopHandler } from "@/__tests__/src/noop/noop.event-handler";
import { Cqrs } from "@/adapters/elysia";
import Elysia from "elysia";
import { CqrsModule } from "./cqrs.module";

export const NoopModule = new Elysia().use(CqrsModule).use(Cqrs.registerEvents(new NoopHandler()));
