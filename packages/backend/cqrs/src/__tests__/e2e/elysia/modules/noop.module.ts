import { NoopHandler } from "@/__tests__/src/noop/noop.event-handler";
import Elysia from "elysia";
import { CqrsModule } from "./cqrs.module";

export const NoopModule = new Elysia().use(CqrsModule.registerEvents(new NoopHandler()));
