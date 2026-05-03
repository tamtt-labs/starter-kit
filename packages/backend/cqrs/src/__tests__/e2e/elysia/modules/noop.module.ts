import Elysia from "elysia";

import { NoopHandler } from "@/__tests__/src/noop/noop.event-handler";

import { CqrsModule } from "./cqrs.module";

export const NoopModule = new Elysia().use(CqrsModule.registerEvents(new NoopHandler()));
