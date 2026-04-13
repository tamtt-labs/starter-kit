import { Cqrs } from "@tamtt-labs/cqrs/adapters/elysia";

export type * from "@tamtt-labs/cqrs";

export const CqrsModule = Cqrs.createModule({ name: "CqrsModule" });
