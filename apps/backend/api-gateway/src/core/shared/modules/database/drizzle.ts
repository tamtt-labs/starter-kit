import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import Elysia from "elysia";
import { assertElysia } from "../../utils/assert-elysia";
import type { DrizzleFactory } from "./drizzle-factory/drizzle-factory";

type DrizzleOptions = {
  drizzleFactory: DrizzleFactory;
  name?: string;
};

export class Drizzle {
  static createModule(options: DrizzleOptions) {
    const moduleName = options.name ?? "DrizzleModule";
    const drizzleModule = new Elysia({ name: moduleName }).decorate(moduleName, options);

    const register = <
      const TDecoratorName extends string,
      TSchema extends Record<string, unknown> = Record<string, never>,
    >(
      decoratorName: TDecoratorName,
      schema: TSchema,
    ) => {
      return <TApp>(app: TApp) => {
        assertElysia(app);

        type DrizzleContext = {
          [name in TDecoratorName]: PgDatabase<PgQueryResultHKT, TSchema>;
        };

        return app.use(drizzleModule).use(({ decorator }) =>
          new Elysia({ name: decoratorName })
            .decorate(() => decorator)
            .resolve<DrizzleContext, "global">({ as: "global" }, () => {
              const drizzle = decorator[moduleName]!.drizzleFactory.createDrizzle(schema);
              return { [decoratorName]: drizzle } as DrizzleContext;
            }),
        );
      };
    };

    return Object.assign(drizzleModule, { register });
  }
}
