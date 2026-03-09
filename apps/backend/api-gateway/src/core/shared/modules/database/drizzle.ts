import { drizzle } from "drizzle-orm/bun-sql";
import Elysia from "elysia";
import { assertElysia } from "../../utils/assert-elysia";

type DrizzleOptions = {
  client: Bun.SQL;
  casing?: "snake_case" | "camelCase";
};

export class Drizzle {
  static createModule(options: DrizzleOptions & { name?: string }) {
    const moduleName = options?.name ?? "DrizzleModule";
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
        return app.use(drizzleModule).use(({ decorator }) =>
          new Elysia({ name: decoratorName })
            .decorate(() => decorator)
            .decorate(
              decoratorName,
              drizzle({
                client: decorator[moduleName]!.client,
                casing: decorator[moduleName]!.casing ?? "snake_case",
                schema,
              }),
            ),
        );
      };
    };

    return Object.assign(drizzleModule, { register });
  }
}
