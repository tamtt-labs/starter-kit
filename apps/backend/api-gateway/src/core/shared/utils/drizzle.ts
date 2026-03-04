import { drizzle } from "drizzle-orm/bun-sql";
import Elysia from "elysia";

type DrizzleOptions = {
  client: Bun.SQL;
  casing?: "snake_case" | "camelCase";
};

type DrizzleModule = ReturnType<typeof Drizzle.createModule>;

type DrizzleModuleInjectedElysia = {
  decorator: {
    [key: string]: DrizzleOptions;
  };
};

export class Drizzle {
  static createModule(options: DrizzleOptions & { name?: string }) {
    const name = options?.name ?? "DrizzleModule";
    return new Elysia({ name }).decorate(name, options);
  }

  static register<
    const TName extends string,
    TSchema extends Record<string, unknown> = Record<string, never>,
  >(name: TName, schema: TSchema) {
    return <TApp extends DrizzleModuleInjectedElysia>(app: TApp) => {
      assertDrizzleModuleInjected(app);
      return app.use(({ decorator }) =>
        new Elysia({ name: name }).decorate(
          name,
          drizzle({
            client: decorator[String(app.config.name)]!.client,
            casing: decorator[String(app.config.name)]!.casing ?? "snake_case",
            schema,
          }),
        ),
      );
    };
  }
}

function assertDrizzleModuleInjected(app: unknown): asserts app is DrizzleModule {
  const isDrizzleModuleInjected = app instanceof Elysia && String(app.config.name) in app.decorator;

  if (!isDrizzleModuleInjected) {
    throw new Error(
      "DrizzleModule must be created with Drizzle.createModule() and injected to the Elysia app",
    );
  }
}
