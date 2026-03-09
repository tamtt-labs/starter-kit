import Elysia from "elysia";

export const assertElysia: (app: unknown) => asserts app is Elysia = (app) => {
  const isElysia = app instanceof Elysia;
  if (!isElysia) {
    throw new Error("App is not an Elysia instance");
  }
};
