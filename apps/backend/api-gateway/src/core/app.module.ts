import { Elysia } from "elysia";

export const AppModule = new Elysia();

export type App = typeof AppModule;
