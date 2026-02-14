import { treaty } from "@elysiajs/eden";
import { describe, expect, it } from "bun:test";
import { app, type App } from ".";

describe("GET /", () => {
  const api = treaty<App>(app);

  it("returns a response", async () => {
    const { data } = await api.get();

    expect(data).toBe("Hello Elysia");
  });
});
