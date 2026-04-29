import { base } from "@tamtt-labs/tsdown";
import { defineConfig, mergeConfig } from "tsdown";

export default defineConfig((inlineConfig, context) =>
  mergeConfig(base(inlineConfig, context), {
    entry: ["src/index.ts", "src/adapters/elysia.ts"],
    deps: {
      neverBundle: ["elysia"],
    },
  }),
);
