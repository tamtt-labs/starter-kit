import { base } from "@tamtt-labs/tsdown";
import { defineConfig } from "tsdown";

export default defineConfig((inlineConfig, context) => ({
  ...base(inlineConfig, context),
  entry: ["src/index.ts", "src/adapters/elysia.ts"],
  external: ["elysia"],
}));
