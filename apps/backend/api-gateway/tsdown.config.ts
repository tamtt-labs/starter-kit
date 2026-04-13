import { base } from "@tamtt-labs/tsdown";
import { defineConfig, mergeConfig } from "tsdown";

export default defineConfig((inlineConfig, context) =>
  mergeConfig(
    {
      entry: ["src/index.ts"],
      platform: "neutral", // Generate .d.ts instead of .d.mts
      clean: false, // Avoid removing the dist directory
      dts: { emitDtsOnly: true }, // Only emit .d.ts files
      exports: false,
      deps: {
        onlyBundle: false,
      },
    },
    base(inlineConfig, context),
  ),
);
