import { base } from "@tamtt-labs/tsdown";
import { defineConfig } from "tsdown";

export default defineConfig((inlineConfig, context) => ({
  ...base(inlineConfig, context),
  entry: ["src/index.ts"],
  platform: "neutral", // Generate .d.ts instead of .d.mts
  clean: false, // Avoid removing the dist directory
  dts: { emitDtsOnly: true }, // Only emit .d.ts files
  exports: false,
  inlineOnly: false,
}));
