import { react } from "@tamtt-labs/tsdown";
import { copyFileSync } from "fs";
import { defineConfig } from "tsdown";

export default defineConfig((inlineConfig, context) => ({
  ...react(inlineConfig, context),
  onSuccess: () => copyFileSync("src/tailwind.css", "dist/tailwind.css"),
  exports: false, // avoid overriding export tailwind.css
}));
