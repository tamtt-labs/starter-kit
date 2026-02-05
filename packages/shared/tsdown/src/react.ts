import pluginBabel from "@rollup/plugin-babel";
import { defineTsdownConfig } from "./utils";

export const react = defineTsdownConfig({
  platform: "neutral",
  plugins: [
    pluginBabel({
      babelHelpers: "bundled",
      parserOpts: {
        sourceType: "module",
        plugins: ["jsx", "typescript"],
      },
      plugins: ["babel-plugin-react-compiler"],
      extensions: [".js", ".jsx", ".ts", ".tsx"],
    }),
  ],
});
