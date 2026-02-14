import { defineConfig } from "tsdown";
import { base } from "./src";

export default defineConfig({
  ...base,
  external: ["tsdown", "babel-plugin-react-compiler"],
});
