import { base } from "@/base";
import { defineConfig } from "tsdown";

export default defineConfig({
  ...base,
  external: ["tsdown", "babel-plugin-react-compiler"],
});
