import { defineTsdownConfig } from "./src/utils";

export default defineTsdownConfig({
  deps: {
    neverBundle: ["tsdown", "babel-plugin-react-compiler"],
  },
});
