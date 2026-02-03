import * as TsdownPrimitives from "tsdown";

export const defineConfig = (userConfig?: TsdownPrimitives.UserConfig) => {
  return TsdownPrimitives.defineConfig(
    (inlineConfig) =>
      ({
        ...userConfig,
        minify: !inlineConfig.watch,
        clean: !inlineConfig.watch,
        exports: !inlineConfig.watch,
        skipNodeModulesBundle: inlineConfig.watch,
      }) as TsdownPrimitives.UserConfig,
  );
};
