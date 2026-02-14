import type { UserConfig, UserConfigFn } from "tsdown";

export const defineTsdownConfig = (userConfig?: UserConfig): UserConfigFn => {
  return (inlineConfig) => ({
    minify: !inlineConfig.watch,
    clean: !inlineConfig.watch,
    exports: !inlineConfig.watch,
    skipNodeModulesBundle: Boolean(inlineConfig.watch),
    ...userConfig,
  });
};
