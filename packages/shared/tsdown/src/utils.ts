import { mergeConfig, type InlineConfig, type UserConfig } from "tsdown";

type BaseTsdownConfigFn = (
  inlineConfig: InlineConfig,
  context: {
    ci: boolean;
    rootConfig?: UserConfig;
  },
) => UserConfig;

export const defineTsdownConfig = (userConfig?: UserConfig): BaseTsdownConfigFn => {
  return (inlineConfig) =>
    mergeConfig(
      {
        minify: !inlineConfig.watch,
        clean: !inlineConfig.watch,
        exports: !inlineConfig.watch,
        deps: {
          skipNodeModulesBundle: Boolean(inlineConfig.watch),
        },
      },
      userConfig ?? {},
    );
};
