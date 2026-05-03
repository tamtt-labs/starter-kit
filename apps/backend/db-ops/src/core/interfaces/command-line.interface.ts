import type { Command as Cli } from "commander";

export abstract class ICommandLine<TArgs extends any = any> {
  public abstract register(cli: Cli): void;
  public abstract parseArgs(args: unknown): TArgs;

  protected parseRepeatable(value: string, previous: string[]): string[] {
    return previous.concat([value]);
  }
}
