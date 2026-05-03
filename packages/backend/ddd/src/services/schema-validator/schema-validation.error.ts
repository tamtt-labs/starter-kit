export class SchemaValidationError extends Error {
  constructor(
    public readonly message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = "SchemaValidationError";
  }
}
