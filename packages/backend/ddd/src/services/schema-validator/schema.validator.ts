import { SchemaValidationError } from "./schema-validation.error";

export type SafeValidateResult<TData> =
  | { success: true; data: TData }
  | { success: false; error: SchemaValidationError };

export abstract class SchemaValidator<TData, TSchema> {
  public abstract readonly schema: TSchema;
  public abstract validate(raw: unknown): TData;

  public safeValidate(raw: unknown): SafeValidateResult<TData> {
    try {
      const data = this.validate(raw);
      return { success: true, data };
    } catch (error) {
      if (error instanceof SchemaValidationError) {
        return { success: false, error };
      }
      throw error;
    }
  }
}
