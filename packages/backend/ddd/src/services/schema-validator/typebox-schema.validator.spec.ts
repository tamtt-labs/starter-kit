import { Type } from "@sinclair/typebox";
import { describe, expect, it } from "bun:test";

import { SchemaValidationError } from "./schema-validation.error";
import { TypeboxSchemaValidator } from "./typebox-schema.validator";

describe(TypeboxSchemaValidator.name, () => {
  type User = {
    name: string;
    age: number;
    email?: string;
  };

  const validator = new TypeboxSchemaValidator<User>({
    name: Type.String(),
    age: Type.Number(),
    email: Type.Optional(Type.String()),
  });

  describe("schema", () => {
    it("should expose the compiled schema", () => {
      expect(validator.schema).toBeDefined();
    });
  });

  describe("validate", () => {
    it("should return parsed data for valid input", () => {
      const input = { name: "Alice", age: 30 };
      const result = validator.validate(input);

      expect(result).toEqual({ name: "Alice", age: 30 });
    });

    it("should coerce compatible types (Convert)", () => {
      const input = { name: "Alice", age: "30" };
      const result = validator.validate(input);

      expect(result.age).toBe(30);
    });

    it("should strip unknown properties (Clean)", () => {
      const input = { name: "Alice", age: 30, unknown: "extra" };
      const result = validator.validate(input);

      expect(result).not.toHaveProperty("unknown");
    });

    it("should throw SchemaValidationError for invalid input", () => {
      const input = { name: 123, age: "not-a-number" };

      expect(() => validator.validate(input)).toThrow(SchemaValidationError);
    });

    it("should throw SchemaValidationError when required fields are missing", () => {
      const input = { name: "Alice" };

      expect(() => validator.validate(input)).toThrow(SchemaValidationError);
    });
  });

  describe("safeValidate", () => {
    it("should return success result for valid input", () => {
      const input = { name: "Alice", age: 30 };
      const result = validator.safeValidate(input);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toEqual({ name: "Alice", age: 30 });
      }
    });

    it("should return failure result for invalid input", () => {
      const input = { name: 123, age: "not-a-number" };
      const result = validator.safeValidate(input);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeInstanceOf(SchemaValidationError);
      }
    });
  });
});
