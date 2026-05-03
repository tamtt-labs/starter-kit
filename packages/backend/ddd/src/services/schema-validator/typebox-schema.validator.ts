import {
  Type,
  type TObject as TypeboxObject,
  type TSchema as TypeboxSchema,
} from "@sinclair/typebox";
import { TypeCheck, TypeCompiler } from "@sinclair/typebox/compiler";
import { Value } from "@sinclair/typebox/value";

import { SchemaValidationError } from "./schema-validation.error";
import { SchemaValidator } from "./schema.validator";

type Schema<TData> = TypeboxObject<Record<keyof TData, TypeboxSchema>>;

export class TypeboxSchemaValidator<TData> extends SchemaValidator<TData, Schema<TData>> {
  public readonly schema: Schema<TData>;
  private readonly compiler: TypeCheck<Schema<TData>>;

  constructor(private readonly properties: Record<keyof TData, TypeboxSchema>) {
    super();
    this.schema = Type.Object(this.properties);
    this.compiler = TypeCompiler.Compile(this.schema);
  }

  public validate(raw: unknown): TData {
    const parsedData = Value.Parse(
      ["Clone", "Clean", "Default", "Decode", "Convert"],
      this.schema,
      raw,
    );

    const isValid = this.compiler.Check(parsedData);
    if (isValid) {
      return parsedData as unknown as TData;
    }

    const errors = [...this.compiler.Errors(parsedData)].reduce((errors, e) => {
      const path = e.path.substring(1);
      return { ...errors, [path]: e.message };
    }, {});

    throw new SchemaValidationError(JSON.stringify(errors, null, 2), errors);
  }
}
