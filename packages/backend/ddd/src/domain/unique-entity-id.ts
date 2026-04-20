import type { IdGenerator } from "./id-generator/id-generator";
import { UuidIdGenerator } from "./id-generator/uuid-id-generator";

export class UniqueEntityId<T extends string | number> {
  private _value: T;

  constructor(id?: T, idGenerator: IdGenerator = UuidIdGenerator) {
    this._value = id ?? (idGenerator() as T);
  }

  public toString() {
    return this._value.toString();
  }

  public toValue() {
    return this._value;
  }

  public equals(other?: UniqueEntityId<T>) {
    return this.toValue() === other?.toValue();
  }
}
