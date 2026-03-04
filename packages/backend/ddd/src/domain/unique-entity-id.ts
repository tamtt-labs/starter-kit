export class UniqueEntityId<T extends string | number> {
  private _value: T;

  constructor(id?: T) {
    this._value = id ?? (Bun.randomUUIDv7() as T);
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
