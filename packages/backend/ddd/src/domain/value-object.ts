import isEqual from "fast-deep-equal";

export abstract class ValueObject<Props extends object = object> {
  constructor(protected props: Props) {
    this.props = Object.freeze(props);
  }

  public equals(other?: ValueObject<Props>): boolean {
    return !!other?.props && isEqual(this.props, other.props);
  }

  public getProps(): Props {
    return this.props;
  }

  public abstract validate(): void;
}
