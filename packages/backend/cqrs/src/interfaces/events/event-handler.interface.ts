import type { Type } from "../type.interface";
import type { IEvent } from "./event.interface";

type IsUnion<T, U = T> = T extends T ? ([U] extends [T] ? false : true) : never;

export abstract class IEventHandler<T extends IEvent = IEvent> {
  abstract readonly event: IsUnion<T> extends true ? readonly Type<T>[] : Type<T>;
  abstract handle(event: T): any;
}
