import type { ISaga } from "./saga.interface";

export abstract class ISagaProvider {
  abstract readonly saga: ISaga | ISaga[];
}
