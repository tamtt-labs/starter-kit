import type { ISagaProvider } from "@/interfaces";
import { ofType } from "@/operators";
import { Observable, mergeMap, of } from "rxjs";
import { UnhandledExceptionEvent } from "./unhandled-exception.event";

export class ErrorsSagas implements ISagaProvider {
  readonly saga = this.onError;

  onError(events$: Observable<any>): Observable<any> {
    return events$.pipe(
      ofType(UnhandledExceptionEvent),
      mergeMap((event) => {
        if (event.failAt === "saga") {
          throw new Error(`Unhandled exception in ${event.failAt}`);
        }
        return of();
      }),
    );
  }
}
