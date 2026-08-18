export class WorkerDeferred<T> {
  readonly promise: Promise<T>;
  private resolveValue: ((value: T) => void) | null = null;
  private rejectValue: ((error: Error) => void) | null = null;

  constructor() {
    this.promise = new Promise(this.capture);
  }

  resolve(value: T): void {
    if (!this.resolveValue) throw new Error('Worker deferred resolver is unavailable');
    this.resolveValue(value);
  }

  reject(error: Error): void {
    if (!this.rejectValue) throw new Error('Worker deferred rejecter is unavailable');
    this.rejectValue(error);
  }

  private readonly capture = (
    resolve: (value: T | PromiseLike<T>) => void,
    reject: (reason?: unknown) => void,
  ): void => {
    this.resolveValue = resolve;
    this.rejectValue = reject;
  };
}
