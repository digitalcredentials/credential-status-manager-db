export class ConcurrencyLimiter {
  private readonly limit: number;
  private counter: number;
  private readonly queue: Array<(() => void)>;

  constructor(limit: number) {
    this.limit = limit;
    this.counter = 0;
    this.queue = [];
  }

  async acquire(): Promise<void> {
      this.counter++;
      if (this.counter >= this.limit) {
        await new Promise<void>(resolve => this.queue.push(resolve));
      }
  }

  release(): void {
      this.counter--;
      if (this.queue.length > 0) {
        const next = this.queue.shift();
        if (next) {
          next();
        }
      }
  }

  async execute<T>(task: (...args: unknown[]) => Promise<T>): Promise<T> {
      await this.acquire();
      try {
        return await task();
      } finally {
        this.release();
      }
  }
}
