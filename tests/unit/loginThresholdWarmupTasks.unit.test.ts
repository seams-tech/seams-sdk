import { expect, test } from '@playwright/test';
import { runThresholdLoginWarmupTasks } from '@/SeamsWeb/operations/auth/login';

class TestDeferred {
  readonly promise: Promise<void>;
  private resolvePromise!: () => void;

  constructor() {
    this.promise = new Promise(this.capture.bind(this));
  }

  resolve(): void {
    this.resolvePromise();
  }

  private capture(resolve: () => void): void {
    this.resolvePromise = resolve;
  }
}

async function settleDelayedEd25519Task(
  delayed: TestDeferred,
  events: string[],
): Promise<void> {
  await delayed.promise;
  events.push('ed25519-settled');
}

async function failEcdsaTask(): Promise<void> {
  throw new Error('ecdsa failed');
}

function recordEcdsaFailure(events: string[]): void {
  events.push('ecdsa-failure-observed');
}

function recordRejection(state: { rejected: boolean }): void {
  state.rejected = true;
}

test('waits for every concurrent warm-up task before propagating a failure', async () => {
  const delayed = new TestDeferred();
  const events: string[] = [];
  const rejectionState = { rejected: false };
  const warmup = runThresholdLoginWarmupTasks([
    {
      signer: 'ed25519',
      dependencies: [],
      onFailure: null,
      run: settleDelayedEd25519Task.bind(undefined, delayed, events),
    },
    {
      signer: 'ecdsa',
      dependencies: [],
      onFailure: recordEcdsaFailure.bind(undefined, events),
      run: failEcdsaTask,
    },
  ]);
  void warmup.catch(recordRejection.bind(undefined, rejectionState));

  await Promise.resolve();
  await Promise.resolve();
  expect(rejectionState.rejected).toBe(false);
  expect(events).toEqual(['ecdsa-failure-observed']);

  delayed.resolve();
  await expect(warmup).rejects.toThrow('ecdsa failed');
  expect(events).toEqual(['ecdsa-failure-observed', 'ed25519-settled']);
});
