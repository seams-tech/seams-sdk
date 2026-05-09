import { toAccountId, type AccountId } from '@/core/types/accountIds';

export async function withThresholdEcdsaBootstrapQueue<T>(
  queueByAccount: Map<string, Promise<void>>,
  nearAccountId: AccountId | string,
  task: () => Promise<T>,
): Promise<T> {
  const accountKey = String(toAccountId(String(nearAccountId || '').trim()));
  const previous = queueByAccount.get(accountKey) || Promise.resolve();
  const waitForPrevious = previous.catch(() => undefined);

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const next = waitForPrevious.then(() => gate);
  queueByAccount.set(accountKey, next);

  await waitForPrevious;
  try {
    return await task();
  } finally {
    release();
    if (queueByAccount.get(accountKey) === next) {
      queueByAccount.delete(accountKey);
    }
  }
}
