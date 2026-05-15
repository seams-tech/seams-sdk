import { toAccountId, type AccountId } from '@/core/types/accountIds';

export async function withThresholdEcdsaBootstrapQueue<T>(
  queueByWallet: Map<string, Promise<void>>,
  walletId: AccountId | string,
  task: () => Promise<T>,
): Promise<T> {
  const walletKey = String(toAccountId(String(walletId || '').trim()));
  const previous = queueByWallet.get(walletKey) || Promise.resolve();
  const waitForPrevious = previous.catch(() => undefined);

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const next = waitForPrevious.then(() => gate);
  queueByWallet.set(walletKey, next);

  await waitForPrevious;
  try {
    return await task();
  } finally {
    release();
    if (queueByWallet.get(walletKey) === next) {
      queueByWallet.delete(walletKey);
    }
  }
}
