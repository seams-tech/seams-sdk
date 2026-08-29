import type { ActiveWalletSessionV1 } from './contracts';

declare const activeWithoutQuota: Omit<ActiveWalletSessionV1, 'quotaId'>;

// @ts-expect-error Exact active Wallet Sessions require their quota identity.
const invalidActive: ActiveWalletSessionV1 = activeWithoutQuota;

void invalidActive;
