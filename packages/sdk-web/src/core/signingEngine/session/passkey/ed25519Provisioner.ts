import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '../warmCapabilities/transitions';
import { toOptionalNonEmptyString } from '../../useCases/provisionEcdsaSession';
import type { WarmSessionEnvelope } from '../warmCapabilities/types';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import type { WalletId } from '../../interfaces/ecdsaChainTarget';

export type WarmSessionEd25519ProvisionerDeps = {
  getWarmSession: (walletId: WalletId | string) => Promise<WarmSessionEnvelope>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

function assertPersistedEd25519WarmSessionRecord(args: {
  walletId: string;
  expectedSessionId: string;
  persistedSessionIdRaw: unknown;
}): void {
  const persistedSessionId = String(args.persistedSessionIdRaw || '').trim();
  if (persistedSessionId === args.expectedSessionId) {
    return;
  }
  throw new Error(
    `[WarmSessionStore] provisioned Ed25519 capability was not persisted for ${args.walletId} (expected sessionId=${args.expectedSessionId}, found=${persistedSessionId || 'missing'})`,
  );
}

export async function provisionWarmEd25519Capability(
  deps: WarmSessionEd25519ProvisionerDeps,
  args: ProvisionWarmEd25519CapabilityArgs,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('[WarmSessionStore] walletId is required to provision Ed25519 capability');
  }
  if (typeof deps.provisionThresholdEd25519Session !== 'function') {
    throw new Error(
      '[WarmSessionStore] provisionThresholdEd25519Session is required to provision Ed25519 capability',
    );
  }
  const beforeWarmSession = await deps.getWarmSession(walletId);
  await args.beforeProvision?.();
  args.assertNotCancelled?.();
  const provisioned = await deps.provisionThresholdEd25519Session(args);
  args.assertNotCancelled?.();

  if (!provisioned.ok) {
    return provisioned;
  }

  const expectedSessionId = toOptionalNonEmptyString(provisioned.sessionId);
  if (!expectedSessionId) {
    throw new Error(
      `[WarmSessionStore] provisioned Ed25519 capability is missing sessionId for ${nearAccountId}`,
    );
  }

  const afterWarmSession = await deps.getWarmSession(walletId);
  assertPersistedEd25519WarmSessionRecord({
    walletId,
    expectedSessionId,
    persistedSessionIdRaw: afterWarmSession.capabilities.ed25519.record?.thresholdSessionId,
  });
  emitWarmSessionTransition({
    onTransition: deps.onTransition,
    event: {
      type: 'ed25519_capability_provisioned',
      walletId,
      thresholdSessionId: expectedSessionId,
      before: summarizeWarmSessionTransition(beforeWarmSession),
      after: summarizeWarmSessionTransition(afterWarmSession),
    },
  });
  return provisioned;
}
