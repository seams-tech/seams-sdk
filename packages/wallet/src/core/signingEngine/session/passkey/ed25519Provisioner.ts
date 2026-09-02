import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '../warmCapabilities/transitions';
import type { WarmSessionEnvelope } from '../warmCapabilities/types';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import { nearProtocolProjectionFromExactLane } from '../identity/exactSigningLaneIdentity';
import { toWalletId, type WalletId } from '../../interfaces/ecdsaChainTarget';

function toOptionalNonEmptyString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

export type WarmSessionEd25519ProvisionerDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

function assertPersistedEd25519WarmSessionRecord(args: {
  walletId: WalletId;
  expectedThresholdSessionId: string;
  persistedSessionIdRaw: unknown;
}): void {
  const persistedSessionId = String(args.persistedSessionIdRaw || '').trim();
  if (persistedSessionId === args.expectedThresholdSessionId) {
    return;
  }
  throw new Error(
    `[WarmSessionStore] provisioned Ed25519 capability was not persisted for ${args.walletId} (expected thresholdSessionId=${args.expectedThresholdSessionId}, found=${persistedSessionId || 'missing'})`,
  );
}

function walletIdFromEd25519ProvisionArgs(args: ProvisionWarmEd25519CapabilityArgs): WalletId {
  if (args.kind === 'exact_ed25519_provisioning') {
    return toWalletId(
      nearProtocolProjectionFromExactLane(
        args.laneIdentity,
        'exact Ed25519 capability provisioning',
      ).walletId,
    );
  }
  return toWalletId(args.walletId);
}

function nearAccountIdFromEd25519ProvisionArgs(
  args: ProvisionWarmEd25519CapabilityArgs,
): AccountId {
  const nearAccountId =
    args.kind === 'exact_ed25519_provisioning'
      ? nearProtocolProjectionFromExactLane(
          args.laneIdentity,
          'exact Ed25519 capability provisioning',
        ).nearAccountId
      : args.nearAccountId;
  return toAccountId(nearAccountId);
}

export async function provisionWarmEd25519Capability(
  deps: WarmSessionEd25519ProvisionerDeps,
  args: ProvisionWarmEd25519CapabilityArgs,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  const nearAccountId = nearAccountIdFromEd25519ProvisionArgs(args);
  const walletId = walletIdFromEd25519ProvisionArgs(args);
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

  const expectedThresholdSessionId = toOptionalNonEmptyString(
    provisioned.thresholdSessionId,
  );
  if (!expectedThresholdSessionId) {
    throw new Error(
      `[WarmSessionStore] provisioned Ed25519 capability is missing thresholdSessionId for ${nearAccountId}`,
    );
  }

  const afterWarmSession = await deps.getWarmSession(walletId);
  assertPersistedEd25519WarmSessionRecord({
    walletId,
    expectedThresholdSessionId,
    persistedSessionIdRaw:
      afterWarmSession.capabilities.ed25519.runtime?.thresholdSessionId,
  });
  emitWarmSessionTransition({
    onTransition: deps.onTransition,
    event: {
      type: 'ed25519_capability_provisioned',
      walletId,
      thresholdSessionId: expectedThresholdSessionId,
      before: summarizeWarmSessionTransition(beforeWarmSession),
      after: summarizeWarmSessionTransition(afterWarmSession),
    },
  });
  return provisioned;
}
