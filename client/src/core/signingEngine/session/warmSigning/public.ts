import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  getWalletSigningBudgetAvailableStatus as getWalletSigningBudgetAvailableStatusValue,
  mergeWalletSigningBudgetStatus,
  type WalletSigningBudgetAvailableStatusDeps,
} from '../signingSession/budgetStatusReader';
import {
  getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue,
} from '../persistence/records';
import { provisionWarmEd25519Capability } from './ed25519Provisioner';
import {
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillValue,
  type ThresholdEcdsaLoginPrefillResult,
} from './ecdsaLoginPrefill';
import type { BootstrapEcdsaSessionArgs } from './ecdsaBootstrap';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
  WarmSessionCapabilityReader,
  ThresholdWarmSessionStatusReader,
} from './types';

export type PersistThresholdEcdsaBootstrapChainAccountInput = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  smartAccount?: BootstrapEcdsaSessionArgs['smartAccount'];
  deployment?: {
    deployed: boolean;
    deploymentTxHash?: string;
  };
  ensureEmailOtpNearAccountMapping?: boolean;
};

export type HydrateSigningSessionInput = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: {
    curve?: 'ed25519' | 'ecdsa';
    relayerUrl?: string;
    thresholdSessionAuthToken?: string;
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
};

export type WarmSigningPublicDeps = {
  capabilityReader: Pick<WarmSessionCapabilityReader, 'getWarmSession'>;
  statusReader: Pick<
    ThresholdWarmSessionStatusReader,
    'getEd25519SigningSessionStatus' | 'getEcdsaSigningSessionStatus' | 'listEcdsaSigningSessionStatuses'
  >;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  bootstrapEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  persistThresholdEcdsaBootstrapChainAccount: (
    args: PersistThresholdEcdsaBootstrapChainAccountInput,
  ) => Promise<void>;
  hydrateSigningSession: (args: HydrateSigningSessionInput) => Promise<void>;
  clearWarmSigningSessions: (nearAccountId?: AccountId | string) => Promise<void>;
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
  resolveCanonicalThresholdEcdsaSessionIdForChain: (
    nearAccountId: AccountId | string,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string | null;
  getSignerWorkerContext: Parameters<
    typeof scheduleThresholdEcdsaLoginPresignPrefillValue
  >[0]['getSignerWorkerContext'];
  thresholdEcdsaPresignPoolPolicy?: Parameters<
    typeof scheduleThresholdEcdsaLoginPresignPrefillValue
  >[0]['thresholdEcdsaPresignPoolPolicy'];
};

export async function connectEd25519Session(
  deps: WarmSigningPublicDeps,
  args: Omit<ProvisionWarmEd25519CapabilityArgs, 'beforeProvision' | 'assertNotCancelled'>,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  return await provisionWarmEd25519Capability(
    {
      getWarmSession: (nearAccountId) => deps.capabilityReader.getWarmSession(nearAccountId),
      provisionThresholdEd25519Session: async (provisionArgs) =>
        await deps.provisionThresholdEd25519Session(provisionArgs),
    },
    args,
  );
}

export async function bootstrapEcdsaSession(
  deps: WarmSigningPublicDeps,
  args: BootstrapEcdsaSessionArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await deps.bootstrapEcdsaSession(args);
}

export async function persistThresholdEcdsaBootstrapChainAccount(
  deps: WarmSigningPublicDeps,
  args: PersistThresholdEcdsaBootstrapChainAccountInput,
): Promise<void> {
  await deps.persistThresholdEcdsaBootstrapChainAccount(args);
}

export async function getWarmThresholdEd25519SessionStatus(
  deps: WarmSigningPublicDeps,
  nearAccountId: AccountId | string,
): Promise<SigningSessionStatus | null> {
  const status = await deps.statusReader.getEd25519SigningSessionStatus(nearAccountId);
  const record = getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId);
  const walletBudgetStatus = await getWalletSigningBudgetAvailableStatusValue(
    {
      getAvailableStatus: deps.getWalletSigningBudgetStatus,
    },
    {
      nearAccountId,
      walletSigningSessionId: record?.walletSigningSessionId,
    },
  );
  if (!status) return walletBudgetStatus;
  return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
}

export async function getWarmThresholdEcdsaSessionStatus(
  deps: WarmSigningPublicDeps,
  nearAccountId: AccountId | string,
  chainTarget: ThresholdEcdsaChainTarget,
  thresholdSessionId: string,
): Promise<WarmEcdsaSigningSessionStatus | null> {
  const status = await deps.statusReader.getEcdsaSigningSessionStatus({
    nearAccountId,
    chainTarget,
    thresholdSessionId,
  });
  const walletBudgetStatus = await getWalletSigningBudgetAvailableStatusValue(
    {
      getAvailableStatus: deps.getWalletSigningBudgetStatus,
    },
    {
      nearAccountId,
      walletSigningSessionId: status?.walletSigningSessionId,
    },
  );
  if (!status) return walletBudgetStatus as WarmEcdsaSigningSessionStatus | null;
  return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
}

export async function listWarmThresholdEcdsaSessionStatuses(
  deps: WarmSigningPublicDeps,
  nearAccountId: AccountId | string,
  chainTarget: ThresholdEcdsaChainTarget,
): Promise<WarmEcdsaSigningSessionStatus[]> {
  const statuses = await deps.statusReader.listEcdsaSigningSessionStatuses({
    nearAccountId,
    chainTarget,
  });
  return await Promise.all(
    statuses.map(async (status) => {
      const walletBudgetStatus = await getWalletSigningBudgetAvailableStatusValue(
        {
          getAvailableStatus: deps.getWalletSigningBudgetStatus,
        },
        {
          nearAccountId,
          walletSigningSessionId: status.walletSigningSessionId,
        },
      );
      return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
    }),
  );
}

export async function scheduleThresholdEcdsaLoginPresignPrefill(
  deps: WarmSigningPublicDeps,
  args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  return await scheduleThresholdEcdsaLoginPresignPrefillValue(
    {
      getWarmThresholdEcdsaSessionStatus: async (
        nearAccountIdArg: AccountId | string,
        thresholdSessionId: string,
        chainTargetArg: ThresholdEcdsaChainTarget,
      ) => {
        const canonicalSessionId = deps.resolveCanonicalThresholdEcdsaSessionIdForChain(
          nearAccountIdArg,
          chainTargetArg,
        );
        if (canonicalSessionId && canonicalSessionId !== String(thresholdSessionId || '').trim()) {
          return {
            sessionId: canonicalSessionId,
            status: 'not_found',
          };
        }
        return await deps.statusReader.getEcdsaSigningSessionStatus({
          nearAccountId: nearAccountIdArg,
          chainTarget: chainTargetArg,
          thresholdSessionId,
        });
      },
      getSignerWorkerContext: deps.getSignerWorkerContext,
      thresholdEcdsaPresignPoolPolicy: deps.thresholdEcdsaPresignPoolPolicy,
    },
    args,
  );
}

export async function hydrateSigningSession(
  deps: WarmSigningPublicDeps,
  args: HydrateSigningSessionInput,
): Promise<void> {
  await deps.hydrateSigningSession(args);
}

export async function clearWarmSigningSessions(
  deps: WarmSigningPublicDeps,
  nearAccountId?: AccountId | string,
): Promise<void> {
  await deps.clearWarmSigningSessions(nearAccountId);
}

export type { ThresholdEcdsaLoginPrefillResult };
