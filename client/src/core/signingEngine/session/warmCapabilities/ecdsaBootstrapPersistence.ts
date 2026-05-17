import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
  UpsertProfileInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import { buildNearAccountRefs, inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import { buildNearProfileId } from '@/core/accountData/near/profileId';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import { DEFAULT_CONFIRMATION_CONFIG } from '@/core/types/signer-worker';
import {
  normalizeIndexedDbAccountAddress,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type ThresholdEcdsaBootstrapIndexedDbPort = {
  clientDB: {
    resolveProfileAccountContext: (args: {
      chainIdKey: string;
      accountAddress: string;
    }) => Promise<{
      profileId: string;
      accountRef: { chainIdKey: string; accountAddress: string };
    } | null>;
    getProfile?: (profileId: string) => Promise<{ defaultSignerSlot?: number } | null>;
    upsertProfile: (input: UpsertProfileInput) => Promise<unknown>;
    setLastProfileStateForProfile: (profileId: string, signerSlot: number) => Promise<void>;
  };
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<ChainAccountRecord>;
};

function resolveBootstrapTargetChainIdKey(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): string {
  const keygenChainId = Number(args.bootstrap.keygen.chainId);
  if (Number.isFinite(keygenChainId) && keygenChainId > 0) {
    return toIndexedDbChainTargetKey(
      thresholdEcdsaChainTargetFromChainFamily({
        chain: args.chainTarget.kind,
        chainId: Math.floor(keygenChainId),
        networkSlug: args.chainTarget.networkSlug,
      }),
    );
  }
  return toIndexedDbChainTargetKey(args.chainTarget);
}

async function ensureEmailOtpWalletProfileAccountMapping(args: {
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  walletId: AccountId;
}): Promise<void> {
  const walletId = toAccountId(String(args.walletId || '').trim());
  const existing = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB as any,
    buildNearAccountRefs(walletId),
  );
  if (existing?.profileId) {
    const profile = await args.indexedDB.clientDB
      .getProfile?.(existing.profileId)
      .catch(() => null);
    const signerSlot = Number(profile?.defaultSignerSlot);
    await args.indexedDB.clientDB.setLastProfileStateForProfile(
      existing.profileId,
      Number.isSafeInteger(signerSlot) && signerSlot >= 1 ? signerSlot : 1,
    );
    return;
  }

  const accountAddress = normalizeIndexedDbAccountAddress(walletId);
  if (!accountAddress) {
    throw new Error(
      `[SigningEngine] cannot create Email OTP profile/account mapping for ${String(walletId)}`,
    );
  }
  const profileId = buildNearProfileId(walletId);
  const chainIdKey = inferNearChainIdKey(walletId);
  const useNetwork = chainIdKey.endsWith('mainnet') ? 'mainnet' : 'testnet';

  await args.indexedDB.clientDB.upsertProfile({
    profileId,
    defaultSignerSlot: 1,
    preferences: {
      useRelayer: false,
      useNetwork,
      confirmationConfig: DEFAULT_CONFIRMATION_CONFIG,
    },
  });
  await args.indexedDB.upsertChainAccount({
    profileId,
    chainIdKey,
    accountAddress,
    accountModel: 'near-native',
    isPrimary: true,
  });
  await args.indexedDB.clientDB.setLastProfileStateForProfile(profileId, 1);
}

export async function persistThresholdEcdsaBootstrapForWalletTarget(args: {
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  walletId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  ensureEmailOtpNearAccountMapping?: boolean;
}): Promise<void> {
  const walletId = toAccountId(String(args.walletId || '').trim());
  if (args.ensureEmailOtpNearAccountMapping) {
    await ensureEmailOtpWalletProfileAccountMapping({
      indexedDB: args.indexedDB,
      walletId,
    });
  }
  const nearContext = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB as any,
    buildNearAccountRefs(walletId),
  );
  if (!nearContext?.profileId) {
    throw new Error(`[SigningEngine] missing profile/account mapping for ${String(walletId)}`);
  }

  const accountAddress = normalizeIndexedDbAccountAddress(args.bootstrap.keygen.ethereumAddress);
  if (!accountAddress) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide a threshold owner address',
    );
  }

  const chainIdKey = resolveBootstrapTargetChainIdKey({
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
  });

  await args.indexedDB.upsertChainAccount({
    profileId: nearContext.profileId,
    chainIdKey,
    accountAddress,
    accountModel: 'threshold-ecdsa',
    isPrimary: true,
  });
}
