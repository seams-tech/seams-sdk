import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import {
  resolveProfileAccountContextFromCandidates,
  selectAccountSigner,
} from '@/core/indexedDB/profileAccountProjection';
import {
  resolveAccountAuthMetadataForSignerSource,
  type AccountAuthMetadata,
} from './walletAuthModeResolver';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';

export type EvmFamilyAccountMetadataDeps = {
  indexedDB: UnifiedIndexedDBManager;
};

export async function resolveEvmFamilyTransactionAccountAuth(args: {
  deps: EvmFamilyAccountMetadataDeps;
  nearAccountId: string;
  senderSignatureAlgorithm: 'secp256k1' | 'webauthnP256';
  sessionSource?: string;
  isEmailOtpThresholdContext?: boolean;
}): Promise<AccountAuthMetadata> {
  if (args.senderSignatureAlgorithm === 'webauthnP256') {
    return resolveAccountAuthMetadataForSignerSource();
  }

  const accountId = toAccountId(args.nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.deps.indexedDB.clientDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (context?.profileId) {
    const [profile, activeSigners, lastProfileState] = await Promise.all([
      args.deps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null),
      args.deps.indexedDB.clientDB
        .listAccountSigners({
          chainIdKey: context.accountRef.chainIdKey,
          accountAddress: context.accountRef.accountAddress,
          status: 'active',
        })
        .catch(() => []),
      args.deps.indexedDB.clientDB.getLastProfileState().catch(() => null),
    ]);
    if (profile && activeSigners.length) {
      const activeSignerSlot =
        lastProfileState?.profileId === context.profileId
          ? Number(lastProfileState.activeSignerSlot)
          : undefined;
      const selectedSigner = selectAccountSigner({
        profile,
        activeSigners,
        ...(typeof activeSignerSlot === 'number' &&
        Number.isSafeInteger(activeSignerSlot) &&
        activeSignerSlot >= 1
          ? { signerSlot: activeSignerSlot }
          : {}),
      });
      if (selectedSigner?.signerAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
        return resolveAccountAuthMetadataForSignerSource({
          source: SIGNER_AUTH_METHODS.emailOtp,
        });
      }
      if (selectedSigner?.signerAuthMethod === SIGNER_AUTH_METHODS.passkey) {
        return resolveAccountAuthMetadataForSignerSource({
          source: SIGNER_AUTH_METHODS.passkey,
        });
      }
    }
  }

  if (args.isEmailOtpThresholdContext === true) {
    return resolveAccountAuthMetadataForSignerSource({
      source: SIGNER_AUTH_METHODS.emailOtp,
    });
  }

  return resolveAccountAuthMetadataForSignerSource({
    source: args.sessionSource,
  });
}
