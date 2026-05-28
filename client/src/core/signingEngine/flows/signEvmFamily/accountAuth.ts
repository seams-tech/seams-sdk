import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import {
  resolveProfileAccountContextFromCandidates,
  selectAccountSigner,
} from '@/core/indexedDB/profileAccountProjection';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  resolveAccountAuthMetadataForSignerSource,
  type AccountAuthMetadata,
} from '../../interfaces/accountAuthMetadata';

export type EvmFamilyAccountMetadataDeps = {
  indexedDB: UnifiedIndexedDBManager;
};

export async function resolveEvmFamilyTransactionWalletAuth(args: {
  deps: EvmFamilyAccountMetadataDeps;
  walletId: string;
  senderSignatureAlgorithm: 'secp256k1' | 'webauthnP256';
  sessionSource?: string;
  isEmailOtpThresholdContext?: boolean;
}): Promise<AccountAuthMetadata> {
  if (args.senderSignatureAlgorithm === 'webauthnP256') {
    return resolveAccountAuthMetadataForSignerSource();
  }

  const walletId = toAccountId(args.walletId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.deps.indexedDB,
    buildNearAccountRefs(walletId),
  ).catch(() => null);
  if (context?.profileId) {
    const [profile, activeSigners, lastProfileState] = await Promise.all([
      args.deps.indexedDB.getProfile(context.profileId).catch(() => null),
      args.deps.indexedDB
        .listAccountSigners({
          chainIdKey: context.accountRef.chainIdKey,
          accountAddress: context.accountRef.accountAddress,
          status: 'active',
        })
        .catch(() => []),
      args.deps.indexedDB.getLastProfileState().catch(() => null),
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
