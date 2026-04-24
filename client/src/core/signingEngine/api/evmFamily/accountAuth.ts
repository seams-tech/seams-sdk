import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import {
  resolveProfileAccountContextFromCandidates,
  selectAccountSigner,
} from '@/core/indexedDB/profileAccountProjection';
import {
  resolveAccountAuthMetadataForSignerSource,
  type AccountAuthMetadata,
} from '@/core/signingEngine/auth';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaSessionRecord,
} from '../thresholdLifecycle/thresholdSessionStore';
import { getStoredThresholdEd25519SessionRecordForAccount } from '../thresholdLifecycle/thresholdSessionStore';
import { isEmailOtpThresholdEcdsaSigningContext } from './ecdsaLanes';
import type { EvmFamilySenderSignatureAlgorithm } from './types';

export type EvmFamilyAccountMetadataDeps = {
  indexedDB: UnifiedIndexedDBManager;
};

export async function resolveEvmFamilyTransactionAccountAuth(args: {
  deps: EvmFamilyAccountMetadataDeps;
  nearAccountId: string;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
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

  const ed25519Record = getStoredThresholdEd25519SessionRecordForAccount(accountId);
  if (ed25519Record) {
    return resolveAccountAuthMetadataForSignerSource({ source: ed25519Record.source });
  }

  if (isEmailOtpThresholdEcdsaSigningContext(args)) {
    return resolveAccountAuthMetadataForSignerSource({
      source: SIGNER_AUTH_METHODS.emailOtp,
    });
  }

  return resolveAccountAuthMetadataForSignerSource({
    source: args.record?.source,
  });
}
