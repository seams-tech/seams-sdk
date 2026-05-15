import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import { toAccountId } from '@/core/types/accountIds';
import { base64UrlDecode } from '@shared/utils/base64';
import { decodeCoseP256PublicKeyWasm } from '../../chains/evm/ethSignerWasm';
import type { KeyRef } from '../../interfaces/signing';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

export async function resolveWebAuthnP256KeyRefForWallet(args: {
  indexedDB: UnifiedIndexedDBManager;
  walletId: string;
  workerCtx: WorkerOperationContext;
  rpId?: string;
}): Promise<KeyRef & { type: 'webauthnP256' }> {
  const walletId = toAccountId(args.walletId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB,
    buildNearAccountRefs(walletId),
  );
  if (!context?.profileId) {
    throw new Error(`[multichain] no profile/account mapping found for wallet ${walletId}`);
  }

  const authenticators = await args.indexedDB.clientDB.listProfileAuthenticators(context.profileId);
  if (!authenticators.length) {
    throw new Error(`[multichain] no passkeys found for wallet ${walletId}`);
  }

  const { authenticatorsForPrompt } =
    await args.indexedDB.clientDB.selectProfileAuthenticatorsForPrompt({
      profileId: context.profileId,
      authenticators,
      accountLabel: walletId,
    });
  const auth = authenticatorsForPrompt[0];
  if (!auth) {
    throw new Error(`[multichain] missing authenticator for wallet ${walletId}`);
  }

  const { pubKeyX32, pubKeyY32 } = await decodeCoseP256PublicKeyWasm({
    cosePublicKey: auth.credentialPublicKey,
    workerCtx: args.workerCtx,
  });
  const credentialId = base64UrlDecode(auth.credentialId);
  if (credentialId.length === 0) {
    throw new Error('[multichain] invalid credentialId for authenticator');
  }

  return {
    type: 'webauthnP256',
    credentialId,
    pubKeyX: pubKeyX32,
    pubKeyY: pubKeyY32,
    rpId: args.rpId,
  };
}
