import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { base64UrlDecode } from '@shared/utils/base64';
import { decodeCoseP256PublicKeyWasm } from '../../chains/evm/ethSignerWasm';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import type { KeyRef } from '../../interfaces/signing';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

export async function resolveWebAuthnP256KeyRefForWallet(args: {
  indexedDB: UnifiedIndexedDBManager;
  walletId: string;
  workerCtx: WorkerOperationContext;
  rpId?: string;
}): Promise<KeyRef & { type: 'webauthnP256' }> {
  const walletId = toWalletId(args.walletId);
  const authenticators = await args.indexedDB.listWalletPasskeyAuthenticators(walletId);
  if (!authenticators.length) {
    throw new Error(`[multichain] no passkeys found for wallet ${walletId}`);
  }

  const { authenticatorsForPrompt } =
    await args.indexedDB.selectProfileAuthenticatorsForPrompt({
      profileId: walletId,
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
