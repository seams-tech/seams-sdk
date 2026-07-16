import { base64UrlDecode } from '@shared/utils/base64';
import { decodeCoseP256PublicKeyWasm } from '../../chains/evm/evmCryptoWasm';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import type { EvmFamilyPasskeyAuthenticatorStorePort } from '../../interfaces/passkeyAuthenticatorStore';
import type { KeyRef } from '../../interfaces/signing';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

export async function resolveWebAuthnP256KeyRefForWallet(args: {
  passkeyAuthenticatorStore: EvmFamilyPasskeyAuthenticatorStorePort;
  walletId: string;
  workerCtx: WorkerOperationContext;
  rpId?: string;
}): Promise<KeyRef & { type: 'webauthnP256' }> {
  const walletId = toWalletId(args.walletId);
  const authenticators = await args.passkeyAuthenticatorStore.listWalletPasskeyAuthenticators(
    walletId,
  );
  if (!authenticators.length) {
    throw new Error(`[multichain] no passkeys found for wallet ${walletId}`);
  }

  const { authenticatorsForPrompt } =
    await args.passkeyAuthenticatorStore.selectProfileAuthenticatorsForPrompt({
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
