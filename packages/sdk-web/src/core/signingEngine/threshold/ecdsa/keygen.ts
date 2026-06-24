import { bootstrapEcdsaSession } from './bootstrapSession';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ThresholdCredentialStorePort, ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletKeyId } from '@shared/signing-lanes';

/**
 * Threshold-ecdsa (secp256k1) keygen helper (standard WebAuthn).
 *
 * - Uses the staged `ecdsa-hss` bootstrap path
 * - Returns the keygen projection of the bootstrap response
 *
 * Notes:
 * - This helper performs staged bootstrap and returns the finalized keygen/session projection.
 */
export async function keygenEcdsa(args: {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
  walletKeyId: WalletKeyId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  workerCtx: WorkerOperationContext;
}): Promise<
	  | {
	      ok: true;
	      keygenSessionId?: string;
	      walletKeyId: string;
	      keyHandle?: string;
	      ecdsaThresholdKeyId?: string;
	      clientVerifyingShareB64u?: string;
      thresholdEcdsaPublicKeyB64u?: string;
      ethereumAddress?: string;
      relayerKeyId?: string;
      relayerVerifyingShareB64u?: string;
      participantIds?: number[];
      chainId: number;
    }
  | {
      ok: false;
      code: string;
      message: string;
    }
> {
  const bootstrap = await bootstrapEcdsaSession({
    credentialStore: args.credentialStore,
    touchIdPrompt: args.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    userId: String(args.userId || '').trim(),
    walletKeyId: args.walletKeyId,
    chainTarget: args.chainTarget,
    authKind: 'passkey_prompt',
    workerCtx: args.workerCtx,
  });
  if (!bootstrap.ok) return bootstrap;
	  return {
	    ok: true,
	    keygenSessionId: bootstrap.keygenSessionId,
	    walletKeyId: bootstrap.walletKeyId,
	    keyHandle: bootstrap.keyHandle,
    ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
    clientVerifyingShareB64u: bootstrap.clientVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerKeyId: bootstrap.relayerKeyId,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: bootstrap.participantIds,
    chainId: bootstrap.chainId,
  };
}
