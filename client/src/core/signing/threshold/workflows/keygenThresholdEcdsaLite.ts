import { bootstrapThresholdEcdsaLite } from './bootstrapThresholdEcdsaLite';
import type { WorkerOperationContext } from '../../workers/operations/executeSignerWorkerOperation';
import type { ThresholdIndexedDbPort, ThresholdWebAuthnPromptPort } from '../webauthn';

/**
 * Threshold-ecdsa (secp256k1) keygen helper (standard WebAuthn).
 *
 * - Uses the atomic relay bootstrap path (`POST /threshold-ecdsa/bootstrap`)
 * - Returns the keygen projection of the bootstrap response for backward compatibility
 *
 * Notes:
 * - This helper now performs bootstrap-side session mint as part of the atomic flow.
 */
export async function keygenThresholdEcdsaLite(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
  workerCtx: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  clientVerifyingShareB64u?: string;
  groupPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  participantIds?: number[];
  chainId?: string;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
  code?: string;
  message?: string;
}> {
  const bootstrap = await bootstrapThresholdEcdsaLite({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    userId: String(args.userId || '').trim(),
    workerCtx: args.workerCtx,
  });
  if (!bootstrap.ok) return bootstrap;
  return {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    clientVerifyingShareB64u: bootstrap.clientVerifyingShareB64u,
    groupPublicKeyB64u: bootstrap.groupPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerKeyId: bootstrap.relayerKeyId,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: bootstrap.participantIds,
    ...(typeof bootstrap.chainId === 'string' && bootstrap.chainId.trim()
      ? { chainId: bootstrap.chainId.trim() }
      : {}),
    ...(typeof bootstrap.factory === 'string' && bootstrap.factory.trim()
      ? { factory: bootstrap.factory.trim() }
      : {}),
    ...(typeof bootstrap.entryPoint === 'string' && bootstrap.entryPoint.trim()
      ? { entryPoint: bootstrap.entryPoint.trim() }
      : {}),
    ...(typeof bootstrap.salt === 'string' && bootstrap.salt.trim()
      ? { salt: bootstrap.salt.trim() }
      : {}),
    ...(typeof bootstrap.counterfactualAddress === 'string' && bootstrap.counterfactualAddress.trim()
      ? { counterfactualAddress: bootstrap.counterfactualAddress.trim() }
      : {}),
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };
}
