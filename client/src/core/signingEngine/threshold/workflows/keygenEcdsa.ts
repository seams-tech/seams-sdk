import { bootstrapEcdsaSession } from './bootstrapEcdsaSession';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ThresholdIndexedDbPort, ThresholdWebAuthnPromptPort } from '../webauthn';
import type { ThresholdEcdsaChainTarget } from '../../session/signingSession/ecdsaChainTarget';

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
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  workerCtx: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  ecdsaThresholdKeyId?: string;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  participantIds?: number[];
  chainId?: number;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
  code?: string;
  message?: string;
}> {
  const bootstrap = await bootstrapEcdsaSession({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    userId: String(args.userId || '').trim(),
    chainTarget: args.chainTarget,
    workerCtx: args.workerCtx,
  });
  if (!bootstrap.ok) return bootstrap;
  return {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
    clientVerifyingShareB64u: bootstrap.clientVerifyingShareB64u,
    clientAdditiveShare32B64u: bootstrap.clientAdditiveShare32B64u,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerKeyId: bootstrap.relayerKeyId,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: bootstrap.participantIds,
    ...(typeof bootstrap.chainId === 'number' ? { chainId: bootstrap.chainId } : {}),
    ...(typeof bootstrap.factory === 'string' && bootstrap.factory.trim()
      ? { factory: bootstrap.factory.trim() }
      : {}),
    ...(typeof bootstrap.entryPoint === 'string' && bootstrap.entryPoint.trim()
      ? { entryPoint: bootstrap.entryPoint.trim() }
      : {}),
    ...(typeof bootstrap.salt === 'string' && bootstrap.salt.trim()
      ? { salt: bootstrap.salt.trim() }
      : {}),
    ...(typeof bootstrap.counterfactualAddress === 'string' &&
    bootstrap.counterfactualAddress.trim()
      ? { counterfactualAddress: bootstrap.counterfactualAddress.trim() }
      : {}),
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };
}
