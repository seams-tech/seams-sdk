import { toAccountId } from '../../../../types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../types';
import { bootstrapThresholdEcdsaLite } from '../../../threshold/workflows/bootstrapThresholdEcdsaLite';
import type {
  ActivateThresholdEcdsaSessionLiteDeps,
  ActivateThresholdEcdsaSessionLiteRequest,
  ThresholdEcdsaKeygenLiteSuccess,
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaSessionLiteSuccess,
} from './types';

export async function activateThresholdEcdsaSessionLite(
  deps: ActivateThresholdEcdsaSessionLiteDeps,
  args: ActivateThresholdEcdsaSessionLiteRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);

  const bootstrap = await bootstrapThresholdEcdsaLite({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.prfFirstCache,
    relayerUrl: args.relayerUrl,
    userId: nearAccountId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId: deps.getOrCreateActiveSigningSessionId(nearAccountId),
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx: deps.workerCtx,
  });
  if (!bootstrap.ok) {
    throw new Error(bootstrap.message || bootstrap.code || 'threshold-ecdsa bootstrap failed');
  }

  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throw new Error('threshold-ecdsa bootstrap returned empty relayerKeyId');
  }

  const clientVerifyingShareB64u = String(bootstrap.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientVerifyingShareB64u');
  }

  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty sessionId');
  }

  const keygen: ThresholdEcdsaKeygenLiteSuccess = {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    clientVerifyingShareB64u,
    relayerKeyId,
    groupPublicKeyB64u: bootstrap.groupPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: bootstrap.participantIds,
    ...(typeof bootstrap.chainId === 'string' ? { chainId: bootstrap.chainId } : {}),
    ...(typeof bootstrap.factory === 'string' ? { factory: bootstrap.factory } : {}),
    ...(typeof bootstrap.entryPoint === 'string' ? { entryPoint: bootstrap.entryPoint } : {}),
    ...(typeof bootstrap.salt === 'string' ? { salt: bootstrap.salt } : {}),
    ...(typeof bootstrap.counterfactualAddress === 'string' ? { counterfactualAddress: bootstrap.counterfactualAddress } : {}),
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const session: ThresholdEcdsaSessionLiteSuccess = {
    ok: true,
    sessionId,
    expiresAtMs: bootstrap.expiresAtMs,
    remainingUses: bootstrap.remainingUses,
    jwt: bootstrap.jwt,
    clientVerifyingShareB64u,
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: nearAccountId,
    relayerUrl: args.relayerUrl,
    relayerKeyId,
    clientVerifyingShareB64u,
    ...(Array.isArray(args.participantIds)
      ? { participantIds: args.participantIds }
      : Array.isArray(bootstrap.participantIds)
        ? { participantIds: bootstrap.participantIds }
        : {}),
    ...(typeof bootstrap.groupPublicKeyB64u === 'string' && bootstrap.groupPublicKeyB64u.trim()
      ? { groupPublicKeyB64u: bootstrap.groupPublicKeyB64u.trim() }
      : {}),
    ...(typeof bootstrap.relayerVerifyingShareB64u === 'string' && bootstrap.relayerVerifyingShareB64u.trim()
      ? { relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u.trim() }
      : {}),
    thresholdSessionKind: args.sessionKind || 'jwt',
    thresholdSessionId: sessionId,
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { thresholdSessionJwt: session.jwt.trim() }
      : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: keygen as ThresholdEcdsaKeygenLiteSuccess,
    session: session as ThresholdEcdsaSessionLiteSuccess,
  };
}
