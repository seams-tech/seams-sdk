import { base64UrlEncode } from '@shared/utils/encoders';
import { toAccountId } from '@/core/types/accountIds';
import { cacheSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import { deriveThresholdSecp256k1ClientShareWasm } from '../../signers/wasm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type ThresholdPrfFirstCachePort,
  type ThresholdSigningKeyOpsPort,
  type ThresholdWebAuthnPromptPort,
} from '../webauthn';
import { buildEd25519SessionPolicy } from '../session/sessionPolicy';
import {
  buildAndCacheEd25519AuthSession,
  mintEd25519AuthSession,
} from '../session/ed25519AuthSession';
import type { Ed25519SessionKind } from '../session/ed25519AuthSession';

const DUMMY_WRAP_KEY_SALT_B64U = base64UrlEncode(new Uint8Array(32));

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - extract `PRF.first` (base64url) and derive `clientVerifyingShareB64u` via the signer worker
 * - mint a relay threshold session token via `POST /threshold-ed25519/session` (lite)
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the relay is PRF-redacted in `mintEd25519AuthSession`.
 */
export async function connectEd25519Session(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  signingKeyOps: ThresholdSigningKeyOpsPort;
  prfFirstCache?: ThresholdPrfFirstCachePort;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds?: number[];
  sessionKind?: Ed25519SessionKind;
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  clientVerifyingShareB64u?: string;
  ecdsaClientVerifyingShareB64u?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: Ed25519SessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }

  const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerKeyId: args.relayerKeyId,
    participantIds: args.participantIds,
    sessionId: args.sessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });

  // 1) Collect WebAuthn assertion for challenge=sessionPolicyDigest32 and include PRF outputs.
  const credential = await collectAuthenticationCredentialForChallengeB64u({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: args.nearAccountId,
    challengeB64u: sessionPolicyDigest32,
  });

  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }

  // 2) Derive client verifying share using the signer worker (share stays inside the worker).
  const sessionId = policy.sessionId;
  const derive = await args.signingKeyOps.deriveThresholdEd25519ClientVerifyingShare({
    sessionId,
    nearAccountId: toAccountId(args.nearAccountId),
    prfFirstB64u,
    wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
  });
  if (!derive.success) {
    return {
      ok: false,
      code: 'internal',
      message: derive.error || 'Failed to derive client verifying share',
    };
  }
  const clientVerifyingShareB64u = derive.clientVerifyingShareB64u;
  let ecdsaClientVerifyingShareB64u: string | undefined;
  if (args.workerCtx) {
    try {
      const ecdsaDerived = await deriveThresholdSecp256k1ClientShareWasm({
        prfFirstB64u,
        userId: args.nearAccountId,
        workerCtx: args.workerCtx,
      });
      const normalizedEcdsaShare = String(ecdsaDerived.clientVerifyingShareB64u || '').trim();
      if (normalizedEcdsaShare) {
        ecdsaClientVerifyingShareB64u = normalizedEcdsaShare;
      }
    } catch {}
  }

  // 3) Mint threshold auth session token/cookie with standard WebAuthn verification.
  const minted = await mintEd25519AuthSession({
    relayerUrl: args.relayerUrl,
    sessionKind,
    relayerKeyId: args.relayerKeyId,
    clientVerifyingShareB64u,
    sessionPolicy: policy,
    webauthnAuthentication: credential,
  });
  if (!minted.ok) {
    return minted;
  }
  const resolvedSessionId = String(minted.sessionId || sessionId).trim() || sessionId;

  // Cache PRF.first in-memory for the session TTL/uses window so subsequent signing can
  // dispense the client share seed without prompting again (wallet-origin only).
  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const prfFirstCache = args.prfFirstCache;
  if (prfFirstCache) {
    await cacheSigningSessionPrfFirstBestEffort(prfFirstCache, {
      sessionId: resolvedSessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    });
  }

  // 4) Cache for on-demand `/threshold-ed25519/authorize` usage.
  await buildAndCacheEd25519AuthSession({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    participantIds: args.participantIds,
    sessionKind,
    sessionId: resolvedSessionId,
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    policyTtlMs: policy.ttlMs,
    policyRemainingUses: policy.remainingUses,
  });

  return {
    ok: true,
    sessionId: resolvedSessionId,
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    clientVerifyingShareB64u,
    ecdsaClientVerifyingShareB64u,
  };
}
