import { cacheSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import { deriveThresholdSecp256k1ClientShareWasm } from '../../signers/wasm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type ThresholdPrfFirstCachePort,
  type ThresholdWebAuthnPromptPort,
} from '../webauthn';
import { buildEd25519SessionPolicy } from '../session/sessionPolicy';
import type { ThresholdRuntimeSnapshotScope } from '../session/sessionPolicy';
import {
  buildAndCacheEd25519AuthSession,
  mintEd25519AuthSession,
} from '../session/ed25519AuthSession';
import type { Ed25519SessionKind } from '../session/ed25519AuthSession';

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - mint a relay threshold session token via `POST /threshold-ed25519/session` (lite)
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the relay is PRF-redacted in `mintEd25519AuthSession`.
 */
export async function connectEd25519Session(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache?: ThresholdPrfFirstCachePort;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds?: number[];
  runtimeSnapshotScope?: ThresholdRuntimeSnapshotScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
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
    ...(args.runtimeSnapshotScope ? { runtimeSnapshotScope: args.runtimeSnapshotScope } : {}),
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
    sessionPolicy: policy,
    webauthnAuthentication: credential,
    runtimeEnvironmentId: args.runtimeScopeBootstrap?.environmentId,
    publishableKey: args.runtimeScopeBootstrap?.publishableKey,
  });
  if (!minted.ok) {
    return minted;
  }
  const requestedSessionId = String(policy.sessionId || '').trim();
  const resolvedSessionId =
    String(minted.sessionId || requestedSessionId).trim() || requestedSessionId;

  // Persist the canonical session record before sealing PRF cache state.
  // Sealed-refresh persistence resolves relayer transport from this record.
  const expiresAtMs = minted.expiresAtMs ?? Date.now() + policy.ttlMs;
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  await buildAndCacheEd25519AuthSession({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(minted.runtimeSnapshotScope ? { runtimeSnapshotScope: minted.runtimeSnapshotScope } : {}),
    participantIds: args.participantIds,
    sessionKind,
    sessionId: resolvedSessionId,
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    policyTtlMs: policy.ttlMs,
    policyRemainingUses: policy.remainingUses,
    source: 'manual-connect',
  });

  // Cache PRF.first in-memory for the session TTL/uses window so subsequent signing can
  // dispense the client share seed without prompting again (wallet-origin only).
  const prfFirstCache = args.prfFirstCache;
  if (prfFirstCache) {
    await cacheSigningSessionPrfFirstBestEffort(prfFirstCache, {
      sessionId: resolvedSessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    });
  }

  return {
    ok: true,
    sessionId: resolvedSessionId,
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    ecdsaClientVerifyingShareB64u,
  };
}
