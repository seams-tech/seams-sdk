import { toAccountId } from '@/core/types/accountIds';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { connectEd25519Session } from '../../threshold/ed25519/connectSession';
import { cacheSigningSessionPrfFirst, generateSessionId } from './prfCache';
import {
  persistWarmSessionEd25519Capability,
  type PersistWarmSessionEd25519CapabilityArgs,
} from '../warmCapabilities/persistence';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import type { ThresholdEd25519SessionStoreSource } from '../identity/laneIdentity';

type ConnectEd25519SessionInput = Parameters<typeof connectEd25519Session>[0];

export type ProvisionThresholdEd25519SessionDeps = {
  credentialStore: ConnectEd25519SessionInput['credentialStore'];
  touchIdPrompt: ConnectEd25519SessionInput['touchIdPrompt'];
  touchConfirm: Parameters<typeof cacheSigningSessionPrfFirst>[0];
  defaultRelayerUrl: string;
  getSignerWorkerContext: () => ConnectEd25519SessionInput['workerCtx'];
  persistWarmSessionEd25519Capability?: (args: PersistWarmSessionEd25519CapabilityArgs) => unknown;
};

export async function provisionThresholdEd25519Session(
  deps: ProvisionThresholdEd25519SessionDeps,
  args: ProvisionWarmEd25519CapabilityArgs,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = String(args.relayerUrl || deps.defaultRelayerUrl || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const sessionKind = 'jwt';
  const source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'> =
    args.source === 'email_otp' ? 'manual-connect' : args.source || 'manual-connect';
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  if (!participantIds) {
    throw new Error('Missing participantIds for threshold Ed25519 session provision');
  }
  const workerCtx = deps.getSignerWorkerContext();
  const sessionId =
    args.kind === 'exact_ed25519_provisioning'
      ? String(args.sessionId || '').trim()
      : generateSessionId('threshold-ed25519');
  const connected = await connectEd25519Session({
    credentialStore: deps.credentialStore,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(args.auth ? { auth: args.auth } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
    nearAccountId,
    participantIds,
    sessionKind,
    sessionId,
    ...(args.kind === 'exact_ed25519_provisioning'
      ? { walletSigningSessionId: args.walletSigningSessionId }
      : {}),
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx,
  });
  if (!connected.ok) {
    return {
      ok: false,
      code: String(connected.code || 'worker_error').trim() || 'worker_error',
      message: String(connected.message || '').trim() || 'Threshold Ed25519 session mint failed',
    };
  }

  const resolvedSessionId = String(connected.sessionId || sessionId).trim();
  const walletSigningSessionId = String(connected.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(connected.expiresAtMs);
  const remainingUses = Number(connected.remainingUses);
  const jwt = String(connected.jwt || '').trim();
  const prfFirstB64u = String(connected.ecdsaHssPasskeyPrfFirstB64u || '').trim();
  if (
    !resolvedSessionId ||
    !walletSigningSessionId ||
    !Number.isFinite(expiresAtMs) ||
    !Number.isFinite(remainingUses) ||
    !jwt
  ) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    };
  }

  const persist = deps.persistWarmSessionEd25519Capability || persistWarmSessionEd25519Capability;
  persist({
    kind: 'jwt_passkey',
    nearAccountId,
    rpId: deps.touchIdPrompt.getRpId(),
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(connected.runtimePolicyScope || args.runtimePolicyScope
      ? { runtimePolicyScope: connected.runtimePolicyScope || args.runtimePolicyScope }
      : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    participantIds,
    sessionKind: 'jwt',
    sessionId: resolvedSessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    jwt,
    source,
  });

  if (prfFirstB64u) {
    try {
      await cacheSigningSessionPrfFirst(deps.touchConfirm, {
        sessionId: resolvedSessionId,
        prfFirstB64u,
        expiresAtMs,
        remainingUses,
        transport: {
          curve: 'ed25519',
          walletId: String(nearAccountId),
          relayerUrl,
          walletSigningSessionId,
          ...(jwt ? { walletSessionJwt: jwt } : {}),
        },
      });
    } catch (error: unknown) {
      const details = String(
        error && typeof error === 'object' && 'message' in error
          ? (error as { message?: unknown }).message
          : error || '',
      ).trim();
      return {
        ok: false,
        code: 'warm_session_cache_failed',
        message: details || 'Threshold Ed25519 session material could not be cached',
      };
    }
  }

  return {
    ok: true,
    sessionId: resolvedSessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    ...(connected.runtimePolicyScope ? { runtimePolicyScope: connected.runtimePolicyScope } : {}),
    jwt,
    ...(connected.ecdsaHssPasskeyPrfFirstB64u
      ? { ecdsaHssPasskeyPrfFirstB64u: connected.ecdsaHssPasskeyPrfFirstB64u }
      : {}),
  };
}
