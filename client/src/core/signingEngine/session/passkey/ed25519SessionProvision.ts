import { toAccountId } from '@/core/types/accountIds';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { connectEd25519Session } from '../../threshold/ed25519/connectSession';
import {
  cacheSigningSessionPrfFirstBestEffort,
  generateSessionId,
} from './prfCache';
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
  indexedDB: ConnectEd25519SessionInput['indexedDB'];
  touchIdPrompt: ConnectEd25519SessionInput['touchIdPrompt'];
  touchConfirm: Parameters<typeof cacheSigningSessionPrfFirstBestEffort>[0];
  defaultRelayerUrl: string;
  getSignerWorkerContext: () => ConnectEd25519SessionInput['workerCtx'];
  persistWarmSessionEd25519Capability?: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown;
};

export async function provisionThresholdEd25519Session(
  deps: ProvisionThresholdEd25519SessionDeps,
  args: ProvisionWarmEd25519CapabilityArgs,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = String(args.relayerUrl || deps.defaultRelayerUrl || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const sessionKind = args.sessionKind === 'cookie' ? 'cookie' : 'jwt';
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
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
    ...(args.useAppSessionCookie ? { useAppSessionCookie: args.useAppSessionCookie } : {}),
    ...(args.localPrfCredential ? { localPrfCredential: args.localPrfCredential } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
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
      message:
        String(connected.message || '').trim() || 'Threshold Ed25519 session mint failed',
    };
  }

  const resolvedSessionId = String(connected.sessionId || sessionId).trim();
  const walletSigningSessionId = String(connected.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(connected.expiresAtMs);
  const remainingUses = Number(connected.remainingUses);
  const jwt = String(connected.jwt || '').trim();
  if (
    !resolvedSessionId ||
    !walletSigningSessionId ||
    !Number.isFinite(expiresAtMs) ||
    !Number.isFinite(remainingUses) ||
    (sessionKind === 'jwt' && !jwt)
  ) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    };
  }

  const persist = deps.persistWarmSessionEd25519Capability || persistWarmSessionEd25519Capability;
  if (sessionKind === 'cookie') {
    persist({
      kind: 'cookie_passkey',
      nearAccountId,
      rpId: deps.touchIdPrompt.getRpId(),
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      ...(connected.runtimePolicyScope || args.runtimePolicyScope
        ? { runtimePolicyScope: connected.runtimePolicyScope || args.runtimePolicyScope }
        : {}),
      participantIds,
      sessionKind: 'cookie',
      sessionId: resolvedSessionId,
      walletSigningSessionId,
      expiresAtMs,
      remainingUses,
      source,
    });
  } else {
    persist({
      kind: 'jwt_passkey',
      nearAccountId,
      rpId: deps.touchIdPrompt.getRpId(),
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      ...(connected.runtimePolicyScope || args.runtimePolicyScope
        ? { runtimePolicyScope: connected.runtimePolicyScope || args.runtimePolicyScope }
        : {}),
      participantIds,
      sessionKind: 'jwt',
      sessionId: resolvedSessionId,
      walletSigningSessionId,
      expiresAtMs,
      remainingUses,
      jwt,
      source,
    });
  }

  const prfFirstB64u = String(connected.ecdsaHssClientRootShare32B64u || '').trim();
  if (prfFirstB64u) {
    await cacheSigningSessionPrfFirstBestEffort(deps.touchConfirm, {
      sessionId: resolvedSessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
      transport: {
        curve: 'ed25519',
        relayerUrl,
        walletSigningSessionId,
        thresholdSessionAuthToken: jwt,
      },
    });
  }

  return {
    ok: true,
    sessionId: resolvedSessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    ...(connected.runtimePolicyScope ? { runtimePolicyScope: connected.runtimePolicyScope } : {}),
    jwt,
    ...(connected.ecdsaHssClientRootShare32B64u
      ? { ecdsaHssClientRootShare32B64u: connected.ecdsaHssClientRootShare32B64u }
      : {}),
  };
}
