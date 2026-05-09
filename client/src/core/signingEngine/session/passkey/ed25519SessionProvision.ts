import { toAccountId } from '@/core/types/accountIds';
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
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  const workerCtx = deps.getSignerWorkerContext();
  const sessionId = String(args.sessionId || '').trim() || generateSessionId('threshold-ed25519');
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
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx,
  });
  if (!connected.ok) {
    return connected;
  }

  const resolvedSessionId = String(connected.sessionId || sessionId).trim();
  const expiresAtMs = Number(connected.expiresAtMs);
  const remainingUses = Number(connected.remainingUses);
  if (!resolvedSessionId || !Number.isFinite(expiresAtMs) || !Number.isFinite(remainingUses)) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    };
  }

  const persist = deps.persistWarmSessionEd25519Capability || persistWarmSessionEd25519Capability;
  persist({
    nearAccountId,
    rpId: deps.touchIdPrompt.getRpId(),
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(connected.runtimePolicyScope || args.runtimePolicyScope
      ? { runtimePolicyScope: connected.runtimePolicyScope || args.runtimePolicyScope }
      : {}),
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId: resolvedSessionId,
    ...(connected.walletSigningSessionId
      ? { walletSigningSessionId: connected.walletSigningSessionId }
      : {}),
    expiresAtMs,
    remainingUses,
    jwt: connected.jwt,
    source: args.source || 'manual-connect',
  });

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
        ...(connected.walletSigningSessionId
          ? { walletSigningSessionId: connected.walletSigningSessionId }
          : {}),
        ...(typeof connected.jwt === 'string' && connected.jwt.trim()
          ? { thresholdSessionAuthToken: connected.jwt.trim() }
          : {}),
      },
    });
  }

  return connected;
}
