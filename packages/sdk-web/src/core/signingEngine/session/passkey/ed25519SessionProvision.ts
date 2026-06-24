import { toAccountId } from '@/core/types/accountIds';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { connectEd25519Session } from '../../threshold/ed25519/connectSession';
import { cacheCredentialBoundarySetupExportPrfFirst, generateSessionId } from './prfCache';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
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
type Ed25519MintAuthorization = NonNullable<ConnectEd25519SessionInput['auth']>;

export type ProvisionThresholdEd25519SessionDeps = {
  credentialStore: ConnectEd25519SessionInput['credentialStore'];
  touchIdPrompt: ConnectEd25519SessionInput['touchIdPrompt'];
  touchConfirm: Parameters<typeof cacheCredentialBoundarySetupExportPrfFirst>[0];
  defaultRelayerUrl: string;
  getSignerWorkerContext: () => ConnectEd25519SessionInput['workerCtx'];
  persistWarmSessionEd25519Capability?: (args: PersistWarmSessionEd25519CapabilityArgs) => unknown;
};

function sealTransportForProvisionedEd25519Session(args: {
  source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
  walletId: string;
  relayerUrl: string;
  signingGrantId: string;
  walletSessionJwt: string;
}): WarmSessionSealTransportInput | undefined {
  if (args.source === 'login') return undefined;
  return {
    curve: 'ed25519',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    signingGrantId: args.signingGrantId,
    ...(args.walletSessionJwt ? { walletSessionJwt: args.walletSessionJwt } : {}),
  };
}

function passkeyCredentialIdB64uFromMintAuthorization(auth: Ed25519MintAuthorization): string {
  switch (auth.kind) {
    case 'app_session_jwt':
    case 'app_session_cookie': {
      const credentialIdB64u = String(
        auth.localSecretSource.credential.rawId || auth.localSecretSource.credential.id || '',
      ).trim();
      if (!credentialIdB64u) {
        throw new Error('[threshold-ed25519] passkey credential id is required');
      }
      return credentialIdB64u;
    }
    case 'threshold_session_policy_webauthn': {
      const credentialIdB64u = String(
        auth.policySecretSource.credential.rawId || auth.policySecretSource.credential.id || '',
      ).trim();
      if (!credentialIdB64u) {
        throw new Error('[threshold-ed25519] passkey credential id is required');
      }
      return credentialIdB64u;
    }
    case 'threshold_ecdsa_session_jwt':
      throw new Error('[threshold-ed25519] threshold ECDSA authorization must provide passkey auth');
  }
  auth satisfies never;
  throw new Error('[threshold-ed25519] unsupported mint authorization');
}

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
    walletId: args.walletId,
    ed25519KeyScopeId: args.ed25519KeyScopeId,
    ...(args.auth ? { auth: args.auth } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
    nearAccountId,
    participantIds,
    sessionKind,
    sessionId,
    ...(args.kind === 'exact_ed25519_provisioning'
      ? { signingGrantId: args.signingGrantId }
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
  const signingGrantId = String(connected.signingGrantId || '').trim();
  const expiresAtMs = Number(connected.expiresAtMs);
  const remainingUses = Number(connected.remainingUses);
  const jwt = String(connected.jwt || '').trim();
  const prfFirstB64u = String(connected.ecdsaHssPasskeyPrfFirstB64u || '').trim();
  if (
    !resolvedSessionId ||
    !signingGrantId ||
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
  if (!args.auth) {
    throw new Error('[threshold-ed25519] passkey mint authorization is required');
  }
  persist({
    kind: 'jwt_passkey',
    walletId: args.walletId,
    nearAccountId,
    ed25519KeyScopeId: args.ed25519KeyScopeId,
    rpId: deps.touchIdPrompt.getRpId(),
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    ...(connected.runtimePolicyScope || args.runtimePolicyScope
      ? { runtimePolicyScope: connected.runtimePolicyScope || args.runtimePolicyScope }
      : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    participantIds,
    sessionKind: 'jwt',
    signerSlot: args.signerSlot,
    sessionId: resolvedSessionId,
    signingGrantId,
    expiresAtMs,
    remainingUses,
    jwt,
    passkeyCredentialIdB64u: passkeyCredentialIdB64uFromMintAuthorization(args.auth),
    source,
  });

  if (prfFirstB64u) {
    const transport = sealTransportForProvisionedEd25519Session({
      source,
      walletId: args.walletId,
      relayerUrl,
      signingGrantId,
      walletSessionJwt: jwt,
    });
    try {
      await cacheCredentialBoundarySetupExportPrfFirst(deps.touchConfirm, {
        sessionId: resolvedSessionId,
        prfFirstB64u,
        expiresAtMs,
        remainingUses,
        ...(transport ? { transport } : {}),
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
    signingGrantId,
    expiresAtMs,
    remainingUses,
    ...(connected.runtimePolicyScope ? { runtimePolicyScope: connected.runtimePolicyScope } : {}),
    jwt,
    ...(connected.ecdsaHssPasskeyPrfFirstB64u
      ? { ecdsaHssPasskeyPrfFirstB64u: connected.ecdsaHssPasskeyPrfFirstB64u }
      : {}),
  };
}
