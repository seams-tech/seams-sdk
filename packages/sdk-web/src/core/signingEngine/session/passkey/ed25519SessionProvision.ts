import { toAccountId, type AccountId } from '@/core/types/accountIds';
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
import { nearProtocolProjectionFromExactLane } from '../identity/exactSigningLaneIdentity';

type ConnectEd25519SessionInput = Parameters<typeof connectEd25519Session>[0];
type Ed25519MintAuthorization = NonNullable<ConnectEd25519SessionInput['auth']>;

type ResolvedEd25519ProvisionProtocol =
  | {
      kind: 'fresh';
      walletId: string;
      nearAccountId: AccountId | string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      sessionId: string;
      signingGrantId?: never;
    }
  | {
      kind: 'exact';
      walletId: string;
      nearAccountId: AccountId | string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      sessionId: string;
      signingGrantId: string;
    };

export type ProvisionThresholdEd25519SessionDeps = {
  credentialStore: ConnectEd25519SessionInput['credentialStore'];
  touchIdPrompt: ConnectEd25519SessionInput['touchIdPrompt'];
  touchConfirm: Parameters<typeof cacheCredentialBoundarySetupExportPrfFirst>[0];
  defaultRelayerUrl: string;
  getSignerWorkerContext: () => ConnectEd25519SessionInput['workerCtx'];
  persistWarmSessionEd25519Capability?: (args: PersistWarmSessionEd25519CapabilityArgs) => unknown;
};

function sealTransportForProvisionedEd25519Session(args: {
  walletId: string;
  relayerUrl: string;
  signingGrantId: string;
  walletSessionJwt: string;
}): WarmSessionSealTransportInput {
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
    case 'threshold_session_policy_webauthn':
    case 'router_ab_ed25519_yao_budget_refresh_v1': {
      const credentialIdB64u = String(
        auth.policySecretSource.credential.rawId || auth.policySecretSource.credential.id || '',
      ).trim();
      if (!credentialIdB64u) {
        throw new Error('[threshold-ed25519] passkey credential id is required');
      }
      return credentialIdB64u;
    }
    case 'threshold_ecdsa_session_jwt':
      throw new Error(
        '[threshold-ed25519] threshold ECDSA authorization must provide passkey auth',
      );
  }
  auth satisfies never;
  throw new Error('[threshold-ed25519] unsupported mint authorization');
}

function resolveEd25519ProvisionProtocol(
  args: ProvisionWarmEd25519CapabilityArgs,
): ResolvedEd25519ProvisionProtocol {
  switch (args.kind) {
    case 'fresh_ed25519_provisioning':
      return {
        kind: 'fresh',
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
        signerSlot: args.signerSlot,
        sessionId: generateSessionId('threshold-ed25519'),
      };
    case 'exact_ed25519_provisioning': {
      const projection = nearProtocolProjectionFromExactLane(
        args.laneIdentity,
        'exact Ed25519 capability provisioning',
      );
      return {
        kind: 'exact',
        walletId: String(projection.walletId),
        nearAccountId: projection.nearAccountId,
        nearEd25519SigningKeyId: String(projection.nearEd25519SigningKeyId),
        signerSlot: projection.signerSlot,
        sessionId: String(args.laneIdentity.thresholdSessionId),
        signingGrantId: String(args.laneIdentity.signingGrantId),
      };
    }
  }
  args satisfies never;
  throw new Error('[threshold-ed25519] unsupported Ed25519 provisioning kind');
}

function exactEd25519ProvisionReturnedDifferentIdentity(args: {
  requested: ResolvedEd25519ProvisionProtocol;
  returnedSessionId: string;
  returnedSigningGrantId: string;
}): boolean {
  switch (args.requested.kind) {
    case 'fresh':
      return false;
    case 'exact':
      return (
        args.returnedSessionId !== args.requested.sessionId ||
        args.returnedSigningGrantId !== args.requested.signingGrantId
      );
  }
  args.requested satisfies never;
  throw new Error('[threshold-ed25519] unsupported resolved provisioning identity');
}

export async function provisionThresholdEd25519Session(
  deps: ProvisionThresholdEd25519SessionDeps,
  args: ProvisionWarmEd25519CapabilityArgs,
): Promise<ProvisionWarmEd25519CapabilityResult> {
  const protocol = resolveEd25519ProvisionProtocol(args);
  const nearAccountId = toAccountId(protocol.nearAccountId);
  const relayerUrl = String(args.relayerUrl || deps.defaultRelayerUrl || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const sessionKind = 'jwt';
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  if (!participantIds) {
    throw new Error('Missing participantIds for threshold Ed25519 session provision');
  }
  const workerCtx = deps.getSignerWorkerContext();
  const connected = await connectEd25519Session({
    credentialStore: deps.credentialStore,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    walletId: protocol.walletId,
    nearEd25519SigningKeyId: protocol.nearEd25519SigningKeyId,
    authority: args.authority,
    ...(args.auth ? { auth: args.auth } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    routerAbNormalSigning: args.routerAbNormalSigning,
    ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
    nearAccountId,
    participantIds,
    sessionKind,
    sessionId: protocol.sessionId,
    ...(protocol.kind === 'exact'
      ? { signingGrantId: protocol.signingGrantId }
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

  const resolvedSessionId = String(connected.sessionId || protocol.sessionId).trim();
  const signingGrantId = String(connected.signingGrantId || '').trim();
  const expiresAtMs = Number(connected.expiresAtMs);
  const remainingUses = Number(connected.remainingUses);
  const jwt = String(connected.jwt || '').trim();
  const prfFirstB64u = String(connected.ecdsaDerivationPasskeyPrfFirstB64u || '').trim();
  const runtimePolicyScope = connected.runtimePolicyScope || args.runtimePolicyScope;
  if (
    !resolvedSessionId ||
    !signingGrantId ||
    !Number.isFinite(expiresAtMs) ||
    !Number.isFinite(remainingUses) ||
    !jwt ||
    !runtimePolicyScope
  ) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 session mint returned incomplete public session metadata',
    };
  }
  if (
    exactEd25519ProvisionReturnedDifferentIdentity({
      requested: protocol,
      returnedSessionId: resolvedSessionId,
      returnedSigningGrantId: signingGrantId,
    })
  ) {
    return {
      ok: false,
      code: 'invalid_result',
      message: 'Threshold Ed25519 exact provisioning returned a different lifecycle identity',
    };
  }

  const persist = deps.persistWarmSessionEd25519Capability || persistWarmSessionEd25519Capability;
  if (args.source === 'email_otp') {
    persist({
      kind: 'jwt_email_otp',
      walletId: protocol.walletId,
      nearAccountId,
      nearEd25519SigningKeyId: protocol.nearEd25519SigningKeyId,
      rpId: deps.touchIdPrompt.getRpId(),
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      runtimePolicyScope,
      routerAbNormalSigning: args.routerAbNormalSigning,
      participantIds,
      signerSlot: protocol.signerSlot,
      sessionId: resolvedSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses,
      jwt,
      emailOtpAuthContext: args.emailOtpAuthContext,
      source: 'email_otp',
    });
  } else {
    const passkeyAuth = args.auth;
    if (!passkeyAuth) {
      throw new Error('[threshold-ed25519] passkey mint authorization is required');
    }
    persist({
      kind: 'jwt_passkey',
      walletId: protocol.walletId,
      nearAccountId,
      nearEd25519SigningKeyId: protocol.nearEd25519SigningKeyId,
      rpId: deps.touchIdPrompt.getRpId(),
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      runtimePolicyScope,
      routerAbNormalSigning: args.routerAbNormalSigning,
      participantIds,
      signerSlot: protocol.signerSlot,
      sessionId: resolvedSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses,
      jwt,
      passkeyCredentialIdB64u: passkeyCredentialIdB64uFromMintAuthorization(passkeyAuth),
      source: args.source,
    });
  }

  if (prfFirstB64u) {
    const transport = sealTransportForProvisionedEd25519Session({
      walletId: protocol.walletId,
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
        transport,
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
    ...(connected.ecdsaDerivationPasskeyPrfFirstB64u
      ? { ecdsaDerivationPasskeyPrfFirstB64u: connected.ecdsaDerivationPasskeyPrfFirstB64u }
      : {}),
  };
}
