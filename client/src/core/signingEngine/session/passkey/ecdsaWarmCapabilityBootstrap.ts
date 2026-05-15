import { toAccountId } from '@/core/types/accountIds';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import { SigningOperationIntent } from '../operationState/types';
import type {
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import {
  listThresholdEcdsaKeyRefsForTarget,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  type EcdsaBootstrapRequest,
  type ThresholdSessionActivationDeps,
} from './ecdsaBootstrap';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../warmCapabilities/sealedRefreshParity';
import {
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
  tryReuseReadyWarmEcdsaBootstrap,
} from './ecdsaProvisioner';
import { claimPasskeyEcdsaPrfFirst } from './ecdsaRecovery';
import {
  provisionThresholdEcdsaSessionFromBootstrapArgs,
  type ProvisionThresholdEcdsaSessionDeps,
} from './ecdsaSessionProvision';
import { buildEcdsaSessionIdentity } from '../warmCapabilities/ecdsaProvisionPlan';
import type {
  WarmSessionCapabilityReader,
} from '../warmCapabilities/types';

export type BootstrapWarmEcdsaCapabilityDeps = {
  ensureSealedRefreshStartupParity: () => Promise<void>;
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: ThresholdSessionActivationDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  capabilityReader: WarmSessionCapabilityReader;
};

function createProvisionThresholdEcdsaSessionDeps(
  deps: BootstrapWarmEcdsaCapabilityDeps,
): ProvisionThresholdEcdsaSessionDeps {
  return {
    queueByWallet: deps.queueByWallet,
    activationDeps: deps.activationDeps,
    touchConfirm: deps.touchConfirm,
    resolveSealTransport: ({ thresholdSessionId, chainTarget }) =>
      deps.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
        thresholdSessionId,
        chainTarget,
      }),
  };
}

function parityArgsFromBootstrapRequest(request: EcdsaBootstrapRequest): Parameters<
  typeof ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap
>[1] {
  if (request.source === 'registration') {
    return {
      kind: 'registration_bootstrap_parity',
      walletId: request.walletId,
      chainTarget: request.chainTarget,
    };
  }
  if (request.operationIntent === SigningOperationIntent.TransactionSign) {
    return {
      kind: 'transaction_bootstrap_parity',
      walletId: request.walletId,
      chainTarget: request.chainTarget,
      operationIntent: SigningOperationIntent.TransactionSign,
    };
  }
  if (request.kind === 'email_otp_ecdsa_bootstrap') {
    return {
      kind: 'email_otp_bootstrap_parity',
      walletId: request.walletId,
      chainTarget: request.chainTarget,
      authMethod: 'email_otp',
    };
  }
  return {
    kind: 'default_bootstrap_parity',
    walletId: request.walletId,
    chainTarget: request.chainTarget,
  };
}

async function bootstrapDirectEcdsaRequest(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await provisionThresholdEcdsaSessionFromBootstrapArgs(
    createProvisionThresholdEcdsaSessionDeps(deps),
    request,
  );
}

async function bootstrapPasskeyCookieReconnect(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  walletId: ReturnType<typeof toAccountId>,
  request: Extract<EcdsaBootstrapRequest, { kind: 'passkey_cookie_reconnect_ecdsa_bootstrap' }>,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const clientRootShare32B64u = await claimPasskeyEcdsaPrfFirst({
    touchConfirm: deps.touchConfirm,
    walletId,
    walletSigningSessionId: request.sessionIdentity.walletSigningSessionId,
    thresholdSessionId: request.sessionIdentity.thresholdSessionId,
    chainTarget: request.chainTarget,
    errorContext: 'threshold-ecdsa restored-session bootstrap',
    uses: 1,
  });
  return await bootstrapDirectEcdsaRequest(deps, {
    kind: 'passkey_fresh_ecdsa_bootstrap',
    walletId,
    subjectId: request.subjectId,
    chainTarget: request.chainTarget,
    source: request.source,
    relayerUrl: request.relayerUrl,
    ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
    participantIds: request.participantIds,
    operationIntent: request.operationIntent,
    runtimePolicyScope: request.runtimePolicyScope,
    runtimeScopeBootstrap: request.runtimeScopeBootstrap,
    ttlMs: request.ttlMs,
    remainingUses: request.remainingUses,
    smartAccount: request.smartAccount,
    sessionKind: request.sessionKind,
    sessionIdentity: request.sessionIdentity,
    clientRootShare32B64u,
  });
}

async function bootstrapReuseWarmEcdsaCapability(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  walletId: ReturnType<typeof toAccountId>,
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const chainTarget = request.chainTarget;
  const reusableBootstrap = await tryReuseReadyWarmEcdsaBootstrap(
    {
      getWarmSession: (warmSessionWalletId) => deps.capabilityReader.getWarmSession(warmSessionWalletId),
      listThresholdEcdsaKeyRefsForWalletTarget: ({ subjectId, chainTarget, source }) =>
        listThresholdEcdsaKeyRefsForTarget(deps.ecdsaSessions, {
          subjectId,
          chainTarget,
          ...(source ? { source } : {}),
        }),
    },
    {
      walletId,
      subjectId: request.subjectId,
      chainTarget,
      source: request.source,
    },
  );
  if (reusableBootstrap) return reusableBootstrap;

  const warmSession = await deps.capabilityReader.getWarmSession(walletId);
  const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
    warmSession,
    chainTarget,
  });
  const primaryWarmCapability = primary.prfClaim?.state === 'warm' ? primary : null;
  const reusableWarmCapability = primaryWarmCapability;
  const preferredRecord = primary.record || secondary.record || null;
  const participantIds =
    normalizeParticipantIds(request.participantIds) ||
    normalizeParticipantIds(primary.record?.participantIds) ||
    normalizeParticipantIds(secondary.record?.participantIds);
  const relayerUrl =
    toOptionalNonEmptyString(request.relayerUrl) ||
    toOptionalNonEmptyString(preferredRecord?.relayerUrl) ||
    String(deps.activationDeps.defaultRelayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  const ecdsaThresholdKeyId =
    toOptionalNonEmptyString(request.ecdsaThresholdKeyId) ||
    toOptionalNonEmptyString(primary.record?.ecdsaThresholdKeyId) ||
    toOptionalNonEmptyString(secondary.record?.ecdsaThresholdKeyId);
  const reusableSessionId = toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId);
  const reusableWalletSigningSessionId = toOptionalNonEmptyString(
    reusableWarmCapability?.record?.walletSigningSessionId,
  );
  const reusableThresholdSessionAuthToken = toOptionalNonEmptyString(
    reusableWarmCapability?.auth?.thresholdSessionAuthToken,
  );

  if (reusableSessionId && reusableWalletSigningSessionId && reusableThresholdSessionAuthToken) {
    const clientRootShare32B64u = await claimPasskeyEcdsaPrfFirst({
      touchConfirm: deps.touchConfirm,
      walletId,
      walletSigningSessionId: reusableWalletSigningSessionId,
      thresholdSessionId: reusableSessionId,
      chainTarget: request.chainTarget,
      errorContext: 'threshold-ecdsa authorization bootstrap',
      uses: 1,
    });
    return await bootstrapDirectEcdsaRequest(deps, {
      kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
      walletId,
      subjectId: request.subjectId,
      chainTarget: request.chainTarget,
      source: request.source,
      relayerUrl,
      ecdsaThresholdKeyId: ecdsaThresholdKeyId || undefined,
      participantIds: participantIds || undefined,
      operationIntent: request.operationIntent,
      runtimePolicyScope: request.runtimePolicyScope,
      runtimeScopeBootstrap: request.runtimeScopeBootstrap,
      ttlMs: request.ttlMs,
      remainingUses: request.remainingUses,
      smartAccount: request.smartAccount,
      sessionKind: 'jwt',
      sessionIdentity: buildEcdsaSessionIdentity({
        thresholdSessionId: reusableSessionId,
        walletSigningSessionId: reusableWalletSigningSessionId,
      }),
      routeAuth: {
        kind: 'threshold_session',
        jwt: reusableThresholdSessionAuthToken,
      },
      clientRootShare32B64u,
    });
  }

  if (reusableSessionId && reusableWalletSigningSessionId) {
    return await bootstrapPasskeyCookieReconnect(deps, walletId, {
      kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
      walletId,
      subjectId: request.subjectId,
      chainTarget: request.chainTarget,
      source: request.source,
      relayerUrl,
      ecdsaThresholdKeyId: ecdsaThresholdKeyId || undefined,
      participantIds: participantIds || undefined,
      operationIntent: request.operationIntent,
      runtimePolicyScope: request.runtimePolicyScope,
      runtimeScopeBootstrap: request.runtimeScopeBootstrap,
      ttlMs: request.ttlMs,
      remainingUses: request.remainingUses,
      smartAccount: request.smartAccount,
      sessionKind: 'cookie',
      sessionIdentity: buildEcdsaSessionIdentity({
        thresholdSessionId: reusableSessionId,
        walletSigningSessionId: reusableWalletSigningSessionId,
      }),
    });
  }

  throw new Error(
    '[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap requires a reusable or reconnectable ECDSA lane',
  );
}

export async function bootstrapWarmEcdsaCapability(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  await ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
    deps.ensureSealedRefreshStartupParity,
    parityArgsFromBootstrapRequest(request),
  );
  const walletId = toAccountId(request.walletId);
  switch (request.kind) {
    case 'reuse_warm_ecdsa_bootstrap':
      return await bootstrapReuseWarmEcdsaCapability(deps, walletId, request);
    case 'passkey_fresh_ecdsa_bootstrap':
    case 'threshold_session_auth_reconnect_ecdsa_bootstrap':
    case 'email_otp_ecdsa_bootstrap':
      return await bootstrapDirectEcdsaRequest(deps, request);
    case 'passkey_cookie_reconnect_ecdsa_bootstrap':
      return await bootstrapPasskeyCookieReconnect(deps, walletId, request);
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported warm bootstrap request');
}
