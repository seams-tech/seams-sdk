import { toAccountId } from '@/core/types/accountIds';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import { SigningOperationIntent } from '../operationState/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  listThresholdEcdsaKeyRefsForTarget,
  thresholdEcdsaSessionRecordReadModel,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  ecdsaBootstrapChainTarget,
  ecdsaBootstrapWalletId,
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
import type { WarmSessionCapabilityReader } from '../warmCapabilities/types';
import { buildEvmFamilyEcdsaSessionLanePolicy } from '../identity/evmFamilyEcdsaIdentity';

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

function parityArgsFromBootstrapRequest(
  request: EcdsaBootstrapRequest,
): Parameters<typeof ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap>[1] {
  const walletId = ecdsaBootstrapWalletId(request);
  const chainTarget = ecdsaBootstrapChainTarget(request);
  if (request.source === 'registration') {
    return {
      kind: 'registration_bootstrap_parity',
      walletId,
      chainTarget,
    };
  }
  if (request.operationIntent === SigningOperationIntent.TransactionSign) {
    return {
      kind: 'transaction_bootstrap_parity',
      walletId,
      chainTarget,
      operationIntent: SigningOperationIntent.TransactionSign,
    };
  }
  if (request.kind === 'email_otp_ecdsa_bootstrap') {
    return {
      kind: 'email_otp_bootstrap_parity',
      walletId,
      chainTarget,
      authMethod: 'email_otp',
    };
  }
  return {
    kind: 'default_bootstrap_parity',
    walletId,
    chainTarget,
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
    ...(request.keyIntent ? { keyIntent: request.keyIntent } : {}),
    operationIntent: request.operationIntent,
    runtimePolicyScope: request.runtimePolicyScope,
    runtimeScopeBootstrap: request.runtimeScopeBootstrap,
    ttlMs: request.ttlMs,
    remainingUses: request.remainingUses,
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
  const tryReusableBootstrap = async (): Promise<ThresholdEcdsaSessionBootstrapResult | null> =>
    await tryReuseReadyWarmEcdsaBootstrap(
      {
        getWarmSession: (warmSessionWalletId) =>
          deps.capabilityReader.getWarmSession(warmSessionWalletId),
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
  let reusableBootstrap = await tryReusableBootstrap();
  if (reusableBootstrap) return reusableBootstrap;
  if (typeof deps.touchConfirm.restorePersistedSessionsForWallet === 'function') {
    await deps.touchConfirm
      .restorePersistedSessionsForWallet({
        walletId,
        authMethod: 'passkey',
        ecdsaChainTargets: [chainTarget],
        maxRecords: 1,
      })
      .catch((error: unknown) => {
        console.warn('[SigningEngine][ecdsa] reuse warm sealed restore failed', {
          walletId,
          chainTarget,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      });
  }
  reusableBootstrap = await tryReusableBootstrap();
  if (reusableBootstrap) return reusableBootstrap;

  const warmSession = await deps.capabilityReader.getWarmSession(walletId);
  const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
    warmSession,
    chainTarget,
  });
  const primaryPasskeyCapability =
    primary.record?.source === 'email_otp' ? null : primary.record ? primary : null;
  const reusableWarmCapability =
    primaryPasskeyCapability?.prfClaim?.state === 'warm' ? primaryPasskeyCapability : null;
  const reconnectableCapability = reusableWarmCapability || primaryPasskeyCapability;
  const preferredRecord =
    reconnectableCapability?.record || primary.record || secondary.record || null;
  const participantIds =
    normalizeParticipantIds(request.keyIntent?.participantIds) ||
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
    toOptionalNonEmptyString(request.keyIntent?.ecdsaThresholdKeyId) ||
    toOptionalNonEmptyString(primary.record?.ecdsaThresholdKeyId) ||
    toOptionalNonEmptyString(secondary.record?.ecdsaThresholdKeyId);
  const reusableSessionId = toOptionalNonEmptyString(
    reconnectableCapability?.record?.thresholdSessionId,
  );
  const reusableWalletSigningSessionId = toOptionalNonEmptyString(
    reconnectableCapability?.record?.walletSigningSessionId,
  );
  const reusableThresholdSessionAuthToken = toOptionalNonEmptyString(
    reconnectableCapability?.auth?.thresholdSessionAuthToken,
  );

  if (reusableSessionId && reusableWalletSigningSessionId && reusableThresholdSessionAuthToken) {
    if (!preferredRecord) {
      throw new Error(
        '[SigningEngine][ecdsa] reusable threshold-session bootstrap requires a canonical ECDSA record',
      );
    }
    const readModel = thresholdEcdsaSessionRecordReadModel(preferredRecord);
    const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
      chainTarget: request.chainTarget,
      thresholdSessionId: reusableSessionId,
      walletSigningSessionId: reusableWalletSigningSessionId,
      thresholdSessionKind: 'jwt',
      ttlMs: request.ttlMs || Math.max(1, readModel.lane.expiresAtMs - Date.now()),
      remainingUses: request.remainingUses || readModel.lane.remainingUses,
      ...(request.runtimePolicyScope ? { runtimePolicyScope: request.runtimePolicyScope } : {}),
    });
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
      source: request.source,
      relayerUrl,
      key: readModel.key,
      lanePolicy,
      operationIntent: request.operationIntent,
      runtimeScopeBootstrap: request.runtimeScopeBootstrap,
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
      ...(ecdsaThresholdKeyId && participantIds
        ? {
            keyIntent: {
              kind: 'existing_ecdsa_key',
              ecdsaThresholdKeyId,
              participantIds,
            },
          }
        : {}),
      operationIntent: request.operationIntent,
      runtimePolicyScope: request.runtimePolicyScope,
      runtimeScopeBootstrap: request.runtimeScopeBootstrap,
      ttlMs: request.ttlMs,
      remainingUses: request.remainingUses,
      sessionKind: 'cookie',
      sessionIdentity: buildEcdsaSessionIdentity({
        thresholdSessionId: reusableSessionId,
        walletSigningSessionId: reusableWalletSigningSessionId,
      }),
    });
  }

  throw new Error(
    `[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap requires restored passkey ECDSA material for ${thresholdEcdsaChainTargetKey(
      chainTarget,
    )}`,
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
  const walletId = toAccountId(ecdsaBootstrapWalletId(request));
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
