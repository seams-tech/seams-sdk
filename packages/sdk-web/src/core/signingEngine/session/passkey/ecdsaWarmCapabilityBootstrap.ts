import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { DurableSealedSessionPort, UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import { SigningOperationIntent } from '../operationState/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  thresholdEcdsaSessionRecordReadModel,
  listThresholdEcdsaSessionRecordsForWalletTarget,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import { parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord } from '../persistence/ecdsaRoleLocalRecords';
import {
  ecdsaBootstrapChainTarget,
  ecdsaBootstrapWalletId,
  type EcdsaBootstrapRequest,
  type WalletSessionActivationDeps,
} from './ecdsaBootstrap';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../warmCapabilities/sealedRefreshParity';
import {
  getPrimaryAndSecondaryEcdsaCapabilities,
  tryReuseReadyWarmEcdsaBootstrap,
} from '../../useCases/provisionEcdsaSession';
import { claimWarmSessionPrfFirst } from './prfClaim';
import {
  provisionThresholdEcdsaSessionFromBootstrapArgs,
  type ProvisionThresholdEcdsaSessionDeps,
} from './ecdsaSessionProvision';
import type { WarmSessionCapabilityReader } from '../warmCapabilities/types';
import { buildEvmFamilyEcdsaSessionLanePolicy } from '../identity/evmFamilyEcdsaIdentity';

type NoPromptEcdsaPasskeyPrfFirstClaim = {
  kind: 'claim_no_prompt_ecdsa_prf_first';
  walletId: ReturnType<typeof toAccountId>;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  chainTarget: Extract<
    EcdsaBootstrapRequest,
    { kind: 'reuse_warm_ecdsa_bootstrap' }
  >['chainTarget'];
  uses: 1;
};

export type BootstrapWarmEcdsaCapabilityDeps = {
  ensureSealedRefreshStartupParity: () => Promise<void>;
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: WalletSessionActivationDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  capabilityReader: WarmSessionCapabilityReader;
};

export type NoPromptWarmSessionDeps = {
  getWarmSession: WarmSessionCapabilityReader['getWarmSession'];
  restorePersistedSessionsForWallet: NonNullable<
    DurableSealedSessionPort['restorePersistedSessionsForWallet']
  >;
  claimEcdsaPasskeyPrfFirst: (args: NoPromptEcdsaPasskeyPrfFirstClaim) => Promise<string>;
  reconnectWithWalletSessionAuth: (
    request: Extract<
      EcdsaBootstrapRequest,
      { kind: 'wallet_session_reconnect_ecdsa_bootstrap' }
    >,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  prompt?: never;
  webauthnPrompt?: never;
  touchIdPrompt?: never;
  passkeyCredentialCollector?: never;
  freshBootstrap?: never;
};

export type PromptCapableWarmupDeps = {
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: WalletSessionActivationDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  capabilityReader: WarmSessionCapabilityReader;
};

export type ReuseWarmEcdsaBootstrapSuccess = {
  ok: true;
  source: 'volatile_material' | 'sealed_restore';
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
};

export type ReuseWarmEcdsaBootstrapFailure = {
  ok: false;
  code:
    | 'missing_exact_material'
    | 'sealed_restore_failed'
    | 'sealed_record_expired'
    | 'sealed_record_exhausted';
  chainTargetKey: string;
  errorMessage?: string;
  promptAllowed?: never;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u?: never;
};

export type ReuseWarmEcdsaBootstrapResult =
  | ReuseWarmEcdsaBootstrapSuccess
  | ReuseWarmEcdsaBootstrapFailure;

export type BootstrapWarmEcdsaCapabilityResult =
  | {
      ok: true;
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
    }
  | {
      ok: false;
      kind: 'reuse_failed';
      failure: ReuseWarmEcdsaBootstrapFailure;
      promptAllowed?: never;
      webauthnAuthentication?: never;
      passkeyPrfFirstB64u?: never;
    };

function createProvisionThresholdEcdsaSessionDeps(
  deps: PromptCapableWarmupDeps,
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

function createNoPromptWarmSessionDeps(
  deps: BootstrapWarmEcdsaCapabilityDeps,
): NoPromptWarmSessionDeps {
  const restorePersistedSessionsForWallet = deps.touchConfirm.restorePersistedSessionsForWallet;
  if (typeof restorePersistedSessionsForWallet !== 'function') {
    throw new Error('[SigningEngine][ecdsa] no-prompt reuse requires durable restore capability');
  }
  return {
    getWarmSession: (walletId) => deps.capabilityReader.getWarmSession(walletId),
    restorePersistedSessionsForWallet: restorePersistedSessionsForWallet.bind(deps.touchConfirm),
    claimEcdsaPasskeyPrfFirst: (args) =>
      claimWarmSessionPrfFirst({
        touchConfirm: deps.touchConfirm,
        thresholdSessionId: args.thresholdSessionId,
        errorContext: 'threshold-ecdsa authorization bootstrap',
        uses: args.uses,
        curve: 'ecdsa',
        chainTarget: args.chainTarget,
      }),
    reconnectWithWalletSessionAuth: (request) =>
      provisionThresholdEcdsaSessionFromBootstrapArgs(
        createProvisionThresholdEcdsaSessionDeps({
          queueByWallet: deps.queueByWallet,
          activationDeps: deps.activationDeps,
          touchConfirm: deps.touchConfirm,
          capabilityReader: deps.capabilityReader,
        }),
        request,
      ),
    ecdsaSessions: deps.ecdsaSessions,
  };
}

function parityArgsFromBootstrapRequest(
  request: EcdsaBootstrapRequest,
): Parameters<typeof ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap>[1] {
  const walletId = ecdsaBootstrapWalletId(request);
  const chainTarget = ecdsaBootstrapChainTarget(request);
  if (request.source === 'registration') {
    return {
      kind: 'key_enrollment_bootstrap_parity',
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
  deps: PromptCapableWarmupDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await provisionThresholdEcdsaSessionFromBootstrapArgs(
    createProvisionThresholdEcdsaSessionDeps(deps),
    request,
  );
}

function sealedRestoreFailureFromError(args: {
  chainTargetKey: string;
  error: unknown;
}): ReuseWarmEcdsaBootstrapResult {
  const errorMessage =
    args.error instanceof Error ? args.error.message : String(args.error || 'unknown error');
  const normalized = errorMessage.toLowerCase();
  const code = normalized.includes('exhausted')
    ? 'sealed_record_exhausted'
    : normalized.includes('expired')
      ? 'sealed_record_expired'
      : 'sealed_restore_failed';
  return {
    ok: false,
    code,
    chainTargetKey: args.chainTargetKey,
    errorMessage,
  };
}

function resolveNoPromptReconnectTtlMs(args: {
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>;
  recordExpiresAtMs: number;
}): number {
  const requestedTtlMs = Math.floor(Number(args.request.ttlMs));
  if (Number.isFinite(requestedTtlMs) && requestedTtlMs > 0) return requestedTtlMs;
  return Math.max(1, Math.floor(Number(args.recordExpiresAtMs) || 0) - Date.now());
}

function resolveNoPromptReconnectRemainingUses(args: {
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>;
  recordRemainingUses: number;
}): number {
  const requestedRemainingUses = Math.floor(Number(args.request.remainingUses));
  if (Number.isFinite(requestedRemainingUses) && requestedRemainingUses > 0) {
    return requestedRemainingUses;
  }
  return Math.max(1, Math.floor(Number(args.recordRemainingUses) || 0));
}

async function tryNoPromptWalletSessionReconnect(args: {
  deps: NoPromptWarmSessionDeps;
  walletId: ReturnType<typeof toAccountId>;
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>;
}): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
  const warmSession = await args.deps.getWarmSession(args.walletId);
  const { primary } = getPrimaryAndSecondaryEcdsaCapabilities({
    warmSession,
    chainTarget: args.request.chainTarget,
  });
  if (primary.record?.source === 'email_otp') return null;
  if (primary.state !== 'ready' || primary.prfClaim?.state !== 'warm') return null;
  const record = primary.record;
  const auth = primary.auth;
  if (!record || !auth?.walletSessionJwt) return null;

  const readModel = thresholdEcdsaSessionRecordReadModel(record);
  const readyRecord = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
  if (readyRecord.authMethod.kind !== 'passkey') return null;
  const passkeyPrfFirstB64u = await args.deps.claimEcdsaPasskeyPrfFirst({
    kind: 'claim_no_prompt_ecdsa_prf_first',
    walletId: args.walletId,
    walletSigningSessionId: record.walletSigningSessionId,
    thresholdSessionId: record.thresholdSessionId,
    chainTarget: args.request.chainTarget,
    uses: 1,
  });
  const relayerUrl = String(args.request.relayerUrl || record.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('[SigningEngine][ecdsa] no-prompt reconnect requires relayerUrl');
  }

  return await args.deps.reconnectWithWalletSessionAuth({
    kind: 'wallet_session_reconnect_ecdsa_bootstrap',
    source: args.request.source || record.source,
    relayerUrl,
    keyHandle: record.keyHandle,
    key: readModel.key,
    lanePolicy: buildEvmFamilyEcdsaSessionLanePolicy({
      chainTarget: args.request.chainTarget,
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
      thresholdSessionKind: 'jwt',
      ttlMs: resolveNoPromptReconnectTtlMs({
        request: args.request,
        recordExpiresAtMs: readModel.lane.expiresAtMs,
      }),
      remainingUses: resolveNoPromptReconnectRemainingUses({
        request: args.request,
        recordRemainingUses: readModel.lane.remainingUses,
      }),
      ...(args.request.runtimePolicyScope
        ? { runtimePolicyScope: args.request.runtimePolicyScope }
        : {}),
    }),
    operationIntent: args.request.operationIntent,
    runtimeScopeBootstrap: args.request.runtimeScopeBootstrap,
    routeAuth: {
      kind: 'wallet_session',
      jwt: auth.walletSessionJwt,
    },
    passkeyPrfFirstB64u,
    passkeyCredentialIdB64u: readyRecord.authMethod.credentialIdB64u,
  });
}

export async function bootstrapReuseWarmEcdsaCapabilityNoPrompt(
  deps: NoPromptWarmSessionDeps,
  walletId: ReturnType<typeof toAccountId>,
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>,
): Promise<ReuseWarmEcdsaBootstrapResult> {
  const chainTarget = request.chainTarget;
  const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
  const tryReusableBootstrap = async (): Promise<ThresholdEcdsaSessionBootstrapResult | null> =>
    await tryReuseReadyWarmEcdsaBootstrap(
      {
        getWarmSession: (warmSessionWalletId) => deps.getWarmSession(warmSessionWalletId),
        listThresholdEcdsaRecordsForWalletTarget: ({ walletId, chainTarget, source }) =>
          listThresholdEcdsaSessionRecordsForWalletTarget(deps.ecdsaSessions, {
            walletId,
            chainTarget,
            ...(source ? { source } : {}),
          }).map((record) => ({ source: record.source, record })),
      },
      {
        walletId: toWalletId(walletId),
        chainTarget,
        source: request.source,
      },
    );
  let reusableBootstrap = await tryReusableBootstrap();
  if (reusableBootstrap) {
    return {
      ok: true,
      source: 'volatile_material',
      bootstrap: reusableBootstrap,
    };
  }
  try {
    await deps.restorePersistedSessionsForWallet({
      kind: 'restore_wallet_ecdsa_signing_sessions',
      walletId,
      authMethod: 'passkey',
      ecdsaChainTargets: [chainTarget],
      maxRecords: 1,
    });
  } catch (error: unknown) {
    console.warn('[SigningEngine][ecdsa] reuse warm sealed restore failed', {
      walletId,
      chainTarget,
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
    return sealedRestoreFailureFromError({ chainTargetKey, error });
  }
  reusableBootstrap = await tryReusableBootstrap();
  if (reusableBootstrap) {
    return {
      ok: true,
      source: 'sealed_restore',
      bootstrap: reusableBootstrap,
    };
  }
  try {
    const reconnectedBootstrap = await tryNoPromptWalletSessionReconnect({
      deps,
      walletId,
      request,
    });
    if (reconnectedBootstrap) {
      return {
        ok: true,
        source: 'sealed_restore',
        bootstrap: reconnectedBootstrap,
      };
    }
  } catch (error: unknown) {
    console.warn('[SigningEngine][ecdsa] reuse warm threshold-session reconnect failed', {
      walletId,
      chainTarget,
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
    return sealedRestoreFailureFromError({ chainTargetKey, error });
  }

  return {
    ok: false,
    code: 'missing_exact_material',
    chainTargetKey,
  };
}

function reuseWarmEcdsaBootstrapFailureMessage(result: ReuseWarmEcdsaBootstrapFailure): string {
  const code = result.code;
  switch (code) {
    case 'missing_exact_material':
      return `[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap requires restored passkey ECDSA material for ${result.chainTargetKey}`;
    case 'sealed_restore_failed':
      return `[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap sealed restore failed for ${result.chainTargetKey}: ${result.errorMessage || 'unknown error'}`;
    case 'sealed_record_expired':
      return `[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap sealed record expired for ${result.chainTargetKey}`;
    case 'sealed_record_exhausted':
      return `[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap sealed record exhausted for ${result.chainTargetKey}`;
  }
  code satisfies never;
  return '[SigningEngine][ecdsa] reuse_warm_ecdsa_bootstrap failed';
}

export function reuseWarmEcdsaBootstrapFailureToError(
  result: ReuseWarmEcdsaBootstrapFailure,
): Error {
  return new Error(reuseWarmEcdsaBootstrapFailureMessage(result));
}

export async function bootstrapWarmEcdsaCapabilityResult(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  request: EcdsaBootstrapRequest,
): Promise<BootstrapWarmEcdsaCapabilityResult> {
  await ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
    deps.ensureSealedRefreshStartupParity,
    parityArgsFromBootstrapRequest(request),
  );
  const walletId = toAccountId(ecdsaBootstrapWalletId(request));
  switch (request.kind) {
    case 'reuse_warm_ecdsa_bootstrap': {
      const result = await bootstrapReuseWarmEcdsaCapabilityNoPrompt(
        createNoPromptWarmSessionDeps(deps),
        walletId,
        request,
      );
      if (result.ok) {
        return { ok: true, bootstrap: result.bootstrap };
      }
      return {
        ok: false,
        kind: 'reuse_failed',
        failure: result,
      };
    }
    case 'passkey_fresh_ecdsa_bootstrap':
    case 'wallet_session_reconnect_ecdsa_bootstrap':
    case 'email_otp_ecdsa_bootstrap':
      return {
        ok: true,
        bootstrap: await bootstrapDirectEcdsaRequest(deps, request),
      };
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported warm bootstrap request');
}

export async function bootstrapWarmEcdsaCapability(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const result = await bootstrapWarmEcdsaCapabilityResult(deps, request);
  if (result.ok) return result.bootstrap;
  const failureKind = result.kind;
  switch (failureKind) {
    case 'reuse_failed':
      throw reuseWarmEcdsaBootstrapFailureToError(result.failure);
  }
  failureKind satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported warm bootstrap result');
}
