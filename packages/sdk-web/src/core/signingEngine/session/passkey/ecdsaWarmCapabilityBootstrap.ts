import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { DurableRecordStore } from '@/core/platform';
import type {
  DurableSealedSessionPort,
  UiConfirmRuntimeBridgePort,
} from '../../uiConfirm/uiConfirm.types';
import { SigningOperationIntent } from '../operationState/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  thresholdEcdsaSessionRecordReadModel,
  listThresholdEcdsaSessionRecordsForWalletTarget,
  requirePersistedEcdsaRoleLocalMaterial,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
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
import type { WarmSessionCapabilityReader, WarmSessionEnvelope } from '../warmCapabilities/types';
import { buildEvmFamilyEcdsaSessionLanePolicy } from '../identity/evmFamilyEcdsaIdentity';

type SharedEd25519WalletSessionGrant = {
  kind: 'shared_ed25519_wallet_session_grant_v1';
  signingGrantId: string;
  walletSessionJwt: string;
  remainingUses: number;
  expiresAtMs: number;
};

type PasskeyRoleLocalEcdsaRecord = {
  kind: 'passkey_role_local_ecdsa_record_v1';
  record: ThresholdEcdsaSessionRecord;
  passkeyCredentialIdB64u: string;
};

function resolveSharedEd25519WalletSessionGrant(
  warmSession: WarmSessionEnvelope,
): SharedEd25519WalletSessionGrant | null {
  const ed25519 = warmSession.capabilities.ed25519;
  const record = ed25519.record;
  const auth = ed25519.auth;
  const prfClaim = ed25519.prfClaim;
  const signingGrantId = String(record?.signingGrantId || '').trim();
  const walletSessionJwt =
    auth && 'walletSessionJwt' in auth ? String(auth.walletSessionJwt || '').trim() : '';
  if (!record || !signingGrantId || !walletSessionJwt || prfClaim?.state !== 'warm') {
    return null;
  }
  const remainingUses = Math.floor(Number(prfClaim.remainingUses));
  const expiresAtMs = Math.floor(Number(prfClaim.expiresAtMs));
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) return null;
  return {
    kind: 'shared_ed25519_wallet_session_grant_v1',
    signingGrantId,
    walletSessionJwt,
    remainingUses,
    expiresAtMs,
  };
}

function ecdsaBootstrapUsesSharedGrant(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  sharedGrant: SharedEd25519WalletSessionGrant;
}): boolean {
  return (
    String(args.bootstrap.session.signingGrantId || '').trim() === args.sharedGrant.signingGrantId
  );
}

function resolveSharedGrantReconnectTtlMs(args: {
  sharedGrant: SharedEd25519WalletSessionGrant;
  recordExpiresAtMs: number;
}): number {
  const sharedTtlMs = Math.max(0, args.sharedGrant.expiresAtMs - Date.now());
  const recordTtlMs = Math.max(0, Math.floor(Number(args.recordExpiresAtMs)) - Date.now());
  const candidates = [sharedTtlMs, recordTtlMs];
  return Math.max(1, Math.min(...candidates.filter((value) => value > 0)));
}

function selectPasskeyRoleLocalEcdsaRecord(args: {
  deps: Pick<NoPromptWarmSessionDeps, 'ecdsaSessions'>;
  walletId: ReturnType<typeof toWalletId>;
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>;
}): PasskeyRoleLocalEcdsaRecord | null {
  const records = listThresholdEcdsaSessionRecordsForWalletTarget(args.deps.ecdsaSessions, {
    walletId: toWalletId(args.walletId),
    chainTarget: args.request.chainTarget,
    ...(args.request.source ? { source: args.request.source } : {}),
  });
  for (const record of records) {
    if (record.source === 'email_otp') continue;
    if (record.ecdsaRoleLocalAuthMethod.kind !== 'passkey') continue;
    const passkeyCredentialIdB64u = String(
      record.ecdsaRoleLocalAuthMethod.credentialIdB64u || '',
    ).trim();
    if (!passkeyCredentialIdB64u) continue;
    return {
      kind: 'passkey_role_local_ecdsa_record_v1',
      record,
      passkeyCredentialIdB64u,
    };
  }
  return null;
}

type NoPromptEcdsaPasskeyPrfFirstClaim = {
  kind: 'claim_no_prompt_ecdsa_prf_first';
  walletId: ReturnType<typeof toWalletId>;
  signingGrantId: string;
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
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  capabilityReader: WarmSessionCapabilityReader;
};

export type NoPromptWarmSessionDeps = {
  getWarmSession: WarmSessionCapabilityReader['getWarmSession'];
  discoverPersistedSessionsForWallet: NonNullable<
    DurableSealedSessionPort['discoverPersistedSessionsForWallet']
  >;
  claimEcdsaPasskeyPrfFirst: (args: NoPromptEcdsaPasskeyPrfFirstClaim) => Promise<string>;
  reconnectWithWalletSessionAuth: (
    request: Extract<EcdsaBootstrapRequest, { kind: 'wallet_session_reconnect_ecdsa_bootstrap' }>,
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
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
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
    persistEcdsaRoleLocalReadyRecord: deps.persistEcdsaRoleLocalReadyRecord,
    resolveSealTransport: ({ lane }) =>
      deps.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
        lane,
      }),
  };
}

function createNoPromptWarmSessionDeps(
  deps: BootstrapWarmEcdsaCapabilityDeps,
): NoPromptWarmSessionDeps {
  const discoverPersistedSessionsForWallet = deps.touchConfirm.discoverPersistedSessionsForWallet;
  if (typeof discoverPersistedSessionsForWallet !== 'function') {
    throw new Error('[SigningEngine][ecdsa] no-prompt reuse requires durable discovery capability');
  }
  return {
    getWarmSession: (walletId) => deps.capabilityReader.getWarmSession(walletId),
    discoverPersistedSessionsForWallet: discoverPersistedSessionsForWallet.bind(deps.touchConfirm),
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
          persistEcdsaRoleLocalReadyRecord: deps.persistEcdsaRoleLocalReadyRecord,
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

async function tryNoPromptWalletSessionReconnect(args: {
  deps: NoPromptWarmSessionDeps;
  walletId: ReturnType<typeof toWalletId>;
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>;
  sharedGrant: SharedEd25519WalletSessionGrant;
}): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
  const selected = selectPasskeyRoleLocalEcdsaRecord({
    deps: args.deps,
    walletId: args.walletId,
    request: args.request,
  });
  if (!selected) return null;
  const record = selected.record;

  const readModel = thresholdEcdsaSessionRecordReadModel(record);
  const passkeyPrfFirstB64u = await args.deps.claimEcdsaPasskeyPrfFirst({
    kind: 'claim_no_prompt_ecdsa_prf_first',
    walletId: args.walletId,
    signingGrantId: record.signingGrantId,
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
    publicCapability: record.ecdsaRoleLocalPublicFacts.publicCapability,
    existingRoleLocalMaterial: requirePersistedEcdsaRoleLocalMaterial(record),
    lanePolicy: buildEvmFamilyEcdsaSessionLanePolicy({
      chainTarget: args.request.chainTarget,
      thresholdSessionId: record.thresholdSessionId,
      signingGrantId: args.sharedGrant.signingGrantId,
      thresholdSessionKind: 'jwt',
      ttlMs: resolveSharedGrantReconnectTtlMs({
        sharedGrant: args.sharedGrant,
        recordExpiresAtMs: readModel.lane.expiresAtMs,
      }),
      remainingUses: args.sharedGrant.remainingUses,
      ...(args.request.runtimePolicyScope
        ? { runtimePolicyScope: args.request.runtimePolicyScope }
        : {}),
    }),
    operationIntent: args.request.operationIntent,
    runtimeScopeBootstrap: args.request.runtimeScopeBootstrap,
    routeAuth: {
      kind: 'wallet_session',
      jwt: args.sharedGrant.walletSessionJwt,
    },
    passkeyPrfFirstB64u,
    passkeyCredentialIdB64u: selected.passkeyCredentialIdB64u,
  });
}

export async function bootstrapReuseWarmEcdsaCapabilityNoPrompt(
  deps: NoPromptWarmSessionDeps,
  walletId: ReturnType<typeof toWalletId>,
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>,
): Promise<ReuseWarmEcdsaBootstrapResult> {
  const chainTarget = request.chainTarget;
  const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
  const warmSession = await deps.getWarmSession(walletId);
  const sharedGrant = resolveSharedEd25519WalletSessionGrant(warmSession);
  if (!sharedGrant) {
    return {
      ok: false,
      code: 'missing_exact_material',
      chainTargetKey,
    };
  }
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
  if (
    reusableBootstrap &&
    ecdsaBootstrapUsesSharedGrant({ bootstrap: reusableBootstrap, sharedGrant })
  ) {
    return {
      ok: true,
      source: 'volatile_material',
      bootstrap: reusableBootstrap,
    };
  }
  try {
    await deps.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_ecdsa_signing_sessions',
      walletId,
      authMethod: 'passkey',
      ecdsaChainTargets: [chainTarget],
      maxRecords: 1,
    });
  } catch (error: unknown) {
    console.warn('[SigningEngine][ecdsa] reuse warm sealed discovery failed', {
      walletId,
      chainTarget,
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
    return sealedRestoreFailureFromError({ chainTargetKey, error });
  }
  reusableBootstrap = await tryReusableBootstrap();
  if (
    reusableBootstrap &&
    ecdsaBootstrapUsesSharedGrant({ bootstrap: reusableBootstrap, sharedGrant })
  ) {
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
      sharedGrant,
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
  const walletId = toWalletId(ecdsaBootstrapWalletId(request));
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
