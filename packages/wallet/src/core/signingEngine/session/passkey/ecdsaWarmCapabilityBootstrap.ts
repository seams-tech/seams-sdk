import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { DurableRecordStore } from '@/core/platform';
import type { PasskeyMpcSessionPort } from '../../uiConfirm/uiConfirm.types';
import { SigningOperationIntent } from '../operationState/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  ecdsaBootstrapChainTarget,
  ecdsaBootstrapWalletId,
  type EcdsaBootstrapRequest,
  type WalletSessionActivationDeps,
} from './ecdsaBootstrap';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '../warmCapabilities/sealedRefreshParity';
import {
  provisionThresholdEcdsaSessionFromBootstrapArgs,
  type ProvisionThresholdEcdsaSessionDeps,
} from './ecdsaSessionProvision';
import type { WarmSessionCapabilityReader } from '../warmCapabilities/types';
import { walletSessionFailureFromError } from '../lifecycle/walletSessionFailure';

export type BootstrapWarmEcdsaCapabilityDeps = {
  ensureSealedRefreshStartupParity: () => Promise<void>;
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: WalletSessionActivationDeps;
  passkeyMpcSession: PasskeyMpcSessionPort;
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  capabilityReader: WarmSessionCapabilityReader;
};

export type NoPromptWarmSessionDeps = {
  getWarmSession: WarmSessionCapabilityReader['getWarmSession'];
  discoverPersistedSessionsForWallet: NonNullable<
    PasskeyMpcSessionPort['discoverPersistedSessionsForWallet']
  >;
  prompt?: never;
  webauthnPrompt?: never;
  touchIdPrompt?: never;
  passkeyCredentialCollector?: never;
  freshBootstrap?: never;
};

export type PromptCapableWarmupDeps = {
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: WalletSessionActivationDeps;
  passkeyMpcSession: PasskeyMpcSessionPort;
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
    persistEcdsaRoleLocalReadyRecord: deps.persistEcdsaRoleLocalReadyRecord,
  };
}

function createNoPromptWarmSessionDeps(
  deps: BootstrapWarmEcdsaCapabilityDeps,
): NoPromptWarmSessionDeps {
  return {
    getWarmSession: (walletId) => deps.capabilityReader.getWarmSession(walletId),
    discoverPersistedSessionsForWallet:
      deps.passkeyMpcSession.discoverPersistedSessionsForWallet.bind(deps.passkeyMpcSession),
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
  const code = sealedRestoreFailureCodeFromError(args.error);
  return {
    ok: false,
    code,
    chainTargetKey: args.chainTargetKey,
    errorMessage,
  };
}

function sealedRestoreFailureCodeFromError(error: unknown): ReuseWarmEcdsaBootstrapFailure['code'] {
  const walletSessionFailure = walletSessionFailureFromError(error);
  if (walletSessionFailure) {
    switch (walletSessionFailure.kind) {
      case 'expired':
        return 'sealed_record_expired';
      case 'exhausted':
        return 'sealed_record_exhausted';
      case 'missing':
      case 'invalid':
      case 'unavailable':
        return 'sealed_restore_failed';
    }
  }

  const code = error && typeof error === 'object' ? Reflect.get(error, 'code') : undefined;
  switch (code) {
    case 'expired':
      return 'sealed_record_expired';
    case 'exhausted':
      return 'sealed_record_exhausted';
    default:
      return 'sealed_restore_failed';
  }
}

export async function bootstrapReuseWarmEcdsaCapabilityNoPrompt(
  deps: NoPromptWarmSessionDeps,
  walletId: ReturnType<typeof toWalletId>,
  request: Extract<EcdsaBootstrapRequest, { kind: 'reuse_warm_ecdsa_bootstrap' }>,
): Promise<ReuseWarmEcdsaBootstrapResult> {
  const chainTarget = request.chainTarget;
  const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
  const warmSession = await deps.getWarmSession(walletId);
  if (warmSession.capabilities.ed25519.state !== 'ready') {
    return {
      ok: false,
      code: 'missing_exact_material',
      chainTargetKey,
    };
  }
  try {
    await deps.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_ecdsa_signing_sessions',
      walletId,
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
    case 'passkey_preauthorized_ecdsa_bootstrap':
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
