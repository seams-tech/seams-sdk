import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  ecdsaSigningTargetFromChainTarget,
  resolveEcdsaExportMaterialForLane,
  type EcdsaExportMaterial,
} from './ecdsaExportMaterial';
import {
  exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth,
  exportThresholdEcdsaKeyWithFreshPasskeyAuthorization,
  type EcdsaExportFlowDeps,
} from './ecdsaExportFlow';
import {
  resolveExactKeyExportLane as resolveExactKeyExportLaneValue,
  resolveEcdsaSessionForExport,
  type ExportLaneSelectionDeps,
} from './exportLaneSelection';
import {
  runKeyExportWithFlowEvents,
  type SigningEngineExportKeypairWithUIInput,
  type SigningEngineResolveExactKeyExportLaneInput,
  type SigningEngineResolveExactKeyExportLaneResult,
} from './keyExportFlow';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  exportEd25519YaoKeyWithFreshAuthorization,
  type Ed25519YaoExportFlowDeps,
} from './ed25519YaoExportFlow';
import { SIGNING_SESSION_EXPIRY_DETECTION_SOURCES } from '@/core/types/sdkSentEvents';
import {
  requireAuthoritativeExpiredWalletSessionAuthorizationBoundary,
  type ExpiredWalletSessionAuthorizationState,
  type WalletSessionAuthorizationIdentitySource,
  type WalletSessionAuthorizationState,
} from '../../session/identity/clientSessionPersistenceState';
import type { ReadClientWalletSessionAuthorizationRequest } from '../../session/persistence/clientSessionPersistence';
import { walletSessionFailureFromError } from '../../session/lifecycle/walletSessionFailure';

export type KeyExportWalletSessionLifecycleDeps = {
  readonly readAuthorization: (
    args: ReadClientWalletSessionAuthorizationRequest,
  ) => Promise<WalletSessionAuthorizationState>;
  readonly invalidateExpiredAuthorization: (args: {
    readonly state: ExpiredWalletSessionAuthorizationState;
    readonly source:
      | typeof SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.operationPreflight
      | typeof SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection;
  }) => Promise<void>;
};

export type ExportKeypairWithUIDeps = {
  laneSelection: ExportLaneSelectionDeps;
  ecdsa: EcdsaExportFlowDeps;
  ed25519Yao: Ed25519YaoExportFlowDeps;
  sessionLifecycle: KeyExportWalletSessionLifecycleDeps;
};

type ExportedKeySchemes = Array<'ed25519' | 'secp256k1'>;
type ExportKeypairResult = { accountId: string; exportedSchemes: ExportedKeySchemes };

type PreparedEcdsaExport = {
  exportLane: Awaited<ReturnType<typeof resolveEcdsaSessionForExport>>;
  exportMaterial: EcdsaExportMaterial;
};

type KeyExportAttempt =
  | { readonly kind: 'initial' }
  | { readonly kind: 'fresh_auth_retry' };

function authorizationWithExpiry(
  state: WalletSessionAuthorizationState,
): Extract<WalletSessionAuthorizationState, { readonly kind: 'active' | 'expired' }> | null {
  switch (state.kind) {
    case 'active':
    case 'expired':
      return state;
    case 'missing':
    case 'unavailable':
    case 'invalid':
      return null;
    default: {
      const exhaustive: never = state;
      return exhaustive;
    }
  }
}

async function invalidateExpiredExportAuthorization(args: {
  readonly deps: ExportKeypairWithUIDeps;
  readonly state: ExpiredWalletSessionAuthorizationState;
  readonly source:
    | typeof SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.operationPreflight
    | typeof SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection;
}): Promise<void> {
  await args.deps.sessionLifecycle.invalidateExpiredAuthorization({
    state: args.state,
    source: args.source,
  });
}

async function readAndInvalidateExpiredExportAuthorization(args: {
  readonly deps: ExportKeypairWithUIDeps;
  readonly request: ReadClientWalletSessionAuthorizationRequest;
}): Promise<WalletSessionAuthorizationState> {
  const state = await args.deps.sessionLifecycle.readAuthorization(args.request);
  if (state.kind === 'expired') {
    await invalidateExpiredExportAuthorization({
      deps: args.deps,
      state,
      source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.operationPreflight,
    });
  }
  return state;
}

function authoritativeExpiredExportAuthorization(args: {
  readonly source: WalletSessionAuthorizationIdentitySource;
  readonly preflightState: WalletSessionAuthorizationState;
  readonly detectedAtMs: number;
}): ExpiredWalletSessionAuthorizationState | null {
  const stateWithExpiry = authorizationWithExpiry(args.preflightState);
  if (!stateWithExpiry) return null;
  return requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
    source: args.source,
    expiresAtMs: stateWithExpiry.expiresAtMs,
    detectedAtMs: args.detectedAtMs,
  });
}

async function prepareEcdsaExport(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }>,
): Promise<PreparedEcdsaExport> {
  const walletId = toWalletId(args.walletSession.walletId);
  const exportLane = await resolveEcdsaSessionForExport(deps.laneSelection, {
    walletId,
    signingTarget: ecdsaSigningTargetFromChainTarget(args.chainTarget),
    laneIdentity: args.laneIdentity,
  });
  const exportMaterial = await resolveEcdsaExportMaterialForLane(
    deps.ecdsa.sessionStore,
    exportLane,
  );
  return { exportLane, exportMaterial };
}

function emitEcdsaExportFailureDiagnostics(args: {
  input: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }>;
  flowId: string;
  exportLane?: Awaited<ReturnType<typeof resolveEcdsaSessionForExport>>;
  exportMaterial?: EcdsaExportMaterial;
  error: unknown;
}): void {
  const publicFacts = args.exportMaterial?.publicFacts || args.exportLane?.publicFacts;
  const keyFingerprint = args.exportLane
    ? deriveEvmFamilyKeyFingerprintFromPublicFacts({
        walletId: args.exportLane.key.walletId,
        publicFacts: args.exportLane.publicFacts,
      })
    : undefined;
  try {
    console.warn('[SigningEngine][ecdsa-export][failure]', {
      operationId: args.flowId,
      authMethod: args.exportLane?.authMethod,
      ...(keyFingerprint ? { evmFamilyKeyFingerprint: keyFingerprint } : {}),
      ...(publicFacts ? { keyHandle: String(publicFacts.keyHandle) } : {}),
      chainTargetKey: thresholdEcdsaChainTargetKey(args.input.chainTarget),
      ...(args.exportLane?.authorization
        ? { walletSessionId: args.exportLane.authorization.projection.walletSessionId }
        : {}),
      materialActivationId:
        args.exportLane?.laneIdentity.signer.materialActivation.activationId,
      freshAuthRetrySideEffectState: 'not_applicable',
      error:
        args.error instanceof Error ? args.error.message : String(args.error || 'unknown error'),
    });
  } catch {}
}

async function executePreparedEcdsaExport(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }> & { flowId: string },
  prepared: PreparedEcdsaExport,
): Promise<ExportKeypairResult> {
  const walletId = toWalletId(args.walletSession.walletId);
  if (prepared.exportMaterial.kind === 'fresh_email_otp_route_auth_ready') {
    return await exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(deps.ecdsa, {
      walletId,
      exportLane: prepared.exportLane,
      material: prepared.exportMaterial,
      options: {
        variant: args.options.variant,
        theme: args.options.theme,
      },
      flowId: args.flowId,
      onEvent: args.options.onEvent,
    });
  }
  if (prepared.exportMaterial.kind === 'fresh_passkey_needs_authorization') {
    return await exportThresholdEcdsaKeyWithFreshPasskeyAuthorization(deps.ecdsa, {
      walletId,
      exportLane: prepared.exportLane,
      material: prepared.exportMaterial,
      options: {
        variant: args.options.variant,
        theme: args.options.theme,
      },
      flowId: args.flowId,
      onEvent: args.options.onEvent,
    });
  }
  prepared.exportMaterial satisfies never;
  throw new Error('[SigningEngine][ecdsa-export] unsupported export material');
}

async function exportEcdsaKeypairWithSessionLifecycle(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }> & { flowId: string },
  attempt: KeyExportAttempt,
): Promise<ExportKeypairResult> {
  const [prepared] = await Promise.all([
    prepareEcdsaExport(deps, args),
    deps.ecdsa.touchConfirm.initialize(),
  ]);
  if (prepared.exportLane.authorizationState === 'authorization_required') {
    try {
      return await executePreparedEcdsaExport(deps, args, prepared);
    } catch (error: unknown) {
      emitEcdsaExportFailureDiagnostics({
        input: args,
        flowId: args.flowId,
        exportLane: prepared.exportLane,
        exportMaterial: prepared.exportMaterial,
        error,
      });
      throw error;
    }
  }
  const source: WalletSessionAuthorizationIdentitySource = {
    kind: 'ecdsa',
    laneIdentity: prepared.exportLane.laneIdentity,
    authorization: prepared.exportLane.authorization,
  };
  const preflightState = await readAndInvalidateExpiredExportAuthorization({
    deps,
    request: {
      kind: 'ecdsa',
      laneIdentity: prepared.exportLane.laneIdentity,
      authorization: prepared.exportLane.authorization,
      nowMs: Date.now(),
    },
  });
  try {
    return await executePreparedEcdsaExport(deps, args, prepared);
  } catch (error: unknown) {
    emitEcdsaExportFailureDiagnostics({
      input: args,
      flowId: args.flowId,
      exportLane: prepared.exportLane,
      exportMaterial: prepared.exportMaterial,
      error,
    });
    const failure = walletSessionFailureFromError(error);
    if (attempt.kind === 'fresh_auth_retry' || failure?.kind !== 'expired') throw error;
    const expiredState = authoritativeExpiredExportAuthorization({
      source,
      preflightState,
      detectedAtMs: Date.now(),
    });
    if (!expiredState) throw error;
    await invalidateExpiredExportAuthorization({
      deps,
      state: expiredState,
      source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection,
    });
    return await exportEcdsaKeypairWithSessionLifecycle(deps, args, {
      kind: 'fresh_auth_retry',
    });
  }
}

async function exportEd25519KeypairWithFlowId(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ed25519' }> & { flowId: string },
): Promise<ExportKeypairResult> {
  return await exportEd25519YaoKeyWithFreshAuthorization(deps.ed25519Yao, {
    walletId: args.walletSession.walletId,
    nearAccountId: args.nearAccount.accountId,
    laneIdentity: args.laneIdentity,
    materialActivation: args.materialActivation,
    options: {
      variant: args.options.variant,
      theme: args.options.theme,
    },
    flowId: args.flowId,
    onEvent: args.options.onEvent,
  });
}

async function exportEd25519KeypairWithSessionLifecycle(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ed25519' }> & { flowId: string },
): Promise<ExportKeypairResult> {
  return await exportEd25519KeypairWithFlowId(deps, args);
}

export async function exportKeypairWithUI(
  deps: ExportKeypairWithUIDeps,
  input: SigningEngineExportKeypairWithUIInput,
): Promise<ExportKeypairResult> {
  return await runKeyExportWithFlowEvents(input, async (args) => {
    switch (args.kind) {
      case 'ecdsa':
        return await exportEcdsaKeypairWithSessionLifecycle(deps, args, { kind: 'initial' });
      case 'ed25519':
        return await exportEd25519KeypairWithSessionLifecycle(deps, args);
    }
  });
}

export async function resolveExactKeyExportLane(
  deps: ExportKeypairWithUIDeps,
  input: SigningEngineResolveExactKeyExportLaneInput,
): Promise<SigningEngineResolveExactKeyExportLaneResult> {
  return await resolveExactKeyExportLaneValue(deps.laneSelection, input);
}

export type {
  SigningEngineExportKeypairWithUIInput,
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
} from './keyExportFlow';
