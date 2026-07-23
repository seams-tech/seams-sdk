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
  exportThresholdEcdsaKeyWithAuthorization,
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
  exportEd25519YaoKeyWithFreshEmailOtp,
  exportEd25519YaoKeyWithFreshPasskey,
  type Ed25519YaoExportFlowDeps,
} from './ed25519YaoExportFlow';
import { SIGNING_SESSION_EXPIRY_DETECTION_SOURCES } from '@/core/types/sdkSentEvents';
import type { ExactSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import {
  requireAuthoritativeExpiredWalletSessionAuthorizationBoundary,
  type ExpiredWalletSessionAuthorizationState,
  type WalletSessionAuthorizationState,
} from '../../session/identity/clientSessionPersistenceState';
import { walletSessionFailureFromError } from '../../session/lifecycle/walletSessionFailure';

export type KeyExportWalletSessionLifecycleDeps = {
  readonly readAuthorization: (args: {
    readonly identity: ExactSigningLaneIdentity;
    readonly nowMs: number;
  }) => WalletSessionAuthorizationState;
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
  readonly identity: ExactSigningLaneIdentity;
}): Promise<WalletSessionAuthorizationState> {
  const state = args.deps.sessionLifecycle.readAuthorization({
    identity: args.identity,
    nowMs: Date.now(),
  });
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
  readonly identity: ExactSigningLaneIdentity;
  readonly preflightState: WalletSessionAuthorizationState;
  readonly detectedAtMs: number;
}): ExpiredWalletSessionAuthorizationState | null {
  const stateWithExpiry = authorizationWithExpiry(args.preflightState);
  if (!stateWithExpiry) return null;
  return requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
    identity: args.identity,
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
  const keyFingerprint =
    args.exportMaterial?.kind === 'ready_threshold_ecdsa_export_material'
      ? args.exportMaterial.evmFamilyKeyFingerprint
      : args.exportLane
        ? deriveEvmFamilyKeyFingerprintFromPublicFacts({
            walletId: args.exportLane.key.walletId,
            publicFacts: args.exportLane.publicFacts,
          })
        : undefined;
  try {
    console.warn('[SigningEngine][ecdsa-export][failure]', {
      operationId: args.flowId,
      authMethod: args.exportLane?.session.authMethod,
      ...(keyFingerprint ? { evmFamilyKeyFingerprint: keyFingerprint } : {}),
      ...(publicFacts ? { keyHandle: String(publicFacts.keyHandle) } : {}),
      chainTargetKey: thresholdEcdsaChainTargetKey(args.input.chainTarget),
      signingGrantId: args.exportLane?.session.signingGrantId,
      thresholdSessionId: args.exportLane?.session.thresholdSessionId,
      budgetProjectionVersion: undefined,
      freshAuthRetrySideEffectState: 'not_applicable',
      error:
        args.error instanceof Error ? args.error.message : String(args.error || 'unknown error'),
    });
  } catch {}
}

async function exportEcdsaKeypairWithFlowId(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }> & { flowId: string },
): Promise<ExportKeypairResult> {
  const walletId = toWalletId(args.walletSession.walletId);
  let exportLane: Awaited<ReturnType<typeof resolveEcdsaSessionForExport>> | undefined;
  let exportMaterial: EcdsaExportMaterial | undefined;
  try {
    const preparation = prepareEcdsaExport(deps, args);
    const uiInitialization = deps.ecdsa.touchConfirm.initialize();
    const [prepared] = await Promise.all([preparation, uiInitialization]);
    exportLane = prepared.exportLane;
    exportMaterial = prepared.exportMaterial;
    if (exportMaterial.kind === 'fresh_email_otp_route_auth_ready') {
      return await exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(deps.ecdsa, {
        walletId,
        exportLane,
        material: exportMaterial,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
        flowId: args.flowId,
        onEvent: args.options.onEvent,
      });
    }
    if (exportMaterial.kind === 'fresh_passkey_needs_authorization') {
      return await exportThresholdEcdsaKeyWithFreshPasskeyAuthorization(deps.ecdsa, {
        walletId,
        exportLane,
        material: exportMaterial,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
        flowId: args.flowId,
        onEvent: args.options.onEvent,
      });
    }
    return await exportThresholdEcdsaKeyWithAuthorization(deps.ecdsa, {
      walletId,
      material: exportMaterial,
      exportLane,
      options: {
        variant: args.options.variant,
        theme: args.options.theme,
      },
      flowId: args.flowId,
      onEvent: args.options.onEvent,
    });
  } catch (error: unknown) {
    emitEcdsaExportFailureDiagnostics({
      input: args,
      flowId: args.flowId,
      ...(exportLane ? { exportLane } : {}),
      ...(exportMaterial ? { exportMaterial } : {}),
      error,
    });
    throw error;
  }
}

async function exportEd25519KeypairWithFlowId(
  deps: ExportKeypairWithUIDeps,
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ed25519' }> & { flowId: string },
): Promise<ExportKeypairResult> {
  const exportArgs = {
    walletId: args.walletSession.walletId,
    nearAccountId: args.nearAccount.accountId,
    laneIdentity: args.laneIdentity,
    options: {
      variant: args.options.variant,
      theme: args.options.theme,
    },
    flowId: args.flowId,
    onEvent: args.options.onEvent,
  };
  switch (args.laneIdentity.auth.kind) {
    case 'passkey':
      return await exportEd25519YaoKeyWithFreshPasskey(deps.ed25519Yao, exportArgs);
    case 'email_otp':
      return await exportEd25519YaoKeyWithFreshEmailOtp(deps.ed25519Yao, exportArgs);
  }
  args.laneIdentity.auth satisfies never;
  throw new Error('[SigningEngine][ed25519-export] unsupported lane authorization method');
}

async function exportKeypairWithFlowId(
  deps: ExportKeypairWithUIDeps,
  args: SigningEngineExportKeypairWithUIInput & { flowId: string },
): Promise<ExportKeypairResult> {
  switch (args.kind) {
    case 'ecdsa':
      return await exportEcdsaKeypairWithFlowId(deps, args);
    case 'ed25519':
      return await exportEd25519KeypairWithFlowId(deps, args);
  }
}

async function exportKeypairWithSessionLifecycle(
  deps: ExportKeypairWithUIDeps,
  args: SigningEngineExportKeypairWithUIInput & { flowId: string },
  attempt: KeyExportAttempt,
): Promise<ExportKeypairResult> {
  const preflightState = await readAndInvalidateExpiredExportAuthorization({
    deps,
    identity: args.laneIdentity,
  });
  try {
    return await exportKeypairWithFlowId(deps, args);
  } catch (error: unknown) {
    const failure = walletSessionFailureFromError(error);
    if (attempt.kind === 'fresh_auth_retry' || failure?.kind !== 'expired') throw error;
    const expiredState = authoritativeExpiredExportAuthorization({
      identity: args.laneIdentity,
      preflightState,
      detectedAtMs: Date.now(),
    });
    if (!expiredState) throw error;
    await invalidateExpiredExportAuthorization({
      deps,
      state: expiredState,
      source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection,
    });
    return await exportKeypairWithSessionLifecycle(deps, args, {
      kind: 'fresh_auth_retry',
    });
  }
}

export async function exportKeypairWithUI(
  deps: ExportKeypairWithUIDeps,
  input: SigningEngineExportKeypairWithUIInput,
): Promise<ExportKeypairResult> {
  return await runKeyExportWithFlowEvents(input, (args) =>
    exportKeypairWithSessionLifecycle(deps, args, { kind: 'initial' }),
  );
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
