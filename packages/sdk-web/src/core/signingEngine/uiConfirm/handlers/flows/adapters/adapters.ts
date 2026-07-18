import type { UiConfirmContext } from '../../../uiConfirm.types';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig';
import { assertNeverConfirmationConfig } from '@/core/types/confirmationConfig';
import { errorMessage } from '@shared/utils/errors';
import { isObject } from '@shared/utils/validation';
import type {
  SerializableCredential,
  UserConfirmRequest,
  TransactionSummary,
  KnownUserConfirmRequest,
  UserConfirmDecision,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { UserConfirmationType } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmSecurityContext } from '@/core/types';
import {
  awaitConfirmUIDecision,
  prepareConfirmUISurface,
  type ConfirmUIHandle,
  type ConfirmUIPromptDiagnostics,
  type ConfirmUISurfaceSource,
  type ConfirmUIUpdate,
} from '../../../ui/confirm-ui';
import {
  getDisplayModel,
  getEmailOtpPrompt,
  getNearAccountId,
  getSignTransactionPayload,
  getSigningAuthMode,
  getSubjectLabel,
} from './request';
import type { ThemeMode } from '@/core/types/seams';
import type { ProfileAuthenticatorRecord } from '@/core/indexedDB';
import { collectAuthenticationCredentialForChallengeB64u } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  sendConfirmResponse,
  type UserConfirmResponsePort,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import type {
  NonceLease,
  NearExecutionReadiness,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import { nonceLeaseToRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import type {
  NearFundingRequest,
  NearTransactionReadiness,
} from '@/core/signingEngine/nonce/nearTransactionReadiness';
import { buildNearNonceLane } from '@/core/signingEngine/nonce/nearNonceLaneIdentity';

function parseReadinessNonce(raw: unknown, fallback: unknown): bigint {
  if (typeof raw === 'bigint') return raw;
  const normalized = String(raw ?? fallback ?? '0').trim();
  if (!normalized) return 0n;
  try {
    return BigInt(normalized);
  } catch {
    return 0n;
  }
}

function parseNearExecutionReadiness(raw: unknown): NearExecutionReadiness | null {
  if (!isObject(raw)) return null;
  const kind = String(raw.kind || '').trim();
  const walletId = String(raw.walletId || '').trim();
  const nearAccountId = String(raw.nearAccountId || '').trim();
  const nearPublicKeyStr = String(raw.nearPublicKeyStr || '').trim();
  if (!walletId || !nearAccountId || !nearPublicKeyStr) return null;
  switch (kind) {
    case 'implicit_unfunded':
      return {
        kind,
        walletId,
        nearAccountId,
        nearPublicKeyStr,
      };
    case 'access_key_available':
    case 'sponsored_named_ready':
      return {
        kind,
        walletId,
        nearAccountId,
        nearPublicKeyStr,
        nonce: parseReadinessNonce(raw.nonce, raw.nextNonce),
        accessKeyNonce: String(raw.accessKeyNonce || '').trim(),
        nextNonce: String(raw.nextNonce || '').trim(),
        txBlockHeight: String(raw.txBlockHeight || '').trim(),
        txBlockHash: String(raw.txBlockHash || '').trim(),
      };
    case 'account_lookup_failed':
      return {
        kind,
        walletId,
        nearAccountId,
        nearPublicKeyStr,
        message: String(raw.message || '').trim(),
      };
    default:
      return null;
  }
}

function nearExecutionReadinessFromError(error: unknown): NearExecutionReadiness | null {
  if (!isObject(error)) return null;
  return parseNearExecutionReadiness(error.readiness);
}

export type NearContextFetchResult =
  | {
      kind: 'readiness';
      readiness: NearTransactionReadiness;
      reservedNonceLeases: NonceLease[];
    }
  | {
      kind: 'failed';
      error: 'NEAR_ACCOUNT_LOOKUP_FAILED' | 'NEAR_CONTEXT_UNAVAILABLE';
      details: string;
    };

function implicitFundingReadinessMatchesRequest(
  readiness: Extract<NearExecutionReadiness, { kind: 'implicit_unfunded' }>,
  request: NearFundingRequest,
): boolean {
  return (
    readiness.walletId === String(request.subject.walletId) &&
    readiness.nearAccountId === String(request.subject.nearAccountId) &&
    readiness.nearPublicKeyStr === request.subject.nearPublicKeyStr
  );
}

export async function fetchNearContext(
  ctx: UiConfirmContext,
  request: NearFundingRequest,
): Promise<NearContextFetchResult> {
  try {
    const { context, leases } = await ctx.nonceCoordinator.reserveNearContext({
      lane: buildNearNonceLane({
        chains: ctx.chains,
        walletId: String(request.subject.walletId),
        nearAccountId: String(request.subject.nearAccountId),
        nearPublicKeyStr: request.subject.nearPublicKeyStr,
      }),
      operation: request.operation,
      count: request.signatureUses,
      nearClient: ctx.nearClient,
    });
    return {
      kind: 'readiness',
      readiness: {
        kind: 'context_ready',
        transactionContext: { ...context },
        nonceLeases: leases.map(nonceLeaseToRef),
      },
      reservedNonceLeases: leases,
    };
  } catch (error) {
    const readiness = nearExecutionReadinessFromError(error);
    if (
      readiness?.kind === 'implicit_unfunded' &&
      implicitFundingReadinessMatchesRequest(readiness, request)
    ) {
      return {
        kind: 'readiness',
        readiness: {
          kind: 'funding_required',
          request,
        },
        reservedNonceLeases: [],
      };
    }
    return {
      kind: 'failed',
      error:
        readiness?.kind === 'account_lookup_failed'
          ? 'NEAR_ACCOUNT_LOOKUP_FAILED'
          : 'NEAR_CONTEXT_UNAVAILABLE',
      details: errorMessage(error),
    };
  }
}

export async function releaseReservedNonces(
  ctx: UiConfirmContext,
  nonceLeases?: readonly NonceLease[],
) {
  if (!nonceLeases?.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.release({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
        reason: 'cancelled',
      }),
    ),
  );
}

async function collectAuthenticationCredentialWithPRF({
  ctx,
  nearAccountId,
  challengeB64u,
  onBeforePrompt,
  includeSecondPrfOutput = false,
}: {
  ctx: UiConfirmContext;
  nearAccountId: string;
  challengeB64u: string;
  onBeforePrompt?: (info: {
    authenticators: ProfileAuthenticatorRecord[];
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    challengeB64u: string;
  }) => void;
  /**
   * When true, include PRF.second in the serialized credential.
   * Use only for explicit recovery/export flows (higher-friction paths).
   */
  includeSecondPrfOutput?: boolean;
}): Promise<SerializableCredential> {
  return collectAuthenticationCredentialForChallengeB64u({
    credentialStore: ctx.webauthnCredentialStore,
    touchIdPrompt: ctx.touchIdPrompt,
    nearAccountId,
    challengeB64u,
    includeSecondPrfOutput,
    onBeforePrompt,
  });
}

function closeModalSafely(confirmed: boolean, handle?: ConfirmUIHandle) {
  handle?.close?.(confirmed);
}

type RenderConfirmUIResult = {
  confirmed: boolean;
  confirmHandle?: ConfirmUIHandle;
  error?: string;
  otpCode?: string;
  emailOtpChallengeId?: string;
  diagnostics: ConfirmUIPromptDiagnostics;
};

type BaseRenderConfirmUIArgs = {
  ctx: UiConfirmContext;
  request: UserConfirmRequest;
  confirmationConfig: NormalizedConfirmationConfig;
  transactionSummary: TransactionSummary;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme: ThemeMode;
  surface: ConfirmUISurfaceSource;
  onMounted?: (handle: ConfirmUIHandle) => void;
};

type VisibleRenderConfirmUIArgs = BaseRenderConfirmUIArgs & {
  confirmationConfig: Exclude<NormalizedConfirmationConfig, { kind: 'silent' }>;
  txSigningRequests: ReturnType<typeof getSignTransactionPayload>['txSigningRequests'] | [];
  model: ReturnType<typeof getDisplayModel>;
  signingAuthMode: ReturnType<typeof getSigningAuthMode>;
  emailOtpPrompt: ReturnType<typeof getEmailOtpPrompt>;
  nearAccountIdForUi: string;
};

function emptyConfirmDiagnostics(): ConfirmUIPromptDiagnostics {
  return {
    kind: 'confirm_ui_prompt_diagnostics_v1',
    elementDefineMs: 0,
    mountMs: 0,
    hostFirstUpdateMs: 0,
    hostInteractiveMs: 0,
    confirmEventMs: 0,
    decisionWaitMs: 0,
  };
}

async function renderAutoProceedConfirmUI(
  args: VisibleRenderConfirmUIArgs & {
    confirmationConfig: Extract<NormalizedConfirmationConfig, { kind: 'auto_proceed' }>;
  },
): Promise<RenderConfirmUIResult> {
  const mountStartedAt = performance.now();
  const handle = await prepareConfirmUISurface({
    ctx: args.ctx,
    summary: args.transactionSummary,
    txSigningRequests: args.txSigningRequests,
    model: args.model,
    securityContext: args.securityContext,
    loading: args.loading ?? true,
    theme: args.theme,
    uiMode: args.confirmationConfig.uiMode,
    nearAccountIdOverride: args.nearAccountIdForUi,
    signingAuthMode: args.signingAuthMode,
    emailOtpPrompt: args.emailOtpPrompt,
    surface: args.surface,
  });
  const mountMs = Math.max(0, Math.round(performance.now() - mountStartedAt));
  args.onMounted?.(handle);
  const decisionWaitStartedAt = performance.now();
  await new Promise((resolve) => setTimeout(resolve, args.confirmationConfig.autoProceedDelay));
  const decisionWaitMs = Math.max(0, Math.round(performance.now() - decisionWaitStartedAt));
  return {
    confirmed: true,
    confirmHandle: handle,
    diagnostics: {
      ...emptyConfirmDiagnostics(),
      mountMs,
      decisionWaitMs,
    },
  };
}

async function renderInteractiveConfirmUI(
  args: VisibleRenderConfirmUIArgs & {
    confirmationConfig: Extract<NormalizedConfirmationConfig, { kind: 'interactive' }>;
  },
): Promise<RenderConfirmUIResult> {
  const { confirmed, handle, error, otpCode, emailOtpChallengeId, diagnostics } =
    await awaitConfirmUIDecision({
      ctx: args.ctx,
      summary: args.transactionSummary,
      txSigningRequests: args.txSigningRequests,
      model: args.model,
      securityContext: args.securityContext,
      loading: args.loading,
      theme: args.theme,
      uiMode: args.confirmationConfig.uiMode,
      nearAccountIdOverride: args.nearAccountIdForUi,
      onMounted: args.onMounted,
      signingAuthMode: args.signingAuthMode,
      emailOtpPrompt: args.emailOtpPrompt,
      surface: args.surface,
    });
  return {
    confirmed,
    confirmHandle: handle,
    error,
    otpCode,
    emailOtpChallengeId,
    diagnostics,
  };
}

async function renderConfirmUI({
  ctx,
  request,
  confirmationConfig,
  transactionSummary,
  securityContext,
  loading,
  theme,
  surface,
  onMounted,
}: BaseRenderConfirmUIArgs): Promise<RenderConfirmUIResult> {
  const nearAccountIdForUi = getSubjectLabel(request);

  const txSigningRequests =
    request.type === UserConfirmationType.SIGN_TRANSACTION
      ? getSignTransactionPayload(request).txSigningRequests
      : [];
  const model = getDisplayModel(request);
  const signingAuthMode = getSigningAuthMode(request);
  const emailOtpPrompt = getEmailOtpPrompt(request);

  switch (confirmationConfig.kind) {
    case 'silent': {
      if (surface.kind === 'reuse_mounted') {
        surface.handle.close(true);
      }
      return {
        confirmed: true,
        confirmHandle: undefined,
        diagnostics: emptyConfirmDiagnostics(),
      };
    }
    case 'auto_proceed': {
      return await renderAutoProceedConfirmUI({
        ctx,
        request,
        confirmationConfig,
        transactionSummary,
        securityContext,
        loading,
        theme,
        surface,
        onMounted,
        txSigningRequests,
        model,
        signingAuthMode,
        emailOtpPrompt,
        nearAccountIdForUi,
      });
    }
    case 'interactive': {
      return await renderInteractiveConfirmUI({
        ctx,
        request,
        confirmationConfig,
        transactionSummary,
        securityContext,
        loading,
        theme,
        surface,
        onMounted,
        txSigningRequests,
        model,
        signingAuthMode,
        emailOtpPrompt,
        nearAccountIdForUi,
      });
    }
    default: {
      return assertNeverConfirmationConfig(confirmationConfig);
    }
  }
}

type CollectAuthenticationCredentialWithPRFArgs = Omit<
  Parameters<typeof collectAuthenticationCredentialWithPRF>[0],
  'ctx'
>;

type RenderConfirmUiArgs = Omit<Parameters<typeof renderConfirmUI>[0], 'ctx'>;

export function createConfirmTxFlowAdapters(ctx: UiConfirmContext) {
  return {
    near: {
      fetchNearContext: (opts: Parameters<typeof fetchNearContext>[1]) =>
        fetchNearContext(ctx, opts),
      releaseReservedNonces: (nonceLease: Parameters<typeof releaseReservedNonces>[1]) =>
        releaseReservedNonces(ctx, nonceLease),
    },
    security: {
      getRpId: () => ctx.touchIdPrompt.getRpId(),
    },
    webauthn: {
      collectAuthenticationCredentialWithPRF: (args: CollectAuthenticationCredentialWithPRFArgs) =>
        collectAuthenticationCredentialWithPRF({ ctx, ...args }),
      createRegistrationCredential: (
        args: Parameters<
          UiConfirmContext['touchIdPrompt']['generateRegistrationCredentialsInternal']
        >[0],
      ) => ctx.touchIdPrompt.generateRegistrationCredentialsInternal(args),
    },
    ui: {
      renderConfirmUI: (args: RenderConfirmUiArgs) => renderConfirmUI({ ctx, ...args }),
      closeModalSafely,
    },
  };
}

type ConfirmTxFlowAdapters = ReturnType<typeof createConfirmTxFlowAdapters>;

export function createConfirmSession({
  adapters,
  worker,
  request,
  confirmationConfig,
  transactionSummary,
  theme,
  surface,
}: {
  adapters: ConfirmTxFlowAdapters;
  worker: UserConfirmResponsePort;
  request: KnownUserConfirmRequest;
  confirmationConfig: NormalizedConfirmationConfig;
  transactionSummary: TransactionSummary;
  theme: ThemeMode;
  surface: ConfirmUISurfaceSource;
}): {
  setNonceLeases: (leases?: readonly NonceLease[]) => void;
  updateUI: (props: ConfirmUIUpdate) => void;
  promptUser: (args: {
    securityContext?: Partial<UserConfirmSecurityContext>;
    loading?: boolean;
    onMounted?: (handle: ConfirmUIHandle) => void;
  }) => Promise<{
    confirmed: boolean;
    error?: string;
    otpCode?: string;
    emailOtpChallengeId?: string;
    diagnostics: ConfirmUIPromptDiagnostics;
  }>;
  /**
   * Send decision back to worker and perform standard cleanup.
   * - On `confirmed: false`, releases any reserved nonces.
   * - Always closes the confirm UI handle when present.
   */
  confirmAndCloseModal: (decision: UserConfirmDecision) => void;
} {
  let nonceLeases: readonly NonceLease[] | undefined;
  let confirmHandle: ConfirmUIHandle | undefined;

  const setNonceLeases = (leases?: readonly NonceLease[]) => {
    nonceLeases = leases;
  };

  const updateUI = (props: ConfirmUIUpdate) => {
    confirmHandle?.update?.(props);
  };

  const promptUser = async ({
    securityContext,
    loading,
    onMounted,
  }: {
    securityContext?: Partial<UserConfirmSecurityContext>;
    loading?: boolean;
    onMounted?: (handle: ConfirmUIHandle) => void;
  }) => {
    const {
      confirmed,
      confirmHandle: handle,
      error,
      otpCode,
      emailOtpChallengeId,
      diagnostics,
    } = await adapters.ui.renderConfirmUI({
      request,
      confirmationConfig,
      transactionSummary,
      securityContext,
      loading,
      theme,
      surface,
      onMounted: (mountedHandle) => {
        confirmHandle = mountedHandle;
        onMounted?.(mountedHandle);
      },
    });
    confirmHandle = handle;
    return { confirmed, error, otpCode, emailOtpChallengeId, diagnostics };
  };

  const confirmAndCloseModal = (decision: UserConfirmDecision) => {
    try {
      sendConfirmResponse(worker, decision);
    } finally {
      if (!decision.confirmed) {
        void adapters.near.releaseReservedNonces(nonceLeases);
      }
      adapters.ui.closeModalSafely(!!decision.confirmed, confirmHandle);
    }
  };

  return {
    setNonceLeases,
    updateUI,
    promptUser,
    confirmAndCloseModal,
  };
}
