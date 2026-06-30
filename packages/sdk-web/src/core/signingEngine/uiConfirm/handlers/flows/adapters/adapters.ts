import type { UiConfirmContext } from '../../../uiConfirm.types';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig';
import { assertNeverConfirmationConfig } from '@/core/types/confirmationConfig';
import { TransactionContext } from '@/core/types';
import type { BlockReference, AccessKeyView } from '@near-js/types';
import { errorMessage } from '@shared/utils/errors';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
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
  mountConfirmUI,
  type ConfirmUIHandle,
  type ConfirmUIPromptDiagnostics,
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
import type { ThemeName } from '@/core/types/seams';
import type { ProfileAuthenticatorRecord } from '@/core/indexedDB';
import { collectAuthenticationCredentialForChallengeB64u } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  sendConfirmResponse,
  type UserConfirmResponsePort,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import { toAccountId } from '@/core/types/accountIds';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import type {
  NonceLease,
  PreparedNonceOperationContext,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  classifyNearExecutionReadiness,
  type NearExecutionReadiness,
} from '@/core/signingEngine/nonce/nearNonceLane';

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

function nearExecutionReadinessForContext(input: {
  walletId: string;
  nearAccountId: string;
  nearPublicKeyStr: string;
  transactionContext: TransactionContext;
}): NearExecutionReadiness {
  return classifyNearExecutionReadiness({
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearPublicKeyStr: input.nearPublicKeyStr,
    accessKeyAvailable: true,
    transactionContext: input.transactionContext,
  });
}

function nearExecutionReadinessFromError(error: unknown): NearExecutionReadiness | null {
  if (!isObject(error)) return null;
  return parseNearExecutionReadiness(error.readiness);
}

export async function fetchNearContext(
  ctx: UiConfirmContext,
  opts: {
    walletId: string;
    nearAccountId: string;
    nearPublicKeyStr?: string;
    txCount: number;
    reserveNonces: boolean;
    allowFallback?: boolean;
    operationId?: string;
    operationFingerprint?: string;
  },
): Promise<{
  transactionContext: TransactionContext | null;
  error?: string;
  details?: string;
  readiness?: NearExecutionReadiness;
  reservedNonces?: string[];
  nonceLeases?: NonceLease[];
}> {
  const allowFallback = opts.allowFallback === true;
  try {
    const explicitNearPublicKeyStr =
      typeof opts.nearPublicKeyStr === 'string' && opts.nearPublicKeyStr.trim()
        ? opts.nearPublicKeyStr.trim()
        : '';
    if (explicitNearPublicKeyStr) {
      const txCount = Math.max(1, Math.floor(Number(opts.txCount) || 1));
      if (opts.reserveNonces) {
        const { transactionContext, nonceLeases } = await reserveNearTransactionContext(ctx, {
          walletId: opts.walletId,
          nearAccountId: opts.nearAccountId,
          nearPublicKeyStr: explicitNearPublicKeyStr,
          count: txCount,
          operationId: opts.operationId,
          operationFingerprint: opts.operationFingerprint,
        });
        const reservedNonces = nonceLeases.map((lease) => String(lease.nonce));
        return {
          transactionContext,
          reservedNonces,
          nonceLeases,
          readiness: nearExecutionReadinessForContext({
            walletId: opts.walletId,
            nearAccountId: opts.nearAccountId,
            nearPublicKeyStr: explicitNearPublicKeyStr,
            transactionContext,
          }),
        };
      }

      const transactionContext = await ctx.nonceCoordinator.fetchNearContext({
        lane: createNearNonceLane(ctx, {
          walletId: opts.walletId,
          nearAccountId: opts.nearAccountId,
          nearPublicKeyStr: explicitNearPublicKeyStr,
        }),
        nearClient: ctx.nearClient,
      });
      return {
        transactionContext,
        readiness: nearExecutionReadinessForContext({
          walletId: opts.walletId,
          nearAccountId: opts.nearAccountId,
          nearPublicKeyStr: explicitNearPublicKeyStr,
          transactionContext,
        }),
      };
    }

    const txCount = opts.txCount || 1;
    if (opts.reserveNonces) {
      const nearPublicKeyStr = String(ctx.nonceCoordinator.getActiveNearPublicKey() || '').trim();
      if (!nearPublicKeyStr) {
        throw new Error('NEAR nonce reservation requires nearPublicKeyStr');
      }
      const { transactionContext, nonceLeases } = await reserveNearTransactionContext(ctx, {
        walletId: opts.walletId,
        nearAccountId: opts.nearAccountId,
        nearPublicKeyStr,
        count: txCount,
        operationId: opts.operationId,
        operationFingerprint: opts.operationFingerprint,
      });
      return {
        transactionContext,
        reservedNonces: nonceLeases.map((lease) => String(lease.nonce)),
        nonceLeases,
        readiness: nearExecutionReadinessForContext({
          walletId: opts.walletId,
          nearAccountId: opts.nearAccountId,
          nearPublicKeyStr,
          transactionContext,
        }),
      };
    }

    // Prefer coordinator-owned NEAR context when initialized (signing flows).
    // Use cached transaction context if fresh; avoid forcing a refresh here.
    const nearPublicKeyStr = String(ctx.nonceCoordinator.getActiveNearPublicKey() || '').trim();
    if (!nearPublicKeyStr) {
      throw new Error('NEAR context fetch requires nearPublicKeyStr');
    }
    const cached = await ctx.nonceCoordinator.fetchNearContext({
      lane: createNearNonceLane(ctx, {
        walletId: opts.walletId,
        nearAccountId: opts.nearAccountId,
        nearPublicKeyStr,
      }),
      nearClient: ctx.nearClient,
    });
    // IMPORTANT: the NEAR nonce context may originate from a shared cached object.
    // Never mutate it in-place here, otherwise concurrent signing requests can race and overwrite
    // `nextNonce` for each other, leading to duplicate nonces (InvalidNonce) under load.
    const transactionContext: TransactionContext = { ...cached };

    return {
      transactionContext,
      readiness: nearExecutionReadinessForContext({
        walletId: opts.walletId,
        nearAccountId: opts.nearAccountId,
        nearPublicKeyStr,
        transactionContext,
      }),
    };
  } catch (error) {
    if (!allowFallback) {
      const errorCode =
        error && typeof error === 'object' && 'code' in error
          ? String((error as { code?: unknown }).code || '').trim()
          : '';
      const readiness = nearExecutionReadinessFromError(error);
      const isImplicitUnfunded = errorCode === 'near_implicit_account_unfunded';
      const isAccountLookupFailed =
        errorCode === 'near_account_lookup_failed' ||
        readiness?.kind === 'account_lookup_failed';
      return {
        transactionContext: null,
        error: isImplicitUnfunded
          ? 'NEAR_IMPLICIT_ACCOUNT_UNFUNDED'
          : isAccountLookupFailed
            ? 'NEAR_ACCOUNT_LOOKUP_FAILED'
            : 'NEAR_CONTEXT_UNAVAILABLE',
        details: errorMessage(error),
        ...(readiness ? { readiness } : {}),
      };
    }

    // Registration or pre-login flows may not have coordinator NEAR context initialized.
    // Fallback: fetch latest block info directly; nonces are not required for registration/link flows.
    try {
      const block = await ctx.nearClient.viewBlock({ finality: 'final' } as BlockReference);
      const txBlockHeight = String(block?.header?.height ?? '');
      const txBlockHash = String(block?.header?.hash ?? '');
      const fallback: TransactionContext = {
        nearPublicKeyStr: '', // not needed for registration/link flows here
        accessKeyInfo: {
          nonce: 0,
          permission: 'FullAccess',
          block_height: 0,
          block_hash: '',
        } as unknown as AccessKeyView, // minimal shape; not used in registration/link flows
        nextNonce: '0',
        txBlockHeight,
        txBlockHash,
      } as TransactionContext;
      return { transactionContext: fallback };
    } catch (e) {
      return {
        transactionContext: null,
        error: 'NEAR_RPC_FAILED',
        details: errorMessage(e) || errorMessage(error),
      };
    }
  }
}

async function reserveNearTransactionContext(
  ctx: UiConfirmContext,
  args: {
    walletId: string;
    nearAccountId: string;
    nearPublicKeyStr: string;
    count: number;
    operationId?: string;
    operationFingerprint?: string;
  },
): Promise<{ transactionContext: TransactionContext; nonceLeases: NonceLease[] }> {
  const nearPublicKeyStr = String(args.nearPublicKeyStr || '').trim();
  if (!nearPublicKeyStr) {
    throw new Error('NEAR nonce reservation requires nearPublicKeyStr');
  }
  const { context, leases } = await ctx.nonceCoordinator.reserveNearContext({
    lane: createNearNonceLane(ctx, {
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      nearPublicKeyStr,
    }),
    operation: createNearPreparedNonceOperationContext({
      nearAccountId: args.nearAccountId,
      operationId: args.operationId,
      operationFingerprint: args.operationFingerprint,
    }),
    count: Math.max(1, Math.floor(Number(args.count) || 1)),
    nearClient: ctx.nearClient,
  });
  return { transactionContext: context, nonceLeases: leases };
}

function createNearNonceLane(
  ctx: UiConfirmContext,
  args: { walletId: string; nearAccountId: string; nearPublicKeyStr: string },
) {
  return {
    family: 'near' as const,
    networkKey: resolveNearNonceNetworkKey(ctx),
    walletId: String(args.walletId || '').trim(),
    nearAccountId: toAccountId(args.nearAccountId),
    publicKey: String(args.nearPublicKeyStr || '').trim(),
  };
}

function createNearPreparedNonceOperationContext(args: {
  nearAccountId: string;
  operationId?: string;
  operationFingerprint?: string;
}): PreparedNonceOperationContext {
  const randomId = secureRandomBase64Url(32, 'NEAR touch confirmation nonce operation IDs');
  const operationId = SigningSessionIds.signingOperation(
    args.operationId || `near-touch-confirm:${randomId}`,
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    args.operationFingerprint || `near-touch-confirm:${operationId}`,
  );
  return {
    operationId: operationId as SigningOperationId,
    operationFingerprint: operationFingerprint as SigningOperationFingerprint,
    intent: SigningOperationIntent.TransactionSign,
    accountId: args.nearAccountId,
  };
}

function resolveNearNonceNetworkKey(ctx: UiConfirmContext): string {
  const nearChain = ctx.chains?.find((chain) =>
    String((chain as { network?: unknown }).network || '').startsWith('near-'),
  );
  return String((nearChain as { network?: unknown } | undefined)?.network || 'near');
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
  theme: ThemeName;
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
  const handle = await mountConfirmUI({
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
}: {
  adapters: ConfirmTxFlowAdapters;
  worker: UserConfirmResponsePort;
  request: KnownUserConfirmRequest;
  confirmationConfig: NormalizedConfirmationConfig;
  transactionSummary: TransactionSummary;
  theme: ThemeName;
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
