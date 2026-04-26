import type { TouchConfirmContext } from '../../../';
import type { ConfirmationConfig, ConfirmationUIMode } from '@/core/types/signer-worker';
import { TransactionContext } from '@/core/types';
import type { BlockReference, AccessKeyView } from '@near-js/types';
import { errorMessage } from '@shared/utils/errors';
import type {
  SerializableCredential,
  UserConfirmRequest,
  TransactionSummary,
  KnownUserConfirmRequest,
  UserConfirmDecision,
} from '../../../shared/confirmTypes';
import { UserConfirmationType } from '../../../shared/confirmTypes';
import type { UserConfirmSecurityContext } from '@/core/types';
import {
  awaitConfirmUIDecision,
  mountConfirmUI,
  type ConfirmUIHandle,
  type ConfirmUIUpdate,
} from '../../../ui/confirm-ui';
import {
  getDisplayModel,
  getEmailOtpPrompt,
  getNearAccountId,
  getSignTransactionPayload,
  getSigningAuthMode,
} from './request';
import type { ThemeName } from '@/core/types/tatchi';
import type { ProfileAuthenticatorRecord } from '@/core/indexedDB';
import { collectAuthenticationCredentialForChallengeB64u } from '@/core/signingEngine/signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import { sendConfirmResponse } from '../../../shared/confirmCommon';
import { toAccountId } from '@/core/types/accountIds';
import {
  SigningSessionIds,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '@/core/signingEngine/session/signingSessionTypes';
import type {
  NonceLease,
  NonceOperationContext,
} from '@/core/signingEngine/nonce/NonceCoordinator';

export async function fetchNearContext(
  ctx: TouchConfirmContext,
  opts: {
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
  reservedNonces?: string[];
  nonceLease?: NonceLease;
}> {
  const allowFallback = opts.allowFallback === true;
  try {
    const explicitNearPublicKeyStr =
      typeof opts.nearPublicKeyStr === 'string' && opts.nearPublicKeyStr.trim()
        ? opts.nearPublicKeyStr.trim()
        : '';
    if (explicitNearPublicKeyStr) {
      ctx.nonceManager.initializeUser(toAccountId(opts.nearAccountId), explicitNearPublicKeyStr);
      const cached = await ctx.nonceManager.getNonceBlockHashAndHeight(ctx.nearClient);
      const transactionContext: TransactionContext = { ...cached };
      const txCount = Math.max(1, Math.floor(Number(opts.txCount) || 1));
      const nonceLease = opts.reserveNonces
        ? await reserveNearNonceLease(ctx, {
            nearAccountId: opts.nearAccountId,
            nearPublicKeyStr: explicitNearPublicKeyStr,
            count: txCount,
            operationId: opts.operationId,
            operationFingerprint: opts.operationFingerprint,
          })
        : undefined;
      const reservedNonces = nonceLease?.nonces.map((nonce) => String(nonce));
      if (reservedNonces?.[0]) {
        transactionContext.nextNonce = reservedNonces[0];
      }
      return {
        transactionContext,
        reservedNonces,
        nonceLease,
      };
    }

    // Prefer NonceManager when initialized (signing flows).
    // Use cached transaction context if fresh; avoid forcing a refresh here.
    const cached = await ctx.nonceManager.getNonceBlockHashAndHeight(ctx.nearClient);
    // IMPORTANT: `NonceManager` returns its cached `transactionContext` object by reference.
    // Never mutate it in-place here, otherwise concurrent signing requests can race and overwrite
    // `nextNonce` for each other, leading to duplicate nonces (InvalidNonce) under load.
    const transactionContext: TransactionContext = { ...cached };

    const txCount = opts.txCount || 1;
    let reservedNonces: string[] | undefined;
    let nonceLease: NonceLease | undefined;
    if (opts.reserveNonces) {
      const nearPublicKeyStr = String(transactionContext.nearPublicKeyStr || '').trim();
      if (!nearPublicKeyStr) {
        throw new Error('NEAR nonce reservation requires nearPublicKeyStr');
      }
      nonceLease = await reserveNearNonceLease(ctx, {
        nearAccountId: opts.nearAccountId,
        nearPublicKeyStr,
        count: txCount,
        operationId: opts.operationId,
        operationFingerprint: opts.operationFingerprint,
      });
      reservedNonces = nonceLease.nonces.map((nonce) => String(nonce));
      // Provide the first reserved nonce to the worker context; worker handles per-tx assignment
      transactionContext.nextNonce = reservedNonces[0];
    }

    return { transactionContext, reservedNonces, nonceLease };
  } catch (error) {
    if (!allowFallback) {
      return {
        transactionContext: null,
        error: 'NEAR_CONTEXT_UNAVAILABLE',
        details: errorMessage(error),
      };
    }

    // Registration or pre-login flows may not have NonceManager initialized.
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

function createNearNonceOperationContext(args: {
  nearAccountId: string;
  operationId?: string;
  operationFingerprint?: string;
}): NonceOperationContext {
  const randomId =
    typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  const operationId = SigningSessionIds.signingOperation(
    args.operationId || `near-touch-confirm:${randomId}`,
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    args.operationFingerprint || `near-touch-confirm:${operationId}`,
  );
  return {
    operationId: operationId as SigningOperationId,
    operationFingerprint: operationFingerprint as SigningOperationFingerprint,
    accountId: args.nearAccountId,
    chainFamily: 'near',
  };
}

async function reserveNearNonceLease(
  ctx: TouchConfirmContext,
  args: {
    nearAccountId: string;
    nearPublicKeyStr: string;
    count: number;
    operationId?: string;
    operationFingerprint?: string;
  },
): Promise<NonceLease> {
  const nearPublicKeyStr = String(args.nearPublicKeyStr || '').trim();
  if (!nearPublicKeyStr) {
    throw new Error('NEAR nonce reservation requires nearPublicKeyStr');
  }
  return await ctx.nonceCoordinator.reserve({
    lane: {
      family: 'near',
      networkKey: resolveNearNonceNetworkKey(ctx),
      accountId: args.nearAccountId,
      publicKey: nearPublicKeyStr,
    },
    operation: createNearNonceOperationContext({
      nearAccountId: args.nearAccountId,
      operationId: args.operationId,
      operationFingerprint: args.operationFingerprint,
    }),
    count: Math.max(1, Math.floor(Number(args.count) || 1)),
  });
}

function resolveNearNonceNetworkKey(ctx: TouchConfirmContext): string {
  const nearChain = ctx.chains?.find((chain) =>
    String((chain as { network?: unknown }).network || '').startsWith('near-'),
  );
  return String((nearChain as { network?: unknown } | undefined)?.network || 'near');
}

export async function releaseReservedNonces(
  ctx: TouchConfirmContext,
  nonceLease?: NonceLease,
) {
  if (!nonceLease) return;
  await ctx.nonceCoordinator.release({
    leaseId: nonceLease.leaseId,
    operationId: nonceLease.operationId,
    reason: 'cancelled',
  });
}

async function collectAuthenticationCredentialWithPRF({
  ctx,
  nearAccountId,
  challengeB64u,
  onBeforePrompt,
  includeSecondPrfOutput = false,
}: {
  ctx: TouchConfirmContext;
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
    indexedDB: ctx.indexedDB,
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

async function renderConfirmUI({
  ctx,
  request,
  confirmationConfig,
  transactionSummary,
  securityContext,
  loading,
  theme,
  onMounted,
}: {
  ctx: TouchConfirmContext;
  request: UserConfirmRequest;
  confirmationConfig: ConfirmationConfig;
  transactionSummary: TransactionSummary;
  securityContext?: Partial<UserConfirmSecurityContext>;
  loading?: boolean;
  theme: ThemeName;
  onMounted?: (handle: ConfirmUIHandle) => void;
}): Promise<{
  confirmed: boolean;
  confirmHandle?: ConfirmUIHandle;
  error?: string;
  otpCode?: string;
  emailOtpChallengeId?: string;
}> {
  const nearAccountIdForUi = getNearAccountId(request);

  const uiMode = confirmationConfig.uiMode as ConfirmationUIMode;
  const txSigningRequests =
    request.type === UserConfirmationType.SIGN_TRANSACTION
      ? getSignTransactionPayload(request).txSigningRequests
      : [];
  const model = getDisplayModel(request);
  const signingAuthMode = getSigningAuthMode(request);
  const emailOtpPrompt = getEmailOtpPrompt(request);

  const renderDrawerOrModal = async (mode: 'drawer' | 'modal') => {
    if (confirmationConfig.behavior === 'skipClick') {
      const handle = await mountConfirmUI({
        ctx,
        summary: transactionSummary,
        txSigningRequests,
        model,
        securityContext,
        loading: loading ?? true,
        theme,
        uiMode: mode,
        nearAccountIdOverride: nearAccountIdForUi,
        signingAuthMode,
        emailOtpPrompt,
      });
      onMounted?.(handle);
      const delay = confirmationConfig.autoProceedDelay ?? 0;
      await new Promise((r) => setTimeout(r, delay));
      return { confirmed: true, confirmHandle: handle } as const;
    }

    const { confirmed, handle, error, otpCode, emailOtpChallengeId } =
      await awaitConfirmUIDecision({
      ctx,
      summary: transactionSummary,
      txSigningRequests,
      model,
      securityContext,
      loading,
      theme,
      uiMode: mode,
      nearAccountIdOverride: nearAccountIdForUi,
      onMounted,
      signingAuthMode,
      emailOtpPrompt,
    });
    return { confirmed, confirmHandle: handle, error, otpCode, emailOtpChallengeId } as const;
  };

  switch (uiMode) {
    case 'none': {
      return { confirmed: true, confirmHandle: undefined };
    }
    case 'drawer': {
      return await renderDrawerOrModal('drawer');
    }
    case 'modal': {
      return await renderDrawerOrModal('modal');
    }
    default: {
      // Defensive fallback for unexpected uiMode values:
      // treat as modal flow instead of auto-confirming.
      return await renderDrawerOrModal('modal');
    }
  }
}

type CollectAuthenticationCredentialWithPRFArgs = Omit<
  Parameters<typeof collectAuthenticationCredentialWithPRF>[0],
  'ctx'
>;

type RenderConfirmUiArgs = Omit<Parameters<typeof renderConfirmUI>[0], 'ctx'>;

export function createConfirmTxFlowAdapters(ctx: TouchConfirmContext) {
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
          TouchConfirmContext['touchIdPrompt']['generateRegistrationCredentialsInternal']
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
  worker: Worker;
  request: KnownUserConfirmRequest;
  confirmationConfig: ConfirmationConfig;
  transactionSummary: TransactionSummary;
  theme: ThemeName;
}): {
  setNonceLease: (lease?: NonceLease) => void;
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
  }>;
  /**
   * Send decision back to worker and perform standard cleanup.
   * - On `confirmed: false`, releases any reserved nonces.
   * - Always closes the confirm UI handle when present.
   */
  confirmAndCloseModal: (decision: UserConfirmDecision) => void;
} {
  let nonceLease: NonceLease | undefined;
  let confirmHandle: ConfirmUIHandle | undefined;

  const setNonceLease = (lease?: NonceLease) => {
    nonceLease = lease;
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
    return { confirmed, error, otpCode, emailOtpChallengeId };
  };

  const confirmAndCloseModal = (decision: UserConfirmDecision) => {
    try {
      sendConfirmResponse(worker, decision);
    } finally {
      if (!decision.confirmed) {
        void adapters.near.releaseReservedNonces(nonceLease);
      }
      adapters.ui.closeModalSafely(!!decision.confirmed, confirmHandle);
    }
  };

  return {
    setNonceLease,
    updateUI,
    promptUser,
    confirmAndCloseModal,
  };
}
