import type { TransactionInputWasm } from '@/core/types/actions';
import { ActionType } from '@/core/types/actions';
import type { RpcCallPayload, ConfirmationConfig } from '@/core/types/signer-worker';
import type { TransactionContext } from '@/core/types/rpc';
import { computeUiIntentDigestFromTxs, orderActionForDigest } from '@/utils/intentDigest';
import {
  UserConfirmationType,
  type UserConfirmRequest,
  type SigningAuthMode,
  type EmailOtpConfirmPrompt,
  type TransactionSummary,
  type SerializableCredential,
  type UserConfirmProgressEvent,
  type UserConfirmDecision,
} from '../shared/confirmTypes';
import type { TxDisplayModel } from '../shared/displayModel';
import { buildNearDisplayModel } from '../displayFormat/nearTx';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  registerIntentDigestPreparation,
} from '../intentDigestPreparationRegistry';

export type SigningConfirmationChain = 'near' | 'evm' | 'tempo';

type RequestUserConfirmationBridge = (
  request: UserConfirmRequest,
  options?: { onProgress?: (progress: UserConfirmProgressEvent) => void },
) => Promise<UserConfirmDecision>;

type TouchConfirmRequestBridgeContext = {
  touchConfirm: {
    requestUserConfirmation: RequestUserConfirmationBridge;
  };
};

export interface OrchestrateSigningConfirmationBaseParams {
  ctx: TouchConfirmRequestBridgeContext;
  sessionId: string;
  chain: SigningConfirmationChain;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  onProgress?: (progress: UserConfirmProgressEvent) => void;
  /**
   * Optional override for signing auth mode.
   * When omitted, the UserConfirm worker may auto-select `warmSession` when a warm session is available.
   *
   * Threshold signing typically selects `warmSession` only when a valid relay session token exists
   * and PRF.first is cached in the UserConfirm worker; otherwise it uses `webauthn`.
   */
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  /**
   * Optional base64url-encoded 32-byte digest to bind a relayer session policy into the WebAuthn challenge.
   * When provided, it is forwarded to UserConfirm for challenge construction and intent binding.
   */
  sessionPolicyDigest32?: string;
}

export interface OrchestrateNearTransactionSigningConfirmationParams extends OrchestrateSigningConfirmationBaseParams {
  chain: 'near';
  kind: 'transaction';
  txSigningRequests: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  nearPublicKeyStr?: string;
  title?: string;
  body?: string;
}

export interface OrchestrateNearDelegateSigningConfirmationParams extends OrchestrateSigningConfirmationBaseParams {
  chain: 'near';
  kind: 'delegate';
  nearAccountId: string;
  title?: string;
  body?: string;
  delegate: {
    senderId: string;
    receiverId: string;
    actions: TransactionInputWasm['actions'];
    nonce: string | number | bigint;
    maxBlockHeight: string | number | bigint;
  };
  rpcCall: RpcCallPayload;
  nearPublicKeyStr?: string;
}

export interface OrchestrateNearNep413SigningConfirmationParams extends OrchestrateSigningConfirmationBaseParams {
  chain: 'near';
  kind: 'nep413';
  nearAccountId: string;
  nearPublicKeyStr?: string;
  message: string;
  recipient: string;
  title?: string;
  body?: string;
}

export interface OrchestrateIntentDigestSigningConfirmationParams extends OrchestrateSigningConfirmationBaseParams {
  kind: 'intentDigest';
  signerAccountId: string;
  challengeB64u: string;
  intentDigest: string;
  displayModel?: TxDisplayModel;
  title?: string;
  body?: string;
}

export type OrchestrateSigningConfirmationParams =
  | OrchestrateNearTransactionSigningConfirmationParams
  | OrchestrateNearDelegateSigningConfirmationParams
  | OrchestrateNearNep413SigningConfirmationParams
  | OrchestrateIntentDigestSigningConfirmationParams;

export interface SigningConfirmationResultWithTxContext {
  sessionId: string;
  transactionContext: TransactionContext;
  intentDigest: string;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
}

export interface SigningConfirmationResultIntentDigest {
  sessionId: string;
  intentDigest: string;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
}

function normalizeIntentDigestForUi(value: unknown): string {
  const digest = String(value || '').trim();
  if (!digest || digest === PENDING_INTENT_DIGEST) return '';
  return digest;
}

function normalizeChallengeB64u(value: unknown): string {
  const challenge = String(value || '').trim();
  if (!challenge) return PENDING_CHALLENGE_B64U;
  return challenge;
}

function buildPendingIntentDisplayModel(args: {
  chain: SigningConfirmationChain;
  signerAccountId: string;
  title?: string;
  body?: string;
  intentDigest?: string;
}): TxDisplayModel {
  return {
    chain: args.chain,
    ...(args.intentDigest ? { intentDigest: args.intentDigest } : {}),
    signerAccount: args.signerAccountId,
    ...(args.title != null ? { title: args.title } : {}),
    ...(args.body != null ? { subtitle: args.body } : {}),
    operations: [
      {
        id: `${args.chain}.pending`,
        kind: 'raw.fallback',
        label: 'Loading transaction details...',
        raw: '',
      },
    ],
  };
}

function buildNearDisplayModelWithFallback(args: {
  txSigningRequests: TransactionInputWasm[];
  intentDigest?: string;
  signerAccountId: string;
  title?: string;
  body?: string;
}): TxDisplayModel {
  try {
    return buildNearDisplayModel({
      txSigningRequests: args.txSigningRequests,
      intentDigest: args.intentDigest || '',
      signerAccount: args.signerAccountId,
      title: args.title,
      subtitle: args.body,
    });
  } catch {
    return buildPendingIntentDisplayModel({
      chain: 'near',
      signerAccountId: args.signerAccountId,
      title: args.title,
      body: args.body,
      intentDigest: args.intentDigest,
    });
  }
}

/**
 * Orchestrates chain-specific signing confirmation requests for UserConfirm.
 *
 * This creates a `UserConfirmRequest` and routes it through the worker handshake so touchConfirm
 * can render UI in wallet origin and collect signing artifacts.
 */
export async function orchestrateSigningConfirmation(
  params: OrchestrateIntentDigestSigningConfirmationParams,
): Promise<SigningConfirmationResultIntentDigest>;
export async function orchestrateSigningConfirmation(
  params: Exclude<
    OrchestrateSigningConfirmationParams,
    OrchestrateIntentDigestSigningConfirmationParams
  >,
): Promise<SigningConfirmationResultWithTxContext>;
export async function orchestrateSigningConfirmation(
  params: OrchestrateSigningConfirmationParams,
): Promise<SigningConfirmationResultWithTxContext | SigningConfirmationResultIntentDigest>;
export async function orchestrateSigningConfirmation(
  params: OrchestrateSigningConfirmationParams,
): Promise<SigningConfirmationResultWithTxContext | SigningConfirmationResultIntentDigest> {
  const { sessionId } = params;
  const requestUserConfirmation = resolveRequestUserConfirmationBridge(params.ctx);

  let intentDigest: string;
  let request: UserConfirmRequest;

  switch (params.kind) {
    case 'transaction': {
      const txSigningRequests = params.txSigningRequests;
      const normalizedTxs = txSigningRequests.map((tx) => ({
        receiverId: tx.receiverId,
        actions: tx.actions.map(orderActionForDigest),
      })) as TransactionInputWasm[];
      const summaryBase: TransactionSummary = {
        receiverId: txSigningRequests[0]?.receiverId,
        totalAmount: computeTotalAmountYocto(txSigningRequests),
        type: 'transaction',
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
      };

      if (params.chain === 'near' && params.signingAuthMode === 'warmSession') {
        const eagerDisplayModel = buildNearDisplayModelWithFallback({
          txSigningRequests,
          signerAccountId: params.rpcCall.nearAccountId,
          title: summaryBase.title,
          body: summaryBase.body,
        });
        registerIntentDigestPreparation({
          requestId: sessionId,
          preparation: (async () => {
            const preparedIntentDigest = await computeUiIntentDigestFromTxs(normalizedTxs);
            const preparedDisplayModel = buildNearDisplayModelWithFallback({
              txSigningRequests,
              intentDigest: preparedIntentDigest,
              signerAccountId: params.rpcCall.nearAccountId,
              title: summaryBase.title,
              body: summaryBase.body,
            });
            return {
              intentDigest: preparedIntentDigest,
              challengeB64u: preparedIntentDigest,
              displayModel: preparedDisplayModel,
              ...(summaryBase.title != null ? { title: summaryBase.title } : {}),
              ...(summaryBase.body != null ? { body: summaryBase.body } : {}),
            };
          })(),
        });
        intentDigest = PENDING_INTENT_DIGEST;

        request = {
          requestId: sessionId,
          type: UserConfirmationType.SIGN_TRANSACTION,
          summary: summaryBase,
          payload: {
            txSigningRequests,
            intentDigest: PENDING_INTENT_DIGEST,
            displayModel: eagerDisplayModel,
            rpcCall: params.rpcCall,
            ...(params.nearPublicKeyStr ? { nearPublicKeyStr: params.nearPublicKeyStr } : {}),
            ...(params.sessionPolicyDigest32
              ? { sessionPolicyDigest32: params.sessionPolicyDigest32 }
              : {}),
            ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
            ...(params.emailOtpPrompt ? { emailOtpPrompt: params.emailOtpPrompt } : {}),
          },
          confirmationConfig: params.confirmationConfigOverride,
          intentDigest: PENDING_INTENT_DIGEST,
        };
        break;
      }

      intentDigest = await computeUiIntentDigestFromTxs(normalizedTxs);

      const summary: TransactionSummary = {
        ...summaryBase,
        intentDigest,
      };
      const displayModel = buildNearDisplayModelWithFallback({
        txSigningRequests,
        intentDigest,
        signerAccountId: params.rpcCall.nearAccountId,
        title: summary.title,
        body: summary.body,
      });

      request = {
        requestId: sessionId,
        type: UserConfirmationType.SIGN_TRANSACTION,
        summary,
        payload: {
          txSigningRequests,
          intentDigest,
          displayModel,
          rpcCall: params.rpcCall,
          ...(params.nearPublicKeyStr ? { nearPublicKeyStr: params.nearPublicKeyStr } : {}),
          ...(params.sessionPolicyDigest32
            ? { sessionPolicyDigest32: params.sessionPolicyDigest32 }
            : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
          ...(params.emailOtpPrompt ? { emailOtpPrompt: params.emailOtpPrompt } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'delegate': {
      const txSigningRequests: TransactionInputWasm[] = [
        {
          receiverId: params.delegate.receiverId,
          actions: params.delegate.actions,
        },
      ];

      intentDigest = await computeUiIntentDigestFromTxs(
        txSigningRequests.map((tx) => ({
          receiverId: tx.receiverId,
          actions: tx.actions.map(orderActionForDigest),
        })),
      );

      const summary: TransactionSummary = {
        intentDigest,
        receiverId: txSigningRequests[0]?.receiverId,
        totalAmount: computeTotalAmountYocto(txSigningRequests),
        type: 'delegateAction',
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
        delegate: {
          senderId: params.delegate.senderId,
          receiverId: params.delegate.receiverId,
          nonce: String(params.delegate.nonce),
          maxBlockHeight: String(params.delegate.maxBlockHeight),
        },
      };
      const displayModel = buildNearDisplayModelWithFallback({
        txSigningRequests,
        intentDigest,
        signerAccountId: params.nearAccountId,
        title: summary.title,
        body: summary.body,
      });

      request = {
        requestId: sessionId,
        type: UserConfirmationType.SIGN_TRANSACTION,
        summary,
        payload: {
          txSigningRequests,
          intentDigest,
          displayModel,
          rpcCall: params.rpcCall,
          ...(params.nearPublicKeyStr ? { nearPublicKeyStr: params.nearPublicKeyStr } : {}),
          ...(params.sessionPolicyDigest32
            ? { sessionPolicyDigest32: params.sessionPolicyDigest32 }
            : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
          ...(params.emailOtpPrompt ? { emailOtpPrompt: params.emailOtpPrompt } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'nep413': {
      intentDigest = `${params.nearAccountId}:${params.recipient}:${params.message}`;
      const summary: TransactionSummary = {
        intentDigest,
        method: 'NEP-413',
        receiverId: params.recipient,
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
      };

      request = {
        requestId: sessionId,
        type: UserConfirmationType.SIGN_NEP413_MESSAGE,
        summary,
        payload: {
          nearAccountId: params.nearAccountId,
          ...(params.nearPublicKeyStr ? { nearPublicKeyStr: params.nearPublicKeyStr } : {}),
          message: params.message,
          recipient: params.recipient,
          ...(params.sessionPolicyDigest32
            ? { sessionPolicyDigest32: params.sessionPolicyDigest32 }
            : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
          ...(params.emailOtpPrompt ? { emailOtpPrompt: params.emailOtpPrompt } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'intentDigest': {
      const uiIntentDigest = normalizeIntentDigestForUi(params.intentDigest);
      intentDigest = uiIntentDigest;
      const challengeB64u = normalizeChallengeB64u(params.challengeB64u);
      const displayModel =
        params.displayModel ||
        buildPendingIntentDisplayModel({
          chain: params.chain,
          signerAccountId: params.signerAccountId,
          title: params.title,
          body: params.body,
          intentDigest: uiIntentDigest || undefined,
        });

      const summary: TransactionSummary = {
        ...(uiIntentDigest ? { intentDigest: uiIntentDigest } : {}),
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
      };

      request = {
        requestId: sessionId,
        type: UserConfirmationType.SIGN_INTENT_DIGEST,
        summary,
        payload: {
          nearAccountId: params.signerAccountId,
          challengeB64u,
          displayModel,
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
          ...(params.emailOtpPrompt ? { emailOtpPrompt: params.emailOtpPrompt } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        ...(uiIntentDigest ? { intentDigest: uiIntentDigest } : {}),
      };
      break;
    }
    default: {
      throw new Error('Unsupported signing confirmation kind');
    }
  }

  const decision = await requestUserConfirmation(request, {
    onProgress: params.onProgress,
  });

  if (!decision?.confirmed) {
    throw new Error(decision?.error || 'User rejected signing request');
  }

  if (params.kind === 'intentDigest') {
    return {
      sessionId,
      intentDigest: decision.intentDigest || intentDigest,
      credential: decision.credential,
      otpCode: decision.otpCode,
      emailOtpChallengeId: decision.emailOtpChallengeId,
    };
  }

  if (!decision.transactionContext) {
    throw new Error('Missing transactionContext from confirmation flow');
  }

  return {
    sessionId,
    transactionContext: decision.transactionContext,
    intentDigest: decision.intentDigest || intentDigest,
    credential: decision.credential,
    otpCode: decision.otpCode,
    emailOtpChallengeId: decision.emailOtpChallengeId,
  };
}

function resolveRequestUserConfirmationBridge(
  ctx: TouchConfirmRequestBridgeContext,
): RequestUserConfirmationBridge {
  if (typeof ctx?.touchConfirm?.requestUserConfirmation !== 'function') {
    throw new Error('UserConfirm manager request bridge is unavailable');
  }
  return async (request, options) =>
    await ctx.touchConfirm.requestUserConfirmation(request, options);
}

function computeTotalAmountYocto(txSigningRequests: TransactionInputWasm[]): string | undefined {
  try {
    let total = BigInt(0);
    for (const tx of txSigningRequests) {
      for (const action of tx.actions) {
        switch (action.action_type) {
          case ActionType.Transfer:
            total += BigInt(action.deposit || '0');
            break;
          case ActionType.FunctionCall:
            total += BigInt(action.deposit || '0');
            break;
          case ActionType.Stake:
            total += BigInt(action.stake || '0');
            break;
          default:
            break;
        }
      }
    }
    return total > BigInt(0) ? total.toString() : undefined;
  } catch {
    return undefined;
  }
}
