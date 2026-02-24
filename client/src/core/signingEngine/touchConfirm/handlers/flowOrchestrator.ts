import type { TransactionInputWasm } from '@/core/types/actions';
import { ActionType } from '@/core/types/actions';
import type { RpcCallPayload, ConfirmationConfig } from '@/core/types/signer-worker';
import type { TransactionContext } from '@/core/types/rpc';
import { computeUiIntentDigestFromTxs, orderActionForDigest } from '@/utils/intentDigest';
import {
  UserConfirmationType,
  type UserConfirmRequest,
  type SigningAuthMode,
  type TransactionSummary,
  type SerializableCredential,
  type UserConfirmProgressEvent,
  type UserConfirmDecision,
} from '../shared/confirmTypes';
import type { TxDisplayModel } from '../shared/displayModel';
import { buildNearDisplayModel } from '../displayFormat/nearTx';

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
}

export interface OrchestrateNearNep413SigningConfirmationParams extends OrchestrateSigningConfirmationBaseParams {
  chain: 'near';
  kind: 'nep413';
  nearAccountId: string;
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
}

export interface SigningConfirmationResultIntentDigest {
  sessionId: string;
  intentDigest: string;
  credential?: SerializableCredential;
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
  params: Exclude<OrchestrateSigningConfirmationParams, OrchestrateIntentDigestSigningConfirmationParams>,
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
      intentDigest = await computeUiIntentDigestFromTxs(
        txSigningRequests.map((tx) => ({
          receiverId: tx.receiverId,
          actions: tx.actions.map(orderActionForDigest),
        })) as TransactionInputWasm[]
      );

      const summary: TransactionSummary = {
        intentDigest,
        receiverId: txSigningRequests[0]?.receiverId,
        totalAmount: computeTotalAmountYocto(txSigningRequests),
        type: 'transaction',
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
      };
      const displayModel = buildNearDisplayModel({
        txSigningRequests,
        intentDigest,
        signerAccount: params.rpcCall.nearAccountId,
        title: summary.title,
        subtitle: summary.body,
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
          ...(params.sessionPolicyDigest32 ? { sessionPolicyDigest32: params.sessionPolicyDigest32 } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'delegate': {
      const txSigningRequests: TransactionInputWasm[] = [{
        receiverId: params.delegate.receiverId,
        actions: params.delegate.actions,
      }];

      intentDigest = await computeUiIntentDigestFromTxs(
        txSigningRequests.map((tx) => ({
          receiverId: tx.receiverId,
          actions: tx.actions.map(orderActionForDigest),
        }))
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
      const displayModel = buildNearDisplayModel({
        txSigningRequests,
        intentDigest,
        signerAccount: params.nearAccountId,
        title: summary.title,
        subtitle: summary.body,
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
          ...(params.sessionPolicyDigest32 ? { sessionPolicyDigest32: params.sessionPolicyDigest32 } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
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
          message: params.message,
          recipient: params.recipient,
          ...(params.sessionPolicyDigest32 ? { sessionPolicyDigest32: params.sessionPolicyDigest32 } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'intentDigest': {
      intentDigest = String(params.intentDigest || '').trim();
      if (!intentDigest) {
        throw new Error('Missing intentDigest for intent digest signing flow');
      }
      const challengeB64u = String(params.challengeB64u || '').trim();
      if (!challengeB64u) {
        throw new Error('Missing challengeB64u for intent digest signing flow');
      }

      const summary: TransactionSummary = {
        intentDigest,
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
          ...(params.displayModel ? { displayModel: params.displayModel } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
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
  };
}

function resolveRequestUserConfirmationBridge(
  ctx: TouchConfirmRequestBridgeContext,
): RequestUserConfirmationBridge {
  if (typeof ctx?.touchConfirm?.requestUserConfirmation !== 'function') {
    throw new Error('UserConfirm manager request bridge is unavailable');
  }
  return async (request, options) => await ctx.touchConfirm.requestUserConfirmation(request, options);
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
