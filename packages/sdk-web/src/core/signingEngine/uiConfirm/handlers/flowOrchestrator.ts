import type { TransactionInputWasm } from '@/core/types/actions';
import { ActionType } from '@/core/types/actions';
import { computeUiIntentDigestFromTxs, orderActionForDigest } from '@/utils/intentDigest';
import {
  SigningAuthPlanKind,
  signingAuthModeFromSigningAuthPlan,
  type SigningAuthPlan,
} from '../../stepUpConfirmation/types';
import {
  UserConfirmationType,
  type UserConfirmRequest,
  type TransactionSummary,
  type SignIntentDigestSubject,
  type SignIntentDigestPayload,
  type SignTransactionPayload,
  type WebAuthnChallenge,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { TxDisplayModel } from '../../interfaces/display';
import { buildNearDisplayModel } from '../../chains/near/display';
import type {
  OrchestrateIntentDigestSigningConfirmationParams,
  OrchestrateNearSignatureOnlySigningConfirmationParams,
  OrchestrateNearTransactionSigningConfirmationParams,
  OrchestrateSigningConfirmationParams,
  NearTransactionSigningConfirmationResult,
  RequestUserConfirmationBridge,
  SigningConfirmationChain,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultSignatureOnly,
  UiConfirmRequestBridgeContext,
} from '../../stepUpConfirmation/confirmOperation';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  registerIntentDigestPreparation,
} from '../../stepUpConfirmation/intentDigestPreparation';
import {
  clearConfirmationReadiness,
  registerConfirmationReadiness,
  type ConfirmationReadiness,
} from '../confirmationReadinessRegistry';

function buildSignTransactionPayload(args: {
  params: OrchestrateNearTransactionSigningConfirmationParams;
  txSigningRequests: TransactionInputWasm[];
  intentDigest: string;
  displayModel: TxDisplayModel;
}): SignTransactionPayload {
  const base = {
    signingKind: 'transaction' as const,
    walletId: args.params.walletId,
    txSigningRequests: args.txSigningRequests,
    intentDigest: args.intentDigest,
    displayModel: args.displayModel,
    rpcCall: args.params.rpcCall,
    nearPublicKeyStr: args.params.nearPublicKeyStr,
    nearFundingRequest: args.params.nearFundingRequest,
  };
  switch (args.params.signingAuthPlan.kind) {
    case SigningAuthPlanKind.WarmSession:
      return {
        ...base,
        signingAuthPlan: args.params.signingAuthPlan,
      };
    case SigningAuthPlanKind.PasskeyReauth:
      return {
        ...base,
        signingAuthPlan: args.params.signingAuthPlan,
        ...(args.params.webauthnChallenge
          ? { webauthnChallenge: args.params.webauthnChallenge }
          : {}),
      };
    case SigningAuthPlanKind.EmailOtpReauth:
      if (!args.params.emailOtpPrompt) {
        throw new Error('Email OTP NEAR confirmation requires a prompt');
      }
      return {
        ...base,
        signingAuthPlan: args.params.signingAuthPlan,
        emailOtpPrompt: args.params.emailOtpPrompt,
      };
    default:
      return assertNeverTransactionSigningAuthParams(args.params.signingAuthPlan);
  }
}

function assertNeverTransactionSigningAuthParams(value: never): never {
  throw new Error(`Unsupported transaction signing auth params: ${String(value)}`);
}

function buildDelegateSignTransactionPayload(args: {
  params: Extract<OrchestrateNearSignatureOnlySigningConfirmationParams, { kind: 'delegate' }>;
  txSigningRequests: TransactionInputWasm[];
  intentDigest: string;
  displayModel: TxDisplayModel;
}): SignTransactionPayload {
  const base = {
    signingKind: 'delegate' as const,
    walletId: args.params.walletId,
    txSigningRequests: args.txSigningRequests,
    intentDigest: args.intentDigest,
    displayModel: args.displayModel,
    rpcCall: args.params.rpcCall,
    ...(args.params.nearPublicKeyStr ? { nearPublicKeyStr: args.params.nearPublicKeyStr } : {}),
  };
  switch (args.params.signingAuthPlan.kind) {
    case SigningAuthPlanKind.WarmSession:
      return {
        ...base,
        signingAuthPlan: args.params.signingAuthPlan,
      };
    case SigningAuthPlanKind.PasskeyReauth:
      return {
        ...base,
        signingAuthPlan: args.params.signingAuthPlan,
        ...(args.params.webauthnChallenge
          ? { webauthnChallenge: args.params.webauthnChallenge }
          : {}),
      };
    case SigningAuthPlanKind.EmailOtpReauth: {
      const emailOtpPrompt = args.params.signingAuthPlan.emailOtpPrompt;
      if (!emailOtpPrompt) {
        throw new Error('Email OTP delegate confirmation requires a prompt');
      }
      return {
        ...base,
        signingAuthPlan: args.params.signingAuthPlan,
        emailOtpPrompt,
      };
    }
    default:
      return assertNeverTransactionSigningAuthParams(args.params.signingAuthPlan);
  }
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

function signingSubjectLabel(subject: SignIntentDigestSubject): string {
  switch (subject.kind) {
    case 'near_wallet':
      return subject.nearAccountId;
    case 'evm_wallet':
      return subject.walletId;
    default: {
      const exhaustive: never = subject;
      throw new Error(`Unsupported signing subject: ${String(exhaustive)}`);
    }
  }
}

function requireIntentDigestWebAuthnChallenge(
  value: WebAuthnChallenge | undefined,
): WebAuthnChallenge {
  if (!value) {
    throw new Error('[SigningConfirmation] passkey intent signing requires webauthnChallenge');
  }
  return value;
}

function buildSignIntentDigestPayload(args: {
  signingSubject: SignIntentDigestSubject;
  challengeB64u: string;
  displayModel?: TxDisplayModel;
  webauthnChallenge?: WebAuthnChallenge;
  signingAuthPlan: SigningAuthPlan;
  emailOtpPrompt?: OrchestrateIntentDigestSigningConfirmationParams['emailOtpPrompt'];
}): SignIntentDigestPayload {
  if (args.signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth) {
    return {
      signingSubject: args.signingSubject,
      challengeB64u: args.challengeB64u,
      ...(args.displayModel ? { displayModel: args.displayModel } : {}),
      webauthnChallenge: requireIntentDigestWebAuthnChallenge(args.webauthnChallenge),
      signingAuthPlan: args.signingAuthPlan,
    };
  }
  return {
    signingSubject: args.signingSubject,
    challengeB64u: args.challengeB64u,
    ...(args.displayModel ? { displayModel: args.displayModel } : {}),
    signingAuthPlan: args.signingAuthPlan,
    ...(args.webauthnChallenge ? { webauthnChallenge: args.webauthnChallenge } : {}),
    ...(args.emailOtpPrompt ? { emailOtpPrompt: args.emailOtpPrompt } : {}),
  };
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
 * This creates a `UserConfirmRequest` and routes it through the worker handshake so uiConfirm
 * can render UI in wallet origin and collect signing artifacts.
 */
export async function orchestrateSigningConfirmation(
  params: OrchestrateIntentDigestSigningConfirmationParams,
): Promise<SigningConfirmationResultIntentDigest>;
export async function orchestrateSigningConfirmation(
  params: OrchestrateNearTransactionSigningConfirmationParams,
): Promise<NearTransactionSigningConfirmationResult>;
export async function orchestrateSigningConfirmation(
  params: OrchestrateNearSignatureOnlySigningConfirmationParams,
): Promise<SigningConfirmationResultSignatureOnly>;
export async function orchestrateSigningConfirmation(
  params: OrchestrateSigningConfirmationParams,
): Promise<
  | NearTransactionSigningConfirmationResult
  | SigningConfirmationResultIntentDigest
  | SigningConfirmationResultSignatureOnly
>;
export async function orchestrateSigningConfirmation(
  params: OrchestrateSigningConfirmationParams,
): Promise<
  | NearTransactionSigningConfirmationResult
  | SigningConfirmationResultIntentDigest
  | SigningConfirmationResultSignatureOnly
> {
  const { sessionId } = params;
  const requestUserConfirmation = resolveRequestUserConfirmationBridge(params.ctx);
  const effectiveSigningAuthMode = signingAuthModeFromSigningAuthPlan(params.signingAuthPlan);

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

      if (params.chain === 'near' && effectiveSigningAuthMode === 'warmSession') {
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
          payload: buildSignTransactionPayload({
            params,
            txSigningRequests,
            intentDigest: PENDING_INTENT_DIGEST,
            displayModel: eagerDisplayModel,
          }),
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
        payload: buildSignTransactionPayload({
          params,
          txSigningRequests,
          intentDigest,
          displayModel,
        }),
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
        payload: buildDelegateSignTransactionPayload({
          params,
          txSigningRequests,
          intentDigest,
          displayModel,
        }),
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
          walletId: params.walletId,
          nearAccountId: params.nearAccountId,
          ...(params.nearPublicKeyStr ? { nearPublicKeyStr: params.nearPublicKeyStr } : {}),
          message: params.message,
          recipient: params.recipient,
          ...(params.webauthnChallenge ? { webauthnChallenge: params.webauthnChallenge } : {}),
          signingAuthPlan: params.signingAuthPlan,
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
      const signingSubject = params.signingSubject;
      const signingSubjectDisplayLabel = signingSubjectLabel(signingSubject);
      const displayModel =
        params.displayModel ||
        buildPendingIntentDisplayModel({
          chain: params.chain,
          signerAccountId: signingSubjectDisplayLabel,
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
        payload: buildSignIntentDigestPayload({
          signingSubject,
          challengeB64u,
          displayModel,
          webauthnChallenge: params.webauthnChallenge,
          signingAuthPlan: params.signingAuthPlan,
          ...(params.emailOtpPrompt ? { emailOtpPrompt: params.emailOtpPrompt } : {}),
        }),
        confirmationConfig: params.confirmationConfigOverride,
        ...(uiIntentDigest ? { intentDigest: uiIntentDigest } : {}),
      };
      break;
    }
    default: {
      throw new Error('Unsupported signing confirmation kind');
    }
  }

  if (params.confirmationReadiness) {
    registerConfirmationReadiness({
      requestId: sessionId,
      readiness: params.confirmationReadiness,
    });
  }

  const decision = await requestUserConfirmation(request, {
    onProgress: params.onProgress,
  }).finally(() => {
    clearConfirmationReadiness(sessionId);
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

  if (params.kind === 'delegate' || params.kind === 'nep413') {
    return {
      sessionId,
      intentDigest: decision.intentDigest || intentDigest,
      credential: decision.credential,
      otpCode: decision.otpCode,
      emailOtpChallengeId: decision.emailOtpChallengeId,
    };
  }

  if (!decision.nearTransactionReadiness) {
    throw new Error('Missing explicit NEAR transaction readiness from confirmation flow');
  }

  return {
    sessionId,
    readiness: decision.nearTransactionReadiness,
    intentDigest: decision.intentDigest || intentDigest,
    credential: decision.credential,
    otpCode: decision.otpCode,
    emailOtpChallengeId: decision.emailOtpChallengeId,
  };
}

function resolveRequestUserConfirmationBridge(
  ctx: UiConfirmRequestBridgeContext,
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
