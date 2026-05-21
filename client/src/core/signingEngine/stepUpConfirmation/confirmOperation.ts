import type { TransactionInputWasm } from '@/core/types/actions';
import type { RpcCallPayload, ConfirmationConfig } from '@/core/types/signer-worker';
import type { TransactionContext } from '@/core/types/rpc';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
  UserConfirmProgressEvent,
} from './types';
import type {
  SerializableCredential,
  UserConfirmDecision,
  UserConfirmRequest,
  WebAuthnChallenge,
} from './channel/confirmTypes';
import type { NonceLeaseRef } from '../interfaces/nonceLease';
import type { TxDisplayModel } from '../interfaces/display';

export type SigningConfirmationChain = 'near' | 'evm' | 'tempo';

export type RequestUserConfirmationBridge = (
  request: UserConfirmRequest,
  options?: { onProgress?: (progress: UserConfirmProgressEvent) => void },
) => Promise<UserConfirmDecision>;

export type UiConfirmRequestBridgeContext = {
  touchConfirm: {
    requestUserConfirmation: RequestUserConfirmationBridge;
  };
};

export type ConfirmationReadiness = {
  promise: Promise<unknown>;
  body?: string;
};

export type OrchestrateSigningConfirmationBaseParams = {
  ctx: UiConfirmRequestBridgeContext;
  sessionId: string;
  chain: SigningConfirmationChain;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  onProgress?: (progress: UserConfirmProgressEvent) => void;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  confirmationReadiness?: ConfirmationReadiness;
};

type OrchestrateSigningConfirmationAuthParams =
  {
    signingAuthPlan: SigningAuthPlan;
    webauthnChallenge?: WebAuthnChallenge;
  };

type OrchestrateIntentDigestSigningConfirmationAuthParams =
  | {
      signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
      webauthnChallenge: WebAuthnChallenge;
    }
  | {
      signingAuthPlan: Exclude<SigningAuthPlan, Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>>;
      webauthnChallenge?: WebAuthnChallenge;
    };

export type OrchestrateNearTransactionSigningConfirmationParams =
  OrchestrateSigningConfirmationBaseParams &
    OrchestrateSigningConfirmationAuthParams & {
      chain: 'near';
      kind: 'transaction';
      txSigningRequests: TransactionInputWasm[];
      rpcCall: RpcCallPayload;
      nearPublicKeyStr?: string;
      title?: string;
      body?: string;
    };

export type OrchestrateNearDelegateSigningConfirmationParams =
  OrchestrateSigningConfirmationBaseParams &
    OrchestrateSigningConfirmationAuthParams & {
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
    };

export type OrchestrateNearNep413SigningConfirmationParams =
  OrchestrateSigningConfirmationBaseParams &
    OrchestrateSigningConfirmationAuthParams & {
      chain: 'near';
      kind: 'nep413';
      nearAccountId: string;
      nearPublicKeyStr?: string;
      message: string;
      recipient: string;
      title?: string;
      body?: string;
    };

export type OrchestrateIntentDigestSigningConfirmationParams =
  OrchestrateSigningConfirmationBaseParams &
    OrchestrateIntentDigestSigningConfirmationAuthParams & {
      kind: 'intentDigest';
      signerAccountId: string;
      challengeB64u: string;
      intentDigest: string;
      displayModel?: TxDisplayModel;
      title?: string;
      body?: string;
    };

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
  nonceLeases?: NonceLeaseRef[];
}

export interface SigningConfirmationResultIntentDigest {
  sessionId: string;
  intentDigest: string;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
}

export type ConfirmSigningOperationRuntime = {
  orchestrateSigningConfirmation(
    params: OrchestrateIntentDigestSigningConfirmationParams,
  ): Promise<SigningConfirmationResultIntentDigest>;
  orchestrateSigningConfirmation(
    params: Exclude<
      OrchestrateSigningConfirmationParams,
      OrchestrateIntentDigestSigningConfirmationParams
    >,
  ): Promise<SigningConfirmationResultWithTxContext>;
};

export type ConfirmSigningOperationParams = OrchestrateSigningConfirmationParams;
export type ConfirmIntentDigestSigningOperationRequest =
  OrchestrateIntentDigestSigningConfirmationParams;
export type ConfirmTransactionSigningOperationRequest = Exclude<
  OrchestrateSigningConfirmationParams,
  OrchestrateIntentDigestSigningConfirmationParams
>;
export type ConfirmIntentDigestSigningOperationResult = SigningConfirmationResultIntentDigest;
export type ConfirmTransactionSigningOperationResult = SigningConfirmationResultWithTxContext;
export type ConfirmSigningOperationResult =
  | SigningConfirmationResultWithTxContext
  | SigningConfirmationResultIntentDigest;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: ConfirmIntentDigestSigningOperationRequest;
}): Promise<SigningConfirmationResultIntentDigest>;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: ConfirmTransactionSigningOperationRequest;
}): Promise<SigningConfirmationResultWithTxContext>;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: OrchestrateSigningConfirmationParams;
}): Promise<ConfirmSigningOperationResult> {
  const orchestrate = args.runtime.orchestrateSigningConfirmation as (
    request: OrchestrateSigningConfirmationParams,
  ) => Promise<ConfirmSigningOperationResult>;
  return await orchestrate(args.request);
}
