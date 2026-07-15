import type { TransactionInputWasm } from '@/core/types/actions';
import type { RpcCallPayload, ConfirmationConfig } from '@/core/types/signer-worker';
import type { EmailOtpConfirmPrompt, SigningAuthPlan, UserConfirmProgressEvent } from './types';
import { SigningAuthPlanKind as SigningAuthPlanKinds } from './types';
import type {
  SerializableCredential,
  UserConfirmDecision,
  UserConfirmRequest,
  WebAuthnChallenge,
} from './channel/confirmTypes';
import type { TxDisplayModel } from '../interfaces/display';
import type {
  NearFundingRequest,
  NearTransactionReadiness,
} from '../nonce/nearTransactionReadiness';

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
  confirmationReadiness?: ConfirmationReadiness;
};

type WarmSessionSigningConfirmationAuthParams = {
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
  webauthnChallenge?: never;
  emailOtpPrompt?: never;
};

type PasskeySigningConfirmationAuthParams = {
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
  webauthnChallenge?: WebAuthnChallenge;
  emailOtpPrompt?: never;
};

type EmailOtpSigningConfirmationAuthParams = {
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
  webauthnChallenge?: never;
  emailOtpPrompt: EmailOtpConfirmPrompt;
};

type OrchestrateSigningConfirmationAuthParams =
  | WarmSessionSigningConfirmationAuthParams
  | PasskeySigningConfirmationAuthParams
  | EmailOtpSigningConfirmationAuthParams;

type OrchestrateIntentDigestSigningConfirmationAuthParams =
  | (PasskeySigningConfirmationAuthParams & { webauthnChallenge: WebAuthnChallenge })
  | WarmSessionSigningConfirmationAuthParams
  | EmailOtpSigningConfirmationAuthParams;

export function buildSigningConfirmationAuthParams(args: {
  signingAuthPlan: SigningAuthPlan;
  webauthnChallenge?: WebAuthnChallenge;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}): OrchestrateSigningConfirmationAuthParams {
  switch (args.signingAuthPlan.kind) {
    case SigningAuthPlanKinds.WarmSession:
      return {
        signingAuthPlan: args.signingAuthPlan,
      };
    case SigningAuthPlanKinds.PasskeyReauth:
      return {
        signingAuthPlan: args.signingAuthPlan,
        ...(args.webauthnChallenge ? { webauthnChallenge: args.webauthnChallenge } : {}),
      };
    case SigningAuthPlanKinds.EmailOtpReauth: {
      const emailOtpPrompt = args.emailOtpPrompt ?? args.signingAuthPlan.emailOtpPrompt;
      if (!emailOtpPrompt) {
        throw new Error('[SigningConfirmation] missing_email_otp_prompt');
      }
      return {
        signingAuthPlan: args.signingAuthPlan,
        emailOtpPrompt,
      };
    }
    default:
      return assertNeverSigningAuthPlan(args.signingAuthPlan);
  }
}

function assertNeverSigningAuthPlan(value: never): never {
  throw new Error(`Unsupported signing auth plan: ${String((value as { kind?: unknown }).kind)}`);
}

type OrchestrateNearTransactionSigningConfirmationBaseParams =
  OrchestrateSigningConfirmationBaseParams & {
    chain: 'near';
    kind: 'transaction';
    walletId: string;
    txSigningRequests: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    nearPublicKeyStr: string;
    nearFundingRequest: NearFundingRequest;
    title?: string;
    body?: string;
  };

export type OrchestrateNearTransactionSigningConfirmationParams =
  OrchestrateNearTransactionSigningConfirmationBaseParams &
    OrchestrateSigningConfirmationAuthParams;

export type OrchestrateNearDelegateSigningConfirmationParams =
  OrchestrateSigningConfirmationBaseParams &
    OrchestrateSigningConfirmationAuthParams & {
      chain: 'near';
      kind: 'delegate';
      walletId: string;
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
      walletId: string;
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
      challengeB64u: string;
      intentDigest: string;
      displayModel?: TxDisplayModel;
      title?: string;
      body?: string;
    } & (
      | {
          chain: 'near';
          signingSubject: {
            kind: 'near_wallet';
            walletId: string;
            nearAccountId: string;
          };
        }
      | {
          chain: Exclude<SigningConfirmationChain, 'near'>;
          signingSubject: {
            kind: 'evm_wallet';
            walletId: string;
          };
        }
    );

export type OrchestrateSigningConfirmationParams =
  | OrchestrateNearTransactionSigningConfirmationParams
  | OrchestrateNearDelegateSigningConfirmationParams
  | OrchestrateNearNep413SigningConfirmationParams
  | OrchestrateIntentDigestSigningConfirmationParams;

export type OrchestrateNearSignatureOnlySigningConfirmationParams =
  | OrchestrateNearDelegateSigningConfirmationParams
  | OrchestrateNearNep413SigningConfirmationParams;

type SigningConfirmationResultBase = {
  sessionId: string;
  intentDigest: string;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
};

export type NearTransactionSigningConfirmationResult = SigningConfirmationResultBase & {
  readiness: NearTransactionReadiness;
};

export interface SigningConfirmationResultIntentDigest {
  sessionId: string;
  intentDigest: string;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
}

export interface SigningConfirmationResultSignatureOnly {
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
    params: OrchestrateNearTransactionSigningConfirmationParams,
  ): Promise<NearTransactionSigningConfirmationResult>;
  orchestrateSigningConfirmation(
    params: OrchestrateNearSignatureOnlySigningConfirmationParams,
  ): Promise<SigningConfirmationResultSignatureOnly>;
};

export type ConfirmSigningOperationParams = OrchestrateSigningConfirmationParams;
export type ConfirmIntentDigestSigningOperationRequest =
  OrchestrateIntentDigestSigningConfirmationParams;
export type ConfirmTransactionSigningOperationRequest =
  OrchestrateNearTransactionSigningConfirmationParams;
export type ConfirmSignatureOnlySigningOperationRequest =
  OrchestrateNearSignatureOnlySigningConfirmationParams;
export type ConfirmIntentDigestSigningOperationResult = SigningConfirmationResultIntentDigest;
export type ConfirmTransactionSigningOperationResult = NearTransactionSigningConfirmationResult;
export type ConfirmSignatureOnlySigningOperationResult = SigningConfirmationResultSignatureOnly;
export type ConfirmNearStepUpSigningOperationResult =
  | ConfirmTransactionSigningOperationResult
  | ConfirmSignatureOnlySigningOperationResult;
export type ConfirmSigningOperationResult =
  | NearTransactionSigningConfirmationResult
  | SigningConfirmationResultIntentDigest
  | SigningConfirmationResultSignatureOnly;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: ConfirmIntentDigestSigningOperationRequest;
}): Promise<SigningConfirmationResultIntentDigest>;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: ConfirmTransactionSigningOperationRequest;
}): Promise<NearTransactionSigningConfirmationResult>;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: ConfirmSignatureOnlySigningOperationRequest;
}): Promise<SigningConfirmationResultSignatureOnly>;

export async function confirmSigningOperation(args: {
  runtime: ConfirmSigningOperationRuntime;
  request: OrchestrateSigningConfirmationParams;
}): Promise<ConfirmSigningOperationResult> {
  validateSigningConfirmationAuthRoute(args.request);
  const orchestrate = args.runtime.orchestrateSigningConfirmation as (
    request: OrchestrateSigningConfirmationParams,
  ) => Promise<ConfirmSigningOperationResult>;
  return await orchestrate(args.request);
}

function validateSigningConfirmationAuthRoute(request: OrchestrateSigningConfirmationParams): void {
  const raw = request as OrchestrateSigningConfirmationParams & {
    emailOtpPrompt?: unknown;
    webauthnChallenge?: unknown;
  };
  switch (request.signingAuthPlan.kind) {
    case SigningAuthPlanKinds.WarmSession:
      if (raw.emailOtpPrompt !== undefined || raw.webauthnChallenge !== undefined) {
        throw new Error('[SigningConfirmation] auth_method_route_mismatch');
      }
      return;
    case SigningAuthPlanKinds.PasskeyReauth:
      if (raw.emailOtpPrompt !== undefined) {
        throw new Error('[SigningConfirmation] auth_method_route_mismatch');
      }
      return;
    case SigningAuthPlanKinds.EmailOtpReauth:
      if (raw.webauthnChallenge !== undefined || !raw.emailOtpPrompt) {
        throw new Error('[SigningConfirmation] auth_method_route_mismatch');
      }
      return;
    default:
      return assertNeverSigningAuthPlan(request.signingAuthPlan);
  }
}
