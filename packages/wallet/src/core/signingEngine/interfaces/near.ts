import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { TransactionInputWasm } from '@/core/types/actions';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  TransactionPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { NearSigningRuntimeDeps } from './runtime';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import type { NearAccountRef, NearCommandSubject } from './ecdsaChainTarget';
import type {
  EmailOtpStepUpAuthorization,
  PasskeyStepUpAuthorization,
  SigningAuthPlan,
  WarmSessionStepUpAuthorization,
} from '../stepUpConfirmation/types';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { SigningOperationId, SigningSessionPlan } from '../session/operationState/types';
import type { NearTransactionSigningLane } from '../session/operationState/lanes';
import type { SelectedEd25519Lane } from '../session/identity/laneIdentity';
import type { AuthorizationRequiredEd25519LaneCandidate } from '../session/identity/selectLane';
import type { PreparedTransactionOperation } from '../session/operationState/transactionState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { RouterAbEd25519SigningWalletSession } from '../session/routerAbSigningWalletSession';
import type { RouterAbEd25519YaoActiveClientV1 } from '../threshold/ed25519/yaoClient';
import type { EmailOtpTransactionSigningChallenge } from '../session/emailOtp/publicTypes';
import type { PasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../session/warmCapabilities/routerAbEd25519WalletSessionState';
import type { MpcMaterialActivationRef, ThresholdEd25519SessionId } from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { NearEd25519YaoSigningPreparation } from '../session/material/nearEd25519YaoSigningPreparation';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { Ed25519OperationStepUpProof } from '../threshold/ed25519/walletSession';
export type NearResolvedEd25519WalletSessionAuth = {
  kind: 'wallet_session_opaque';
  walletSessionToken: string;
};

export type NearPasskeyOperationStepUpPlan = {
  thresholdSessionId: ThresholdEd25519SessionId;
  authority: PasskeyWalletAuthAuthority;
};

export type NearEd25519WarmSessionStepUpAuthorization = WarmSessionStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'warmSession' }>
>;

export type NearEd25519PasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>,
  {
    plannedPasskeyOperationStepUp: NearPasskeyOperationStepUpPlan;
  }
>;

export type NearEd25519EmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>
>;

export type NearEd25519StepUpAuthorization =
  | NearEd25519WarmSessionStepUpAuthorization
  | NearEd25519EmailOtpStepUpAuthorization
  | NearEd25519PasskeyStepUpAuthorization;

export type NearResolvedEd25519SigningSessionState = {
  walletSessionAuth: NearResolvedEd25519WalletSessionAuth;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingLane: NearTransactionSigningLane;
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  signingWalletSession: RouterAbEd25519SigningWalletSession;
  sessionKind?: never;
};

export type NearAuthorizedEd25519SigningSessionState = NearResolvedEd25519SigningSessionState & {
  walletSessionAuthorization: ActiveWalletSessionAuthorizationProjection;
};

export type NearEd25519YaoOperationMaterialFacts = {
  thresholdSessionId: ThresholdEd25519SessionId;
  signer: NearTransactionSigningLane['identity']['signer'];
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
};

export type NearEd25519YaoOperationMaterial = {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  facts: NearEd25519YaoOperationMaterialFacts;
};

export type NearEd25519FundingSession = {
  readonly kind: 'near_ed25519_funding_session';
  readonly signer: NearTransactionSigningLane['identity']['signer'];
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly walletSessionToken: string;
};

export type NearEd25519OperationStepUpAuthorization = {
  kind: 'verified_step_up';
  authorization: { kind: 'operation_step_up'; evidence_set_digest: string };
  expiresAtMs: number;
};

export type NearPasskeyEd25519OperationStepUpCapabilityPreparation = {
  materialActivation: MpcMaterialActivationRef;
  facts: NearEd25519YaoOperationMaterialFacts;
  participantIds: readonly number[];
  rehydrate(credential: WebAuthnAuthenticationCredential): Promise<NearEd25519YaoOperationMaterial>;
};

export type NearEmailOtpEd25519OperationStepUpCapabilityPreparation =
  | {
      kind: 'live';
      materialActivation: MpcMaterialActivationRef;
      material: NearEd25519YaoOperationMaterial;
      authorizeAndRehydrate?: never;
    }
  | {
      kind: 'sealed';
      materialActivation: MpcMaterialActivationRef;
      facts: NearEd25519YaoOperationMaterialFacts;
      material?: never;
      authorizeAndRehydrate(args: {
        normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
        displayDigest: string;
        proof: Extract<Ed25519OperationStepUpProof, { kind: 'email_otp' }>;
      }): Promise<{
        material: NearEd25519YaoOperationMaterial;
        issuedAuthorization: NearEd25519OperationStepUpAuthorization;
      }>;
    };

export type NearEd25519YaoMaterialExecutor = {
  resolveSigningKeyMaterial: () => Promise<ThresholdEd25519KeyMaterial>;
  resolve: (
    preparation: NearEd25519YaoSigningPreparation,
  ) => Promise<NearEd25519YaoOperationMaterial>;
  resolveWalletSessionState: () => Promise<ResolvedRouterAbEd25519WalletSessionState>;
  resolveFundingSession: () => Promise<NearEd25519FundingSession>;
  preparePasskeyOperationStepUp: (
    preparation: NearEd25519YaoSigningPreparation,
  ) => Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation>;
  prepareEmailOtpOperationStepUp: (
    preparation: NearEd25519YaoSigningPreparation,
  ) => Promise<NearEmailOtpEd25519OperationStepUpCapabilityPreparation>;
};

export type NearEd25519YaoPreparedMaterialBoundary = {
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
};

export type NearPasskeyEd25519OperationStepUpHook = {
  prepare: () => Promise<{
    thresholdSessionId: ThresholdEd25519SessionId;
    authority: PasskeyWalletAuthAuthority;
  }>;
};

export type NearEmailOtpEd25519StepUpHook = {
  prepare: () => Promise<EmailOtpTransactionSigningChallenge>;
  resend?: () => Promise<EmailOtpTransactionSigningChallenge>;
};

export type NearEd25519TransactionAdmissionBoundary = {
  thresholdSessionId: ThresholdEd25519SessionId;
  signingSessionPlan: SigningSessionPlan;
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
};

export type NearEd25519TransactionSigningBoundary = NearEd25519TransactionAdmissionBoundary;

type NearTransactionWithActionsPayloadBase = {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  transaction: TransactionInputWasm;
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signerSlot?: number;
  signingOperationId?: SigningOperationId;
  signingSessionCoordinator: SigningSessionCoordinator;
  passkeyEd25519OperationStepUp?: NearPasskeyEd25519OperationStepUpHook;
  emailOtpEd25519StepUp?: NearEmailOtpEd25519StepUpHook;
  sensitivePolicy?: SensitiveOperationPolicy;
  yaoSigningPreparation: NearEd25519YaoSigningPreparation;
  yaoMaterialExecutor: NearEd25519YaoMaterialExecutor;
};

export type NearTransactionWithActionsPayload =
  | (NearTransactionWithActionsPayloadBase & {
      selection: {
        kind: 'authorized';
        selectedLane: SelectedEd25519Lane;
        candidate?: never;
      };
      transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
      ed25519SigningBoundary: NearEd25519TransactionSigningBoundary;
    })
  | (NearTransactionWithActionsPayloadBase & {
      selection: {
        kind: 'authorization_required';
        selectedLane?: never;
        candidate: AuthorizationRequiredEd25519LaneCandidate;
      };
      transactionOperation?: never;
      ed25519SigningBoundary?: never;
    });

export type NearAdHocEd25519Selection =
  | {
      kind: 'authorized';
      selectedLane: SelectedEd25519Lane;
      candidate?: never;
    }
  | {
      kind: 'authorization_required';
      selectedLane?: never;
      candidate: AuthorizationRequiredEd25519LaneCandidate;
    };

export type NearDelegateActionPayload = {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  signingSessionCoordinator: SigningSessionCoordinator;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  operationId: SigningOperationId;
  signerSlot?: number;
  forceFreshAuth: boolean;
  selection: NearAdHocEd25519Selection;
  passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
  emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
  yaoSigningPreparation: NearEd25519YaoSigningPreparation;
  yaoMaterialExecutor: NearEd25519YaoMaterialExecutor;
};

export type NearNep413Payload = {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth: boolean;
  selection: NearAdHocEd25519Selection;
  passkeyEd25519OperationStepUp: NearPasskeyEd25519OperationStepUpHook | null;
  emailOtpEd25519StepUp: NearEmailOtpEd25519StepUpHook | null;
  yaoSigningPreparation: NearEd25519YaoSigningPreparation;
  yaoMaterialExecutor: NearEd25519YaoMaterialExecutor;
  payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: string;
    signerSlot?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    operationId: SigningOperationId;
    nearRpcUrl?: string;
  };
};

export type NearSigningRequest =
  | {
      chain: 'near';
      kind: 'transactionWithActions';
      payload: NearTransactionWithActionsPayload;
    }
  | {
      chain: 'near';
      kind: 'delegateAction';
      payload: NearDelegateActionPayload;
    }
  | {
      chain: 'near';
      kind: 'nep413';
      payload: NearNep413Payload;
    };

export type NearEd25519SignRequest =
  | {
      kind: 'near-transaction-with-actions';
      algorithm: 'ed25519';
      payload: NearTransactionWithActionsPayload;
    }
  | {
      kind: 'near-delegate-action';
      algorithm: 'ed25519';
      payload: NearDelegateActionPayload;
    }
  | {
      kind: 'near-nep413-message';
      algorithm: 'ed25519';
      payload: NearNep413Payload;
    };

export type NearTransactionWithActionsResult = {
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
};

export type NearDelegateActionResult = {
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
};

export type NearNep413Result = {
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
};

export type NearEd25519SignOutput =
  | {
      kind: 'near-transaction-with-actions';
      result: NearTransactionWithActionsResult;
    }
  | {
      kind: 'near-delegate-action';
      result: NearDelegateActionResult;
    }
  | {
      kind: 'near-nep413-message';
      result: NearNep413Result;
    };

export type NearSignedResult = NearEd25519SignOutput['result'];

export type NearIntentResultByKind = {
  transactionWithActions: NearTransactionWithActionsResult;
  delegateAction: NearDelegateActionResult;
  nep413: NearNep413Result;
};

export type NearIntentResult<T extends NearSigningRequest> = T extends { kind: infer K }
  ? K extends keyof NearIntentResultByKind
    ? NearIntentResultByKind[K]
    : never
  : never;

export type NearIntentUiModel =
  | {
      kind: 'transactionWithActions';
      nearAccountId: string;
      totalActionCount: number;
      txSigningRequest: TransactionPayload;
    }
  | {
      kind: 'delegateAction';
      nearAccountId: string;
      receiverId: string;
      actionCount: number;
    }
  | {
      kind: 'nep413';
      nearAccountId: string;
      recipient: string;
    };
