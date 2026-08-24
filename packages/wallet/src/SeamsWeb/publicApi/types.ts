import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type {
  WalletIframeRequestId,
  WalletIframeSurfaceId,
} from '@/core/types/walletIframeIdentity';
export type {
  WalletIframeRequestId,
  WalletIframeSurfaceId,
} from '@/core/types/walletIframeIdentity';
import type {
  NearAccountRef,
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletId as EcdsaWalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaChainSelector,
  EvmChainSelector,
  TempoChainSelector,
} from '@/SeamsWeb/publicApi/chainTargets';
import type { WalletSessionInput } from '@/SeamsWeb/publicApi/currentWallet';
export type { WalletSessionInput } from '@/SeamsWeb/publicApi/currentWallet';
import type {
  EmailOtpChallengeDelivery,
  EmailOtpEnrollmentResult,
  DemoEmailOtpCodeResponse,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { ProvisionWarmEd25519CapabilityResult } from '@/core/signingEngine/session/warmCapabilities/types';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { NearClient, SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type {
  ActionResult,
  DelegateRouterApiResult,
  EmailOtpAuthPolicy,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  RegistrationResult,
  NearProvisioningState,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SigningSessionStatus,
  SignTransactionResult,
  SeamsRegistrationNearAccountProvisioning,
  ThemeMode,
  SeamsConfigsReadonly,
} from '@/core/types/seams';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  RegistrationFlowEvent,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SigningFlowEvent,
  SyncAccountHooksOptions,
  UnlockFlowEvent,
  NearProvisioningStateChangedEvent,
} from '@/core/types/sdkSentEvents';
import type { AwaitNearReadyResult } from '@/SeamsWeb/publicApi/awaitNearReady';
export type { AwaitNearReadyResult } from '@/SeamsWeb/publicApi/awaitNearReady';
import type { EmailOtpProvider } from '@shared/utils/walletAuthAuthority';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletAuthMethodRevocationProof } from '@shared/utils/registrationIntent';
import type {
  ConfirmationBehavior,
  ConfirmationConfig,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AccountId } from '@/core/types/accountIds';
import type { ActionArgs, TransactionInput } from '@/core/types/actions';
import type { DelegateActionInput, SignedDelegate } from '@/core/types/delegate';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type {
  SignNEP413MessageParams,
  SignNEP413MessageResult,
} from '@/SeamsWeb/operations/near/signNEP413';
import type { SyncAccountResult } from '@/SeamsWeb/operations/recovery/syncAccount';
import type {
  AddPasskeyAuthorization,
  AddPasskeyHooksOptions,
  AddPasskeyResult,
} from '@/SeamsWeb/operations/authMethods/passkey/addPasskey';
import type {
  WalletRecoveryBackupAcknowledgementResult,
  WalletRecoveryCodeStatusResult,
  WalletCustodyEmailOtpChallengeResult,
} from '@/core/rpcClients/relayer/walletRecoveryRotate';
import type { WalletRecoveryRotationAuthorization } from '@/SeamsWeb/operations/recovery/walletRecoveryRotation';
import type { WalletRecoveryRotationOutcome } from '@/core/signingEngine/walletCustody/walletRecoveryRotation';
export type {
  AddPasskeyAuthorization,
  AddPasskeyHooksOptions,
  AddPasskeyResult,
} from '@/SeamsWeb/operations/authMethods/passkey/addPasskey';
export type {
  WalletRecoveryBackupAcknowledgementResult,
  WalletRecoveryCodeStatusResult,
  WalletCustodyEmailOtpChallengeResult,
} from '@/core/rpcClients/relayer/walletRecoveryRotate';
export type { WalletRecoveryRotationAuthorization } from '@/SeamsWeb/operations/recovery/walletRecoveryRotation';
export type { WalletRecoveryRotationOutcome } from '@/core/signingEngine/walletCustody/walletRecoveryRotation';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type {
  AvailableSigningLanes,
  ReadAvailableSigningLanesInput,
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
} from '@/core/signingEngine/session/public';
import type {
  NearSignIntentRequest,
  NearSignIntentResult,
} from '@/core/signingEngine/flows/signNear/signNear';
import type {
  ReconcileTempoNonceLaneArgs as RuntimeReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs as RuntimeReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs as RuntimeReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs as RuntimeReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs as RuntimeReportTempoFinalizedArgs,
  TempoNonceLaneStatus as RuntimeTempoNonceLaneStatus,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import type {
  EvmAddress,
  EvmBytes,
  EvmSigningRequest,
} from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { TempoFeeTokenValidation } from '@/core/signingEngine/chains/tempo/feeToken';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
  SigningEngineExportKeypairWithUIInput,
} from '@/core/signingEngine/flows/recovery/public';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ConnectEd25519SessionArgs } from '@/core/signingEngine/session/passkey/public';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  EnrollEmailOtpInternalArgs,
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type {
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '@/core/types/linkDevice';
export type {
  LinkedDeviceEmailOtpActivationStateV1,
  LinkedDeviceTargetEmailOtpActivationV1,
  LinkedDeviceTargetFactorActivationV1,
  LinkedDeviceTargetFactorV1,
  LinkedDeviceTargetPasskeyActivationV1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
  StartDeviceLinkingOptionsDevice2,
} from '@/core/types/linkDevice';
import type {
  LinkedDeviceListResultV1,
  LinkedDeviceRevokeResultV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationNearAccountProvisioning,
  RegistrationSignerSetSelection,
  WalletId,
} from '@shared/utils/registrationIntent';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type { FinalizeWalletRegistrationEcdsaSessionsInput } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type {
  StoreAuthenticatorInput,
  StoredRegistrationData,
  StoreWalletEcdsaRegistrationInput,
  StoreWalletEcdsaSignerRecordsInput,
  StoreWalletEcdsaSignerRecordsResult,
  StoreWalletEd25519RegistrationInput,
  StoreWalletEd25519SignerRecordInput,
  StoreWalletEmailOtpEd25519RegistrationInput,
  StoreWalletEmailOtpEcdsaRegistrationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import type { HydrateWarmSigningSessionInput } from '@/core/signingEngine/session/passkey/warmSessionHydration';
export type {
  LinkedDeviceListResultV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
} from '@shared/device-linking';

type PublicThresholdEcdsaSessionKeyRef = Omit<
  ThresholdEcdsaSessionBootstrapResult['thresholdEcdsaKeyRef'],
  'ecdsaThresholdKeyId' | 'signingRootId' | 'signingRootVersion' | 'ecdsaDerivationExportArtifact'
>;

export type PublicThresholdEcdsaSessionBootstrapResult = Omit<
  ThresholdEcdsaSessionBootstrapResult,
  'thresholdEcdsaKeyRef'
> & {
  thresholdEcdsaKeyRef: PublicThresholdEcdsaSessionKeyRef;
};

export type SignTempoArgs = {
  /** A `WalletSessionRef` or bare wallet id. Omitted, resolves to the authenticated wallet. */
  walletSession?: WalletSessionInput;
  request: TempoSigningRequest;
  /** A configured Tempo network slug, or an exact target. */
  chainTarget: TempoChainSelector;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  };
};

export type SignEvmTransactionArgs = {
  /** A `WalletSessionRef` or bare wallet id. Omitted, resolves to the authenticated wallet. */
  walletSession?: WalletSessionInput;
  request: EvmSigningRequest;
  /** A configured EVM network slug, or an exact target. */
  chainTarget: EvmChainSelector;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  };
};

export type GetTempoFeeTokenPreferenceArgs = {
  chainTarget: TempoChainTarget;
  account: EvmAddress;
  timeoutMs?: number;
};

export type ValidateTempoFeeTokenArgs = {
  chainTarget: TempoChainTarget;
  feeToken: EvmAddress;
  timeoutMs?: number;
};

export type SetTempoFeeTokenPreferenceArgs = {
  walletSession: WalletSessionRef;
  chainTarget: TempoChainTarget;
  account: EvmAddress;
  feeToken: EvmAddress;
  feeCaps: {
    maxPriorityFeePerGas: bigint;
    maxFeePerGas: bigint;
  };
  gasLimit?: bigint;
  finalization?: {
    timeoutMs?: number;
    pollIntervalMs?: number;
    confirmations?: number;
  };
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: TempoNonceLifecycleEvent) => void;
  };
};

export type RegisterNearImplicitWalletArgs = {
  accountProvisioning?: Extract<RegistrationNearAccountProvisioning, { kind: 'implicit_account' }>;
  nearAccountId?: never;
  wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>;
  authMethod: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type RegisterNearSponsoredWalletArgs = {
  accountProvisioning: Extract<
    RegistrationNearAccountProvisioning,
    { kind: 'sponsored_named_account' }
  >;
  wallet: Extract<RegisterWalletInput, { kind: 'provided' }>;
  nearAccountId?: never;
  authMethod: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type RegisterNearWalletArgs =
  | RegisterNearImplicitWalletArgs
  | RegisterNearSponsoredWalletArgs;

export type FundImplicitNearAccountForTestingResult =
  | {
      ok: true;
      walletId: string;
      nearAccountId: string;
      fundedAmountYocto: string;
      transactionHash?: string;
      message?: string;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type PasskeyRegistrationOptions = RegistrationHooksOptions & {
  wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>;
  nearAccountProvisioning?: SeamsRegistrationNearAccountProvisioning;
};

export type RegisterEvmWalletArgs = {
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  participantIds: readonly number[];
  authMethod: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type TempoNonceLifecycleEvent = SigningFlowEvent;

export type TempoNonceLifecycleOptions = {
  onEvent?: (event: TempoNonceLifecycleEvent) => void;
};

type ReportTempoNonceLifecycleBaseArgs = {
  walletSession: WalletSessionRef;
  signedResult: TempoSignedResult | EvmSignedResult;
  options?: TempoNonceLifecycleOptions;
};

export type ReportTempoBroadcastAcceptedArgs = ReportTempoNonceLifecycleBaseArgs & {
  txHash: `0x${string}`;
};

export type ReportTempoBroadcastRejectedArgs = ReportTempoNonceLifecycleBaseArgs & {
  error?: unknown;
};

export type ReportTempoFinalizedArgs = ReportTempoNonceLifecycleBaseArgs & {
  txHash?: `0x${string}`;
  receiptStatus?: 'success' | 'reverted';
};

export type ReportTempoDroppedOrReplacedArgs = ReportTempoNonceLifecycleBaseArgs & {
  reason: 'dropped' | 'replaced';
  txHash?: `0x${string}`;
};

export type ReconcileTempoNonceLaneArgs = ReportTempoNonceLifecycleBaseArgs;

export type TempoNonceLaneStatus = {
  chainNextNonce: string;
  unresolvedInFlightNonces: string[];
  blocked: boolean;
  blockedNonce?: string;
};

export type FinalizedEvmEip1559PayloadExpectation = {
  kind: 'evm_eip1559';
  to: EvmAddress | null;
  input: EvmBytes;
};

export type FinalizedTempoEip2718CallPayloadExpectation = {
  to: EvmAddress;
  input: EvmBytes;
};

export type FinalizedTempoEip2718PayloadExpectation = {
  kind: 'tempo_eip2718_calls';
  calls: readonly [
    FinalizedTempoEip2718CallPayloadExpectation,
    ...FinalizedTempoEip2718CallPayloadExpectation[],
  ];
};

export type FinalizedEvmTxPayloadExpectation =
  | FinalizedEvmEip1559PayloadExpectation
  | FinalizedTempoEip2718PayloadExpectation;

export type FinalizedEvmEip1559PayloadObservation = {
  kind: 'evm_eip1559';
  to: string | null;
  input: string | null;
};

export type FinalizedTempoEip2718CallPayloadObservation = {
  to: string | null;
  input: string | null;
  data: string | null;
};

export type FinalizedTempoEip2718PayloadObservation = {
  kind: 'tempo_eip2718_calls';
  calls: readonly FinalizedTempoEip2718CallPayloadObservation[];
};

export type FinalizedEvmTxPayloadObservation =
  | FinalizedEvmEip1559PayloadObservation
  | FinalizedTempoEip2718PayloadObservation;

export type FinalizedEvmTxPayloadVerification =
  | {
      kind: 'matched';
      expected: FinalizedEvmTxPayloadExpectation;
      observed: FinalizedEvmTxPayloadObservation;
    }
  | {
      kind: 'tx_unavailable';
      expected: FinalizedEvmTxPayloadExpectation;
    }
  | {
      kind: 'mismatch';
      expected: FinalizedEvmTxPayloadExpectation;
      observed: FinalizedEvmTxPayloadObservation;
    };

type ExecuteEvmFamilyTransactionBaseArgs = {
  /** A `WalletSessionRef` or bare wallet id. Omitted, resolves to the authenticated wallet. */
  walletSession?: WalletSessionInput;
  /** A configured EVM-family network slug, or an exact target. */
  chainTarget: EcdsaChainSelector;
  postFinalizationCheck?: () => Promise<void>;
  finalization?: {
    timeoutMs?: number;
    pollIntervalMs?: number;
    confirmations?: number;
  };
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: TempoNonceLifecycleEvent) => void;
  };
};

/**
 * On the execute path `tx.chainId` is redundant: `chainTarget` already named the
 * chain, and a value that disagreed with it would be a bug. Omit it and the SDK
 * fills it from the resolved target. The sign-only paths keep it required,
 * because there is no target to derive it from there.
 */
type WithOptionalChainId<TRequest extends { tx: { chainId: number } }> = Omit<TRequest, 'tx'> & {
  tx: Omit<TRequest['tx'], 'chainId'> & { chainId?: number };
};

/** Execute an EIP-1559 transaction on a configured EVM chain. */
export type ExecuteEvmTransactionArgs = Omit<ExecuteEvmFamilyTransactionBaseArgs, 'chainTarget'> & {
  /** A configured EVM network slug, or an exact target. */
  chainTarget: EvmChainSelector;
  request: WithOptionalChainId<EvmSigningRequest>;
  payloadExpectation?: FinalizedEvmEip1559PayloadExpectation;
};

/** Execute an EIP-2718 typed transaction on a configured Tempo chain. */
export type ExecuteTempoTransactionArgs = Omit<
  ExecuteEvmFamilyTransactionBaseArgs,
  'chainTarget'
> & {
  /** A configured Tempo network slug, or an exact target. */
  chainTarget: TempoChainSelector;
  request: WithOptionalChainId<TempoSigningRequest>;
  payloadExpectation?: FinalizedTempoEip2718PayloadExpectation;
};

/**
 * The shared execute shape. Prefer the family-specific
 * `seams.evm.executeTransaction` / `seams.tempo.executeTransaction`, which keep
 * the request, the chain, and the payload expectation matched to one family.
 */
export type ExecuteEvmFamilyTransactionArgs =
  | ExecuteEvmTransactionArgs
  | ExecuteTempoTransactionArgs;

export type ExecuteEvmFamilyTransactionResult = {
  txHash: `0x${string}`;
  signedResult: TempoSignedResult | EvmSignedResult;
  payloadVerification: FinalizedEvmTxPayloadVerification;
};

export type BootstrapThresholdEcdsaSessionArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl?: string;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  kind: 'reuse_warm_ecdsa_bootstrap';
  source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
  sessionIdentity?: never;
  routeAuth?: never;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u?: never;
  emailOtpAuthContext?: never;
};

export type EmailOtpChallengeResult = {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  delivery: EmailOtpChallengeDelivery;
  emailHint?: string;
  expiresAtMs?: number;
};

export type EmailOtpOperationChallengeResult = EmailOtpChallengeResult & {
  ownerProofBindingDigest: string;
};

export type { EmailOtpEnrollmentResult };

export type GoogleEmailOtpRegistrationEnrollmentResult = Omit<
  EmailOtpEnrollmentResult,
  'challengeId'
> & {
  registrationAuthorityId: string;
  challengeId?: never;
  otpCode?: never;
  delivery?: never;
  webauthn?: never;
  passkey?: never;
};

export type EmailOtpEcdsaCapabilityArgs = {
  walletSession: WalletSessionRef;
  /** Exact Email OTP method selected during challenge resolution. */
  walletAuthMethodId?: string;
  chainTarget: ThresholdEcdsaChainTarget;
  providerIdentity: {
    provider: EmailOtpProvider;
    providerSubjectId: string;
  };
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  groupId?: string;
  registrationAttemptId?: string;
  emailOtpAuthorityEmail?: string;
  onEvent?: (event: UnlockFlowEvent) => void;
};

export type EmailOtpEcdsaCapabilityResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: PublicThresholdEcdsaSessionBootstrapResult;
  authorization: ActiveWalletSessionAuthorizationProjection;
  authorizations: readonly [
    ActiveWalletSessionAuthorizationProjection,
    ...ActiveWalletSessionAuthorizationProjection[],
  ];
};

export type GoogleEmailOtpWalletAuthRequestedMode = 'register' | 'login';
export type GoogleEmailOtpWalletAuthResolvedMode = 'register' | 'login';
export type GoogleEmailOtpWalletAuthDelivery = EmailOtpChallengeDelivery;

export type GoogleEmailOtpRegistrationOfferId = string & {
  readonly __googleEmailOtpRegistrationOfferId: unique symbol;
};

export type GoogleEmailOtpRegistrationCandidateId = string & {
  readonly __googleEmailOtpRegistrationCandidateId: unique symbol;
};

export type RegistrationFinalizeIdempotencyKey = string & {
  readonly __registrationFinalizeIdempotencyKey: unique symbol;
};

export function registrationFinalizeIdempotencyKeyFromString(
  value: string,
): RegistrationFinalizeIdempotencyKey {
  const normalized = value.trim();
  if (!normalized) throw new Error('Registration finalize idempotency key is required');
  return normalized as RegistrationFinalizeIdempotencyKey;
}

export type GoogleEmailOtpRegistrationCandidate = {
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  walletId: WalletId;
};

export type GoogleEmailOtpRegistrationOffer = {
  kind: 'google_email_otp_registration_offer_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  expiresAtMs: number;
  emailHint: string;
  candidates: readonly [
    GoogleEmailOtpRegistrationCandidate,
    ...GoogleEmailOtpRegistrationCandidate[],
  ];
  selectedCandidateId: GoogleEmailOtpRegistrationCandidateId;
  delivery?: never;
  challengeId?: never;
  otpCode?: never;
  webauthn?: never;
  passkey?: never;
};

export type GoogleEmailOtpRegistrationFinalizeInput = {
  kind: 'google_email_otp_registration_finalize_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  idempotencyKey: RegistrationFinalizeIdempotencyKey;
  emailOtpEnrollment: GoogleEmailOtpRegistrationEnrollmentResult;
  walletId?: never;
  otpCode?: never;
  challengeId?: never;
  delivery?: never;
  webauthn?: never;
  passkey?: never;
};

export type GoogleEmailOtpWalletAuthEcdsaTargets =
  | { kind: 'configured' }
  | { kind: 'none' }
  | {
      kind: 'explicit';
      targets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
    };

export type GoogleEmailOtpWalletAuthFailureCode =
  | 'google_verification_failed'
  | 'google_account_registration_required'
  | 'email_otp_challenge_failed'
  | 'email_otp_invalid_code'
  | 'email_otp_expired'
  | 'email_otp_rate_limited'
  | 'registration_failed'
  | 'registration_restore_required'
  | 'unlock_failed'
  | 'recovery_code_backup_incomplete'
  | 'local_signing_session_not_ready'
  | 'wallet_iframe_unavailable'
  | 'flow_cancelled'
  | 'flow_expired';

export type GoogleEmailOtpWalletAuthFailure = {
  code: GoogleEmailOtpWalletAuthFailureCode;
  message: string;
  retryAfterMs?: number;
};

export type GoogleEmailOtpWalletAuthResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: GoogleEmailOtpWalletAuthFailure };

export type GoogleEmailOtpWalletAuthPromptCopy = {
  title: string;
  description: string;
  submitLabel: string;
  helperText: string;
};

export type GoogleEmailOtpWalletAuthSubmitSuccess = {
  walletId: WalletId;
  session: WalletSession;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
};

export type GoogleEmailOtpWalletAuthRegistrationCompleted = {
  walletId: WalletId;
  session: WalletSession;
  registration: RegistrationResult;
  mode: 'register';
};

export type GoogleEmailOtpWalletAuthBaseFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  walletId: WalletId;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  expiresAtMs: number;
  cancel(): Promise<void>;
};

export type GoogleEmailOtpWalletAuthRegistrationFlow = GoogleEmailOtpWalletAuthBaseFlow & {
  state: 'registration_ready';
  mode: 'register';
  completeRegistration(): Promise<
    GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted>
  >;
  rerollWalletId(): Promise<
    GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationFlow>
  >;
  delivery?: never;
  resend?: never;
  submit?: never;
};

export type GoogleEmailOtpWalletAuthLoginFlow = GoogleEmailOtpWalletAuthBaseFlow & {
  state: 'challenge_sent';
  mode: 'login';
  delivery: GoogleEmailOtpWalletAuthDelivery;
  resend(): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
  submit(input: {
    otpCode: string;
  }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthSubmitSuccess>>;
  completeRegistration?: never;
  rerollWalletId?: never;
};

export type GoogleEmailOtpWalletAuthFlow =
  | GoogleEmailOtpWalletAuthRegistrationFlow
  | GoogleEmailOtpWalletAuthLoginFlow;

export type GoogleEmailOtpWalletAuthStartInput = {
  idToken: string;
  mode: GoogleEmailOtpWalletAuthRequestedMode;
  /**
   * Register-mode only: start a fresh wallet even when this Google account
   * already holds an Email OTP wallet. Completing the new registration retires
   * the previous wallet's email factor, so this is always an explicit choice —
   * without it, register mode fails when the account already has a wallet.
   */
  replaceExistingWallet?: boolean;
  relayUrl?: string;
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onDemoOtp?: (response: DemoEmailOtpCodeResponse) => void;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};
export interface AuthCapability {
  unlock(walletId: string, options?: LoginHooksOptions): Promise<LoginAndCreateSessionResult>;
  lock(): Promise<void>;
  getWalletSession(walletId?: string): Promise<WalletSession>;
  getRecentUnlocks(): Promise<GetRecentUnlocksResult>;
  hasPasskeyCredential(walletId: string): Promise<boolean>;
  prefillRouterAbEcdsaDerivationPresignaturePool(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult>;
  requestEmailOtpChallenge(args: {
    walletId: string;
    walletAuthMethodId?: string;
    relayUrl?: string;
    operation?: WalletEmailOtpLoginOperation;
    operationFingerprintDigest?: DigestB64u;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpOperationChallengeResult>;
  requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<Pick<EmailOtpChallengeResult, 'challengeId' | 'emailHint'>>;
  refreshEmailOtpSigningSession(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpEcdsaCapabilityResult>;
  loginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult>;
  beginGoogleEmailOtpWalletAuth(
    args: GoogleEmailOtpWalletAuthStartInput,
  ): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
}

export interface RegistrationCapability {
  getNearProvisioningState(args: {
    walletId: WalletId | string;
  }): Promise<NearProvisioningState | null>;
  onNearProvisioningStateChanged(
    listener: (event: NearProvisioningStateChangedEvent) => void,
  ): () => void;
  /**
   * Waits for a pending NEAR account to become ready.
   *
   * A mixed registration returns `ecdsa_wallet_registered_near_pending`, which
   * carries no NEAR account id — this is how you get one without hand-rolling
   * the subscribe/read/timeout race. Resolves (never rejects) on `near_ready`,
   * `near_failed_retryable`, or timeout; rejects only if `signal` aborts.
   *
   * @param args.timeoutMs defaults to 120_000
   */
  awaitNearReady(args: {
    walletId: WalletId | string;
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<AwaitNearReadyResult>;
  addWalletSigner(args: {
    walletId: WalletId | string;
    rpId: string;
    signerSelection: AddSignerSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  addPasskey(args: {
    walletId: WalletId | string;
    rpId: string;
    authorization: AddPasskeyAuthorization;
    options?: AddPasskeyHooksOptions;
  }): Promise<AddPasskeyResult>;
  registerWallet(args: {
    authMethod: RegistrationAuthMethodInput;
    wallet: RegisterWalletInput;
    signerSelection: RegistrationSignerSetSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  /**
   * @deprecated Use `registerWallet` with an `email_otp` `authMethod` — this is
   * the same function, only narrower. Two names for one operation makes the
   * registration surface look larger than it is.
   */
  registerWithEmailOtp(args: {
    authMethod: Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>;
    wallet: RegisterWalletInput;
    signerSelection: RegistrationSignerSetSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  registerPasskey(options?: PasskeyRegistrationOptions): Promise<RegistrationResult>;
  requestEmailOtpEnrollmentChallenge(args: {
    walletId: string;
    relayUrl?: string;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult>;
  enrollEmailOtp(args: {
    walletId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    groupId?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpEnrollmentResult>;
}

/**
 * Names the wallet and NEAR account a call authorizes.
 *
 * Both are optional: omitted, they resolve to the currently **authenticated**
 * wallet and its NEAR account. Pass them explicitly to target an exact subject —
 * required whenever the application manages more than one wallet at a time.
 */
export type NearSubjectInput = {
  /** A `WalletSessionRef`, or a bare wallet id. */
  walletSession?: WalletSessionInput;
  /** A `NearAccountRef`, or a bare NEAR account id. */
  nearAccount?: NearAccountRef | string;
};

export interface NearSignerCapability {
  registerNearWallet(args: RegisterNearWalletArgs): Promise<RegistrationResult>;

  fundImplicitNearAccountForTesting(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    nearPublicKey: string;
  }): Promise<FundImplicitNearAccountForTestingResult>;

  executeAction(
    args: NearSubjectInput & {
      receiverId: string;
      actionArgs: ActionArgs | ActionArgs[];
      options?: ActionHooksOptions;
    },
  ): Promise<ActionResult>;

  signAndSendTransaction(
    args: NearSubjectInput & {
      receiverId: string;
      actions: ActionArgs[];
      options?: SignAndSendTransactionHooksOptions;
    },
  ): Promise<ActionResult>;

  signTransactionWithActions(
    args: NearSubjectInput & {
      transaction: TransactionInput;
      options?: SignTransactionHooksOptions;
    },
  ): Promise<SignTransactionResult>;

  sendTransaction(
    args: NearSubjectInput & {
      signedTransaction: SignedTransaction;
      options?: SendTransactionHooksOptions;
    },
  ): Promise<ActionResult>;

  signDelegateAction(
    args: NearSubjectInput & {
      delegate: DelegateActionInput;
      options?: DelegateActionHooksOptions;
    },
  ): Promise<SignDelegateActionResult>;

  sendDelegateActionViaRelayer(args: {
    relayerUrl: string;
    signedDelegate: SignedDelegate | WasmSignedDelegate;
    hash: string;
    signal?: AbortSignal;
    options?: DelegateRelayHooksOptions;
  }): Promise<DelegateRouterApiResult>;

  signAndSendDelegateAction(
    args: NearSubjectInput & {
      delegate: DelegateActionInput;
      relayerUrl: string;
      signal?: AbortSignal;
      options?: SignAndSendDelegateActionHooksOptions;
    },
  ): Promise<SignAndSendDelegateActionResult>;

  signNEP413Message(
    args: NearSubjectInput & {
      params: SignNEP413MessageParams;
      options?: SignNEP413HooksOptions;
    },
  ): Promise<SignNEP413MessageResult>;
}

/**
 * Tempo-specific operations.
 *
 * The generic EVM-family entry points live on `seams.evm` — `seams.evm.execute`
 * sends on any configured EVM-family chain, Tempo included. What remains here
 * is what only Tempo has: the fee-token preference.
 */
/**
 * Post-broadcast lifecycle. `executeTransaction` drives all of it; reach for
 * these only when your application broadcasts the signed payload itself.
 */
export interface EvmFamilyAdvancedCapability {
  reportBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void>;
  reportFinalized(args: ReportTempoFinalizedArgs): Promise<void>;
  reportDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus>;
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<PublicThresholdEcdsaSessionBootstrapResult>;
}

/**
 * Tempo signing — EIP-2718 typed transactions.
 *
 * Deliberately separate from `seams.evm`: a Tempo transaction is a different
 * envelope with a different signed result (`senderHashHex`, not `txHashHex`) and
 * its own fee-token model. The two namespaces mirror each other's method names
 * so the shape is familiar, without unioning two chain families into one call.
 */
export interface TempoSignerCapability {
  /** Sign an EIP-2718 typed transaction without broadcasting. */
  signTransaction(args: SignTempoArgs): Promise<TempoSignedResult>;
  /** Sign, broadcast, and await finalization. The usual entry point. */
  executeTransaction(args: ExecuteTempoTransactionArgs): Promise<ExecuteEvmFamilyTransactionResult>;
  /** Post-broadcast lifecycle reporting; `executeTransaction` already drives it. */
  readonly advanced: EvmFamilyAdvancedCapability;

  /** Tempo pays fees in a configurable token; this is that preference. */
  getFeeTokenPreference(args: GetTempoFeeTokenPreferenceArgs): Promise<EvmAddress | null>;
  validateFeeToken(args: ValidateTempoFeeTokenArgs): Promise<TempoFeeTokenValidation>;
  setFeeTokenPreference(
    args: SetTempoFeeTokenPreferenceArgs,
  ): Promise<ExecuteEvmFamilyTransactionResult>;

  /** @deprecated Renamed to `signTransaction`, to mirror `seams.evm`. */
  signTempo(args: SignTempoArgs): Promise<TempoSignedResult>;
  /** @deprecated Renamed to `executeTransaction`, to mirror `seams.evm`. */
  executeEvmFamilyTransaction(
    args: ExecuteEvmFamilyTransactionArgs,
  ): Promise<ExecuteEvmFamilyTransactionResult>;
  /** @deprecated Use `seams.tempo.advanced.reportBroadcastAccepted`. */
  reportBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void>;
  /** @deprecated Use `seams.tempo.advanced.reportBroadcastRejected`. */
  reportBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void>;
  /** @deprecated Use `seams.tempo.advanced.reportFinalized`. */
  reportFinalized(args: ReportTempoFinalizedArgs): Promise<void>;
  /** @deprecated Use `seams.tempo.advanced.reportDroppedOrReplaced`. */
  reportDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void>;
  /** @deprecated Use `seams.tempo.advanced.reconcileNonceLane`. */
  reconcileNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus>;
  /** @deprecated Use `seams.tempo.advanced.bootstrapEcdsaSession`. */
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<PublicThresholdEcdsaSessionBootstrapResult>;
}

/**
 * EVM signing — EIP-1559 transactions on a configured EVM chain.
 *
 * Mirrors `seams.tempo` method for method. The two stay separate because the
 * envelopes and the signed results differ: this one yields `txHashHex`, Tempo's
 * yields `senderHashHex`.
 */
export interface EvmSignerCapability {
  /** Sign an EIP-1559 transaction without broadcasting. */
  signTransaction(args: SignEvmTransactionArgs): Promise<EvmSignedResult>;
  /** Sign, broadcast, and await finalization. The usual entry point. */
  executeTransaction(args: ExecuteEvmTransactionArgs): Promise<ExecuteEvmFamilyTransactionResult>;
  /** Post-broadcast lifecycle reporting; `executeTransaction` already drives it. */
  readonly advanced: EvmFamilyAdvancedCapability;

  registerEvmWallet(args: RegisterEvmWalletArgs): Promise<RegistrationResult>;

  /** @deprecated Use `seams.evm.advanced.bootstrapEcdsaSession`. */
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<PublicThresholdEcdsaSessionBootstrapResult>;
}

export interface RecoveryCapability {
  syncAccount(args: {
    walletId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult>;

  getWalletRecoveryCodeStatus(args: { walletId: string }): Promise<WalletRecoveryCodeStatusResult>;

  acknowledgeWalletRecoveryCodeBackup(args: {
    walletId: string;
  }): Promise<WalletRecoveryBackupAcknowledgementResult>;

  requestWalletCustodyEmailOtpChallenge(args: {
    walletId: string;
    providerSubjectId: string;
    operation:
      | 'credentials_list'
      | 'credential_label'
      | 'recovery_acknowledge'
      | 'recovery_rotate'
      | 'recovery_read';
    payload: Record<string, unknown>;
    requestOrigin?: string;
  }): Promise<WalletCustodyEmailOtpChallengeResult>;

  rotateWalletRecoveryCodes(args: {
    walletId: string;
    authorization: WalletRecoveryRotationAuthorization;
  }): Promise<WalletRecoveryRotationOutcome>;
}

export interface DevicesCapability {
  startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults>;

  cancelDeviceLinking(): Promise<void>;

  scanAndLinkDevice(
    qrData: QrLinkedDeviceSessionPayloadV5,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult>;

  listLinkedDevices(args: {
    walletId: string;
    limit: number;
    cursor: string | null;
  }): Promise<LinkedDeviceListResultV1>;

  revokeLinkedDevice(args: {
    walletId: string;
    walletAuthMethodId: string;
    requestedAtMs: number;
    sourceProof: WalletAuthMethodRevocationProof;
  }): Promise<LinkedDeviceRevokeResultV1>;
}

export type KeyExportUiOptions = SigningEngineExportKeypairWithUIInput['options'];

/** Every field of the UI options is optional, so the bag itself is too. */
type WithOptionalOptions<T> = T extends unknown
  ? Omit<T, 'options'> & { options?: KeyExportUiOptions }
  : never;

export type ExportKeypairWithUIInput = WithOptionalOptions<SigningEngineExportKeypairWithUIInput>;

export type ResolveExactKeyExportLaneInput = SigningEngineResolveExactKeyExportLaneInput;
export type ResolveExactKeyExportLaneResult = SigningEngineResolveExactKeyExportLaneResult;

/**
 * What `exportKeypair` did.
 *
 * `relink_required` is a real, reachable state — the wallet has no canonical
 * owner binding on this device — and is returned rather than thrown so the
 * caller can route the person to re-link instead of showing a generic error.
 */
export type KeyExportOutcome =
  | { kind: 'exported' }
  | { kind: 'relink_required'; reason: 'missing_canonical_owner_binding' };

export type ExportKeypairInput =
  | {
      kind: 'ed25519';
      /** A `WalletSessionRef` or bare wallet id. Omitted, resolves to the authenticated wallet. */
      walletSession?: WalletSessionInput;
      /** Omitted, resolves to the authenticated wallet's NEAR account. */
      nearAccount?: NearAccountRef | string;
      chainTarget?: never;
      options?: KeyExportUiOptions;
    }
  | {
      kind: 'ecdsa';
      /** A `WalletSessionRef` or bare wallet id. Omitted, resolves to the authenticated wallet. */
      walletSession?: WalletSessionInput;
      /** A configured EVM-family network slug, or an exact target. */
      chainTarget: EcdsaChainSelector;
      nearAccount?: never;
      options?: KeyExportUiOptions;
    };

export interface KeyExportCapability {
  /**
   * Resolve the exact export lane, then open the wallet-origin export viewer.
   *
   * One call: the lane resolution feeds straight into the export, and the
   * `relink_required` lane comes back as a result instead of an exception.
   */
  exportKeypair(input: ExportKeypairInput): Promise<KeyExportOutcome>;

  /** Lower-level: resolve the lane without exporting (e.g. to pre-check availability). */
  resolveExactKeyExportLane(
    input: ResolveExactKeyExportLaneInput,
  ): Promise<ResolveExactKeyExportLaneResult>;
  /** Lower-level: export with a lane you already resolved. */
  exportKeypairWithUI(input: ExportKeypairWithUIInput): Promise<void>;
}

export interface PreferencesCapability {
  setCurrentWallet(walletId: WalletId): void;
  getCurrentWalletId(): WalletId | null;
  onConfirmationConfigChange(callback: (config: ConfirmationConfig) => void): () => void;
  onCurrentWalletChange(callback: (walletId: WalletId | null) => void): () => void;
  setConfirmBehavior(behavior: ConfirmationBehavior): void;
  setConfirmationConfig(config: Partial<ConfirmationConfig>): void;
  getConfirmationConfig(): ConfirmationConfig;
}
