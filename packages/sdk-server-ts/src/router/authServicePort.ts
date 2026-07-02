import type { AuthService } from '../core/AuthService';
import type { ThresholdSigningService } from '../core/ThresholdService/ThresholdSigningService';
import type {
  CreateAddAuthMethodIntentRequest,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentRequest,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
  ThresholdRuntimePolicyScope,
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerHssRespondRequest,
  WalletAddSignerHssRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationHssRespondRequest,
  WalletRegistrationHssRespondResponse,
  WalletRegistrationPrepareRequest,
  WalletRegistrationPrepareResponse,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
} from '../core/types';

type CloudflareEmailOtpDeliveryMode = 'email_provider' | 'log' | 'memory' | 'dev_d1_outbox';

type CloudflareEmailOtpDelivery<T> = T extends { mode: unknown }
  ? Omit<T, 'mode'> & { readonly mode: CloudflareEmailOtpDeliveryMode }
  : T;

type CloudflareEmailOtpDeliveryResult<T> = T extends { delivery: infer Delivery }
  ? Omit<T, 'delivery'> & { readonly delivery: CloudflareEmailOtpDelivery<Delivery> }
  : T;

type AuthServiceUnaryAsyncMethod<M extends keyof AuthService> = Extract<
  AuthService[M],
  (input: never) => Promise<unknown>
>;

type RouterApiAsyncMethod<M extends keyof AuthService> = (
  input: Parameters<AuthServiceUnaryAsyncMethod<M>>[0],
) => ReturnType<AuthServiceUnaryAsyncMethod<M>>;

type RouterApiEmailOtpAsyncMethod<M extends keyof AuthService> = (
  input: Parameters<AuthServiceUnaryAsyncMethod<M>>[0],
) => Promise<CloudflareEmailOtpDeliveryResult<Awaited<ReturnType<AuthServiceUnaryAsyncMethod<M>>>>>;

export type GoogleEmailOtpRegistrationCandidateWalletValidationRequest = {
  readonly registrationAttemptId: string;
  readonly walletId: string;
  readonly appSessionVersion: string;
  readonly providerSubject: string;
};

export type GoogleEmailOtpRegistrationCandidateWalletValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface ThresholdRouterApiAuthService {
  getThresholdSigningService(): ThresholdSigningService | null;
}

export interface RouterApiEmailOtpChallengeService {
  createEmailOtpChallenge: RouterApiEmailOtpAsyncMethod<'createEmailOtpChallenge'>;
  createEmailOtpDeviceRecoveryChallenge: RouterApiEmailOtpAsyncMethod<'createEmailOtpDeviceRecoveryChallenge'>;
  createEmailOtpEnrollmentChallenge: RouterApiEmailOtpAsyncMethod<'createEmailOtpEnrollmentChallenge'>;
}

export interface RouterApiWalletRegistrationService {
  createRegistrationIntent(input: {
    request: CreateRegistrationIntentRequest;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateRegistrationIntentResponse>;
  prepareWalletRegistration(
    input: WalletRegistrationPrepareRequest,
  ): Promise<WalletRegistrationPrepareResponse>;
  startWalletRegistration(
    input: WalletRegistrationStartRequest,
  ): Promise<WalletRegistrationStartResponse>;
  respondWalletRegistrationHss(
    input: WalletRegistrationHssRespondRequest,
  ): Promise<WalletRegistrationHssRespondResponse>;
  finalizeWalletRegistration(
    input: WalletRegistrationFinalizeRequest,
  ): Promise<WalletRegistrationFinalizeResponse>;
}

export interface RouterApiAuthService
  extends
    ThresholdRouterApiAuthService,
    RouterApiEmailOtpChallengeService,
    RouterApiWalletRegistrationService {
  applyEmailOtpServerSeal: RouterApiAsyncMethod<'applyEmailOtpServerSeal'>;
  cleanupGoogleEmailOtpDevRegistrationState: RouterApiAsyncMethod<'cleanupGoogleEmailOtpDevRegistrationState'>;
  consumeEmailOtpGrant: RouterApiAsyncMethod<'consumeEmailOtpGrant'>;
  consumeGoogleEmailOtpRegistrationAttemptRateLimit: RouterApiAsyncMethod<'consumeGoogleEmailOtpRegistrationAttemptRateLimit'>;
  consumeEmailOtpRecoveryKey: RouterApiAsyncMethod<'consumeEmailOtpRecoveryKey'>;
  createAddAuthMethodIntent(input: {
    request: CreateAddAuthMethodIntentRequest;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateAddAuthMethodIntentResponse>;
  createAddSignerIntent(input: {
    request: CreateAddSignerIntentRequest;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateAddSignerIntentResponse>;
  createEmailOtpUnlockChallenge: RouterApiAsyncMethod<'createEmailOtpUnlockChallenge'>;
  createWebAuthnLoginOptions: RouterApiAsyncMethod<'createWebAuthnLoginOptions'>;
  createWebAuthnSyncAccountOptions: RouterApiAsyncMethod<'createWebAuthnSyncAccountOptions'>;
  ecdsaHssRoleLocalBootstrap: RouterApiAsyncMethod<'ecdsaHssRoleLocalBootstrap'>;
  ecdsaHssRoleLocalExportShare: RouterApiAsyncMethod<'ecdsaHssRoleLocalExportShare'>;
  finalizeWalletAddAuthMethod(
    input: WalletAddAuthMethodFinalizeRequest,
  ): Promise<WalletAddAuthMethodFinalizeResponse>;
  finalizeWalletAddSigner(
    input: WalletAddSignerFinalizeRequest,
  ): Promise<WalletAddSignerFinalizeResponse>;
  fundImplicitNearAccount(
    input: FundImplicitNearAccountRequest,
  ): Promise<FundImplicitNearAccountResult>;
  getConfiguredRelayerAccount(): string;
  getEmailOtpRecoveryCodeStatus: RouterApiAsyncMethod<'getEmailOtpRecoveryCodeStatus'>;
  getGoogleOidcPublicConfig(): { configured: boolean; clientId?: string };
  getOrCreateAppSessionVersion: RouterApiAsyncMethod<'getOrCreateAppSessionVersion'>;
  getRecoverySession: RouterApiAsyncMethod<'getRecoverySession'>;
  getRelayerAccount(): Promise<{ accountId: string; publicKey: string }>;
  isEmailOtpStrongAuthRequired: RouterApiAsyncMethod<'isEmailOtpStrongAuthRequired'>;
  linkIdentity: RouterApiAsyncMethod<'linkIdentity'>;
  listIdentities: RouterApiAsyncMethod<'listIdentities'>;
  listNearPublicKeysForUser: RouterApiAsyncMethod<'listNearPublicKeysForUser'>;
  listThresholdEcdsaKeyIdentityTargetsForUser: RouterApiAsyncMethod<'listThresholdEcdsaKeyIdentityTargetsForUser'>;
  listWalletEcdsaKeyFactsInventory: RouterApiAsyncMethod<'listWalletEcdsaKeyFactsInventory'>;
  listWebAuthnAuthenticatorsForUser: RouterApiAsyncMethod<'listWebAuthnAuthenticatorsForUser'>;
  markEmailOtpStrongAuthSatisfied: RouterApiAsyncMethod<'markEmailOtpStrongAuthSatisfied'>;
  readActiveEmailOtpEnrollment: RouterApiAsyncMethod<'readActiveEmailOtpEnrollment'>;
  readEmailOtpEnrollment: RouterApiAsyncMethod<'readEmailOtpEnrollment'>;
  readEmailOtpOutboxEntry: RouterApiAsyncMethod<'readEmailOtpOutboxEntry'>;
  recordEmailOtpRecoveryKeyAttemptFailure: RouterApiAsyncMethod<'recordEmailOtpRecoveryKeyAttemptFailure'>;
  recordRecoveryExecution: RouterApiAsyncMethod<'recordRecoveryExecution'>;
  removeEmailOtpServerSeal: RouterApiAsyncMethod<'removeEmailOtpServerSeal'>;
  respondWalletAddSignerHss(
    input: WalletAddSignerHssRespondRequest,
  ): Promise<WalletAddSignerHssRespondResponse>;
  resolveGoogleEmailOtpSession: RouterApiAsyncMethod<'resolveGoogleEmailOtpSession'>;
  resolveOidcWalletId: RouterApiAsyncMethod<'resolveOidcWalletId'>;
  revokeWalletAuthMethod(
    input: WalletRevokeAuthMethodRequest,
  ): Promise<WalletRevokeAuthMethodResponse>;
  rotateEmailOtpRecoveryKeys: RouterApiAsyncMethod<'rotateEmailOtpRecoveryKeys'>;
  rotateAppSessionVersion: RouterApiAsyncMethod<'rotateAppSessionVersion'>;
  startWalletAddAuthMethod(
    input: WalletAddAuthMethodStartRequest,
  ): Promise<WalletAddAuthMethodStartResponse>;
  startWalletAddSigner(input: WalletAddSignerStartRequest): Promise<WalletAddSignerStartResponse>;
  unlinkIdentity: RouterApiAsyncMethod<'unlinkIdentity'>;
  updateRecoverySessionStatus: RouterApiAsyncMethod<'updateRecoverySessionStatus'>;
  validateAppSessionVersion: RouterApiAsyncMethod<'validateAppSessionVersion'>;
  validateGoogleEmailOtpRegistrationCandidateWallet(
    input: GoogleEmailOtpRegistrationCandidateWalletValidationRequest,
  ): Promise<GoogleEmailOtpRegistrationCandidateWalletValidationResult>;
  verifyEmailOtpChallenge: RouterApiAsyncMethod<'verifyEmailOtpChallenge'>;
  verifyEmailOtpDeviceRecoveryChallenge: RouterApiAsyncMethod<'verifyEmailOtpDeviceRecoveryChallenge'>;
  verifyEmailOtpEnrollment: RouterApiAsyncMethod<'verifyEmailOtpEnrollment'>;
  verifyEmailOtpUnlockProof: RouterApiAsyncMethod<'verifyEmailOtpUnlockProof'>;
  verifyEcdsaHssRoleLocalClientRootProofForExistingKey: RouterApiAsyncMethod<'verifyEcdsaHssRoleLocalClientRootProofForExistingKey'>;
  verifyGoogleLogin: RouterApiAsyncMethod<'verifyGoogleLogin'>;
  verifyOidcJwtExchange: RouterApiAsyncMethod<'verifyOidcJwtExchange'>;
  verifyWebAuthnAuthenticationLite: RouterApiAsyncMethod<'verifyWebAuthnAuthenticationLite'>;
  verifyWebAuthnLogin: RouterApiAsyncMethod<'verifyWebAuthnLogin'>;
  verifyWebAuthnSyncAccount: RouterApiAsyncMethod<'verifyWebAuthnSyncAccount'>;
}
