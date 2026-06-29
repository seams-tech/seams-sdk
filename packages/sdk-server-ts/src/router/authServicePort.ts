import type { AuthService } from '../core/AuthService';

export type ThresholdRouterApiAuthService = Pick<AuthService, 'getThresholdSigningService'>;

export type CloudflareRouterApiAuthServiceMethod =
  | 'applyEmailOtpServerSeal'
  | 'cleanupGoogleEmailOtpDevRegistrationState'
  | 'consumeEmailOtpGrant'
  | 'consumeGoogleEmailOtpRegistrationAttemptRateLimit'
  | 'consumeEmailOtpRecoveryKey'
  | 'createAddAuthMethodIntent'
  | 'createAddSignerIntent'
  | 'createEmailOtpUnlockChallenge'
  | 'createRegistrationIntent'
  | 'createWebAuthnLoginOptions'
  | 'createWebAuthnSyncAccountOptions'
  | 'ecdsaHssRoleLocalBootstrap'
  | 'ecdsaHssRoleLocalExportShare'
  | 'finalizeWalletAddAuthMethod'
  | 'finalizeWalletAddSigner'
  | 'finalizeWalletRegistration'
  | 'getConfiguredRelayerAccount'
  | 'getEmailOtpRecoveryCodeStatus'
  | 'getGoogleOidcPublicConfig'
  | 'getOrCreateAppSessionVersion'
  | 'getRecoverySession'
  | 'getRelayerAccount'
  | 'getThresholdSigningService'
  | 'isEmailOtpStrongAuthRequired'
  | 'linkIdentity'
  | 'listIdentities'
  | 'listNearPublicKeysForUser'
  | 'listThresholdEcdsaKeyIdentityTargetsForUser'
  | 'listWalletEcdsaKeyFactsInventory'
  | 'listWebAuthnAuthenticatorsForUser'
  | 'markEmailOtpStrongAuthSatisfied'
  | 'prepareWalletRegistration'
  | 'readActiveEmailOtpEnrollment'
  | 'readEmailOtpEnrollment'
  | 'readEmailOtpOutboxEntry'
  | 'recordEmailOtpRecoveryKeyAttemptFailure'
  | 'recordRecoveryExecution'
  | 'removeEmailOtpServerSeal'
  | 'respondWalletAddSignerHss'
  | 'respondWalletRegistrationHss'
  | 'resolveGoogleEmailOtpSession'
  | 'resolveOidcWalletId'
  | 'revokeWalletAuthMethod'
  | 'rotateEmailOtpRecoveryKeys'
  | 'rotateAppSessionVersion'
  | 'startWalletAddAuthMethod'
  | 'startWalletAddSigner'
  | 'startWalletRegistration'
  | 'unlinkIdentity'
  | 'updateRecoverySessionStatus'
  | 'validateAppSessionVersion'
  | 'verifyEmailOtpChallenge'
  | 'verifyEmailOtpDeviceRecoveryChallenge'
  | 'verifyEmailOtpEnrollment'
  | 'verifyEmailOtpUnlockProof'
  | 'verifyEcdsaHssRoleLocalClientRootProofForExistingKey'
  | 'verifyGoogleLogin'
  | 'verifyOidcJwtExchange'
  | 'verifyWebAuthnAuthenticationLite'
  | 'verifyWebAuthnLogin'
  | 'verifyWebAuthnSyncAccount';

type CloudflareEmailOtpDeliveryMode =
  | 'email_provider'
  | 'log'
  | 'memory'
  | 'dev_d1_outbox';

type CloudflareEmailOtpDelivery<T> = T extends { mode: unknown }
  ? Omit<T, 'mode'> & { readonly mode: CloudflareEmailOtpDeliveryMode }
  : T;

type CloudflareEmailOtpDeliveryResult<T> = T extends { delivery: infer Delivery }
  ? Omit<T, 'delivery'> & { readonly delivery: CloudflareEmailOtpDelivery<Delivery> }
  : T;

type AuthServiceMethod = (...args: any[]) => unknown;

type AuthServiceMethodKey = {
  [K in keyof AuthService]: AuthService[K] extends AuthServiceMethod ? K : never;
}[keyof AuthService];

type AuthServiceMethodAt<M extends AuthServiceMethodKey> = Extract<
  AuthService[M],
  AuthServiceMethod
>;

type CloudflareEmailOtpMethod<M extends AuthServiceMethodKey> = (
  input: Parameters<AuthServiceMethodAt<M>>[0],
) => Promise<CloudflareEmailOtpDeliveryResult<Awaited<ReturnType<AuthServiceMethodAt<M>>>>>;

export interface CloudflareRouterApiEmailOtpChallengeService {
  createEmailOtpChallenge: CloudflareEmailOtpMethod<'createEmailOtpChallenge'>;
  createEmailOtpDeviceRecoveryChallenge: CloudflareEmailOtpMethod<'createEmailOtpDeviceRecoveryChallenge'>;
  createEmailOtpEnrollmentChallenge: CloudflareEmailOtpMethod<'createEmailOtpEnrollmentChallenge'>;
}

export type CloudflareRouterApiAuthService = Pick<AuthService, CloudflareRouterApiAuthServiceMethod> &
  CloudflareRouterApiEmailOtpChallengeService;
