import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { isValidAccountId, toOptionalTrimmedString } from '@shared/utils/validation';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  addAuthMethodIntentGrantFromString,
  addSignerIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  normalizeAddAuthMethodInput,
  normalizeAddSignerSelection,
  normalizeRegistrationAuthMethodInput,
  normalizeRegistrationSignerSelection,
  registrationIntentGrantFromString,
  requireGeneratedImplicitWalletId,
  walletIdFromString,
  type AddAuthMethodInput,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type AddSignerSelection,
  type GeneratedImplicitWalletId,
  type RegistrationAuthority,
  type RegistrationAuthMethodInput,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
  type RuntimePolicyScopeLike,
  type RegisterWalletInput,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseGoogleProviderSubject,
  parseOrgId,
  parseProviderSubject,
  parseVerifiedGoogleEmail,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveHostedNearAccountId } from '../../core/hostedAccountIds';
import { buildRecoveryExecutionRecord } from '../../core/recoveryExecutionRecords';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentResponse,
  ThresholdStoreConfigInput,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse,
  WalletAddAuthMethodFinalizeResponse,
  WalletAddAuthMethodStartResponse,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerHssRespondResponse,
  WalletAddSignerStartResponse,
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
  WebAuthnAuthenticationCredential,
} from '../../core/types';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../../core/defaultConfigsServer';
import type {
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredWalletAddSignerCeremony,
  StoredWalletAddAuthMethodCeremony,
  StoredRegistrationIntent,
} from '../../core/RegistrationCeremonyStore';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromValue,
  type ThresholdEcdsaChainTarget,
} from '../../core/thresholdEcdsaChainTarget';
import { createCloudflareDurableObjectThresholdSigningService } from '../../core/ThresholdService/createCloudflareDurableObjectThresholdSigningService';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpGrantAction,
  EmailOtpGrantRecord,
  EmailOtpLoginChallengeOperation,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpUnlockChallengeRecord,
  EmailOtpWalletEnrollmentRecord,
  GoogleEmailOtpRegistrationAttemptRecord,
  GoogleEmailOtpRegistrationOfferCandidateRecord,
  NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
  PendingGoogleEmailOtpRegistrationAttemptRecord,
} from '../../core/EmailOtpStores';
import type {
  RecoveryExecutionRecord,
  RecoveryExecutionStatus,
} from '../../core/RecoveryExecutionStore';
import type { RecoverySessionRecord, RecoverySessionStatus } from '../../core/RecoverySessionStore';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../../core/ThresholdService/ethSignerWasm';
import {
  D1WalletAuthMethodStore,
  type WalletAuthMethodRecord,
  type WalletAuthMethodStore,
} from '../../core/d1WalletAuthMethodStore';
import {
  D1WalletStore,
  buildWalletEcdsaSignerRecord,
  type WalletRecord,
  type WalletStore,
} from '../../core/d1WalletStore';
import {
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
} from '../../core/keyMaterialBrands';
import { createSigningSessionSealShamir3PassCipherAdapter } from '../../threshold/session/signingSessionSeal/crypto/cipher';
import type {
  SigningSessionSealCipherAdapter,
} from '../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../storage/tenantRoute';
import type { CloudflareRelayAuthService } from '../authServicePort';
import { createDisabledCloudflareRelayAuthService } from './disabledRelayAuthService';

const DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT = 'cloudflare-disabled-relayer.local';
const DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY = 'disabled-relayer-public-key';
const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;

type SimpleWebAuthnVerifier = (args: unknown) => Promise<unknown>;

type SimpleWebAuthnServerModule = {
  readonly verifyAuthenticationResponse?: SimpleWebAuthnVerifier;
  readonly verifyRegistrationResponse?: SimpleWebAuthnVerifier;
};

export type CloudflareD1EmailOtpDeliveryProviderInput = {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId?: string;
  readonly email: string;
  readonly emailHint: string;
  readonly otpCode: string;
  readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
  readonly action: EmailOtpChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly expiresAtMs: number;
};

export type CloudflareD1EmailOtpDeliveryProviderResult =
  | { readonly ok: true; readonly providerMessageId?: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface CloudflareD1EmailOtpDeliveryProvider {
  deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult>;
}

export type CloudflareD1OidcExchangeIssuerConfig = {
  readonly issuer: string;
  readonly audiences: readonly string[];
  readonly jwksUrl: string;
  readonly subjectPrefix?: string;
};

export type CloudflareD1OidcExchangeConfig = {
  readonly issuers: readonly CloudflareD1OidcExchangeIssuerConfig[];
  readonly clockSkewSec?: number | string;
};

export type CloudflareD1EmailOtpServerSealConfig = {
  readonly keyVersion: string;
  readonly shamirPrimeB64u: string;
  readonly serverEncryptExponentB64u: string;
  readonly serverDecryptExponentB64u: string;
};

export interface CloudflareD1RelayAuthServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly googleOidcClientId?: string;
  readonly oidcExchange?: CloudflareD1OidcExchangeConfig;
  readonly accountIdDerivationSecret?: string;
  readonly emailOtpServerSeal?: CloudflareD1EmailOtpServerSealConfig;
  readonly emailOtpDeliveryMode?: string;
  readonly emailOtpDeliveryProvider?: CloudflareD1EmailOtpDeliveryProvider;
  readonly emailOtpDevOutboxEnabled?: boolean | string;
  readonly emailOtpProduction?: boolean | string;
  readonly emailOtpChallengeTtlMs?: number | string;
  readonly emailOtpGrantTtlMs?: number | string;
  readonly emailOtpMaxAttempts?: number | string;
  readonly emailOtpLockoutTtlMs?: number | string;
  readonly emailOtpCodeLength?: number | string;
  readonly emailOtpMaxActiveChallengesPerContext?: number | string;
  readonly emailOtpChallengeRateLimitMax?: number | string;
  readonly emailOtpChallengeRateLimitWindowMs?: number | string;
  readonly emailOtpVerifyRateLimitMax?: number | string;
  readonly emailOtpVerifyRateLimitWindowMs?: number | string;
  readonly emailOtpGrantRateLimitMax?: number | string;
  readonly emailOtpGrantRateLimitWindowMs?: number | string;
  readonly emailOtpRecoveryKeyAttemptRateLimitMax?: number | string;
  readonly emailOtpRecoveryKeyAttemptRateLimitWindowMs?: number | string;
  readonly emailOtpGoogleRegistrationAttemptRateLimitMax?: number | string;
  readonly emailOtpGoogleRegistrationAttemptRateLimitWindowMs?: number | string;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly thresholdSigningService?: ThresholdSigningService | null;
}

type EmailOtpDeliveryMode = 'email_provider' | 'log' | 'memory';

type EmailOtpRuntimeConfig = {
  readonly deliveryMode: EmailOtpDeliveryMode;
  readonly deliveryProvider?: CloudflareD1EmailOtpDeliveryProvider;
  readonly devOutboxEnabled: boolean;
  readonly production: boolean;
  readonly challengeTtlMs: number;
  readonly grantTtlMs: number;
  readonly maxAttempts: number;
  readonly lockoutTtlMs: number;
  readonly codeLength: number;
  readonly maxActiveChallengesPerContext: number;
  readonly rateLimits: {
    readonly challenge: EmailOtpRateLimitPolicy;
    readonly verify: EmailOtpRateLimitPolicy;
    readonly grant: EmailOtpRateLimitPolicy;
    readonly recoveryKeyAttempt: EmailOtpRateLimitPolicy;
    readonly googleRegistrationAttempt: EmailOtpRateLimitPolicy;
  };
};

type EmailOtpRateLimitPolicy = {
  readonly limit: number;
  readonly windowMs: number;
};

type EmailOtpServerSealRuntimeConfig =
  | {
      readonly configured: true;
      readonly keyVersion: string;
      readonly shamirPrimeB64u: string;
      readonly serverEncryptExponentB64u: string;
      readonly serverDecryptExponentB64u: string;
    }
  | {
      readonly configured: false;
      readonly message: string;
    };

type NormalizedCloudflareD1RelayAuthServiceOptions = Omit<
  CloudflareD1RelayAuthServiceOptions,
  | 'relayerAccount'
  | 'relayerPublicKey'
  | 'googleOidcClientId'
  | 'oidcExchange'
  | 'accountIdDerivationSecret'
  | 'emailOtpServerSeal'
  | 'emailOtpDeliveryMode'
  | 'emailOtpDeliveryProvider'
  | 'emailOtpDevOutboxEnabled'
  | 'emailOtpProduction'
  | 'emailOtpChallengeTtlMs'
  | 'emailOtpGrantTtlMs'
  | 'emailOtpMaxAttempts'
  | 'emailOtpLockoutTtlMs'
  | 'emailOtpCodeLength'
  | 'emailOtpMaxActiveChallengesPerContext'
  | 'emailOtpChallengeRateLimitMax'
  | 'emailOtpChallengeRateLimitWindowMs'
  | 'emailOtpVerifyRateLimitMax'
  | 'emailOtpVerifyRateLimitWindowMs'
  | 'emailOtpGrantRateLimitMax'
  | 'emailOtpGrantRateLimitWindowMs'
  | 'emailOtpRecoveryKeyAttemptRateLimitMax'
  | 'emailOtpRecoveryKeyAttemptRateLimitWindowMs'
  | 'emailOtpGoogleRegistrationAttemptRateLimitMax'
  | 'emailOtpGoogleRegistrationAttemptRateLimitWindowMs'
  | 'thresholdStore'
  | 'thresholdSigningService'
> & {
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly googleOidcClientId?: string;
  readonly oidcExchange?: {
    readonly issuers: readonly CloudflareD1OidcExchangeIssuerConfig[];
    readonly clockSkewSec: number;
  };
  readonly accountIdDerivationSecret?: string;
  readonly emailOtp: EmailOtpRuntimeConfig;
  readonly emailOtpServerSeal: EmailOtpServerSealRuntimeConfig;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly thresholdSigningService?: ThresholdSigningService | null;
};

type RegistrationIntentWalletResolution =
  | {
      readonly ok: true;
      readonly walletId: WalletId;
      readonly code?: never;
      readonly message?: never;
    }
  | {
      readonly ok: false;
      readonly code: 'invalid_body' | 'wallet_id_collision' | 'configuration';
      readonly message: string;
      readonly walletId?: never;
    };

type CloudflareDoResponse<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code?: string; readonly message?: string };

type CloudflareDoSetRequest = {
  readonly op: 'set';
  readonly key: string;
  readonly value: unknown;
  readonly ttlMs?: number;
};

type CloudflareDoReserveReplayGuardRequest = {
  readonly op: 'authReserveReplayGuard';
  readonly key: string;
  readonly expiresAtMs: number;
};

type CloudflareDoGetRequest = {
  readonly op: 'get';
  readonly key: string;
};

type CloudflareDoGetDelRequest = {
  readonly op: 'getdel';
  readonly key: string;
};

type CloudflareRegistrationIntentDoRequest =
  | CloudflareDoSetRequest
  | CloudflareDoReserveReplayGuardRequest
  | CloudflareDoGetRequest
  | CloudflareDoGetDelRequest;

type RegistrationCeremonyIntentScope =
  | 'intent'
  | 'add-auth-method-intent'
  | 'add-signer-intent'
  | 'add-auth-method'
  | 'add-signer'
  | 'generated-wallet-reservation';

type RegistrationIntentDoPutInput =
  | StoredRegistrationIntent
  | StoredAddSignerIntent
  | StoredWalletAddSignerCeremony
  | StoredAddAuthMethodIntent
  | StoredWalletAddAuthMethodCeremony;

type RegistrationCeremonyDoConfig = {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  readonly objectName: string;
  readonly prefix: string;
};

type ListIdentitiesInput = Parameters<CloudflareRelayAuthService['listIdentities']>[0];
type ListIdentitiesResult = Awaited<ReturnType<CloudflareRelayAuthService['listIdentities']>>;
type CreateRegistrationIntentInput = Parameters<
  CloudflareRelayAuthService['createRegistrationIntent']
>[0];
type CreateAddSignerIntentInput = Parameters<
  CloudflareRelayAuthService['createAddSignerIntent']
>[0];
type StartWalletAddSignerInput = Parameters<
  CloudflareRelayAuthService['startWalletAddSigner']
>[0];
type RespondWalletAddSignerHssInput = Parameters<
  CloudflareRelayAuthService['respondWalletAddSignerHss']
>[0];
type D1EcdsaPublicIdentity = EcdsaHssServerBootstrapResponse['publicIdentity'];
type D1EcdsaClientSharePublicKey = D1EcdsaPublicIdentity['hssClientSharePublicKey33B64u'];
type D1EcdsaRelayerPublicKey = D1EcdsaPublicIdentity['relayerPublicKey33B64u'];
type FinalizeWalletAddSignerInput = Parameters<
  CloudflareRelayAuthService['finalizeWalletAddSigner']
>[0];
type CreateAddAuthMethodIntentInput = Parameters<
  CloudflareRelayAuthService['createAddAuthMethodIntent']
>[0];
type StartWalletAddAuthMethodInput = Parameters<
  CloudflareRelayAuthService['startWalletAddAuthMethod']
>[0];
type FinalizeWalletAddAuthMethodInput = Parameters<
  CloudflareRelayAuthService['finalizeWalletAddAuthMethod']
>[0];
type LinkIdentityInput = Parameters<CloudflareRelayAuthService['linkIdentity']>[0];
type LinkIdentityResult = Awaited<ReturnType<CloudflareRelayAuthService['linkIdentity']>>;
type UnlinkIdentityInput = Parameters<CloudflareRelayAuthService['unlinkIdentity']>[0];
type UnlinkIdentityResult = Awaited<ReturnType<CloudflareRelayAuthService['unlinkIdentity']>>;
type ResolveOidcWalletIdInput = Parameters<CloudflareRelayAuthService['resolveOidcWalletId']>[0];
type ResolveOidcWalletIdResult = Awaited<
  ReturnType<CloudflareRelayAuthService['resolveOidcWalletId']>
>;
type ReadEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['readEmailOtpEnrollment']
>[0];
type ReadEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readEmailOtpEnrollment']>
>;
type ReadActiveEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['readActiveEmailOtpEnrollment']
>[0];
type ReadActiveEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readActiveEmailOtpEnrollment']>
>;
type IsEmailOtpStrongAuthRequiredInput = Parameters<
  CloudflareRelayAuthService['isEmailOtpStrongAuthRequired']
>[0];
type IsEmailOtpStrongAuthRequiredResult = Awaited<
  ReturnType<CloudflareRelayAuthService['isEmailOtpStrongAuthRequired']>
>;
type MarkEmailOtpStrongAuthSatisfiedInput = Parameters<
  CloudflareRelayAuthService['markEmailOtpStrongAuthSatisfied']
>[0];
type MarkEmailOtpStrongAuthSatisfiedResult = Awaited<
  ReturnType<CloudflareRelayAuthService['markEmailOtpStrongAuthSatisfied']>
>;
type GetEmailOtpRecoveryCodeStatusInput = Parameters<
  CloudflareRelayAuthService['getEmailOtpRecoveryCodeStatus']
>[0];
type GetEmailOtpRecoveryCodeStatusResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getEmailOtpRecoveryCodeStatus']>
>;
type ConsumeEmailOtpGrantInput = Parameters<CloudflareRelayAuthService['consumeEmailOtpGrant']>[0];
type ConsumeEmailOtpGrantResult = Awaited<
  ReturnType<CloudflareRelayAuthService['consumeEmailOtpGrant']>
>;
type ConsumeEmailOtpRecoveryKeyInput = Parameters<
  CloudflareRelayAuthService['consumeEmailOtpRecoveryKey']
>[0];
type ConsumeEmailOtpRecoveryKeyResult = Awaited<
  ReturnType<CloudflareRelayAuthService['consumeEmailOtpRecoveryKey']>
>;
type RecordEmailOtpRecoveryKeyAttemptFailureInput = Parameters<
  CloudflareRelayAuthService['recordEmailOtpRecoveryKeyAttemptFailure']
>[0];
type RecordEmailOtpRecoveryKeyAttemptFailureResult = Awaited<
  ReturnType<CloudflareRelayAuthService['recordEmailOtpRecoveryKeyAttemptFailure']>
>;
type RotateEmailOtpRecoveryKeysInput = Parameters<
  CloudflareRelayAuthService['rotateEmailOtpRecoveryKeys']
>[0];
type RotateEmailOtpRecoveryKeysResult = Awaited<
  ReturnType<CloudflareRelayAuthService['rotateEmailOtpRecoveryKeys']>
>;
type CreateEmailOtpChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpChallenge']
>[0];
type CreateEmailOtpChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpChallenge']>
>;
type CreateEmailOtpEnrollmentChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpEnrollmentChallenge']
>[0];
type CreateEmailOtpEnrollmentChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpEnrollmentChallenge']>
>;
type VerifyEmailOtpChallengeInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpChallenge']
>[0];
type VerifyEmailOtpChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpChallenge']>
>;
type CreateEmailOtpDeviceRecoveryChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpDeviceRecoveryChallenge']
>[0];
type CreateEmailOtpDeviceRecoveryChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpDeviceRecoveryChallenge']>
>;
type VerifyEmailOtpDeviceRecoveryChallengeInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpDeviceRecoveryChallenge']
>[0];
type VerifyEmailOtpDeviceRecoveryChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpDeviceRecoveryChallenge']>
>;
type VerifyEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpEnrollment']
>[0];
type VerifyEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpEnrollment']>
>;
type ReadEmailOtpOutboxEntryInput = Parameters<
  CloudflareRelayAuthService['readEmailOtpOutboxEntry']
>[0];
type ReadEmailOtpOutboxEntryResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readEmailOtpOutboxEntry']>
>;
type CreateEmailOtpUnlockChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpUnlockChallenge']
>[0];
type CreateEmailOtpUnlockChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpUnlockChallenge']>
>;
type VerifyEmailOtpUnlockProofInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpUnlockProof']
>[0];
type VerifyEmailOtpUnlockProofResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpUnlockProof']>
>;
type RevokeWalletAuthMethodInput = Parameters<
  CloudflareRelayAuthService['revokeWalletAuthMethod']
>[0];
type RevokeWalletAuthMethodResult = Awaited<
  ReturnType<CloudflareRelayAuthService['revokeWalletAuthMethod']>
>;
type ApplyEmailOtpServerSealInput = Parameters<
  CloudflareRelayAuthService['applyEmailOtpServerSeal']
>[0];
type ApplyEmailOtpServerSealResult = Awaited<
  ReturnType<CloudflareRelayAuthService['applyEmailOtpServerSeal']>
>;
type RemoveEmailOtpServerSealInput = Parameters<
  CloudflareRelayAuthService['removeEmailOtpServerSeal']
>[0];
type RemoveEmailOtpServerSealResult = Awaited<
  ReturnType<CloudflareRelayAuthService['removeEmailOtpServerSeal']>
>;
type GetOrCreateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['getOrCreateAppSessionVersion']
>[0];
type GetOrCreateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getOrCreateAppSessionVersion']>
>;
type GetRecoverySessionInput = Parameters<CloudflareRelayAuthService['getRecoverySession']>[0];
type GetRecoverySessionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getRecoverySession']>
>;
type UpdateRecoverySessionStatusInput = Parameters<
  CloudflareRelayAuthService['updateRecoverySessionStatus']
>[0];
type UpdateRecoverySessionStatusResult = Awaited<
  ReturnType<CloudflareRelayAuthService['updateRecoverySessionStatus']>
>;
type RecordRecoveryExecutionInput = Parameters<
  CloudflareRelayAuthService['recordRecoveryExecution']
>[0];
type RecordRecoveryExecutionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['recordRecoveryExecution']>
>;
type RotateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['rotateAppSessionVersion']
>[0];
type RotateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['rotateAppSessionVersion']>
>;
type ValidateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['validateAppSessionVersion']
>[0];
type ValidateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['validateAppSessionVersion']>
>;
type ListWebAuthnAuthenticatorsInput = Parameters<
  CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']
>[0];
type ListWebAuthnAuthenticatorsResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']>
>;
type CreateWebAuthnLoginOptionsInput = Parameters<
  CloudflareRelayAuthService['createWebAuthnLoginOptions']
>[0];
type CreateWebAuthnLoginOptionsResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createWebAuthnLoginOptions']>
>;
type CreateWebAuthnSyncAccountOptionsInput = Parameters<
  CloudflareRelayAuthService['createWebAuthnSyncAccountOptions']
>[0];
type CreateWebAuthnSyncAccountOptionsResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createWebAuthnSyncAccountOptions']>
>;
type VerifyWebAuthnAuthenticationLiteInput = Parameters<
  CloudflareRelayAuthService['verifyWebAuthnAuthenticationLite']
>[0];
type VerifyWebAuthnAuthenticationLiteResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyWebAuthnAuthenticationLite']>
>;
type VerifyWebAuthnLoginInput = Parameters<CloudflareRelayAuthService['verifyWebAuthnLogin']>[0];
type VerifyWebAuthnLoginResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyWebAuthnLogin']>
>;
type VerifyWebAuthnSyncAccountInput = Parameters<
  CloudflareRelayAuthService['verifyWebAuthnSyncAccount']
>[0];
type VerifyWebAuthnSyncAccountResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyWebAuthnSyncAccount']>
>;
type ListNearPublicKeysInput = Parameters<
  CloudflareRelayAuthService['listNearPublicKeysForUser']
>[0];
type ListNearPublicKeysResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listNearPublicKeysForUser']>
>;
type ListThresholdEcdsaKeyIdentityTargetsForUserInput = Parameters<
  CloudflareRelayAuthService['listThresholdEcdsaKeyIdentityTargetsForUser']
>[0];
type ListThresholdEcdsaKeyIdentityTargetsForUserResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listThresholdEcdsaKeyIdentityTargetsForUser']>
>;
type ListWalletEcdsaKeyFactsInventoryInput = Parameters<
  CloudflareRelayAuthService['listWalletEcdsaKeyFactsInventory']
>[0];
type ListWalletEcdsaKeyFactsInventoryResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listWalletEcdsaKeyFactsInventory']>
>;
type EcdsaHssRoleLocalBootstrapInput = Parameters<
  CloudflareRelayAuthService['ecdsaHssRoleLocalBootstrap']
>[0];
type EcdsaHssRoleLocalBootstrapResult = Awaited<
  ReturnType<CloudflareRelayAuthService['ecdsaHssRoleLocalBootstrap']>
>;
type VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyInput = Parameters<
  CloudflareRelayAuthService['verifyEcdsaHssRoleLocalClientRootProofForExistingKey']
>[0];
type VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEcdsaHssRoleLocalClientRootProofForExistingKey']>
>;
type EcdsaHssRoleLocalExportShareInput = Parameters<
  CloudflareRelayAuthService['ecdsaHssRoleLocalExportShare']
>[0];
type EcdsaHssRoleLocalExportShareResult = Awaited<
  ReturnType<CloudflareRelayAuthService['ecdsaHssRoleLocalExportShare']>
>;
type ConsumeGoogleEmailOtpRegistrationAttemptRateLimitInput = Parameters<
  CloudflareRelayAuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit']
>[0];
type ConsumeGoogleEmailOtpRegistrationAttemptRateLimitResult = Awaited<
  ReturnType<CloudflareRelayAuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit']>
>;
type ResolveGoogleEmailOtpSessionInput = Parameters<
  CloudflareRelayAuthService['resolveGoogleEmailOtpSession']
>[0];
type ResolveGoogleEmailOtpSessionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['resolveGoogleEmailOtpSession']>
>;
type CleanupGoogleEmailOtpDevRegistrationStateInput = Parameters<
  CloudflareRelayAuthService['cleanupGoogleEmailOtpDevRegistrationState']
>[0];
type CleanupGoogleEmailOtpDevRegistrationStateResult = Awaited<
  ReturnType<CloudflareRelayAuthService['cleanupGoogleEmailOtpDevRegistrationState']>
>;
type VerifyGoogleLoginInput = Parameters<CloudflareRelayAuthService['verifyGoogleLogin']>[0];
type VerifyGoogleLoginResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyGoogleLogin']>
>;
type VerifyOidcJwtExchangeInput = Parameters<
  CloudflareRelayAuthService['verifyOidcJwtExchange']
>[0];
type VerifyOidcJwtExchangeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyOidcJwtExchange']>
>;
type VerifyGoogleLoginFailure = {
  readonly ok: false;
  readonly verified: false;
  readonly code: string;
  readonly message: string;
};
type GoogleEmailOtpRegistrationOfferForResponse = Extract<
  ResolveGoogleEmailOtpSessionResult,
  { readonly ok: true; readonly mode: 'register_started' }
>['offer'];

type D1IdentityRow = {
  readonly subject?: unknown;
  readonly user_id?: unknown;
  readonly created_at_ms?: unknown;
  readonly subject_count?: unknown;
};

type D1SessionRow = {
  readonly session_version?: unknown;
  readonly record_json?: unknown;
};

type D1EmailOtpEnrollmentRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpAuthStateRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpChallengeRow = {
  readonly challenge_id?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

type D1EmailOtpRecoveryEscrowRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpGrantRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

type D1EmailOtpRateLimitRow = {
  readonly consumed_count?: unknown;
  readonly reset_at_ms?: unknown;
};

type D1EmailOtpUnlockChallengeRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

type D1EmailOtpRegistrationAttemptRow = {
  readonly attempt_id?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1RecoverySessionRow = {
  readonly record_json?: unknown;
};

type D1RecoveryExecutionRow = {
  readonly record_json?: unknown;
};

type D1AuthenticatorRow = {
  readonly credential_id_b64u?: unknown;
  readonly credential_public_key_b64u?: unknown;
  readonly counter?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1RecordJsonRow = {
  readonly record_json?: unknown;
};

type JsonWebKeyCache = {
  readonly keysByKid: Map<string, JsonWebKey>;
  readonly expiresAtMs: number;
};

type JwtVerificationFailure = {
  readonly ok: false;
  readonly verified: false;
  readonly code: string;
  readonly message: string;
};

type ParsedRs256Jwt = {
  readonly headerB64u: string;
  readonly payloadB64u: string;
  readonly signatureB64u: string;
  readonly payload: Record<string, unknown>;
  readonly kid: string;
};

type ParsedRs256JwtResult =
  | { readonly ok: true; readonly jwt: ParsedRs256Jwt }
  | JwtVerificationFailure;

type EmailOtpServerSealCipherResult =
  | {
      readonly ok: true;
      readonly keyVersion: string;
      readonly cipher: SigningSessionSealCipherAdapter;
    }
  | {
      readonly ok: false;
      readonly code: 'not_configured';
      readonly message: string;
    };

type D1RevokeWalletAuthMethodTarget =
  | {
      readonly kind: 'passkey';
      readonly credentialIdB64u: string;
    }
  | {
      readonly kind: 'email_otp';
      readonly email: string;
    };

type D1RevokeWalletAuthMethodAuth =
  | {
      readonly kind: 'webauthn_assertion';
      readonly credential: unknown;
    }
  | {
      readonly kind: 'app_session';
      readonly policy: {
        readonly permission: 'wallet_auth_method_revoke';
        readonly walletId: WalletId;
        readonly target: D1RevokeWalletAuthMethodTarget;
        readonly expiresAtMs: number;
      };
    };

type D1RevokeWalletAuthMethodBoundary =
  | {
      readonly ok: true;
      readonly walletId: WalletId;
      readonly rpId: string;
      readonly target: D1RevokeWalletAuthMethodTarget;
      readonly auth: D1RevokeWalletAuthMethodAuth;
    }
  | {
      readonly ok: false;
      readonly result: RevokeWalletAuthMethodResult;
    };

type AppSessionVersionRecord = {
  readonly version: 'app_session_version_v1';
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type IdentitySubjectRecord = {
  readonly version: 'identity_subject_v1';
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type WebAuthnCredentialBindingRecord = {
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly userId: string;
  readonly nearAccountId?: string;
  readonly nearEd25519SigningKeyId?: string;
  readonly signerSlot: number;
  readonly publicKey?: string;
  readonly relayerKeyId?: string;
  readonly keyVersion?: string;
  readonly recoveryExportCapable?: boolean;
  readonly clientParticipantId?: number;
  readonly relayerParticipantId?: number;
  readonly participantIds?: number[];
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

type WebAuthnAuthenticatorRecord = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type WebAuthnSyncWalletBinding = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly rpId: string;
  readonly signerSlot: number;
};

type WebAuthnLoginChallengeRecord = {
  readonly version: 'webauthn_login_challenge_v1';
  readonly challengeId: string;
  readonly userId: string;
  readonly rpId: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

type WebAuthnSyncChallengeRecord = {
  readonly version: 'webauthn_sync_challenge_v1';
  readonly challengeId: string;
  readonly rpId: string;
  readonly expectedUserId?: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

type WebAuthnChallengeKind = 'login' | 'sync';

type NearPublicKeyRecord = {
  readonly publicKey: string;
  readonly kind: 'threshold' | 'local' | 'backup' | 'ephemeral';
  readonly signerSlot?: number;
  readonly credentialIdB64u?: string;
  readonly rpId?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

type EmailOtpOutboxEntry = {
  readonly walletId: string;
  readonly userId: string;
  readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
  readonly emailHint: string;
  readonly otpCode: string;
  readonly expiresAtMs: number;
};

type EmailOtpAuthStatePatch = {
  readonly otpFailureCount?: number | null;
  readonly lastOtpFailureAtMs?: number | null;
  readonly otpLockedUntilMs?: number | null;
  readonly lastEmailOtpLoginAtMs?: number | null;
  readonly lastStrongAuthAtMs?: number | null;
};

type EmailOtpRateLimitScope =
  | 'challenge'
  | 'verify'
  | 'grant'
  | 'recoveryKeyAttempt'
  | 'googleRegistrationAttempt';
type EmailOtpChallengeIssueAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.login
  | typeof WALLET_EMAIL_OTP_ACTIONS.registration
  | typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;

type EmailOtpRecoveryChallengeEscrow = Omit<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  | 'recoveryKeyId'
  | 'recoveryKeyStatus'
  | 'issuedAtMs'
  | 'updatedAtMs'
  | 'consumedAtMs'
  | 'revokedAtMs'
>;

type EmailOtpChallengeIssueBaseInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly email?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
  readonly reuseActiveChallenge?: unknown;
};

type EmailOtpChallengeIssueInput =
  | (EmailOtpChallengeIssueBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      readonly operation: EmailOtpLoginChallengeOperation;
    })
  | (EmailOtpChallengeIssueBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
      readonly operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    })
  | (EmailOtpChallengeIssueBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
      readonly operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    });

type EmailOtpChallengeIssueResult =
  | {
      ok: true;
      challenge: {
        readonly challengeId: string;
        readonly issuedAtMs: number;
        readonly expiresAtMs: number;
        readonly challengeSubjectId: string;
        readonly walletId: string;
        readonly orgId: string;
        readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
        readonly sessionHash: string;
        readonly appSessionVersion: string;
        readonly action: EmailOtpChallengeIssueAction;
        readonly operation: EmailOtpChallengeOperation;
      };
      delivery: {
        readonly status: 'sent' | 'reused';
        readonly mode: EmailOtpDeliveryMode;
        readonly emailHint: string;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

type EmailOtpExistingChallengeVerifyBaseInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
};

type EmailOtpExistingChallengeVerifyInput =
  | (EmailOtpExistingChallengeVerifyBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      readonly operation: EmailOtpLoginChallengeOperation;
    })
  | (EmailOtpExistingChallengeVerifyBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
      readonly operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    });

type EmailOtpExistingChallengeVerifyResult =
  | {
      ok: true;
      readonly challengeId: string;
      readonly userId: string;
      readonly walletId: string;
      readonly orgId: string;
      readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
      readonly sessionHash: string;
      readonly appSessionVersion: string;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

type EmailOtpRegistrationChallengeVerifyInput = {
  readonly providerSubject?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly proofEmail?: unknown;
  readonly clientIp?: unknown;
};

type EmailOtpRegistrationChallengeVerifyResult =
  | {
      ok: true;
      readonly challengeId: string;
      readonly challengeSubjectId: string;
      readonly walletId: string;
      readonly orgId: string;
      readonly email: string;
      readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

type EmailOtpEnrollmentMaterialValidationResult =
  | {
      ok: true;
      readonly recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      readonly enrollmentSealKeyVersion: string;
      readonly clientUnlockPublicKeyB64u: string;
      readonly unlockKeyVersion: string;
      readonly thresholdEcdsaClientVerifyingShareB64u: string;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

type EmailOtpRecoveryEnrollmentEscrowBoundary = {
  readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly binding: ReturnType<typeof buildEmailOtpRecoveryWrapBinding>;
};

function requireD1RelayAuthScopeString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for Cloudflare D1 relay auth service`);
  return value;
}

function parseBooleanFlag(input: unknown, fallback: boolean, field: string): boolean {
  if (input == null || input === '') return fallback;
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  switch (value) {
    case '1':
    case 'true':
    case 'yes':
    case 'on':
      return true;
    case '0':
    case 'false':
    case 'no':
    case 'off':
      return false;
    default:
      throw new Error(`${field} must be a boolean flag`);
  }
}

function isTrueFlag(input: unknown): boolean {
  return input === true || String(input || '').trim().toLowerCase() === 'true';
}

function configuredInteger(input: {
  readonly field: string;
  readonly raw: unknown;
  readonly fallback: number;
  readonly min: number;
  readonly max: number;
}): number {
  if (input.raw == null || input.raw === '') return input.fallback;
  const value = typeof input.raw === 'number' ? input.raw : Number(input.raw);
  if (!Number.isFinite(value)) throw new Error(`${input.field} must be a finite number`);
  if (value < input.min || value > input.max) {
    throw new Error(`${input.field} must be between ${input.min} and ${input.max}`);
  }
  return Math.floor(value);
}

function normalizeEmailOtpDeliveryMode(input: unknown): EmailOtpDeliveryMode {
  const value = toOptionalTrimmedString(input)?.toLowerCase() || 'email_provider';
  switch (value) {
    case 'email_provider':
    case 'log':
    case 'memory':
      return value;
    default:
      throw new Error('emailOtpDeliveryMode must be one of email_provider, log, or memory');
  }
}

function emailOtpRateLimitPolicy(input: {
  readonly limitField: string;
  readonly limitRaw: unknown;
  readonly limitFallback: number;
  readonly limitMax: number;
  readonly windowField: string;
  readonly windowRaw: unknown;
  readonly windowFallback: number;
}): EmailOtpRateLimitPolicy {
  return {
    limit: configuredInteger({
      field: input.limitField,
      raw: input.limitRaw,
      fallback: input.limitFallback,
      min: 1,
      max: input.limitMax,
    }),
    windowMs: configuredInteger({
      field: input.windowField,
      raw: input.windowRaw,
      fallback: input.windowFallback,
      min: 1_000,
      max: 24 * 60 * 60_000,
    }),
  };
}

function normalizeEmailOtpConfig(
  input: CloudflareD1RelayAuthServiceOptions,
): EmailOtpRuntimeConfig {
  const production = parseBooleanFlag(input.emailOtpProduction, false, 'emailOtpProduction');
  const deliveryMode = normalizeEmailOtpDeliveryMode(input.emailOtpDeliveryMode);
  const challengeDefault = production
    ? { limit: 5, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const verifyDefault = production
    ? { limit: 10, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const grantDefault = production
    ? { limit: 8, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const recoveryKeyAttemptDefault = production
    ? { limit: 10, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const googleRegistrationAttemptDefault = production
    ? { limit: 12, windowMs: 10 * 60_000 }
    : { limit: 200, windowMs: 60_000 };
  return {
    deliveryMode,
    ...(input.emailOtpDeliveryProvider
      ? { deliveryProvider: input.emailOtpDeliveryProvider }
      : {}),
    production,
    devOutboxEnabled:
      deliveryMode === 'memory' &&
      !production &&
      parseBooleanFlag(input.emailOtpDevOutboxEnabled, true, 'emailOtpDevOutboxEnabled'),
    challengeTtlMs: configuredInteger({
      field: 'emailOtpChallengeTtlMs',
      raw: input.emailOtpChallengeTtlMs,
      fallback: 5 * 60_000,
      min: 30_000,
      max: 15 * 60_000,
    }),
    grantTtlMs: configuredInteger({
      field: 'emailOtpGrantTtlMs',
      raw: input.emailOtpGrantTtlMs,
      fallback: 30_000,
      min: 10_000,
      max: 5 * 60_000,
    }),
    maxAttempts: configuredInteger({
      field: 'emailOtpMaxAttempts',
      raw: input.emailOtpMaxAttempts,
      fallback: 5,
      min: 1,
      max: 10,
    }),
    lockoutTtlMs: configuredInteger({
      field: 'emailOtpLockoutTtlMs',
      raw: input.emailOtpLockoutTtlMs,
      fallback: 15 * 60_000,
      min: 60_000,
      max: 24 * 60 * 60_000,
    }),
    codeLength: configuredInteger({
      field: 'emailOtpCodeLength',
      raw: input.emailOtpCodeLength,
      fallback: 6,
      min: 6,
      max: 8,
    }),
    maxActiveChallengesPerContext: configuredInteger({
      field: 'emailOtpMaxActiveChallengesPerContext',
      raw: input.emailOtpMaxActiveChallengesPerContext,
      fallback: 5,
      min: 1,
      max: 20,
    }),
    rateLimits: {
      challenge: emailOtpRateLimitPolicy({
        limitField: 'emailOtpChallengeRateLimitMax',
        limitRaw: input.emailOtpChallengeRateLimitMax,
        limitFallback: challengeDefault.limit,
        limitMax: 500,
        windowField: 'emailOtpChallengeRateLimitWindowMs',
        windowRaw: input.emailOtpChallengeRateLimitWindowMs,
        windowFallback: challengeDefault.windowMs,
      }),
      verify: emailOtpRateLimitPolicy({
        limitField: 'emailOtpVerifyRateLimitMax',
        limitRaw: input.emailOtpVerifyRateLimitMax,
        limitFallback: verifyDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpVerifyRateLimitWindowMs',
        windowRaw: input.emailOtpVerifyRateLimitWindowMs,
        windowFallback: verifyDefault.windowMs,
      }),
      grant: emailOtpRateLimitPolicy({
        limitField: 'emailOtpGrantRateLimitMax',
        limitRaw: input.emailOtpGrantRateLimitMax,
        limitFallback: grantDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpGrantRateLimitWindowMs',
        windowRaw: input.emailOtpGrantRateLimitWindowMs,
        windowFallback: grantDefault.windowMs,
      }),
      recoveryKeyAttempt: emailOtpRateLimitPolicy({
        limitField: 'emailOtpRecoveryKeyAttemptRateLimitMax',
        limitRaw: input.emailOtpRecoveryKeyAttemptRateLimitMax,
        limitFallback: recoveryKeyAttemptDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpRecoveryKeyAttemptRateLimitWindowMs',
        windowRaw: input.emailOtpRecoveryKeyAttemptRateLimitWindowMs,
        windowFallback: recoveryKeyAttemptDefault.windowMs,
      }),
      googleRegistrationAttempt: emailOtpRateLimitPolicy({
        limitField: 'emailOtpGoogleRegistrationAttemptRateLimitMax',
        limitRaw: input.emailOtpGoogleRegistrationAttemptRateLimitMax,
        limitFallback: googleRegistrationAttemptDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpGoogleRegistrationAttemptRateLimitWindowMs',
        windowRaw: input.emailOtpGoogleRegistrationAttemptRateLimitWindowMs,
        windowFallback: googleRegistrationAttemptDefault.windowMs,
      }),
    },
  };
}

function normalizedOidcIssuer(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function normalizeOidcExchangeAudiences(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const audiences: string[] = [];
  for (const item of input) {
    const value = toOptionalTrimmedString(item);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    audiences.push(value);
  }
  return audiences;
}

function normalizeOidcExchangeIssuerConfig(
  input: unknown,
): CloudflareD1OidcExchangeIssuerConfig | null {
  if (!isRecord(input)) return null;
  const issuer = normalizedOidcIssuer(input.issuer);
  const jwksUrl = toOptionalTrimmedString(input.jwksUrl);
  const audiences = normalizeOidcExchangeAudiences(input.audiences);
  const subjectPrefix = toOptionalTrimmedString(input.subjectPrefix);
  if (!issuer || !jwksUrl || audiences.length === 0) return null;
  return {
    issuer,
    jwksUrl,
    audiences,
    ...(subjectPrefix ? { subjectPrefix } : {}),
  };
}

function normalizeOidcExchangeClockSkewSec(input: unknown): number {
  if (input == null || input === '') return 60;
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value)) return 60;
  return Math.max(0, Math.floor(value));
}

function normalizeOidcExchangeConfig(
  input: CloudflareD1RelayAuthServiceOptions,
): NormalizedCloudflareD1RelayAuthServiceOptions['oidcExchange'] {
  const raw = input.oidcExchange;
  if (!raw || !Array.isArray(raw.issuers)) return undefined;
  const issuers: CloudflareD1OidcExchangeIssuerConfig[] = [];
  for (const issuer of raw.issuers) {
    const normalized = normalizeOidcExchangeIssuerConfig(issuer);
    if (normalized) issuers.push(normalized);
  }
  if (issuers.length === 0) return undefined;
  return {
    issuers,
    clockSkewSec: normalizeOidcExchangeClockSkewSec(raw.clockSkewSec),
  };
}

function missingEmailOtpServerSealConfig(): EmailOtpServerSealRuntimeConfig {
  return {
    configured: false,
    message:
      'Email OTP server seal requires emailOtpServerSeal.keyVersion, emailOtpServerSeal.shamirPrimeB64u, emailOtpServerSeal.serverEncryptExponentB64u, and emailOtpServerSeal.serverDecryptExponentB64u',
  };
}

function normalizeEmailOtpServerSealConfig(
  input: CloudflareD1RelayAuthServiceOptions,
): EmailOtpServerSealRuntimeConfig {
  const raw = input.emailOtpServerSeal;
  if (!raw) return missingEmailOtpServerSealConfig();
  const keyVersionRaw = toOptionalTrimmedString(raw.keyVersion);
  const shamirPrimeRaw = toOptionalTrimmedString(raw.shamirPrimeB64u);
  const serverEncryptExponentB64u = toOptionalTrimmedString(raw.serverEncryptExponentB64u);
  const serverDecryptExponentB64u = toOptionalTrimmedString(raw.serverDecryptExponentB64u);
  if (
    !keyVersionRaw ||
    !shamirPrimeRaw ||
    !serverEncryptExponentB64u ||
    !serverDecryptExponentB64u
  ) {
    return missingEmailOtpServerSealConfig();
  }
  try {
    const keyVersion = formatSigningSessionSealKeyVersionForWire(
      parseSigningSessionSealKeyVersion(keyVersionRaw),
    );
    const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(
      parseSigningSessionSealShamirPrimeB64u(shamirPrimeRaw),
    );
    return {
      configured: true,
      keyVersion,
      shamirPrimeB64u,
      serverEncryptExponentB64u,
      serverDecryptExponentB64u,
    };
  } catch (error: unknown) {
    return {
      configured: false,
      message: errorMessage(error) || 'Email OTP Shamir configuration is invalid',
    };
  }
}

function normalizeD1RelayAuthOptions(
  input: CloudflareD1RelayAuthServiceOptions,
): NormalizedCloudflareD1RelayAuthServiceOptions {
  return {
    database: input.database,
    namespace: requireD1RelayAuthScopeString(input.namespace, 'namespace'),
    orgId: requireD1RelayAuthScopeString(input.orgId, 'orgId'),
    projectId: requireD1RelayAuthScopeString(input.projectId, 'projectId'),
    envId: requireD1RelayAuthScopeString(input.envId, 'envId'),
    relayerAccount: toOptionalTrimmedString(input.relayerAccount),
    relayerPublicKey: toOptionalTrimmedString(input.relayerPublicKey),
    googleOidcClientId: toOptionalTrimmedString(input.googleOidcClientId),
    oidcExchange: normalizeOidcExchangeConfig(input),
    accountIdDerivationSecret: toOptionalTrimmedString(input.accountIdDerivationSecret),
    emailOtp: normalizeEmailOtpConfig(input),
    emailOtpServerSeal: normalizeEmailOtpServerSealConfig(input),
    thresholdStore: input.thresholdStore,
    thresholdSigningService: input.thresholdSigningService,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

class CloudflareD1RegistrationCeremonyIntentStore {
  private readonly stub: CloudflareDurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: RegistrationCeremonyDoConfig) {
    this.stub = resolveRegistrationCeremonyDoStub(input);
    this.prefix = input.prefix;
  }

  async reserveGeneratedWalletId(input: {
    readonly rpId: string;
    readonly walletId: GeneratedImplicitWalletId;
    readonly expiresAtMs: number;
  }): Promise<boolean> {
    const rpId = toOptionalTrimmedString(input.rpId);
    const walletId = toOptionalTrimmedString(input.walletId);
    const expiresAtMs = Math.floor(Number(input.expiresAtMs));
    if (!rpId || !walletId || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
      return false;
    }
    const response = await callRegistrationCeremonyDo<{ readonly reserved: true }>(this.stub, {
      op: 'authReserveReplayGuard',
      key: this.key('generated-wallet-reservation', generatedWalletReservationKey(input)),
      expiresAtMs,
    });
    return response.ok;
  }

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    await this.put({
      scope: 'intent',
      id: intent.grant,
      record: intent,
      expiresAtMs: intent.expiresAtMs,
    });
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    await this.put({
      scope: 'add-signer-intent',
      id: intent.grant,
      record: intent,
      expiresAtMs: intent.expiresAtMs,
    });
  }

  async getAddSignerIntent(grant: string): Promise<StoredAddSignerIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.get('add-signer-intent', id);
    const intent = parseD1StoredAddSignerIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: string): Promise<StoredAddSignerIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.getDel('add-signer-intent', id);
    const intent = parseD1StoredAddSignerIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    await this.put({
      scope: 'add-signer',
      id: ceremony.addSignerCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const id = toOptionalTrimmedString(addSignerCeremonyId);
    if (!id) return null;
    const value = await this.get('add-signer', id);
    const ceremony = parseD1StoredWalletAddSignerCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    await this.put({
      scope: 'add-signer',
      id: ceremony.addSignerCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const id = toOptionalTrimmedString(addSignerCeremonyId);
    if (!id) return null;
    const value = await this.getDel('add-signer', id);
    const ceremony = parseD1StoredWalletAddSignerCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void> {
    await this.put({
      scope: 'add-auth-method-intent',
      id: intent.grant,
      record: intent,
      expiresAtMs: intent.expiresAtMs,
    });
  }

  async getAddAuthMethodIntent(
    grant: string,
  ): Promise<StoredAddAuthMethodIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.get('add-auth-method-intent', id);
    const intent = parseD1StoredAddAuthMethodIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddAuthMethodIntent(
    grant: string,
  ): Promise<StoredAddAuthMethodIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.getDel('add-auth-method-intent', id);
    const intent = parseD1StoredAddAuthMethodIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    await this.put({
      scope: 'add-auth-method',
      id: ceremony.addAuthMethodCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const id = toOptionalTrimmedString(addAuthMethodCeremonyId);
    if (!id) return null;
    const value = await this.get('add-auth-method', id);
    const ceremony = parseD1StoredWalletAddAuthMethodCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const id = toOptionalTrimmedString(addAuthMethodCeremonyId);
    if (!id) return null;
    const value = await this.getDel('add-auth-method', id);
    const ceremony = parseD1StoredWalletAddAuthMethodCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  private async put(input: {
    readonly scope: RegistrationCeremonyIntentScope;
    readonly id: string;
    readonly record: RegistrationIntentDoPutInput;
    readonly expiresAtMs: number;
  }): Promise<void> {
    const id = toOptionalTrimmedString(input.id);
    if (!id) throw new Error('Registration ceremony intent id is required');
    const ttlMs = Math.max(1, input.expiresAtMs - Date.now());
    const response = await callRegistrationCeremonyDo<boolean>(this.stub, {
      op: 'set',
      key: this.key(input.scope, id),
      value: input.record,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message || 'Registration ceremony DO write failed');
  }

  private async get(scope: RegistrationCeremonyIntentScope, id: string): Promise<unknown | null> {
    const response = await callRegistrationCeremonyDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key(scope, id),
    });
    return response.ok ? response.value : null;
  }

  private async getDel(
    scope: RegistrationCeremonyIntentScope,
    id: string,
  ): Promise<unknown | null> {
    const response = await callRegistrationCeremonyDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key(scope, id),
    });
    return response.ok ? response.value : null;
  }

  private key(scope: RegistrationCeremonyIntentScope, id: string): string {
    return `${this.prefix}${scope}:${id}`;
  }
}

function resolveRegistrationCeremonyDoConfig(
  input: ThresholdStoreConfigInput | null | undefined,
): RegistrationCeremonyDoConfig | null {
  const config = toRecordValue(input);
  if (!config) return null;
  if (toOptionalTrimmedString(config.kind) !== 'cloudflare-do') return null;
  const namespace = config.namespace;
  if (!isCloudflareDurableObjectNamespaceLike(namespace)) return null;
  return {
    namespace,
    objectName: resolveRegistrationCeremonyDoObjectName(config),
    prefix: resolveRegistrationCeremonyDoPrefix(config),
  };
}

function resolveRegistrationCeremonyDoObjectName(config: Record<string, unknown>): string {
  return (
    toOptionalTrimmedString(config.name) ||
    toOptionalTrimmedString(config.objectName) ||
    THRESHOLD_DO_OBJECT_NAME_DEFAULT
  );
}

function resolveRegistrationCeremonyDoPrefix(config: Record<string, unknown>): string {
  const explicit =
    toOptionalTrimmedString(config.WALLET_REGISTRATION_PREFIX) ||
    toOptionalTrimmedString(config.walletRegistrationPrefix);
  const base =
    explicit ||
    toOptionalTrimmedString(config.keyPrefix) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  if (!base) return 'wallet-registration:';
  return base.endsWith(':') ? `${base}wallet-registration:` : `${base}:wallet-registration:`;
}

function resolveRegistrationCeremonyDoStub(
  input: RegistrationCeremonyDoConfig,
): CloudflareDurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id);
}

async function callRegistrationCeremonyDo<T>(
  stub: CloudflareDurableObjectStubLike,
  request: CloudflareRegistrationIntentDoRequest,
): Promise<CloudflareDoResponse<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const body = await readDoJsonResponse(response);
  return parseDoResponse<T>(body);
}

async function readDoJsonResponse(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function parseDoResponse<T>(body: unknown): CloudflareDoResponse<T> {
  if (!isRecordValue(body)) {
    return { ok: false, code: 'invalid_response', message: 'Durable Object returned invalid JSON' };
  }
  if (body.ok === true) return { ok: true, value: body.value as T };
  return {
    ok: false,
    code: toOptionalTrimmedString(body.code) || 'do_error',
    message: toOptionalTrimmedString(body.message) || 'Durable Object request failed',
  };
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function toRecordValue(value: unknown): Record<string, unknown> | null {
  return isRecordValue(value) ? value : null;
}

function isCloudflareDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isRecordValue(value) &&
    typeof value.idFromName === 'function' &&
    typeof value.get === 'function'
  );
}

function generatedWalletReservationKey(input: {
  readonly rpId: string;
  readonly walletId: GeneratedImplicitWalletId;
}): string {
  const rpId = toOptionalTrimmedString(input.rpId);
  const walletId = toOptionalTrimmedString(input.walletId);
  if (!rpId || !walletId) return '';
  return `${encodeURIComponent(rpId)}:${walletId}`;
}

function createD1GeneratedWalletId(): GeneratedImplicitWalletId {
  const bytes = new Uint8Array(3);
  crypto.getRandomValues(bytes);
  return requireGeneratedImplicitWalletId(`seams-wallet-${bytesToHex(bytes)}`);
}

function missingRegistrationCeremonyDoStore(): {
  readonly ok: false;
  readonly code: 'configuration';
  readonly message: string;
} {
  return {
    ok: false,
    code: 'configuration',
    message: 'Cloudflare D1 relay registration intents require thresholdStore.kind cloudflare-do',
  };
}

function parseWalletIdForIntent(raw: unknown): WalletId | null {
  const value = toOptionalTrimmedString(raw);
  if (!value) return null;
  try {
    return walletIdFromString(value);
  } catch {
    return null;
  }
}

function inferRuntimePolicyScopeFromSigningRoot(input: {
  readonly orgId: string;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
}): RuntimePolicyScope | undefined {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  if (!signingRootId || !signingRootVersion) return undefined;
  const [projectId, envId] = signingRootId.split(':');
  if (!projectId || !envId) return undefined;
  return {
    orgId: toOptionalTrimmedString(input.orgId) || '',
    projectId,
    envId,
    signingRootVersion,
  };
}

function buildRegistrationIntent(input: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly authMethod: RegistrationAuthMethodInput;
  readonly signerSelection: RegistrationSignerSelection;
  readonly runtimePolicyScope?: RuntimePolicyScope;
}): RegistrationIntentV1 {
  const nonceB64u = secureRandomBase64Url(32);
  if (input.runtimePolicyScope) {
    return {
      version: 'registration_intent_v1',
      walletId: input.walletId,
      rpId: input.rpId,
      authMethod: input.authMethod,
      signerSelection: input.signerSelection,
      runtimePolicyScope: input.runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'registration_intent_v1',
    walletId: input.walletId,
    rpId: input.rpId,
    authMethod: input.authMethod,
    signerSelection: input.signerSelection,
    nonceB64u,
  };
}

function buildAddSignerIntent(input: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly signerSelection: AddSignerSelection;
  readonly runtimePolicyScope?: RuntimePolicyScope;
}): AddSignerIntentV1 {
  const nonceB64u = secureRandomBase64Url(32);
  if (input.runtimePolicyScope) {
    return {
      version: 'add_signer_intent_v1',
      walletId: input.walletId,
      rpId: input.rpId,
      signerSelection: input.signerSelection,
      runtimePolicyScope: input.runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_signer_intent_v1',
    walletId: input.walletId,
    rpId: input.rpId,
    signerSelection: input.signerSelection,
    nonceB64u,
  };
}

function parseD1StoredAddSignerIntent(raw: unknown): StoredAddSignerIntent | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'add_signer_intent_allocated') return null;
  const grant = addSignerIntentGrantFromString(toOptionalTrimmedString(record.grant) || '');
  const intent = parseD1AddSignerIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (!grant || !intent || !digestB64u || !orgId || expiresAtMs === null) return null;
  return {
    kind: 'add_signer_intent_allocated',
    grant,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    ...intentScopeMetadata(record),
  };
}

function parseD1AddSignerIntent(raw: unknown): AddSignerIntentV1 | null {
  const record = toRecordValue(raw);
  if (!record || record.version !== 'add_signer_intent_v1') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const signerSelection = normalizeAddSignerSelection(record.signerSelection, {
    normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
  });
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (!walletId || !rpId || !signerSelection.ok || !nonceB64u) return null;
  if (record.runtimePolicyScope !== undefined && !runtimePolicyScope) return null;
  if (runtimePolicyScope) {
    return {
      version: 'add_signer_intent_v1',
      walletId,
      rpId,
      signerSelection: signerSelection.value,
      runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_signer_intent_v1',
    walletId,
    rpId,
    signerSelection: signerSelection.value,
    nonceB64u,
  };
}

function parseD1StoredWalletAddSignerCeremony(
  raw: unknown,
): StoredWalletAddSignerCeremony | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const addSignerCeremonyId = toOptionalTrimmedString(record.addSignerCeremonyId);
  const intent = parseD1AddSignerIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const auth = parseD1StoredAddSignerAuth(record.auth);
  const signerState = parseD1StoredWalletAddSignerSignerState(record.signerState);
  if (
    !addSignerCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    expiresAtMs === null ||
    !auth ||
    !signerState
  ) {
    return null;
  }
  const ceremony: StoredWalletAddSignerCeremony = {
    addSignerCeremonyId,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    auth,
    signerState,
  };
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (signingRootId) ceremony.signingRootId = signingRootId;
  if (signingRootVersion) ceremony.signingRootVersion = signingRootVersion;
  return ceremony;
}

function parseD1StoredAddSignerAuth(
  raw: unknown,
): StoredWalletAddSignerCeremony['auth'] | null {
  const record = toRecordValue(raw);
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'app_session') return { kind: 'app_session' };
  if (kind === 'webauthn_assertion') {
    const credentialIdB64u = toOptionalTrimmedString(record?.credentialIdB64u);
    return credentialIdB64u ? { kind: 'webauthn_assertion', credentialIdB64u } : null;
  }
  return null;
}

function parseD1StoredWalletAddSignerSignerState(
  raw: unknown,
): StoredWalletAddSignerCeremony['signerState'] | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind === 'ecdsa_add_signer_prepared') {
    return parseD1StoredEcdsaAddSignerPrepared(record);
  }
  if (kind === 'ecdsa_add_signer_responded') {
    return parseD1StoredEcdsaAddSignerResponded(record);
  }
  return null;
}

function parseD1StoredEcdsaAddSignerPrepared(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_prepared' }
> | null {
  const hssKind = toOptionalTrimmedString(record.hssKind);
  const chainTargets = Array.isArray(record.chainTargets)
    ? normalizeThresholdEcdsaChainTargets(record.chainTargets)
    : null;
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  if (hssKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare) return null;
  return {
    kind: 'ecdsa_add_signer_prepared',
    hssKind,
    chainTargets,
    prepare,
  };
}

function parseD1StoredEcdsaAddSignerResponded(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_responded' }
> | null {
  const hssKind = toOptionalTrimmedString(record.hssKind);
  const chainTargets = Array.isArray(record.chainTargets)
    ? normalizeThresholdEcdsaChainTargets(record.chainTargets)
    : null;
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  const responded = toRecordValue(record.responded);
  const bootstrap = parseD1EcdsaHssServerBootstrapResponse(responded?.bootstrap);
  if (hssKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare || !bootstrap) {
    return null;
  }
  return {
    kind: 'ecdsa_add_signer_responded',
    hssKind,
    chainTargets,
    prepare,
    responded: {
      bootstrap,
    },
  };
}

function parseD1WalletRegistrationEcdsaPrepare(
  raw: unknown,
): WalletRegistrationEcdsaPreparePayload['prepare'] | null {
  const record = toRecordValue(raw);
  if (!record || record.formatVersion !== 'ecdsa-hss-role-local') return null;
  if (record.keyScope !== 'evm-family') return null;
  if (record.registrationPreparationId !== undefined) return null;
  const walletId = toOptionalTrimmedString(record.walletId);
  const walletKeyId = toOptionalTrimmedString(record.walletKeyId);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(record.ecdsaThresholdKeyId);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const requestId = toOptionalTrimmedString(record.requestId);
  const thresholdSessionId = toOptionalTrimmedString(record.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(record.signingGrantId);
  const ttlMs = safeInteger(record.ttlMs);
  const remainingUses = safeInteger(record.remainingUses);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (
    !walletId ||
    !walletKeyId ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerKeyId ||
    !requestId ||
    !thresholdSessionId ||
    !signingGrantId ||
    ttlMs === null ||
    remainingUses === null ||
    !participantIds ||
    (record.runtimePolicyScope !== undefined && !runtimePolicyScope)
  ) {
    return null;
  }
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    walletKeyId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    requestId,
    thresholdSessionId,
    signingGrantId,
    ttlMs,
    remainingUses,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

function parseD1EcdsaHssServerBootstrapResponse(
  raw: unknown,
): EcdsaHssServerBootstrapResponse | null {
  const record = toRecordValue(raw);
  if (!record || record.formatVersion !== 'ecdsa-hss-role-local') return null;
  const walletId = toOptionalTrimmedString(record.walletId);
  const walletKeyId = toOptionalTrimmedString(record.walletKeyId);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(record.ecdsaThresholdKeyId);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const applicationBindingDigestB64u = toOptionalTrimmedString(
    record.applicationBindingDigestB64u,
  );
  const contextBinding32B64u = toOptionalTrimmedString(record.contextBinding32B64u);
  const publicIdentity = parseD1EcdsaHssPublicIdentity(record.publicIdentity);
  const clientShareRetryCounter = safeInteger(record.clientShareRetryCounter);
  const relayerShareRetryCounter = safeInteger(record.relayerShareRetryCounter);
  const publicTranscriptDigest32B64u = toOptionalTrimmedString(
    record.publicTranscriptDigest32B64u,
  );
  const keyHandle = toOptionalTrimmedString(record.keyHandle);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(
    record.thresholdEcdsaPublicKeyB64u,
  );
  const ethereumAddress = toOptionalTrimmedString(record.ethereumAddress);
  const relayerVerifyingShareB64u = toOptionalTrimmedString(record.relayerVerifyingShareB64u);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  const thresholdSessionId = toOptionalTrimmedString(record.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(record.signingGrantId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const expiresAt = toOptionalTrimmedString(record.expiresAt);
  const remainingUses = safeInteger(record.remainingUses);
  if (
    !walletId ||
    !walletKeyId ||
    !ecdsaThresholdKeyId ||
    !relayerKeyId ||
    !applicationBindingDigestB64u ||
    !contextBinding32B64u ||
    !publicIdentity ||
    clientShareRetryCounter === null ||
    relayerShareRetryCounter === null ||
    !publicTranscriptDigest32B64u ||
    !keyHandle ||
    !signingRootId ||
    !signingRootVersion ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress ||
    !relayerVerifyingShareB64u ||
    !participantIds ||
    !thresholdSessionId ||
    !signingGrantId ||
    expiresAtMs === null ||
    !expiresAt ||
    remainingUses === null
  ) {
    return null;
  }
  const bootstrap: EcdsaHssServerBootstrapResponse = {
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    walletKeyId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    applicationBindingDigestB64u,
    contextBinding32B64u,
    publicIdentity,
    clientShareRetryCounter,
    relayerShareRetryCounter,
    publicTranscriptDigest32B64u,
    keyHandle,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    participantIds,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    expiresAt,
    remainingUses,
  };
  const jwt = toOptionalTrimmedString(record.jwt);
  if (jwt) bootstrap.jwt = jwt;
  return bootstrap;
}

function parseD1EcdsaHssPublicIdentity(
  raw: unknown,
): D1EcdsaPublicIdentity | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const hssClientSharePublicKey33B64u = toOptionalTrimmedString(
    record.hssClientSharePublicKey33B64u,
  );
  const relayerPublicKey33B64u = toOptionalTrimmedString(record.relayerPublicKey33B64u);
  const groupPublicKey33B64u = toOptionalTrimmedString(record.groupPublicKey33B64u);
  const ethereumAddress = toOptionalTrimmedString(record.ethereumAddress);
  if (
    !hssClientSharePublicKey33B64u ||
    !relayerPublicKey33B64u ||
    !groupPublicKey33B64u ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    hssClientSharePublicKey33B64u: hssClientSharePublicKey33B64u as D1EcdsaClientSharePublicKey,
    relayerPublicKey33B64u: relayerPublicKey33B64u as D1EcdsaRelayerPublicKey,
    groupPublicKey33B64u,
    ethereumAddress,
  };
}

function parseD1PositiveIntegerArray(raw: unknown): number[] | null {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const values: number[] = [];
  for (const item of raw) {
    const value = safeInteger(item);
    if (value === null || value <= 0) return null;
    values.push(value);
  }
  return values;
}

function buildAddAuthMethodIntent(input: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly authMethod: AddAuthMethodInput;
  readonly runtimePolicyScope?: RuntimePolicyScope;
}): AddAuthMethodIntentV1 {
  const nonceB64u = secureRandomBase64Url(32);
  if (input.runtimePolicyScope) {
    return {
      version: 'add_auth_method_intent_v1',
      walletId: input.walletId,
      rpId: input.rpId,
      authMethod: input.authMethod,
      runtimePolicyScope: input.runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_auth_method_intent_v1',
    walletId: input.walletId,
    rpId: input.rpId,
    authMethod: input.authMethod,
    nonceB64u,
  };
}

function addAuthMethodInputMatches(
  left: AddAuthMethodInput,
  right: AddAuthMethodInput,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return true;
    case 'email_otp':
      return right.kind === 'email_otp' && left.email.toLowerCase() === right.email.toLowerCase();
  }
  return unreachableAddAuthMethodInput(left);
}

function addSignerSelectionMatches(
  left: AddSignerSelection,
  right: AddSignerSelection,
): boolean {
  if (left.mode !== right.mode) return false;
  switch (left.mode) {
    case 'ecdsa':
      return (
        right.mode === 'ecdsa' &&
        positiveIntegerArraysEqual(left.ecdsa.participantIds, right.ecdsa.participantIds) &&
        thresholdEcdsaChainTargetsEqual(left.ecdsa.chainTargets, right.ecdsa.chainTargets)
      );
    case 'ed25519':
      return right.mode === 'ed25519' && addSignerEd25519SelectionsMatch(left, right);
  }
  return unreachableAddSignerSelection(left);
}

function addSignerEd25519SelectionsMatch(
  left: Extract<AddSignerSelection, { mode: 'ed25519' }>,
  right: Extract<AddSignerSelection, { mode: 'ed25519' }>,
): boolean {
  const leftEd25519 = left.ed25519;
  const rightEd25519 = right.ed25519;
  return (
    leftEd25519.mode === rightEd25519.mode &&
    leftEd25519.nearAccountId === rightEd25519.nearAccountId &&
    leftEd25519.signerSlot === rightEd25519.signerSlot &&
    leftEd25519.keyPurpose === rightEd25519.keyPurpose &&
    leftEd25519.keyVersion === rightEd25519.keyVersion &&
    leftEd25519.derivationVersion === rightEd25519.derivationVersion &&
    positiveIntegerArraysEqual(leftEd25519.participantIds, rightEd25519.participantIds)
  );
}

function positiveIntegerArraysEqual(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function thresholdEcdsaChainTargetsEqual(left: readonly unknown[], right: readonly unknown[]): boolean {
  const leftTargets = normalizeThresholdEcdsaChainTargets(left);
  const rightTargets = normalizeThresholdEcdsaChainTargets(right);
  if (!leftTargets || !rightTargets || leftTargets.length !== rightTargets.length) return false;
  return leftTargets.every(
    (target, index) => thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(rightTargets[index]),
  );
}

function normalizeThresholdEcdsaChainTargets(
  input: readonly unknown[],
): ThresholdEcdsaChainTarget[] | null {
  const targets: ThresholdEcdsaChainTarget[] = [];
  for (const raw of input) {
    const target = thresholdEcdsaChainTargetFromValue(raw);
    if (!target) return null;
    targets.push(target);
  }
  return targets;
}

function unreachableAddAuthMethodInput(value: never): never {
  throw new Error(`Unhandled add-auth-method input kind: ${String(value)}`);
}

function unreachableAddSignerSelection(value: never): never {
  throw new Error(`Unhandled add-signer selection mode: ${String(value)}`);
}

function runtimePolicyScopeMatches(
  left: RuntimePolicyScopeLike | undefined,
  right: RuntimePolicyScopeLike | undefined,
): boolean {
  if (!left && !right) return true;
  if (!left || !right) return false;
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function isMatchingD1EcdsaClientBootstrap(
  expected: WalletRegistrationEcdsaPreparePayload['prepare'],
  actual: WalletRegistrationEcdsaClientBootstrap,
): boolean {
  return (
    actual.formatVersion === expected.formatVersion &&
    actual.walletId === expected.walletId &&
    actual.walletKeyId === expected.walletKeyId &&
    actual.ecdsaThresholdKeyId === expected.ecdsaThresholdKeyId &&
    actual.signingRootId === expected.signingRootId &&
    actual.signingRootVersion === expected.signingRootVersion &&
    actual.keyScope === expected.keyScope &&
    actual.relayerKeyId === expected.relayerKeyId &&
    actual.registrationPreparationId === expected.registrationPreparationId &&
    actual.requestId === expected.requestId &&
    actual.thresholdSessionId === expected.thresholdSessionId &&
    actual.signingGrantId === expected.signingGrantId &&
    actual.ttlMs === expected.ttlMs &&
    actual.remainingUses === expected.remainingUses &&
    positiveIntegerArraysEqual(actual.participantIds, expected.participantIds) &&
    runtimePolicyScopeMatches(actual.runtimePolicyScope, expected.runtimePolicyScope)
  );
}

function toD1EcdsaHssClientBootstrapRequest(
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap,
): EcdsaHssClientBootstrapRequest {
  return {
    formatVersion: clientBootstrap.formatVersion,
    walletId: clientBootstrap.walletId,
    walletKeyId: clientBootstrap.walletKeyId,
    ecdsaThresholdKeyId: clientBootstrap.ecdsaThresholdKeyId,
    signingRootId: clientBootstrap.signingRootId,
    signingRootVersion: clientBootstrap.signingRootVersion,
    keyScope: clientBootstrap.keyScope,
    relayerKeyId: clientBootstrap.relayerKeyId,
    ...(clientBootstrap.registrationPreparationId
      ? { registrationPreparationId: clientBootstrap.registrationPreparationId }
      : {}),
    hssClientSharePublicKey33B64u: clientBootstrap.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: clientBootstrap.requestId,
    sessionId: clientBootstrap.thresholdSessionId,
    signingGrantId: clientBootstrap.signingGrantId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: clientBootstrap.remainingUses,
    participantIds: clientBootstrap.participantIds,
    ...(clientBootstrap.runtimePolicyScope
      ? { runtimePolicyScope: clientBootstrap.runtimePolicyScope }
      : {}),
  };
}

function buildD1EcdsaAddSignerRespondedCeremony(input: {
  readonly ceremony: StoredWalletAddSignerCeremony;
  readonly bootstrap: EcdsaHssServerBootstrapResponse;
}): StoredWalletAddSignerCeremony {
  const state = input.ceremony.signerState;
  if (state.kind !== 'ecdsa_add_signer_prepared') {
    throw new Error('ECDSA add-signer ceremony must be prepared before respond');
  }
  const ceremony: StoredWalletAddSignerCeremony = {
    addSignerCeremonyId: input.ceremony.addSignerCeremonyId,
    intent: input.ceremony.intent,
    digestB64u: input.ceremony.digestB64u,
    orgId: input.ceremony.orgId,
    expiresAtMs: input.ceremony.expiresAtMs,
    auth: input.ceremony.auth,
    signerState: {
      kind: 'ecdsa_add_signer_responded',
      hssKind: state.hssKind,
      chainTargets: state.chainTargets,
      prepare: state.prepare,
      responded: {
        bootstrap: input.bootstrap,
      },
    },
  };
  if (input.ceremony.signingRootId) ceremony.signingRootId = input.ceremony.signingRootId;
  if (input.ceremony.signingRootVersion) {
    ceremony.signingRootVersion = input.ceremony.signingRootVersion;
  }
  return ceremony;
}

type D1EcdsaWalletKeyBuildResult =
  | {
      readonly ok: true;
      readonly walletKeys: WalletRegistrationEcdsaWalletKey[];
    }
  | {
      readonly ok: false;
      readonly code: 'incomplete_ecdsa_wallet_key';
      readonly message: string;
    };

function buildD1EcdsaWalletKeysFromBootstrap(input: {
  readonly bootstrap: EcdsaHssServerBootstrapResponse;
  readonly chainTargets: readonly ThresholdEcdsaChainTarget[];
  readonly errorContext: string;
}): D1EcdsaWalletKeyBuildResult {
  const bootstrap = input.bootstrap;
  const required = {
    walletId: toOptionalTrimmedString(bootstrap.walletId),
    walletKeyId: toOptionalTrimmedString(bootstrap.walletKeyId),
    keyHandle: toOptionalTrimmedString(bootstrap.keyHandle),
    ecdsaThresholdKeyId: toOptionalTrimmedString(bootstrap.ecdsaThresholdKeyId),
    signingRootId: toOptionalTrimmedString(bootstrap.signingRootId),
    signingRootVersion: toOptionalTrimmedString(bootstrap.signingRootVersion),
    thresholdEcdsaPublicKeyB64u: toOptionalTrimmedString(bootstrap.thresholdEcdsaPublicKeyB64u),
    thresholdOwnerAddress: toOptionalTrimmedString(bootstrap.ethereumAddress),
    relayerKeyId: toOptionalTrimmedString(bootstrap.relayerKeyId),
    relayerVerifyingShareB64u: toOptionalTrimmedString(bootstrap.relayerVerifyingShareB64u),
  };
  const missingField = Object.entries(required).find(([, value]) => !value)?.[0];
  if (missingField) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} returned incomplete ECDSA wallet key material: ${missingField}`,
    };
  }
  const participantIds = parseD1PositiveIntegerArray(bootstrap.participantIds);
  if (!participantIds) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} returned incomplete ECDSA wallet key material: participantIds`,
    };
  }
  if (input.chainTargets.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} has no ECDSA chain targets`,
    };
  }
  return {
    ok: true,
    walletKeys: input.chainTargets.map((chainTarget) => ({
      keyScope: 'evm-family',
      chainTarget,
      walletId: required.walletId,
      walletKeyId: required.walletKeyId,
      keyHandle: required.keyHandle,
      ecdsaThresholdKeyId: required.ecdsaThresholdKeyId,
      signingRootId: required.signingRootId,
      signingRootVersion: required.signingRootVersion,
      thresholdEcdsaPublicKeyB64u: required.thresholdEcdsaPublicKeyB64u,
      thresholdOwnerAddress: required.thresholdOwnerAddress,
      relayerKeyId: required.relayerKeyId,
      relayerVerifyingShareB64u: required.relayerVerifyingShareB64u,
      participantIds,
    })),
  };
}

function buildD1WalletRecord(input: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly now: number;
}): WalletRecord {
  return {
    version: 'wallet_v1',
    walletId: input.walletId,
    rpId: input.rpId,
    createdAtMs: input.now,
    updatedAtMs: input.now,
  };
}

function buildD1WalletEcdsaSignerRecords(input: {
  readonly walletId: WalletId;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  readonly now: number;
}) {
  return input.walletKeys.map((walletKey) =>
    buildWalletEcdsaSignerRecord({
      walletId: input.walletId,
      walletKey,
      createdAtMs: input.now,
      updatedAtMs: input.now,
    }),
  );
}

function derivePlannedEvmFamilyWalletKeyId(input: {
  readonly walletId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): string {
  const walletId = toOptionalTrimmedString(input.walletId);
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  if (!walletId || !signingRootId || !signingRootVersion) {
    throw new Error('ECDSA wallet-key identity requires walletId and signing root');
  }
  return [
    'wallet-key',
    'evm-family',
    encodeURIComponent(walletId),
    encodeURIComponent(signingRootId),
    encodeURIComponent(signingRootVersion),
  ].join(':');
}

function intentScopeMetadata(input: {
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly expectedOrigin?: string;
}): {
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly expectedOrigin?: string;
} {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
  return {
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(expectedOrigin ? { expectedOrigin } : {}),
  };
}

function parseD1StoredAddAuthMethodIntent(raw: unknown): StoredAddAuthMethodIntent | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'add_auth_method_intent_allocated') return null;
  const grant = addAuthMethodIntentGrantFromString(toOptionalTrimmedString(record.grant) || '');
  const intent = parseD1AddAuthMethodIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (!grant || !intent || !digestB64u || !orgId || expiresAtMs === null) return null;
  return {
    kind: 'add_auth_method_intent_allocated',
    grant,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    ...intentScopeMetadata(record),
  };
}

function parseD1StoredWalletAddAuthMethodCeremony(
  raw: unknown,
): StoredWalletAddAuthMethodCeremony | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const addAuthMethodCeremonyId = toOptionalTrimmedString(record.addAuthMethodCeremonyId);
  const intent = parseD1AddAuthMethodIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const auth = parseD1StoredAddAuthMethodAuth(record.auth);
  const authority = parseD1RegistrationAuthority(record.authority);
  if (
    !addAuthMethodCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    expiresAtMs === null ||
    !auth ||
    !authority
  ) {
    return null;
  }
  return {
    addAuthMethodCeremonyId,
    intent,
    digestB64u,
    orgId,
    ...(toOptionalTrimmedString(record.expectedOrigin)
      ? { expectedOrigin: toOptionalTrimmedString(record.expectedOrigin) }
      : {}),
    expiresAtMs,
    auth,
    authority,
  };
}

function parseD1AddAuthMethodIntent(raw: unknown): AddAuthMethodIntentV1 | null {
  const record = toRecordValue(raw);
  if (!record || record.version !== 'add_auth_method_intent_v1') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const authMethod = normalizeAddAuthMethodInput(record.authMethod);
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (!walletId || !rpId || !authMethod || !nonceB64u) return null;
  if (record.runtimePolicyScope !== undefined && !runtimePolicyScope) return null;
  if (runtimePolicyScope) {
    return {
      version: 'add_auth_method_intent_v1',
      walletId,
      rpId,
      authMethod,
      runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_auth_method_intent_v1',
    walletId,
    rpId,
    authMethod,
    nonceB64u,
  };
}

function parseD1RuntimePolicyScope(raw: unknown): RuntimePolicyScope | undefined {
  if (raw === undefined || raw === null) return undefined;
  const record = toRecordValue(raw);
  if (!record) return undefined;
  const orgId = toOptionalTrimmedString(record.orgId);
  const projectId = toOptionalTrimmedString(record.projectId);
  const envId = toOptionalTrimmedString(record.envId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return {
    orgId,
    projectId,
    envId,
    signingRootVersion,
  };
}

function parseD1StoredAddAuthMethodAuth(
  raw: unknown,
): StoredWalletAddAuthMethodCeremony['auth'] | null {
  const record = toRecordValue(raw);
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'app_session') return { kind: 'app_session' };
  if (kind === 'webauthn_assertion') {
    const credentialIdB64u = toOptionalTrimmedString(record?.credentialIdB64u);
    return credentialIdB64u ? { kind: 'webauthn_assertion', credentialIdB64u } : null;
  }
  return null;
}

function parseD1RegistrationAuthority(raw: unknown): RegistrationAuthority | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'passkey') return parseD1PasskeyRegistrationAuthority(record);
  if (kind === 'email_otp') return parseD1EmailOtpRegistrationAuthority(record);
  return null;
}

function parseD1PasskeyRegistrationAuthority(
  record: Record<string, unknown>,
): Extract<RegistrationAuthority, { kind: 'passkey' }> | null {
  const walletId = parseWalletIdForIntent(record.walletId);
  const rpId = parseWebAuthnRpId(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(record.credentialPublicKeyB64u);
  const counter = safeInteger(record.counter);
  const registrationIntentDigestB64u = toOptionalTrimmedString(
    record.registrationIntentDigestB64u,
  );
  if (
    !walletId ||
    !rpId.ok ||
    !credentialIdB64u ||
    !credentialPublicKeyB64u ||
    counter === null ||
    !registrationIntentDigestB64u
  ) {
    return null;
  }
  return {
    kind: 'passkey',
    walletId,
    rpId: rpId.value,
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter,
    registrationIntentDigestB64u,
  };
}

function parseD1EmailOtpRegistrationAuthority(
  record: Record<string, unknown>,
): Extract<RegistrationAuthority, { kind: 'email_otp'; proofKind: 'otp_challenge' }> | null {
  if (record.proofKind !== 'otp_challenge') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const providerSubject = parseProviderSubject(record.providerSubject);
  const challengeSubjectId = parseChallengeSubjectId(record.challengeSubjectId);
  const email = toOptionalTrimmedString(record.email);
  const emailHashHex = toOptionalTrimmedString(record.emailHashHex);
  const challengeId = parseEmailOtpChallengeId(record.challengeId);
  const registrationAuthorityId = parseEmailOtpChallengeId(record.registrationAuthorityId);
  const originalWalletId = parseWalletIdForIntent(record.originalWalletId);
  const finalWalletId = parseWalletIdForIntent(record.finalWalletId);
  const orgId = parseOrgId(record.orgId);
  const appSessionVersion = parseAppSessionVersion(record.appSessionVersion);
  const challengePurpose = toOptionalTrimmedString(record.challengePurpose);
  const registrationIntentDigestB64u = toOptionalTrimmedString(
    record.registrationIntentDigestB64u,
  );
  if (
    !walletId ||
    !providerSubject.ok ||
    !challengeSubjectId.ok ||
    !email ||
    !emailHashHex ||
    !challengeId.ok ||
    !registrationAuthorityId.ok ||
    !originalWalletId ||
    !finalWalletId ||
    !orgId.ok ||
    !appSessionVersion.ok ||
    (challengePurpose !== 'registration' && challengePurpose !== 'registration_reroll') ||
    !registrationIntentDigestB64u
  ) {
    return null;
  }
  return {
    kind: 'email_otp',
    proofKind: 'otp_challenge',
    walletId,
    providerSubject: providerSubject.value,
    challengeSubjectId: challengeSubjectId.value,
    email,
    emailHashHex,
    challengeId: challengeId.value,
    registrationAuthorityId: registrationAuthorityId.value,
    originalWalletId,
    finalWalletId,
    orgId: orgId.value,
    appSessionVersion: appSessionVersion.value,
    challengePurpose,
    registrationIntentDigestB64u,
  };
}

function unreachableAddAuthMethodAuthority(value: never): never {
  throw new Error(`Unhandled add-auth-method authority kind: ${String(value)}`);
}

function walletAuthMethodRecordFromRegistrationAuthority(input: {
  readonly authority: RegistrationAuthority;
  readonly now: number;
}): WalletAuthMethodRecord {
  switch (input.authority.kind) {
    case 'passkey':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId: input.authority.walletId,
        rpId: input.authority.rpId,
        credentialIdB64u: input.authority.credentialIdB64u,
        credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
        counter: input.authority.counter,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      };
    case 'email_otp':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: input.authority.walletId,
        emailHashHex: input.authority.emailHashHex,
        registrationAuthorityId: input.authority.registrationAuthorityId,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      };
  }
  return unreachableRegistrationAuthority(input.authority);
}

function unreachableRegistrationAuthority(value: never): never {
  throw new Error(`Unhandled registration authority kind: ${String(value)}`);
}

function safeInteger(raw: unknown): number | null {
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

async function loadSimpleWebAuthnServer(): Promise<SimpleWebAuthnServerModule> {
  try {
    return (await import('@simplewebauthn/server')) as SimpleWebAuthnServerModule;
  } catch (error: unknown) {
    throw new Error(
      `Server WebAuthn route selected but '@simplewebauthn/server' dependency is not available: ${
        errorMessage(error) || 'import failed'
      }`,
    );
  }
}

function appSessionVersion(): string {
  return secureRandomBase64Url(32, 'app session versions');
}

function webAuthnLoginChallengeTtlMs(input: unknown): number {
  const defaultTtlMs = 5 * 60_000;
  const minTtlMs = 10_000;
  const maxTtlMs = 10 * 60_000;
  if (input == null || input === '') return defaultTtlMs;
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return defaultTtlMs;
  return Math.min(Math.max(Math.floor(value), minTtlMs), maxTtlMs);
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return Boolean(input) && typeof input === 'object' && !Array.isArray(input);
}

function parseJsonObject(input: unknown): Record<string, unknown> | null {
  if (isRecord(input)) return input;
  if (typeof input !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(input);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function decodeBase64UrlOrBase64(input: string, fieldName: string): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (error: unknown) {
      throw new Error(
        `Invalid ${fieldName}: expected base64url/base64 string (${
          errorMessage(error) || 'decode failed'
        })`,
      );
    }
  }
}

function parseClientDataJsonBase64url(clientDataJSONB64u: string): {
  readonly challenge: string;
  readonly origin: string;
  readonly type: string;
} {
  const bytes = decodeBase64UrlOrBase64(
    clientDataJSONB64u,
    'webauthn_authentication.response.clientDataJSON',
  );
  const json = new TextDecoder().decode(bytes);
  const record = parseJsonObject(json);
  if (!record) throw new Error('Invalid clientDataJSON: expected object');
  const challenge = toOptionalTrimmedString(record.challenge);
  const origin = toOptionalTrimmedString(record.origin);
  const type = toOptionalTrimmedString(record.type);
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

function originHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isHostWithinRpId(host: string, rpId: string): boolean {
  const normalizedHost = host.toLowerCase();
  const normalizedRpId = rpId.toLowerCase();
  if (!normalizedHost || !normalizedRpId) return false;
  const env = typeof process !== 'undefined' ? process.env : {};
  if (
    (env.NO_CADDY === '1' || env.VITE_NO_CADDY === '1') &&
    (normalizedHost === 'localhost' || normalizedHost === '127.0.0.1') &&
    normalizedRpId.endsWith('.localhost')
  ) {
    return true;
  }
  return normalizedHost === normalizedRpId || normalizedHost.endsWith(`.${normalizedRpId}`);
}

function webAuthnCredentialIdB64uFromCredential(input: unknown):
  | { readonly ok: true; readonly credentialIdB64u: string }
  | { readonly ok: false; readonly code: string; readonly message: string } {
  const credential = isRecord(input) ? input : {};
  const rawId = toOptionalTrimmedString(credential.rawId);
  const id = toOptionalTrimmedString(credential.id);
  const selected = rawId || id;
  if (!selected) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Missing webauthn_authentication.id/rawId',
    };
  }
  try {
    return {
      ok: true,
      credentialIdB64u: base64UrlEncode(
        decodeBase64UrlOrBase64(selected, 'webauthn_authentication.rawId'),
      ),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(error) || 'Invalid credential rawId',
    };
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

function parseD1RevokeWalletAuthMethodTarget(
  input: unknown,
): D1RevokeWalletAuthMethodTarget | null {
  if (!isRecord(input)) return null;
  const kind = toOptionalTrimmedString(input.kind);
  if (kind === 'passkey') {
    const credentialIdB64u = toOptionalTrimmedString(input.credentialIdB64u);
    if (!credentialIdB64u || Object.prototype.hasOwnProperty.call(input, 'email')) return null;
    return { kind: 'passkey', credentialIdB64u };
  }
  if (kind === 'email_otp') {
    const email = toOptionalTrimmedString(input.email).toLowerCase();
    if (!email || Object.prototype.hasOwnProperty.call(input, 'credentialIdB64u')) return null;
    return { kind: 'email_otp', email };
  }
  return null;
}

function d1RevokeWalletAuthMethodInvalidBody(message: string): D1RevokeWalletAuthMethodBoundary {
  return {
    ok: false,
    result: {
      ok: false,
      code: 'invalid_body',
      message,
    },
  };
}

function parseD1RevokeWalletAuthMethodAuth(input: {
  readonly raw: unknown;
  readonly walletId: WalletId;
}): D1RevokeWalletAuthMethodAuth | null {
  if (!isRecord(input.raw)) return null;
  const kind = toOptionalTrimmedString(input.raw.kind);
  if (kind === 'webauthn_assertion') {
    return {
      kind: 'webauthn_assertion',
      credential: input.raw.credential,
    };
  }
  if (kind !== 'app_session') return null;
  const rawPolicy = isRecord(input.raw.policy) ? input.raw.policy : null;
  const target = parseD1RevokeWalletAuthMethodTarget(rawPolicy?.target);
  const expiresAtMs = Math.floor(Number(rawPolicy?.expiresAtMs));
  const permission = toOptionalTrimmedString(rawPolicy?.permission);
  const policyWalletId = walletIdFromString(toOptionalTrimmedString(rawPolicy?.walletId));
  if (
    !rawPolicy ||
    permission !== 'wallet_auth_method_revoke' ||
    !policyWalletId ||
    !target ||
    !Number.isSafeInteger(expiresAtMs)
  ) {
    return null;
  }
  return {
    kind: 'app_session',
    policy: {
      permission: 'wallet_auth_method_revoke',
      walletId: policyWalletId,
      target,
      expiresAtMs,
    },
  };
}

function parseD1RevokeWalletAuthMethodInput(
  input: RevokeWalletAuthMethodInput,
): D1RevokeWalletAuthMethodBoundary {
  const raw: Record<string, unknown> = isRecord(input) ? input : {};
  const walletId = walletIdFromString(toOptionalTrimmedString(raw.walletId));
  if (!walletId) return d1RevokeWalletAuthMethodInvalidBody('walletId is required');
  const parsedRpId = parseWebAuthnRpId(raw.rpId);
  if (!parsedRpId.ok) return d1RevokeWalletAuthMethodInvalidBody('rpId is required');
  const target = parseD1RevokeWalletAuthMethodTarget(raw.target);
  if (!target) return d1RevokeWalletAuthMethodInvalidBody('target is required');
  const auth = parseD1RevokeWalletAuthMethodAuth({
    raw: raw.auth,
    walletId,
  });
  if (!auth) return d1RevokeWalletAuthMethodInvalidBody('auth is required');
  return {
    ok: true,
    walletId,
    rpId: parsedRpId.value,
    target,
    auth,
  };
}

function d1RevokeTargetsEqual(
  left: D1RevokeWalletAuthMethodTarget,
  right: D1RevokeWalletAuthMethodTarget,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return right.kind === 'passkey' && left.credentialIdB64u === right.credentialIdB64u;
    case 'email_otp':
      return right.kind === 'email_otp' && left.email === right.email;
  }
}

function activeWalletAuthMethodRecord(record: WalletAuthMethodRecord): boolean {
  return record.status === 'active';
}

function revokedD1WalletAuthMethodRecord(input: {
  readonly record: WalletAuthMethodRecord;
  readonly updatedAtMs: number;
}): WalletAuthMethodRecord {
  switch (input.record.kind) {
    case 'passkey':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'revoked',
        walletId: input.record.walletId,
        rpId: input.record.rpId,
        credentialIdB64u: input.record.credentialIdB64u,
        credentialPublicKeyB64u: input.record.credentialPublicKeyB64u,
        counter: input.record.counter,
        createdAtMs: input.record.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
    case 'email_otp':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'revoked',
        walletId: input.record.walletId,
        emailHashHex: input.record.emailHashHex,
        registrationAuthorityId: input.record.registrationAuthorityId,
        createdAtMs: input.record.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
  }
}

function parseD1WebAuthnAuthenticationCredential(
  input: unknown,
): WebAuthnAuthenticationCredential | null {
  const credential = isRecord(input) ? input : null;
  const response = isRecord(credential?.response) ? credential.response : null;
  const id = toOptionalTrimmedString(credential?.id);
  const rawId = toOptionalTrimmedString(credential?.rawId);
  const type = toOptionalTrimmedString(credential?.type);
  const clientDataJSON = toOptionalTrimmedString(response?.clientDataJSON);
  const authenticatorData = toOptionalTrimmedString(response?.authenticatorData);
  const signature = toOptionalTrimmedString(response?.signature);
  const userHandle =
    response?.userHandle === null ? null : toOptionalTrimmedString(response?.userHandle) || null;
  const authenticatorAttachment =
    credential?.authenticatorAttachment === null
      ? null
      : toOptionalTrimmedString(credential?.authenticatorAttachment) || null;
  if (!id || !rawId || type !== 'public-key') return null;
  if (!clientDataJSON || !authenticatorData || !signature) return null;
  return {
    id,
    rawId,
    type,
    authenticatorAttachment,
    response: {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    },
    clientExtensionResults: credential?.clientExtensionResults ?? null,
  };
}

function positiveInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.floor(value);
}

function positiveSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  return Math.floor(value);
}

function nonNegativeSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return Math.floor(value);
}

function isB64uString(input: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(input);
}

function parseRuntimePolicyScope(input: unknown): RuntimePolicyScope | undefined {
  const record = parseJsonObject(input);
  if (!record) return undefined;
  const orgId = toOptionalTrimmedString(record.orgId);
  const projectId = toOptionalTrimmedString(record.projectId);
  const envId = toOptionalTrimmedString(record.envId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return { orgId, projectId, envId, signingRootVersion };
}

function requireRuntimePolicyScope(input: unknown): RuntimePolicyScope {
  const scope = parseRuntimePolicyScope(input);
  if (scope) return scope;
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, runtimePolicyScope.envId, and runtimePolicyScope.signingRootVersion are required for Google Email OTP registration',
  );
}

function runtimePolicyScopeKey(scope: RuntimePolicyScope | undefined): string {
  if (!scope) return '';
  return `${scope.orgId}\n${scope.projectId}\n${scope.envId}\n${scope.signingRootVersion}`;
}

function parseGoogleEmailOtpRegistrationOfferCandidate(
  input: unknown,
): GoogleEmailOtpRegistrationOfferCandidateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const candidateId = toOptionalTrimmedString(record.candidateId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const collisionCounter = nonNegativeSafeInteger(record.collisionCounter);
  if (!candidateId || !walletId || collisionCounter == null) return null;
  return { candidateId, walletId, collisionCounter };
}

function parseGoogleEmailOtpRegistrationOfferCandidates(
  input: unknown,
): NonEmptyGoogleEmailOtpRegistrationOfferCandidates | null {
  if (!Array.isArray(input)) return null;
  const candidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
  for (const item of input) {
    const candidate = parseGoogleEmailOtpRegistrationOfferCandidate(item);
    if (!candidate) return null;
    candidates.push(candidate);
  }
  const first = candidates[0];
  if (!first) return null;
  return [first, ...candidates.slice(1)];
}

function googleEmailOtpRegistrationOfferContainsCandidate(input: {
  readonly candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly candidateId: string;
}): boolean {
  for (const candidate of input.candidates) {
    if (candidate.candidateId === input.candidateId) return true;
  }
  return false;
}

function googleEmailOtpRegistrationAttemptState(
  input: unknown,
): GoogleEmailOtpRegistrationAttemptRecord['state'] | null {
  const state = toOptionalTrimmedString(input);
  switch (state) {
    case 'started':
    case 'key_finalized':
    case 'active':
    case 'abandoned':
    case 'failed':
    case 'expired':
      return state;
    default:
      return null;
  }
}

type GoogleEmailOtpRegistrationAttemptParseFields = {
  readonly attemptId: string;
  readonly providerSubject: string;
  readonly email: string;
  readonly walletId: string;
  readonly offerId: string;
  readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly selectedCandidateId: string;
  readonly appSessionVersion: string;
  readonly authProvider: string;
  readonly accountIdSlugVersion: 'hmac_readable_v1';
  readonly walletIdDerivationNonce: string;
  readonly collisionCounter: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly expiresAtMs: number;
  readonly runtimePolicyScope?: RuntimePolicyScope;
};

function startedGoogleEmailOtpRegistrationAttemptRecord(
  input: GoogleEmailOtpRegistrationAttemptParseFields,
): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'started',
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

function keyFinalizedGoogleEmailOtpRegistrationAttemptRecord(
  input: GoogleEmailOtpRegistrationAttemptParseFields & { readonly finalizedPublicKey: string },
): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: input.finalizedPublicKey,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

function terminalGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly fields: GoogleEmailOtpRegistrationAttemptParseFields;
  readonly state: 'active' | 'abandoned' | 'failed' | 'expired';
  readonly finalizedPublicKey?: string;
  readonly failureCode?: string;
}): GoogleEmailOtpRegistrationAttemptRecord | null {
  const fields = input.fields;
  switch (input.state) {
    case 'active':
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'active',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
      };
    case 'abandoned':
      if (!input.failureCode) return null;
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'abandoned',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        failureCode: input.failureCode,
      };
    case 'failed':
      if (!input.failureCode) return null;
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'failed',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        failureCode: input.failureCode,
      };
    case 'expired':
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'expired',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        ...(input.failureCode ? { failureCode: input.failureCode } : {}),
      };
  }
}

function googleEmailOtpRegistrationAttemptFields(
  record: GoogleEmailOtpRegistrationAttemptRecord,
): GoogleEmailOtpRegistrationAttemptParseFields {
  return {
    attemptId: record.attemptId,
    providerSubject: record.providerSubject,
    email: record.email,
    walletId: record.walletId,
    offerId: record.offerId,
    offerCandidates: record.offerCandidates,
    selectedCandidateId: record.selectedCandidateId,
    appSessionVersion: record.appSessionVersion,
    authProvider: record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: record.walletIdDerivationNonce,
    collisionCounter: record.collisionCounter,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
    expiresAtMs: record.expiresAtMs,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
  };
}

function activeGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  const terminal = terminalGoogleEmailOtpRegistrationAttemptRecord({
    fields: {
      ...googleEmailOtpRegistrationAttemptFields(input.record),
      updatedAtMs: input.updatedAtMs,
    },
    state: 'active',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
  });
  if (!terminal) throw new Error('Failed to build active Google Email OTP registration attempt');
  return terminal;
}

function expiredGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: GoogleEmailOtpRegistrationAttemptRecord;
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  const terminal = terminalGoogleEmailOtpRegistrationAttemptRecord({
    fields: {
      ...googleEmailOtpRegistrationAttemptFields(input.record),
      updatedAtMs: input.updatedAtMs,
    },
    state: 'expired',
    ...('finalizedPublicKey' in input.record && input.record.finalizedPublicKey
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    ...('failureCode' in input.record && input.record.failureCode
      ? { failureCode: input.record.failureCode }
      : {}),
  });
  if (!terminal) throw new Error('Failed to build expired Google Email OTP registration attempt');
  return terminal;
}

function failedGoogleEmailOtpRegistrationAttemptWithCode(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: string;
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  const terminal = terminalGoogleEmailOtpRegistrationAttemptRecord({
    fields: {
      ...googleEmailOtpRegistrationAttemptFields(input.record),
      updatedAtMs: input.updatedAtMs,
    },
    state: 'failed',
    failureCode: input.failureCode,
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
  });
  if (!terminal) throw new Error('Failed to build failed Google Email OTP registration attempt');
  return terminal;
}

function parseGoogleEmailOtpRegistrationAttemptRecord(
  input: unknown,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const attemptId = toOptionalTrimmedString(record.attemptId);
  const providerSubject = toOptionalTrimmedString(record.providerSubject);
  const email = toOptionalTrimmedString(record.email);
  const walletId = toOptionalTrimmedString(record.walletId);
  const offerId = toOptionalTrimmedString(record.offerId);
  const offerCandidates = parseGoogleEmailOtpRegistrationOfferCandidates(record.offerCandidates);
  const selectedCandidateId = toOptionalTrimmedString(record.selectedCandidateId);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const authProvider = toOptionalTrimmedString(record.authProvider);
  const accountIdSlugVersion = toOptionalTrimmedString(record.accountIdSlugVersion);
  const walletIdDerivationNonce = toOptionalTrimmedString(record.walletIdDerivationNonce);
  const collisionCounter = nonNegativeSafeInteger(record.collisionCounter);
  const state = googleEmailOtpRegistrationAttemptState(record.state);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const runtimePolicyScope = parseRuntimePolicyScope(record.runtimePolicyScope);
  const finalizedPublicKey = toOptionalTrimmedString(record.finalizedPublicKey);
  const failureCode = toOptionalTrimmedString(record.failureCode);
  if (
    version !== 'google_email_otp_registration_attempt_v1' ||
    !attemptId ||
    !providerSubject ||
    !email ||
    !walletId ||
    !offerId ||
    !offerCandidates ||
    !selectedCandidateId ||
    !googleEmailOtpRegistrationOfferContainsCandidate({
      candidates: offerCandidates,
      candidateId: selectedCandidateId,
    }) ||
    !appSessionVersion ||
    !authProvider ||
    accountIdSlugVersion !== 'hmac_readable_v1' ||
    !walletIdDerivationNonce ||
    !isB64uString(walletIdDerivationNonce) ||
    collisionCounter == null ||
    !state ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  if (state === 'key_finalized' && !finalizedPublicKey) return null;
  const fields: GoogleEmailOtpRegistrationAttemptParseFields = {
    attemptId,
    providerSubject,
    email,
    walletId,
    offerId,
    offerCandidates,
    selectedCandidateId,
    appSessionVersion,
    authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce,
    collisionCounter,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
  switch (state) {
    case 'started':
      return startedGoogleEmailOtpRegistrationAttemptRecord(fields);
    case 'key_finalized':
      return keyFinalizedGoogleEmailOtpRegistrationAttemptRecord({
        ...fields,
        finalizedPublicKey: finalizedPublicKey || '',
      });
    case 'active':
    case 'abandoned':
    case 'failed':
    case 'expired':
      return terminalGoogleEmailOtpRegistrationAttemptRecord({
        fields,
        state,
        ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
        ...(failureCode ? { failureCode } : {}),
      });
  }
}

function parseGoogleEmailOtpRegistrationAttemptRow(
  row: D1EmailOtpRegistrationAttemptRow | null,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseGoogleEmailOtpRegistrationAttemptRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !expiresAtMs || !updatedAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function registrationAttemptMatchesStartedScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope?: RuntimePolicyScope;
    readonly nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion === input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

function registrationAttemptMatchesReplacementScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope?: RuntimePolicyScope;
    readonly nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion !== input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

function googleEmailOtpRegistrationOfferWalletIdsJson(
  candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
): string {
  const walletIds: string[] = [];
  for (const candidate of candidates) walletIds.push(candidate.walletId);
  return JSON.stringify(walletIds);
}

function googleEmailOtpRegistrationOfferForResponse(
  input: Pick<
    PendingGoogleEmailOtpRegistrationAttemptRecord,
    'offerId' | 'offerCandidates' | 'selectedCandidateId'
  >,
): GoogleEmailOtpRegistrationOfferForResponse {
  const first = input.offerCandidates[0];
  const candidates: { readonly candidateId: string; readonly walletId: string }[] = [
    { candidateId: first.candidateId, walletId: first.walletId },
  ];
  for (let index = 1; index < input.offerCandidates.length; index += 1) {
    const candidate = input.offerCandidates[index];
    if (!candidate) continue;
    candidates.push({ candidateId: candidate.candidateId, walletId: candidate.walletId });
  }
  return {
    offerId: input.offerId,
    selectedCandidateId: input.selectedCandidateId,
    candidates: [candidates[0], ...candidates.slice(1)],
  };
}

function pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt(
  record: PendingGoogleEmailOtpRegistrationAttemptRecord,
  updatedAtMs: number,
): PendingGoogleEmailOtpRegistrationAttemptRecord {
  if (record.state === 'started') {
    return {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: record.attemptId,
      providerSubject: record.providerSubject,
      email: record.email,
      walletId: record.walletId,
      offerId: record.offerId,
      offerCandidates: record.offerCandidates,
      selectedCandidateId: record.selectedCandidateId,
      appSessionVersion: record.appSessionVersion,
      authProvider: record.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: record.walletIdDerivationNonce,
      collisionCounter: record.collisionCounter,
      state: 'started',
      createdAtMs: record.createdAtMs,
      updatedAtMs,
      expiresAtMs: record.expiresAtMs,
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    };
  }
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: record.attemptId,
    providerSubject: record.providerSubject,
    email: record.email,
    walletId: record.walletId,
    offerId: record.offerId,
    offerCandidates: record.offerCandidates,
    selectedCandidateId: record.selectedCandidateId,
    appSessionVersion: record.appSessionVersion,
    authProvider: record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: record.walletIdDerivationNonce,
    collisionCounter: record.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: record.finalizedPublicKey,
    createdAtMs: record.createdAtMs,
    updatedAtMs,
    expiresAtMs: record.expiresAtMs,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
  };
}

function abandonedGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: 'app_session_version_replaced' | 'offer_restarted_by_user';
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.record.attemptId,
    providerSubject: input.record.providerSubject,
    email: input.record.email,
    walletId: input.record.walletId,
    offerId: input.record.offerId,
    offerCandidates: input.record.offerCandidates,
    selectedCandidateId: input.record.selectedCandidateId,
    appSessionVersion: input.record.appSessionVersion,
    authProvider: input.record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.record.walletIdDerivationNonce,
    collisionCounter: input.record.collisionCounter,
    state: 'abandoned',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    failureCode: input.failureCode,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    ...(input.record.runtimePolicyScope
      ? { runtimePolicyScope: input.record.runtimePolicyScope }
      : {}),
  };
}

function failedGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: 'non_hmac_readable_wallet_id';
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.record.attemptId,
    providerSubject: input.record.providerSubject,
    email: input.record.email,
    walletId: input.record.walletId,
    offerId: input.record.offerId,
    offerCandidates: input.record.offerCandidates,
    selectedCandidateId: input.record.selectedCandidateId,
    appSessionVersion: input.record.appSessionVersion,
    authProvider: input.record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.record.walletIdDerivationNonce,
    collisionCounter: input.record.collisionCounter,
    state: 'failed',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    failureCode: input.failureCode,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    ...(input.record.runtimePolicyScope
      ? { runtimePolicyScope: input.record.runtimePolicyScope }
      : {}),
  };
}

function hasDifferentWalletIdentitySubject(input: {
  readonly subjects: readonly string[];
  readonly expectedWalletSubject: string;
}): boolean {
  for (const subject of input.subjects) {
    if (subject.startsWith('wallet:') && subject !== input.expectedWalletSubject) return true;
  }
  return false;
}

function googleEmailOtpStaleIdentityMapping(input: {
  readonly providerSubject: string;
  readonly linkedWalletId: string;
  readonly email?: string;
}): Extract<ResolveGoogleEmailOtpSessionResult, { readonly ok: false }> {
  return {
    ok: false,
    mode: 'stale_identity_mapping',
    code: 'stale_identity_mapping',
    walletId: input.linkedWalletId,
    providerSubject: input.providerSubject,
    ...(input.email ? { email: input.email } : {}),
    message:
      'Google Email OTP identity mapping is stale. Clear the stale identity mapping with the dev cleanup route before registering this Google account.',
  };
}

function optionalNonNegativeInteger(input: unknown): number | undefined {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

function parseAppSessionCreatedAt(input: unknown, fallback: number): number {
  const record = parseJsonObject(input);
  const value = positiveInteger(record?.createdAtMs);
  return value ?? fallback;
}

function parseIdentityCreatedAt(input: unknown, fallback: number): number {
  return positiveInteger(input) ?? fallback;
}

function parseIdentitySubjectCount(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function d1MutationChanges(result: D1ResultLike<unknown>): number {
  const value = result.meta?.changes ?? result.meta?.rows_written;
  return parseIdentitySubjectCount(value);
}

function identitySubjectRecord(input: {
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): IdentitySubjectRecord {
  return {
    version: 'identity_subject_v1',
    subject: input.subject,
    userId: input.userId,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function hasRecordField(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

function parseEmailOtpWalletEnrollmentRecord(
  input: unknown,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseJsonObject(input);
  if (!record || hasRecordField(record, 'enrollmentEscrowCiphertextB64u')) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const verifiedEmail = toOptionalTrimmedString(record.verifiedEmail)?.toLowerCase() || '';
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryWrappedEnrollmentEscrowCount = positiveSafeInteger(
    record.recoveryWrappedEnrollmentEscrowCount,
  );
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(record.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(record.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    record.thresholdEcdsaClientVerifyingShareB64u,
  );
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  if (
    version !== 'email_otp_wallet_enrollment_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !verifiedEmail ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryWrappedEnrollmentEscrowCount ||
    !clientUnlockPublicKeyB64u ||
    !unlockKeyVersion ||
    !thresholdEcdsaClientVerifyingShareB64u ||
    !createdAtMs ||
    !updatedAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId,
    providerUserId,
    orgId,
    verifiedEmail,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryWrappedEnrollmentEscrowCount,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
    createdAtMs,
    updatedAtMs,
  };
}

function parseEmailOtpWalletEnrollmentRow(
  row: D1EmailOtpEnrollmentRow | null,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseEmailOtpWalletEnrollmentRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function optionalPositiveSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return positiveSafeInteger(record[field]);
}

function optionalNonNegativeSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return nonNegativeSafeInteger(record[field]);
}

function parseEmailOtpAuthStateRecord(input: unknown): EmailOtpAuthStateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const otpFailureCount = optionalNonNegativeSafeIntegerField(record, 'otpFailureCount');
  const lastOtpFailureAtMs = optionalPositiveSafeIntegerField(record, 'lastOtpFailureAtMs');
  const otpLockedUntilMs = optionalPositiveSafeIntegerField(record, 'otpLockedUntilMs');
  const lastEmailOtpLoginAtMs = optionalPositiveSafeIntegerField(
    record,
    'lastEmailOtpLoginAtMs',
  );
  const lastStrongAuthAtMs = optionalPositiveSafeIntegerField(record, 'lastStrongAuthAtMs');
  if (
    version !== 'email_otp_auth_state_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !createdAtMs ||
    !updatedAtMs ||
    otpFailureCount === null ||
    lastOtpFailureAtMs === null ||
    otpLockedUntilMs === null ||
    lastEmailOtpLoginAtMs === null ||
    lastStrongAuthAtMs === null ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_auth_state_v1',
    walletId,
    providerUserId,
    orgId,
    createdAtMs,
    updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

function parseEmailOtpAuthStateRow(
  row: D1EmailOtpAuthStateRow | null,
): EmailOtpAuthStateRecord | null {
  const record = parseEmailOtpAuthStateRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function parseEmailOtpChallengeOperation(input: unknown): EmailOtpChallengeOperation | null {
  const operation = toOptionalTrimmedString(input);
  if (!operation) return null;
  if (isWalletEmailOtpLoginOperation(operation)) return operation;
  if (operation === WALLET_EMAIL_OTP_REGISTRATION_OPERATION) return operation;
  return null;
}

function parseEmailOtpChallengeAction(input: unknown): EmailOtpChallengeIssueAction | null {
  const action = toOptionalTrimmedString(input);
  switch (action) {
    case WALLET_EMAIL_OTP_ACTIONS.login:
    case WALLET_EMAIL_OTP_ACTIONS.registration:
    case WALLET_EMAIL_OTP_ACTIONS.deviceRecovery:
      return action;
    default:
      return null;
  }
}

function parseEmailOtpLoginOperation(input: unknown): EmailOtpLoginChallengeOperation {
  const operation = toOptionalTrimmedString(input);
  if (operation && isWalletEmailOtpLoginOperation(operation)) return operation;
  return WALLET_EMAIL_OTP_UNLOCK_OPERATION;
}

function emailOtpChallengePurposeIsValid(input: {
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): boolean {
  switch (input.action) {
    case WALLET_EMAIL_OTP_ACTIONS.login:
      return isWalletEmailOtpLoginOperation(input.operation);
    case WALLET_EMAIL_OTP_ACTIONS.registration:
      return input.operation === WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    case WALLET_EMAIL_OTP_ACTIONS.deviceRecovery:
      return input.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  }
}

function parseEmailOtpChallengeRecord(input: unknown): EmailOtpChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const challengeSubjectId = toOptionalTrimmedString(record.challengeSubjectId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const otpChannel = toOptionalTrimmedString(record.otpChannel);
  const email = toOptionalTrimmedString(record.email)?.toLowerCase() || '';
  const otpCode = toOptionalTrimmedString(record.otpCode);
  const sessionHash = toOptionalTrimmedString(record.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const action = parseEmailOtpChallengeAction(record.action);
  const operation = parseEmailOtpChallengeOperation(record.operation);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const attemptCount = nonNegativeSafeInteger(record.attemptCount);
  const maxAttempts = positiveSafeInteger(record.maxAttempts);
  if (
    version !== 'email_otp_challenge_v1' ||
    !challengeId ||
    !challengeSubjectId ||
    !walletId ||
    !email ||
    !otpCode ||
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !operation ||
    !emailOtpChallengePurposeIsValid({ action, operation }) ||
    otpChannel !== EMAIL_OTP_CHANNEL ||
    !createdAtMs ||
    !expiresAtMs ||
    attemptCount === null ||
    !maxAttempts ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_challenge_v1',
    challengeId,
    challengeSubjectId,
    walletId,
    ...(orgId ? { orgId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    email,
    otpCode,
    sessionHash,
    appSessionVersion,
    action,
    operation,
    createdAtMs,
    expiresAtMs,
    attemptCount,
    maxAttempts,
  };
}

function parseEmailOtpChallengeRow(
  row: D1EmailOtpChallengeRow | null,
): EmailOtpChallengeRecord | null {
  const record = parseEmailOtpChallengeRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

function parseEmailOtpUnlockChallengeRecord(
  input: unknown,
): EmailOtpUnlockChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    version !== 'email_otp_unlock_challenge_v1' ||
    !challengeId ||
    !walletId ||
    !userId ||
    !challengeB64u ||
    !createdAtMs ||
    !expiresAtMs ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId,
    walletId,
    userId,
    ...(orgId ? { orgId } : {}),
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

function parseEmailOtpUnlockChallengeRow(
  row: D1EmailOtpUnlockChallengeRow | null,
): EmailOtpUnlockChallengeRecord | null {
  const record = parseEmailOtpUnlockChallengeRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

function emailOtpChallengeContextValues(input: {
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): readonly unknown[] {
  return [
    input.challengeSubjectId,
    input.walletId,
    input.orgId,
    EMAIL_OTP_CHANNEL,
    input.sessionHash,
    input.appSessionVersion,
    input.action,
    input.operation,
  ];
}

function emailOtpChallengeRecord(input: {
  readonly challengeId: string;
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly email: string;
  readonly otpCode: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly maxAttempts: number;
}): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: input.challengeId,
    challengeSubjectId: input.challengeSubjectId,
    walletId: input.walletId,
    orgId: input.orgId,
    otpChannel: EMAIL_OTP_CHANNEL,
    email: input.email,
    otpCode: input.otpCode,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    action: input.action,
    operation: input.operation,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
    attemptCount: 0,
    maxAttempts: input.maxAttempts,
  };
}

function emailOtpGrantRecord(input: {
  readonly grantToken: string;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpGrantAction;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpGrantRecord {
  return {
    version: 'email_otp_grant_v1',
    grantToken: input.grantToken,
    userId: input.userId,
    walletId: input.walletId,
    orgId: input.orgId,
    challengeId: input.challengeId,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    action: input.action,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

function emailOtpUnlockChallengeRecord(input: {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpUnlockChallengeRecord {
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId: input.challengeId,
    walletId: input.walletId,
    userId: input.userId,
    orgId: input.orgId,
    challengeB64u: input.challengeB64u,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

function parseEmailOtpGrantRecord(input: unknown): EmailOtpGrantRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const grantToken = toOptionalTrimmedString(record.grantToken);
  const userId = toOptionalTrimmedString(record.userId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const otpChannel = toOptionalTrimmedString(record.otpChannel);
  const sessionHash = toOptionalTrimmedString(record.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const action = toOptionalTrimmedString(record.action);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    version !== 'email_otp_grant_v1' ||
    !grantToken ||
    !userId ||
    !walletId ||
    !challengeId ||
    otpChannel !== EMAIL_OTP_CHANNEL ||
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !issuedAtMs ||
    !expiresAtMs ||
    expiresAtMs <= issuedAtMs
  ) {
    return null;
  }
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.unseal &&
    action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery
  ) {
    return null;
  }
  return {
    version: 'email_otp_grant_v1',
    grantToken,
    userId,
    walletId,
    ...(orgId ? { orgId } : {}),
    challengeId,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion,
    action,
    issuedAtMs,
    expiresAtMs,
  };
}

function parseEmailOtpGrantRow(row: D1EmailOtpGrantRow | null): EmailOtpGrantRecord | null {
  const record = parseEmailOtpGrantRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

function parseEmailOtpRecoveryEscrowRecord(
  input: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const alg = toOptionalTrimmedString(record.alg);
  const secretKind = toOptionalTrimmedString(record.secretKind);
  const escrowKind = toOptionalTrimmedString(record.escrowKind);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const authSubjectId = toOptionalTrimmedString(record.authSubjectId);
  const authMethod = toOptionalTrimmedString(record.authMethod);
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryKeyId = toOptionalTrimmedString(record.recoveryKeyId);
  const recoveryKeyLabel = toOptionalTrimmedString(record.recoveryKeyLabel);
  const recoveryKeyStatus = toOptionalTrimmedString(record.recoveryKeyStatus);
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    record.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(record.aadHashB64u);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const consumedAtMs =
    record.consumedAtMs == null ? undefined : positiveSafeInteger(record.consumedAtMs);
  const revokedAtMs =
    record.revokedAtMs == null ? undefined : positiveSafeInteger(record.revokedAtMs);
  if (
    version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1' ||
    alg !== EMAIL_OTP_RECOVERY_WRAP_ALG ||
    secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND ||
    escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND ||
    !walletId ||
    !userId ||
    !authSubjectId ||
    authMethod !== 'google_sso_email_otp' ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryKeyId ||
    !nonceB64u ||
    !wrappedDeviceEnrollmentEscrowB64u ||
    !aadHashB64u ||
    !recoveryKeyStatus ||
    !issuedAtMs ||
    !updatedAtMs ||
    userId !== authSubjectId ||
    !isB64uString(nonceB64u) ||
    !isB64uString(wrappedDeviceEnrollmentEscrowB64u) ||
    !isB64uString(aadHashB64u) ||
    hasRecordField(record, 'acknowledgedAtMs') ||
    hasRecordField(record, 'abandonedAtMs') ||
    hasRecordField(record, 'cleanupReason') ||
    updatedAtMs < issuedAtMs
  ) {
    return null;
  }
  const base = {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1' as const,
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId,
    userId,
    authSubjectId,
    authMethod: 'google_sso_email_otp' as const,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryKeyId,
    ...(recoveryKeyLabel ? { recoveryKeyLabel } : {}),
    nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u,
    issuedAtMs,
    updatedAtMs,
  };
  switch (recoveryKeyStatus) {
    case 'active':
      if (consumedAtMs !== undefined || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus };
    case 'consumed':
      if (consumedAtMs == null || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus, consumedAtMs };
    case 'revoked':
      if (consumedAtMs !== undefined || revokedAtMs == null) return null;
      return { ...base, recoveryKeyStatus, revokedAtMs };
    default:
      return null;
  }
}

function parseEmailOtpRecoveryEnrollmentEscrowBoundary(
  input: unknown,
): EmailOtpRecoveryEnrollmentEscrowBoundary | null {
  const record = parseEmailOtpRecoveryEscrowRecord(input);
  if (!record) return null;
  return {
    record,
    binding: buildEmailOtpRecoveryWrapBinding({
      walletId: record.walletId,
      userId: record.userId,
      authSubjectId: record.authSubjectId,
      authMethod: record.authMethod,
      enrollmentId: record.enrollmentId,
      enrollmentVersion: record.enrollmentVersion,
      enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      recoveryKeyId: record.recoveryKeyId,
    }),
  };
}

function parseEmailOtpRecoveryEscrowRow(
  row: D1EmailOtpRecoveryEscrowRow | null,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseEmailOtpRecoveryEscrowRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function emailOtpRecoveryEscrowMatchesEnrollment(input: {
  readonly escrow: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): boolean {
  return (
    input.escrow.walletId === input.enrollment.walletId &&
    input.escrow.userId === input.enrollment.providerUserId &&
    input.escrow.authSubjectId === input.enrollment.providerUserId &&
    input.escrow.enrollmentId === input.enrollment.enrollmentId &&
    input.escrow.enrollmentVersion === input.enrollment.enrollmentVersion &&
    input.escrow.enrollmentSealKeyVersion === input.enrollment.enrollmentSealKeyVersion &&
    input.escrow.signingRootId === input.enrollment.signingRootId &&
    input.escrow.signingRootVersion === input.enrollment.signingRootVersion
  );
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function parseJwtSegmentJson(input: string | undefined): Record<string, unknown> | null {
  if (!input) return null;
  try {
    const decoded = base64UrlDecode(input);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(decoded));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseRs256JwtForVerification(input: {
  readonly token: string;
  readonly tokenLabel: string;
}): ParsedRs256JwtResult {
  const parts = input.token.split('.');
  if (parts.length !== 3) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `${input.tokenLabel} must be a JWT (3 segments)`,
    };
  }
  const headerB64u = parts[0] || '';
  const payloadB64u = parts[1] || '';
  const signatureB64u = parts[2] || '';
  const header = parseJwtSegmentJson(headerB64u);
  if (!header) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `Invalid ${input.tokenLabel} header encoding`,
    };
  }
  const payload = parseJwtSegmentJson(payloadB64u);
  if (!payload) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `Invalid ${input.tokenLabel} payload encoding`,
    };
  }

  const kid = toOptionalTrimmedString(header.kid);
  const alg = toOptionalTrimmedString(header.alg);
  if (!kid) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `${input.tokenLabel} header.kid is required`,
    };
  }
  if (alg !== 'RS256') {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `${input.tokenLabel} header.alg must be RS256`,
    };
  }

  return {
    ok: true,
    jwt: {
      headerB64u,
      payloadB64u,
      signatureB64u,
      payload,
      kid,
    },
  };
}

async function verifyRs256JwtSignature(input: {
  readonly subtle: SubtleCrypto;
  readonly jwt: ParsedRs256Jwt;
  readonly jwk: JsonWebKey;
  readonly tokenLabel: string;
  readonly invalidSignatureMessage: string;
}): Promise<{ readonly ok: true } | JwtVerificationFailure> {
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(input.jwt.signatureB64u);
  } catch {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: `Invalid ${input.tokenLabel} signature encoding`,
    };
  }
  const dataBytes = new TextEncoder().encode(`${input.jwt.headerB64u}.${input.jwt.payloadB64u}`);
  const key = await input.subtle.importKey(
    'jwk',
    input.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const verified = await input.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    toArrayBufferCopy(signatureBytes),
    toArrayBufferCopy(dataBytes),
  );
  if (!verified) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_signature',
      message: input.invalidSignatureMessage,
    };
  }
  return { ok: true };
}

function parseJwtAud(input: unknown): string[] {
  const values: string[] = [];
  if (Array.isArray(input)) {
    for (const item of input) {
      const value = toOptionalTrimmedString(item);
      if (value) values.push(value);
    }
    return values;
  }
  const value = toOptionalTrimmedString(input);
  return value ? [value] : [];
}

function parseCacheControlMaxAgeSec(input: unknown): number | null {
  const header = toOptionalTrimmedString(input);
  if (!header) return null;
  for (const part of header.split(',')) {
    const segment = part.trim().toLowerCase();
    if (!segment.startsWith('max-age=')) continue;
    const value = Number(segment.slice('max-age='.length));
    if (Number.isFinite(value) && value > 0) return Math.floor(value);
  }
  return null;
}

function oidcIssuerConfigForTokenIssuer(input: {
  readonly issuers: readonly CloudflareD1OidcExchangeIssuerConfig[];
  readonly issuer: string;
}): CloudflareD1OidcExchangeIssuerConfig | null {
  for (const candidate of input.issuers) {
    if (normalizedOidcIssuer(candidate.issuer) === input.issuer) return candidate;
  }
  return null;
}

function parseGoogleJwks(input: unknown): Map<string, JsonWebKey> | null {
  if (!isRecord(input)) return null;
  const rawKeys = input.keys;
  if (!Array.isArray(rawKeys)) return null;
  const keysByKid = new Map<string, JsonWebKey>();
  for (const rawKey of rawKeys) {
    if (!isRecord(rawKey)) continue;
    const kid = toOptionalTrimmedString(rawKey.kid);
    const kty = toOptionalTrimmedString(rawKey.kty);
    const use = toOptionalTrimmedString(rawKey.use);
    const alg = toOptionalTrimmedString(rawKey.alg);
    const n = toOptionalTrimmedString(rawKey.n);
    const e = toOptionalTrimmedString(rawKey.e);
    if (!kid || kty !== 'RSA' || use !== 'sig' || alg !== 'RS256' || !n || !e) continue;
    keysByKid.set(kid, {
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n,
      e,
    });
  }
  return keysByKid.size > 0 ? keysByKid : null;
}

function parseOidcJwks(input: unknown): Map<string, JsonWebKey> | null {
  if (!isRecord(input)) return null;
  const rawKeys = input.keys;
  if (!Array.isArray(rawKeys)) return null;
  const keysByKid = new Map<string, JsonWebKey>();
  for (const rawKey of rawKeys) {
    if (!isRecord(rawKey)) continue;
    const kid = toOptionalTrimmedString(rawKey.kid);
    const kty = toOptionalTrimmedString(rawKey.kty);
    const use = toOptionalTrimmedString(rawKey.use);
    const alg = toOptionalTrimmedString(rawKey.alg);
    const n = toOptionalTrimmedString(rawKey.n);
    const e = toOptionalTrimmedString(rawKey.e);
    if (!kid || kty !== 'RSA' || !n || !e) continue;
    if (use && use !== 'sig') continue;
    if (alg && alg !== 'RS256') continue;
    keysByKid.set(kid, {
      kty: 'RSA',
      ...(use ? { use } : {}),
      alg: 'RS256',
      n,
      e,
    });
  }
  return keysByKid.size > 0 ? keysByKid : null;
}

function parseBooleanJwtClaim(input: unknown): boolean | undefined {
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

async function sha256BytesPortable(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.digest === 'function') {
    return new Uint8Array(await subtle.digest('SHA-256', toArrayBufferCopy(input)));
  }
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { createHash } = await import('node:crypto');
    return Uint8Array.from(createHash('sha256').update(input).digest());
  }
  throw new Error('SHA-256 digest is unavailable in this runtime');
}

function invalidRecoveryRotationBody(message: string): RotateEmailOtpRecoveryKeysResult {
  return { ok: false, code: 'invalid_body', message };
}

function recoveryRotationBindingMismatch(): RotateEmailOtpRecoveryKeysResult {
  return {
    ok: false,
    code: 'recovery_rotation_binding_mismatch',
    message: 'Recovery-code rotation does not match the active Email OTP enrollment',
  };
}

function recoveryRotationInputObject(input: unknown): Record<string, unknown> | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  return input as Record<string, unknown>;
}

function revokedEmailOtpRecoveryEscrowRecord(input: {
  readonly record: Extract<
    EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    { readonly recoveryKeyStatus: 'active' }
  >;
  readonly revokedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  return {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    recoveryKeyStatus: 'revoked',
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.revokedAtMs,
    revokedAtMs: input.revokedAtMs,
  };
}

function emailOtpRecoveryEscrowWithUpdatedAt(input: {
  readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly updatedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const base = {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.updatedAtMs,
  };
  switch (input.record.recoveryKeyStatus) {
    case 'active':
      return {
        ...base,
        recoveryKeyStatus: 'active',
      };
    case 'consumed':
      return {
        ...base,
        recoveryKeyStatus: 'consumed',
        consumedAtMs: input.record.consumedAtMs,
      };
    case 'revoked':
      return {
        ...base,
        recoveryKeyStatus: 'revoked',
        revokedAtMs: input.record.revokedAtMs,
      };
  }
}

async function activeEmailOtpRecoveryRotationEscrowRecord(input: {
  readonly raw: unknown;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly issuedAtMs: number;
  readonly recoveryKeyIds: Set<string>;
  readonly nonceB64us: Set<string>;
}): Promise<
  | { readonly ok: true; readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord }
  | { readonly ok: false; readonly result: RotateEmailOtpRecoveryKeysResult }
> {
  const obj = recoveryRotationInputObject(input.raw);
  if (!obj) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Invalid recovery escrow input'),
    };
  }
  const recoveryKeyId = toOptionalTrimmedString(obj.recoveryKeyId);
  const nonceB64u = toOptionalTrimmedString(obj.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    obj.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(obj.aadHashB64u);
  if (!recoveryKeyId || !nonceB64u || !wrappedDeviceEnrollmentEscrowB64u || !aadHashB64u) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation escrow input is missing required fields',
      ),
    };
  }
  if (input.recoveryKeyIds.has(recoveryKeyId)) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation recoveryKeyId values must be unique',
      ),
    };
  }
  if (input.nonceB64us.has(nonceB64u)) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Recovery rotation nonce values must be unique'),
    };
  }
  try {
    base64UrlDecode(nonceB64u);
    base64UrlDecode(wrappedDeviceEnrollmentEscrowB64u);
    base64UrlDecode(aadHashB64u);
  } catch {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation escrow input must use base64url fields',
      ),
    };
  }
  const binding = buildEmailOtpRecoveryWrapBinding({
    walletId: input.enrollment.walletId,
    userId: input.enrollment.providerUserId,
    authSubjectId: input.enrollment.providerUserId,
    authMethod: 'google_sso_email_otp',
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentVersion: input.enrollment.enrollmentVersion,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    signingRootId: input.enrollment.signingRootId,
    signingRootVersion: input.enrollment.signingRootVersion,
    recoveryKeyId,
  });
  const expectedAadHashB64u = base64UrlEncode(
    await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)),
  );
  if (aadHashB64u !== expectedAadHashB64u) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation aadHashB64u does not match enrollment metadata',
      ),
    };
  }
  input.recoveryKeyIds.add(recoveryKeyId);
  input.nonceB64us.add(nonceB64u);
  return {
    ok: true,
    record: {
      version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
      alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
      secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
      escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
      walletId: input.enrollment.walletId,
      userId: input.enrollment.providerUserId,
      authSubjectId: input.enrollment.providerUserId,
      authMethod: 'google_sso_email_otp',
      enrollmentId: input.enrollment.enrollmentId,
      enrollmentVersion: input.enrollment.enrollmentVersion,
      enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
      signingRootId: input.enrollment.signingRootId,
      signingRootVersion: input.enrollment.signingRootVersion,
      recoveryKeyId,
      recoveryKeyStatus: 'active',
      nonceB64u,
      wrappedDeviceEnrollmentEscrowB64u,
      aadHashB64u,
      issuedAtMs: input.issuedAtMs,
      updatedAtMs: input.issuedAtMs,
    },
  };
}

function countActiveEmailOtpRecoveryEscrows(
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
): number {
  let count = 0;
  for (const record of records) {
    if (activeEmailOtpRecoveryEscrow(record)) count += 1;
  }
  return count;
}

function normalizeHexLike(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function normalizeAccountAddress(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function parseRecordMetadata(input: unknown): Record<string, unknown> | undefined {
  if (!isRecord(input)) return undefined;
  return { ...input };
}

function parseRecoverySessionStatus(input: unknown): RecoverySessionStatus | null {
  const status = toOptionalTrimmedString(input);
  switch (status) {
    case 'prepared':
    case 'verified':
    case 'near_recovered':
    case 'evm_recovering':
    case 'completed':
    case 'failed':
    case 'cancelled':
      return status;
    default:
      return null;
  }
}

function parseRecoveryExecutionStatus(input: unknown): RecoveryExecutionStatus | null {
  const status = toOptionalTrimmedString(input);
  switch (status) {
    case 'pending':
    case 'submitted':
    case 'confirmed':
    case 'failed':
    case 'skipped':
      return status;
    default:
      return null;
  }
}

function parseRecoverySessionRecord(input: unknown): RecoverySessionRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const sessionId = toOptionalTrimmedString(record.sessionId);
  const userId = toOptionalTrimmedString(record.userId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const signerSlot = positiveSafeInteger(record.signerSlot);
  const status = parseRecoverySessionStatus(record.status);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const newNearPublicKey = toOptionalTrimmedString(record.newNearPublicKey);
  const newEvmOwnerAddress = normalizeHexLike(record.newEvmOwnerAddress);
  const recoveryDeadlineEpochSeconds = positiveSafeInteger(record.recoveryDeadlineEpochSeconds);
  const recoveryEmailPayloadHash = toOptionalTrimmedString(record.recoveryEmailPayloadHash);
  const verifiedRecoveryPayloadHash = toOptionalTrimmedString(record.verifiedRecoveryPayloadHash);
  const verifiedRecoveryArtifactHash = toOptionalTrimmedString(record.verifiedRecoveryArtifactHash);
  const scope = toOptionalTrimmedString(record.scope);
  const metadata = parseRecordMetadata(record.metadata);
  if (
    version !== 'recovery_session_v1' ||
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !signerSlot ||
    !status ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs ||
    !newNearPublicKey ||
    !newEvmOwnerAddress ||
    !recoveryDeadlineEpochSeconds ||
    !recoveryEmailPayloadHash
  ) {
    return null;
  }
  return {
    version: 'recovery_session_v1',
    sessionId,
    userId,
    nearAccountId,
    signerSlot,
    status,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    newNearPublicKey,
    newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash,
    ...(verifiedRecoveryPayloadHash ? { verifiedRecoveryPayloadHash } : {}),
    ...(verifiedRecoveryArtifactHash ? { verifiedRecoveryArtifactHash } : {}),
    ...(scope ? { scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function parseRecoveryExecutionRecord(input: unknown): RecoveryExecutionRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const sessionId = toOptionalTrimmedString(record.sessionId);
  const userId = toOptionalTrimmedString(record.userId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const chainIdKey = toOptionalTrimmedString(record.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeAccountAddress(record.accountAddress);
  const action = toOptionalTrimmedString(record.action);
  const status = parseRecoveryExecutionStatus(record.status);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const transactionHash = toOptionalTrimmedString(record.transactionHash);
  const errorCode = toOptionalTrimmedString(record.errorCode);
  const errorMessage = toOptionalTrimmedString(record.errorMessage);
  const metadata = parseRecordMetadata(record.metadata);
  if (
    version !== 'recovery_execution_v1' ||
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !chainIdKey ||
    !accountAddress ||
    !action ||
    !status ||
    !createdAtMs ||
    !updatedAtMs
  ) {
    return null;
  }
  return {
    version: 'recovery_execution_v1',
    sessionId,
    userId,
    nearAccountId,
    chainIdKey,
    accountAddress,
    action,
    status,
    createdAtMs,
    updatedAtMs,
    ...(transactionHash ? { transactionHash } : {}),
    ...(errorCode ? { errorCode } : {}),
    ...(errorMessage ? { errorMessage } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function recoverySessionWithStatus(input: {
  readonly record: RecoverySessionRecord;
  readonly status: RecoverySessionStatus;
  readonly updatedAtMs: number;
  readonly metadataPatch?: Record<string, unknown>;
}): RecoverySessionRecord {
  const metadata =
    input.metadataPatch
      ? { ...(input.record.metadata || {}), ...input.metadataPatch }
      : input.record.metadata
        ? { ...input.record.metadata }
        : undefined;
  return {
    version: 'recovery_session_v1',
    sessionId: input.record.sessionId,
    userId: input.record.userId,
    nearAccountId: input.record.nearAccountId,
    signerSlot: input.record.signerSlot,
    status: input.status,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    newNearPublicKey: input.record.newNearPublicKey,
    newEvmOwnerAddress: input.record.newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: input.record.recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash: input.record.recoveryEmailPayloadHash,
    ...(input.record.verifiedRecoveryPayloadHash
      ? { verifiedRecoveryPayloadHash: input.record.verifiedRecoveryPayloadHash }
      : {}),
    ...(input.record.verifiedRecoveryArtifactHash
      ? { verifiedRecoveryArtifactHash: input.record.verifiedRecoveryArtifactHash }
      : {}),
    ...(input.record.scope ? { scope: input.record.scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function resolveHostedOidcWalletScope(input: unknown): {
  readonly projectId: string;
  readonly envId: string;
} {
  const scope = isRecord(input) ? input : {};
  const orgId = toOptionalTrimmedString(scope.orgId);
  const projectId = toOptionalTrimmedString(scope.projectId);
  const envId = toOptionalTrimmedString(scope.envId);
  if (orgId && projectId && envId) return { projectId, envId };
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
  );
}

function codedError(code: string, message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

function parseBoundaryWalletIdForD1(input: unknown): string | null {
  const value = toOptionalTrimmedString(input);
  if (!value) return null;
  try {
    return String(walletIdFromString(value));
  } catch {
    return null;
  }
}

function appSessionRecord(input: {
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): AppSessionVersionRecord {
  return {
    version: 'app_session_version_v1',
    userId: input.userId,
    appSessionVersion: input.appSessionVersion,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function parseWebAuthnLoginChallengeRecord(input: unknown): WebAuthnLoginChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const userId = toOptionalTrimmedString(record.userId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_login_challenge_v1') return null;
  if (!challengeId || !userId || !rpId || !challengeB64u) return null;
  if (createdAtMs === null || expiresAtMs === null) return null;
  return {
    version: 'webauthn_login_challenge_v1',
    challengeId,
    userId,
    rpId,
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

function parseWebAuthnSyncChallengeRecord(input: unknown): WebAuthnSyncChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const expectedUserId = toOptionalTrimmedString(record.expectedUserId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_sync_challenge_v1') return null;
  if (!challengeId || !rpId || !challengeB64u) return null;
  if (createdAtMs === null || expiresAtMs === null) return null;
  return {
    version: 'webauthn_sync_challenge_v1',
    challengeId,
    rpId,
    ...(expectedUserId ? { expectedUserId } : {}),
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

function parseWebAuthnAuthenticator(
  row: D1AuthenticatorRow | null,
): WebAuthnAuthenticatorRecord | null {
  const credentialIdB64u = toOptionalTrimmedString(row?.credential_id_b64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(row?.credential_public_key_b64u);
  const counter = nonNegativeSafeInteger(row?.counter);
  const createdAtMs = positiveInteger(row?.created_at_ms);
  const updatedAtMs = positiveInteger(row?.updated_at_ms);
  if (!credentialIdB64u || !credentialPublicKeyB64u) return null;
  if (counter === null || createdAtMs === null || updatedAtMs === null) return null;
  return { credentialIdB64u, credentialPublicKeyB64u, counter, createdAtMs, updatedAtMs };
}

function optionalNumberArray(input: unknown): number[] | undefined {
  if (!Array.isArray(input)) return undefined;
  const values: number[] = [];
  for (const item of input) {
    const value = nonNegativeSafeInteger(item);
    if (value === null) return undefined;
    values.push(value);
  }
  return values;
}

function parseWebAuthnBinding(row: D1RecordJsonRow): WebAuthnCredentialBindingRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const userId = toOptionalTrimmedString(record.userId);
  const signerSlot = positiveInteger(record.signerSlot);
  if (!rpId || !credentialIdB64u || !userId || signerSlot === null) return null;
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const keyVersion = toOptionalTrimmedString(record.keyVersion);
  const clientParticipantId = optionalNonNegativeInteger(record.clientParticipantId);
  const relayerParticipantId = optionalNonNegativeInteger(record.relayerParticipantId);
  const participantIds = optionalNumberArray(record.participantIds);
  const createdAtMs = optionalNonNegativeInteger(record.createdAtMs);
  const updatedAtMs = optionalNonNegativeInteger(record.updatedAtMs);
  return {
    rpId,
    credentialIdB64u,
    userId,
    signerSlot,
    ...(nearAccountId ? { nearAccountId } : {}),
    ...(nearEd25519SigningKeyId ? { nearEd25519SigningKeyId } : {}),
    ...(publicKey ? { publicKey } : {}),
    ...(relayerKeyId ? { relayerKeyId } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(typeof record.recoveryExportCapable === 'boolean'
      ? { recoveryExportCapable: record.recoveryExportCapable }
      : {}),
    ...(clientParticipantId !== undefined ? { clientParticipantId } : {}),
    ...(relayerParticipantId !== undefined ? { relayerParticipantId } : {}),
    ...(participantIds ? { participantIds } : {}),
    ...(createdAtMs !== undefined ? { createdAtMs } : {}),
    ...(updatedAtMs !== undefined ? { updatedAtMs } : {}),
  };
}

function webAuthnSyncWalletBindingFromCredentialBinding(
  binding: WebAuthnCredentialBindingRecord,
): WebAuthnSyncWalletBinding | null {
  if (!binding.nearAccountId || !binding.nearEd25519SigningKeyId) return null;
  return {
    walletId: binding.userId,
    nearAccountId: binding.nearAccountId,
    nearEd25519SigningKeyId: binding.nearEd25519SigningKeyId,
    rpId: binding.rpId,
    signerSlot: binding.signerSlot,
  };
}

function parseNearPublicKey(row: D1RecordJsonRow): NearPublicKeyRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const kindRaw = toOptionalTrimmedString(record.kind);
  const kind = parseNearPublicKeyKind(kindRaw);
  if (!publicKey || !kind) return null;
  return {
    publicKey,
    kind,
    signerSlot: optionalNonNegativeInteger(record.signerSlot),
    credentialIdB64u: toOptionalTrimmedString(record.credentialIdB64u),
    rpId: toOptionalTrimmedString(record.rpId),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKeyKind(
  input: string | undefined,
): NearPublicKeyRecord['kind'] | null {
  switch (input) {
    case 'threshold':
    case 'local':
    case 'backup':
    case 'ephemeral':
      return input;
    default:
      return null;
  }
}

function maskEmail(email: string): string {
  const trimmed = email.trim().toLowerCase();
  const atIndex = trimmed.indexOf('@');
  if (atIndex <= 0 || atIndex === trimmed.length - 1) return 'hidden';
  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);
  const localMask =
    local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
  const domainParts = domain.split('.');
  const domainName = domainParts[0] || '';
  const domainMask =
    domainName.length <= 2
      ? `${domainName[0] || '*'}*`
      : `${domainName[0]}***${domainName.slice(-1)}`;
  return `${localMask}@${[domainMask, ...domainParts.slice(1)].join('.')}`;
}

function generateNumericOtp(length: number): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let code = '';
  for (const byte of bytes) code += String(byte % 10);
  return code;
}

function singletonRejectedDiagnostic(reason: string): Record<string, number> {
  return { [reason]: 1 };
}

async function unsupportedCloudflareD1NearAccessKeyList(): Promise<never> {
  throw new Error('Cloudflare D1 relay auth service does not support NEAR access-key reads');
}

async function unsupportedCloudflareD1NearTransactionDispatch(): Promise<never> {
  throw new Error('Cloudflare D1 relay auth service does not support NEAR transaction dispatch');
}

function emptyThresholdEcdsaKeyInventoryResult(input: {
  readonly userId: string;
  readonly inputCount: number;
  readonly rejectionReason: 'missing_scope' | 'threshold_service_missing';
}): ListThresholdEcdsaKeyIdentityTargetsForUserResult {
  return {
    records: [],
    diagnostics: {
      userId: input.userId,
      inputCount: input.inputCount,
      returnedCount: 0,
      thresholdServicePresent: false,
      rejected: singletonRejectedDiagnostic(input.rejectionReason),
    },
  };
}

function clampedEmailOtpUnlockTtlMs(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return 5 * 60_000;
  return Math.min(Math.max(Math.floor(value), 10_000), 10 * 60_000);
}

function decodeFixedBase64Url(input: string, byteLength: number): Uint8Array | null {
  try {
    const decoded = base64UrlDecode(input);
    return decoded.length === byteLength ? decoded : null;
  } catch {
    return null;
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] || 0) ^ (right[index] || 0);
  }
  return difference === 0;
}

function emailOtpRateLimitKeys(input: {
  readonly scope: EmailOtpRateLimitScope;
  readonly action?: string;
  readonly policy: EmailOtpRateLimitPolicy;
  readonly userId?: string;
  readonly walletId?: string;
  readonly providerSubject?: string;
  readonly orgId?: string;
  readonly clientIp?: string;
}): readonly string[] {
  const keySuffix = [
    `scope=${input.scope}`,
    `action=${input.action || 'default'}`,
    `limit=${input.policy.limit}`,
    `windowMs=${input.policy.windowMs}`,
  ].join(':');
  return [
    input.clientIp ? `${keySuffix}:ip:${input.clientIp}` : '',
    input.userId ? `${keySuffix}:user:${input.userId}` : '',
    input.walletId ? `${keySuffix}:wallet:${input.walletId}` : '',
    input.providerSubject ? `${keySuffix}:provider:${input.providerSubject}` : '',
    input.orgId ? `${keySuffix}:org:${input.orgId}` : '',
  ].filter(Boolean);
}

function emailOtpRateLimitExceeded(row: D1EmailOtpRateLimitRow | null): {
  ok: false;
  code: 'rate_limited';
  message: string;
  retryAfterMs?: number;
  resetAtMs?: number;
} {
  const resetAtMs = positiveSafeInteger(row?.reset_at_ms);
  const retryAfterMs = resetAtMs ? Math.max(0, resetAtMs - Date.now()) : undefined;
  return {
    ok: false,
    code: 'rate_limited',
    message: 'Email OTP rate limit exceeded',
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    ...(resetAtMs ? { resetAtMs } : {}),
  };
}

function emailOtpChallengeInvalidOrExpired(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'challenge_expired_or_invalid',
    message: 'Email OTP challenge expired or invalid',
  };
}

function emailOtpChallengeBindingMismatchCode(input: {
  readonly record: EmailOtpChallengeRecord;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): string | null {
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return 'challenge_channel_mismatch';
  if (input.record.challengeSubjectId !== input.userId) return 'challenge_subject_mismatch';
  if (input.record.walletId !== input.walletId) return 'challenge_wallet_mismatch';
  if (String(input.record.orgId || '') !== input.orgId) return 'challenge_org_mismatch';
  if (input.record.action !== input.action) return 'challenge_purpose_mismatch';
  if (input.record.operation !== input.operation) return 'challenge_purpose_mismatch';
  if (input.record.sessionHash !== input.sessionHash) return 'challenge_session_mismatch';
  if (input.record.appSessionVersion !== input.appSessionVersion) {
    return 'challenge_session_mismatch';
  }
  return null;
}

function emailOtpRegistrationChallengeBindingMismatchCode(input: {
  readonly record: EmailOtpChallengeRecord;
  readonly providerSubject: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly proofEmail: string;
}): string | null {
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return 'challenge_channel_mismatch';
  if (input.record.challengeSubjectId !== input.providerSubject) {
    return 'challenge_subject_mismatch';
  }
  if (toOptionalTrimmedString(input.record.email)?.toLowerCase() !== input.proofEmail) {
    return 'challenge_email_mismatch';
  }
  if (String(input.record.orgId || '') !== input.orgId) return 'challenge_org_mismatch';
  if (input.record.action !== WALLET_EMAIL_OTP_ACTIONS.registration) {
    return 'challenge_purpose_mismatch';
  }
  if (input.record.operation !== WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
    return 'challenge_purpose_mismatch';
  }
  if (input.record.walletId !== input.walletId) return 'challenge_wallet_mismatch';
  if (input.record.sessionHash !== input.sessionHash) return 'challenge_session_mismatch';
  if (input.record.appSessionVersion !== input.appSessionVersion) {
    return 'challenge_session_mismatch';
  }
  return null;
}

function redactEmailOtpRecoveryChallengeEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): EmailOtpRecoveryChallengeEscrow {
  return {
    version: record.version,
    alg: record.alg,
    secretKind: record.secretKind,
    escrowKind: record.escrowKind,
    walletId: record.walletId,
    userId: record.userId,
    authSubjectId: record.authSubjectId,
    authMethod: record.authMethod,
    enrollmentId: record.enrollmentId,
    enrollmentVersion: record.enrollmentVersion,
    enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    nonceB64u: record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: record.aadHashB64u,
  };
}

function activeEmailOtpRecoveryEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): record is Extract<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  { readonly recoveryKeyStatus: 'active' }
> {
  return record.recoveryKeyStatus === 'active';
}

function emailOtpChallengeWithAttemptCount(
  record: EmailOtpChallengeRecord,
  attemptCount: number,
): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: record.challengeId,
    challengeSubjectId: record.challengeSubjectId,
    walletId: record.walletId,
    ...(record.orgId ? { orgId: record.orgId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    email: record.email,
    otpCode: record.otpCode,
    sessionHash: record.sessionHash,
    appSessionVersion: record.appSessionVersion,
    action: record.action,
    operation: record.operation,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    attemptCount,
    maxAttempts: record.maxAttempts,
  };
}

class CloudflareD1RelayAuthMetadataService {
  private readonly options: NormalizedCloudflareD1RelayAuthServiceOptions;
  private readonly emailOtpMemoryOutbox = new Map<string, EmailOtpOutboxEntry>();
  private googleJwksCache: JsonWebKeyCache | null = null;
  private googleJwksFetchPromise: Promise<JsonWebKeyCache> | null = null;
  private readonly oidcJwksCacheByUrl = new Map<string, JsonWebKeyCache>();
  private readonly oidcJwksFetchPromiseByUrl = new Map<string, Promise<JsonWebKeyCache>>();
  private walletStore: WalletStore | null = null;
  private walletAuthMethodStore: WalletAuthMethodStore | null = null;
  private registrationCeremonyIntentStore: CloudflareD1RegistrationCeremonyIntentStore | null =
    null;
  private thresholdSigningService: ThresholdSigningService | null = null;
  private thresholdSigningServiceInitialized = false;

  constructor(input: CloudflareD1RelayAuthServiceOptions) {
    this.options = normalizeD1RelayAuthOptions(input);
  }

  async createRegistrationIntent(
    input: CreateRegistrationIntentInput,
  ): Promise<CreateRegistrationIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const rpId = toOptionalTrimmedString(input.request?.rpId);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };

      const signerSelection = normalizeRegistrationSignerSelection(input.request?.signerSelection);
      if (!signerSelection.ok) return signerSelection;
      const authMethod = normalizeRegistrationAuthMethodInput(input.request?.authMethod);
      if (!authMethod) {
        return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
      }

      const expiresAtMs = Date.now() + 5 * 60_000;
      const wallet = await this.resolveRegistrationIntentWalletId({
        store,
        wallet: input.request?.wallet,
        signerSelection: signerSelection.value,
        rpId,
        expiresAtMs,
      });
      if (!wallet.ok) return wallet;

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent = buildRegistrationIntent({
        walletId: wallet.walletId,
        rpId,
        authMethod,
        signerSelection: signerSelection.value,
        runtimePolicyScope,
      });
      const digestB64u = await computeRegistrationIntentDigestB64u(intent);
      const grant = registrationIntentGrantFromString(`rig_${secureRandomBase64Url(32)}`);
      await store.putIntent({
        kind: 'intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        expiresAtMs,
        ...intentScopeMetadata(input),
      });
      return {
        ok: true,
        intent,
        registrationIntentDigestB64u: digestB64u,
        registrationIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create registration intent',
      };
    }
  }

  async createAddSignerIntent(
    input: CreateAddSignerIntentInput,
  ): Promise<CreateAddSignerIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(input.request?.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const rpId = toOptionalTrimmedString(input.request?.rpId);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };

      const signerSelection = normalizeAddSignerSelection(input.request?.signerSelection, {
        normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
      });
      if (!signerSelection.ok) return signerSelection;

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent = buildAddSignerIntent({
        walletId,
        rpId,
        signerSelection: signerSelection.value,
        runtimePolicyScope,
      });
      const digestB64u = await computeAddSignerIntentDigestB64u(intent);
      const grant = addSignerIntentGrantFromString(`wasig_${secureRandomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await store.putAddSignerIntent({
        kind: 'add_signer_intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        expiresAtMs,
        ...intentScopeMetadata(input),
      });
      return {
        ok: true,
        intent,
        addSignerIntentDigestB64u: digestB64u,
        addSignerIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create add-signer intent',
      };
    }
  }

  async startWalletAddSigner(
    request: StartWalletAddSignerInput,
  ): Promise<WalletAddSignerStartResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(request.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addSignerIntentGrantFromString(
        toOptionalTrimmedString(request.addSignerIntentGrant) || '',
      );
      if (!grant) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant is required' };
      }
      const intentPreview = await store.getAddSignerIntent(grant);
      if (!intentPreview) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      if (request.intent.walletId !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-signer walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addSignerIntentDigestB64u);
      const requestDigest = await computeAddSignerIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'add-signer intent digest mismatch' };
      }
      if (intentPreview.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer start currently supports ECDSA signer selection',
        };
      }

      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const storedAuth = await this.resolveAddSignerExistingAuth({
        auth: request.auth,
        walletId,
        rpId: intentPreview.intent.rpId,
        intent: intentPreview.intent,
        walletAuthMethodStore,
      });
      if (!storedAuth.ok) return storedAuth;

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }

      const storedIntent = await store.takeAddSignerIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      const selection = storedIntent.intent.signerSelection;
      if (selection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer start currently supports ECDSA signer selection',
        };
      }
      const runtimePolicyScope = parseD1RuntimePolicyScope(storedIntent.intent.runtimePolicyScope);
      if (!runtimePolicyScope) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer requires a runtime policy scope',
        };
      }
      const signingRootId = storedIntent.signingRootId || deriveSigningRootId(runtimePolicyScope);
      const signingRootVersion =
        toOptionalTrimmedString(storedIntent.signingRootVersion) ||
        runtimePolicyScope.signingRootVersion;
      const chainTargets = normalizeThresholdEcdsaChainTargets(selection.ecdsa.chainTargets);
      if (!chainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer contains an invalid chain target',
        };
      }

      const addSignerCeremonyId = `wasc_${secureRandomBase64Url(24)}`;
      const walletKeyId = derivePlannedEvmFamilyWalletKeyId({
        walletId,
        signingRootId,
        signingRootVersion,
      });
      const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
        walletId,
        walletKeyId,
        signingRootId,
        signingRootVersion,
      });
      const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
        walletId,
        walletKeyId,
      });
      const ecdsa = {
        kind: 'evm_family_ecdsa_keygen' as const,
        chainTargets,
        prepare: {
          formatVersion: 'ecdsa-hss-role-local' as const,
          walletId,
          walletKeyId,
          ecdsaThresholdKeyId,
          signingRootId,
          signingRootVersion,
          keyScope: 'evm-family' as const,
          relayerKeyId,
          requestId: `${addSignerCeremonyId}:ecdsa`,
          thresholdSessionId: `tehss_${secureRandomBase64Url(24)}`,
          signingGrantId: `wss_${secureRandomBase64Url(24)}`,
          ttlMs: 10 * 60_000,
          remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
          participantIds: selection.ecdsa.participantIds,
          runtimePolicyScope,
        },
      };
      await store.putAddSignerCeremony({
        addSignerCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: runtimePolicyScope.orgId,
        signingRootId,
        signingRootVersion,
        expiresAtMs: Date.now() + 10 * 60_000,
        auth: storedAuth.auth,
        signerState: {
          kind: 'ecdsa_add_signer_prepared',
          hssKind: ecdsa.kind,
          chainTargets,
          prepare: ecdsa.prepare,
        },
      });
      return {
        ok: true,
        addSignerCeremonyId,
        intent: storedIntent.intent,
        ecdsa,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-signer ceremony',
      };
    }
  }

  async respondWalletAddSignerHss(
    request: RespondWalletAddSignerHssInput,
  ): Promise<WalletAddSignerHssRespondResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer respond currently supports ECDSA signer selection',
        };
      }
      if (!request.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'missing ECDSA add-signer HSS response',
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_add_signer_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA add-signer HSS response already recorded',
        };
      }
      const expected = ceremony.signerState.prepare;
      const actual = request.ecdsa.clientBootstrap;
      if (!isMatchingD1EcdsaClientBootstrap(expected, actual)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer bootstrap identity mismatch',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(
        toD1EcdsaHssClientBootstrapRequest(actual),
      );
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'hss_respond_failed',
          message: bootstrap.message || 'ECDSA add-signer HSS bootstrap failed',
        };
      }
      await store.updateAddSignerCeremony(
        buildD1EcdsaAddSignerRespondedCeremony({
          ceremony,
          bootstrap: bootstrap.value,
        }),
      );
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          bootstrap: bootstrap.value,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet add-signer ceremony',
      };
    }
  }

  async finalizeWalletAddSigner(
    request: FinalizeWalletAddSignerInput,
  ): Promise<WalletAddSignerFinalizeResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer finalize currently supports ECDSA signer selection',
        };
      }
      if (!request.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'missing ECDSA add-signer finalize input',
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_add_signer_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA add-signer HSS response is required before finalize',
        };
      }
      const bootstrap = ceremony.signerState.responded.bootstrap;
      const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
      if (expectedKeyHandles.some((keyHandle) => keyHandle !== bootstrap.keyHandle)) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA add-signer finalize expected key handle mismatch',
        };
      }
      const walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
        bootstrap,
        chainTargets: ceremony.signerState.chainTargets,
        errorContext: 'ECDSA add-signer finalize',
      });
      if (!walletKeyResult.ok) return walletKeyResult;

      const walletKeys = walletKeyResult.walletKeys;
      const signerWriteNow = Date.now();
      const wallet = buildD1WalletRecord({
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        now: signerWriteNow,
      });
      const walletSigners = buildD1WalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys,
        now: signerWriteNow,
      });
      const walletStore = this.getWalletStore();
      await walletStore.putSubject(wallet);
      await walletStore.putSigners(walletSigners);

      const consumed = await store.takeAddSignerCeremony(ceremony.addSignerCeremonyId);
      if (!consumed) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (consumed.signerState.kind !== 'ecdsa_add_signer_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA add-signer HSS response is required before finalize',
        };
      }
      return {
        ok: true,
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        ecdsa: {
          walletKeys,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-signer ceremony',
      };
    }
  }

  async createAddAuthMethodIntent(
    input: CreateAddAuthMethodIntentInput,
  ): Promise<CreateAddAuthMethodIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(input.request?.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const rpId = toOptionalTrimmedString(input.request?.rpId);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };
      const authMethod = normalizeAddAuthMethodInput(input.request?.authMethod);
      if (!authMethod) {
        return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
      }

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent = buildAddAuthMethodIntent({
        walletId,
        rpId,
        authMethod,
        runtimePolicyScope,
      });
      const digestB64u = await computeAddAuthMethodIntentDigestB64u(intent);
      const grant = addAuthMethodIntentGrantFromString(`waig_${secureRandomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await store.putAddAuthMethodIntent({
        kind: 'add_auth_method_intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        expiresAtMs,
        ...intentScopeMetadata(input),
      });
      return {
        ok: true,
        intent,
        addAuthMethodIntentDigestB64u: digestB64u,
        addAuthMethodIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create add-auth-method intent',
      };
    }
  }

  async startWalletAddAuthMethod(
    request: StartWalletAddAuthMethodInput,
  ): Promise<WalletAddAuthMethodStartResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(request.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addAuthMethodIntentGrantFromString(
        toOptionalTrimmedString(request.addAuthMethodIntentGrant) || '',
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant is required',
        };
      }
      const intentPreview = await store.getAddAuthMethodIntent(grant);
      if (!intentPreview) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      if (request.intent.walletId !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-auth-method walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addAuthMethodIntentDigestB64u);
      const requestDigest = await computeAddAuthMethodIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method intent digest mismatch',
        };
      }

      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const walletMethods = await walletAuthMethodStore.listForWallet({
        walletId,
        rpId: intentPreview.intent.rpId,
      });
      const activeWalletMethods = walletMethods.filter(activeWalletAuthMethodRecord);
      if (activeWalletMethods.length === 0) {
        return { ok: false, code: 'not_found', message: 'wallet has no active auth methods' };
      }

      const storedAuth = await this.resolveAddAuthMethodExistingAuth({
        auth: request.auth,
        walletId,
        rpId: intentPreview.intent.rpId,
        intent: intentPreview.intent,
        walletAuthMethodStore,
      });
      if (!storedAuth.ok) return storedAuth;

      const storedIntent = await store.takeAddAuthMethodIntent(grant);
      if (!storedIntent) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(storedIntent.expectedOrigin);
      if (request.authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const authority = await this.verifyAddAuthMethodAuthority({
        orgId: storedIntent.orgId,
        authority: request.authority,
        expectedDigestB64u: storedIntent.digestB64u,
        expectedOrigin: storedExpectedOrigin || '',
        intent: storedIntent.intent,
        walletAuthMethodStore,
      });
      if (!authority.ok) return authority;

      const addAuthMethodCeremonyId = `wauthc_${secureRandomBase64Url(24)}`;
      await store.putAddAuthMethodCeremony({
        addAuthMethodCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
        expiresAtMs: Date.now() + 10 * 60_000,
        auth: storedAuth.auth,
        authority: authority.authority,
      });
      return {
        ok: true,
        addAuthMethodCeremonyId,
        intent: storedIntent.intent,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-auth-method ceremony',
      };
    }
  }

  async finalizeWalletAddAuthMethod(
    request: FinalizeWalletAddAuthMethodInput,
  ): Promise<WalletAddAuthMethodFinalizeResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getAddAuthMethodCeremony(request.addAuthMethodCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
      }
      const duplicate = await this.findDuplicateAddAuthMethodAuthority(ceremony.authority);
      if (duplicate) return duplicate;
      const consumed = await store.takeAddAuthMethodCeremony(ceremony.addAuthMethodCeremonyId);
      if (!consumed) {
        return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
      }
      await this.persistAddAuthMethodAuthority({
        authority: consumed.authority,
        now: Date.now(),
      });
      return {
        ok: true,
        walletId: consumed.intent.walletId,
        rpId: consumed.intent.rpId,
        authMethod: {
          kind: consumed.authority.kind,
          status: 'active',
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-auth-method ceremony',
      };
    }
  }

  async listIdentities(input: ListIdentitiesInput): Promise<ListIdentitiesResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT subject
           FROM signer_identity_links
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY created_at_ms ASC`,
        [userId],
      ).all<D1IdentityRow>();
      const subjects: string[] = [];
      for (const row of result.results || []) {
        const subject = toOptionalTrimmedString(row.subject);
        if (subject) subjects.push(subject);
      }
      return { ok: true, subjects };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list identities',
      };
    }
  }

  async linkIdentity(input: LinkIdentityInput): Promise<LinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

      const now = Date.now();
      const existing = await this.readIdentityLinkBySubject(subject);
      const existingUserId = toOptionalTrimmedString(existing?.user_id);
      const createdAtMs = parseIdentityCreatedAt(existing?.created_at_ms, now);

      if (existingUserId && existingUserId !== userId) {
        return await this.moveIdentityIfAllowed({
          userId,
          subject,
          existingUserId,
          createdAtMs,
          updatedAtMs: now,
          allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
        });
      }

      await this.scopePrepare(
        `INSERT INTO signer_identity_links (
          namespace,
          org_id,
          project_id,
          env_id,
          subject,
          user_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, subject)
        DO UPDATE SET
          user_id = EXCLUDED.user_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
        WHERE signer_identity_links.user_id = EXCLUDED.user_id`,
        [
          subject,
          userId,
          JSON.stringify(identitySubjectRecord({ subject, userId, createdAtMs, updatedAtMs: now })),
          createdAtMs,
          now,
        ],
      ).run();

      const finalUserId = await this.readIdentityUserIdBySubject(subject);
      if (finalUserId === userId) return { ok: true };
      if (finalUserId) return identityAlreadyLinked();
      return { ok: false, code: 'internal', message: 'Failed to link identity' };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to link identity',
      };
    }
  }

  async unlinkIdentity(input: UnlinkIdentityInput): Promise<UnlinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

      const deleted = d1MutationChanges(
        await this.options.database
          .prepare(
            `DELETE FROM signer_identity_links
              WHERE namespace = ?
                AND org_id = ?
                AND project_id = ?
                AND env_id = ?
                AND subject = ?
                AND user_id = ?
                AND (
                  SELECT COUNT(*)
                    FROM signer_identity_links
                   WHERE namespace = ?
                     AND org_id = ?
                     AND project_id = ?
                     AND env_id = ?
                     AND user_id = ?
                ) > 1`,
          )
          .bind(
            ...this.scopeValues([subject, userId]),
            ...this.scopeValues([userId]),
          )
          .run(),
      );
      if (deleted > 0) return { ok: true };

      const existingUserId = await this.readIdentityUserIdBySubject(subject);
      if (existingUserId !== userId) {
        return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
      }
      const subjectCount = await this.readIdentitySubjectCountForUserId(userId);
      if (subjectCount <= 1) {
        return {
          ok: false,
          code: 'cannot_unlink_last_identity',
          message: 'Refusing to remove the last remaining identity',
        };
      }
      return { ok: false, code: 'internal', message: 'Failed to unlink identity' };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to unlink identity',
      };
    }
  }

  async resolveOidcWalletId(
    input: ResolveOidcWalletIdInput,
  ): Promise<ResolveOidcWalletIdResult> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject) {
      throw new Error('Cannot resolve OIDC wallet id without provider subject');
    }
    if (providerSubject.startsWith('google:')) {
      const resolution = await this.resolveGoogleEmailOtpSession(input);
      if (resolution.ok) return resolution.walletId;
      throw codedError(resolution.code, resolution.message);
    }

    const linkedWalletId = await this.readIdentityUserIdBySubject(`wallet:${providerSubject}`);
    if (linkedWalletId && isValidAccountId(linkedWalletId)) return linkedWalletId;

    const scope = resolveHostedOidcWalletScope(input.runtimePolicyScope);
    const verifiedEmail = toOptionalTrimmedString(input.email);
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RelayAuthScopeString(
        this.options.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RelayAuthScopeString(this.options.relayerAccount, 'relayerAccount'),
      projectId: scope.projectId,
      envId: scope.envId,
      authProvider: 'oidc',
      providerSubject,
      ...(verifiedEmail ? { verifiedEmail } : {}),
    });
  }

  async consumeGoogleEmailOtpRegistrationAttemptRateLimit(
    input: ConsumeGoogleEmailOtpRegistrationAttemptRateLimitInput,
  ): Promise<ConsumeGoogleEmailOtpRegistrationAttemptRateLimitResult> {
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register') return { ok: true };
    const providerSubject = parseGoogleProviderSubject(input.providerSubject);
    if (!providerSubject.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: providerSubject.error.message,
      };
    }
    const email = parseVerifiedGoogleEmail(input.email);
    if (!email.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: email.error.message,
      };
    }
    const orgId = parseOrgId(input.runtimePolicyScope?.orgId);
    if (!orgId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: orgId.error.message,
      };
    }
    const restartOffer = isTrueFlag(input.restartRegistrationOffer);
    return await this.consumeEmailOtpRateLimit({
      scope: 'googleRegistrationAttempt',
      action: restartOffer
        ? 'google_email_otp_registration_offer_restart'
        : 'google_email_otp_registration_create',
      userId: toOptionalTrimmedString(input.appSessionUserId),
      providerSubject: providerSubject.value,
      orgId: orgId.value,
      clientIp: toOptionalTrimmedString(input.clientIp),
    });
  }

  async resolveGoogleEmailOtpSession(
    input: ResolveGoogleEmailOtpSessionInput,
  ): Promise<ResolveGoogleEmailOtpSessionResult> {
    const providerSubject = parseGoogleProviderSubject(input.providerSubject ?? input.sub);
    if (!providerSubject.ok) {
      throw new Error('Cannot resolve Google Email OTP session without Google provider subject');
    }
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register' && accountMode !== 'login') {
      throw new Error('Google Email OTP accountMode must be register or login');
    }
    const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
    const runtimePolicyScope = requireRuntimePolicyScope(input.runtimePolicyScope);
    const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
    if (accountMode === 'register' && !appSessionVersion) {
      throw new Error('Google Email OTP registration requires appSessionVersion');
    }
    const restartRegistrationOffer = isTrueFlag(input.restartRegistrationOffer);
    const walletSubject = `wallet:${providerSubject.value}`;
    const linkedWalletId = await this.readIdentityUserIdBySubject(walletSubject);
    const linkedIsUsableRelayerWallet = Boolean(
      linkedWalletId && isValidAccountId(linkedWalletId) && this.isRelayerSubaccount(linkedWalletId),
    );
    const linkedIsHostedHmacReadableWallet = Boolean(
      linkedWalletId && this.isHostedHmacReadableRelayerSubaccount(linkedWalletId),
    );

    if (accountMode === 'login') {
      return await this.resolveGoogleEmailOtpLoginSession({
        providerSubject: providerSubject.value,
        email,
        orgId: runtimePolicyScope.orgId,
        walletSubject,
        linkedWalletId,
        linkedIsUsableRelayerWallet,
        linkedIsHostedHmacReadableWallet,
      });
    }

    if (!email) {
      throw new Error('Email is required to register a Google Email OTP wallet id');
    }
    return await this.resolveGoogleEmailOtpRegistrationSession({
      providerSubject: providerSubject.value,
      email,
      orgId: runtimePolicyScope.orgId,
      appSessionVersion: appSessionVersion || '',
      runtimePolicyScope,
      restartRegistrationOffer,
      walletSubject,
      linkedWalletId,
    });
  }

  async cleanupGoogleEmailOtpDevRegistrationState(
    input: CleanupGoogleEmailOtpDevRegistrationStateInput,
  ): Promise<CleanupGoogleEmailOtpDevRegistrationStateResult> {
    if (this.options.emailOtp.production) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Google Email OTP dev cleanup is not available',
      };
    }

    const providerSubject = toOptionalTrimmedString(input.providerSubject);
    if (!providerSubject || !providerSubject.startsWith('google:')) {
      return { ok: false, code: 'invalid_body', message: 'Missing Google provider subject' };
    }

    const requestedWalletId = toOptionalTrimmedString(input.walletId);
    const requestedOrgId = toOptionalTrimmedString(input.orgId);
    const nowMsRaw = typeof input.nowMs === 'number' ? input.nowMs : Number(input.nowMs);
    const nowMs = Number.isFinite(nowMsRaw) && nowMsRaw > 0 ? Math.floor(nowMsRaw) : Date.now();
    const expiredRegistrationAttemptsDeleted =
      await this.cleanupGoogleEmailOtpRegistrationAttempts(nowMs);
    const subject = `wallet:${providerSubject}`;
    const linkedWalletId = await this.readIdentityUserIdBySubject(subject);

    if (!linkedWalletId) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'no_linked_wallet',
      };
    }
    if (requestedWalletId && requestedWalletId !== linkedWalletId) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'wallet_id_mismatch',
      };
    }
    if (!isValidAccountId(linkedWalletId) || !this.isRelayerSubaccount(linkedWalletId)) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'not_relayer_subaccount',
      };
    }

    const activeEnrollment = await this.readEmailOtpWalletEnrollment(linkedWalletId);
    if (activeEnrollment) {
      const enrollmentMatchesProvider = activeEnrollment.providerUserId === providerSubject;
      const enrollmentMatchesOrg = !requestedOrgId || activeEnrollment.orgId === requestedOrgId;
      if (enrollmentMatchesProvider && enrollmentMatchesOrg) {
        return {
          ok: true,
          providerSubject,
          expiredRegistrationAttemptsDeleted,
          linkedWalletId,
          orphanedWalletMappingRemoved: false,
          orphanedWalletMappingSkippedReason: 'active_email_otp_enrollment',
        };
      }
    }

    const deleted = await this.deleteIdentitySubjectLinkForDevCleanup({
      userId: linkedWalletId,
      subject,
    });
    if (!deleted.ok && deleted.code !== 'not_found') return deleted;
    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      linkedWalletId,
      orphanedWalletMappingRemoved: deleted.ok,
    };
  }

  async readEmailOtpEnrollment(
    input: ReadEmailOtpEnrollmentInput,
  ): Promise<ReadEmailOtpEnrollmentResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) return emailOtpEnrollmentTenantMismatch();
    return { ok: true, enrollment };
  }

  async readActiveEmailOtpEnrollment(
    input: ReadActiveEmailOtpEnrollmentInput,
  ): Promise<ReadActiveEmailOtpEnrollmentResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) return emailOtpEnrollmentTenantMismatch();
    if (providerUserId && enrollment.providerUserId !== providerUserId) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the requested provider user',
      };
    }
    return { ok: true, enrollment };
  }

  async isEmailOtpStrongAuthRequired(
    input: IsEmailOtpStrongAuthRequiredInput,
  ): Promise<IsEmailOtpStrongAuthRequiredResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) return { ok: true, required: false, walletId };
    const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) return { ok: true, required: false, walletId };
    const lastEmailOtpLoginAtMs =
      typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
    const lastStrongAuthAtMs =
      typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
    return {
      ok: true,
      required: Boolean(
        lastEmailOtpLoginAtMs &&
          (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
      ),
      walletId,
      ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
      ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
    };
  }

  async markEmailOtpStrongAuthSatisfied(
    input: MarkEmailOtpStrongAuthSatisfiedInput,
  ): Promise<MarkEmailOtpStrongAuthSatisfiedResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) return { ok: true, walletId };
    const nowMs = Date.now();
    await this.putEmailOtpAuthStateForEnrollment(enrollment, { lastStrongAuthAtMs: nowMs });
    return { ok: true, walletId, lastStrongAuthAtMs: nowMs };
  }

  async getEmailOtpRecoveryCodeStatus(
    input: GetEmailOtpRecoveryCodeStatusInput,
  ): Promise<GetEmailOtpRecoveryCodeStatusResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) {
        if (enrollment.code === 'not_found') return emailOtpRecoveryNotEnrolledStatus(walletId);
        return enrollment;
      }

      const records = await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment);
      let activeRecoveryCodeCount = 0;
      let consumedRecoveryCodeCount = 0;
      let revokedRecoveryCodeCount = 0;
      let issuedAtMs: number | null = null;
      for (const record of records) {
        switch (record.recoveryKeyStatus) {
          case 'active':
            activeRecoveryCodeCount += 1;
            break;
          case 'consumed':
            consumedRecoveryCodeCount += 1;
            break;
          case 'revoked':
            revokedRecoveryCodeCount += 1;
            break;
        }
        issuedAtMs =
          issuedAtMs === null ? record.issuedAtMs : Math.min(issuedAtMs, record.issuedAtMs);
      }
      return {
        ok: true,
        status:
          activeRecoveryCodeCount === EMAIL_OTP_RECOVERY_KEY_COUNT ? 'ready' : 'incomplete',
        walletId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        activeRecoveryCodeCount,
        consumedRecoveryCodeCount,
        revokedRecoveryCodeCount,
        totalRecoveryCodeCount: records.length,
        issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read Email OTP recovery-code status',
      };
    }
  }

  private async createEmailOtpChallengeWithAction(
    input: EmailOtpChallengeIssueInput,
  ): Promise<EmailOtpChallengeIssueResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      const action = input.action;
      const operation = input.operation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      if (!emailOtpChallengePurposeIsValid({ action, operation })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP challenge action does not match operation',
        };
      }

      let challengeEmail = email;
      if (action !== WALLET_EMAIL_OTP_ACTIONS.registration) {
        const enrollment = await this.readActiveEmailOtpEnrollment({
          walletId,
          orgId,
          providerUserId: userId,
        });
        if (!enrollment.ok) return enrollment;
        const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
        if (!authState.ok) return authState;
        if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
          return {
            ok: false,
            code: 'otp_locked_out',
            message: 'Email OTP is temporarily locked for this wallet',
            lockedUntilMs: authState.state.otpLockedUntilMs,
          };
        }
        challengeEmail = enrollment.enrollment.verifiedEmail;
      }
      if (!challengeEmail) {
        return {
          ok: false,
          code: 'recovery_email_missing',
          message: 'Current app session does not include a recovery email',
        };
      }

      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(nowMs);
      if (input.reuseActiveChallenge === true) {
        const existing = await this.findLatestActiveEmailOtpChallenge({
          challengeSubjectId: userId,
          walletId,
          orgId,
          action,
          sessionHash,
          appSessionVersion,
          operation,
          nowMs,
        });
        if (existing) {
          return {
            ok: true,
            challenge: {
              challengeId: existing.challengeId,
              issuedAtMs: existing.createdAtMs,
              expiresAtMs: existing.expiresAtMs,
              challengeSubjectId: userId,
              walletId,
              orgId,
              otpChannel: EMAIL_OTP_CHANNEL,
              sessionHash,
              appSessionVersion,
              action,
              operation,
            },
            delivery: {
              status: 'reused',
              mode: this.options.emailOtp.deliveryMode,
              emailHint: maskEmail(existing.email),
            },
          };
        }
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'challenge',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      await this.enforceEmailOtpActiveChallengeLimit({
        challengeSubjectId: userId,
        walletId,
        orgId,
        action,
        sessionHash,
        appSessionVersion,
        operation,
        nowMs,
      });

      const challengeId = secureRandomBase64Url(16, 'email otp challenge ids');
      const otpCode = generateNumericOtp(this.options.emailOtp.codeLength);
      const expiresAtMs = nowMs + this.options.emailOtp.challengeTtlMs;
      const record = emailOtpChallengeRecord({
        challengeId,
        challengeSubjectId: userId,
        walletId,
        orgId,
        email: challengeEmail,
        otpCode,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        createdAtMs: nowMs,
        expiresAtMs,
        maxAttempts: this.options.emailOtp.maxAttempts,
      });
      await this.putEmailOtpChallenge(record);
      const delivery = await this.deliverEmailOtpCode(record);
      if (!delivery.ok) {
        await this.deleteEmailOtpChallenge(challengeId);
        return delivery;
      }

      return {
        ok: true,
        challenge: {
          challengeId,
          issuedAtMs: nowMs,
          expiresAtMs,
          challengeSubjectId: userId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action,
          operation,
        },
        delivery: {
          status: 'sent',
          mode: delivery.deliveryMode,
          emailHint: delivery.emailHint,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create Email OTP challenge',
      };
    }
  }

  async createEmailOtpChallenge(
    input: CreateEmailOtpChallengeInput,
  ): Promise<CreateEmailOtpChallengeResult> {
    const operation = parseEmailOtpLoginOperation(input.operation);
    const result = await this.createEmailOtpChallengeWithAction({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      email: input.email,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      reuseActiveChallenge: input.reuseActiveChallenge,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation,
      },
      delivery: result.delivery,
    };
  }

  async createEmailOtpEnrollmentChallenge(
    input: CreateEmailOtpEnrollmentChallengeInput,
  ): Promise<CreateEmailOtpEnrollmentChallengeResult> {
    const result = await this.createEmailOtpChallengeWithAction({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      email: input.email,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      },
      delivery: {
        mode: result.delivery.mode,
        emailHint: result.delivery.emailHint,
      },
    };
  }

  async createEmailOtpDeviceRecoveryChallenge(
    input: CreateEmailOtpDeviceRecoveryChallengeInput,
  ): Promise<CreateEmailOtpDeviceRecoveryChallengeResult> {
    const result = await this.createEmailOtpChallengeWithAction({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      email: input.email,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  private async verifyEmailOtpExistingChallengeCode(
    input: EmailOtpExistingChallengeVerifyInput,
  ): Promise<EmailOtpExistingChallengeVerifyResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const otpCode = toOptionalTrimmedString(input.otpCode);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      const action = input.action;
      const operation = input.operation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'verify',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
      if (!authState.ok) return authState;
      if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: authState.state.otpLockedUntilMs,
        };
      }

      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(nowMs);
      const record = await this.readEmailOtpChallenge(challengeId);
      if (!record) return emailOtpChallengeInvalidOrExpired();
      if (nowMs > record.expiresAtMs) {
        await this.deleteEmailOtpChallenge(record.challengeId);
        return emailOtpChallengeInvalidOrExpired();
      }

      const bindingMismatch = emailOtpChallengeBindingMismatchCode({
        record,
        userId,
        walletId,
        orgId,
        sessionHash,
        appSessionVersion,
        action,
        operation,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }

      if (record.otpCode !== otpCode) {
        return await this.recordEmailOtpInvalidAttempt({
          enrollment: enrollment.enrollment,
          authState: authState.state,
          record,
        });
      }

      const consumed = await this.consumeEmailOtpChallenge(record.challengeId);
      if (!consumed) return emailOtpChallengeInvalidOrExpired();
      await this.resetEmailOtpFailureState({
        enrollment: enrollment.enrollment,
        authState: authState.state,
      });

      return {
        ok: true,
        challengeId: consumed.challengeId,
        userId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion,
        enrollment: enrollment.enrollment,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP challenge',
      };
    }
  }

  private async verifyEmailOtpRegistrationChallengeCode(
    input: EmailOtpRegistrationChallengeVerifyInput,
  ): Promise<EmailOtpRegistrationChallengeVerifyResult> {
    try {
      const providerSubject = toOptionalTrimmedString(input.providerSubject);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const otpCode = toOptionalTrimmedString(input.otpCode);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const proofEmail = toOptionalTrimmedString(input.proofEmail)?.toLowerCase() || '';
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!providerSubject) {
        return { ok: false, code: 'invalid_body', message: 'Missing providerSubject' };
      }
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      if (!proofEmail) {
        return { ok: false, code: 'invalid_body', message: 'Email OTP registration requires proofEmail' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'verify',
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        userId: providerSubject,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const existingEnrollment = await this.readEmailOtpWalletEnrollment(walletId);
      if (existingEnrollment && existingEnrollment.orgId !== orgId) {
        return {
          ok: false,
          code: 'tenant_scope_mismatch',
          message: 'Email OTP enrollment does not match the requested orgId',
        };
      }
      const authState = existingEnrollment
        ? await this.readEmailOtpAuthStateForEnrollment(existingEnrollment)
        : { ok: true as const, state: null };
      if (!authState.ok) return authState;
      if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: authState.state.otpLockedUntilMs,
        };
      }

      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(nowMs);
      const record = await this.readEmailOtpChallenge(challengeId);
      if (!record) return emailOtpChallengeInvalidOrExpired();
      if (nowMs > record.expiresAtMs) {
        await this.deleteEmailOtpChallenge(record.challengeId);
        return emailOtpChallengeInvalidOrExpired();
      }

      const bindingMismatch = emailOtpRegistrationChallengeBindingMismatchCode({
        record,
        providerSubject,
        walletId,
        orgId,
        sessionHash,
        appSessionVersion,
        proofEmail,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }

      if (record.otpCode !== otpCode) {
        return await this.recordEmailOtpInvalidRegistrationAttempt({
          enrollment: existingEnrollment,
          authState: authState.state,
          record,
        });
      }

      const consumed = await this.consumeEmailOtpChallenge(record.challengeId);
      if (!consumed) return emailOtpChallengeInvalidOrExpired();
      if (existingEnrollment) {
        await this.resetEmailOtpFailureState({
          enrollment: existingEnrollment,
          authState: authState.state,
        });
      }
      return {
        ok: true,
        challengeId: consumed.challengeId,
        challengeSubjectId: providerSubject,
        walletId,
        orgId,
        email: consumed.email,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP enrollment challenge',
      };
    }
  }

  private async validateEmailOtpEnrollmentMaterial(input: {
    readonly recoveryWrappedEnrollmentEscrows?: unknown;
    readonly enrollmentSealKeyVersion?: unknown;
    readonly clientUnlockPublicKeyB64u?: unknown;
    readonly unlockKeyVersion?: unknown;
    readonly thresholdEcdsaClientVerifyingShareB64u?: unknown;
  }): Promise<EmailOtpEnrollmentMaterialValidationResult> {
    const enrollmentSealKeyVersion = toOptionalTrimmedString(input.enrollmentSealKeyVersion);
    const rawRecoveryWrappedEnrollmentEscrows = Array.isArray(
      input.recoveryWrappedEnrollmentEscrows,
    )
      ? input.recoveryWrappedEnrollmentEscrows
      : [];
    const parsedRecoveryWrappedEnrollmentEscrows: EmailOtpRecoveryEnrollmentEscrowBoundary[] =
      [];
    const recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const rawEscrow of rawRecoveryWrappedEnrollmentEscrows) {
      const parsed = parseEmailOtpRecoveryEnrollmentEscrowBoundary(rawEscrow);
      if (!parsed) continue;
      parsedRecoveryWrappedEnrollmentEscrows.push(parsed);
      recoveryWrappedEnrollmentEscrows.push(parsed.record);
    }
    const clientUnlockPublicKeyB64u = toOptionalTrimmedString(input.clientUnlockPublicKeyB64u);
    const unlockKeyVersion = toOptionalTrimmedString(input.unlockKeyVersion);
    const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
      input.thresholdEcdsaClientVerifyingShareB64u,
    );
    if (
      rawRecoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
      recoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    if (!enrollmentSealKeyVersion) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'enrollmentSealKeyVersion is required',
      };
    }
    const escrowSetValidation = await this.validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
      parsedRecoveryWrappedEnrollmentEscrows,
    );
    if (!escrowSetValidation.ok) return escrowSetValidation;
    if (!clientUnlockPublicKeyB64u) {
      return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
    }
    if (!unlockKeyVersion) {
      return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
    }
    if (!thresholdEcdsaClientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u is required',
      };
    }

    let unlockPublicKeyBytes: Uint8Array;
    try {
      unlockPublicKeyBytes = base64UrlDecode(clientUnlockPublicKeyB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u must be valid base64url',
      };
    }
    if (unlockPublicKeyBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    try {
      await validateSecp256k1PublicKey33(unlockPublicKeyBytes);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u is not a valid secp256k1 public key',
      };
    }

    let clientVerifyingShareBytes: Uint8Array;
    try {
      clientVerifyingShareBytes = base64UrlDecode(thresholdEcdsaClientVerifyingShareB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u must be valid base64url',
      };
    }
    if (clientVerifyingShareBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'thresholdEcdsaClientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    try {
      await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u is not a valid secp256k1 public key',
      };
    }

    return {
      ok: true,
      recoveryWrappedEnrollmentEscrows,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u,
      unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u,
    };
  }

  private async validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
    records: readonly EmailOtpRecoveryEnrollmentEscrowBoundary[],
  ): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const first = records[0];
    if (!first) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }

    const recoveryKeyIds = new Set<string>();
    const nonceB64us = new Set<string>();
    for (const boundary of records) {
      if (boundary.record.recoveryKeyStatus !== 'active') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrows must be active at enrollment',
        };
      }
      const record = boundary.record;
      if (recoveryKeyIds.has(record.recoveryKeyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow recoveryKeyId values must be unique',
        };
      }
      recoveryKeyIds.add(record.recoveryKeyId);

      if (nonceB64us.has(record.nonceB64u)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow nonce values must be unique',
        };
      }
      nonceB64us.add(record.nonceB64u);

      if (
        record.walletId !== first.record.walletId ||
        record.userId !== first.record.userId ||
        record.authSubjectId !== first.record.authSubjectId ||
        record.authMethod !== first.record.authMethod ||
        record.enrollmentId !== first.record.enrollmentId ||
        record.enrollmentVersion !== first.record.enrollmentVersion ||
        record.enrollmentSealKeyVersion !== first.record.enrollmentSealKeyVersion ||
        record.signingRootId !== first.record.signingRootId ||
        record.signingRootVersion !== first.record.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata must share one enrollment scope',
        };
      }

      const expectedAadHashB64u = base64UrlEncode(
        await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(boundary.binding)),
      );
      if (record.aadHashB64u !== expectedAadHashB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow aadHashB64u does not match metadata',
        };
      }
    }

    if (
      recoveryKeyIds.size !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
      nonceB64us.size !== EMAIL_OTP_RECOVERY_KEY_COUNT
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} distinct recovery-wrapped enrollment escrows are required`,
      };
    }

    return { ok: true };
  }

  async verifyEmailOtpEnrollment(
    input: VerifyEmailOtpEnrollmentInput,
  ): Promise<VerifyEmailOtpEnrollmentResult> {
    try {
      const providerSubject = toOptionalTrimmedString(input.providerSubject);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const registrationAttemptId = toOptionalTrimmedString(
        input.googleEmailOtpRegistrationAttemptId,
      );
      if (!providerSubject) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires providerSubject',
        };
      }
      if (!walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires walletId',
        };
      }
      if (!orgId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires orgId',
        };
      }
      if (!challengeId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires challengeId',
        };
      }
      if (!appSessionVersion) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires appSessionVersion',
        };
      }

      let proofEmail = toOptionalTrimmedString(input.proofEmail)?.toLowerCase() || '';
      if (registrationAttemptId) {
        const attempt = await this.readGoogleEmailOtpRegistrationAttempt(registrationAttemptId);
        if (!attempt) {
          return {
            ok: false,
            code: 'registration_attempt_missing',
            message: 'Google Email OTP registration attempt expired or was not found',
          };
        }
        if (attempt.providerSubject !== providerSubject) {
          return {
            ok: false,
            code: 'challenge_subject_mismatch',
            message: 'Email OTP registration attempt does not match the provider subject',
          };
        }
        if (attempt.expiresAtMs <= Date.now()) {
          return {
            ok: false,
            code: 'registration_attempt_expired',
            message: 'Google Email OTP registration attempt expired',
          };
        }
        if (attempt.walletId !== walletId) {
          return {
            ok: false,
            code: 'wallet_identity_mismatch',
            message: 'registrationAttemptId does not match walletId',
          };
        }
        proofEmail = attempt.email.toLowerCase();
      }
      if (!proofEmail) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires proofEmail',
        };
      }

      const verified = await this.verifyEmailOtpRegistrationChallengeCode({
        providerSubject,
        walletId,
        orgId,
        challengeId,
        otpCode: input.otpCode,
        otpChannel: input.otpChannel,
        sessionHash: input.sessionHash,
        appSessionVersion,
        proofEmail,
        clientIp: input.clientIp,
      });
      if (!verified.ok) return verified;
      const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase() || '';
      if (!verifiedEmail) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email OTP enrollment verification did not include a verified email',
        };
      }

      const enrollmentMaterial = await this.validateEmailOtpEnrollmentMaterial(input);
      if (!enrollmentMaterial.ok) return enrollmentMaterial;
      const canonicalWalletExists = await this.signerWalletExists(verified.walletId);
      if (!canonicalWalletExists) {
        return {
          ok: false,
          code: 'wallet_registration_incomplete',
          message:
            'Email OTP enrollment requires an existing canonical wallet. New wallet registration must finalize through /wallets/register/finalize.',
        };
      }

      const existing = await this.readEmailOtpWalletEnrollment(verified.walletId);
      const existingState = await this.readEmailOtpAuthState(verified.walletId);
      const nowMs = Date.now();
      const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
      if (!enrollmentScope) {
        return {
          ok: false,
          code: 'invalid_body',
          message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
        };
      }
      for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
        if (
          record.walletId !== verified.walletId ||
          record.userId !== verified.challengeSubjectId ||
          record.authSubjectId !== verified.challengeSubjectId ||
          record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
          record.recoveryKeyStatus !== 'active'
        ) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Recovery-wrapped enrollment escrow metadata does not match enrollment',
          };
        }
      }

      const enrollmentRecord: EmailOtpWalletEnrollmentRecord = {
        version: 'email_otp_wallet_enrollment_v1',
        walletId: verified.walletId,
        providerUserId: verified.challengeSubjectId,
        orgId: verified.orgId,
        verifiedEmail,
        enrollmentId: enrollmentScope.enrollmentId,
        enrollmentVersion: enrollmentScope.enrollmentVersion,
        enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
        signingRootId: enrollmentScope.signingRootId,
        signingRootVersion: enrollmentScope.signingRootVersion,
        recoveryWrappedEnrollmentEscrowCount:
          enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
        clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
        unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u:
          enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        updatedAtMs: nowMs,
      };
      const existingProviderEnrollment = await this.readEmailOtpWalletEnrollmentByProviderUserId({
        providerUserId: enrollmentRecord.providerUserId,
        orgId: enrollmentRecord.orgId,
      });
      if (
        existingProviderEnrollment &&
        existingProviderEnrollment.walletId !== enrollmentRecord.walletId
      ) {
        await this.deleteEmailOtpWalletEnrollment(existingProviderEnrollment.walletId);
      }
      await this.putEmailOtpWalletEnrollment(enrollmentRecord);
      await this.putEmailOtpRecoveryEscrows(
        enrollmentMaterial.recoveryWrappedEnrollmentEscrows.map((record) =>
          emailOtpRecoveryEscrowWithUpdatedAt({ record, updatedAtMs: nowMs }),
        ),
      );
      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollmentRecord)
      ).filter(activeEmailOtpRecoveryEscrow).length;
      if (activeRecoveryWrappedEnrollmentEscrowCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return {
          ok: false,
          code: 'internal',
          message: `Email OTP enrollment persisted ${activeRecoveryWrappedEnrollmentEscrowCount} active recovery-wrapped escrows; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
        };
      }
      await this.resetEmailOtpAuthStateForEnrollment({
        enrollment: enrollmentRecord,
        existingState,
        updatedAtMs: nowMs,
      });
      const completedRegistration = await this.completeGoogleEmailOtpRegistrationAttempt({
        registrationAttemptId,
        walletId: verified.walletId,
      });
      if (!completedRegistration.ok) return completedRegistration;
      return {
        ok: true,
        walletId: verified.walletId,
        otpChannel: verified.otpChannel,
        enrollment: {
          createdAtMs: existing?.createdAtMs ?? nowMs,
          updatedAtMs: nowMs,
          enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
          unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP enrollment',
      };
    }
  }

  async verifyEmailOtpChallenge(
    input: VerifyEmailOtpChallengeInput,
  ): Promise<VerifyEmailOtpChallengeResult> {
    const operation = parseEmailOtpLoginOperation(input.operation);
    const verified = await this.verifyEmailOtpExistingChallengeCode({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    });
    if (!verified.ok) return verified;

    const issuedAtMs = Date.now();
    const grantExpiresAtMs = issuedAtMs + this.options.emailOtp.grantTtlMs;
    const loginGrant = secureRandomBase64Url(24, 'email otp login grants');
    await this.putEmailOtpGrant(
      emailOtpGrantRecord({
        grantToken: loginGrant,
        userId: verified.userId,
        walletId: verified.walletId,
        orgId: verified.orgId,
        challengeId: verified.challengeId,
        sessionHash: verified.sessionHash,
        appSessionVersion: verified.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.unseal,
        issuedAtMs,
        expiresAtMs: grantExpiresAtMs,
      }),
    );

    return {
      ok: true,
      challengeId: verified.challengeId,
      loginGrant,
      grantExpiresAtMs,
      otpChannel: EMAIL_OTP_CHANNEL,
    };
  }

  async revokeWalletAuthMethod(
    input: RevokeWalletAuthMethodInput,
  ): Promise<RevokeWalletAuthMethodResult> {
    try {
      const parsed = parseD1RevokeWalletAuthMethodInput(input);
      if (!parsed.ok) return parsed.result;
      if (parsed.auth.kind === 'app_session') {
        if (parsed.auth.policy.walletId !== parsed.walletId) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke policy wallet mismatch',
          };
        }
        if (!d1RevokeTargetsEqual(parsed.auth.policy.target, parsed.target)) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke policy target mismatch',
          };
        }
        if (parsed.auth.policy.expiresAtMs <= Date.now()) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke policy is expired',
          };
        }
      }

      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const walletMethods = await walletAuthMethodStore.listForWallet({
        walletId: parsed.walletId,
        rpId: parsed.rpId,
      });
      const activeWalletMethods = walletMethods.filter(activeWalletAuthMethodRecord);
      if (activeWalletMethods.length === 0) {
        return { ok: false, code: 'not_found', message: 'wallet has no active auth methods' };
      }
      if (parsed.auth.kind === 'webauthn_assertion') {
        const authorizationCredentialId = webAuthnCredentialIdB64uFromCredential(
          parsed.auth.credential,
        );
        if (!authorizationCredentialId.ok) return authorizationCredentialId;
        const authorizationMethod = await walletAuthMethodStore.getPasskey({
          rpId: parsed.rpId,
          credentialIdB64u: authorizationCredentialId.credentialIdB64u,
        });
        if (
          !authorizationMethod ||
          authorizationMethod.kind !== 'passkey' ||
          authorizationMethod.walletId !== parsed.walletId ||
          authorizationMethod.status !== 'active'
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'WebAuthn authorization credential is not active for this wallet',
          };
        }
      }

      const targetRecord = await this.findWalletAuthMethodRecordForRevokeTarget({
        walletAuthMethodStore,
        walletId: parsed.walletId,
        rpId: parsed.rpId,
        target: parsed.target,
      });
      if (!targetRecord) {
        return { ok: false, code: 'not_found', message: 'wallet auth method not found' };
      }
      if (targetRecord.status !== 'active') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet auth method is already revoked',
        };
      }
      if (activeWalletMethods.length <= 1) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet must retain at least one active auth method',
        };
      }
      await walletAuthMethodStore.put(
        revokedD1WalletAuthMethodRecord({
          record: targetRecord,
          updatedAtMs: Date.now(),
        }),
      );
      return {
        ok: true,
        walletId: parsed.walletId,
        rpId: parsed.rpId,
        authMethod: {
          kind: targetRecord.kind,
          status: 'revoked',
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to revoke wallet auth method',
      };
    }
  }

  async removeEmailOtpServerSeal(
    input: RemoveEmailOtpServerSealInput,
  ): Promise<RemoveEmailOtpServerSealResult> {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(input.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createEmailOtpServerSealCipher();
      if (!shamir.ok) return shamir;
      const removed = await shamir.cipher.run({
        operation: 'remove-server-seal',
        thresholdSessionId: 'email-otp-unseal',
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!removed.ok) return removed;
      return {
        ok: true,
        ciphertext: removed.ciphertext,
        enrollmentSealKeyVersion: removed.keyVersion || shamir.keyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to remove Email OTP server seal',
      };
    }
  }

  async applyEmailOtpServerSeal(
    input: ApplyEmailOtpServerSealInput,
  ): Promise<ApplyEmailOtpServerSealResult> {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(input.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createEmailOtpServerSealCipher();
      if (!shamir.ok) return shamir;
      const applied = await shamir.cipher.run({
        operation: 'apply-server-seal',
        thresholdSessionId: 'email-otp-enroll',
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!applied.ok) return applied;
      return {
        ok: true,
        ciphertext: applied.ciphertext,
        enrollmentSealKeyVersion: applied.keyVersion || shamir.keyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to apply Email OTP server seal',
      };
    }
  }

  async verifyEmailOtpDeviceRecoveryChallenge(
    input: VerifyEmailOtpDeviceRecoveryChallengeInput,
  ): Promise<VerifyEmailOtpDeviceRecoveryChallengeResult> {
    const verified = await this.verifyEmailOtpExistingChallengeCode({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;

    const activeRecoveryWrappedEnrollmentEscrows = (
      await this.listEmailOtpRecoveryEscrowsForEnrollment(verified.enrollment)
    ).filter(activeEmailOtpRecoveryEscrow);
    if (activeRecoveryWrappedEnrollmentEscrows.length <= 0) {
      return {
        ok: false,
        code: 'recovery_wrapped_escrows_missing',
        message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
      };
    }

    const issuedAtMs = Date.now();
    const recoveryConsumeGrantExpiresAtMs = issuedAtMs + this.options.emailOtp.grantTtlMs;
    const recoveryConsumeGrant = secureRandomBase64Url(
      24,
      'email otp device recovery grants',
    );
    await this.putEmailOtpGrant(
      emailOtpGrantRecord({
        grantToken: recoveryConsumeGrant,
        userId: verified.userId,
        walletId: verified.walletId,
        orgId: verified.orgId,
        challengeId: verified.challengeId,
        sessionHash: verified.sessionHash,
        appSessionVersion: verified.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        issuedAtMs,
        expiresAtMs: recoveryConsumeGrantExpiresAtMs,
      }),
    );

    return {
      ok: true,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      recoveryConsumeGrant,
      recoveryConsumeGrantExpiresAtMs,
      recoveryWrappedEnrollmentEscrows: activeRecoveryWrappedEnrollmentEscrows.map(
        redactEmailOtpRecoveryChallengeEscrow,
      ),
      enrollment: {
        walletId: verified.enrollment.walletId,
        providerUserId: verified.enrollment.providerUserId,
        orgId: verified.enrollment.orgId,
        enrollmentId: verified.enrollment.enrollmentId,
        enrollmentVersion: verified.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: verified.enrollment.enrollmentSealKeyVersion,
        signingRootId: verified.enrollment.signingRootId,
        signingRootVersion: verified.enrollment.signingRootVersion,
        recoveryWrappedEnrollmentEscrowCount:
          verified.enrollment.recoveryWrappedEnrollmentEscrowCount,
      },
    };
  }

  async readEmailOtpOutboxEntry(
    input: ReadEmailOtpOutboxEntryInput,
  ): Promise<ReadEmailOtpOutboxEntryResult> {
    if (!this.options.emailOtp.devOutboxEnabled) {
      return { ok: false, code: 'not_found', message: 'Email OTP dev outbox is not enabled' };
    }
    const challengeId = toOptionalTrimmedString(input.challengeId);
    const userId = toOptionalTrimmedString(input.userId);
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const entry = this.emailOtpMemoryOutbox.get(challengeId);
    if (!entry || entry.userId !== userId || entry.walletId !== walletId) {
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
    }
    if (Date.now() > entry.expiresAtMs) {
      this.emailOtpMemoryOutbox.delete(challengeId);
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry expired' };
    }
    return {
      ok: true,
      challengeId,
      walletId,
      userId,
      otpChannel: entry.otpChannel,
      emailHint: entry.emailHint,
      otpCode: entry.otpCode,
      expiresAtMs: entry.expiresAtMs,
    };
  }

  async createEmailOtpUnlockChallenge(
    input: CreateEmailOtpUnlockChallengeInput,
  ): Promise<CreateEmailOtpUnlockChallengeResult> {
    try {
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!isValidAccountId(walletId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid walletId' };
      }
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      const enrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!enrollment.ok) return enrollment;
      const nowMs = Date.now();
      const ttlMs = clampedEmailOtpUnlockTtlMs(input.ttlMs ?? input.ttl_ms);
      const challengeId = secureRandomBase64Url(16, 'email otp unlock challenge ids');
      const challengeB64u = secureRandomBase64Url(32, 'email otp unlock challenges');
      const expiresAtMs = nowMs + ttlMs;
      await this.putEmailOtpUnlockChallenge(
        emailOtpUnlockChallengeRecord({
          challengeId,
          walletId: enrollment.enrollment.walletId,
          userId: enrollment.enrollment.providerUserId,
          orgId: enrollment.enrollment.orgId,
          challengeB64u,
          createdAtMs: nowMs,
          expiresAtMs,
        }),
      );
      return {
        ok: true,
        walletId: enrollment.enrollment.walletId,
        challengeId,
        challengeB64u,
        expiresAtMs,
        unlockKeyVersion: enrollment.enrollment.unlockKeyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create Email OTP unlock challenge',
      };
    }
  }

  async verifyEmailOtpUnlockProof(
    input: VerifyEmailOtpUnlockProofInput,
  ): Promise<VerifyEmailOtpUnlockProofResult> {
    try {
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const unlockProof = isRecord(input.unlockProof) ? input.unlockProof : null;
      if (!walletId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing walletId' };
      }
      if (!isValidAccountId(walletId)) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Invalid walletId' };
      }
      if (!orgId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing orgId' };
      }
      if (!challengeId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!unlockProof) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof is required',
        };
      }

      const publicKeyB64u = toOptionalTrimmedString(unlockProof.publicKey);
      const signatureB64u = toOptionalTrimmedString(unlockProof.signature);
      if (!publicKeyB64u) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is required',
        };
      }
      if (!signatureB64u) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature is required',
        };
      }

      const challenge = await this.consumeEmailOtpUnlockChallenge(challengeId);
      if (!challenge || Date.now() > challenge.expiresAtMs) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP unlock challenge expired or invalid',
        };
      }
      if (challenge.walletId !== walletId) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this walletId',
        };
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!enrollment.ok) {
        return {
          ok: false,
          verified: false,
          code: enrollment.code,
          message: enrollment.message,
        };
      }
      if (
        challenge.userId !== enrollment.enrollment.providerUserId ||
        challenge.orgId !== enrollment.enrollment.orgId
      ) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this enrollment',
        };
      }

      const providedPublicKey = decodeFixedBase64Url(publicKeyB64u, 33);
      if (!providedPublicKey) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey must decode to 33 bytes',
        };
      }
      try {
        await validateSecp256k1PublicKey33(providedPublicKey);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is not a valid secp256k1 public key',
        };
      }

      const signature = decodeFixedBase64Url(signatureB64u, 65);
      if (!signature) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature must decode to 65 bytes',
        };
      }
      const enrolledPublicKey = decodeFixedBase64Url(
        enrollment.enrollment.clientUnlockPublicKeyB64u,
        33,
      );
      if (!enrolledPublicKey || !bytesEqual(enrolledPublicKey, providedPublicKey)) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.publicKey does not match the enrolled clientUnlockPublicKeyB64u',
        };
      }
      const challengeDigest = decodeFixedBase64Url(challenge.challengeB64u, 32);
      if (!challengeDigest) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Stored unlock challenge digest must decode to 32 bytes',
        };
      }
      try {
        await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
          challengeDigest,
          signature,
          providedPublicKey,
        );
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.signature did not verify against unlockProof.publicKey',
        };
      }

      await this.putEmailOtpAuthStateForEnrollment(enrollment.enrollment, {
        lastEmailOtpLoginAtMs: Date.now(),
      });
      return {
        ok: true,
        verified: true,
        userId: enrollment.enrollment.walletId,
        walletId: enrollment.enrollment.walletId,
        unlockKeyVersion: enrollment.enrollment.unlockKeyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP unlock proof',
      };
    }
  }

  async consumeEmailOtpGrant(input: ConsumeEmailOtpGrantInput): Promise<ConsumeEmailOtpGrantResult> {
    try {
      const loginGrant = toOptionalTrimmedString(input.loginGrant);
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!loginGrant) return { ok: false, code: 'invalid_body', message: 'Missing loginGrant' };
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.consumeEmailOtpGrantRecord(loginGrant);
      if (!record || Date.now() > record.expiresAtMs) return emailOtpGrantInvalidOrExpired();
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.unseal) {
        return emailOtpGrantInvalidOrExpired();
      }
      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      return {
        ok: true,
        challengeId: record.challengeId,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to consume Email OTP grant',
      };
    }
  }

  async consumeEmailOtpRecoveryKey(
    input: ConsumeEmailOtpRecoveryKeyInput,
  ): Promise<ConsumeEmailOtpRecoveryKeyResult> {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(input.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!recoveryKeyId) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryKeyId' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const grantRecord = await this.consumeEmailOtpGrantRecord(recoveryConsumeGrant);
      if (!grantRecord || Date.now() > grantRecord.expiresAtMs) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (grantRecord.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      const bindingMismatch =
        grantRecord.userId !== userId ||
        grantRecord.walletId !== walletId ||
        grantRecord.otpChannel !== EMAIL_OTP_CHANNEL ||
        grantRecord.sessionHash !== sessionHash ||
        grantRecord.appSessionVersion !== appSessionVersion ||
        grantRecord.orgId !== orgId;
      if (bindingMismatch) return emailOtpRecoveryGrantBindingMismatch();

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const recoveryRecord = await this.readEmailOtpRecoveryEscrow({ walletId, recoveryKeyId });
      if (!recoveryRecord || recoveryRecord.recoveryKeyStatus !== 'active') {
        return {
          ok: false,
          code: 'recovery_key_not_active',
          message: 'Recovery key is not active',
        };
      }
      if (
        !emailOtpRecoveryEscrowMatchesEnrollment({
          escrow: recoveryRecord,
          enrollment: enrollment.enrollment,
        })
      ) {
        return {
          ok: false,
          code: 'recovery_key_binding_mismatch',
          message: 'Recovery key is not valid for this Email OTP enrollment',
        };
      }

      const consumedAtMs = Date.now();
      const consumedRecord = await this.consumeEmailOtpRecoveryEscrow({
        record: recoveryRecord,
        consumedAtMs,
      });
      if (!consumedRecord) {
        return {
          ok: false,
          code: 'recovery_key_not_active',
          message: 'Recovery key is not active',
        };
      }
      await this.putEmailOtpAuthStateForEnrollment(enrollment.enrollment, {
        lastStrongAuthAtMs: consumedAtMs,
      });
      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment)
      ).filter(activeEmailOtpRecoveryEscrow).length;

      return {
        ok: true,
        walletId,
        recoveryKeyId,
        consumedAtMs,
        activeRecoveryWrappedEnrollmentEscrowCount,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to consume Email OTP recovery key',
      };
    }
  }

  async rotateEmailOtpRecoveryKeys(
    input: RotateEmailOtpRecoveryKeysInput,
  ): Promise<RotateEmailOtpRecoveryKeysResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const enrollmentId = toOptionalTrimmedString(input.enrollmentId);
      const enrollmentSealKeyVersion = toOptionalTrimmedString(input.enrollmentSealKeyVersion);
      if (!userId) return invalidRecoveryRotationBody('Missing userId');
      if (!walletId) return invalidRecoveryRotationBody('Missing walletId');
      if (!orgId) return invalidRecoveryRotationBody('Missing orgId');
      if (!enrollmentId) return invalidRecoveryRotationBody('Missing enrollmentId');
      if (!enrollmentSealKeyVersion) {
        return invalidRecoveryRotationBody('Missing enrollmentSealKeyVersion');
      }
      const rawEscrows = Array.isArray(input.recoveryWrappedEnrollmentEscrows)
        ? input.recoveryWrappedEnrollmentEscrows
        : [];
      if (rawEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return invalidRecoveryRotationBody(
          `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
        );
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      if (
        enrollment.enrollment.enrollmentId !== enrollmentId ||
        enrollment.enrollment.enrollmentSealKeyVersion !== enrollmentSealKeyVersion
      ) {
        return recoveryRotationBindingMismatch();
      }

      const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
      if (!authState.ok) return authState;
      const lastStrongAuthAtMs =
        typeof authState.state?.lastStrongAuthAtMs === 'number'
          ? authState.state.lastStrongAuthAtMs
          : 0;
      const issuedAtMs = Date.now();
      const freshAuthExpiresAtMs = lastStrongAuthAtMs + this.options.emailOtp.grantTtlMs;
      if (!lastStrongAuthAtMs || issuedAtMs > freshAuthExpiresAtMs) {
        return {
          ok: false,
          code: 'fresh_auth_required',
          message: 'Fresh account authentication is required to rotate recovery codes',
        };
      }

      const recoveryKeyIds = new Set<string>();
      const nonceB64us = new Set<string>();
      const nextActiveRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
      for (const rawEscrow of rawEscrows) {
        const nextRecord = await activeEmailOtpRecoveryRotationEscrowRecord({
          raw: rawEscrow,
          enrollment: enrollment.enrollment,
          issuedAtMs,
          recoveryKeyIds,
          nonceB64us,
        });
        if (!nextRecord.ok) return nextRecord.result;
        nextActiveRecords.push(nextRecord.record);
      }

      const existingRecords = await this.listEmailOtpRecoveryEscrowsForEnrollment(
        enrollment.enrollment,
      );
      const oldActiveRecords: Extract<
        EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
        { readonly recoveryKeyStatus: 'active' }
      >[] = [];
      for (const record of existingRecords) {
        if (activeEmailOtpRecoveryEscrow(record)) oldActiveRecords.push(record);
      }
      const revokedRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
      for (const record of oldActiveRecords) {
        revokedRecords.push(
          revokedEmailOtpRecoveryEscrowRecord({ record, revokedAtMs: issuedAtMs }),
        );
      }

      await this.putEmailOtpRecoveryEscrows([...revokedRecords, ...nextActiveRecords]);
      const updatedRecords = await this.listEmailOtpRecoveryEscrowsForEnrollment(
        enrollment.enrollment,
      );
      const activeRecoveryCodeCount = countActiveEmailOtpRecoveryEscrows(updatedRecords);
      if (activeRecoveryCodeCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return {
          ok: false,
          code: 'internal',
          message: `Email OTP recovery-code rotation left ${activeRecoveryCodeCount} active codes; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
        };
      }
      return {
        ok: true,
        walletId,
        enrollmentId,
        enrollmentSealKeyVersion,
        activeRecoveryCodeCount,
        revokedRecoveryCodeCount: revokedRecords.length,
        totalRecoveryCodeCount: updatedRecords.length,
        issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate Email OTP recovery codes',
      };
    }
  }

  async recordEmailOtpRecoveryKeyAttemptFailure(
    input: RecordEmailOtpRecoveryKeyAttemptFailureInput,
  ): Promise<RecordEmailOtpRecoveryKeyAttemptFailureResult> {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(input.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const grantRecord = await this.readEmailOtpGrantRecord(recoveryConsumeGrant);
      if (!grantRecord || Date.now() > grantRecord.expiresAtMs) {
        if (grantRecord) await this.deleteEmailOtpGrantRecord(recoveryConsumeGrant);
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (grantRecord.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      const bindingMismatch =
        grantRecord.userId !== userId ||
        grantRecord.walletId !== walletId ||
        grantRecord.otpChannel !== EMAIL_OTP_CHANNEL ||
        grantRecord.sessionHash !== sessionHash ||
        grantRecord.appSessionVersion !== appSessionVersion ||
        grantRecord.orgId !== orgId;
      if (bindingMismatch) return emailOtpRecoveryGrantBindingMismatch();

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'recoveryKeyAttempt',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment)
      ).filter(activeEmailOtpRecoveryEscrow).length;
      if (activeRecoveryWrappedEnrollmentEscrowCount <= 0) {
        return {
          ok: false,
          code: 'recovery_wrapped_escrows_missing',
          message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
        };
      }

      return {
        ok: true,
        walletId,
        recordedAtMs: Date.now(),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to record Email OTP recovery-key failure',
      };
    }
  }

  async getRecoverySession(input: GetRecoverySessionInput): Promise<GetRecoverySessionResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      return { ok: true, record: await this.readRecoverySessionRecord(sessionId) };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read recovery session',
      };
    }
  }

  async updateRecoverySessionStatus(
    input: UpdateRecoverySessionStatusInput,
  ): Promise<UpdateRecoverySessionStatusResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const status = parseRecoverySessionStatus(input.status);
      if (!sessionId || !status) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery session update' };
      }
      if (input.metadataPatch != null && !isRecord(input.metadataPatch)) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery metadata patch' };
      }

      const existing = await this.readRecoverySessionRecord(sessionId);
      if (!existing) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }
      const record = recoverySessionWithStatus({
        record: existing,
        status,
        updatedAtMs: Date.now(),
        ...(input.metadataPatch ? { metadataPatch: input.metadataPatch } : {}),
      });
      await this.putRecoverySessionRecord(record);
      return { ok: true, record };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to update recovery session',
      };
    }
  }

  async recordRecoveryExecution(
    input: RecordRecoveryExecutionInput,
  ): Promise<RecordRecoveryExecutionResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution fields' };
      }

      const recoverySession = await this.readRecoverySessionRecord(sessionId);
      if (!recoverySession) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const existing = await this.readRecoveryExecutionRecord({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      const nowMs = Date.now();
      const record = buildRecoveryExecutionRecord({
        sessionId,
        userId: recoverySession.userId,
        nearAccountId: recoverySession.nearAccountId,
        chainIdKey,
        accountAddress,
        action,
        status: input.status,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        nowMs,
        transactionHash: input.transactionHash,
        errorCode: input.errorCode,
        errorMessage: input.errorMessage,
        metadata: input.metadata,
      });
      if (!record) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Invalid recovery execution payload',
        };
      }

      await this.putRecoveryExecutionRecord(record);
      return { ok: true, record };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to persist recovery execution',
      };
    }
  }

  async getOrCreateAppSessionVersion(
    input: GetOrCreateAppSessionVersionInput,
  ): Promise<GetOrCreateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.readAppSessionVersion(userId);
      if (existing) return { ok: true, appSessionVersion: existing };
      const now = Date.now();
      const next = appSessionVersion();
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id) DO NOTHING`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs: now,
              updatedAtMs: now,
            }),
          ),
          now,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: (await this.readAppSessionVersion(userId)) || next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(
    input: RotateAppSessionVersionInput,
  ): Promise<RotateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.scopePrepare(
        `SELECT record_json
           FROM signer_app_session_versions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          LIMIT 1`,
        [userId],
      ).first<D1SessionRow>();
      const now = Date.now();
      const next = appSessionVersion();
      const createdAtMs = parseAppSessionCreatedAt(existing?.record_json, now);
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id)
        DO UPDATE SET
          session_version = EXCLUDED.session_version,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs,
              updatedAtMs: now,
            }),
          ),
          createdAtMs,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(
    input: ValidateAppSessionVersionInput,
  ): Promise<ValidateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSession = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSession) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const current = await this.readAppSessionVersion(userId);
      if (!current || current !== appSession) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to validate app session version',
      };
    }
  }

  async listWebAuthnAuthenticatorsForUser(
    input: ListWebAuthnAuthenticatorsInput,
  ): Promise<ListWebAuthnAuthenticatorsResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const rpId = toOptionalTrimmedString(input.rpId);
      const authRows = await this.readWebAuthnAuthenticatorRows(userId);
      const bindingRows = await this.readWebAuthnBindingRows({ userId, rpId });
      const authByCredentialId = new Map<string, D1AuthenticatorRow>();
      for (const row of authRows) {
        const credentialId = toOptionalTrimmedString(row.credential_id_b64u);
        if (credentialId) authByCredentialId.set(credentialId, row);
      }
      const authenticators: NonNullable<
        ListWebAuthnAuthenticatorsResult['authenticators']
      > = [];
      for (const row of bindingRows) {
        const binding = parseWebAuthnBinding(row);
        if (!binding) continue;
        const authenticator = authByCredentialId.get(binding.credentialIdB64u);
        authenticators.push({
          credentialIdB64u: binding.credentialIdB64u,
          signerSlot: binding.signerSlot,
          publicKey: binding.publicKey,
          createdAtMs:
            optionalNonNegativeInteger(authenticator?.created_at_ms) ?? binding.createdAtMs,
          updatedAtMs:
            optionalNonNegativeInteger(authenticator?.updated_at_ms) ?? binding.updatedAtMs,
        });
      }
      authenticators.sort(compareAuthenticatorSlots);
      return { ok: true, authenticators };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list authenticators',
      };
    }
  }

  async createWebAuthnLoginOptions(
    input: CreateWebAuthnLoginOptionsInput,
  ): Promise<CreateWebAuthnLoginOptionsResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId ?? input.user_id);
      const rpId = toOptionalTrimmedString(input.rpId ?? input.rp_id);
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!isValidAccountId(userId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid userId' };
      }
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rpId' };

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + webAuthnLoginChallengeTtlMs(input.ttlMs ?? input.ttl_ms);
      const challengeId = secureRandomBase64Url(16, 'WebAuthn login challenge id');
      const challengeB64u = secureRandomBase64Url(32, 'WebAuthn login challenge');
      const record: WebAuthnLoginChallengeRecord = {
        version: 'webauthn_login_challenge_v1',
        challengeId,
        userId,
        rpId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      };

      await this.writeWebAuthnChallenge({
        challengeId,
        challengeKind: 'login',
        record,
        createdAtMs,
        expiresAtMs,
      });

      return { ok: true, challengeId, challengeB64u, expiresAtMs };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create login options',
      };
    }
  }

  async createWebAuthnSyncAccountOptions(
    input: CreateWebAuthnSyncAccountOptionsInput,
  ): Promise<CreateWebAuthnSyncAccountOptionsResult> {
    try {
      const rpId = toOptionalTrimmedString(input.rp_id);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const expectedUserIdRaw = toOptionalTrimmedString(input.account_id);
      const expectedUserId = expectedUserIdRaw
        ? parseBoundaryWalletIdForD1(expectedUserIdRaw)
        : null;
      if (expectedUserIdRaw && !expectedUserId) {
        return { ok: false, code: 'invalid_body', message: 'Invalid wallet account_id' };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + webAuthnLoginChallengeTtlMs(input.ttlMs ?? input.ttl_ms);
      const challengeId = secureRandomBase64Url(16, 'WebAuthn sync challenge id');
      const challengeB64u = secureRandomBase64Url(32, 'WebAuthn sync challenge');
      let credentialIds: string[] | undefined;
      let walletBinding: WebAuthnSyncWalletBinding | undefined;

      if (expectedUserId) {
        credentialIds = [];
        const seenCredentialIds = new Set<string>();
        const rows = await this.readWebAuthnBindingRows({ userId: expectedUserId, rpId });
        for (const row of rows) {
          const binding = parseWebAuthnBinding(row);
          if (!binding) continue;
          const credentialId = toOptionalTrimmedString(binding.credentialIdB64u);
          if (credentialId && !seenCredentialIds.has(credentialId)) {
            seenCredentialIds.add(credentialId);
            credentialIds.push(credentialId);
          }
          if (!walletBinding) {
            walletBinding = webAuthnSyncWalletBindingFromCredentialBinding(binding) || undefined;
          }
        }
      }

      const record: WebAuthnSyncChallengeRecord = {
        version: 'webauthn_sync_challenge_v1',
        challengeId,
        rpId,
        ...(expectedUserId ? { expectedUserId } : {}),
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      };
      await this.writeWebAuthnChallenge({
        challengeId,
        challengeKind: 'sync',
        record,
        createdAtMs,
        expiresAtMs,
      });

      return {
        ok: true,
        challengeId,
        challengeB64u,
        ...(credentialIds ? { credentialIds } : {}),
        ...(walletBinding ? { walletBinding } : {}),
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create sync account options',
      };
    }
  }

  async verifyWebAuthnAuthenticationLite(
    input: VerifyWebAuthnAuthenticationLiteInput,
  ): Promise<VerifyWebAuthnAuthenticationLiteResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const rpId = parseWebAuthnRpId(input.rpId);
      const expectedChallenge = toOptionalTrimmedString(input.expectedChallenge);
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      const credential = parseD1WebAuthnAuthenticationCredential(input.webauthn_authentication);
      if (!userId) {
        return { success: false, verified: false, code: 'invalid_body', message: 'Missing userId' };
      }
      if (!rpId.ok) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: rpId.error.message,
        };
      }
      if (!expectedChallenge) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing expectedChallenge',
        };
      }
      if (!expectedOrigin) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      if (!credential) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };
      }

      try {
        const clientData = parseClientDataJsonBase64url(
          toOptionalTrimmedString(parseJsonObject(credential.response)?.clientDataJSON),
        );
        if (!isHostWithinRpId(originHostnameOrEmpty(clientData.origin), String(rpId.value))) {
          return {
            success: false,
            verified: false,
            code: 'invalid_origin',
            message: 'WebAuthn origin is not within rpId',
          };
        }
      } catch (error: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(error) || 'Invalid webauthn_authentication.response.clientDataJSON',
        };
      }

      const credentialId = webAuthnCredentialIdB64uFromCredential(credential);
      if (!credentialId.ok) {
        return {
          success: false,
          verified: false,
          code: credentialId.code,
          message: credentialId.message,
        };
      }
      const authenticator = await this.readWebAuthnAuthenticator({
        userId,
        credentialIdB64u: credentialId.credentialIdB64u,
      });
      if (!authenticator) {
        return {
          success: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }

      const mod = await loadSimpleWebAuthnServer();
      const verifyAuthenticationResponse = mod.verifyAuthenticationResponse;
      if (typeof verifyAuthenticationResponse !== 'function') {
        return {
          success: false,
          verified: false,
          code: 'unsupported',
          message: 'WebAuthn verifier is unavailable in this runtime',
        };
      }

      let credentialPublicKeyBytes: Uint8Array;
      try {
        credentialPublicKeyBytes = decodeBase64UrlOrBase64(
          authenticator.credentialPublicKeyB64u,
          'authenticator.credentialPublicKeyB64u',
        );
      } catch (error: unknown) {
        return {
          success: false,
          verified: false,
          code: 'internal',
          message: `Stored credential public key is invalid: ${
            errorMessage(error) || 'decode failed'
          }`,
        };
      }

      let verification: unknown;
      try {
        verification = await verifyAuthenticationResponse({
          response: credential,
          expectedChallenge,
          expectedOrigin,
          expectedRPID: rpId.value,
          credential: {
            id: credentialId.credentialIdB64u,
            publicKey: credentialPublicKeyBytes,
            counter: authenticator.counter,
          },
          requireUserVerification: false,
        });
      } catch (error: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_assertion',
          message: errorMessage(error) || 'Authentication assertion verification threw',
        };
      }

      const verificationRecord = isRecord(verification) ? verification : {};
      if (verificationRecord.verified !== true) {
        return {
          success: false,
          verified: false,
          code: 'not_verified',
          message: 'Authentication verification failed',
        };
      }
      const authenticationInfo = parseJsonObject(verificationRecord.authenticationInfo);
      const newCounter = nonNegativeSafeInteger(authenticationInfo?.newCounter);
      if (newCounter !== null) {
        await this.updateWebAuthnAuthenticatorCounter({
          userId,
          credentialIdB64u: credentialId.credentialIdB64u,
          newCounter,
          updatedAtMs: Date.now(),
        });
      }
      return { success: true, verified: true };
    } catch (error: unknown) {
      return {
        success: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Verification failed',
      };
    }
  }

  async verifyWebAuthnLogin(
    input: VerifyWebAuthnLoginInput,
  ): Promise<VerifyWebAuthnLoginResult> {
    try {
      const challengeId = toOptionalTrimmedString(input.challengeId ?? input.challenge_id);
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      const challenge = await this.consumeWebAuthnLoginChallenge(challengeId);
      if (!challenge) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Login challenge expired or invalid',
        };
      }
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      if (!expectedOrigin) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      const rpId = parseWebAuthnRpId(challenge.rpId);
      if (!rpId.ok) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: `Stored login challenge rpId is invalid: ${rpId.error.message}`,
        };
      }
      const credential = parseD1WebAuthnAuthenticationCredential(input.webauthn_authentication);
      if (!credential) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };
      }
      const verification = await this.verifyWebAuthnAuthenticationLite({
        userId: challenge.userId,
        rpId: rpId.value,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: credential,
        expected_origin: expectedOrigin,
      });
      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }
      try {
        await this.linkIdentity({
          userId: challenge.userId,
          subject: `near:${challenge.userId}`,
          allowMoveIfSoleIdentity: false,
        });
      } catch {
        // Best-effort identity alias for login UX.
      }
      return { ok: true, verified: true, userId: challenge.userId, rpId: challenge.rpId };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Login verification failed',
      };
    }
  }

  async verifyWebAuthnSyncAccount(
    input: VerifyWebAuthnSyncAccountInput,
  ): Promise<VerifyWebAuthnSyncAccountResult> {
    try {
      const challengeId = toOptionalTrimmedString(input.challengeId ?? input.challenge_id);
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      const challenge = await this.consumeWebAuthnSyncChallenge(challengeId);
      if (!challenge) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Sync challenge expired or invalid',
        };
      }
      const credential = parseD1WebAuthnAuthenticationCredential(input.webauthn_authentication);
      if (!credential) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };
      }
      const credentialId = webAuthnCredentialIdB64uFromCredential(credential);
      if (!credentialId.ok) {
        return {
          ok: false,
          verified: false,
          code: credentialId.code,
          message: credentialId.message,
        };
      }
      const binding = await this.readWebAuthnBindingByCredential({
        rpId: challenge.rpId,
        credentialIdB64u: credentialId.credentialIdB64u,
      });
      if (!binding) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered on this relay',
        };
      }
      if (challenge.expectedUserId && binding.userId !== challenge.expectedUserId) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: `Credential is not registered for account ${challenge.expectedUserId}`,
        };
      }
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      if (!expectedOrigin) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      const rpId = parseWebAuthnRpId(binding.rpId);
      if (!rpId.ok) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: `Stored sync credential binding rpId is invalid: ${rpId.error.message}`,
        };
      }
      const verification = await this.verifyWebAuthnAuthenticationLite({
        userId: binding.userId,
        rpId: rpId.value,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: credential,
        expected_origin: expectedOrigin,
      });
      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }
      const authenticator = await this.readWebAuthnAuthenticator({
        userId: binding.userId,
        credentialIdB64u: credentialId.credentialIdB64u,
      });
      if (!authenticator) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }
      const walletBinding = webAuthnSyncWalletBindingFromCredentialBinding(binding);
      if (!walletBinding) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Credential binding is missing wallet identity fields',
        };
      }
      if (isRecord(input.threshold_ed25519)) {
        const thresholdSessionPolicy = parseJsonObject(input.threshold_ed25519.session_policy);
        if (thresholdSessionPolicy) {
          return {
            ok: false,
            verified: false,
            code: 'not_configured',
            message: 'Threshold signing is not configured on this Worker',
          };
        }
      }
      const thresholdEd25519 = binding.relayerKeyId && binding.publicKey
        ? {
            relayerKeyId: binding.relayerKeyId,
            publicKey: binding.publicKey,
            ...(binding.keyVersion ? { keyVersion: binding.keyVersion } : {}),
            ...(typeof binding.recoveryExportCapable === 'boolean'
              ? { recoveryExportCapable: binding.recoveryExportCapable }
              : {}),
            ...(typeof binding.clientParticipantId === 'number'
              ? { clientParticipantId: binding.clientParticipantId }
              : {}),
            ...(typeof binding.relayerParticipantId === 'number'
              ? { relayerParticipantId: binding.relayerParticipantId }
              : {}),
            ...(binding.participantIds ? { participantIds: binding.participantIds } : {}),
          }
        : undefined;
      return {
        ok: true,
        verified: true,
        accountId: walletBinding.walletId,
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        walletBinding,
        rpId: walletBinding.rpId,
        signerSlot: walletBinding.signerSlot,
        ...(binding.publicKey ? { publicKey: binding.publicKey } : {}),
        ...(binding.relayerKeyId ? { relayerKeyId: binding.relayerKeyId } : {}),
        credentialIdB64u: credentialId.credentialIdB64u,
        credentialPublicKeyB64u: authenticator.credentialPublicKeyB64u,
        ...(thresholdEd25519 ? { thresholdEd25519 } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Sync verification failed',
      };
    }
  }

  async listNearPublicKeysForUser(
    input: ListNearPublicKeysInput,
  ): Promise<ListNearPublicKeysResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT record_json
           FROM signer_near_public_keys
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY COALESCE(signer_slot, 0) ASC, created_at_ms ASC, public_key ASC`,
        [userId],
      ).all<D1RecordJsonRow>();
      const keys: NonNullable<ListNearPublicKeysResult['keys']> = [];
      for (const row of result.results || []) {
        const record = parseNearPublicKey(row);
        if (!record) continue;
        keys.push({
          publicKey: record.publicKey,
          kind: record.kind,
          signerSlot: record.signerSlot,
          createdAtMs: record.createdAtMs,
          updatedAtMs: record.updatedAtMs,
          rpId: record.rpId,
          credentialIdB64u: record.credentialIdB64u,
        });
      }
      return { ok: true, keys };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list keys',
      };
    }
  }

  async listThresholdEcdsaKeyIdentityTargetsForUser(
    input: ListThresholdEcdsaKeyIdentityTargetsForUserInput,
  ): Promise<ListThresholdEcdsaKeyIdentityTargetsForUserResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const rpId = toOptionalTrimmedString(input.rpId);
    const inputCount = input.keyTargets.length;
    if (!userId || !rpId) {
      return emptyThresholdEcdsaKeyInventoryResult({
        userId: userId || '',
        inputCount,
        rejectionReason: 'missing_scope',
      });
    }
    return emptyThresholdEcdsaKeyInventoryResult({
      userId,
      inputCount,
      rejectionReason: 'threshold_service_missing',
    });
  }

  async listWalletEcdsaKeyFactsInventory(
    input: ListWalletEcdsaKeyFactsInventoryInput,
  ): Promise<ListWalletEcdsaKeyFactsInventoryResult> {
    return await this.listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: input.walletId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
    });
  }

  async getThresholdRelayerAccount(): Promise<{
    readonly accountId: string;
    readonly publicKey: string;
  }> {
    return {
      accountId: this.options.relayerAccount || DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT,
      publicKey: this.options.relayerPublicKey || DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY,
    };
  }

  getThresholdSigningService(): ThresholdSigningService | null {
    if (this.thresholdSigningServiceInitialized) return this.thresholdSigningService;
    this.thresholdSigningServiceInitialized = true;
    if (this.options.thresholdSigningService !== undefined) {
      this.thresholdSigningService = this.options.thresholdSigningService;
      return this.thresholdSigningService;
    }
    if (!this.options.thresholdStore) {
      this.thresholdSigningService = null;
      return null;
    }
    this.thresholdSigningService = createCloudflareDurableObjectThresholdSigningService({
      thresholdStore: this.options.thresholdStore,
      auth: {
        getRelayerAccount: this.getThresholdRelayerAccount.bind(this),
        verifyWebAuthnAuthenticationLite: this.verifyWebAuthnAuthenticationLite.bind(this),
        viewAccessKeyList: unsupportedCloudflareD1NearAccessKeyList,
        dispatchNearSignedTransactionBorsh: unsupportedCloudflareD1NearTransactionDispatch,
      },
    });
    return this.thresholdSigningService;
  }

  async ecdsaHssRoleLocalBootstrap(
    request: EcdsaHssRoleLocalBootstrapInput,
  ): Promise<EcdsaHssRoleLocalBootstrapResult> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.ecdsaHssRoleLocalBootstrap(request);
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyInput,
  ): Promise<VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyResult> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(request);
  }

  async ecdsaHssRoleLocalExportShare(
    input: EcdsaHssRoleLocalExportShareInput,
  ): Promise<EcdsaHssRoleLocalExportShareResult> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.ecdsaHssRoleLocalExportShare(input);
  }

  getGoogleOidcPublicConfig(): ReturnType<CloudflareRelayAuthService['getGoogleOidcPublicConfig']> {
    const clientId = toOptionalTrimmedString(this.options.googleOidcClientId);
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  async verifyOidcJwtExchange(
    input: VerifyOidcJwtExchangeInput,
  ): Promise<VerifyOidcJwtExchangeResult> {
    try {
      const oidcExchange = this.options.oidcExchange;
      if (!oidcExchange || oidcExchange.issuers.length === 0) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'OIDC exchange is not configured on this Worker',
        };
      }

      const token = toOptionalTrimmedString(input.token);
      if (!token) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token is required',
        };
      }
      const subtle = globalThis.crypto?.subtle;
      if (!subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parsed = parseRs256JwtForVerification({
        token,
        tokenLabel: 'exchange.token',
      });
      if (!parsed.ok) return parsed;
      const jwt = parsed.jwt;
      const payload = jwt.payload;

      const iss = normalizedOidcIssuer(payload.iss);
      if (!iss) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token iss',
        };
      }
      const issuerConfig = oidcIssuerConfigForTokenIssuer({
        issuers: oidcExchange.issuers,
        issuer: iss,
      });
      if (!issuerConfig) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_issuer',
          message: 'exchange.token issuer is not allowed',
        };
      }

      const aud = parseJwtAud(payload.aud);
      if (aud.length === 0) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token aud',
        };
      }
      let audienceAllowed = false;
      for (const audience of aud) {
        if (issuerConfig.audiences.includes(audience)) audienceAllowed = true;
      }
      if (!audienceAllowed) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_audience',
          message: 'exchange.token audience mismatch',
        };
      }

      const sub = toOptionalTrimmedString(payload.sub);
      if (!sub) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token sub',
        };
      }

      const jwks = await this.getOidcJwksByUrl(issuerConfig.jwksUrl);
      const jwk = jwks.keysByKid.get(jwt.kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown OIDC key id (kid)',
        };
      }

      const signature = await verifyRs256JwtSignature({
        subtle,
        jwt,
        jwk,
        tokenLabel: 'exchange.token',
        invalidSignatureMessage: 'Invalid exchange.token signature',
      });
      if (!signature.ok) return signature;

      const nowSec = Math.floor(Date.now() / 1_000);
      const exp = Number(payload.exp);
      if (!Number.isFinite(exp) || exp <= 0) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid exchange.token exp',
        };
      }
      if (nowSec > exp + oidcExchange.clockSkewSec) {
        return {
          ok: false,
          verified: false,
          code: 'expired',
          message: 'exchange.token is expired',
        };
      }
      if (payload.nbf !== undefined) {
        const nbf = Number(payload.nbf);
        if (!Number.isFinite(nbf)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid exchange.token nbf',
          };
        }
        if (nowSec + oidcExchange.clockSkewSec < nbf) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'exchange.token is not yet valid',
          };
        }
      }
      if (payload.iat !== undefined) {
        const iat = Number(payload.iat);
        if (!Number.isFinite(iat)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid exchange.token iat',
          };
        }
        if (iat > nowSec + oidcExchange.clockSkewSec) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'exchange.token issued-at is in the future',
          };
        }
      }

      const providerSubject = `${issuerConfig.subjectPrefix || `oidc:${iss}:`}${sub}`;
      const email = toOptionalTrimmedString(payload.email);
      const name = toOptionalTrimmedString(payload.name);
      const givenName = toOptionalTrimmedString(payload.given_name);
      const familyName = toOptionalTrimmedString(payload.family_name);
      let userId = providerSubject;
      try {
        const linked = await this.readIdentityUserIdBySubject(providerSubject);
        if (linked) userId = linked;
        await this.linkIdentity({
          userId,
          subject: providerSubject,
          allowMoveIfSoleIdentity: false,
        });
      } catch {}

      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        iss,
        aud,
        sub,
        ...(email ? { email } : {}),
        ...(name ? { name } : {}),
        ...(givenName ? { given_name: givenName } : {}),
        ...(familyName ? { family_name: familyName } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'OIDC exchange verification failed',
      };
    }
  }

  async verifyGoogleLogin(input: VerifyGoogleLoginInput): Promise<VerifyGoogleLoginResult> {
    try {
      const clientId = toOptionalTrimmedString(this.options.googleOidcClientId);
      if (!clientId) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'Google OIDC is not configured on this Worker',
        };
      }
      const idToken = toOptionalTrimmedString(input.idToken ?? input.id_token);
      if (!idToken) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token is required',
        };
      }
      const subtle = globalThis.crypto?.subtle;
      if (!subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parsed = parseRs256JwtForVerification({
        token: idToken,
        tokenLabel: 'id_token',
      });
      if (!parsed.ok) return parsed;
      const jwt = parsed.jwt;

      const jwks = await this.getGoogleJwks();
      const jwk = jwks.keysByKid.get(jwt.kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown Google key id (kid)',
        };
      }

      const signature = await verifyRs256JwtSignature({
        subtle,
        jwt,
        jwk,
        tokenLabel: 'id_token',
        invalidSignatureMessage: 'Invalid Google id_token signature',
      });
      if (!signature.ok) return signature;

      const claims = this.validateGoogleIdTokenClaims({ payload: jwt.payload, clientId });
      if (!claims.ok) return claims;
      const providerSubject = `google:${claims.sub}`;
      let userId = providerSubject;
      const linked = await this.readIdentityUserIdBySubject(providerSubject);
      if (linked) userId = linked;
      await this.linkIdentity({
        userId,
        subject: providerSubject,
        allowMoveIfSoleIdentity: false,
      });
      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        sub: claims.sub,
        ...(claims.email ? { email: claims.email } : {}),
        ...(claims.name ? { name: claims.name } : {}),
        ...(claims.givenName ? { given_name: claims.givenName } : {}),
        ...(claims.familyName ? { family_name: claims.familyName } : {}),
        ...(typeof claims.emailVerified === 'boolean'
          ? { emailVerified: claims.emailVerified }
          : {}),
        ...(claims.hostedDomain ? { hostedDomain: claims.hostedDomain } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Google OIDC verification failed',
      };
    }
  }

  private validateGoogleIdTokenClaims(input: {
    readonly payload: Record<string, unknown>;
    readonly clientId: string;
  }):
    | {
        readonly ok: true;
        readonly sub: string;
        readonly email?: string;
        readonly name?: string;
        readonly givenName?: string;
        readonly familyName?: string;
        readonly emailVerified?: boolean;
        readonly hostedDomain?: string;
      }
    | VerifyGoogleLoginFailure {
    const payload = input.payload;
    const iss = toOptionalTrimmedString(payload.iss);
    if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
      return {
        ok: false,
        verified: false,
        code: 'invalid_issuer',
        message: 'Invalid Google id_token issuer',
      };
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const exp = Number(payload.exp);
    if (!Number.isFinite(exp) || exp <= 0) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Invalid Google id_token exp',
      };
    }
    if (nowSec >= exp) {
      return {
        ok: false,
        verified: false,
        code: 'expired',
        message: 'Google id_token is expired',
      };
    }
    if (payload.nbf !== undefined) {
      const nbf = Number(payload.nbf);
      if (!Number.isFinite(nbf)) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid Google id_token nbf',
        };
      }
      if (nowSec < nbf) {
        return {
          ok: false,
          verified: false,
          code: 'not_yet_valid',
          message: 'Google id_token is not yet valid',
        };
      }
    }

    const aud = parseJwtAud(payload.aud);
    if (aud.length === 0) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Missing Google id_token aud',
      };
    }
    if (!aud.includes(input.clientId)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_audience',
        message: 'Google id_token audience mismatch',
      };
    }

    const sub = toOptionalTrimmedString(payload.sub);
    if (!sub) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Missing Google id_token sub',
      };
    }
    const email = toOptionalTrimmedString(payload.email);
    const name = toOptionalTrimmedString(payload.name);
    const givenName = toOptionalTrimmedString(payload.given_name);
    const familyName = toOptionalTrimmedString(payload.family_name);
    const emailVerified = parseBooleanJwtClaim(payload.email_verified);
    const hostedDomain = toOptionalTrimmedString(payload.hd);
    return {
      ok: true,
      sub,
      ...(email ? { email } : {}),
      ...(name ? { name } : {}),
      ...(givenName ? { givenName } : {}),
      ...(familyName ? { familyName } : {}),
      ...(typeof emailVerified === 'boolean' ? { emailVerified } : {}),
      ...(hostedDomain ? { hostedDomain } : {}),
    };
  }

  private async getGoogleJwks(): Promise<JsonWebKeyCache> {
    const nowMs = Date.now();
    if (this.googleJwksCache && nowMs < this.googleJwksCache.expiresAtMs) {
      return this.googleJwksCache;
    }
    if (this.googleJwksFetchPromise) return await this.googleJwksFetchPromise;
    this.googleJwksFetchPromise = this.fetchGoogleJwks(nowMs);
    try {
      return await this.googleJwksFetchPromise;
    } finally {
      this.googleJwksFetchPromise = null;
    }
  }

  private async fetchGoogleJwks(nowMs: number): Promise<JsonWebKeyCache> {
    if (typeof fetch !== 'function') {
      throw new Error('fetch is unavailable in this runtime');
    }
    const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    const text = await response.text();
    if (!response.ok) {
      throw new Error(
        `Google OIDC certs fetch failed (HTTP ${response.status}): ${text.slice(0, 200)}`,
      );
    }
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw new Error('Google OIDC certs returned non-JSON response');
    }
    const keysByKid = parseGoogleJwks(parsed);
    if (!keysByKid) throw new Error('Google OIDC certs returned no usable RSA keys');
    const maxAgeSec = parseCacheControlMaxAgeSec(response.headers.get('cache-control')) || 60 * 60;
    const value = { keysByKid, expiresAtMs: nowMs + maxAgeSec * 1000 };
    this.googleJwksCache = value;
    return value;
  }

  private async getOidcJwksByUrl(jwksUrl: string): Promise<JsonWebKeyCache> {
    const url = toOptionalTrimmedString(jwksUrl);
    if (!url) throw new Error('Missing OIDC JWKS URL');
    const nowMs = Date.now();
    const cached = this.oidcJwksCacheByUrl.get(url);
    if (cached && nowMs < cached.expiresAtMs) return cached;
    const inflight = this.oidcJwksFetchPromiseByUrl.get(url);
    if (inflight) return await inflight;
    const promise = this.fetchOidcJwks(url, nowMs);
    this.oidcJwksFetchPromiseByUrl.set(url, promise);
    try {
      return await promise;
    } finally {
      this.oidcJwksFetchPromiseByUrl.delete(url);
    }
  }

  private async fetchOidcJwks(url: string, nowMs: number): Promise<JsonWebKeyCache> {
    if (typeof fetch !== 'function') {
      throw new Error('fetch is unavailable in this runtime');
    }
    const response = await fetch(url);
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`OIDC JWKS fetch failed (HTTP ${response.status}): ${text.slice(0, 200)}`);
    }
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw new Error('OIDC JWKS returned non-JSON response');
    }
    const keysByKid = parseOidcJwks(parsed);
    if (!keysByKid) throw new Error('OIDC JWKS returned no usable RSA keys');
    const maxAgeSec = parseCacheControlMaxAgeSec(response.headers.get('cache-control')) || 60 * 60;
    const value = { keysByKid, expiresAtMs: nowMs + maxAgeSec * 1_000 };
    this.oidcJwksCacheByUrl.set(url, value);
    return value;
  }

  private async resolveGoogleEmailOtpLoginSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly walletSubject: string;
    readonly linkedWalletId: string | null;
    readonly linkedIsUsableRelayerWallet: boolean;
    readonly linkedIsHostedHmacReadableWallet: boolean;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    if (
      input.linkedWalletId &&
      input.linkedIsUsableRelayerWallet &&
      input.linkedIsHostedHmacReadableWallet
    ) {
      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: input.linkedWalletId,
        orgId: input.orgId,
        providerUserId: input.providerSubject,
      });
      if (enrollment.ok) {
        return {
          ok: true,
          mode: 'existing_wallet',
          walletId: input.linkedWalletId,
          providerSubject: input.providerSubject,
          ...(input.email ? { email: input.email } : {}),
          hasEmailOtpEnrollment: true,
        };
      }
      if (!this.isGoogleEmailOtpEnrollmentLookupMiss(enrollment.code)) {
        throw codedError(enrollment.code, enrollment.message);
      }
    }

    const discovered = await this.getGoogleEmailOtpEnrollmentBySubject({
      providerSubject: input.providerSubject,
      orgId: input.orgId,
    });
    if (!discovered) {
      if (input.linkedWalletId) {
        const stale = googleEmailOtpStaleIdentityMapping({
          providerSubject: input.providerSubject,
          linkedWalletId: input.linkedWalletId,
          ...(input.email ? { email: input.email } : {}),
        });
        throw codedError(stale.code, stale.message);
      }
      throw codedError('not_found', 'Email OTP enrollment not found');
    }

    const repaired = await this.repairGoogleEmailOtpWalletLink({
      providerSubject: input.providerSubject,
      walletId: discovered.walletId,
    });
    if (!repaired.ok) throw codedError(repaired.code, repaired.message);
    return {
      ok: true,
      mode: 'existing_wallet',
      walletId: discovered.walletId,
      providerSubject: input.providerSubject,
      ...(input.email ? { email: input.email } : {}),
      hasEmailOtpEnrollment: true,
    };
  }

  private async resolveGoogleEmailOtpRegistrationSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly restartRegistrationOffer: boolean;
    readonly walletSubject: string;
    readonly linkedWalletId: string | null;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    const discoveredExistingEnrollment = await this.getGoogleEmailOtpEnrollmentBySubject({
      providerSubject: input.providerSubject,
      orgId: input.orgId,
    });
    if (discoveredExistingEnrollment && !input.restartRegistrationOffer) {
      const repaired = await this.repairGoogleEmailOtpWalletLink({
        providerSubject: input.providerSubject,
        walletId: discoveredExistingEnrollment.walletId,
      });
      if (!repaired.ok) {
        return {
          ok: false,
          mode: 'registration_incomplete',
          code: 'registration_incomplete',
          walletId: discoveredExistingEnrollment.walletId,
          providerSubject: input.providerSubject,
          email: input.email,
          message: repaired.message,
        };
      }
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: discoveredExistingEnrollment.walletId,
        providerSubject: input.providerSubject,
        email: input.email,
        hasEmailOtpEnrollment: true,
      };
    }
    if (input.linkedWalletId && !input.restartRegistrationOffer) {
      return googleEmailOtpStaleIdentityMapping({
        providerSubject: input.providerSubject,
        linkedWalletId: input.linkedWalletId,
        email: input.email,
      });
    }

    const nowMs = Date.now();
    await this.abandonStartedGoogleEmailOtpRegistrationAttemptsExceptAppSession({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      runtimePolicyScope: input.runtimePolicyScope,
      nowMs,
      failureCode: 'app_session_version_replaced',
    });

    const startedAttempt = await this.findStartedGoogleEmailOtpRegistrationAttempt({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      runtimePolicyScope: input.runtimePolicyScope,
    });
    if (startedAttempt) {
      if (input.restartRegistrationOffer) {
        await this.putGoogleEmailOtpRegistrationAttempt(
          abandonedGoogleEmailOtpRegistrationAttemptRecord({
            record: startedAttempt,
            failureCode: 'offer_restarted_by_user',
            updatedAtMs: Date.now(),
          }),
        );
      } else {
        return {
          ok: true,
          mode: 'register_started',
          walletId: startedAttempt.walletId,
          providerSubject: input.providerSubject,
          email: input.email,
          registrationAttemptId: startedAttempt.attemptId,
          expiresAtMs: startedAttempt.expiresAtMs,
          offer: googleEmailOtpRegistrationOfferForResponse(startedAttempt),
        };
      }
    }

    return await this.createFreshGoogleEmailOtpRegistrationAttempt(input);
  }

  private async createFreshGoogleEmailOtpRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly walletSubject: string;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    const nowMs = Date.now();
    const authProvider = 'google_oidc';
    const walletIdDerivationNonce = secureRandomBase64Url(
      18,
      'google email otp wallet derivation nonces',
    );
    const offerCandidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
    for (let attempt = 0; attempt < 30 && offerCandidates.length < 5; attempt += 1) {
      const walletId = await this.deriveHostedGoogleEmailOtpWalletId({
        providerSubject: input.providerSubject,
        email: input.email,
        authProvider,
        runtimePolicyScope: input.runtimePolicyScope,
        walletIdDerivationNonce,
        collisionCounter: attempt,
      });
      const inUseByLiveAttempt = await this.hasLiveStartedGoogleEmailOtpWalletAttempt({
        walletId,
        nowMs,
      });
      if (inUseByLiveAttempt) continue;
      const inUseByEnrollment = await this.readEmailOtpWalletEnrollment(walletId);
      if (inUseByEnrollment) continue;
      const existingSubjects = await this.readIdentitySubjectsByUserId(walletId);
      if (
        hasDifferentWalletIdentitySubject({
          subjects: existingSubjects,
          expectedWalletSubject: input.walletSubject,
        })
      ) {
        continue;
      }
      offerCandidates.push({
        candidateId: secureRandomBase64Url(18, 'google email otp offer candidate ids'),
        walletId,
        collisionCounter: attempt,
      });
    }

    const selectedCandidate = offerCandidates[0];
    if (!selectedCandidate) {
      return {
        ok: false,
        mode: 'registration_incomplete',
        code: 'registration_incomplete',
        providerSubject: input.providerSubject,
        email: input.email,
        message: 'Unable to allocate a fresh Google Email OTP registration attempt',
      };
    }
    const nonEmptyOfferCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates = [
      selectedCandidate,
      ...offerCandidates.slice(1),
    ];
    const attempt = await this.createGoogleEmailOtpRegistrationAttempt({
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: selectedCandidate.walletId,
      offerId: secureRandomBase64Url(18, 'google email otp offer ids'),
      offerCandidates: nonEmptyOfferCandidates,
      selectedCandidateId: selectedCandidate.candidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider,
      walletIdDerivationNonce,
      collisionCounter: selectedCandidate.collisionCounter,
      runtimePolicyScope: input.runtimePolicyScope,
    });
    return {
      ok: true,
      mode: 'register_started',
      walletId: attempt.walletId,
      providerSubject: input.providerSubject,
      email: input.email,
      registrationAttemptId: attempt.attemptId,
      expiresAtMs: attempt.expiresAtMs,
      offer: googleEmailOtpRegistrationOfferForResponse(attempt),
    };
  }

  private isRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = toOptionalTrimmedString(this.options.relayerAccount);
    return Boolean(relayerAccount && accountId.endsWith(`.${relayerAccount}`));
  }

  private isHostedHmacReadableRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = toOptionalTrimmedString(this.options.relayerAccount);
    if (!relayerAccount || !accountId.endsWith(`.${relayerAccount}`)) return false;
    const slug = accountId.slice(0, -(relayerAccount.length + 1));
    return /^[a-z]+-[a-z]+-[a-z0-9]{10}$/.test(slug);
  }

  private async deriveHostedGoogleEmailOtpWalletId(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly authProvider: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly walletIdDerivationNonce: string;
    readonly collisionCounter: number;
  }): Promise<string> {
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RelayAuthScopeString(
        this.options.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RelayAuthScopeString(this.options.relayerAccount, 'relayerAccount'),
      projectId: input.runtimePolicyScope.projectId,
      envId: input.runtimePolicyScope.envId,
      authProvider: input.authProvider,
      providerSubject: input.providerSubject,
      verifiedEmail: input.email,
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      ...(input.collisionCounter > 0 ? { collisionCounter: input.collisionCounter } : {}),
    });
  }

  private async getGoogleEmailOtpEnrollmentBySubject(input: {
    readonly providerSubject: string;
    readonly orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const enrollment = await this.readEmailOtpWalletEnrollmentByProviderUserId({
      providerUserId: input.providerSubject,
      orgId: input.orgId,
    });
    if (
      !enrollment ||
      enrollment.providerUserId !== input.providerSubject ||
      enrollment.orgId !== input.orgId ||
      !isValidAccountId(enrollment.walletId) ||
      !this.isHostedHmacReadableRelayerSubaccount(enrollment.walletId)
    ) {
      return null;
    }
    return enrollment;
  }

  private async repairGoogleEmailOtpWalletLink(input: {
    readonly providerSubject: string;
    readonly walletId: string;
  }): Promise<LinkIdentityResult> {
    return await this.linkIdentity({
      userId: input.walletId,
      subject: `wallet:${input.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
  }

  private isGoogleEmailOtpEnrollmentLookupMiss(code: string): boolean {
    return (
      code === 'not_found' ||
      code === 'provider_identity_mismatch' ||
      code === 'tenant_scope_mismatch'
    );
  }

  private async cleanupGoogleEmailOtpRegistrationAttempts(nowMs: number): Promise<number> {
    return d1MutationChanges(
      await this.scopePrepare(
        `DELETE FROM signer_email_otp_registration_attempts
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND (expires_at_ms <= ? OR state = 'expired')`,
        [nowMs],
      ).run(),
    );
  }

  private async createGoogleEmailOtpRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly walletId: string;
    readonly offerId: string;
    readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
    readonly selectedCandidateId: string;
    readonly appSessionVersion: string;
    readonly authProvider: string;
    readonly walletIdDerivationNonce: string;
    readonly collisionCounter: number;
    readonly runtimePolicyScope: RuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord> {
    const nowMs = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(nowMs);
    const attempt: PendingGoogleEmailOtpRegistrationAttemptRecord = {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: secureRandomBase64Url(18, 'google email otp registration attempt ids'),
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: input.walletId,
      offerId: input.offerId,
      offerCandidates: input.offerCandidates,
      selectedCandidateId: input.selectedCandidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider: input.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      collisionCounter: input.collisionCounter,
      state: 'started',
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      expiresAtMs: nowMs + 30 * 60_000,
      runtimePolicyScope: input.runtimePolicyScope,
    };
    await this.putGoogleEmailOtpRegistrationAttempt(attempt);
    return attempt;
  }

  private async findStartedGoogleEmailOtpRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
    const nowMs = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(nowMs);
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND app_session_version = ?
          AND runtime_org_id = ?
          AND runtime_policy_key = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [
        input.providerSubject,
        input.email,
        nowMs,
        input.appSessionVersion,
        input.orgId,
        runtimePolicyScopeKey(input.runtimePolicyScope),
      ],
    ).first<D1EmailOtpRegistrationAttemptRow>();
    const parsed = parseGoogleEmailOtpRegistrationAttemptRow(row);
    if (!parsed) {
      const malformedAttemptId = toOptionalTrimmedString(row?.attempt_id);
      if (malformedAttemptId) await this.deleteGoogleEmailOtpRegistrationAttempt(malformedAttemptId);
      return null;
    }
    if (
      !registrationAttemptMatchesStartedScope(parsed, {
        providerSubject: input.providerSubject,
        email: input.email,
        orgId: input.orgId,
        appSessionVersion: input.appSessionVersion,
        runtimePolicyScope: input.runtimePolicyScope,
        nowMs,
      })
    ) {
      return null;
    }
    if (!this.isHostedHmacReadableRelayerSubaccount(parsed.walletId)) {
      await this.putGoogleEmailOtpRegistrationAttempt(
        failedGoogleEmailOtpRegistrationAttemptRecord({
          record: parsed,
          failureCode: 'non_hmac_readable_wallet_id',
          updatedAtMs: nowMs,
        }),
      );
      return null;
    }
    const refreshed = pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt(parsed, nowMs);
    await this.putGoogleEmailOtpRegistrationAttempt(refreshed);
    return refreshed;
  }

  private async abandonStartedGoogleEmailOtpRegistrationAttemptsExceptAppSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly nowMs: number;
    readonly failureCode: 'app_session_version_replaced';
  }): Promise<void> {
    const result = await this.scopePrepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?`,
      [input.providerSubject, input.email, input.nowMs],
    ).all<D1EmailOtpRegistrationAttemptRow>();
    for (const row of result.results || []) {
      const parsed = parseGoogleEmailOtpRegistrationAttemptRow(row);
      if (!parsed) {
        const malformedAttemptId = toOptionalTrimmedString(row.attempt_id);
        if (malformedAttemptId) {
          await this.deleteGoogleEmailOtpRegistrationAttempt(malformedAttemptId);
        }
        continue;
      }
      if (!registrationAttemptMatchesReplacementScope(parsed, input)) continue;
      await this.putGoogleEmailOtpRegistrationAttempt(
        abandonedGoogleEmailOtpRegistrationAttemptRecord({
          record: parsed,
          failureCode: input.failureCode,
          updatedAtMs: input.nowMs,
        }),
      );
    }
  }

  private async hasLiveStartedGoogleEmailOtpWalletAttempt(input: {
    readonly walletId: string;
    readonly nowMs: number;
  }): Promise<boolean> {
    const row = await this.scopePrepare(
      `SELECT 1 AS found
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND (
            wallet_id = ?
            OR EXISTS (
              SELECT 1
                FROM json_each(offer_wallet_ids_json)
               WHERE value = ?
            )
          )
        LIMIT 1`,
      [input.nowMs, input.walletId, input.walletId],
    ).first<{ readonly found?: unknown }>();
    return Boolean(row);
  }

  private async readGoogleEmailOtpRegistrationAttempt(
    attemptId: string,
  ): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?
        LIMIT 1`,
      [attemptId],
    ).first<D1EmailOtpRegistrationAttemptRow>();
    return parseGoogleEmailOtpRegistrationAttemptRow(row);
  }

  private async completeGoogleEmailOtpRegistrationAttempt(input: {
    readonly registrationAttemptId?: unknown;
    readonly walletId?: unknown;
  }): Promise<{ readonly ok: true } | { readonly ok: false; readonly code: string; readonly message: string }> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return { ok: true };
    const walletId = toOptionalTrimmedString(input.walletId);
    const attempt = await this.readGoogleEmailOtpRegistrationAttempt(registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      await this.putGoogleEmailOtpRegistrationAttempt(
        expiredGoogleEmailOtpRegistrationAttemptRecord({
          record: attempt,
          updatedAtMs: Date.now(),
        }),
      );
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (walletId !== attempt.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt is no longer active',
      };
    }
    const linked = await this.linkIdentity({
      userId: attempt.walletId,
      subject: `wallet:${attempt.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      await this.putGoogleEmailOtpRegistrationAttempt(
        failedGoogleEmailOtpRegistrationAttemptWithCode({
          record: attempt,
          failureCode: linked.code,
          updatedAtMs: Date.now(),
        }),
      );
      return { ok: false, code: linked.code, message: linked.message };
    }
    await this.putGoogleEmailOtpRegistrationAttempt(
      activeGoogleEmailOtpRegistrationAttemptRecord({
        record: attempt,
        updatedAtMs: Date.now(),
      }),
    );
    return { ok: true };
  }

  private async putGoogleEmailOtpRegistrationAttempt(
    record: GoogleEmailOtpRegistrationAttemptRecord,
  ): Promise<void> {
    if (record.runtimePolicyScope?.orgId !== this.options.orgId) {
      throw new Error('Google Email OTP registration attempt org scope mismatch');
    }
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        attempt_id,
        provider_subject,
        email,
        wallet_id,
        state,
        app_session_version,
        runtime_org_id,
        runtime_policy_key,
        offer_wallet_ids_json,
        record_json,
        created_at_ms,
        updated_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, attempt_id)
      DO UPDATE SET
        provider_subject = EXCLUDED.provider_subject,
        email = EXCLUDED.email,
        wallet_id = EXCLUDED.wallet_id,
        state = EXCLUDED.state,
        app_session_version = EXCLUDED.app_session_version,
        runtime_org_id = EXCLUDED.runtime_org_id,
        runtime_policy_key = EXCLUDED.runtime_policy_key,
        offer_wallet_ids_json = EXCLUDED.offer_wallet_ids_json,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        record.attemptId,
        record.providerSubject,
        record.email,
        record.walletId,
        record.state,
        record.appSessionVersion,
        record.runtimePolicyScope?.orgId || '',
        runtimePolicyScopeKey(record.runtimePolicyScope),
        googleEmailOtpRegistrationOfferWalletIdsJson(record.offerCandidates),
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async deleteGoogleEmailOtpRegistrationAttempt(attemptId: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?`,
      [attemptId],
    ).run();
  }

  private async resolveAddSignerExistingAuth(input: {
    readonly auth: StartWalletAddSignerInput['auth'];
    readonly walletId: WalletId;
    readonly rpId: string;
    readonly intent: AddSignerIntentV1;
    readonly walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<
    | {
        readonly ok: true;
        readonly auth: StoredWalletAddSignerCeremony['auth'];
      }
    | {
        readonly ok: false;
        readonly code: string;
        readonly message: string;
      }
  > {
    if (input.auth.kind === 'app_session') {
      if (input.auth.policy.walletId !== input.walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-signer auth.policy wallet mismatch',
        };
      }
      if (!addSignerSelectionMatches(input.auth.policy.signerSelection, input.intent.signerSelection)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-signer auth.policy selection mismatch',
        };
      }
      if (
        !runtimePolicyScopeMatches(
          input.auth.policy.runtimePolicyScope,
          input.intent.runtimePolicyScope,
        )
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-signer auth.policy runtime scope mismatch',
        };
      }
      if (input.auth.policy.expiresAtMs <= Date.now()) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-signer auth.policy is expired',
        };
      }
      return { ok: true, auth: { kind: 'app_session' } };
    }

    const credentialId = webAuthnCredentialIdB64uFromCredential(input.auth.credential);
    if (!credentialId.ok) return credentialId;
    const authorizationMethod = await input.walletAuthMethodStore.getPasskey({
      rpId: input.rpId,
      credentialIdB64u: credentialId.credentialIdB64u,
    });
    if (
      !authorizationMethod ||
      authorizationMethod.kind !== 'passkey' ||
      authorizationMethod.walletId !== input.walletId ||
      authorizationMethod.status !== 'active'
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'WebAuthn authorization credential is not active for this wallet',
      };
    }
    return {
      ok: true,
      auth: {
        kind: 'webauthn_assertion',
        credentialIdB64u: credentialId.credentialIdB64u,
      },
    };
  }

  private async resolveAddAuthMethodExistingAuth(input: {
    readonly auth: StartWalletAddAuthMethodInput['auth'];
    readonly walletId: WalletId;
    readonly rpId: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<
    | {
        readonly ok: true;
        readonly auth: StoredWalletAddAuthMethodCeremony['auth'];
      }
    | {
        readonly ok: false;
        readonly code: string;
        readonly message: string;
      }
  > {
    if (input.auth.kind === 'app_session') {
      if (input.auth.policy.walletId !== input.walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method auth.policy wallet mismatch',
        };
      }
      if (!addAuthMethodInputMatches(input.auth.policy.authMethod, input.intent.authMethod)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method auth.policy method mismatch',
        };
      }
      if (
        !runtimePolicyScopeMatches(
          input.auth.policy.runtimePolicyScope,
          input.intent.runtimePolicyScope,
        )
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method auth.policy runtime scope mismatch',
        };
      }
      if (input.auth.policy.expiresAtMs <= Date.now()) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method auth.policy is expired',
        };
      }
      return { ok: true, auth: { kind: 'app_session' } };
    }

    const credentialId = webAuthnCredentialIdB64uFromCredential(input.auth.credential);
    if (!credentialId.ok) return credentialId;
    const authorizationMethod = await input.walletAuthMethodStore.getPasskey({
      rpId: input.rpId,
      credentialIdB64u: credentialId.credentialIdB64u,
    });
    if (
      !authorizationMethod ||
      authorizationMethod.kind !== 'passkey' ||
      authorizationMethod.walletId !== input.walletId ||
      authorizationMethod.status !== 'active'
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'WebAuthn authorization credential is not active for this wallet',
      };
    }
    return {
      ok: true,
      auth: {
        kind: 'webauthn_assertion',
        credentialIdB64u: credentialId.credentialIdB64u,
      },
    };
  }

  private async verifyRegistrationCredentialForIntent(input: {
    readonly webauthnRegistration: unknown;
    readonly expectedChallenge: string;
    readonly expectedOrigin: string;
    readonly rpId: string;
  }): Promise<
    | {
        readonly ok: true;
        readonly credential: {
          readonly credentialIdB64u: string;
          readonly credentialPublicKeyB64u: string;
          readonly counter: number;
        };
      }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    const credential = toRecordValue(input.webauthnRegistration);
    if (!credential) {
      return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };
    }
    const response = toRecordValue(credential.response);
    const clientDataJSON = toOptionalTrimmedString(response?.clientDataJSON);
    const clientData = parseClientDataJsonBase64url(clientDataJSON);
    if (clientData.type !== 'webauthn.create') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
      };
    }
    if (clientData.challenge !== input.expectedChallenge) {
      return { ok: false, code: 'challenge_mismatch', message: 'Registration challenge mismatch' };
    }
    const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
    if (!expectedOrigin) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'expected_origin is required for WebAuthn registration verification',
      };
    }
    if (!isHostWithinRpId(originHostnameOrEmpty(clientData.origin), input.rpId)) {
      return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
    }

    const mod = await loadSimpleWebAuthnServer();
    const verifyRegistrationResponse = mod.verifyRegistrationResponse;
    if (typeof verifyRegistrationResponse !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'WebAuthn registration verifier is unavailable in this runtime',
      };
    }
    const registration = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: input.expectedChallenge,
      expectedOrigin,
      expectedRPID: input.rpId,
      requireUserVerification: false,
    });
    const registrationRecord = toRecordValue(registration);
    if (registrationRecord?.verified !== true) {
      return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
    }
    const registrationInfo = toRecordValue(registrationRecord.registrationInfo);
    const credentialInfo = toRecordValue(registrationInfo?.credential);
    const credentialIdB64u = toOptionalTrimmedString(credentialInfo?.id);
    const publicKey = credentialInfo?.publicKey;
    if (!credentialInfo || !credentialIdB64u || !(publicKey instanceof Uint8Array)) {
      return {
        ok: false,
        code: 'internal',
        message: 'Registration verification did not return credential public key material',
      };
    }
    const counter = Number(credentialInfo.counter);
    return {
      ok: true,
      credential: {
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(publicKey),
        counter: Number.isFinite(counter) && counter >= 0 ? Math.floor(counter) : 0,
      },
    };
  }

  private async verifyAddAuthMethodAuthority(input: {
    readonly orgId: string;
    readonly authority: StartWalletAddAuthMethodInput['authority'];
    readonly expectedDigestB64u: string;
    readonly expectedOrigin: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<
    | { readonly ok: true; readonly authority: RegistrationAuthority }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    const authority = input.authority;
    switch (authority.kind) {
      case 'passkey':
        return await this.verifyAddAuthMethodPasskeyAuthority({
          authority,
          expectedDigestB64u: input.expectedDigestB64u,
          expectedOrigin: input.expectedOrigin,
          intent: input.intent,
          walletAuthMethodStore: input.walletAuthMethodStore,
        });
      case 'email_otp':
        return await this.verifyAddAuthMethodEmailOtpAuthority({
          orgId: input.orgId,
          authority,
          expectedDigestB64u: input.expectedDigestB64u,
          intent: input.intent,
          walletAuthMethodStore: input.walletAuthMethodStore,
        });
    }
    return unreachableAddAuthMethodAuthority(authority);
  }

  private async verifyAddAuthMethodPasskeyAuthority(input: {
    readonly authority: Extract<StartWalletAddAuthMethodInput['authority'], { kind: 'passkey' }>;
    readonly expectedDigestB64u: string;
    readonly expectedOrigin: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<
    | { readonly ok: true; readonly authority: Extract<RegistrationAuthority, { kind: 'passkey' }> }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    const rpId = parseWebAuthnRpId(input.intent.rpId);
    if (!rpId.ok) return { ok: false, code: 'invalid_body', message: rpId.error.message };
    const verified = await this.verifyRegistrationCredentialForIntent({
      webauthnRegistration: input.authority.webauthnRegistration,
      expectedChallenge: input.expectedDigestB64u,
      expectedOrigin: input.expectedOrigin,
      rpId: rpId.value,
    });
    if (!verified.ok) return verified;
    const duplicateCredential = await input.walletAuthMethodStore.getPasskey({
      rpId: rpId.value,
      credentialIdB64u: verified.credential.credentialIdB64u,
    });
    if (duplicateCredential) {
      return {
        ok: false,
        code: 'duplicate_auth_method',
        message: 'Passkey credential is already registered',
      };
    }
    return {
      ok: true,
      authority: {
        kind: 'passkey',
        walletId: input.intent.walletId,
        rpId: rpId.value,
        credentialIdB64u: verified.credential.credentialIdB64u,
        credentialPublicKeyB64u: verified.credential.credentialPublicKeyB64u,
        counter: verified.credential.counter,
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async verifyAddAuthMethodEmailOtpAuthority(input: {
    readonly orgId: string;
    readonly authority: Extract<StartWalletAddAuthMethodInput['authority'], { kind: 'email_otp' }>;
    readonly expectedDigestB64u: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<
    | {
        readonly ok: true;
        readonly authority: Extract<
          RegistrationAuthority,
          { kind: 'email_otp'; proofKind: 'otp_challenge' }
        >;
      }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    const proof = input.authority.emailOtpRegistrationProof;
    if (proof.proofKind !== 'otp_challenge') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP add-auth-method requires an OTP challenge proof',
      };
    }
    if (proof.registrationIntentDigestB64u !== input.expectedDigestB64u) {
      return {
        ok: false,
        code: 'registration_intent_digest_mismatch',
        message: 'Email OTP registration proof is not bound to this add-auth-method intent',
      };
    }
    if (input.intent.authMethod.kind !== 'email_otp') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP add-auth-method authority requires an Email OTP intent',
      };
    }
    if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
      return {
        ok: false,
        code: 'email_mismatch',
        message: 'Email OTP registration proof email does not match the intent',
      };
    }
    const verified = await this.verifyEmailOtpRegistrationChallengeCode({
      providerSubject: proof.providerSubject,
      proofEmail: proof.email,
      walletId: input.intent.walletId,
      orgId: input.orgId,
      challengeId: proof.challengeId,
      otpCode: proof.otpCode,
      otpChannel: proof.otpChannel,
      sessionHash: input.expectedDigestB64u,
      appSessionVersion: proof.appSessionVersion,
    });
    if (!verified.ok) return verified;
    const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase();
    if (verifiedEmail !== proof.email) {
      return {
        ok: false,
        code: 'email_mismatch',
        message: 'Verified Email OTP address does not match the registration proof',
      };
    }
    const emailHashHex = bytesToHex(
      await sha256BytesPortable(new TextEncoder().encode(proof.email)),
    );
    const duplicateEmailOtp = await input.walletAuthMethodStore.getEmailOtp({
      walletId: input.intent.walletId,
      emailHashHex,
    });
    if (duplicateEmailOtp && duplicateEmailOtp.status === 'active') {
      return {
        ok: false,
        code: 'duplicate_auth_method',
        message: 'Email OTP auth method is already registered',
      };
    }
    const providerSubject = parseProviderSubject(proof.providerSubject);
    const challengeSubjectId = parseChallengeSubjectId(proof.providerSubject);
    const challengeId = parseEmailOtpChallengeId(proof.challengeId);
    const orgId = parseOrgId(input.orgId);
    const appSessionVersion = parseAppSessionVersion(proof.appSessionVersion);
    if (
      !providerSubject.ok ||
      !challengeSubjectId.ok ||
      !challengeId.ok ||
      !orgId.ok ||
      !appSessionVersion.ok
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration proof contains invalid domain fields',
      };
    }
    return {
      ok: true,
      authority: {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        walletId: input.intent.walletId,
        providerSubject: providerSubject.value,
        challengeSubjectId: challengeSubjectId.value,
        email: proof.email,
        emailHashHex,
        challengeId: challengeId.value,
        registrationAuthorityId: challengeId.value,
        originalWalletId: input.intent.walletId,
        finalWalletId: input.intent.walletId,
        orgId: orgId.value,
        appSessionVersion: appSessionVersion.value,
        challengePurpose: 'registration',
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async findDuplicateAddAuthMethodAuthority(
    authority: RegistrationAuthority,
  ): Promise<{ readonly ok: false; readonly code: string; readonly message: string } | null> {
    if (authority.kind === 'passkey') {
      const duplicateCredential = await this.getWalletAuthMethodStore().getPasskey({
        rpId: authority.rpId,
        credentialIdB64u: authority.credentialIdB64u,
      });
      return duplicateCredential
        ? {
            ok: false,
            code: 'duplicate_auth_method',
            message: 'Passkey credential is already registered',
          }
        : null;
    }
    const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtp({
      walletId: authority.walletId,
      emailHashHex: authority.emailHashHex,
    });
    return duplicateEmailOtp && duplicateEmailOtp.status === 'active'
      ? {
          ok: false,
          code: 'duplicate_auth_method',
          message: 'Email OTP auth method is already registered',
        }
      : null;
  }

  private async persistAddAuthMethodAuthority(input: {
    readonly authority: RegistrationAuthority;
    readonly now: number;
  }): Promise<void> {
    if (input.authority.kind === 'passkey') {
      await this.writeWebAuthnAuthenticator({
        userId: input.authority.walletId,
        record: {
          credentialIdB64u: input.authority.credentialIdB64u,
          credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
          counter: input.authority.counter,
          createdAtMs: input.now,
          updatedAtMs: input.now,
        },
      });
    }
    await this.getWalletAuthMethodStore().put(
      walletAuthMethodRecordFromRegistrationAuthority({
        authority: input.authority,
        now: input.now,
      }),
    );
  }

  private getRegistrationCeremonyIntentStore(): CloudflareD1RegistrationCeremonyIntentStore | null {
    if (this.registrationCeremonyIntentStore) return this.registrationCeremonyIntentStore;
    const config = resolveRegistrationCeremonyDoConfig(this.options.thresholdStore);
    if (!config) return null;
    this.registrationCeremonyIntentStore = new CloudflareD1RegistrationCeremonyIntentStore(config);
    return this.registrationCeremonyIntentStore;
  }

  private async createAvailableGeneratedWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly rpId: string;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const walletId = createD1GeneratedWalletId();
      const existing = await this.signerWalletExists(walletId);
      if (existing) continue;
      const reserved = await input.store.reserveGeneratedWalletId({
        rpId: input.rpId,
        walletId,
        expiresAtMs: input.expiresAtMs,
      });
      if (reserved) return { ok: true, walletId };
    }
    return {
      ok: false,
      code: 'wallet_id_collision',
      message: 'Unable to allocate an unused generated walletId',
    };
  }

  private async resolveGenericRegistrationWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly wallet: RegisterWalletInput | undefined;
    readonly rpId: string;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    if (!input.wallet || input.wallet.kind === 'server_generated') {
      return await this.createAvailableGeneratedWalletId(input);
    }
    if (input.wallet.kind === 'provided') {
      const walletId = parseWalletIdForIntent(input.wallet.walletId);
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      return { ok: true, walletId };
    }
    return { ok: false, code: 'invalid_body', message: 'wallet.kind is unsupported' };
  }

  private async resolveRegistrationIntentWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly wallet: RegisterWalletInput | undefined;
    readonly signerSelection: RegistrationSignerSelection;
    readonly rpId: string;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    if (input.signerSelection.mode === 'ecdsa_only') {
      return await this.resolveGenericRegistrationWalletId(input);
    }
    const provisioning = input.signerSelection.ed25519.accountProvisioning;
    switch (provisioning.kind) {
      case 'implicit_account':
        if (input.wallet?.kind === 'provided') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'implicit account registration requires server_generated wallet allocation',
          };
        }
        return await this.createAvailableGeneratedWalletId(input);
      case 'sponsored_named_account': {
        if (input.wallet?.kind !== 'provided') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'sponsored named registration requires a provided walletId',
          };
        }
        const walletId = parseWalletIdForIntent(input.wallet.walletId);
        if (!walletId) {
          return { ok: false, code: 'invalid_body', message: 'walletId is required' };
        }
        return { ok: true, walletId };
      }
      default: {
        const exhaustive: never = provisioning;
        return {
          ok: false,
          code: 'invalid_body',
          message: `unsupported account provisioning: ${String(exhaustive)}`,
        };
      }
    }
  }

  private getWalletAuthMethodStore(): WalletAuthMethodStore {
    if (this.walletAuthMethodStore) return this.walletAuthMethodStore;
    this.walletAuthMethodStore = new D1WalletAuthMethodStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
      ensureSchema: false,
    });
    return this.walletAuthMethodStore;
  }

  private getWalletStore(): WalletStore {
    if (this.walletStore) return this.walletStore;
    this.walletStore = new D1WalletStore({
      database: this.options.database,
      namespace: this.options.namespace,
      orgId: this.options.orgId,
      projectId: this.options.projectId,
      envId: this.options.envId,
      ensureSchema: false,
    });
    return this.walletStore;
  }

  private async findWalletAuthMethodRecordForRevokeTarget(input: {
    readonly walletAuthMethodStore: WalletAuthMethodStore;
    readonly walletId: WalletId;
    readonly rpId: string;
    readonly target: D1RevokeWalletAuthMethodTarget;
  }): Promise<WalletAuthMethodRecord | null> {
    switch (input.target.kind) {
      case 'passkey': {
        const record = await input.walletAuthMethodStore.getPasskey({
          rpId: input.rpId,
          credentialIdB64u: input.target.credentialIdB64u,
        });
        if (!record || record.kind !== 'passkey' || record.walletId !== input.walletId) {
          return null;
        }
        return record;
      }
      case 'email_otp': {
        const emailBytes = new TextEncoder().encode(input.target.email);
        const emailHashHex = bytesToHex(await sha256BytesPortable(emailBytes));
        const record = await input.walletAuthMethodStore.getEmailOtp({
          walletId: input.walletId,
          emailHashHex,
        });
        if (!record || record.kind !== 'email_otp') return null;
        return record;
      }
    }
  }

  private scopePrepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.options.database.prepare(sql).bind(...this.scopeValues(values));
  }

  private scopeValues(values: readonly unknown[]): readonly unknown[] {
    return [
      this.options.namespace,
      this.options.orgId,
      this.options.projectId,
      this.options.envId,
      ...values,
    ];
  }

  private async writeWebAuthnChallenge(input: {
    readonly challengeId: string;
    readonly challengeKind: WebAuthnChallengeKind;
    readonly record: WebAuthnLoginChallengeRecord | WebAuthnSyncChallengeRecord;
    readonly createdAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_webauthn_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_kind,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, challenge_id)
      DO UPDATE SET
        challenge_kind = EXCLUDED.challenge_kind,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        input.challengeId,
        input.challengeKind,
        JSON.stringify(input.record),
        input.createdAtMs,
        input.expiresAtMs,
      ],
    ).run();
  }

  private async consumeWebAuthnLoginChallenge(
    challengeId: string,
  ): Promise<WebAuthnLoginChallengeRecord | null> {
    const row = await this.consumeWebAuthnChallenge({
      challengeId,
      challengeKind: 'login',
    });
    return parseWebAuthnLoginChallengeRecord(row?.record_json);
  }

  private async consumeWebAuthnSyncChallenge(
    challengeId: string,
  ): Promise<WebAuthnSyncChallengeRecord | null> {
    const row = await this.consumeWebAuthnChallenge({
      challengeId,
      challengeKind: 'sync',
    });
    return parseWebAuthnSyncChallengeRecord(row?.record_json);
  }

  private async consumeWebAuthnChallenge(input: {
    readonly challengeId: string;
    readonly challengeKind: WebAuthnChallengeKind;
  }): Promise<D1RecordJsonRow | null> {
    return await this.scopePrepare(
      `DELETE FROM signer_webauthn_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
          AND challenge_kind = ?
          AND expires_at_ms > ?
        RETURNING record_json`,
      [input.challengeId, input.challengeKind, Date.now()],
    ).first<D1RecordJsonRow>();
  }

  private async readWebAuthnAuthenticator(input: {
    readonly userId: string;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnAuthenticatorRecord | null> {
    const row = await this.scopePrepare(
      `SELECT credential_id_b64u, credential_public_key_b64u, counter, created_at_ms, updated_at_ms
         FROM signer_webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
          AND credential_id_b64u = ?
        LIMIT 1`,
      [input.userId, input.credentialIdB64u],
    ).first<D1AuthenticatorRow>();
    return parseWebAuthnAuthenticator(row);
  }

  private async writeWebAuthnAuthenticator(input: {
    readonly userId: string;
    readonly record: WebAuthnAuthenticatorRecord;
  }): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_webauthn_authenticators (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        credential_id_b64u,
        credential_public_key_b64u,
        counter,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, user_id, credential_id_b64u)
      DO UPDATE SET
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        counter = MAX(signer_webauthn_authenticators.counter, EXCLUDED.counter),
        created_at_ms = MIN(signer_webauthn_authenticators.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = MAX(signer_webauthn_authenticators.updated_at_ms, EXCLUDED.updated_at_ms)`,
      [
        input.userId,
        input.record.credentialIdB64u,
        input.record.credentialPublicKeyB64u,
        input.record.counter,
        input.record.createdAtMs,
        input.record.updatedAtMs,
      ],
    ).run();
  }

  private async updateWebAuthnAuthenticatorCounter(input: {
    readonly userId: string;
    readonly credentialIdB64u: string;
    readonly newCounter: number;
    readonly updatedAtMs: number;
  }): Promise<void> {
    await this.options.database
      .prepare(
        `UPDATE signer_webauthn_authenticators
          SET counter = ?,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
          AND credential_id_b64u = ?
          AND counter < ?`,
      )
      .bind(
        input.newCounter,
        input.updatedAtMs,
        this.options.namespace,
        this.options.orgId,
        this.options.projectId,
        this.options.envId,
        input.userId,
        input.credentialIdB64u,
        input.newCounter,
      )
      .run();
  }

  private async readWebAuthnBindingByCredential(input: {
    readonly rpId: string;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnCredentialBindingRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json
         FROM signer_webauthn_credential_bindings
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND rp_id = ?
          AND credential_id_b64u = ?
        LIMIT 1`,
      [input.rpId, input.credentialIdB64u],
    ).first<D1RecordJsonRow>();
    return parseWebAuthnBinding(row || {});
  }

  private async readIdentityLinkBySubject(subject: string): Promise<D1IdentityRow | null> {
    return await this.scopePrepare(
      `SELECT user_id, created_at_ms
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND subject = ?
        LIMIT 1`,
      [subject],
    ).first<D1IdentityRow>();
  }

  private async readIdentityUserIdBySubject(subject: string): Promise<string | null> {
    const row = await this.readIdentityLinkBySubject(subject);
    return toOptionalTrimmedString(row?.user_id) || null;
  }

  private async deleteIdentitySubjectLinkForDevCleanup(input: {
    readonly userId: string;
    readonly subject: string;
  }): Promise<UnlinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const deleted = d1MutationChanges(
      await this.scopePrepare(
        `DELETE FROM signer_identity_links
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND subject = ?
            AND user_id = ?`,
        [subject, userId],
      ).run(),
    );
    if (deleted === 0) {
      return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
    }
    return { ok: true };
  }

  private async readIdentitySubjectCountForUserId(userId: string): Promise<number> {
    const row = await this.scopePrepare(
      `SELECT COUNT(*) AS subject_count
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?`,
      [userId],
    ).first<D1IdentityRow>();
    return parseIdentitySubjectCount(row?.subject_count);
  }

  private async readIdentitySubjectsByUserId(userId: string): Promise<string[]> {
    const result = await this.scopePrepare(
      `SELECT subject
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY subject ASC`,
      [userId],
    ).all<D1IdentityRow>();
    const subjects: string[] = [];
    for (const row of result.results || []) {
      const subject = toOptionalTrimmedString(row.subject);
      if (subject) subjects.push(subject);
    }
    return subjects;
  }

  private async moveIdentityIfAllowed(input: {
    readonly userId: string;
    readonly subject: string;
    readonly existingUserId: string;
    readonly createdAtMs: number;
    readonly updatedAtMs: number;
    readonly allowMoveIfSoleIdentity: boolean;
  }): Promise<LinkIdentityResult> {
    if (!input.allowMoveIfSoleIdentity) return identityAlreadyLinked();

    const moved = d1MutationChanges(
      await this.options.database
        .prepare(
          `UPDATE signer_identity_links
              SET user_id = ?,
                  record_json = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND project_id = ?
              AND env_id = ?
              AND subject = ?
              AND user_id = ?
              AND (
                SELECT COUNT(*)
                  FROM signer_identity_links
                 WHERE namespace = ?
                   AND org_id = ?
                   AND project_id = ?
                   AND env_id = ?
                   AND user_id = ?
              ) = 1`,
        )
        .bind(
          input.userId,
          JSON.stringify(
            identitySubjectRecord({
              subject: input.subject,
              userId: input.userId,
              createdAtMs: input.createdAtMs,
              updatedAtMs: input.updatedAtMs,
            }),
          ),
          input.updatedAtMs,
          ...this.scopeValues([input.subject, input.existingUserId]),
          ...this.scopeValues([input.existingUserId]),
        )
        .run(),
    );

    if (moved > 0) return { ok: true, movedFromUserId: input.existingUserId };
    const subjectCount = await this.readIdentitySubjectCountForUserId(input.existingUserId);
    if (subjectCount !== 1) return identityMoveDisallowed();
    return identityAlreadyLinked();
  }

  private async readEmailOtpWalletEnrollment(
    walletId: string,
  ): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  private async readEmailOtpWalletEnrollmentByProviderUserId(input: {
    readonly providerUserId: string;
    readonly orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_user_id = ?
          AND record_org_id = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [input.providerUserId, input.orgId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  private async signerWalletExists(walletId: string): Promise<boolean> {
    const row = await this.scopePrepare(
      `SELECT 1 AS found
         FROM signer_wallets
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<{ readonly found?: unknown }>();
    return Boolean(row);
  }

  private async deleteEmailOtpWalletEnrollment(walletId: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?`,
      [walletId],
    ).run();
  }

  private async putEmailOtpWalletEnrollment(
    record: EmailOtpWalletEnrollmentRecord,
  ): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_wallet_enrollments (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        verified_email,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        verified_email = EXCLUDED.verified_email,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.walletId,
        record.providerUserId,
        record.orgId,
        record.verifiedEmail,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

  private async readEmailOtpAuthState(
    walletId: string,
  ): Promise<EmailOtpAuthStateRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_auth_states
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpAuthStateRow>();
    return parseEmailOtpAuthStateRow(row);
  }

  private async readEmailOtpAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<
    | { ok: true; state: EmailOtpAuthStateRecord | null }
    | { ok: false; code: string; message: string }
  > {
    const state = await this.readEmailOtpAuthState(enrollment.walletId);
    if (!state) return { ok: true, state: null };
    if (state.orgId !== enrollment.orgId || state.providerUserId !== enrollment.providerUserId) {
      return {
        ok: false,
        code: 'auth_state_enrollment_mismatch',
        message: 'Email OTP auth state does not match the active enrollment',
      };
    }
    return { ok: true, state };
  }

  private async putEmailOtpAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
    patch: EmailOtpAuthStatePatch,
  ): Promise<EmailOtpAuthStateRecord> {
    const nowMs = Date.now();
    const existing = await this.readEmailOtpAuthState(enrollment.walletId);
    if (
      existing &&
      (existing.orgId !== enrollment.orgId || existing.providerUserId !== enrollment.providerUserId)
    ) {
      throw new Error('Email OTP auth state does not match the active enrollment');
    }
    const next = emailOtpAuthStateRecord({
      enrollment,
      existing,
      updatedAtMs: nowMs,
      patch,
    });
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        next.walletId,
        next.providerUserId,
        next.orgId,
        JSON.stringify(next),
        next.createdAtMs,
        next.updatedAtMs,
      ],
    ).run();
    return next;
  }

  private async resetEmailOtpAuthStateForEnrollment(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly existingState: EmailOtpAuthStateRecord | null;
    readonly updatedAtMs: number;
  }): Promise<EmailOtpAuthStateRecord> {
    const reusableExisting =
      input.existingState &&
      input.existingState.providerUserId === input.enrollment.providerUserId &&
      input.existingState.orgId === input.enrollment.orgId
        ? input.existingState
        : null;
    const next = emailOtpAuthStateRecord({
      enrollment: input.enrollment,
      existing: reusableExisting,
      updatedAtMs: input.updatedAtMs,
      patch: {
        otpFailureCount: 0,
        lastOtpFailureAtMs: null,
        otpLockedUntilMs: null,
      },
    });
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        next.walletId,
        next.providerUserId,
        next.orgId,
        JSON.stringify(next),
        next.createdAtMs,
        next.updatedAtMs,
      ],
    ).run();
    return next;
  }

  private async resetEmailOtpFailureState(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly authState: EmailOtpAuthStateRecord | null;
  }): Promise<void> {
    const hasFailureState =
      Number(input.authState?.otpFailureCount || 0) > 0 ||
      input.authState?.lastOtpFailureAtMs != null ||
      input.authState?.otpLockedUntilMs != null;
    if (!hasFailureState) return;
    await this.putEmailOtpAuthStateForEnrollment(input.enrollment, {
      otpFailureCount: 0,
      lastOtpFailureAtMs: null,
      otpLockedUntilMs: null,
    });
  }

  private async recordEmailOtpInvalidAttempt(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly authState: EmailOtpAuthStateRecord | null;
    readonly record: EmailOtpChallengeRecord;
  }): Promise<Extract<EmailOtpExistingChallengeVerifyResult, { ok: false }>> {
    const nextAttemptCount = input.record.attemptCount + 1;
    const nextFailureCount = Number(input.authState?.otpFailureCount || 0) + 1;
    const exhausted = nextAttemptCount >= input.record.maxAttempts;
    const nowMs = Date.now();
    const lockedUntilMs = exhausted ? nowMs + this.options.emailOtp.lockoutTtlMs : undefined;
    await this.putEmailOtpAuthStateForEnrollment(input.enrollment, {
      otpFailureCount: nextFailureCount,
      lastOtpFailureAtMs: nowMs,
      ...(lockedUntilMs ? { otpLockedUntilMs: lockedUntilMs } : {}),
    });
    if (exhausted) {
      await this.deleteEmailOtpChallenge(input.record.challengeId);
      return {
        ok: false,
        code: 'otp_attempts_exhausted',
        message: 'Email OTP challenge exceeded the maximum number of attempts',
        attemptsRemaining: 0,
        ...(lockedUntilMs ? { lockedUntilMs } : {}),
      };
    }
    await this.updateEmailOtpChallengeAttemptCount(input.record, nextAttemptCount);
    return {
      ok: false,
      code: 'invalid_otp',
      message: 'OTP code is invalid',
      attemptsRemaining: input.record.maxAttempts - nextAttemptCount,
    };
  }

  private async recordEmailOtpInvalidRegistrationAttempt(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord | null;
    readonly authState: EmailOtpAuthStateRecord | null;
    readonly record: EmailOtpChallengeRecord;
  }): Promise<Extract<EmailOtpRegistrationChallengeVerifyResult, { ok: false }>> {
    if (input.enrollment) {
      return await this.recordEmailOtpInvalidAttempt({
        enrollment: input.enrollment,
        authState: input.authState,
        record: input.record,
      });
    }
    const nextAttemptCount = input.record.attemptCount + 1;
    const exhausted = nextAttemptCount >= input.record.maxAttempts;
    const lockedUntilMs = exhausted ? Date.now() + this.options.emailOtp.lockoutTtlMs : undefined;
    if (exhausted) {
      await this.deleteEmailOtpChallenge(input.record.challengeId);
      return {
        ok: false,
        code: 'otp_attempts_exhausted',
        message: 'Email OTP challenge exceeded the maximum number of attempts',
        attemptsRemaining: 0,
        ...(lockedUntilMs ? { lockedUntilMs } : {}),
      };
    }
    await this.updateEmailOtpChallengeAttemptCount(input.record, nextAttemptCount);
    return {
      ok: false,
      code: 'invalid_otp',
      message: 'OTP code is invalid',
      attemptsRemaining: input.record.maxAttempts - nextAttemptCount,
    };
  }

  private async pruneExpiredEmailOtpChallenges(nowMs: number): Promise<void> {
    const result = await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms <= ?
      RETURNING challenge_id`,
      [nowMs],
    ).all<D1EmailOtpChallengeRow>();
    for (const row of result.results || []) {
      const challengeId = toOptionalTrimmedString(row.challenge_id);
      if (challengeId) this.emailOtpMemoryOutbox.delete(challengeId);
    }
  }

  private async readEmailOtpChallenge(
    challengeId: string,
  ): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms
         FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
        LIMIT 1`,
      [challengeId],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private async findLatestActiveEmailOtpChallenge(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpChallengeIssueAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms
         FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND expires_at_ms > ?
        ORDER BY created_at_ms DESC
        LIMIT 1`,
      [...emailOtpChallengeContextValues(input), input.nowMs],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private async enforceEmailOtpActiveChallengeLimit(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpChallengeIssueAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<void> {
    let count = await this.countActiveEmailOtpChallenges(input);
    while (count >= this.options.emailOtp.maxActiveChallengesPerContext) {
      const deleted = await this.deleteOldestActiveEmailOtpChallenge(input);
      if (!deleted) return;
      this.emailOtpMemoryOutbox.delete(deleted.challengeId);
      count -= 1;
    }
  }

  private async countActiveEmailOtpChallenges(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpChallengeIssueAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<number> {
    const row = await this.scopePrepare(
      `SELECT COUNT(*) AS subject_count
         FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND expires_at_ms > ?`,
      [...emailOtpChallengeContextValues(input), input.nowMs],
    ).first<D1IdentityRow>();
    return parseIdentitySubjectCount(row?.subject_count);
  }

  private async deleteOldestActiveEmailOtpChallenge(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpChallengeIssueAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = (
            SELECT challenge_id
              FROM signer_email_otp_challenges
             WHERE namespace = ?
               AND org_id = ?
               AND project_id = ?
               AND env_id = ?
               AND challenge_subject_id = ?
               AND wallet_id = ?
               AND record_org_id = ?
               AND otp_channel = ?
               AND session_hash = ?
               AND app_session_version = ?
               AND action = ?
               AND operation = ?
               AND expires_at_ms > ?
             ORDER BY created_at_ms ASC
             LIMIT 1
          )
      RETURNING record_json, expires_at_ms`,
      [...this.scopeValues([]), ...this.scopeValues([...emailOtpChallengeContextValues(input), input.nowMs])],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private async putEmailOtpChallenge(record: EmailOtpChallengeRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_subject_id,
        wallet_id,
        record_org_id,
        otp_channel,
        session_hash,
        app_session_version,
        action,
        operation,
        otp_code,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.challengeSubjectId,
        record.walletId,
        record.orgId || '',
        EMAIL_OTP_CHANNEL,
        record.sessionHash,
        record.appSessionVersion,
        record.action,
        record.operation,
        record.otpCode,
        JSON.stringify(record),
        record.createdAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async updateEmailOtpChallengeAttemptCount(
    record: EmailOtpChallengeRecord,
    attemptCount: number,
  ): Promise<void> {
    const next = emailOtpChallengeWithAttemptCount(record, attemptCount);
    await this.scopePrepare(
      `UPDATE signer_email_otp_challenges
          SET record_json = ?,
              otp_code = ?,
              expires_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [JSON.stringify(next), next.otpCode, next.expiresAtMs, next.challengeId],
    ).run();
  }

  private async deleteEmailOtpChallenge(challengeId: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [challengeId],
    ).run();
    this.emailOtpMemoryOutbox.delete(challengeId);
  }

  private async consumeEmailOtpChallenge(
    challengeId: string,
  ): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [challengeId],
    ).first<D1EmailOtpChallengeRow>();
    this.emailOtpMemoryOutbox.delete(challengeId);
    return parseEmailOtpChallengeRow(row);
  }

  private async putEmailOtpUnlockChallenge(record: EmailOtpUnlockChallengeRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_unlock_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        wallet_id,
        user_id,
        record_org_id,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.walletId,
        record.userId,
        record.orgId || '',
        JSON.stringify(record),
        record.createdAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async consumeEmailOtpUnlockChallenge(
    challengeId: string,
  ): Promise<EmailOtpUnlockChallengeRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_unlock_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [challengeId],
    ).first<D1EmailOtpUnlockChallengeRow>();
    return parseEmailOtpUnlockChallengeRow(row);
  }

  private async putEmailOtpGrant(record: EmailOtpGrantRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_grants (
        namespace,
        org_id,
        project_id,
        env_id,
        grant_token,
        user_id,
        wallet_id,
        record_org_id,
        challenge_id,
        action,
        record_json,
        issued_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.grantToken,
        record.userId,
        record.walletId,
        record.orgId || '',
        record.challengeId,
        record.action,
        JSON.stringify(record),
        record.issuedAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private createEmailOtpServerSealCipher(): EmailOtpServerSealCipherResult {
    const config = this.options.emailOtpServerSeal;
    if (!config.configured) {
      return {
        ok: false,
        code: 'not_configured',
        message: config.message,
      };
    }
    try {
      return {
        ok: true,
        keyVersion: config.keyVersion,
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: config.keyVersion,
          keys: [
            {
              keyVersion: config.keyVersion,
              shamirPrimeB64u: config.shamirPrimeB64u,
              serverEncryptExponentB64u: config.serverEncryptExponentB64u,
              serverDecryptExponentB64u: config.serverDecryptExponentB64u,
            },
          ],
        }),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'not_configured',
        message: errorMessage(error) || 'Email OTP Shamir configuration is invalid',
      };
    }
  }

  private async deliverEmailOtpCode(record: EmailOtpChallengeRecord): Promise<
    | { ok: true; deliveryMode: EmailOtpDeliveryMode; emailHint: string }
    | { ok: false; code: string; message: string }
  > {
    if (this.options.emailOtp.production && this.options.emailOtp.deliveryMode !== 'email_provider') {
      return {
        ok: false,
        code: 'email_otp_delivery_not_allowed',
        message: `Email OTP delivery mode ${this.options.emailOtp.deliveryMode} is disabled in production`,
      };
    }
    const emailHint = maskEmail(record.email);
    if (this.options.emailOtp.deliveryMode === 'email_provider') {
      const provider = this.options.emailOtp.deliveryProvider;
      if (!provider) {
        return {
          ok: false,
          code: 'email_otp_delivery_not_configured',
          message: 'Email OTP email_provider delivery is not configured',
        };
      }
      const delivered = await provider.deliver({
        challengeId: record.challengeId,
        walletId: record.walletId,
        userId: record.challengeSubjectId,
        ...(record.orgId ? { orgId: record.orgId } : {}),
        email: record.email,
        emailHint,
        otpCode: record.otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        action: record.action,
        operation: record.operation,
        expiresAtMs: record.expiresAtMs,
      });
      if (!delivered.ok) return delivered;
      return { ok: true, deliveryMode: 'email_provider', emailHint };
    }
    if (this.options.emailOtp.deliveryMode === 'memory') {
      this.emailOtpMemoryOutbox.set(record.challengeId, {
        walletId: record.walletId,
        userId: record.challengeSubjectId,
        otpChannel: EMAIL_OTP_CHANNEL,
        emailHint,
        otpCode: record.otpCode,
        expiresAtMs: record.expiresAtMs,
      });
    }
    console.warn('[email-otp] development OTP code', {
      challengeId: record.challengeId,
      walletId: record.walletId,
      userId: record.challengeSubjectId,
      otpChannel: EMAIL_OTP_CHANNEL,
      action: record.action,
      operation: record.operation,
      deliveryMode: this.options.emailOtp.deliveryMode,
      emailHint,
      devOtpCode: record.otpCode,
      expiresAtMs: record.expiresAtMs,
    });
    return { ok: true, deliveryMode: this.options.emailOtp.deliveryMode, emailHint };
  }

  private async consumeEmailOtpRateLimit(input: {
    readonly scope: EmailOtpRateLimitScope;
    readonly action?: string;
    readonly userId?: string;
    readonly walletId?: string;
    readonly providerSubject?: string;
    readonly orgId?: string;
    readonly clientIp?: string;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const policy = this.options.emailOtp.rateLimits[input.scope];
    const keys = emailOtpRateLimitKeys({ ...input, policy });
    for (const key of keys) {
      const consumed = await this.consumeEmailOtpRateLimitKey({
        key,
        policy,
        nowMs: Date.now(),
      });
      if (!consumed.ok) return consumed;
    }
    return { ok: true };
  }

  private async consumeEmailOtpRateLimitKey(input: {
    readonly key: string;
    readonly policy: EmailOtpRateLimitPolicy;
    readonly nowMs: number;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const resetAtMs = input.nowMs + input.policy.windowMs;
    const row = await this.scopePrepare(
      `INSERT INTO signer_email_otp_rate_limits (
        namespace,
        org_id,
        project_id,
        env_id,
        rate_key,
        consumed_count,
        reset_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, rate_key)
      DO UPDATE SET
        consumed_count = CASE
          WHEN signer_email_otp_rate_limits.reset_at_ms <= ?
            THEN 1
          ELSE signer_email_otp_rate_limits.consumed_count + 1
        END,
        reset_at_ms = CASE
          WHEN signer_email_otp_rate_limits.reset_at_ms <= ?
            THEN ?
          ELSE signer_email_otp_rate_limits.reset_at_ms
        END,
        updated_at_ms = ?
      WHERE signer_email_otp_rate_limits.reset_at_ms <= ?
         OR signer_email_otp_rate_limits.consumed_count < ?
      RETURNING consumed_count, reset_at_ms`,
      [
        input.key,
        resetAtMs,
        input.nowMs,
        input.nowMs,
        input.nowMs,
        resetAtMs,
        input.nowMs,
        input.nowMs,
        input.policy.limit,
      ],
    ).first<D1EmailOtpRateLimitRow>();
    if (row) return { ok: true };
    const existing = await this.scopePrepare(
      `SELECT consumed_count, reset_at_ms
         FROM signer_email_otp_rate_limits
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND rate_key = ?
        LIMIT 1`,
      [input.key],
    ).first<D1EmailOtpRateLimitRow>();
    return emailOtpRateLimitExceeded(existing);
  }

  private async listEmailOtpRecoveryEscrowsForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const result = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        ORDER BY issued_at_ms ASC, recovery_key_id ASC`,
      [enrollment.walletId],
    ).all<D1EmailOtpRecoveryEscrowRow>();
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const row of result.results || []) {
      const escrow = parseEmailOtpRecoveryEscrowRow(row);
      if (!escrow) continue;
      if (!emailOtpRecoveryEscrowMatchesEnrollment({ escrow, enrollment })) continue;
      records.push(escrow);
    }
    return records;
  }

  private async readEmailOtpRecoveryEscrow(input: {
    readonly walletId: string;
    readonly recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND recovery_key_id = ?
        LIMIT 1`,
      [input.walletId, input.recoveryKeyId],
    ).first<D1EmailOtpRecoveryEscrowRow>();
    return parseEmailOtpRecoveryEscrowRow(row);
  }

  private async consumeEmailOtpRecoveryEscrow(input: {
    readonly record: Extract<
      EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
      { readonly recoveryKeyStatus: 'active' }
    >;
    readonly consumedAtMs: number;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const consumedRecord = consumedEmailOtpRecoveryEscrowRecord(input);
    const row = await this.options.database
      .prepare(
        `UPDATE signer_email_otp_recovery_wrapped_enrollment_escrows
            SET recovery_key_status = ?,
                record_json = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND recovery_key_id = ?
            AND recovery_key_status = 'active'
        RETURNING record_json, updated_at_ms`,
      )
      .bind(
        consumedRecord.recoveryKeyStatus,
        JSON.stringify(consumedRecord),
        consumedRecord.updatedAtMs,
        this.options.namespace,
        this.options.orgId,
        this.options.projectId,
        this.options.envId,
        consumedRecord.walletId,
        consumedRecord.recoveryKeyId,
      )
      .first<D1EmailOtpRecoveryEscrowRow>();
    return parseEmailOtpRecoveryEscrowRow(row);
  }

  private async putEmailOtpRecoveryEscrows(
    records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
  ): Promise<void> {
    if (records.length === 0) return;
    const statements: D1PreparedStatementLike[] = [];
    for (const record of records) {
      statements.push(this.putEmailOtpRecoveryEscrowStatement(record));
    }
    await this.options.database.batch(statements);
  }

  private putEmailOtpRecoveryEscrowStatement(
    record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  ): D1PreparedStatementLike {
    return this.scopePrepare(
      `INSERT INTO signer_email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        recovery_key_id,
        recovery_key_status,
        record_json,
        issued_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id)
      DO UPDATE SET
        recovery_key_status = EXCLUDED.recovery_key_status,
        record_json = EXCLUDED.record_json,
        issued_at_ms = EXCLUDED.issued_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.walletId,
        record.recoveryKeyId,
        record.recoveryKeyStatus,
        JSON.stringify(record),
        record.issuedAtMs,
        record.updatedAtMs,
      ],
    );
  }

  private async consumeEmailOtpGrantRecord(
    loginGrant: string,
  ): Promise<EmailOtpGrantRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
      RETURNING record_json, expires_at_ms`,
      [loginGrant],
    ).first<D1EmailOtpGrantRow>();
    return parseEmailOtpGrantRow(row);
  }

  private async readEmailOtpGrantRecord(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms
         FROM signer_email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
        LIMIT 1`,
      [grantToken],
    ).first<D1EmailOtpGrantRow>();
    return parseEmailOtpGrantRow(row);
  }

  private async deleteEmailOtpGrantRecord(grantToken: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?`,
      [grantToken],
    ).run();
  }

  private async readRecoverySessionRecord(
    sessionId: string,
  ): Promise<RecoverySessionRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json
         FROM signer_recovery_sessions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
        LIMIT 1`,
      [sessionId],
    ).first<D1RecoverySessionRow>();
    const record = parseRecoverySessionRecord(row?.record_json);
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) return null;
    return record;
  }

  private async putRecoverySessionRecord(record: RecoverySessionRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        near_account_id,
        record_json,
        expires_at_ms,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, session_id)
      DO UPDATE SET
        near_account_id = EXCLUDED.near_account_id,
        record_json = EXCLUDED.record_json,
        expires_at_ms = EXCLUDED.expires_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.sessionId,
        record.nearAccountId,
        JSON.stringify(record),
        record.expiresAtMs,
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

  private async readRecoveryExecutionRecord(input: {
    readonly sessionId: string;
    readonly chainIdKey: string;
    readonly accountAddress: string;
    readonly action: string;
  }): Promise<RecoveryExecutionRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json
         FROM signer_recovery_executions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
          AND chain_id_key = ?
          AND account_address = ?
          AND action = ?
        LIMIT 1`,
      [input.sessionId, input.chainIdKey, input.accountAddress, input.action],
    ).first<D1RecoveryExecutionRow>();
    return parseRecoveryExecutionRecord(row?.record_json);
  }

  private async putRecoveryExecutionRecord(record: RecoveryExecutionRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action,
        status,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action
      )
      DO UPDATE SET
        status = EXCLUDED.status,
        record_json = EXCLUDED.record_json,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.sessionId,
        record.chainIdKey,
        record.accountAddress,
        record.action,
        record.status,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

  private async readAppSessionVersion(userId: string): Promise<string | null> {
    const row = await this.scopePrepare(
      `SELECT session_version
         FROM signer_app_session_versions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        LIMIT 1`,
      [userId],
    ).first<D1SessionRow>();
    return toOptionalTrimmedString(row?.session_version) || null;
  }

  private async readWebAuthnAuthenticatorRows(userId: string): Promise<D1AuthenticatorRow[]> {
    const result = await this.scopePrepare(
      `SELECT credential_id_b64u, created_at_ms, updated_at_ms
         FROM signer_webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY created_at_ms ASC`,
      [userId],
    ).all<D1AuthenticatorRow>();
    return [...(result.results || [])];
  }

  private async readWebAuthnBindingRows(input: {
    readonly userId: string;
    readonly rpId?: string;
  }): Promise<D1RecordJsonRow[]> {
    const rpId = toOptionalTrimmedString(input.rpId);
    const sql = rpId
      ? `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
            AND rp_id = ?
          ORDER BY signer_slot ASC`
      : `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY signer_slot ASC`;
    const values = rpId ? [input.userId, rpId] : [input.userId];
    const result = await this.scopePrepare(sql, values).all<D1RecordJsonRow>();
    return [...(result.results || [])];
  }
}

function compareAuthenticatorSlots(
  left: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
  right: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
): number {
  return (Number(left.signerSlot || 0) || 0) - (Number(right.signerSlot || 0) || 0);
}

function identityAlreadyLinked(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is already linked to a different user',
  };
}

function identityMoveDisallowed(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is linked to a different user with other identities; merge is not allowed',
  };
}

function emailOtpEnrollmentTenantMismatch(): ReadEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'tenant_scope_mismatch',
    message: 'Email OTP enrollment does not match the requested orgId',
  };
}

function emailOtpRecoveryNotEnrolledStatus(walletId: string): GetEmailOtpRecoveryCodeStatusResult {
  return {
    ok: true,
    status: 'not_enrolled',
    walletId,
    enrollmentId: '',
    enrollmentSealKeyVersion: '',
    expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
    activeRecoveryCodeCount: 0,
    consumedRecoveryCodeCount: 0,
    revokedRecoveryCodeCount: 0,
    totalRecoveryCodeCount: 0,
    issuedAtMs: null,
  };
}

function emailOtpGrantInvalidOrExpired(): ConsumeEmailOtpGrantResult {
  return {
    ok: false,
    code: 'login_grant_invalid_or_expired',
    message: 'Login grant is invalid or expired',
  };
}

function emailOtpRecoveryConsumeGrantInvalidOrExpired(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'recovery_consume_grant_invalid_or_expired',
    message: 'Recovery consume grant is invalid or expired',
  };
}

function emailOtpRecoveryGrantBindingMismatch(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'recovery_grant_binding_mismatch',
    message: 'Recovery grant is not valid for the current app session',
  };
}

function consumedEmailOtpRecoveryEscrowRecord(input: {
  readonly record: Extract<
    EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    { readonly recoveryKeyStatus: 'active' }
  >;
  readonly consumedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  return {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    recoveryKeyStatus: 'consumed',
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.consumedAtMs,
    consumedAtMs: input.consumedAtMs,
  };
}

function emailOtpAuthStateRecord(input: {
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly existing: EmailOtpAuthStateRecord | null;
  readonly updatedAtMs: number;
  readonly patch: EmailOtpAuthStatePatch;
}): EmailOtpAuthStateRecord {
  const otpFailureCount = patchedNonNegativeAuthStateValue(
    input.existing?.otpFailureCount,
    input.patch.otpFailureCount,
  );
  const lastOtpFailureAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastOtpFailureAtMs,
    input.patch.lastOtpFailureAtMs,
  );
  const otpLockedUntilMs = patchedPositiveAuthStateValue(
    input.existing?.otpLockedUntilMs,
    input.patch.otpLockedUntilMs,
  );
  const lastEmailOtpLoginAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastEmailOtpLoginAtMs,
    input.patch.lastEmailOtpLoginAtMs,
  );
  const lastStrongAuthAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastStrongAuthAtMs,
    input.patch.lastStrongAuthAtMs,
  );
  return {
    version: 'email_otp_auth_state_v1',
    walletId: input.enrollment.walletId,
    providerUserId: input.enrollment.providerUserId,
    orgId: input.enrollment.orgId,
    createdAtMs: input.existing?.createdAtMs ?? input.updatedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

function patchedPositiveAuthStateValue(
  current: number | undefined,
  patch: number | null | undefined,
): number | undefined {
  if (patch === null) return undefined;
  if (patch === undefined) return current;
  return patch > 0 ? Math.floor(patch) : undefined;
}

function patchedNonNegativeAuthStateValue(
  current: number | undefined,
  patch: number | null | undefined,
): number | undefined {
  if (patch === null) return undefined;
  if (patch === undefined) return current;
  return patch >= 0 ? Math.floor(patch) : undefined;
}

export function createCloudflareD1RelayAuthService(
  input: CloudflareD1RelayAuthServiceOptions,
): CloudflareRelayAuthService {
  const service = createDisabledCloudflareRelayAuthService({
    relayerAccount: input.relayerAccount,
    relayerPublicKey: input.relayerPublicKey,
  });
  const metadata = new CloudflareD1RelayAuthMetadataService(input);
  service.createRegistrationIntent = metadata.createRegistrationIntent.bind(metadata);
  service.createAddSignerIntent = metadata.createAddSignerIntent.bind(metadata);
  service.startWalletAddSigner = metadata.startWalletAddSigner.bind(metadata);
  service.respondWalletAddSignerHss = metadata.respondWalletAddSignerHss.bind(metadata);
  service.finalizeWalletAddSigner = metadata.finalizeWalletAddSigner.bind(metadata);
  service.createAddAuthMethodIntent = metadata.createAddAuthMethodIntent.bind(metadata);
  service.startWalletAddAuthMethod = metadata.startWalletAddAuthMethod.bind(metadata);
  service.finalizeWalletAddAuthMethod = metadata.finalizeWalletAddAuthMethod.bind(metadata);
  service.listIdentities = metadata.listIdentities.bind(metadata);
  service.linkIdentity = metadata.linkIdentity.bind(metadata);
  service.unlinkIdentity = metadata.unlinkIdentity.bind(metadata);
  service.resolveOidcWalletId = metadata.resolveOidcWalletId.bind(metadata);
  service.consumeGoogleEmailOtpRegistrationAttemptRateLimit =
    metadata.consumeGoogleEmailOtpRegistrationAttemptRateLimit.bind(metadata);
  service.resolveGoogleEmailOtpSession = metadata.resolveGoogleEmailOtpSession.bind(metadata);
  service.cleanupGoogleEmailOtpDevRegistrationState =
    metadata.cleanupGoogleEmailOtpDevRegistrationState.bind(metadata);
  service.readEmailOtpEnrollment = metadata.readEmailOtpEnrollment.bind(metadata);
  service.readActiveEmailOtpEnrollment = metadata.readActiveEmailOtpEnrollment.bind(metadata);
  service.isEmailOtpStrongAuthRequired = metadata.isEmailOtpStrongAuthRequired.bind(metadata);
  service.markEmailOtpStrongAuthSatisfied = metadata.markEmailOtpStrongAuthSatisfied.bind(metadata);
  service.getEmailOtpRecoveryCodeStatus =
    metadata.getEmailOtpRecoveryCodeStatus.bind(metadata);
  service.createEmailOtpChallenge = metadata.createEmailOtpChallenge.bind(metadata);
  service.createEmailOtpEnrollmentChallenge =
    metadata.createEmailOtpEnrollmentChallenge.bind(metadata);
  service.verifyEmailOtpChallenge = metadata.verifyEmailOtpChallenge.bind(metadata);
  service.verifyEmailOtpEnrollment = metadata.verifyEmailOtpEnrollment.bind(metadata);
  service.createEmailOtpDeviceRecoveryChallenge =
    metadata.createEmailOtpDeviceRecoveryChallenge.bind(metadata);
  service.verifyEmailOtpDeviceRecoveryChallenge =
    metadata.verifyEmailOtpDeviceRecoveryChallenge.bind(metadata);
  service.readEmailOtpOutboxEntry = metadata.readEmailOtpOutboxEntry.bind(metadata);
  service.createEmailOtpUnlockChallenge = metadata.createEmailOtpUnlockChallenge.bind(metadata);
  service.verifyEmailOtpUnlockProof = metadata.verifyEmailOtpUnlockProof.bind(metadata);
  service.revokeWalletAuthMethod = metadata.revokeWalletAuthMethod.bind(metadata);
  service.applyEmailOtpServerSeal = metadata.applyEmailOtpServerSeal.bind(metadata);
  service.removeEmailOtpServerSeal = metadata.removeEmailOtpServerSeal.bind(metadata);
  service.consumeEmailOtpGrant = metadata.consumeEmailOtpGrant.bind(metadata);
  service.consumeEmailOtpRecoveryKey = metadata.consumeEmailOtpRecoveryKey.bind(metadata);
  service.rotateEmailOtpRecoveryKeys = metadata.rotateEmailOtpRecoveryKeys.bind(metadata);
  service.recordEmailOtpRecoveryKeyAttemptFailure =
    metadata.recordEmailOtpRecoveryKeyAttemptFailure.bind(metadata);
  service.getRecoverySession = metadata.getRecoverySession.bind(metadata);
  service.updateRecoverySessionStatus = metadata.updateRecoverySessionStatus.bind(metadata);
  service.recordRecoveryExecution = metadata.recordRecoveryExecution.bind(metadata);
  service.getOrCreateAppSessionVersion = metadata.getOrCreateAppSessionVersion.bind(metadata);
  service.rotateAppSessionVersion = metadata.rotateAppSessionVersion.bind(metadata);
  service.validateAppSessionVersion = metadata.validateAppSessionVersion.bind(metadata);
  service.listWebAuthnAuthenticatorsForUser =
    metadata.listWebAuthnAuthenticatorsForUser.bind(metadata);
  service.createWebAuthnLoginOptions = metadata.createWebAuthnLoginOptions.bind(metadata);
  service.createWebAuthnSyncAccountOptions =
    metadata.createWebAuthnSyncAccountOptions.bind(metadata);
  service.verifyWebAuthnAuthenticationLite =
    metadata.verifyWebAuthnAuthenticationLite.bind(metadata);
  service.verifyWebAuthnLogin = metadata.verifyWebAuthnLogin.bind(metadata);
  service.verifyWebAuthnSyncAccount = metadata.verifyWebAuthnSyncAccount.bind(metadata);
  service.listNearPublicKeysForUser = metadata.listNearPublicKeysForUser.bind(metadata);
  service.listThresholdEcdsaKeyIdentityTargetsForUser =
    metadata.listThresholdEcdsaKeyIdentityTargetsForUser.bind(metadata);
  service.listWalletEcdsaKeyFactsInventory =
    metadata.listWalletEcdsaKeyFactsInventory.bind(metadata);
  service.getThresholdSigningService = metadata.getThresholdSigningService.bind(metadata);
  service.ecdsaHssRoleLocalBootstrap = metadata.ecdsaHssRoleLocalBootstrap.bind(metadata);
  service.verifyEcdsaHssRoleLocalClientRootProofForExistingKey =
    metadata.verifyEcdsaHssRoleLocalClientRootProofForExistingKey.bind(metadata);
  service.ecdsaHssRoleLocalExportShare = metadata.ecdsaHssRoleLocalExportShare.bind(metadata);
  service.getGoogleOidcPublicConfig = metadata.getGoogleOidcPublicConfig.bind(metadata);
  service.verifyGoogleLogin = metadata.verifyGoogleLogin.bind(metadata);
  service.verifyOidcJwtExchange = metadata.verifyOidcJwtExchange.bind(metadata);
  return service;
}
