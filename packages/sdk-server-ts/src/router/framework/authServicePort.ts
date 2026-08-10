import type {
  WalletRegistrationNearProvisioningResponseV2,
  WalletRegistrationActivateResponseV2,
  WalletRegistrationRespondResponseV2,
  WalletRegistrationSetupResponseV2,
} from '../../core/threeRouteRegistrationContracts';
import type {
  WalletRegistrationNearProvisioningInput,
  WalletRegistrationActivateInput,
  WalletRegistrationRespondInput,
  WalletRegistrationSetupInput,
} from '../domains/walletRegistration/walletRegistrationInputs';
import type { WalletEmailOtpAction } from '@shared/utils/emailOtpDomain';
import type { OrgId, ProviderSubject, WalletId, WebAuthnRpId } from '@shared/utils/domainIds';
import type { WebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  EmailOtpChannel,
  EmailOtpChallengeOperation,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import type { EmailRecoveryResolvedWalletBinding } from '../../core/EmailRecoveryPreparationStore';
import type { LinkIdentityResult, UnlinkIdentityResult } from '../../core/IdentityStore';
import type { NearPublicKeyAuthBinding, NearPublicKeyKind } from '../../core/NearPublicKeyStore';
import type {
  RecoveryExecutionRecord,
  RecoveryExecutionStatus,
} from '../../core/RecoveryExecutionStore';
import type { RecoverySessionRecord, RecoverySessionStatus } from '../../core/RecoverySessionStore';
import type { RouterAbEcdsaPresignRuntime } from '../../core/routerAbSigning/RouterAbEcdsaPresignRuntime';
import type { WalletEcdsaSignerKey, WalletEcdsaSignerRecord } from '../../core/WalletStore';
import type {
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
  ThresholdEcdsaChainTarget,
  ThresholdEd25519AuthorityScope,
  ThresholdRuntimePolicyScope,
  WebAuthnAuthenticationCredential,
} from '../../core/types';
import type {
  AddAuthMethodInput,
  AddSignerSelection,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerEcdsaActivationRequest,
  WalletAddSignerEcdsaActivationResponse,
  WalletAddSignerEcdsaDerivationRespondRequest,
  WalletAddSignerEcdsaDerivationRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
  WalletRegistrationEcdsaActivationRequest,
  WalletRegistrationEcdsaActivationResponse,
  WalletRegistrationEcdsaDerivationRespondRequest,
  WalletRegistrationEcdsaDerivationRespondResponse,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
} from '../../core/registrationContracts';

export type WalletAuthMethodManagementSubject = Readonly<{
  kind: 'wallet_auth_method_management';
  walletId: WalletId;
}>;

export type CreateAddAuthMethodIntentCommand = Readonly<{
  subject: WalletAuthMethodManagementSubject;
  authMethod: AddAuthMethodInput;
}>;

export type WalletSignerManagementSubject = Readonly<{
  kind: 'wallet_signer_management';
  walletId: WalletId;
}>;

export type CreateAddSignerIntentCommand = Readonly<{
  subject: WalletSignerManagementSubject;
  signerSelection: AddSignerSelection;
}>;

export type StartWalletAddAuthMethodCommand = Readonly<
  { subject: WalletAuthMethodManagementSubject } & Omit<WalletAddAuthMethodStartRequest, 'walletId'>
>;

export type RevokeWalletAuthMethodCommand = Readonly<
  { subject: WalletAuthMethodManagementSubject } & Omit<WalletRevokeAuthMethodRequest, 'walletId'>
>;

export type FinalizeWalletAddAuthMethodCommand = Readonly<
  { subject: WalletAuthMethodManagementSubject } & WalletAddAuthMethodFinalizeRequest
>;

export type EmailOtpAuthorizationSessionSubject = Readonly<{
  kind: 'authorization_session';
  tenantId: TenantId;
  principalId: PrincipalId;
  walletId: WalletId;
}>;

export type EmailOtpProviderIdentitySubject = Readonly<{
  kind: 'provider_identity';
  orgId: OrgId;
  providerSubject: ProviderSubject;
  walletId: WalletId;
}>;

export type EmailOtpGrantSubject =
  | EmailOtpAuthorizationSessionSubject
  | EmailOtpProviderIdentitySubject;

export type ConsumeEmailOtpGrantCommand = Readonly<{
  subject: EmailOtpGrantSubject;
  loginGrant: string;
  otpChannel: EmailOtpChannel;
  clientIp?: string;
}>;

export type EmailOtpStrongAuthSubject = Readonly<{
  kind: 'email_otp_strong_auth';
  walletId: WalletId;
}>;
import type {
  RouterAbEd25519YaoBudgetRefreshRequestV1,
  RouterAbEd25519YaoBudgetRefreshResponseV1,
  RouterAbEd25519YaoVerifiedWalletUnlockRequestV1,
  RouterAbEd25519YaoVerifiedWalletUnlockResponseV1,
} from '../domains/ed25519Yao/session/routerAbEd25519YaoWalletSession';
import type {
  RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  RouterAbEcdsaDerivationActivationRefreshRequestV1,
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaDerivationRecoveryRequestV1,
  RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  RouterAbEcdsaStrictForwardedRegistrationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  ActiveAuthorizationSession,
  AuthorizedOperation,
  AuthorizedOperationInput,
  HostedWalletSeamsSessionExchangeCode,
  HostedWalletSeamsSessionExchangeDelivery,
  HostedWalletSeamsSessionExchangeNonce,
  RedeemHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  SessionOrigin,
  VerifiedAuthorizationEvidenceSet,
} from '../../authorization/domain';
import type {
  VerifiedFactorEvidenceSetInput,
  VerifiedSessionEvidenceSetInput,
} from '../../authorization/factorEvidence';
import type {
  IssueReusableWalletSessionInput,
  IssuedReusableWalletSession,
  EcdsaMaterialActivationScope,
} from '../../authorization/service';
import type { PrincipalId, SeamsSessionId, TenantId } from '@shared/authorization/capabilityKinds';

export type EmailOtpChallengeDelivery =
  | {
      readonly kind: 'provider';
      readonly status: 'sent' | 'reused';
      readonly mode: 'email_provider';
      readonly emailHint: string;
    }
  | {
      readonly kind: 'development';
      readonly status: 'sent' | 'reused';
      readonly mode: 'log' | 'memory' | 'dev_d1_outbox';
      readonly emailHint: string;
    }
  | {
      readonly kind: 'demo_code_response';
      readonly status: 'sent' | 'reused';
      readonly mode: 'demo_code_response';
      readonly emailHint: string;
      readonly otpCode: string;
    }
  | {
      readonly kind: 'provider_and_demo_code';
      readonly status: 'sent' | 'reused';
      readonly mode: 'provider_and_demo_code';
      readonly emailHint: string;
      readonly otpCode: string;
    };

type EmailOtpChallengeResponse = {
  readonly challengeId: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly otpChannel: EmailOtpChannel;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: WalletEmailOtpAction;
  readonly operation: EmailOtpChallengeOperation;
};

type EmailOtpChallengeCreateInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly email?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
  readonly reuseActiveChallenge?: unknown;
  readonly operation?: unknown;
  readonly requestOrigin?: unknown;
};

type EmailOtpChallengeCreateResult =
  | {
      readonly ok: true;
      readonly challenge: EmailOtpChallengeResponse;
      readonly delivery: EmailOtpChallengeDelivery;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
      readonly lockedUntilMs?: number;
      readonly retryAfterMs?: number;
      readonly resetAtMs?: number;
    };

type EmailOtpChallengeVerifyInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
  readonly operation?: unknown;
};

type EmailOtpChallengeVerifyResult =
  | {
      readonly ok: true;
      readonly challengeId: string;
      readonly loginGrant: string;
      readonly grantExpiresAtMs: number;
      readonly otpChannel: EmailOtpChannel;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
      readonly attemptsRemaining?: number;
      readonly lockedUntilMs?: number;
      readonly retryAfterMs?: number;
      readonly resetAtMs?: number;
    };

type EmailOtpEnrollmentVerifyInput = {
  readonly providerSubject: unknown;
  readonly walletId: unknown;
  readonly orgId: unknown;
  readonly challengeId: unknown;
  readonly otpCode: unknown;
  readonly otpChannel: unknown;
  readonly sessionHash: unknown;
  readonly appSessionVersion: unknown;
  readonly proofEmail?: unknown;
  readonly clientIp?: unknown;
  readonly enrollmentSealKeyVersion?: unknown;
  readonly clientUnlockPublicKeyB64u?: unknown;
  readonly unlockKeyVersion?: unknown;
  readonly googleEmailOtpRegistrationAttemptId?: unknown;
};

type EmailOtpEnrollmentVerifyResult =
  | {
      readonly ok: true;
      readonly walletId: string;
      readonly otpChannel: EmailOtpChannel;
      readonly enrollment: {
        readonly createdAtMs: number;
        readonly updatedAtMs: number;
        readonly enrollmentSealKeyVersion: string;
        readonly unlockKeyVersion: string;
      };
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
      readonly attemptsRemaining?: number;
      readonly lockedUntilMs?: number;
      readonly retryAfterMs?: number;
      readonly resetAtMs?: number;
    };

type GoogleEmailOtpRegistrationOfferCandidate = {
  readonly candidateId: string;
  readonly walletId: string;
};

type GoogleEmailOtpRegistrationOffer = {
  readonly offerId: string;
  readonly selectedCandidateId: string;
  readonly candidates: readonly [
    GoogleEmailOtpRegistrationOfferCandidate,
    ...GoogleEmailOtpRegistrationOfferCandidate[],
  ];
};

type GoogleEmailOtpResolutionResult =
  | {
      readonly ok: true;
      readonly mode: 'existing_wallet';
      readonly walletId: string;
      readonly providerSubject: string;
      readonly email?: string;
      readonly hasEmailOtpEnrollment: true;
    }
  | {
      readonly ok: true;
      readonly mode: 'register_started';
      readonly walletId: string;
      readonly providerSubject: string;
      readonly email: string;
      readonly registrationAttemptId: string;
      readonly expiresAtMs: number;
      readonly offer: GoogleEmailOtpRegistrationOffer;
    }
  | {
      readonly ok: false;
      readonly mode: 'wallet_id_collision' | 'registration_incomplete' | 'stale_identity_mapping';
      readonly code: 'wallet_id_collision' | 'registration_incomplete' | 'stale_identity_mapping';
      readonly walletId?: string;
      readonly providerSubject: string;
      readonly email?: string;
      readonly message: string;
    };

type ThresholdEcdsaKeyInventoryDiagnostics = {
  readonly userId: string;
  readonly inputCount: number;
  readonly returnedCount: number;
  readonly publicCapabilityStorePresent: boolean;
  readonly rejected: Record<string, number>;
};

type ThresholdEcdsaKeyInventoryRecord = {
  readonly keyHandle: string;
  readonly ecdsaThresholdKeyId: string;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly targetKey: string;
  readonly accountAddress: string;
  readonly ownerAddress: string;
  readonly relayerKeyId: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
  readonly key: {
    readonly walletId: string;
    readonly keyHandle: string;
    readonly rpId: string;
    readonly keyScope: 'evm-family';
    readonly ecdsaThresholdKeyId: string;
    readonly signingRootId: string;
    readonly signingRootVersion: string;
    readonly participantIds: number[];
    readonly thresholdOwnerAddress: string;
  };
};

type EmailOtpWalletRecoveryBootstrapChallengeCreateInput = {
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly clientIp?: unknown;
  readonly requestOrigin?: unknown;
};

type EmailOtpWalletRecoveryBootstrapChallengeCreateResult =
  | {
      readonly ok: true;
      readonly challengeId: string;
      readonly otpChannel: EmailOtpChannel;
      readonly expiresAtMs: number;
      readonly emailHint: string;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
      readonly retryAfterMs?: number;
      readonly lockedUntilMs?: number;
    };

type EmailOtpWalletRecoveryBootstrapVerifyInput = {
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly clientIp?: unknown;
};

type EmailOtpWalletRecoveryBootstrapVerifyResult =
  | {
      readonly ok: true;
      readonly walletId: string;
      readonly challengeId: string;
      readonly recoveryBootstrapGrant: string;
      readonly recoveryBootstrapGrantExpiresAtMs: number;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
      readonly attemptsRemaining?: number;
      readonly lockedUntilMs?: number;
      readonly retryAfterMs?: number;
    };
type RouterApiOkFailure = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
};

type RouterApiRateLimitedFailure = RouterApiOkFailure & {
  readonly retryAfterMs?: number;
  readonly resetAtMs?: number;
};

type EmailOtpWalletRecoveryBootstrapConsumeInput = {
  readonly recoveryBootstrapGrant?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
};

type EmailOtpWalletRecoveryBootstrapConsumeResult =
  | {
      readonly ok: true;
      readonly walletId: string;
      readonly providerUserId: string;
      readonly orgId: string;
      readonly challengeId: string;
      readonly grantExpiresAtMs: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type RouterApiMethodTypes = {
  applyEmailOtpServerSeal: {
    readonly input: { readonly wrappedCiphertext?: unknown };
    readonly result:
      | {
          readonly ok: true;
          readonly ciphertext: string;
          readonly enrollmentSealKeyVersion: string;
        }
      | RouterApiOkFailure;
  };

  cleanupGoogleEmailOtpDevRegistrationState: {
    readonly input: {
      readonly providerSubject?: unknown;
      readonly walletId?: unknown;
      readonly orgId?: unknown;
      readonly nowMs?: unknown;
    };
    readonly result:
      | {
          readonly ok: true;
          readonly providerSubject: string;
          readonly expiredRegistrationAttemptsDeleted: number;
          readonly linkedWalletId?: string;
          readonly orphanedWalletMappingRemoved: boolean;
          readonly orphanedWalletMappingSkippedReason?:
            | 'no_linked_wallet'
            | 'wallet_id_mismatch'
            | 'not_relayer_subaccount'
            | 'active_email_otp_enrollment'
            | 'mismatched_email_otp_enrollment';
        }
      | RouterApiOkFailure;
  };
  createAddAuthMethodIntent: {
    readonly input: {
      readonly command: CreateAddAuthMethodIntentCommand;
      readonly orgId: string;
      readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
      readonly signingRootId?: string;
      readonly signingRootVersion?: string;
      readonly expectedOrigin?: string;
    };
    readonly result: CreateAddAuthMethodIntentResponse;
  };
  createAddSignerIntent: {
    readonly input: {
      readonly command: CreateAddSignerIntentCommand;
      readonly orgId: string;
      readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
      readonly signingRootId?: string;
      readonly signingRootVersion?: string;
      readonly expectedOrigin?: string;
    };
    readonly result: CreateAddSignerIntentResponse;
  };
  consumeEmailOtpGrant: {
    readonly input: ConsumeEmailOtpGrantCommand;
    readonly result:
      | { readonly ok: true; readonly challengeId: string; readonly otpChannel: EmailOtpChannel }
      | RouterApiOkFailure;
  };
  consumeGoogleEmailOtpRegistrationAttemptRateLimit: {
    readonly input: {
      readonly providerSubject?: unknown;
      readonly email?: unknown;
      readonly accountMode?: unknown;
      readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
      readonly clientIp?: string;
      readonly appSessionUserId?: string;
      readonly restartRegistrationOffer?: unknown;
    };
    readonly result:
      | { readonly ok: true }
      | {
          readonly ok: false;
          readonly code: 'invalid_body' | 'rate_limited';
          readonly message: string;
          readonly retryAfterMs?: number;
          readonly resetAtMs?: number;
        };
  };
  createEmailOtpChallenge: {
    readonly input: EmailOtpChallengeCreateInput;
    readonly result: EmailOtpChallengeCreateResult;
  };
  createEmailOtpWalletRecoveryBootstrapChallenge: {
    readonly input: EmailOtpWalletRecoveryBootstrapChallengeCreateInput;
    readonly result: EmailOtpWalletRecoveryBootstrapChallengeCreateResult;
  };
  createEmailOtpEnrollmentChallenge: {
    readonly input: Omit<EmailOtpChallengeCreateInput, 'operation' | 'reuseActiveChallenge'>;
    readonly result: EmailOtpChallengeCreateResult;
  };
  createEmailOtpUnlockChallenge: {
    readonly input: {
      readonly walletId?: unknown;
      readonly orgId?: unknown;
      readonly ttlMs?: unknown;
      readonly ttl_ms?: unknown;
    };
    readonly result:
      | {
          readonly ok: true;
          readonly walletId: string;
          readonly challengeId: string;
          readonly challengeB64u: string;
          readonly expiresAtMs: number;
          readonly unlockKeyVersion: string;
        }
      | (RouterApiOkFailure & { readonly lockedUntilMs?: number });
  };
  createWebAuthnLoginOptions: {
    readonly input: {
      readonly userId?: unknown;
      readonly user_id?: unknown;
      readonly rpId?: unknown;
      readonly rp_id?: unknown;
      readonly ttlMs?: unknown;
      readonly ttl_ms?: unknown;
    };
    readonly result: {
      readonly ok: boolean;
      readonly challengeId?: string;
      readonly challengeB64u?: string;
      readonly expiresAtMs?: number;
      readonly code?: string;
      readonly message?: string;
    };
  };
  createWebAuthnSyncAccountOptions: {
    readonly input: {
      readonly rp_id?: unknown;
      readonly account_id?: unknown;
      readonly ttl_ms?: unknown;
      readonly ttlMs?: unknown;
    };
    readonly result: {
      readonly ok: boolean;
      readonly challengeId?: string;
      readonly challengeB64u?: string;
      readonly credentialIds?: string[];
      readonly walletBinding?: EmailRecoveryResolvedWalletBinding;
      readonly expiresAtMs?: number;
      readonly code?: string;
      readonly message?: string;
    };
  };
  finalizeWalletAddAuthMethod: {
    readonly input: FinalizeWalletAddAuthMethodCommand;
    readonly result: WalletAddAuthMethodFinalizeResponse;
  };
  finalizeWalletAddSigner: {
    readonly input: WalletAddSignerFinalizeRequest;
    readonly result: WalletAddSignerFinalizeResponse;
  };
  fundImplicitNearAccount: {
    readonly input: FundImplicitNearAccountRequest;
    readonly result: FundImplicitNearAccountResult;
  };
  getConfiguredRelayerAccount: {
    readonly input: never;
    readonly result: string;
  };
  getGoogleOidcPublicConfig: {
    readonly input: never;
    readonly result: { readonly configured: boolean; readonly clientId?: string };
  };
  getOrCreateAppSessionVersion: {
    readonly input: { readonly userId: string };
    readonly result:
      | { readonly ok: true; readonly appSessionVersion: string }
      | {
          readonly ok: false;
          readonly code: 'invalid_args' | 'internal';
          readonly message: string;
        };
  };
  getRelayerAccount: {
    readonly input: never;
    readonly result: { readonly accountId: string; readonly publicKey: string };
  };
  getRecoverySession: {
    readonly input: { readonly sessionId: string };
    readonly result:
      | { readonly ok: true; readonly record: RecoverySessionRecord | null }
      | {
          readonly ok: false;
          readonly code: 'invalid_args' | 'internal';
          readonly message: string;
        };
  };
  isEmailOtpStrongAuthRequired: {
    readonly input: { readonly subject: EmailOtpStrongAuthSubject };
    readonly result:
      | {
          readonly ok: true;
          readonly required: boolean;
          readonly walletId: string;
          readonly lastEmailOtpLoginAtMs?: number;
          readonly lastStrongAuthAtMs?: number;
        }
      | RouterApiOkFailure;
  };
  linkIdentity: {
    readonly input: {
      readonly userId: string;
      readonly subject: string;
      readonly allowMoveIfSoleIdentity?: boolean;
    };
    readonly result: LinkIdentityResult;
  };
  listIdentities: {
    readonly input: { readonly userId: string };
    readonly result: {
      readonly ok: boolean;
      readonly subjects?: string[];
      readonly code?: string;
      readonly message?: string;
    };
  };
  listNearPublicKeysForUser: {
    readonly input: { readonly userId: string };
    readonly result: {
      readonly ok: boolean;
      readonly code?: string;
      readonly message?: string;
      readonly keys?: Array<{
        readonly publicKey: string;
        readonly kind: NearPublicKeyKind;
        readonly signerSlot?: number;
        readonly createdAtMs?: number;
        readonly updatedAtMs?: number;
        readonly authBinding?: NearPublicKeyAuthBinding;
      }>;
    };
  };
  listWalletEcdsaKeyFactsInventory: {
    readonly input: {
      readonly walletId: string;
      readonly rpId: string;
      readonly keyTargets: readonly unknown[];
    };
    readonly result: {
      readonly records: ThresholdEcdsaKeyInventoryRecord[];
      readonly diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
    };
  };
  listWebAuthnAuthenticatorsForUser: {
    readonly input: { readonly userId: string; readonly rpId?: string };
    readonly result: {
      readonly ok: boolean;
      readonly code?: string;
      readonly message?: string;
      readonly authenticators?: Array<{
        readonly credentialIdB64u: string;
        readonly signerSlot?: number;
        readonly publicKey?: string;
        readonly createdAtMs?: number;
        readonly updatedAtMs?: number;
        /** Device metadata captured at registration; synthesized "Unknown
         * device" for rows written before device capture existed. */
        readonly device: WebAuthnAuthenticatorDeviceInfo;
      }>;
    };
  };
  markEmailOtpStrongAuthSatisfied: {
    readonly input: { readonly walletId?: unknown };
    readonly result:
      | { readonly ok: true; readonly walletId: string; readonly lastStrongAuthAtMs?: number }
      | RouterApiOkFailure;
  };
  readActiveEmailOtpEnrollment: {
    readonly input: {
      readonly walletId?: unknown;
      readonly orgId: unknown;
      readonly providerUserId?: unknown;
    };
    readonly result:
      | { readonly ok: true; readonly enrollment: EmailOtpWalletEnrollmentRecord }
      | RouterApiOkFailure;
  };
  readEmailOtpEnrollment: {
    readonly input: { readonly walletId?: unknown; readonly orgId: unknown };
    readonly result:
      | { readonly ok: true; readonly enrollment: EmailOtpWalletEnrollmentRecord }
      | RouterApiOkFailure;
  };
  readEmailOtpOutboxEntry: {
    readonly input: {
      readonly challengeId?: unknown;
      readonly userId?: unknown;
      readonly walletId?: unknown;
    };
    readonly result:
      | {
          readonly ok: true;
          readonly challengeId: string;
          readonly walletId: string;
          readonly userId: string;
          readonly otpChannel: EmailOtpChannel;
          readonly emailHint: string;
          readonly otpCode: string;
          readonly expiresAtMs: number;
        }
      | RouterApiOkFailure;
  };
  recordRecoveryExecution: {
    readonly input: {
      readonly sessionId: string;
      readonly chainIdKey: string;
      readonly accountAddress: string;
      readonly action: string;
      readonly status: RecoveryExecutionStatus;
      readonly transactionHash?: string;
      readonly errorCode?: string;
      readonly errorMessage?: string;
      readonly metadata?: Record<string, unknown>;
    };
    readonly result:
      | { readonly ok: true; readonly record: RecoveryExecutionRecord }
      | {
          readonly ok: false;
          readonly code: 'invalid_args' | 'internal';
          readonly message: string;
        };
  };
  removeEmailOtpServerSeal: RouterApiMethodTypes['applyEmailOtpServerSeal'];
  respondWalletAddSignerEcdsaDerivation: {
    readonly input: WalletAddSignerEcdsaDerivationRespondRequest;
    readonly result: WalletAddSignerEcdsaDerivationRespondResponse;
  };
  activateWalletAddSignerEcdsa: {
    readonly input: WalletAddSignerEcdsaActivationRequest;
    readonly result: WalletAddSignerEcdsaActivationResponse;
  };
  getWalletAddSignerRuntimePolicyScope: {
    readonly input: { readonly addSignerCeremonyId: string };
    readonly result: ThresholdRuntimePolicyScope | null;
  };
  respondWalletRegistrationEcdsaDerivation: {
    readonly input: WalletRegistrationEcdsaDerivationRespondRequest;
    readonly result: WalletRegistrationEcdsaDerivationRespondResponse;
  };
  activateWalletRegistrationEcdsa: {
    readonly input: WalletRegistrationEcdsaActivationRequest;
    readonly result: WalletRegistrationEcdsaActivationResponse;
  };
  resolveGoogleEmailOtpSession: {
    readonly input: {
      readonly providerSubject?: string;
      readonly sub?: string;
      readonly email?: string;
      readonly accountMode?: unknown;
      readonly appSessionVersion?: string;
      readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
      readonly restartRegistrationOffer?: unknown;
    };
    readonly result: GoogleEmailOtpResolutionResult;
  };
  resolveOidcWalletId: {
    readonly input: {
      readonly providerSubject?: string;
      readonly sub?: string;
      readonly email?: string;
      readonly accountMode?: unknown;
      readonly appSessionVersion?: string;
      readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
      readonly restartRegistrationOffer?: unknown;
    };
    readonly result: string;
  };
  revokeWalletAuthMethod: {
    readonly input: RevokeWalletAuthMethodCommand;
    readonly result: WalletRevokeAuthMethodResponse;
  };
  rotateAppSessionVersion: {
    readonly input: { readonly userId: string };
    readonly result:
      | { readonly ok: true; readonly appSessionVersion: string }
      | {
          readonly ok: false;
          readonly code: 'invalid_args' | 'internal';
          readonly message: string;
        };
  };
  startWalletAddAuthMethod: {
    readonly input: StartWalletAddAuthMethodCommand;
    readonly result: WalletAddAuthMethodStartResponse;
  };
  startWalletAddSigner: {
    readonly input: WalletAddSignerStartRequest;
    readonly result: WalletAddSignerStartResponse;
  };
  unlinkIdentity: {
    readonly input: { readonly userId: string; readonly subject: string };
    readonly result: UnlinkIdentityResult;
  };
  updateRecoverySessionStatus: {
    readonly input: {
      readonly sessionId: string;
      readonly status: RecoverySessionStatus;
      readonly metadataPatch?: Record<string, unknown> | null;
    };
    readonly result:
      | { readonly ok: true; readonly record: RecoverySessionRecord }
      | {
          readonly ok: false;
          readonly code: 'invalid_args' | 'internal';
          readonly message: string;
        };
  };
  validateAppSessionVersion: {
    readonly input: { readonly userId: string; readonly appSessionVersion: string };
    readonly result:
      | { readonly ok: true }
      | {
          readonly ok: false;
          readonly code: 'invalid_session_version' | 'unauthorized' | 'internal';
          readonly message: string;
        };
  };
  validateGoogleEmailOtpRegistrationCandidateWallet: {
    readonly input: GoogleEmailOtpRegistrationCandidateWalletValidationRequest;
    readonly result: GoogleEmailOtpRegistrationCandidateWalletValidationResult;
  };
  verifyEmailOtpChallenge: {
    readonly input: EmailOtpChallengeVerifyInput;
    readonly result: EmailOtpChallengeVerifyResult;
  };
  verifyEmailOtpWalletRecoveryBootstrap: {
    readonly input: EmailOtpWalletRecoveryBootstrapVerifyInput;
    readonly result: EmailOtpWalletRecoveryBootstrapVerifyResult;
  };
  consumeEmailOtpWalletRecoveryBootstrap: {
    readonly input: EmailOtpWalletRecoveryBootstrapConsumeInput;
    readonly result: EmailOtpWalletRecoveryBootstrapConsumeResult;
  };
  verifyEmailOtpWalletRecoveryChallenge: {
    readonly input: Omit<EmailOtpChallengeVerifyInput, 'operation'>;
    readonly result: EmailOtpChallengeVerifyResult;
  };
  verifyEmailOtpEnrollment: {
    readonly input: EmailOtpEnrollmentVerifyInput;
    readonly result: EmailOtpEnrollmentVerifyResult;
  };
  verifyEmailOtpUnlockProof: {
    readonly input: {
      readonly walletId?: unknown;
      readonly orgId?: unknown;
      readonly challengeId?: unknown;
      readonly unlockProof?: unknown;
    };
    readonly result:
      | {
          readonly ok: true;
          readonly verified: true;
          readonly userId: string;
          readonly walletId: string;
          readonly providerUserId: string;
          readonly orgId: string;
          readonly enrollmentId: string;
          readonly enrollmentSealKeyVersion: string;
          readonly unlockKeyVersion: string;
        }
      | {
          readonly ok: false;
          readonly verified: false;
          readonly code: string;
          readonly message: string;
        };
  };
  verifyGoogleLogin: {
    readonly input: { readonly idToken?: unknown; readonly id_token?: unknown };
    readonly result: {
      readonly ok: boolean;
      readonly verified?: boolean;
      readonly userId?: string;
      readonly providerSubject?: string;
      readonly sub?: string;
      readonly email?: string;
      readonly name?: string;
      readonly given_name?: string;
      readonly family_name?: string;
      readonly emailVerified?: boolean;
      readonly hostedDomain?: string;
      readonly code?: string;
      readonly message?: string;
    };
  };
  verifyOidcJwtExchange: {
    readonly input: { readonly token?: unknown };
    readonly result: {
      readonly ok: boolean;
      readonly verified?: boolean;
      readonly userId?: string;
      readonly providerSubject?: string;
      readonly iss?: string;
      readonly aud?: string[];
      readonly sub?: string;
      readonly email?: string;
      readonly name?: string;
      readonly given_name?: string;
      readonly family_name?: string;
      readonly code?: string;
      readonly message?: string;
    };
  };
  verifyWebAuthnAuthenticationLite: {
    readonly input: {
      readonly userId: string;
      readonly rpId: WebAuthnRpId;
      readonly expectedChallenge: string;
      readonly webauthn_authentication: WebAuthnAuthenticationCredential;
      readonly expected_origin: string;
    };
    readonly result: {
      readonly success: boolean;
      readonly verified: boolean;
      readonly code?: string;
      readonly message?: string;
    };
  };
  verifyWebAuthnLogin: {
    readonly input: {
      readonly challengeId?: unknown;
      readonly challenge_id?: unknown;
      readonly webauthn_authentication?: unknown;
      readonly expected_origin?: string;
    };
    readonly result:
      | {
          readonly ok: true;
          readonly verified: true;
          readonly userId: string;
          readonly rpId: string;
          readonly credentialIdB64u: string;
          readonly ed25519:
            | { readonly kind: 'absent' }
            | {
                readonly kind: 'active';
                readonly nearAccountId: string;
                readonly nearEd25519SigningKeyId: string;
                readonly signerSlot: number;
                readonly publicKey: string;
                readonly relayerKeyId: string;
                readonly participantIds: readonly [number, number];
              };
        }
      | {
          readonly ok: false;
          readonly verified?: false;
          readonly code: string;
          readonly message: string;
        };
  };
  verifyWebAuthnSyncAccount: {
    readonly input: {
      readonly challengeId?: unknown;
      readonly challenge_id?: unknown;
      readonly webauthn_authentication?: unknown;
      readonly expected_origin?: string;
    };
    readonly result: {
      readonly ok: boolean;
      readonly verified?: boolean;
      readonly accountId?: string;
      readonly walletId?: string;
      readonly nearAccountId?: string;
      readonly nearEd25519SigningKeyId?: string;
      readonly walletBinding?: EmailRecoveryResolvedWalletBinding;
      readonly rpId?: string;
      readonly signerSlot?: number;
      readonly publicKey?: string;
      readonly relayerKeyId?: string;
      readonly credentialIdB64u?: string;
      readonly credentialPublicKeyB64u?: string;
      readonly thresholdEd25519?: {
        readonly relayerKeyId: string;
        readonly authorityScope: ThresholdEd25519AuthorityScope;
        readonly publicKey: string;
        readonly keyVersion?: string;
        readonly recoveryExportCapable?: boolean;
        readonly clientParticipantId?: number;
        readonly relayerParticipantId?: number;
        readonly participantIds?: number[];
      };
      readonly code?: string;
      readonly message?: string;
    };
  };
};

export type GoogleEmailOtpRegistrationCandidateWalletValidationRequest = {
  readonly registrationAttemptId: string;
  readonly walletId: string;
  readonly appSessionVersion: string;
  readonly providerSubject: string;
};

export type GoogleEmailOtpRegistrationCandidateWalletValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface RouterAbSigningRuntimeService {
  getRouterAbEcdsaPresignRuntime(): RouterAbEcdsaPresignRuntime | null;
}

export interface RouterApiEmailOtpChallengeService {
  createEmailOtpChallenge(
    input: RouterApiMethodTypes['createEmailOtpChallenge']['input'],
  ): Promise<RouterApiMethodTypes['createEmailOtpChallenge']['result']>;
  createEmailOtpWalletRecoveryBootstrapChallenge(
    input: RouterApiMethodTypes['createEmailOtpWalletRecoveryBootstrapChallenge']['input'],
  ): Promise<RouterApiMethodTypes['createEmailOtpWalletRecoveryBootstrapChallenge']['result']>;
  createEmailOtpEnrollmentChallenge(
    input: RouterApiMethodTypes['createEmailOtpEnrollmentChallenge']['input'],
  ): Promise<RouterApiMethodTypes['createEmailOtpEnrollmentChallenge']['result']>;
}

export interface RouterApiWalletRegistrationService {
  listWalletEcdsaCustodyContinuity(input: {
    readonly walletId: string;
  }): Promise<readonly WalletEcdsaSignerRecord[]>;
  resolveEd25519MaterialActivation(input: {
    readonly walletId: string;
    readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  }): Promise<
    | {
        readonly ok: true;
        readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
        readonly nearAccountId: string;
        readonly signerSlot: number;
        readonly signingWorkerId: string;
        readonly participantIds: readonly [number, number];
      }
    | { readonly ok: false; readonly code: 'not_found' | 'internal'; readonly message: string }
  >;
  resolveEcdsaMaterialActivation(input: {
    readonly walletId: string;
    readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  }): Promise<
    | {
        readonly ok: true;
        readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
        readonly keyHandle: string;
        readonly relayerKeyId: string;
        readonly participantIds: readonly [number, number];
      }
    | { readonly ok: false; readonly code: 'not_found' | 'internal'; readonly message: string }
  >;
  listWalletEcdsaKeyFactsInventory(
    input: RouterApiMethodTypes['listWalletEcdsaKeyFactsInventory']['input'],
  ): Promise<RouterApiMethodTypes['listWalletEcdsaKeyFactsInventory']['result']>;
  readActiveEmailOtpEnrollment(
    input: RouterApiMethodTypes['readActiveEmailOtpEnrollment']['input'],
  ): Promise<RouterApiMethodTypes['readActiveEmailOtpEnrollment']['result']>;
  setupWalletRegistration(
    input: WalletRegistrationSetupInput,
  ): Promise<WalletRegistrationSetupResponseV2>;
  respondWalletRegistration(
    input: WalletRegistrationRespondInput,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<WalletRegistrationRespondResponseV2>;
  activateWalletRegistration(
    input: WalletRegistrationActivateInput,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<WalletRegistrationActivateResponseV2>;
  completeWalletRegistrationNearProvisioning(
    input: WalletRegistrationNearProvisioningInput,
  ): Promise<WalletRegistrationNearProvisioningResponseV2>;
  refreshEd25519YaoWalletSession(
    input: RouterAbEd25519YaoBudgetRefreshRequestV1,
  ): Promise<RouterAbEd25519YaoBudgetRefreshResponseV1>;
  provisionEd25519YaoWalletSession(
    input: RouterAbEd25519YaoVerifiedWalletUnlockRequestV1,
  ): Promise<RouterAbEd25519YaoVerifiedWalletUnlockResponseV1>;
  recordEcdsaPostRegistrationProof(
    input:
      | {
          readonly operation: 'recovery';
          readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
          readonly response: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
        }
      | {
          readonly operation: 'refresh';
          readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
          readonly response: RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1;
        },
  ): Promise<
    { readonly ok: true } | { readonly ok: false; readonly code: string; readonly message: string }
  >;
  activateEcdsaPostRegistrationSession(
    input: RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  ): Promise<
    | {
        readonly ok: true;
        readonly walletKey: WalletEcdsaSignerKey;
        readonly session: {
          readonly thresholdSessionId: string;
          readonly expiresAtMs: number;
          readonly remainingUses: number;
        };
        readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
      }
    | { readonly ok: false; readonly code: string; readonly message: string }
  >;
}

export interface RouterApiWalletAuthVerificationService {
  validateAppSessionVersion(
    input: RouterApiMethodTypes['validateAppSessionVersion']['input'],
  ): Promise<RouterApiMethodTypes['validateAppSessionVersion']['result']>;
  verifyWebAuthnAuthenticationLite(
    input: RouterApiMethodTypes['verifyWebAuthnAuthenticationLite']['input'],
  ): Promise<RouterApiMethodTypes['verifyWebAuthnAuthenticationLite']['result']>;
}

export interface RouterApiWalletAuthMethodService {
  resolveActiveEmailOtpAuthorityForVerifiedSubject(input: {
    readonly walletId: string;
    readonly providerUserId: string;
  }): Promise<
    | { readonly ok: true; readonly authority: EmailOtpWalletAuthAuthority }
    | { readonly ok: false; readonly code: string; readonly message: string }
  >;
  createAddAuthMethodIntent(input: {
    command: CreateAddAuthMethodIntentCommand;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateAddAuthMethodIntentResponse>;
  createAddSignerIntent(input: {
    command: CreateAddSignerIntentCommand;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateAddSignerIntentResponse>;
  finalizeWalletAddAuthMethod(
    input: FinalizeWalletAddAuthMethodCommand,
  ): Promise<WalletAddAuthMethodFinalizeResponse>;
  finalizeWalletAddSigner(
    input: WalletAddSignerFinalizeRequest,
  ): Promise<WalletAddSignerFinalizeResponse>;
  respondWalletAddSignerEcdsaDerivation(
    input: WalletAddSignerEcdsaDerivationRespondRequest,
  ): Promise<WalletAddSignerEcdsaDerivationRespondResponse>;
  activateWalletAddSignerEcdsa(
    input: WalletAddSignerEcdsaActivationRequest,
  ): Promise<WalletAddSignerEcdsaActivationResponse>;
  getWalletAddSignerRuntimePolicyScope(
    addSignerCeremonyId: string,
  ): Promise<ThresholdRuntimePolicyScope | null>;
  revokeWalletAuthMethod(
    input: RevokeWalletAuthMethodCommand,
  ): Promise<WalletRevokeAuthMethodResponse>;
  startWalletAddAuthMethod(
    input: StartWalletAddAuthMethodCommand,
    context?: { readonly userAgent?: string },
  ): Promise<WalletAddAuthMethodStartResponse>;
  startWalletAddSigner(input: WalletAddSignerStartRequest): Promise<WalletAddSignerStartResponse>;
}

export interface RouterApiWalletRegistrationRouteService
  extends
    RouterApiWalletRegistrationService,
    RouterApiWalletAuthMethodService,
    RouterApiWalletAuthVerificationService {
  getOrCreateAppSessionVersion(
    input: RouterApiMethodTypes['getOrCreateAppSessionVersion']['input'],
  ): Promise<RouterApiMethodTypes['getOrCreateAppSessionVersion']['result']>;
  fundImplicitNearAccount(
    input: FundImplicitNearAccountRequest,
  ): Promise<FundImplicitNearAccountResult>;
  listWalletEcdsaKeyFactsInventory(
    input: RouterApiMethodTypes['listWalletEcdsaKeyFactsInventory']['input'],
  ): Promise<RouterApiMethodTypes['listWalletEcdsaKeyFactsInventory']['result']>;
}

export interface RouterApiWalletUnlockService {
  createEmailOtpUnlockChallenge(
    input: RouterApiMethodTypes['createEmailOtpUnlockChallenge']['input'],
  ): Promise<RouterApiMethodTypes['createEmailOtpUnlockChallenge']['result']>;
  createWebAuthnLoginOptions(
    input: RouterApiMethodTypes['createWebAuthnLoginOptions']['input'],
  ): Promise<RouterApiMethodTypes['createWebAuthnLoginOptions']['result']>;
  markEmailOtpStrongAuthSatisfied(
    input: RouterApiMethodTypes['markEmailOtpStrongAuthSatisfied']['input'],
  ): Promise<RouterApiMethodTypes['markEmailOtpStrongAuthSatisfied']['result']>;
  verifyEmailOtpUnlockProof(
    input: RouterApiMethodTypes['verifyEmailOtpUnlockProof']['input'],
  ): Promise<RouterApiMethodTypes['verifyEmailOtpUnlockProof']['result']>;
  verifyWebAuthnLogin(
    input: RouterApiMethodTypes['verifyWebAuthnLogin']['input'],
  ): Promise<RouterApiMethodTypes['verifyWebAuthnLogin']['result']>;
}

export interface RouterApiEmailOtpRouteService extends RouterApiEmailOtpChallengeService {
  applyEmailOtpServerSeal(
    input: RouterApiMethodTypes['applyEmailOtpServerSeal']['input'],
  ): Promise<RouterApiMethodTypes['applyEmailOtpServerSeal']['result']>;
  cleanupGoogleEmailOtpDevRegistrationState(
    input: RouterApiMethodTypes['cleanupGoogleEmailOtpDevRegistrationState']['input'],
  ): Promise<RouterApiMethodTypes['cleanupGoogleEmailOtpDevRegistrationState']['result']>;
  consumeEmailOtpGrant(
    input: RouterApiMethodTypes['consumeEmailOtpGrant']['input'],
  ): Promise<RouterApiMethodTypes['consumeEmailOtpGrant']['result']>;
  isEmailOtpStrongAuthRequired(
    input: RouterApiMethodTypes['isEmailOtpStrongAuthRequired']['input'],
  ): Promise<RouterApiMethodTypes['isEmailOtpStrongAuthRequired']['result']>;
  markEmailOtpStrongAuthSatisfied(
    input: RouterApiMethodTypes['markEmailOtpStrongAuthSatisfied']['input'],
  ): Promise<RouterApiMethodTypes['markEmailOtpStrongAuthSatisfied']['result']>;
  readActiveEmailOtpEnrollment(
    input: RouterApiMethodTypes['readActiveEmailOtpEnrollment']['input'],
  ): Promise<RouterApiMethodTypes['readActiveEmailOtpEnrollment']['result']>;
  readEmailOtpEnrollment(
    input: RouterApiMethodTypes['readEmailOtpEnrollment']['input'],
  ): Promise<RouterApiMethodTypes['readEmailOtpEnrollment']['result']>;
  readEmailOtpOutboxEntry(
    input: RouterApiMethodTypes['readEmailOtpOutboxEntry']['input'],
  ): Promise<RouterApiMethodTypes['readEmailOtpOutboxEntry']['result']>;
  removeEmailOtpServerSeal(
    input: RouterApiMethodTypes['removeEmailOtpServerSeal']['input'],
  ): Promise<RouterApiMethodTypes['removeEmailOtpServerSeal']['result']>;
  validateGoogleEmailOtpRegistrationCandidateWallet(
    input: GoogleEmailOtpRegistrationCandidateWalletValidationRequest,
  ): Promise<GoogleEmailOtpRegistrationCandidateWalletValidationResult>;
  verifyEmailOtpChallenge(
    input: RouterApiMethodTypes['verifyEmailOtpChallenge']['input'],
  ): Promise<RouterApiMethodTypes['verifyEmailOtpChallenge']['result']>;
  verifyEmailOtpWalletRecoveryBootstrap(
    input: RouterApiMethodTypes['verifyEmailOtpWalletRecoveryBootstrap']['input'],
  ): Promise<RouterApiMethodTypes['verifyEmailOtpWalletRecoveryBootstrap']['result']>;
  consumeEmailOtpWalletRecoveryBootstrap(
    input: RouterApiMethodTypes['consumeEmailOtpWalletRecoveryBootstrap']['input'],
  ): Promise<RouterApiMethodTypes['consumeEmailOtpWalletRecoveryBootstrap']['result']>;
  verifyEmailOtpWalletRecoveryChallenge(
    input: RouterApiMethodTypes['verifyEmailOtpWalletRecoveryChallenge']['input'],
  ): Promise<RouterApiMethodTypes['verifyEmailOtpWalletRecoveryChallenge']['result']>;
  verifyEmailOtpEnrollment(
    input: RouterApiMethodTypes['verifyEmailOtpEnrollment']['input'],
  ): Promise<RouterApiMethodTypes['verifyEmailOtpEnrollment']['result']>;
  verifyGoogleLogin(
    input: RouterApiMethodTypes['verifyGoogleLogin']['input'],
  ): Promise<RouterApiMethodTypes['verifyGoogleLogin']['result']>;
}

export interface RouterApiSessionVersionService {
  getOrCreateAppSessionVersion(
    input: RouterApiMethodTypes['getOrCreateAppSessionVersion']['input'],
  ): Promise<RouterApiMethodTypes['getOrCreateAppSessionVersion']['result']>;
  rotateAppSessionVersion(
    input: RouterApiMethodTypes['rotateAppSessionVersion']['input'],
  ): Promise<RouterApiMethodTypes['rotateAppSessionVersion']['result']>;
  validateAppSessionVersion(
    input: RouterApiMethodTypes['validateAppSessionVersion']['input'],
  ): Promise<RouterApiMethodTypes['validateAppSessionVersion']['result']>;
}

export interface RouterApiIdentityService {
  consumeGoogleEmailOtpRegistrationAttemptRateLimit(
    input: RouterApiMethodTypes['consumeGoogleEmailOtpRegistrationAttemptRateLimit']['input'],
  ): Promise<RouterApiMethodTypes['consumeGoogleEmailOtpRegistrationAttemptRateLimit']['result']>;
  getGoogleOidcPublicConfig(): { configured: boolean; clientId?: string };
  linkIdentity(
    input: RouterApiMethodTypes['linkIdentity']['input'],
  ): Promise<RouterApiMethodTypes['linkIdentity']['result']>;
  listIdentities(
    input: RouterApiMethodTypes['listIdentities']['input'],
  ): Promise<RouterApiMethodTypes['listIdentities']['result']>;
  resolveGoogleEmailOtpSession(
    input: RouterApiMethodTypes['resolveGoogleEmailOtpSession']['input'],
  ): Promise<RouterApiMethodTypes['resolveGoogleEmailOtpSession']['result']>;
  resolveOidcWalletId(
    input: RouterApiMethodTypes['resolveOidcWalletId']['input'],
  ): Promise<RouterApiMethodTypes['resolveOidcWalletId']['result']>;
  unlinkIdentity(
    input: RouterApiMethodTypes['unlinkIdentity']['input'],
  ): Promise<RouterApiMethodTypes['unlinkIdentity']['result']>;
  verifyGoogleLogin(
    input: RouterApiMethodTypes['verifyGoogleLogin']['input'],
  ): Promise<RouterApiMethodTypes['verifyGoogleLogin']['result']>;
  verifyOidcJwtExchange(
    input: RouterApiMethodTypes['verifyOidcJwtExchange']['input'],
  ): Promise<RouterApiMethodTypes['verifyOidcJwtExchange']['result']>;
}

export interface RouterApiWebAuthnService {
  createWebAuthnLoginOptions(
    input: RouterApiMethodTypes['createWebAuthnLoginOptions']['input'],
  ): Promise<RouterApiMethodTypes['createWebAuthnLoginOptions']['result']>;
  createWebAuthnSyncAccountOptions(
    input: RouterApiMethodTypes['createWebAuthnSyncAccountOptions']['input'],
  ): Promise<RouterApiMethodTypes['createWebAuthnSyncAccountOptions']['result']>;
  listWebAuthnAuthenticatorsForUser(
    input: RouterApiMethodTypes['listWebAuthnAuthenticatorsForUser']['input'],
  ): Promise<RouterApiMethodTypes['listWebAuthnAuthenticatorsForUser']['result']>;
  verifyWebAuthnAuthenticationLite(
    input: RouterApiMethodTypes['verifyWebAuthnAuthenticationLite']['input'],
  ): Promise<RouterApiMethodTypes['verifyWebAuthnAuthenticationLite']['result']>;
  verifyWebAuthnLogin(
    input: RouterApiMethodTypes['verifyWebAuthnLogin']['input'],
  ): Promise<RouterApiMethodTypes['verifyWebAuthnLogin']['result']>;
  verifyWebAuthnSyncAccount(
    input: RouterApiMethodTypes['verifyWebAuthnSyncAccount']['input'],
  ): Promise<RouterApiMethodTypes['verifyWebAuthnSyncAccount']['result']>;
}

export interface RouterApiNearFundingService {
  fundImplicitNearAccount(
    input: FundImplicitNearAccountRequest,
  ): Promise<FundImplicitNearAccountResult>;
  listNearPublicKeysForUser(
    input: RouterApiMethodTypes['listNearPublicKeysForUser']['input'],
  ): Promise<RouterApiMethodTypes['listNearPublicKeysForUser']['result']>;
}

export interface RouterApiRecoveryRouteService {
  getRecoverySession(
    input: RouterApiMethodTypes['getRecoverySession']['input'],
  ): Promise<RouterApiMethodTypes['getRecoverySession']['result']>;
  recordRecoveryExecution(
    input: RouterApiMethodTypes['recordRecoveryExecution']['input'],
  ): Promise<RouterApiMethodTypes['recordRecoveryExecution']['result']>;
  updateRecoverySessionStatus(
    input: RouterApiMethodTypes['updateRecoverySessionStatus']['input'],
  ): Promise<RouterApiMethodTypes['updateRecoverySessionStatus']['result']>;
}

export interface RouterApiRouterAccountService {
  getConfiguredRelayerAccount(): string;
  getRelayerAccount(): Promise<{ accountId: string; publicKey: string }>;
}

export type { RouterApiPasskeyCustodyService } from '../cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import type { RouterApiPasskeyCustodyService } from '../cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';

export interface RouterApiServiceBag {
  walletRegistration: RouterApiWalletRegistrationService;
  walletAuthMethods: RouterApiWalletAuthMethodService;
  walletUnlock: RouterApiWalletUnlockService;
  emailOtp: RouterApiEmailOtpRouteService;
  webAuthn: RouterApiWebAuthnService;
  identity: RouterApiIdentityService;
  sessionVersions: RouterApiSessionVersionService;
  authorizationSessions: RouterApiAuthorizationSessionService;
  authorizedOperations: RouterApiAuthorizedOperationService;
  thresholdRuntime: RouterAbSigningRuntimeService;
  nearFunding: RouterApiNearFundingService;
  recovery: RouterApiRecoveryRouteService;
  router: RouterApiRouterAccountService;
  /**
   * Custody envelope retrieval, for a browser whose local storage is empty.
   *
   * Declared here rather than reached through a store because the whole
   * layer beneath it spent its existence built, tested and unreachable —
   * a port on the bag is what makes it callable from a route.
   */
  passkeyCustody: RouterApiPasskeyCustodyService;
}

export interface RouterApiAuthorizedOperationService {
  readonly tenantId: TenantId;
  recordVerifiedFactorEvidenceSet(
    input: VerifiedFactorEvidenceSetInput,
  ): Promise<VerifiedAuthorizationEvidenceSet>;
  recordVerifiedSessionEvidenceSet(
    input: VerifiedSessionEvidenceSetInput,
  ): Promise<VerifiedAuthorizationEvidenceSet>;
  readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: import('@shared/authorization/operationFingerprint').CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null>;
  admitAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: EcdsaMaterialActivationScope;
  }): Promise<
    | { readonly kind: 'claimed'; readonly operation: AuthorizedOperation }
    | { readonly kind: 'replayed'; readonly operation: AuthorizedOperation }
    | { readonly kind: 'operation_in_progress'; readonly operation: AuthorizedOperation }
    | {
        readonly kind:
          | 'authorization_grant_rejected'
          | 'verified_step_up_rejected'
          | 'wallet_session_quota_exhausted'
          | 'material_mismatch';
      }
  >;
  completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: import('../../authorization/domain').CompletedCapabilityOperationResult;
    readonly response: import('../../authorization/domain').AuthorizedOperationReplayResponse;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation>;
}

export interface RouterApiAuthorizationSessionService {
  readonly tenantId: TenantId;
  recordActiveSession(session: ActiveAuthorizationSession): Promise<void>;
  issueReusableWalletSession(
    input: IssueReusableWalletSessionInput,
  ): Promise<IssuedReusableWalletSession>;
  readActiveSession(input: {
    readonly tenantId: TenantId;
    readonly sessionId: SeamsSessionId;
    readonly nowMs: number;
  }): Promise<ActiveAuthorizationSession | null>;
  readReusableWalletSessionStatus(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletSessionId: ReusableWalletSessionStatus['walletSessionId'];
    readonly quotaId: ReusableWalletSessionStatus['quotaId'];
    readonly nowMs: number;
  }): Promise<ReusableWalletSessionStatus>;
  mintHostedWalletSeamsSessionExchange(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly sourceSessionId: SeamsSessionId;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<HostedWalletSeamsSessionExchangeDelivery>;
  redeemHostedWalletSeamsSessionExchange(input: {
    readonly exchangeCode: HostedWalletSeamsSessionExchangeCode;
    readonly nonce: HostedWalletSeamsSessionExchangeNonce;
    readonly walletOrigin: SessionOrigin;
    readonly redeemedAtMs: number;
  }): Promise<RedeemHostedWalletSeamsSessionExchangeResult>;
}

export function routerApiWalletRegistrationRouteService(
  service: RouterApiServiceBag,
): RouterApiWalletRegistrationRouteService {
  return {
    ...service.walletRegistration,
    ...service.walletAuthMethods,
    getOrCreateAppSessionVersion: service.sessionVersions.getOrCreateAppSessionVersion,
    validateAppSessionVersion: service.sessionVersions.validateAppSessionVersion,
    readActiveEmailOtpEnrollment: service.emailOtp.readActiveEmailOtpEnrollment,
    verifyWebAuthnAuthenticationLite: service.webAuthn.verifyWebAuthnAuthenticationLite,
    fundImplicitNearAccount: service.nearFunding.fundImplicitNearAccount,
    listWalletEcdsaKeyFactsInventory: service.walletRegistration.listWalletEcdsaKeyFactsInventory,
  };
}

export function routerApiEmailOtpRouteService(
  service: RouterApiServiceBag,
): RouterApiEmailOtpRouteService {
  return service.emailOtp;
}
