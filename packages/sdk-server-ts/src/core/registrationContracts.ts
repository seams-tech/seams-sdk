import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { DerivationClientSharePublicKey33B64u } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  AddAuthMethodInput,
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentGrant,
  AddSignerIntentV1,
  AddSignerSelection,
  EmailOtpRegistrationProof,
  RegistrationAuthMethodInput,
  RegistrationNearAccountProvisioning,
  RegisterWalletInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationSignerSetSelection,
  ResolvedRegistrationNearAccount,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletAuthMethodTarget,
  WalletId,
} from '@shared/utils/registrationIntent';
import type {
  EcdsaDerivationKeyScope,
  EcdsaDerivationRoleLocalFormatVersion,
  EcdsaDerivationServerBootstrapResponse,
  EcdsaThresholdKeyId,
  ThresholdEd25519AuthorityScope,
  ThresholdRuntimePolicyScope,
  ThresholdEcdsaChainTarget,
  WebAuthnAuthenticationCredential,
  RegistrationPreparationId,
} from './types';
import { registrationPreparationIdFromString } from './types';

export { registrationPreparationIdFromString };
export type { RegistrationPreparationId };

export type {
  AddAuthMethodInput,
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentGrant,
  AddSignerIntentV1,
  AddSignerSelection,
  EmailOtpRegistrationProof,
  RegisterWalletInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationSignerSetSelection,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletId,
};

export type CreateRegistrationIntentRequest = {
  wallet: RegisterWalletInput;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSetSelection;
};

export type CreateRegistrationIntentResponse =
  | {
      ok: true;
      intent: RegistrationIntentV1;
      registrationIntentDigestB64u: string;
      registrationIntentGrant: RegistrationIntentGrant;
      expiresAtMs: number;
    }
  | {
      ok: false;
      code: string;
      message: string;
      retryAfterMs?: number;
    };

export type CancelRegistrationIntentRequest = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
};

export type CancelRegistrationIntentResponse =
  | {
      ok: true;
      cancelled: boolean;
      releasedServerAllocatedWalletId: boolean;
    }
  | {
      ok: false;
      code: string;
      message: string;
      retryAfterMs?: number;
    };

export type CreateAddSignerIntentRequest = {
  walletId: WalletId;
  signerSelection: AddSignerSelection;
};

export type CreateAddSignerIntentResponse =
  | {
      ok: true;
      intent: AddSignerIntentV1;
      addSignerIntentDigestB64u: string;
      addSignerIntentGrant: AddSignerIntentGrant;
      expiresAtMs: number;
    }
  | {
      ok: false;
      code: string;
      message: string;
      retryAfterMs?: number;
    };

export type CreateAddAuthMethodIntentRequest = {
  walletId: WalletId;
  authMethod: AddAuthMethodInput;
};

export type CreateAddAuthMethodIntentResponse =
  | {
      ok: true;
      intent: AddAuthMethodIntentV1;
      addAuthMethodIntentDigestB64u: string;
      addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
      expiresAtMs: number;
    }
  | {
      ok: false;
      code: string;
      message: string;
      retryAfterMs?: number;
    };

export type AddAuthMethodAppSessionPolicy = {
  permission: 'wallet_auth_method_provision';
  walletId: WalletId;
  authMethod: AddAuthMethodInput;
  runtimePolicyScope?: RuntimePolicyScope;
  expiresAtMs: number;
};

export type AddAuthMethodExistingAuth =
  | {
      kind: 'webauthn_assertion';
      rpId: WebAuthnRpId;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      policy: AddAuthMethodAppSessionPolicy;
    };

export type AddAuthMethodAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: unknown;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type WalletAddAuthMethodStartRequest = {
  walletId: WalletId;
  addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
  addAuthMethodIntentDigestB64u: string;
  intent: AddAuthMethodIntentV1;
  auth: AddAuthMethodExistingAuth;
  authority: AddAuthMethodAuthority;
};

export type WalletAddAuthMethodStartResponse =
  | {
      ok: true;
      addAuthMethodCeremonyId: string;
      intent: AddAuthMethodIntentV1;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletAddAuthMethodFinalizeRequest = {
  addAuthMethodCeremonyId: string;
};

export type WalletAddAuthMethodFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      authority: WalletAuthAuthority;
      rpId?: string;
      authMethod: {
        kind: 'passkey' | 'email_otp';
        status: 'active' | 'revoked';
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type RevokeAuthMethodAppSessionPolicy = {
  permission: 'wallet_auth_method_revoke';
  walletId: WalletId;
  target: WalletAuthMethodTarget;
  runtimePolicyScope?: RuntimePolicyScope;
  expiresAtMs: number;
};

export type RevokeAuthMethodExistingAuth =
  | {
      kind: 'webauthn_assertion';
      rpId: WebAuthnRpId;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      policy: RevokeAuthMethodAppSessionPolicy;
    };

export type WalletRevokeAuthMethodRequest = {
  walletId: WalletId;
  auth: RevokeAuthMethodExistingAuth;
  target: WalletAuthMethodTarget;
};

export type WalletRevokeAuthMethodResponse =
  | {
      ok: true;
      walletId: WalletId;
      authMethod: {
        kind: 'passkey';
        status: 'revoked';
      };
      rpId: string;
    }
  | {
      ok: true;
      walletId: WalletId;
      authMethod: {
        kind: 'email_otp';
        status: 'revoked';
      };
      rpId?: never;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type AddSignerAppSessionPolicy = {
  permission: 'wallet_signer_provision';
  walletId: WalletId;
  signerSelection: AddSignerSelection;
  runtimePolicyScope?: RuntimePolicyScope;
  expiresAtMs: number;
};

export type AddSignerAuth =
  | {
      kind: 'webauthn_assertion';
      rpId: WebAuthnRpId;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      policy: AddSignerAppSessionPolicy;
    };

export type WalletAddSignerStartRequest = {
  walletId: WalletId;
  addSignerIntentGrant: AddSignerIntentGrant;
  addSignerIntentDigestB64u: string;
  intent: AddSignerIntentV1;
  auth: AddSignerAuth;
};

export type WalletAddSignerStartResponse =
  | ({
      ok: true;
      addSignerCeremonyId: string;
      intent: AddSignerIntentV1;
    } &
      (
        | {
            kind: 'near_ed25519';
            ed25519: WalletRegistrationEd25519YaoStart;
            ecdsa?: never;
          }
        | {
            kind: 'evm_family_ecdsa';
            ecdsa: WalletRegistrationEcdsaPreparePayload;
            ed25519?: never;
          }
      ))
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletAddSignerEcdsaDerivationRespondRequest = {
  addSignerCeremonyId: string;
  ecdsa: {
    clientBootstraps: {
      chainTarget: ThresholdEcdsaChainTarget;
      clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
    }[];
  };
};

export type WalletAddSignerEcdsaDerivationRespondResponse =
  | {
      ok: true;
      addSignerCeremonyId: string;
      ecdsa: {
        bootstraps: {
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: EcdsaDerivationServerBootstrapResponse;
        }[];
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletAddSignerFinalizeRequest = {
  addSignerCeremonyId: string;
  idempotencyKey: string;
} &
  (
    | {
        kind: 'near_ed25519';
        ed25519: WalletRegistrationEd25519YaoFinalize;
        ecdsa?: never;
      }
    | {
        kind: 'evm_family_ecdsa';
        ecdsa: {
          expectedKeyHandles?: string[];
        };
        ed25519?: never;
      }
  );

export type WalletAddSignerFinalizeResponse =
  | ({
      ok: true;
      walletId: WalletId;
    } &
      (
        | {
            kind: 'near_ed25519';
            rpId: string;
            credentialIdB64u: string;
            ed25519: WalletRegistrationEd25519YaoPublicResult;
            ecdsa?: never;
          }
        | {
            kind: 'evm_family_ecdsa';
            rpId?: string;
            ecdsa: {
              walletKeys: WalletRegistrationEcdsaWalletKey[];
            };
            ed25519?: never;
          }
      ))
  | {
      ok: false;
      code: string;
      message: string;
    };

type WalletRegistrationStartRequestBase = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
};

export type WalletRegistrationStartAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: unknown;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type WalletRegistrationStartRequest = WalletRegistrationStartRequestBase &
  (
    | {
        registrationPreparationId: RegistrationPreparationId;
        authority?: never;
      }
    | {
        registrationPreparationId?: never;
        authority: WalletRegistrationStartAuthority;
      }
  );

export type WalletRegistrationEcdsaPrepareContext = {
  formatVersion: EcdsaDerivationRoleLocalFormatVersion;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: EcdsaDerivationKeyScope;
  relayerKeyId: string;
  registrationPreparationId?: RegistrationPreparationId;
  requestId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  runtimePolicyScope?: RuntimePolicyScope;
};

export type WalletRegistrationEcdsaPrepareTarget = {
  chainTarget: ThresholdEcdsaChainTarget;
  prepare: WalletRegistrationEcdsaPrepareContext;
};

export type WalletRegistrationEcdsaPreparePayload = {
  kind: 'evm_family_ecdsa_keygen';
  targets: WalletRegistrationEcdsaPrepareTarget[];
};

export type WalletRegistrationEcdsaClientBootstrap = {
  formatVersion: EcdsaDerivationRoleLocalFormatVersion;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: EcdsaDerivationKeyScope;
  relayerKeyId: string;
  registrationPreparationId?: RegistrationPreparationId;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  runtimePolicyScope?: RuntimePolicyScope;
  clientRootProof?: never;
  passkeyBootstrapAuthorization?: never;
};

export type WalletRegistrationEcdsaWalletKey = {
  keyScope: 'evm-family';
  chainTarget: ThresholdEcdsaChainTarget;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
};

export type WalletRegistrationEd25519YaoStart = {
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
};

export type WalletRegistrationStartSignerWork =
  | {
      kind: 'near_ed25519';
      ed25519: WalletRegistrationEd25519YaoStart;
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: WalletRegistrationEcdsaPreparePayload;
      ed25519?: never;
    }
  | {
      kind: 'near_ed25519_and_evm_family_ecdsa';
      ed25519: WalletRegistrationEd25519YaoStart;
      ecdsa: WalletRegistrationEcdsaPreparePayload;
    };

export type WalletRegistrationEd25519YaoActivationReference = {
  kind: 'router_ab_ed25519_yao_activation_reference_v1';
  lifecycle_id: string;
  session_id: RouterAbEd25519YaoBytes32V1;
};

export type WalletRegistrationEd25519YaoFinalize = {
  activationReference: WalletRegistrationEd25519YaoActivationReference;
};

export type WalletRegistrationEcdsaFinalize = {
  expectedKeyHandles?: string[];
};

export type WalletRegistrationFinalizeSignerWork =
  | {
      kind: 'near_ed25519';
      ed25519: WalletRegistrationEd25519YaoFinalize;
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: WalletRegistrationEcdsaFinalize;
      ed25519?: never;
    }
  | {
      kind: 'near_ed25519_and_evm_family_ecdsa';
      ed25519: WalletRegistrationEd25519YaoFinalize;
      ecdsa: WalletRegistrationEcdsaFinalize;
    };

export type WalletRegistrationRouteTimingName =
  | 'registrationIntentLoadMs'
  | 'registrationIntentDigestMs'
  | 'registrationIntentConsumeMs'
  | 'registrationAttemptGateMs'
  | 'registrationPreparationPersistMs'
  | 'registrationPreparationLoadMs'
  | 'registrationPreparationConsumeMs'
  | 'registrationPreparationScopeCheckMs'
  | 'registrationAuthorityVerifyMs'
  | 'registrationEcdsaPrepareMs'
  | 'registrationCeremonyPersistMs'
  | 'registerPrepareTotalMs'
  | 'registerStartTotalMs'
  | 'registrationEcdsaRespondMs'
  | 'registrationFinalizeReplayLoadMs'
  | 'registrationCeremonyLoadMs'
  | 'registrationEcdsaBootstrapVerifyMs'
  | 'sponsoredNearAccountCreateMs'
  | 'registrationKeygenMs'
  | 'registrationEmailOtpEnrollmentPlanMs'
  | 'relaySessionMintMs'
  | 'relayGoogleEmailOtpActivationPlanMs'
  | 'relayPersistenceMs'
  | 'registrationFinalizeReplayCacheMs'
  | 'registerFinalizeTotalMs';

export type WalletRegistrationRouteDiagnostics = {
  kind: 'wallet_registration_route_diagnostics_v1';
  route: 'wallets_register_start' | 'wallets_register_ecdsa_derivation_respond' | 'wallets_register_finalize';
  entries: {
    name: WalletRegistrationRouteTimingName;
    durationMs: number;
  }[];
};

export type WalletRegistrationStartResponse =
  | ({
      ok: true;
      registrationCeremonyId: string;
      intent: RegistrationIntentV1;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
    } & WalletRegistrationStartSignerWork)
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletRegistrationEcdsaDerivationRespondRequest = {
  registrationCeremonyId: string;
  ecdsa: {
    clientBootstraps: {
      chainTarget: ThresholdEcdsaChainTarget;
      clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
    }[];
  };
};

export type WalletRegistrationEcdsaDerivationRespondResponse =
  | {
      ok: true;
      registrationCeremonyId: string;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ecdsa: {
        bootstraps: {
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: EcdsaDerivationServerBootstrapResponse;
        }[];
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

type WalletRegistrationFinalizeRequestBase = {
  registrationCeremonyId: string;
  idempotencyKey?: string;
  emailOtpEnrollment?: {
    recoveryWrappedEnrollmentEscrows: unknown[];
    enrollmentSealKeyVersion: string;
    clientUnlockPublicKeyB64u: string;
    unlockKeyVersion: string;
    thresholdEcdsaClientVerifyingShareB64u: string;
  };
  emailOtpBackupAck?: {
    kind: 'email_otp_recovery_code_backup_ack_v1';
    offerId?: string;
    candidateId?: string;
    recoveryCodesIssuedAtMs: number;
    backupActionKind: 'download' | 'copy' | 'print' | 'manual';
    acknowledgedAtMs: number;
    idempotencyKey: string;
  };
};

export type WalletRegistrationFinalizeRequest = WalletRegistrationFinalizeRequestBase &
  WalletRegistrationFinalizeSignerWork;

export type WalletRegistrationFinalizeAuthMethod =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
    }
  | {
      kind: 'email_otp';
      registrationAuthorityId: string;
    };

export type WalletRegistrationEd25519YaoBootstrapSession = {
  sessionKind: 'jwt';
  walletSessionJwt: string;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  participantIds: readonly [number, number];
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type WalletRegistrationEd25519YaoPublicResult = {
  signerSlot: number;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  participantIds: readonly [number, number];
  session: WalletRegistrationEd25519YaoBootstrapSession;
};

type WalletRegistrationFinalizeResponseBase = {
  ok: true;
  walletId: WalletId;
  authority: WalletAuthAuthority;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
};

type WalletRegistrationFinalizeResponseAuthMethod =
  | {
      rpId: string;
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'passkey' }>;
    }
  | {
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'email_otp' }>;
      rpId?: never;
    };

type WalletRegistrationFinalizeSignerSuccess =
  | {
      kind: 'near_ed25519';
      authorityScope: ThresholdEd25519AuthorityScope;
      accountProvisioning: RegistrationNearAccountProvisioning;
      resolvedAccount: ResolvedRegistrationNearAccount;
      ed25519: WalletRegistrationEd25519YaoPublicResult;
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
      authorityScope?: never;
      accountProvisioning?: never;
      resolvedAccount?: never;
      ed25519?: never;
    }
  | {
      kind: 'near_ed25519_and_evm_family_ecdsa';
      authorityScope: ThresholdEd25519AuthorityScope;
      accountProvisioning: RegistrationNearAccountProvisioning;
      resolvedAccount: ResolvedRegistrationNearAccount;
      ed25519: WalletRegistrationEd25519YaoPublicResult;
      ecdsa: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
    };

type WalletRegistrationFinalizeSuccessForAuth<
  AuthMethod extends WalletRegistrationFinalizeResponseAuthMethod,
  SignerSuccess = WalletRegistrationFinalizeSignerSuccess,
> = SignerSuccess extends WalletRegistrationFinalizeSignerSuccess
  ? WalletRegistrationFinalizeResponseBase & AuthMethod & SignerSuccess
  : never;

export type WalletRegistrationFinalizeSuccess =
  WalletRegistrationFinalizeResponseAuthMethod extends infer AuthMethod
    ? AuthMethod extends WalletRegistrationFinalizeResponseAuthMethod
      ? WalletRegistrationFinalizeSuccessForAuth<AuthMethod>
      : never
    : never;

export type WalletRegistrationFinalizeResponse =
  | WalletRegistrationFinalizeSuccess
  | {
      ok: false;
      code: string;
      message: string;
      retryAfterMs?: number;
    };

type PasskeyWalletRegistrationFinalizeRouteAuth = Extract<
  WalletRegistrationFinalizeResponseAuthMethod,
  { authMethod: { kind: 'passkey' } }
> & { appSessionJwt?: never };

type EmailOtpWalletRegistrationFinalizeRouteAuth = Extract<
  WalletRegistrationFinalizeResponseAuthMethod,
  { authMethod: { kind: 'email_otp' } }
> & { appSessionJwt: string };

export type WalletRegistrationFinalizeRouteSuccess =
  | WalletRegistrationFinalizeSuccessForAuth<PasskeyWalletRegistrationFinalizeRouteAuth>
  | WalletRegistrationFinalizeSuccessForAuth<EmailOtpWalletRegistrationFinalizeRouteAuth>;

export type WalletRegistrationFinalizeRouteResponse =
  | WalletRegistrationFinalizeRouteSuccess
  | Exclude<WalletRegistrationFinalizeResponse, { ok: true }>;
