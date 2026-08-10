import type {
  PasskeyCustodyEnvelopeRecord,
  WalletCustodyRegistrationOutcome,
} from '@shared/passkey-custody';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { DerivationClientSharePublicKey33B64u } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import type { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  RouterAbEd25519YaoActivationAdmissionReceiptV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  RouterAbEcdsaDerivationActivationCommitQueryResultV1,
  RouterAbEcdsaDerivationActivationPrepareResultV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationActivationRequestV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaRegistrationRequestFactsV1,
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
  RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
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
  WalletAuthMethodRecord,
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
      /** Verified by the wallet-unlock route and bound to the active app session. */
      kind: 'email_otp';
      providerUserId: string;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      authorityRef: WalletAuthAuthorityRef;
    }
  | {
      kind: 'app_session';
      policy: AddAuthMethodAppSessionPolicy;
    };

export type WalletRegistrationAuthorityInput =
  | {
      kind: typeof WALLET_AUTH_METHODS.passkey;
      webauthnRegistration: unknown;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: typeof WALLET_AUTH_METHODS.emailOtp;
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type PasskeyWalletRegistrationAuthorityInput = Extract<
  WalletRegistrationAuthorityInput,
  { kind: typeof WALLET_AUTH_METHODS.passkey }
>;

export type EmailOtpWalletRegistrationAuthorityInput = Extract<
  WalletRegistrationAuthorityInput,
  { kind: typeof WALLET_AUTH_METHODS.emailOtp }
>;

export type WalletAddAuthMethodAuthorityInput =
  | {
      kind: typeof WALLET_AUTH_METHODS.passkey;
      webauthnRegistration?: never;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: typeof WALLET_AUTH_METHODS.emailOtp;
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type WalletAddAuthMethodStartRequest = {
  walletId: WalletId;
  addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
  addAuthMethodIntentDigestB64u: string;
  intent: AddAuthMethodIntentV1;
  auth: AddAuthMethodExistingAuth;
  authority: WalletAddAuthMethodAuthorityInput;
};

export type WalletAddAuthMethodRegistrationOptions = {
  readonly kind: 'webauthn_add_auth_method_registration_v1';
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly rpId: string;
  readonly user: {
    readonly idB64u: string;
    readonly name: string;
    readonly displayName: string;
  };
  readonly pubKeyCredParams: readonly [
    { readonly type: 'public-key'; readonly alg: -7 },
    { readonly type: 'public-key'; readonly alg: -257 },
  ];
  readonly authenticatorSelection: {
    readonly residentKey: 'required';
    readonly userVerification: 'preferred';
  };
  readonly timeoutMs: number;
  readonly attestation: 'none';
  readonly extensions: {
    readonly prf: {
      readonly eval: {
        readonly firstB64u: string;
        readonly secondB64u: string;
      };
    };
  };
  readonly excludeCredentials: readonly {
    readonly type: 'public-key';
    readonly id: string;
  }[];
};

export type WalletAddAuthMethodStartResponse =
  | {
      ok: true;
      addAuthMethodCeremonyId: string;
      intent: AddAuthMethodIntentV1 & {
        authMethod: Extract<AddAuthMethodInput, { kind: typeof WALLET_AUTH_METHODS.passkey }>;
      };
      custodyEnvelope: PasskeyCustodyEnvelopeRecord;
      registration: WalletAddAuthMethodRegistrationOptions;
    }
  | {
      ok: true;
      addAuthMethodCeremonyId: string;
      intent: AddAuthMethodIntentV1 & {
        authMethod: Extract<AddAuthMethodInput, { kind: typeof WALLET_AUTH_METHODS.emailOtp }>;
      };
      custodyEnvelope?: never;
      registration?: never;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletAddAuthMethodFinalizeRequest =
  | {
      addAuthMethodCeremonyId: string;
      webauthnRegistration: unknown;
      custodyEnvelope: PasskeyCustodyEnvelopeRecord;
    }
  | {
      addAuthMethodCeremonyId: string;
      webauthnRegistration?: never;
      custodyEnvelope?: never;
    };

export type WalletAuthMethodStatusAnnotation<Status extends WalletAuthMethodRecord['status']> = {
  kind: WalletAuthMethodRecord['kind'];
  status: Status;
};

export type WalletAddAuthMethodFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      authority: WalletAuthAuthority;
      rpId: WebAuthnRpId;
      authMethod: {
        kind: 'passkey';
        status: 'active';
        credentialIdB64u: string;
        credentialPublicKeyB64u: string;
        counter: number;
        device: WebAuthnAuthenticatorDeviceInfo;
      };
    }
  | {
      ok: true;
      walletId: WalletId;
      authority: WalletAuthAuthority;
      rpId?: never;
      authMethod: {
        kind: 'email_otp';
        status: 'active';
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
      authMethod: WalletAuthMethodStatusAnnotation<'revoked'> & {
        kind: typeof WALLET_AUTH_METHODS.passkey;
      };
      rpId: string;
    }
  | {
      ok: true;
      walletId: WalletId;
      authMethod: WalletAuthMethodStatusAnnotation<'revoked'> & {
        kind: typeof WALLET_AUTH_METHODS.emailOtp;
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

export type WalletAddSignerEd25519YaoStart = {
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  custodyEnvelope: PasskeyCustodyEnvelopeRecord;
};

export type WalletAddSignerStartResponse =
  | ({
      ok: true;
      addSignerCeremonyId: string;
      intent: AddSignerIntentV1;
    } & (
      | ({ readonly authorizationKind: 'webauthn_assertion' } & (
          | {
              kind: 'near_ed25519';
              ed25519: WalletAddSignerEd25519YaoStart;
              ecdsa?: never;
            }
          | {
              kind: 'evm_family_ecdsa';
              ecdsa: WalletAddSignerEcdsaPreparePayload;
              ed25519?: never;
            }
        ))
      | {
          readonly authorizationKind: 'app_session';
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
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: RouterAbEcdsaRegistrationRequestV1;
    requestDigestB64u: string;
  };
};

export type WalletAddSignerEcdsaDerivationRespondResponse =
  | {
      ok: true;
      addSignerCeremonyId: string;
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_forwarded_v1';
        strictResult: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

/**
 * The activation commit. `expectedActivationRequestDigest` is the digest of
 * the canonical `wallet_add_signer_activate_v2` command the client computed
 * locally; the server recomputes it from these same coordinates rather than
 * having handed it back from a preparation route.
 */
export type WalletAddSignerEcdsaActivationRequest = {
  addSignerCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_activation_v1';
    activationCorrelationId: RouterAbEcdsaRegistrationActivationRequestV1['ecdsa']['activationCorrelationId'];
    publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
    expectedActivationRequestDigest: RouterAbPublicDigest32V1Wire;
  };
};

export type WalletAddSignerEcdsaActivationResponse =
  | {
      ok: true;
      addSignerCeremonyId: string;
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activated_v1';
        activation: RouterAbEcdsaRegistrationActivationReceiptV1;
        bootstrap: EcdsaDerivationServerBootstrapResponse;
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
} & (
  | {
      kind: 'near_ed25519';
      ed25519: WalletRegistrationEd25519YaoFinalize;
      custodyKeySet: {
        readonly kind: 'near_ed25519_v1';
        readonly keyManifestDigestB64u: string;
        readonly registeredPublicKeyB64u: string;
      };
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: {
        expectedKeyHandles: readonly [string];
      };
      custodyKeySet: {
        readonly kind: 'evm_family_ecdsa_v1';
        readonly keyManifestDigestB64u: string;
        readonly clientRootPublicKey33B64u: string;
      };
      ed25519?: never;
    }
);

export type WalletAddSignerFinalizeResponse =
  | ({
      ok: true;
      walletId: WalletId;
    } & (
      | {
          kind: 'near_ed25519';
          rpId: string;
          credentialIdB64u: string;
          ed25519: WalletEd25519YaoSignerPublicResult;
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

export type WalletRegistrationStartRequest = WalletRegistrationStartRequestBase &
  (
    | {
        registrationPreparationId: RegistrationPreparationId;
        authority?: never;
      }
    | {
        registrationPreparationId?: never;
        authority: WalletRegistrationAuthorityInput;
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
  registrationPreparationId: RegistrationPreparationId;
  requestId: string;
  thresholdSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: readonly [1, 2];
  runtimePolicyScope: RuntimePolicyScope;
};

export type WalletRegistrationEcdsaPreparePayload = {
  kind: 'evm_family_ecdsa_keygen';
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  prepare: WalletRegistrationEcdsaPrepareContext;
  strictRegistration: RouterAbEcdsaRegistrationRequestFactsV1;
};

export type WalletAddSignerEcdsaPreparePayload = WalletRegistrationEcdsaPreparePayload & {
  custodyEnvelope: PasskeyCustodyEnvelopeRecord;
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
  registrationPreparationId: RegistrationPreparationId;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  thresholdSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: readonly [1, 2];
  runtimePolicyScope: RuntimePolicyScope;
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
  contextBinding32B64u: string;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  relayerShareRetryCounter: number;
  participantIds: readonly [1, 2];
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type WalletRegistrationEd25519YaoStart = {
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
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
  expectedKeyHandles: readonly [string];
};

/**
 * One finalize call commits one signer branch. A wallet planned with both
 * signers finalizes twice — `evm_family_ecdsa` first, which returns the wallet
 * ECDSA-ready, then `near_ed25519` once the Yao ceremony settles (Refactor 94
 * Phase 4+5). There is deliberately no combined member: registration success
 * no longer waits on Ed25519, so nothing can commit both at once.
 */
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
    };

export type WalletRegistrationRouteTimingName =
  | 'registrationCeremonyLoadMs'
  | 'registrationEcdsaBootstrapVerifyMs'
  | 'registrationEmailOtpEnrollmentPlanMs'
  | 'relayPersistenceMs'
  | 'registerFinalizeTotalMs'
  /* 94C setup: the ceremony insert is the route's only D1 write, so it gets
     its own mark rather than being folded into a persistence total. */
  | 'registrationCeremonyInsertMs'
  | 'registerSetupTotalMs';

export type WalletRegistrationRouteDiagnostics = {
  kind: 'wallet_registration_route_diagnostics_v1';
  route: 'wallets_register_setup' | 'wallets_register_finalize';
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
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: RouterAbEcdsaRegistrationRequestV1;
  };
};

export type WalletRegistrationEcdsaDerivationRespondResponse =
  | {
      ok: true;
      registrationCeremonyId: string;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      /**
       * Gateway boundary timings for this call, as fixed metric names with
       * millisecond durations. Stripped into a `Server-Timing` response header
       * at the route layer and never serialized into the wire body.
       */
      gatewayServerTiming?: readonly (readonly [string, number])[];
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_forwarded_v1';
        strictResult: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletRegistrationEcdsaActivationRequest = {
  registrationCeremonyId: string;
  ecdsa: RouterAbEcdsaRegistrationActivationRequestV1['ecdsa'] & {
    expectedActivationRequestDigest: RouterAbPublicDigest32V1Wire;
  };
};

export type WalletRegistrationEcdsaActivationResponse =
  | {
      ok: true;
      registrationCeremonyId: string;
      /** See WalletRegistrationEcdsaDerivationRespondResponse.gatewayServerTiming. */
      gatewayServerTiming?: readonly (readonly [string, number])[];
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activated_v1';
        activation: RouterAbEcdsaRegistrationActivationReceiptV1;
        bootstrap: EcdsaDerivationServerBootstrapResponse;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

type WalletRegistrationFinalizeRequestBase = {
  registrationCeremonyId: string;
  idempotencyKey: string;
  /**
   * The wallet custody ceremony's sealed output, when the client ran one for
   * this key set. Carried unvalidated: the admission gate owns every check,
   * and it must be able to *report* a malformed payload rather than have the
   * route reject the request — the wallet is committed either way.
   *
   * Note this participates in `walletRegistrationFinalizeRequestFingerprint`,
   * which hashes the whole request. That is correct: a different custody
   * payload is a different request and must not adopt a prior operation row.
   */
  walletCustodyCommit?: unknown;
  emailOtpEnrollment?: {
    enrollmentSealKeyVersion: string;
    clientUnlockPublicKeyB64u: string;
    unlockKeyVersion: string;
    serverSealedFactorCiphertextB64u: string;
  };
};

export type WalletRegistrationFinalizeRequest = WalletRegistrationFinalizeRequestBase &
  WalletRegistrationFinalizeSignerWork;

export type WalletRegistrationFinalizeAuthMethod =
  | {
      kind: typeof WALLET_AUTH_METHODS.passkey;
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
    }
  | {
      kind: typeof WALLET_AUTH_METHODS.emailOtp;
      registrationAuthorityId: string;
    };

export type PasskeyWalletRegistrationFinalizeAuthMethod = Extract<
  WalletRegistrationFinalizeAuthMethod,
  { kind: typeof WALLET_AUTH_METHODS.passkey }
>;

export type EmailOtpWalletRegistrationFinalizeAuthMethod = Extract<
  WalletRegistrationFinalizeAuthMethod,
  { kind: typeof WALLET_AUTH_METHODS.emailOtp }
>;

export type WalletRegistrationEd25519YaoBootstrapSession = {
  sessionKind: 'jwt';
  walletSessionJwt: string;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  thresholdSessionId: string;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  expiresAtMs: number;
  participantIds: readonly [number, number];
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type WalletEd25519YaoSignerPublicResult = {
  signerSlot: number;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  participantIds: readonly [number, number];
};

export type WalletRegistrationEd25519YaoPublicResult = WalletEd25519YaoSignerPublicResult & {
  thresholdSessionId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

type WalletRegistrationFinalizeResponseBase = {
  ok: true;
  walletId: WalletId;
  authority: WalletAuthAuthority;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
  /**
   * What became of this leg's custody commit. Absent when no custody payload
   * rode the request, so a wallet registered before this existed is unchanged
   * on the wire. Anything other than `committed` is the client's to act on —
   * the registration itself succeeded regardless.
   */
  walletCustody?: WalletCustodyRegistrationOutcome;
};

type WalletRegistrationFinalizeResponseAuthMethod =
  | {
      rpId: string;
      authMethod: PasskeyWalletRegistrationFinalizeAuthMethod;
    }
  | {
      authMethod: EmailOtpWalletRegistrationFinalizeAuthMethod;
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
    };

type WalletRegistrationFinalizeSuccessForAuth<
  AuthMethodBranch extends WalletRegistrationFinalizeResponseAuthMethod,
  SignerSuccess = WalletRegistrationFinalizeSignerSuccess,
> = SignerSuccess extends WalletRegistrationFinalizeSignerSuccess
  ? WalletRegistrationFinalizeResponseBase & AuthMethodBranch & SignerSuccess
  : never;

export type WalletRegistrationFinalizeSuccess =
  WalletRegistrationFinalizeResponseAuthMethod extends infer AuthMethodBranch
    ? AuthMethodBranch extends WalletRegistrationFinalizeResponseAuthMethod
      ? WalletRegistrationFinalizeSuccessForAuth<AuthMethodBranch>
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
  { authMethod: PasskeyWalletRegistrationFinalizeAuthMethod }
> & { appSessionJwt?: never };

type EmailOtpWalletRegistrationFinalizeRouteAuth = Extract<
  WalletRegistrationFinalizeResponseAuthMethod,
  { authMethod: EmailOtpWalletRegistrationFinalizeAuthMethod }
> & { appSessionJwt: string };

export type WalletRegistrationFinalizeRouteSuccess =
  | WalletRegistrationFinalizeSuccessForAuth<PasskeyWalletRegistrationFinalizeRouteAuth>
  | WalletRegistrationFinalizeSuccessForAuth<EmailOtpWalletRegistrationFinalizeRouteAuth>;

export type WalletRegistrationFinalizeRouteResponse =
  | WalletRegistrationFinalizeRouteSuccess
  | Exclude<WalletRegistrationFinalizeResponse, { ok: true }>;
