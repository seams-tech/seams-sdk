// Platform-agnostic types for server functionality
import {
  AuthenticatorOptions,
  UserVerificationPolicy,
  OriginPolicyInput,
} from '@shared/utils/authenticatorOptions';
import type { InitInput } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { Logger } from './logger';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  EcdsaClientRootPublicKey33B64u,
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { RouterAbEcdsaHssNormalSigningScopeV1 } from '@shared/utils/routerAbEcdsaHss';
import type {
  AddAuthMethodInput,
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentGrant,
  AddSignerIntentV1,
  AddSignerSelection,
  EmailOtpRegistrationProof,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationNearAccountProvisioning,
  ResolvedRegistrationNearAccount,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationSignerSelection,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletAuthMethodTarget,
  WalletId,
} from '@shared/utils/registrationIntent';
import type {
  CreateHostedSigningRootShareResolverInput,
  SigningRootShareDecryptAdapter,
  SigningRootShareResolver,
  SigningRootShareSource,
  ThresholdPrfPolicy,
} from './ThresholdService/signingRootShareResolver';

/**
 * WASM Bindgen generates a `free` method and a `[Symbol.dispose]` method on all structs.
 * Strip both so we can pass plain objects to the worker.
 */
export type StripFree<T> = T extends object
  ? { [K in keyof T as K extends 'free' | symbol ? never : K]: StripFree<T[K]> }
  : T;

// Standard request/response interfaces that work across all platforms
export interface ServerRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface ServerResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export type SignerWasmModuleSupplier =
  | InitInput
  | Promise<InitInput>
  | (() => InitInput | Promise<InitInput>);

export interface SignerWasmConfig {
  /**
   * Optional override for locating the signer WASM module. Useful for serverless
   * runtimes (e.g. Workers) where filesystem-relative URLs are unavailable.
   * Accepts any value supported by `initSignerWasm({ module_or_path })` or a
   * function that resolves to one.
   */
  moduleOrPath?: SignerWasmModuleSupplier;
}

export interface ThresholdEd25519HssCanonicalContext {
  applicationBindingDigestB64u: string;
  participantIds: number[];
}

export type ThresholdEd25519RegistrationAccountScope =
  | {
      kind: 'generated_implicit_registration_scope';
      walletId: string;
      rpId: string;
      intentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      ed25519KeyScopeId: string;
      signerSlot: number;
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      participantIds: number[];
      requestedAccountId?: never;
      nearAccountId?: never;
    }
  | {
      kind: 'sponsored_named_registration_scope';
      walletId: string;
      rpId: string;
      intentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      ed25519KeyScopeId: string;
      signerSlot: number;
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      participantIds: number[];
      requestedAccountId: string;
      nearAccountId?: never;
    }
  | {
      kind: 'known_account_registration_scope';
      walletId: string;
      rpId: string;
      intentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      ed25519KeyScopeId: string;
      signerSlot: number;
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      participantIds: number[];
      nearAccountId: string;
      requestedAccountId?: never;
    };

export interface ThresholdEd25519HssClientInputs {
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}

export interface ThresholdEd25519HssServerInputs {
  yRelayerB64u: string;
  tauRelayerB64u: string;
}

export interface ThresholdEd25519HssStoredServerInputs {
  yRelayerBytes: Uint8Array;
  tauRelayerBytes: Uint8Array;
}

export interface ThresholdEd25519HssSessionInputs {
  context: ThresholdEd25519HssCanonicalContext;
  client: ThresholdEd25519HssClientInputs;
  server: ThresholdEd25519HssServerInputs;
}

export interface ThresholdEd25519HssPreparedSessionEnvelope {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
}

export interface ThresholdEd25519HssPreparedServerSessionEnvelope {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
  garblerDriverStateB64u: string;
  clientOtOfferMessageB64u: string;
  preparedSessionHandle: string;
  timings: ThresholdEd25519HssPrepareServerSessionTimings;
}

export interface ThresholdEd25519HssPrepareServerSessionTimings {
  prepareSessionMs: number;
  extractDriverStatesMs: number;
  clientOfferMessageMs: number;
  cachePreparedSessionMs: number;
  encodeStatesMs: number;
}

export interface ThresholdEd25519HssStoredPreparedServerSession {
  preparedSessionHandle?: string;
  evaluatorDriverStateBytes: Uint8Array;
  garblerDriverStateBytes: Uint8Array;
}

export interface ThresholdEd25519HssClientRequestEnvelope {
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
}

export interface ThresholdEd25519HssServerVisibleClientRequestEnvelope {
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u?: never;
  yClientB64u?: never;
  tauClientB64u?: never;
  rClientB64u?: never;
  clientOutputMaskB64u?: never;
  prfFirstB64u?: never;
  prfOutputB64u?: never;
  clientSecretB64u?: never;
  clientSecret32B64u?: never;
}

export interface ThresholdEd25519HssRoleSeparatedRespondWithSessionRequest {
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
}

export interface ThresholdEd25519HssRoleSeparatedRespondForRegistrationRequest {
  registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
  wallet_key_id: string;
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
}

export interface ThresholdEd25519HssServerInputDeliveryEnvelope {
  contextBindingB64u: string;
  serverInputDeliveryB64u: string;
  evaluatorOtStateB64u?: never;
  stagedEvaluatorArtifactB64u?: never;
  yClientB64u?: never;
  tauClientB64u?: never;
  yRelayerB64u?: never;
  tauRelayerB64u?: never;
  rClientB64u?: never;
  prfOutputB64u?: never;
  clientSecret32B64u?: never;
}

export interface ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope {
  contextBindingB64u: string;
  stagedEvaluatorArtifactB64u: string;
  stagedEvaluatorArtifactHandle?: never;
  evaluatorOtStateB64u?: never;
  xClientBaseB64u?: never;
  xRelayerBaseB64u?: never;
  yClientB64u?: never;
  tauClientB64u?: never;
  yRelayerB64u?: never;
  tauRelayerB64u?: never;
  rClientB64u?: never;
  clientOutputMaskB64u?: never;
  prfOutputB64u?: never;
  clientSecret32B64u?: never;
  seedOutputMessageB64u?: never;
}

export interface ThresholdEd25519HssRoleSeparatedServerStageResponsesEnvelope {
  serverAssistInitMessageB64u: string;
  addStageResponseMessageB64u: string;
  messageScheduleResponseMessagesB64u: string[];
  roundCoreResponseMessagesB64u: string[];
  outputProjectionResponseMessageB64u: string;
  evaluatorDriverStateB64u?: never;
  evaluatorOtStateB64u?: never;
  stagedEvaluatorArtifactB64u?: never;
  stagedEvaluatorArtifactBytes?: never;
  yClientB64u?: never;
  tauClientB64u?: never;
  yRelayerB64u?: never;
  tauRelayerB64u?: never;
}

export interface ThresholdEd25519HssRoleSeparatedOutputDeliveryEnvelope {
  clientOutputDeliveryMessageB64u: string;
  outputCommitmentB64u: string;
  clientMaskCommitmentB64u: string;
  evaluatorOtStateB64u?: never;
  rClientB64u?: never;
  xClientBaseB64u?: never;
  xClientBaseBlindedB64u?: never;
  xRelayerBaseB64u?: never;
  yClientB64u?: never;
  tauClientB64u?: never;
  yRelayerB64u?: never;
  tauRelayerB64u?: never;
  prfOutputB64u?: never;
  clientSecret32B64u?: never;
}

export type ThresholdEd25519HssRoleSeparatedRespondResponse =
  | {
      ok: true;
      contextBindingB64u: string;
      serverStageResponses: ThresholdEd25519HssRoleSeparatedServerStageResponsesEnvelope;
      outputDelivery: ThresholdEd25519HssRoleSeparatedOutputDeliveryEnvelope;
      evaluatorDriverStateB64u?: never;
      evaluatorOtStateB64u?: never;
      stagedEvaluatorArtifactB64u?: never;
      stagedEvaluatorArtifactBytes?: never;
      clientOutputMessageB64u?: never;
      seedOutputMessageB64u?: never;
      xClientBaseB64u?: never;
      xClientBaseBlindedB64u?: never;
      xRelayerBaseB64u?: never;
      rClientB64u?: never;
      prfOutputB64u?: never;
      clientSecret32B64u?: never;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type ThresholdEd25519HssStagedEvaluatorArtifactEnvelope =
  | {
      contextBindingB64u: string;
      stagedEvaluatorArtifactHandle: string;
      stagedEvaluatorArtifactBytes?: undefined;
    }
  | {
      contextBindingB64u: string;
      stagedEvaluatorArtifactBytes: Uint8Array;
      stagedEvaluatorArtifactHandle?: undefined;
    };

export type ThresholdEd25519HssStoredStagedEvaluatorArtifact =
  | {
      stagedEvaluatorArtifactHandle: string;
      stagedEvaluatorArtifactBytes?: undefined;
    }
  | {
      stagedEvaluatorArtifactBytes: Uint8Array;
      stagedEvaluatorArtifactHandle?: undefined;
    };

export interface ThresholdEd25519HssFinalizedReportEnvelope {
  contextBindingB64u: string;
  clientOutputMessageB64u: string;
  seedOutputMessageB64u?: string;
}

export interface ThresholdEd25519HssOpenedClientOutput {
  contextBindingB64u: string;
  xClientBaseB64u: string;
}

export interface ThresholdEd25519HssOpenedServerOutput {
  contextBindingB64u: string;
  xRelayerBaseB64u: string;
}

export interface ThresholdEd25519HssOpenedSeedOutput {
  contextBindingB64u: string;
  canonicalSeedB64u: string;
}

export interface ThresholdEd25519HssDerivedPublicKey {
  publicKeyB64u: string;
}

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
  RegistrationSignerSelection,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletId,
};

export type CreateRegistrationIntentRequest = {
  wallet: RegisterWalletInput;
  rpId: string;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSelection;
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
    };

export type CreateAddSignerIntentRequest = {
  walletId: WalletId;
  rpId: string;
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
    };

export type CreateAddAuthMethodIntentRequest = {
  walletId: WalletId;
  rpId: string;
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
      rpId: string;
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
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      policy: RevokeAuthMethodAppSessionPolicy;
    };

export type WalletRevokeAuthMethodRequest = {
  walletId: WalletId;
  rpId: string;
  auth: RevokeAuthMethodExistingAuth;
  target: WalletAuthMethodTarget;
};

export type WalletRevokeAuthMethodResponse =
  | {
      ok: true;
      walletId: WalletId;
      rpId: string;
      authMethod: {
        kind: 'passkey' | 'email_otp';
        status: 'revoked';
      };
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
  | {
      ok: true;
      addSignerCeremonyId: string;
      intent: AddSignerIntentV1;
      ed25519?: {
        ceremonyHandle: string;
        preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
        clientOtOfferMessageB64u: string;
      };
      ecdsa?: WalletRegistrationEcdsaPreparePayload;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletAddSignerHssRespondRequest = {
  addSignerCeremonyId: string;
  ed25519?: {
    clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
  };
  ecdsa?: {
    clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  };
};

export type WalletAddSignerHssRespondResponse =
  | {
      ok: true;
      addSignerCeremonyId: string;
      ed25519?: {
        contextBindingB64u: string;
        serverInputDeliveryB64u: string;
      };
      ecdsa?: {
        bootstrap: EcdsaHssServerBootstrapResponse;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletAddSignerFinalizeRequest = {
  addSignerCeremonyId: string;
  ed25519?: {
    evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope;
    sessionPolicy?: Ed25519SessionPolicy;
    sessionKind?: 'jwt';
  };
  ecdsa?: {
    expectedKeyHandles?: string[];
  };
};

export type WalletAddSignerFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      rpId: string;
      ed25519?: {
        nearAccountId: string;
        ed25519KeyScopeId: string;
        publicKey: string;
        relayerKeyId: string;
        keyVersion: string;
        recoveryExportCapable: true;
        clientParticipantId?: number;
        relayerParticipantId?: number;
        participantIds?: number[];
        session?: ThresholdEd25519BootstrapSession;
      };
      ecdsa?: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
    }
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

export type RegistrationPreparationId = string & { readonly __brand: 'RegistrationPreparationId' };

export function registrationPreparationIdFromString(value: string): RegistrationPreparationId {
  return String(value || '').trim() as RegistrationPreparationId;
}

export type WalletRegistrationPrepareGateContext =
  | {
      kind: 'source_ip';
      sourceIp: string;
    }
  | {
      kind: 'source_unavailable';
      reason: 'source_ip_unavailable' | 'direct_service_call';
    };

export type WalletRegistrationPrepareRequest = WalletRegistrationStartRequestBase & {
  prepareGate: WalletRegistrationPrepareGateContext;
  work:
    | {
        kind: 'ed25519_hss';
        ecdsa?: never;
      }
    | {
        kind: 'ed25519_hss_and_ecdsa';
        ecdsa?: never;
      };
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

export type WalletRegistrationStartRequest = WalletRegistrationStartRequestBase & {
  registrationPreparationId?: RegistrationPreparationId;
  authority: WalletRegistrationStartAuthority;
};

export type WalletRegistrationEcdsaPreparePayload = {
  kind: 'evm_family_ecdsa_keygen';
  chainTargets: ThresholdEcdsaChainTarget[];
  prepare: {
    formatVersion: EcdsaHssRoleLocalFormatVersion;
    walletId: string;
    walletKeyId: string;
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: string;
    signingRootVersion: string;
    keyScope: EcdsaHssKeyScope;
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
};

export type WalletRegistrationEcdsaClientBootstrap = {
  formatVersion: EcdsaHssRoleLocalFormatVersion;
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: EcdsaHssKeyScope;
  relayerKeyId: string;
  registrationPreparationId?: RegistrationPreparationId;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
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
  walletKeyId: string;
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
  | 'registrationHssPrepareMs'
  | 'registrationPreauthHssPrepareMs'
  | 'registrationHssServerInputDeriveMs'
  | 'registrationHssServerSessionPrepareTotalMs'
  | 'registrationHssPrepareSessionMs'
  | 'registrationHssPrepareExtractDriverStatesMs'
  | 'registrationHssPrepareClientOfferMessageMs'
  | 'registrationHssPrepareCachePreparedSessionMs'
  | 'registrationHssPrepareEncodeStatesMs'
  | 'registrationEcdsaPrepareMs'
  | 'registrationCeremonyPersistMs'
  | 'registerPrepareTotalMs'
  | 'registerStartTotalMs'
  | 'registrationHssRespondMs'
  | 'registrationHssRespondDecodeMessagesMs'
  | 'registrationHssRespondMaterializeSessionMs'
  | 'registrationHssRespondPrepareDeliveryMs'
  | 'registrationHssRespondDeliveryOtOpenJoinMs'
  | 'registrationHssRespondDeliveryServerInputOpenMs'
  | 'registrationHssRespondDeliveryServerInputShareMs'
  | 'registrationHssRespondDeliveryServerInputCommitmentMs'
  | 'registrationHssRespondDeliveryServerInputTranscriptMs'
  | 'registrationHssRespondDeliveryServerInputSealMs'
  | 'registrationHssRespondEncodeDeliveryMs'
  | 'registrationEcdsaRespondMs'
  | 'registerHssRespondTotalMs'
  | 'registrationFinalizeReplayLoadMs'
  | 'registrationCeremonyLoadMs'
  | 'registrationHssFinalizeMs'
  | 'registrationHssFinalizeDecodeArtifactMs'
  | 'registrationHssFinalizeSerializedSessionMaterializeMs'
  | 'registrationHssFinalizeReportMs'
  | 'registrationHssFinalizeEncodeReportMs'
  | 'registrationHssFinalizeOpenServerOutputMs'
  | 'registrationHssFinalizeOpenSeedOutputMs'
  | 'registrationHssFinalizeDeriveSeedKeypairMs'
  | 'registrationHssFinalizeDeriveRelayerVerifyingShareMs'
  | 'registrationHssFinalizeKeyStorePutMs'
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
  route:
    | 'wallets_register_prepare'
    | 'wallets_register_start'
    | 'wallets_register_hss_respond'
    | 'wallets_register_finalize';
  entries: {
    name: WalletRegistrationRouteTimingName;
    durationMs: number;
  }[];
};

export type WalletRegistrationPrepareResponse =
  | {
      ok: true;
      state: 'prepared';
      registrationPreparationId: RegistrationPreparationId;
      expiresAtMs: number;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519: {
        ceremonyHandle: string;
        preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
        clientOtOfferMessageB64u: string;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

export type WalletRegistrationStartResponse =
  | {
      ok: true;
      registrationCeremonyId: string;
      intent: RegistrationIntentV1;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519?: {
        ceremonyHandle: string;
        preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
        clientOtOfferMessageB64u: string;
      };
      ecdsa?: WalletRegistrationEcdsaPreparePayload;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletRegistrationHssRespondRequest = {
  registrationCeremonyId: string;
  ed25519?: {
    clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
  };
  ecdsa?: {
    clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  };
};

export type WalletRegistrationHssRespondResponse =
  | {
      ok: true;
      registrationCeremonyId: string;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519?: {
        contextBindingB64u: string;
        serverInputDeliveryB64u: string;
      };
      ecdsa?: {
        bootstrap: EcdsaHssServerBootstrapResponse;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type WalletRegistrationFinalizeRequest = {
  registrationCeremonyId: string;
  idempotencyKey?: string;
  ed25519?: {
    evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope;
    sessionPolicy?: Ed25519SessionPolicy;
    sessionKind?: 'jwt';
  };
  ecdsa?: {
    expectedKeyHandles?: string[];
  };
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

export type WalletRegistrationFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      rpId: string;
      accountProvisioning: RegistrationNearAccountProvisioning;
      resolvedAccount: ResolvedRegistrationNearAccount;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519: {
        nearAccountId: string;
        ed25519KeyScopeId: string;
        publicKey: string;
        relayerKeyId: string;
        keyVersion: string;
        recoveryExportCapable: true;
        clientParticipantId?: number;
        relayerParticipantId?: number;
        participantIds?: number[];
        session?: ThresholdEd25519BootstrapSession;
      };
      ecdsa?: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
    }
  | {
      ok: true;
      walletId: WalletId;
      rpId: string;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ecdsa: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
      accountProvisioning?: never;
      resolvedAccount?: never;
      ed25519?: never;
    }
  | {
      ok: true;
      kind: 'already_finalized_restore_required';
      walletId: WalletId;
      rpId: string;
      reason: 'replay_without_session_material';
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519?: never;
      ecdsa?: never;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type ThresholdEd25519BootstrapSession = {
  sessionKind: 'jwt' | 'cookie';
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  jwt?: string;
};

export type ThresholdEd25519HssSessionOperation =
  | 'tx_signing'
  | 'link_device'
  | 'email_recovery'
  | 'warm_session_reconstruction'
  | 'explicit_key_export';

export interface ThresholdEd25519HssPrepareWithSessionRequest {
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
}

export interface ThresholdEd25519HssPrepareForRegistrationRequest {
  registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
  wallet_key_id: string;
  context: ThresholdEd25519HssCanonicalContext;
}

export interface ThresholdEd25519HssRespondWithSessionRequest {
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
}

export interface ThresholdEd25519HssRespondForRegistrationRequest {
  registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
  wallet_key_id: string;
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
}

export type ThresholdEd25519HssPrepareWithSessionResponse =
  | {
      ok: true;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
      serverInputDeriveMs: number;
      serverSessionPrepareTotalMs: number;
      serverSessionTimings: ThresholdEd25519HssPrepareServerSessionTimings;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssPrepareForRegistrationResponse =
  | {
      ok: true;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
      serverInputDeriveMs: number;
      serverSessionPrepareTotalMs: number;
      serverSessionTimings: ThresholdEd25519HssPrepareServerSessionTimings;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssRespondWithSessionResponse =
  | {
      ok: true;
      contextBindingB64u: string;
      serverInputDeliveryB64u: string;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssRespondForRegistrationResponse =
  | {
      ok: true;
      contextBindingB64u: string;
      serverInputDeliveryB64u: string;
      serverInputDeliveryTimings?: {
        decodeMessagesMs: number;
        materializeSessionMs: number;
        prepareDeliveryMs: number;
        deliveryOtOpenJoinMs: number;
        deliveryServerInputOpenMs: number;
        deliveryServerInputShareMs: number;
        deliveryServerInputCommitmentMs: number;
        deliveryServerInputTranscriptMs: number;
        deliveryServerInputSealMs: number;
        encodeDeliveryMs: number;
      };
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export interface ThresholdEd25519HssFinalizeWithSessionRequest {
  ceremonyHandle: string;
  evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope;
}

export type ThresholdEd25519HssFinalizeAccountResolution =
  | {
      kind: 'registration_provisioning';
      accountProvisioning: RegistrationNearAccountProvisioning;
      nearAccountId?: never;
    }
  | {
      kind: 'known_account';
      nearAccountId: string;
      accountProvisioning?: never;
    };

export interface ThresholdEd25519HssFinalizeForRegistrationRequest {
  registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
  wallet_key_id: string;
  ceremonyHandle: string;
  evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope;
  accountResolution: ThresholdEd25519HssFinalizeAccountResolution;
}

export type ThresholdEd25519HssFinalizeWithSessionResponse =
  | {
      ok: true;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssFinalizeForRegistrationResponse =
  | {
      ok: true;
      publicKey: string;
      nearAccountId: string;
      relayerKeyId: string;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
      finalizeReportTimings?: {
        decodeArtifactMs: number;
        serializedSessionMaterializeMs: number;
        finalizeReportMs: number;
        encodeReportMs: number;
        openServerOutputMs: number;
        openSeedOutputMs: number;
        deriveSeedKeypairMs: number;
        deriveRelayerVerifyingShareMs: number;
        keyStorePutMs: number;
      };
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

// ================================
// Threshold Ed25519 key persistence
// ================================

export type ThresholdEd25519KeyStoreKind =
  | 'in-memory'
  | 'upstash-redis-rest'
  | 'redis-tcp'
  | 'cloudflare-do';

// Structural types so Workers can pass Durable Object bindings without depending on CF type packages.
export interface CloudflareDurableObjectStubLike {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

export interface CloudflareDurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): CloudflareDurableObjectStubLike;
}

export type ThresholdStoreConfig =
  | { kind: 'in-memory' }
  | { kind: 'upstash-redis-rest'; url: string; token: string; keyPrefix?: string }
  | { kind: 'redis-tcp'; redisUrl: string; keyPrefix?: string }
  | { kind: 'postgres'; postgresUrl: string; keyPrefix?: string }
  | {
      kind: 'cloudflare-do';
      /**
       * Durable Object namespace binding (e.g. `env.THRESHOLD_STORE`).
       * Must point to a DO class compatible with the SDK's threshold store protocol.
       */
      namespace: CloudflareDurableObjectNamespaceLike;
      /**
       * Optional DO instance name. Defaults to `threshold-store`.
       * Use different names to isolate environments within the same Worker script.
       */
      name?: string;
    };

/**
 * Env-shaped input for threshold key store selection.
 * - Upstash REST (Cloudflare-friendly): UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN
 * - Redis TCP (Node-only): REDIS_URL
 */
export type ThresholdStoreEnvInput = {
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  REDIS_URL?: string;
  /** Node-only Postgres connection string for durable storage. */
  POSTGRES_URL?: string;
  /**
   * Optional global base prefix for all threshold keyspaces.
   *
   * When set, and the more specific `THRESHOLD_ED25519_*_PREFIX` variables are not set,
   * the SDK derives:
   * - `THRESHOLD_ED25519_WALLET_SESSION_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:wallet-session:`
   * - `THRESHOLD_ED25519_SESSION_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:sess:`
   * - `THRESHOLD_ED25519_KEYSTORE_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:key:`
   *
   * Trailing `:` is optional.
   */
  THRESHOLD_PREFIX?: string;
  THRESHOLD_ED25519_KEYSTORE_PREFIX?: string;
  THRESHOLD_ED25519_SESSION_PREFIX?: string;
  THRESHOLD_ED25519_WALLET_SESSION_PREFIX?: string;
  /**
   * Ed25519 relayer-share source mode. This remains Ed25519-specific because
   * it controls the Ed25519 threshold signing protocol, not the shared store.
   */
  THRESHOLD_ED25519_SHARE_MODE?: string;
  /**
   * Optional prefixes for threshold ECDSA key/session/Wallet Session storage.
   * Defaults derive from `THRESHOLD_PREFIX` with a `threshold-ecdsa:*` namespace when unset.
   */
  THRESHOLD_ECDSA_KEYSTORE_PREFIX?: string;
  THRESHOLD_ECDSA_SESSION_PREFIX?: string;
  THRESHOLD_ECDSA_WALLET_SESSION_PREFIX?: string;
  /**
   * Optional prefix for threshold ECDSA presignature pool storage.
   * Defaults derive from `THRESHOLD_PREFIX` with a `threshold-ecdsa:*` namespace when unset.
   */
  THRESHOLD_ECDSA_PRESIGN_PREFIX?: string;
  /**
   * Optional override for the client FROST participant identifier (u16, >= 1).
   * Must be distinct from `THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID`.
   */
  THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID?: string;
  /**
   * Optional override for the relayer FROST participant identifier (u16, >= 1).
   * Must be distinct from `THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID`.
   */
  THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID?: string;
  /**
   * Threshold node role.
   * - "coordinator" (default): exposes public registration/session routes and Router A/B bridge handlers.
   * - "cosigner": exposes internal relayer-fleet t-of-n cosigning endpoints when configured.
   */
  THRESHOLD_NODE_ROLE?: string;
  /**
   * 32-byte base64url shared secret used to authenticate coordinator→peer calls.
   *
   * When set, cosigner relayers can expose internal endpoints that accept
   * coordinator-signed grants (HMAC-SHA256).
   */
  THRESHOLD_COORDINATOR_SHARED_SECRET_B64U?: string;
  /**
   * Stable identifier for this coordinator instance.
   *
   * Used to pin Router A/B ECDSA-HSS pool-fill sessions to the instance that
   * created the live in-memory WASM session object.
   */
  THRESHOLD_COORDINATOR_INSTANCE_ID?: string;
  /**
   * Optional coordinator peer list (JSON) for cross-instance presign-step forwarding.
   *
   * Example:
   * `THRESHOLD_COORDINATOR_PEERS=[{"instanceId":"coordinator-a","relayerUrl":"https://relay-a.internal"},{"instanceId":"coordinator-b","relayerUrl":"https://relay-b.internal"}]`
   */
  THRESHOLD_COORDINATOR_PEERS?: string;
  /**
   * Optional relayer-fleet cosigner list (JSON) for internal t-of-n cosigning.
   *
   * When configured on a coordinator node, the coordinator can fan out to relayer cosigners
   * (internal-only nodes) and combine their partials into a single outer relayer signature share.
   *
   * Example:
   * `THRESHOLD_ED25519_RELAYER_COSIGNERS=[{"cosignerId":1,"relayerUrl":"https://cosigner-a.internal"},{"cosignerId":2,"relayerUrl":"https://cosigner-b.internal"},{"cosignerId":3,"relayerUrl":"https://cosigner-c.internal"}]`
   */
  THRESHOLD_ED25519_RELAYER_COSIGNERS?: string;
  /**
   * Internal relayer cosigner id for this node (u16, >= 1).
   * Required when running `THRESHOLD_NODE_ROLE=cosigner`.
   */
  THRESHOLD_ED25519_RELAYER_COSIGNER_ID?: string;
  /**
   * Internal relayer cosigner threshold `T` (integer, >= 1).
   * When set together with `THRESHOLD_ED25519_RELAYER_COSIGNERS`, the coordinator will wait for
   * `T` cosigners per signing round.
   */
  THRESHOLD_ED25519_RELAYER_COSIGNER_T?: string;
  /**
   * Optional Router A/B Ed25519 normal-signing SigningWorker id accepted by
   * threshold session policy. When unset, Router A/B normal-signing session
   * policy is rejected.
   */
  ROUTER_AB_NORMAL_SIGNING_WORKER_ID?: string;
  /**
   * Private Router A/B SigningWorker base URL used by the server-side
   * ECDSA-HSS presignature pool-fill bridge.
   */
  ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL?: string;
  /** Shared Router A/B SigningWorker base URL alias for local/dev wiring. */
  ROUTER_AB_SIGNING_WORKER_URL?: string;
  /** Local router-ab-dev SigningWorker URL alias. */
  SIGNING_WORKER_URL?: string;
  /** Secret value sent in `x-router-ab-internal-service-auth` to private workers. */
  ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET?: string;
  /** Token alias for `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET`. */
  ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN?: string;
  /** Optional signing session-seal key metadata and Shamir 3-pass parameters. */
  SIGNING_SESSION_SEAL_KEY_VERSION?: string;
  SIGNING_SESSION_SHAMIR_P_B64U?: string;
  SIGNING_SESSION_SEAL_E_S_B64U?: string;
  SIGNING_SESSION_SEAL_D_S_B64U?: string;
  /** Optional signing session-seal idempotency backend configuration. */
  SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS?: string;
  /**
   * Core signing-root dependency for active signing. Hosted deployments
   * usually build this from storage/decrypt adapters. Direct self-host
   * deployments can supply a resolver backed by imported signing-root shares.
   */
  signingRootShareResolver?: SigningRootShareResolver;
  signingRootShareResolverAdapters?: CreateHostedSigningRootShareResolverInput;
  signingRootSharePolicy?: ThresholdPrfPolicy;
  signingRootShareStore?: SigningRootShareSource;
  signingRootShareDecryptAdapter?: SigningRootShareDecryptAdapter;
};

/**
 * Threshold key store config input.
 *
 * Accepts either:
 * - an env-shaped object (for ergonomics in server examples), or
 * - an explicit `kind` object, optionally augmented with env-shaped overrides
 *   (useful when wiring via code but still wanting env vars like THRESHOLD_NODE_ROLE).
 */
export type ThresholdStoreConfigInput =
  | ThresholdStoreEnvInput
  | (ThresholdStoreConfig & Partial<ThresholdStoreEnvInput>);

export interface AuthServiceConfig {
  relayerAccount: string;
  relayerPrivateKey: string;
  nearRpcUrl: string;
  networkId: string;
  accountInitialBalance: string;
  createAccountAndRegisterGas: string;
  signerWasm?: SignerWasmConfig;
  /**
   * Optional persistence for relayer-held threshold signing shares.
   * Defaults to in-memory unless env-shaped config enables Redis/Upstash.
   */
  thresholdStore?: ThresholdStoreConfigInput;
  /**
   * Optional logger. When unset, the server SDK is silent (no `console.*`).
   * Pass `logger: console` to enable default logging.
   */
  logger?: Logger | null;
  /**
   * Optional Google OIDC configuration for verifying Google `id_token` login sessions.
   */
  googleOidc?: GoogleOidcConfig;
  /**
   * Optional generic OIDC JWT exchange configuration for `POST /session/exchange`.
   */
  oidcExchange?: OidcExchangeConfig;
}

export type GoogleOidcConfig = {
  /** Allowed OAuth client ids (audiences) for Google ID tokens. */
  clientIds: string[];
  /** Optional hosted domain allowlist (the `hd` claim). */
  hostedDomains?: string[];
};

export interface GoogleOidcConfigEnvInput {
  /** Single client id convenience. */
  GOOGLE_OIDC_CLIENT_ID?: string;
  /** Comma-separated client ids. */
  GOOGLE_OIDC_CLIENT_IDS?: string;
  /** Optional comma-separated hosted domains (`hd` claim). */
  GOOGLE_OIDC_HOSTED_DOMAINS?: string;
}

export type GoogleOidcConfigInput = GoogleOidcConfig | GoogleOidcConfigEnvInput;

export type OidcExchangeIssuerConfig = {
  /** Exact issuer (`iss`) value to trust. */
  issuer: string;
  /** Allowed audiences (`aud`) for this issuer. */
  audiences: string[];
  /** JWKS endpoint used to verify JWT signatures for this issuer. */
  jwksUrl: string;
  /**
   * Optional stable subject prefix for internal identity mapping.
   * Defaults to `oidc:{issuer}:`.
   */
  subjectPrefix?: string;
};

export type OidcExchangeConfig = {
  issuers: OidcExchangeIssuerConfig[];
  /**
   * Allowed JWT clock skew in seconds for `iat`/`nbf`/`exp` checks.
   * Defaults to 60 seconds.
   */
  clockSkewSec?: number;
};

export type OidcExchangeConfigInput = OidcExchangeConfig;

/**
 * User-facing input shape for `AuthService`. Fields that have SDK defaults are optional here.
 *
 * Defaults are applied by `createAuthServiceConfig(...)` and by `new AuthService(...)`.
 */
export type AuthServiceConfigInput = Omit<
  AuthServiceConfig,
  | 'nearRpcUrl'
  | 'networkId'
  | 'accountInitialBalance'
  | 'createAccountAndRegisterGas'
  | 'thresholdStore'
  | 'googleOidc'
  | 'oidcExchange'
> & {
  nearRpcUrl?: string;
  networkId?: string;
  accountInitialBalance?: string;
  createAccountAndRegisterGas?: string;
  thresholdStore?: ThresholdStoreConfigInput;
  googleOidc?: GoogleOidcConfigInput;
  oidcExchange?: OidcExchangeConfigInput;
};

// Account creation and registration types (imported from relay-server types)
export interface AccountCreationRequest {
  accountId: string;
  publicKey: string;
  recoveryPublicKey?: string;
}

export interface AccountCreationResult {
  success: boolean;
  transactionHash?: string;
  accountId?: string;
  error?: string;
  message?: string;
}

// Runtime-tested NEAR error types
export interface NearActionErrorKind {
  AccountAlreadyExists?: {
    accountId: string;
  };
  AccountDoesNotExist?: {
    account_id: string;
  };
  InsufficientStake?: {
    account_id: string;
    stake: string;
    minimum_stake: string;
  };
  LackBalanceForState?: {
    account_id: string;
    balance: string;
  };
  [key: string]: any;
}

export interface NearActionError {
  kind: NearActionErrorKind;
  index: string;
}

export interface NearExecutionFailure {
  ActionError?: NearActionError;
  [key: string]: any;
}

export interface NearReceiptStatus {
  SuccessValue?: string;
  SuccessReceiptId?: string;
  Failure?: NearExecutionFailure;
}

export interface NearReceiptOutcomeWithId {
  id: string;
  outcome: {
    logs: string[];
    receipt_ids: string[];
    gas_burnt: number;
    tokens_burnt: string;
    executor_id: string;
    status: NearReceiptStatus;
  };
}

// Re-export authenticator types from core
export type { AuthenticatorOptions, UserVerificationPolicy, OriginPolicyInput };

export interface WebAuthnAuthenticationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string; // base64url-encoded
    authenticatorData: string; // base64url-encoded
    signature: string; // base64url-encoded
    userHandle: string | null; // base64url-encoded or null
  };
  clientExtensionResults: any | null;
}

export interface VerifyAuthenticationResponse {
  success: boolean;
  verified?: boolean;
  jwt?: string;
  sessionCredential?: any;
  // Unified error model
  code?: string;
  message?: string;
  contractResponse?: any;
}

// ================================
// Threshold Ed25519 (2-party) APIs
// ================================

export type ThresholdRuntimePolicyScope = RuntimePolicyScope;

export type ThresholdEcdsaSigningRootMetadata = {
  signingRootId: string;
  signingRootVersion?: string;
  walletKeyVersion: string;
  derivationVersion: number;
};

export type ThresholdRuntimeSnapshotExpectation = {
  snapshotId?: string;
  version?: number;
  checksum?: string;
};

export type ThresholdEd25519Purpose = 'near_tx' | 'nep461_delegate' | 'nep413' | string;

export type Ed25519SessionPolicy = {
  version: 'threshold_session_v1';
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
  rpId: string;
  relayerKeyId: string;
  thresholdSessionId: string;
  signingGrantId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export interface ThresholdEd25519SessionRequest {
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  runtimeEnvironmentId?: string;
  webauthn_authentication?: WebAuthnAuthenticationCredential;
  expected_origin: string;
  appSessionClaims?: Record<string, unknown>;
  ecdsaSessionClaims?: Record<string, unknown>;
  sessionKind?: 'jwt';
}

export interface ThresholdEd25519SessionResponse {
  ok: boolean;
  code?: string;
  message?: string;
  walletId?: string;
  nearAccountId?: string;
  ed25519KeyScopeId?: string;
  thresholdSessionId?: string;
  signingGrantId?: string;
  /** Server-enforced expiry (ms since epoch). */
  expiresAtMs?: number;
  expiresAt?: string;
  /** Signer-set binding (sorted unique participant ids) when available. */
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  jwt?: string;
}

// ==========================================
// Threshold Ed25519 cosign continuation payloads
// ==========================================

export interface ThresholdEd25519CosignInitRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  /**
   * Base64url-encoded 32-byte relayer cosigner signing share (a secret share; unweighted).
   * The cosigner derives its effective outer-protocol share from this and the selected cosigner set.
   */
  cosignerShareB64u: string;
  clientCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerCommitments?: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignFinalizeRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  /**
   * The selected cosigner id set used for internal Lagrange interpolation.
   * Must include this cosigner's configured id.
   */
  cosignerIds: number[];
  /** NEAR ed25519 public key string (`ed25519:<base58>`). */
  groupPublicKey: string;
  /**
   * The combined outer-protocol relayer commitments (sum across the selected cosigners).
   * This must match what the client used for its signing transcript.
   */
  relayerCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerSignatureShareB64u?: string;
}

// ================================
// Threshold ECDSA (2-party) APIs
// ================================

export type ThresholdEcdsaPurpose = string;
export type EcdsaThresholdKeyId = string;
export type ThresholdEcdsaChainTarget =
  import('./thresholdEcdsaChainTarget').ThresholdEcdsaChainTarget;

export interface EcdsaKeyFactsInventoryPolicy {
  permission: 'ecdsa_key_facts_inventory';
  walletId: WalletId;
  chainTargets: ThresholdEcdsaChainTarget[];
  runtimePolicyScope?: RuntimePolicyScope;
  expiresAtMs: number;
}

export type WalletKeyFactsInventoryAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
      serverNonceB64u: string;
      runtimePolicyScope?: RuntimePolicyScope;
    }
  | {
      kind: 'app_session';
      policy: EcdsaKeyFactsInventoryPolicy;
    };

export interface ThresholdEcdsaHssFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  sessionKind?: 'jwt';
  sessionAuthTokenUserId?: string;
  sessionAuthTokenRpId?: string;
  keyHandle?: string;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
  participantIds?: number[];
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  chainId?: number;
  thresholdSessionId?: string;
  signingGrantId?: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  expiresAtMs?: number;
  expiresAt?: string;
  remainingUses?: number;
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
  canonicalPublicKeyHex?: string;
  privateKeyHex?: string;
  canonicalEthereumAddress?: string;
}

export type EcdsaHssErrorCode =
  | 'invalid_body'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'stale_state'
  | 'relayer_key_mismatch'
  | 'context_mismatch'
  | 'public_key_invalid'
  | 'identity_mismatch'
  | 'zero_canonical_key'
  | 'export_authorization_invalid'
  | 'export_authorization_expired'
  | 'export_nonce_replay'
  | 'presign_session_invalid'
  | 'presign_session_burned'
  | 'pool_empty'
  | 'internal';

export type EcdsaHssRouteResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: EcdsaHssErrorCode; message: string; retryAfterMs?: number };

export type EcdsaHssRoleLocalFormatVersion = 'ecdsa-hss-role-local';
export type EcdsaHssRoleLocalExportFormatVersion = 'ecdsa-hss-role-local-export';
export type EcdsaHssKeyScope = 'evm-family';

export interface EcdsaHssPublicIdentity {
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
}

export interface EcdsaHssCaitSithInput {
  participantId: 1 | 2;
  mappedPrivateShare32B64u: string;
  verifyingShare33B64u: string;
}

export interface EcdsaHssClientRootProof {
  version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2';
  clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  digest32B64u: string;
  signature65B64u: string;
}

export interface EcdsaHssPasskeyBootstrapAuthorization {
  kind: 'passkey_bootstrap';
  rpId: string;
  webauthn_authentication: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: RuntimePolicyScope;
  runtimeEnvironmentId?: string;
}

interface EcdsaHssClientBootstrapRequestBase {
  formatVersion: EcdsaHssRoleLocalFormatVersion;
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: EcdsaHssKeyScope;
  relayerKeyId: string;
  registrationPreparationId?: RegistrationPreparationId;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  sessionKind?: 'jwt';
  runtimePolicyScope?: RuntimePolicyScope;
}

export type EcdsaHssClientBootstrapRequest =
  | (EcdsaHssClientBootstrapRequestBase & {
      clientRootProof: EcdsaHssClientRootProof;
      passkeyBootstrapAuthorization?: never;
    })
  | (EcdsaHssClientBootstrapRequestBase & {
      clientRootProof?: never;
      passkeyBootstrapAuthorization: EcdsaHssPasskeyBootstrapAuthorization;
    })
  | (EcdsaHssClientBootstrapRequestBase & {
      clientRootProof?: never;
      passkeyBootstrapAuthorization?: never;
    });

export interface EcdsaHssServerBootstrapResponse {
  formatVersion: EcdsaHssRoleLocalFormatVersion;
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  applicationBindingDigestB64u: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssPublicIdentity;
  clientShareRetryCounter: number;
  relayerShareRetryCounter: number;
  publicTranscriptDigest32B64u: string;
  keyHandle: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  expiresAt: string;
  remainingUses: number;
  jwt?: string;
}

export interface EcdsaHssRoleLocalKeyRecord {
  version: 'threshold_ecdsa_hss_role_local_v2';
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  keyHandle: string;
  walletId: string;
  walletKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: EcdsaHssKeyScope;
  relayerKeyId: string;
  contextBinding32B64u: string;
  relayerShare32B64u: string;
  relayerPublicKey33B64u: string;
  clientPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
  relayerCaitSithInput: EcdsaHssCaitSithInput & { participantId: 2 };
  publicTranscriptDigest32B64u: string;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface EcdsaHssExportShareRequest {
  formatVersion: EcdsaHssRoleLocalExportFormatVersion;
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  authorizationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
}

export interface EcdsaHssExportShareResponse {
  formatVersion: EcdsaHssRoleLocalExportFormatVersion;
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssPublicIdentity;
  exportAuthorizationDigest32B64u: string;
  serverExportShare32B64u: string;
}

export type EcdsaSessionPolicy = {
  version: 'threshold_session_policy_v2';
  walletId: string;
  walletKeyId: string;
  relayerKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle?: string;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  thresholdSessionId: string;
  signingGrantId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export type ThresholdEcdsaBootstrapSessionPolicy = {
  version: 'threshold_session_policy_v2';
  walletId: string;
  walletKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle?: string;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  thresholdSessionId: string;
  signingGrantId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

// =====================================
// Router A/B ECDSA-HSS pool-fill routes
// =====================================

export type RouterAbEcdsaHssPoolFillInitRequest = {
  keyHandle?: string;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  /**
   * Number of presignatures to generate.
   * v1 supports only `1` (single presignature session).
   */
  count?: number;
  /**
   * Optional client-provided request classification for logging/observability.
   * Example: `background_presign_pool_refill`.
   */
  requestTag?: string;
  poolFill: {
    kind: 'router_ab_ecdsa_hss_signing_worker_pool';
    scope: RouterAbEcdsaHssNormalSigningScopeV1;
    expiresAtMs: number;
  };
};

export type RouterAbEcdsaHssPoolFillInitResponse = {
  ok: boolean;
  code?: string;
  message?: string;
  presignSessionId?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  outgoingMessagesB64u?: string[];
};

export type RouterAbEcdsaHssPoolFillStepRequest = {
  presignSessionId: string;
  /**
   * The client-requested stage transition:
   * - `triples`: continue triple generation
   * - `presign`: start/continue presigning (only valid once server is `triples_done`)
   */
  stage: 'triples' | 'presign';
  outgoingMessagesB64u?: string[];
  /**
   * Optional client-provided request classification for logging/observability.
   * Example: `background_presign_pool_refill`.
   */
  requestTag?: string;
};

export type RouterAbEcdsaHssPoolFillStepResponse = {
  ok: boolean;
  code?: string;
  message?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  event?: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u?: string[];
  /** Deterministic id derived from `bigR` (only present when `event==='presign_done'`). */
  presignatureId?: string;
  /** Base64url-encoded compressed secp256k1 point (33 bytes) for `R` (only present when `event==='presign_done'`). */
  bigRB64u?: string;
};

// =======================================
// Threshold ECDSA cosign continuation payloads
// =======================================

export interface ThresholdEcdsaCosignInitRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  cosignerShareB64u: string;
  clientRound1?: unknown;
}

export interface ThresholdEcdsaCosignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound1?: unknown;
}

export interface ThresholdEcdsaCosignFinalizeRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  cosignerIds: number[];
  groupPublicKey: string;
  relayerRound1?: unknown;
}

export interface ThresholdEcdsaCosignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound2?: unknown;
}

export interface RefreshSessionResult {
  ok: boolean;
  jwt?: string;
  code?: string;
  message?: string;
}
