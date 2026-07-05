import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { EcdsaHssClientSharePublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
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
  RegistrationSignerSetSelection,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletAuthMethodTarget,
  WalletId,
} from '@shared/utils/registrationIntent';
import type {
  EcdsaHssKeyScope,
  EcdsaHssRoleLocalFormatVersion,
  EcdsaHssServerBootstrapResponse,
  EcdsaThresholdKeyId,
  Ed25519SessionPolicy,
  ThresholdEcdsaChainTarget,
  ThresholdEd25519AuthorityScope,
  ThresholdEd25519BootstrapSession,
  ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  WebAuthnAuthenticationCredential,
  RegistrationPreparationId,
} from './types';
import {
  registrationPreparationIdFromString
} from './types';

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
    clientBootstraps: {
      chainTarget: ThresholdEcdsaChainTarget;
      clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
    }[];
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
        bootstraps: {
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: EcdsaHssServerBootstrapResponse;
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
      rpId?: string;
      ed25519?: {
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        publicKey: string;
        relayerKeyId: string;
        keyVersion: string;
        recoveryExportCapable: true;
        clientParticipantId?: number;
        relayerParticipantId?: number;
        participantIds?: number[];
        session?: ThresholdEd25519BootstrapSession;
        registrationWorkerMaterialReport: ThresholdEd25519RegistrationWorkerMaterialReport;
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
  authority: WalletRegistrationStartAuthority;
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
  formatVersion: EcdsaHssRoleLocalFormatVersion;
  walletId: string;
  evmFamilySigningKeySlotId: string;
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

export type WalletRegistrationEcdsaPrepareTarget = {
  chainTarget: ThresholdEcdsaChainTarget;
  prepare: WalletRegistrationEcdsaPrepareContext;
};

export type WalletRegistrationEcdsaPreparePayload = {
  kind: 'evm_family_ecdsa_keygen';
  targets: WalletRegistrationEcdsaPrepareTarget[];
};

export type WalletRegistrationEcdsaClientBootstrap = {
  formatVersion: EcdsaHssRoleLocalFormatVersion;
  walletId: string;
  evmFamilySigningKeySlotId: string;
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
    clientBootstraps: {
      chainTarget: ThresholdEcdsaChainTarget;
      clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
    }[];
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
        bootstraps: {
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: EcdsaHssServerBootstrapResponse;
        }[];
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

export type ThresholdEd25519RegistrationWorkerMaterialReport = {
  kind: 'threshold_ed25519_registration_worker_material_report_v1';
  contextBindingB64u: string;
  clientOutputMessageB64u: string;
  seedOutputMessageB64u?: never;
};

export type WalletRegistrationFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      rpId?: string;
      authority: WalletAuthAuthority;
      authorityScope: ThresholdEd25519AuthorityScope;
      authMethod: WalletRegistrationFinalizeAuthMethod;
      accountProvisioning: RegistrationNearAccountProvisioning;
      resolvedAccount: ResolvedRegistrationNearAccount;
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      ed25519: {
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        publicKey: string;
        relayerKeyId: string;
        keyVersion: string;
        recoveryExportCapable: true;
        clientParticipantId?: number;
        relayerParticipantId?: number;
        participantIds?: number[];
        session?: ThresholdEd25519BootstrapSession;
        registrationWorkerMaterialReport: ThresholdEd25519RegistrationWorkerMaterialReport;
      };
      ecdsa?: {
        walletKeys: WalletRegistrationEcdsaWalletKey[];
      };
    }
  | {
      ok: true;
      walletId: WalletId;
      rpId?: string;
      authority: WalletAuthAuthority;
      authMethod: WalletRegistrationFinalizeAuthMethod;
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
      rpId?: string;
      reason: 'replay_without_session_material';
      registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
      authMethod?: never;
      ed25519?: never;
      ecdsa?: never;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };
