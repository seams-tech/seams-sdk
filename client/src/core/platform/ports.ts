
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types/webauthn';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '../signingEngine/interfaces/ecdsaChainTarget';
import type { RpId } from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaThresholdKeyId,
  EmailOtpAuthSubjectId,
  SigningRootId,
  SigningRootVersion,
} from '../signingEngine/session/identity/emailOtpHssIdentity';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type {
  BuildEcdsaRoleLocalExportArtifactCommand as GeneratedBuildEcdsaRoleLocalExportArtifactCommand,
  BuildEcdsaRoleLocalExportArtifactErrorCode as GeneratedBuildEcdsaRoleLocalExportArtifactErrorCode,
  BuildEcdsaRoleLocalExportArtifactOutput as GeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  FinalizeEcdsaClientBootstrapCommand as GeneratedFinalizeEcdsaClientBootstrapCommand,
  FinalizeEcdsaClientBootstrapErrorCode as GeneratedFinalizeEcdsaClientBootstrapErrorCode,
  FinalizeEcdsaClientBootstrapOutput as GeneratedFinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapCommand as GeneratedPrepareEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapErrorCode as GeneratedPrepareEcdsaClientBootstrapErrorCode,
  PrepareEcdsaClientBootstrapOutput as GeneratedPrepareEcdsaClientBootstrapOutput,
} from './generated/signerCoreCommands';
import type { ThresholdRuntimePolicyScope } from '../signingEngine/threshold/sessionPolicy';
import type { PlatformResult } from './http';
import type {
  CleanupMalformedEcdsaRoleLocalRecordInput,
  CleanupMalformedEcdsaRoleLocalRecordResult,
  CredentialIdB64u,
  EcdsaGroupPublicKey33B64u,
  EcdsaRoleLocalAuthMethod,
  EcdsaRoleLocalPendingStateBlob,
  EcdsaRoleLocalPublicFacts,
  EcdsaRoleLocalReadyRecord,
  EcdsaRoleLocalReadyStateBlob,
  LoadEcdsaRoleLocalReadyRecordInput,
  LoadEcdsaRoleLocalReadyRecordResult,
  PersistEcdsaRoleLocalReadyRecordInput,
  PersistEcdsaRoleLocalReadyRecordResult,
  RelayerKeyId,
} from './ecdsaRoleLocalRecords';
import type { EcdsaBootstrapSecretSource } from './secretSources';

export type SignerCryptoInvocationErrorCode =
  | 'unavailable'
  | 'worker_transport_failure'
  | 'native_binding_failure'
  | 'timeout';

export type SignerCryptoResult<Ok, CommandCode extends string> =
  | {
      ok: true;
      value: Ok;
      failure?: never;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      failure: 'command';
      code: CommandCode;
      message: string;
      value?: never;
    }
  | {
      ok: false;
      failure: 'invocation';
      code: SignerCryptoInvocationErrorCode;
      message: string;
      value?: never;
    };

export type DurableRecordStore = {
  kind: 'durable_record_store';
  loadEcdsaRoleLocalReadyRecord(
    input: LoadEcdsaRoleLocalReadyRecordInput,
  ): Promise<LoadEcdsaRoleLocalReadyRecordResult>;
  persistEcdsaRoleLocalReadyRecord(
    input: PersistEcdsaRoleLocalReadyRecordInput,
  ): Promise<PersistEcdsaRoleLocalReadyRecordResult>;
  cleanupMalformedEcdsaRoleLocalRecord(
    input: CleanupMalformedEcdsaRoleLocalRecordInput,
  ): Promise<CleanupMalformedEcdsaRoleLocalRecordResult>;
};

export type SecureSecretStore = {
  kind: 'secure_secret_store';
  seal(input: {
    purpose: string;
    secretB64u: string;
  }): Promise<PlatformResult<{ handle: string }, 'unavailable'>>;
  unseal(input: {
    handle: string;
  }): Promise<PlatformResult<{ secretB64u: string }, 'unavailable' | 'not_found'>>;
  delete(input: { handle: string }): Promise<PlatformResult<void, 'unavailable'>>;
};


export type AuthenticatorOptions = {
  userVerification?: 'required' | 'preferred' | 'discouraged';
  timeoutMs?: number;
};

export type AuthenticatorOperation =
  | {
      kind: 'create_passkey';
      rpId: RpId;
      userHandleB64u: string;
      challengeB64u: string;
      requirePrfFirst: true;
      authenticatorOptions?: AuthenticatorOptions;
    }
  | {
      kind: 'create_passkey';
      rpId: RpId;
      userHandleB64u: string;
      challengeB64u: string;
      requirePrfFirst: false;
      authenticatorOptions?: AuthenticatorOptions;
    }
  | {
      kind: 'get_passkey';
      rpId: RpId;
      credentialIdB64u: string;
      challengeB64u: string;
      requirePrfFirst: true;
    }
  | {
      kind: 'get_passkey';
      rpId: RpId;
      credentialIdB64u: string;
      challengeB64u: string;
      requirePrfFirst: false;
    };

export type AuthenticatorResult =
  | {
      ok: true;
      operation: 'create_passkey';
      requirePrfFirst: true;
      credential: WebAuthnRegistrationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      rpId: RpId;
      prf: {
        kind: 'required';
        prfFirstB64u: string;
      };
    }
  | {
      ok: true;
      operation: 'create_passkey';
      requirePrfFirst: false;
      credential: WebAuthnRegistrationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      rpId: RpId;
      prf:
        | {
            kind: 'available_without_requirement';
            prfFirstB64u: string;
          }
        | {
            kind: 'not_requested_or_unavailable';
            prfFirstB64u?: never;
          };
    }
  | {
      ok: true;
      operation: 'get_passkey';
      requirePrfFirst: true;
      credential: WebAuthnAuthenticationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      rpId: RpId;
      prf: {
        kind: 'required';
        prfFirstB64u: string;
      };
    }
  | {
      ok: true;
      operation: 'get_passkey';
      requirePrfFirst: false;
      credential: WebAuthnAuthenticationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      rpId: RpId;
      prf:
        | {
            kind: 'available_without_requirement';
            prfFirstB64u: string;
          }
        | {
            kind: 'not_requested_or_unavailable';
            prfFirstB64u?: never;
          };
    }
  | {
      ok: false;
      code:
        | 'unavailable'
        | 'cancelled'
        | 'not_allowed'
        | 'prf_unavailable'
        | 'invalid_credential'
        | 'platform_error';
      message: string;
    };

export type RequiredPrfAuthenticatorSuccess = Extract<
  AuthenticatorResult,
  { ok: true; requirePrfFirst: true }
>;

export type AuthenticatorPort = {
  kind: 'authenticator';
  run(operation: AuthenticatorOperation): Promise<AuthenticatorResult>;
};

export type PrepareEcdsaClientBootstrapInput = {
  kind: GeneratedPrepareEcdsaClientBootstrapCommand['kind'];
  algorithm: GeneratedPrepareEcdsaClientBootstrapCommand['algorithm'];
  context: {
    walletId: WalletId;
    rpId: RpId;
    chainTarget: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: SigningRootId;
    signingRootVersion: SigningRootVersion;
    keyPurpose: GeneratedPrepareEcdsaClientBootstrapCommand['context']['keyPurpose'];
    keyVersion: GeneratedPrepareEcdsaClientBootstrapCommand['context']['keyVersion'];
  };
  participants: {
    clientParticipantId: 1;
    relayerParticipantId: 2;
    participantIds: readonly [1, 2];
  };
  secretSource: EcdsaBootstrapSecretSource;
};

export type EcdsaClientBootstrapFacts = {
  contextBinding32B64u: GeneratedPrepareEcdsaClientBootstrapOutput['clientBootstrap']['contextBinding32B64u'];
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientShareRetryCounter: GeneratedPrepareEcdsaClientBootstrapOutput['clientBootstrap']['clientShareRetryCounter'];
  participantId: 1;
};

export type EcdsaPreparePublicFacts = {
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientVerifyingShareB64u: GeneratedPrepareEcdsaClientBootstrapOutput['publicFacts']['clientVerifyingShareB64u'];
};

export type EcdsaRelayerPublicIdentity = {
  relayerKeyId: RelayerKeyId;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: EcdsaGroupPublicKey33B64u;
  ethereumAddress: `0x${string}`;
};

export type EcdsaProvisioningFailureCode =
  | 'authenticator_failed'
  | 'signer_crypto_command_failed'
  | 'signer_crypto_invocation_failed'
  | 'relayer_failed'
  | 'storage_failed'
  | 'invalid_state';

export type RelayerResult<Ok, Code extends string> =
  | {
      ok: true;
      value: Ok;
      code?: never;
      message?: never;
      retryable?: never;
      status?: never;
    }
  | {
      ok: false;
      code: Code;
      message: string;
      retryable: boolean;
      status?: number;
      value?: never;
    };

export type EcdsaBootstrapRouteAuth =
  | {
      kind: 'app_session';
      jwt: string;
      token?: never;
    }
  | {
      kind: 'threshold_session';
      jwt: string;
      token?: never;
    }
  | {
      kind: 'cookie';
      jwt?: never;
      token?: never;
    }
  | {
      kind: 'bootstrap_grant';
      token: string;
      jwt?: never;
    }
  | {
      kind: 'publishable_key';
      token: string;
      jwt?: never;
    };

export type BootstrapEcdsaSessionRouteInput = {
  kind: 'bootstrap_ecdsa_session_route_v1';
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyScope: 'evm-family';
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  relayerKeyId: RelayerKeyId;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  ttlMs: number;
  remainingUses: number;
  sessionKind: 'jwt' | 'cookie';
  participantIds: readonly [1, 2];
  auth: EcdsaBootstrapRouteAuth;
  clientBootstrap: EcdsaClientBootstrapFacts;
  preparePublicFacts: EcdsaPreparePublicFacts;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type BootstrapEcdsaSessionRouteOutput = {
  kind: 'bootstrap_ecdsa_session_route_output_v1';
  walletId: WalletId;
  rpId: RpId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  keyHandle: string;
  relayerPublicIdentity: EcdsaRelayerPublicIdentity;
  participantIds: readonly [1, 2];
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  thresholdSessionAuthToken: string;
};

export type BootstrapEcdsaSessionRouteFailureCode =
  | 'unavailable'
  | 'request_rejected'
  | 'malformed_response';

export type PrepareEcdsaClientBootstrapOutput = {
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  clientBootstrap: EcdsaClientBootstrapFacts;
  publicFacts: EcdsaPreparePublicFacts;
};

export type FinalizeEcdsaClientBootstrapInput = {
  kind: GeneratedFinalizeEcdsaClientBootstrapCommand['kind'];
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  relayerPublicIdentity: {
    relayerKeyId: string;
    relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
    groupPublicKey33B64u: string;
    ethereumAddress: `0x${string}`;
  };
};

export type FinalizeEcdsaClientBootstrapOutput = {
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: {
    contextBinding32B64u: GeneratedFinalizeEcdsaClientBootstrapOutput['publicFacts']['contextBinding32B64u'];
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientVerifyingShareB64u: GeneratedFinalizeEcdsaClientBootstrapOutput['publicFacts']['clientVerifyingShareB64u'];
    relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
    groupPublicKey33B64u: GeneratedFinalizeEcdsaClientBootstrapOutput['publicFacts']['groupPublicKey33B64u'];
    ethereumAddress: `0x${string}`;
  };
};

export type PrepareEcdsaClientBootstrapErrorCode = GeneratedPrepareEcdsaClientBootstrapErrorCode;

export type FinalizeEcdsaClientBootstrapErrorCode = GeneratedFinalizeEcdsaClientBootstrapErrorCode;

export type BuildEcdsaRoleLocalExportArtifactAuthorization =
  | {
      kind: 'passkey_export_authorized';
      walletId: WalletId;
      rpId: RpId;
      credentialIdB64u: CredentialIdB64u;
      authSubjectId?: never;
    }
  | {
      kind: 'email_otp_export_authorized';
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      credentialIdB64u?: never;
    };

export type BuildEcdsaRoleLocalExportArtifactInput = {
  kind: GeneratedBuildEcdsaRoleLocalExportArtifactCommand['kind'];
  algorithm: GeneratedBuildEcdsaRoleLocalExportArtifactCommand['algorithm'];
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
  authorization: BuildEcdsaRoleLocalExportArtifactAuthorization;
  serverExportShare32B64u: GeneratedBuildEcdsaRoleLocalExportArtifactCommand['serverExportShare32B64u'];
};

export type BuildEcdsaRoleLocalExportArtifactOutput = {
  publicKeyHex: GeneratedBuildEcdsaRoleLocalExportArtifactOutput['publicKeyHex'];
  privateKeyHex: GeneratedBuildEcdsaRoleLocalExportArtifactOutput['privateKeyHex'];
  ethereumAddress: `0x${string}`;
};

export type BuildEcdsaRoleLocalExportArtifactErrorCode =
  GeneratedBuildEcdsaRoleLocalExportArtifactErrorCode;

export type EcdsaRelayerClient = {
  bootstrapEcdsaSession(
    input: BootstrapEcdsaSessionRouteInput,
  ): Promise<
    RelayerResult<BootstrapEcdsaSessionRouteOutput, BootstrapEcdsaSessionRouteFailureCode>
  >;
};

export type EcdsaProvisioningState =
  | {
      kind: 'needs_secret_source';
      walletId: WalletId;
      rpId: RpId;
      chainTarget: ThresholdEcdsaChainTarget;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      signingRootId: SigningRootId;
      signingRootVersion: SigningRootVersion;
      authMethod: EcdsaRoleLocalAuthMethod;
    }
  | {
      kind: 'preparing_client_bootstrap';
      input: PrepareEcdsaClientBootstrapInput;
      storageKeyFacts: LoadEcdsaRoleLocalReadyRecordInput;
    }
  | {
      kind: 'awaiting_relayer_identity';
      pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
      clientBootstrap: EcdsaClientBootstrapFacts;
      preparePublicFacts: EcdsaPreparePublicFacts;
      storageKeyFacts: LoadEcdsaRoleLocalReadyRecordInput;
    }
  | {
      kind: 'finalizing_ready_state';
      pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
      relayerPublicIdentity: EcdsaRelayerPublicIdentity;
      storageKeyFacts: LoadEcdsaRoleLocalReadyRecordInput;
    }
  | {
      kind: 'persisting_ready_record';
      record: EcdsaRoleLocalReadyRecord;
      storageKeyFacts: LoadEcdsaRoleLocalReadyRecordInput;
    }
  | {
      kind: 'ready';
      record: EcdsaRoleLocalReadyRecord;
      storageKeyFacts?: never;
    }
  | {
      kind: 'failed';
      code: EcdsaProvisioningFailureCode;
      message: string;
      retryable: boolean;
      record?: never;
      storageKeyFacts?: never;
    };

export type SignerCryptoPort = {
  kind: 'signer_crypto';
  prepareEcdsaClientBootstrap(
    input: PrepareEcdsaClientBootstrapInput,
  ): Promise<
    SignerCryptoResult<PrepareEcdsaClientBootstrapOutput, PrepareEcdsaClientBootstrapErrorCode>
  >;
  finalizeEcdsaClientBootstrap(
    input: FinalizeEcdsaClientBootstrapInput,
  ): Promise<
    SignerCryptoResult<FinalizeEcdsaClientBootstrapOutput, FinalizeEcdsaClientBootstrapErrorCode>
  >;
  buildEcdsaRoleLocalExportArtifact(
    input: BuildEcdsaRoleLocalExportArtifactInput,
  ): Promise<
    SignerCryptoResult<
      BuildEcdsaRoleLocalExportArtifactOutput,
      BuildEcdsaRoleLocalExportArtifactErrorCode
    >
  >;
};
