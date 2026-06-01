import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types/webauthn';
import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '../signingEngine/interfaces/ecdsaChainTarget';
import { toRpId, type RpId } from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEmailOtpAuthSubjectId,
  type EcdsaThresholdKeyId,
  type EmailOtpAuthSubjectId,
  type SigningRootId,
  type SigningRootVersion,
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

export type PlatformKind = 'browser' | 'ios' | 'linux_embedded';

export type PlatformResult<Ok, Code extends string> =
  | {
      ok: true;
      value: Ok;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      code: Code;
      message: string;
      value?: never;
    };

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

export type CredentialIdB64u = string & { readonly __brand: 'CredentialIdB64u' };
export type EcdsaGroupPublicKey33B64u = string & {
  readonly __brand: 'EcdsaGroupPublicKey33B64u';
};
export type RelayerKeyId = string & { readonly __brand: 'RelayerKeyId' };

export type EcdsaRoleLocalPendingStateBlob = {
  kind: 'ecdsa_role_local_pending_state_blob_v1';
  curve: 'secp256k1';
  encoding: 'base64url';
  producer: 'signer_core';
  stateBlobB64u: string;
};

export type EcdsaRoleLocalReadyStateBlob = {
  kind: 'ecdsa_role_local_state_blob_v1';
  curve: 'secp256k1';
  encoding: 'base64url';
  producer: 'signer_core';
  stateBlobB64u: string;
};

export type EcdsaRoleLocalPublicFacts = {
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  clientParticipantId: 1;
  relayerParticipantId: 2;
  participantIds: readonly [1, 2];
  contextBinding32B64u: string;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: EcdsaGroupPublicKey33B64u;
  ethereumAddress: `0x${string}`;
};

export type EcdsaRoleLocalAuthMethod =
  | {
      kind: 'passkey';
      credentialIdB64u: CredentialIdB64u;
      rpId: RpId;
      authSubjectId?: never;
    }
  | {
      kind: 'email_otp';
      authSubjectId: EmailOtpAuthSubjectId;
      credentialIdB64u?: never;
      rpId?: never;
    };

export type EcdsaRoleLocalReadyRecord =
  | {
      kind: 'ecdsa_role_local_ready_passkey_v1';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      publicFacts: EcdsaRoleLocalPublicFacts;
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'passkey' }>;
    }
  | {
      kind: 'ecdsa_role_local_ready_email_otp_v1';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      publicFacts: EcdsaRoleLocalPublicFacts;
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'email_otp' }>;
    };

export type EcdsaRoleLocalMaterialState =
  | {
      kind: 'ready';
      record: EcdsaRoleLocalReadyRecord;
      reauth?: never;
      cleanup?: never;
    }
  | {
      kind: 'reauth_required';
      walletId: WalletId;
      rpId: RpId;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      authMethod: EcdsaRoleLocalAuthMethod;
      reason: 'missing_session' | 'expired_session' | 'sealed_session_unavailable';
      record?: never;
      cleanup?: never;
    }
  | {
      kind: 'invalid_cleanup_required';
      cleanup: CleanupMalformedEcdsaRoleLocalRecordInput;
      reason: string;
      record?: never;
      reauth?: never;
    };

export type EcdsaRoleLocalEmailOtpWorkerShare = {
  kind: 'email_otp_worker_share';
  workerSessionId: string;
};

export type EcdsaRoleLocalReadyStateBlobSigningMaterial = {
  kind: 'role_local_ready_state_blob';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  workerSessionId?: never;
};

export type EcdsaRoleLocalSessionRecordState =
  | {
      kind: 'ready_passkey_role_local_material_v1';
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'passkey' }>;
      readyRecord: Extract<EcdsaRoleLocalReadyRecord, { authMethod: { kind: 'passkey' } }>;
      inlineSigningMaterial: EcdsaRoleLocalReadyStateBlobSigningMaterial;
      reauth?: never;
      cleanup?: never;
    }
  | {
      kind: 'ready_email_otp_role_local_material_v1';
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'email_otp' }>;
      readyRecord: Extract<EcdsaRoleLocalReadyRecord, { authMethod: { kind: 'email_otp' } }>;
      inlineSigningMaterial:
        | EcdsaRoleLocalEmailOtpWorkerShare
        | EcdsaRoleLocalReadyStateBlobSigningMaterial;
      reauth?: never;
      cleanup?: never;
    }
  | {
      kind: 'reauth_required_role_local_material_v1';
      authMethod: EcdsaRoleLocalAuthMethod;
      readyRecord: EcdsaRoleLocalReadyRecord;
      reason:
        | 'missing_worker_share'
        | 'expired'
        | 'exhausted'
        | 'unsupported_material_owner';
      inlineSigningMaterial?: never;
      cleanup?: never;
    }
  | {
      kind: 'cleanup_only_raw_role_local_record_v1';
      reason: 'malformed_record' | 'legacy_after_reset' | 'identity_mismatch';
      message: string;
      authMethod?: never;
      readyRecord?: never;
      inlineSigningMaterial?: never;
      reauth?: never;
    };

export type EcdsaRoleLocalRecordParseResult =
  | {
      ok: true;
      source: 'ready_record';
      state: Extract<EcdsaRoleLocalMaterialState, { kind: 'ready' | 'reauth_required' }>;
      code?: never;
      message?: never;
      cleanup?: never;
    }
  | {
      ok: false;
      code: 'malformed_record';
      message: string;
      cleanup: CleanupMalformedEcdsaRoleLocalRecordInput;
      source?: never;
      state?: never;
    };

export type LoadEcdsaRoleLocalReadyRecordInput = {
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly [1, 2];
  authMethod: EcdsaRoleLocalAuthMethod;
};

export type LoadEcdsaRoleLocalReadyRecordResult = PlatformResult<
  | { kind: 'found'; record: EcdsaRoleLocalReadyRecord }
  | { kind: 'not_found'; record?: never }
  | {
      kind: 'reauth_required';
      state: Extract<EcdsaRoleLocalMaterialState, { kind: 'reauth_required' }>;
      record?: never;
    }
  | {
      kind: 'malformed';
      cleanup: CleanupMalformedEcdsaRoleLocalRecordInput;
      message: string;
      record?: never;
    },
  'unavailable'
>;

export type PersistEcdsaRoleLocalReadyRecordInput = {
  record: EcdsaRoleLocalReadyRecord;
  storageKeyFacts: LoadEcdsaRoleLocalReadyRecordInput;
};

export type PersistEcdsaRoleLocalReadyRecordResult = PlatformResult<
  { kind: 'persisted' },
  'unavailable' | 'invalid_record'
>;

export type CleanupMalformedEcdsaRoleLocalRecordInput = LoadEcdsaRoleLocalReadyRecordInput & {
  reason: string;
};

export type CleanupMalformedEcdsaRoleLocalRecordResult = PlatformResult<
  { kind: 'deleted' } | { kind: 'not_found' },
  'unavailable'
>;

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

const clientSecretSourceBrand: unique symbol = Symbol('ClientSecretSource');
const emailOtpWorkerSessionHandleBrand: unique symbol = Symbol('EmailOtpWorkerSessionHandle');

type ClientSecretSourceBrand<Kind extends string> = {
  readonly [clientSecretSourceBrand]: Kind;
};

export type WebAuthnPrfFirstSecretSource = ClientSecretSourceBrand<'webauthn_prf_first'> & {
  kind: 'webauthn_prf_first';
  prfFirstB64u: string;
  rpId: RpId;
  credentialIdB64u: string;
};

export type SecureEnclaveWrappedSecretSource =
  ClientSecretSourceBrand<'secure_enclave_wrapped_secret'> & {
    kind: 'secure_enclave_wrapped_secret';
    keyId: string;
    accessGroup: string;
  };

export type Fido2HmacSecretSource = ClientSecretSourceBrand<'fido2_hmac_secret'> & {
  kind: 'fido2_hmac_secret';
  credentialIdB64u: string;
  rpId: RpId;
};

export type EmailOtpWorkerIssuedSessionHandle = {
  readonly [emailOtpWorkerSessionHandleBrand]: 'email_otp_worker_session_handle';
} & (
  | {
      kind: 'email_otp_worker_session_handle_v1';
      sessionId: string;
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ecdsa_bootstrap';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      chainTarget: ThresholdEcdsaChainTarget;
    }
  | {
      kind: 'email_otp_worker_session_handle_v1';
      sessionId: string;
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ed25519_session';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      chainTarget?: never;
    }
);

export type EmailOtpWorkerSessionSecretSource =
  ClientSecretSourceBrand<'email_otp_worker_session'> & {
    kind: 'email_otp_worker_session';
    handle: EmailOtpWorkerIssuedSessionHandle;
  };

export type EmailOtpWorkerIssuedSessionHandleInput =
  | {
      sessionId: string;
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ecdsa_bootstrap';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      chainTarget: ThresholdEcdsaChainTarget;
    }
  | {
      sessionId: string;
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ed25519_session';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      chainTarget?: never;
    };

export type ClientSecretSource =
  | WebAuthnPrfFirstSecretSource
  | SecureEnclaveWrappedSecretSource
  | Fido2HmacSecretSource
  | EmailOtpWorkerSessionSecretSource;

export type EcdsaBootstrapSecretSource = ClientSecretSource;

function requirePlatformString(value: string, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[platform] ${field} is required`);
  }
  return normalized;
}

function requirePlatformObject(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[platform] ${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function buildWebAuthnPrfFirstSecretSource(
  input: RequiredPrfAuthenticatorSuccess,
): WebAuthnPrfFirstSecretSource {
  return buildWebAuthnPrfFirstSecretSourceFromParts({
    prfFirstB64u: input.prf.prfFirstB64u,
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
  });
}

export function buildWebAuthnPrfFirstSecretSourceFromParts(input: {
  prfFirstB64u: string;
  rpId: RpId;
  credentialIdB64u: string;
}): WebAuthnPrfFirstSecretSource {
  return {
    kind: 'webauthn_prf_first',
    prfFirstB64u: requirePlatformString(input.prfFirstB64u, 'prfFirstB64u'),
    rpId: input.rpId,
    credentialIdB64u: requirePlatformString(input.credentialIdB64u, 'credentialIdB64u'),
    [clientSecretSourceBrand]: 'webauthn_prf_first',
  };
}

export function buildEmailOtpWorkerIssuedSessionHandle(
  input: EmailOtpWorkerIssuedSessionHandleInput,
): EmailOtpWorkerIssuedSessionHandle {
  const sessionId = requirePlatformString(input.sessionId, 'sessionId');
  const base = {
    kind: 'email_otp_worker_session_handle_v1' as const,
    sessionId,
    walletId: input.walletId,
    rpId: input.rpId,
    authSubjectId: input.authSubjectId,
    operation: input.operation,
  };
  switch (input.action) {
    case 'threshold_ecdsa_bootstrap':
      return {
        ...base,
        action: 'threshold_ecdsa_bootstrap',
        chainTarget: input.chainTarget,
        [emailOtpWorkerSessionHandleBrand]: 'email_otp_worker_session_handle',
      };
    case 'threshold_ed25519_session':
      return {
        ...base,
        action: 'threshold_ed25519_session',
        [emailOtpWorkerSessionHandleBrand]: 'email_otp_worker_session_handle',
      };
    default:
      return assertNeverPlatform(input);
  }
}

export function parseEmailOtpWorkerIssuedSessionHandle(
  input: unknown,
): EmailOtpWorkerIssuedSessionHandle {
  const payload = requirePlatformObject(input, 'email OTP worker-issued session handle');
  const kind = requirePlatformString(
    String(payload.kind || ''),
    'email OTP worker-issued handle kind',
  );
  if (kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(`[platform] unsupported email OTP worker-issued handle kind: ${kind}`);
  }
  const action = requirePlatformString(
    String(payload.action || ''),
    'email OTP worker-issued handle action',
  );
  const operation = requirePlatformString(
    String(payload.operation || ''),
    'email OTP worker-issued handle operation',
  );
  if (
    operation !== 'registration' &&
    operation !== 'wallet_unlock' &&
    operation !== 'sign' &&
    operation !== 'export'
  ) {
    throw new Error(
      `[platform] unsupported email OTP worker-issued handle operation: ${operation}`,
    );
  }
  const normalizedOperation: EmailOtpWorkerIssuedSessionHandleInput['operation'] = operation;
  const base = {
    sessionId: requirePlatformString(
      String(payload.sessionId || ''),
      'email OTP worker-issued handle sessionId',
    ),
    walletId: toWalletId(payload.walletId),
    rpId: toRpId(payload.rpId),
    authSubjectId: toEmailOtpAuthSubjectId(payload.authSubjectId),
    operation: normalizedOperation,
  };
  if (action === 'threshold_ecdsa_bootstrap') {
    return buildEmailOtpWorkerIssuedSessionHandle({
      ...base,
      action,
      chainTarget: thresholdEcdsaChainTargetFromRequest(
        requirePlatformObject(payload.chainTarget, 'email OTP worker-issued handle chainTarget'),
      ),
    });
  }
  if (action === 'threshold_ed25519_session') {
    if ('chainTarget' in payload) {
      throw new Error(
        '[platform] email OTP Ed25519 worker-issued handles cannot include chainTarget',
      );
    }
    return buildEmailOtpWorkerIssuedSessionHandle({
      ...base,
      action,
    });
  }
  throw new Error(`[platform] unsupported email OTP worker-issued handle action: ${action}`);
}

export function buildEmailOtpWorkerSessionSecretSource(
  handle: EmailOtpWorkerIssuedSessionHandle,
): EmailOtpWorkerSessionSecretSource {
  return {
    kind: 'email_otp_worker_session',
    handle,
    [clientSecretSourceBrand]: 'email_otp_worker_session',
  };
}

export function buildRelayerKeyId(input: unknown): RelayerKeyId {
  return requirePlatformString(String(input || ''), 'relayerKeyId') as RelayerKeyId;
}

export function buildSecureEnclaveWrappedSecretSource(input: {
  keyId: string;
  accessGroup: string;
}): SecureEnclaveWrappedSecretSource {
  return {
    kind: 'secure_enclave_wrapped_secret',
    keyId: requirePlatformString(input.keyId, 'keyId'),
    accessGroup: requirePlatformString(input.accessGroup, 'accessGroup'),
    [clientSecretSourceBrand]: 'secure_enclave_wrapped_secret',
  };
}

export function buildFido2HmacSecretSource(input: {
  credentialIdB64u: string;
  rpId: RpId;
}): Fido2HmacSecretSource {
  return {
    kind: 'fido2_hmac_secret',
    credentialIdB64u: requirePlatformString(input.credentialIdB64u, 'credentialIdB64u'),
    rpId: input.rpId,
    [clientSecretSourceBrand]: 'fido2_hmac_secret',
  };
}

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

export type HttpTransport = {
  kind: 'http_transport';
  request(input: {
    method: 'GET' | 'POST';
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
    timeoutMs?: number;
  }): Promise<PlatformResult<{ status: number; body: unknown }, 'network_error' | 'timeout'>>;
};

export type ClockPort = {
  kind: 'clock';
  nowMs(): number;
};

export type RandomSource = {
  kind: 'random_source';
  randomBytes(length: number): Uint8Array;
};

export type PlatformRuntime = {
  kind: PlatformKind;
  storage: DurableRecordStore;
  secrets: SecureSecretStore;
  authenticator: AuthenticatorPort;
  signerCrypto: SignerCryptoPort;
  http: HttpTransport;
  clock: ClockPort;
  random: RandomSource;
};

export function assertNeverPlatform(value: never): never {
  throw new Error(`Unhandled platform branch: ${String(value)}`);
}

export function platformKindLabel(kind: PlatformKind): string {
  switch (kind) {
    case 'browser':
      return 'Browser';
    case 'ios':
      return 'iOS';
    case 'linux_embedded':
      return 'Linux embedded';
  }
  return assertNeverPlatform(kind);
}
