import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../types/webauthn';
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
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: string;
  ethereumAddress: `0x${string}`;
};

export type EcdsaRoleLocalReadyRecord = {
  kind: 'ecdsa_role_local_ready_record_v1';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
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
};

export type LoadEcdsaRoleLocalReadyRecordResult = PlatformResult<
  EcdsaRoleLocalReadyRecord | null,
  'unavailable' | 'malformed_record'
>;

export type PersistEcdsaRoleLocalReadyRecordInput = {
  record: EcdsaRoleLocalReadyRecord;
};

export type PersistEcdsaRoleLocalReadyRecordResult = PlatformResult<
  void,
  'unavailable' | 'invalid_record'
>;

export type CleanupMalformedEcdsaRoleLocalRecordInput = {
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly [1, 2];
  reason: string;
};

export type CleanupMalformedEcdsaRoleLocalRecordResult = PlatformResult<void, 'unavailable'>;

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
  seal(input: { purpose: string; secretB64u: string }): Promise<PlatformResult<{ handle: string }, 'unavailable'>>;
  unseal(input: { handle: string }): Promise<PlatformResult<{ secretB64u: string }, 'unavailable' | 'not_found'>>;
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

export type EcdsaBootstrapSecretSource =
  | WebAuthnPrfFirstSecretSource
  | EmailOtpWorkerSessionSecretSource;

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
  return {
    kind: 'webauthn_prf_first',
    prfFirstB64u: requirePlatformString(input.prf.prfFirstB64u, 'prfFirstB64u'),
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
  const kind = requirePlatformString(String(payload.kind || ''), 'email OTP worker-issued handle kind');
  if (kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(`[platform] unsupported email OTP worker-issued handle kind: ${kind}`);
  }
  const action = requirePlatformString(String(payload.action || ''), 'email OTP worker-issued handle action');
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
    sessionId: requirePlatformString(String(payload.sessionId || ''), 'email OTP worker-issued handle sessionId'),
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
  kind: 'prepare_ecdsa_client_bootstrap_v1';
  algorithm: 'ecdsa_hss_secp256k1_role_local_v1';
  context: {
    walletId: WalletId;
    rpId: RpId;
    chainTarget: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: SigningRootId;
    signingRootVersion: SigningRootVersion;
    keyPurpose: 'evm-signing';
    keyVersion: 'v1';
  };
  participants: {
    clientParticipantId: 1;
    relayerParticipantId: 2;
    participantIds: readonly [1, 2];
  };
  secretSource: EcdsaBootstrapSecretSource;
};

export type PrepareEcdsaClientBootstrapOutput = {
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  clientBootstrap: {
    contextBinding32B64u: string;
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientShareRetryCounter: number;
    participantId: 1;
  };
  publicFacts: {
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientVerifyingShareB64u: string;
  };
};

export type FinalizeEcdsaClientBootstrapInput = {
  kind: 'finalize_ecdsa_client_bootstrap_v1';
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
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientVerifyingShareB64u: string;
    relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
    groupPublicKey33B64u: string;
    ethereumAddress: `0x${string}`;
  };
};

export type PrepareEcdsaClientBootstrapErrorCode =
  | 'unsupported_secret_source'
  | 'invalid_secret_source'
  | 'invalid_context'
  | 'invalid_threshold_parameters'
  | 'invalid_public_material'
  | 'crypto_failure';

export type FinalizeEcdsaClientBootstrapErrorCode =
  | 'invalid_pending_state'
  | 'invalid_relayer_public_identity'
  | 'public_identity_mismatch'
  | 'crypto_failure';

export type SignerCryptoPort = {
  kind: 'signer_crypto';
  prepareEcdsaClientBootstrap(
    input: PrepareEcdsaClientBootstrapInput,
  ): Promise<SignerCryptoResult<PrepareEcdsaClientBootstrapOutput, PrepareEcdsaClientBootstrapErrorCode>>;
  finalizeEcdsaClientBootstrap(
    input: FinalizeEcdsaClientBootstrapInput,
  ): Promise<SignerCryptoResult<FinalizeEcdsaClientBootstrapOutput, FinalizeEcdsaClientBootstrapErrorCode>>;
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
