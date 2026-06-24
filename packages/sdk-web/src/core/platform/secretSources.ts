
import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '../signingEngine/interfaces/ecdsaChainTarget';
import { toRpId, type RpId } from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEmailOtpAuthSubjectId,
  type EmailOtpAuthSubjectId,
} from '../signingEngine/session/identity/emailOtpHssIdentity';
import { parseWalletKeyId, type WalletKeyId } from '@shared/signing-lanes';
import type { RelayerKeyId } from './ecdsaRoleLocalRecords';

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
      walletKeyId: WalletKeyId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ecdsa_bootstrap';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      chainTarget: ThresholdEcdsaChainTarget;
      rpId?: never;
    }
  | {
      kind: 'email_otp_worker_session_handle_v1';
      sessionId: string;
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ed25519_session';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      walletKeyId?: never;
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
      walletKeyId: WalletKeyId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ecdsa_bootstrap';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      chainTarget: ThresholdEcdsaChainTarget;
      rpId?: never;
    }
  | {
      sessionId: string;
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      action: 'threshold_ed25519_session';
      operation: 'registration' | 'wallet_unlock' | 'sign' | 'export';
      walletKeyId?: never;
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

function requirePlatformWalletKeyId(value: unknown, field: string): WalletKeyId {
  const parsed = parseWalletKeyId(value);
  if (!parsed.ok) {
    throw new Error(`[platform] ${field} is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

export type RequiredPrfSecretSourceInput = {
  prf: { prfFirstB64u: string };
  rpId: RpId;
  credentialIdB64u: string;
};

export function buildWebAuthnPrfFirstSecretSource(
  input: RequiredPrfSecretSourceInput,
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
  switch (input.action) {
    case 'threshold_ecdsa_bootstrap':
      return {
        kind: 'email_otp_worker_session_handle_v1',
        sessionId,
        walletId: input.walletId,
        walletKeyId: input.walletKeyId,
        authSubjectId: input.authSubjectId,
        action: 'threshold_ecdsa_bootstrap',
        operation: input.operation,
        chainTarget: input.chainTarget,
        [emailOtpWorkerSessionHandleBrand]: 'email_otp_worker_session_handle',
      };
    case 'threshold_ed25519_session':
      return {
        kind: 'email_otp_worker_session_handle_v1',
        sessionId,
        walletId: input.walletId,
        rpId: input.rpId,
        authSubjectId: input.authSubjectId,
        action: 'threshold_ed25519_session',
        operation: input.operation,
        [emailOtpWorkerSessionHandleBrand]: 'email_otp_worker_session_handle',
      };
    default: {
      const exhaustive: never = input;
      throw new Error(`[platform] unsupported email OTP worker-issued handle action: ${String(exhaustive)}`);
    }
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
    authSubjectId: toEmailOtpAuthSubjectId(payload.authSubjectId),
    operation: normalizedOperation,
  };
  if (action === 'threshold_ecdsa_bootstrap') {
    if ('rpId' in payload) {
      throw new Error(
        '[platform] email OTP ECDSA worker-issued handles cannot include rpId',
      );
    }
    return buildEmailOtpWorkerIssuedSessionHandle({
      ...base,
      action,
      walletKeyId: requirePlatformWalletKeyId(
        payload.walletKeyId,
        'email OTP worker-issued handle walletKeyId',
      ),
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
    if ('walletKeyId' in payload) {
      throw new Error(
        '[platform] email OTP Ed25519 worker-issued handles cannot include walletKeyId',
      );
    }
    return buildEmailOtpWorkerIssuedSessionHandle({
      ...base,
      action,
      rpId: toRpId(payload.rpId),
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
