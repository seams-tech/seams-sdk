import { base64UrlEncode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type { ThresholdEd25519AuthorityScope } from '../types';
import type { ThresholdSigningService } from '../ThresholdService';
import type { NormalizedLogger } from '../logger';
import type {
  WebAuthnAuthenticatorRecord,
  WebAuthnAuthenticatorStore,
} from '../WebAuthnAuthenticatorStore';
import type { WebAuthnLoginChallengeStore } from '../WebAuthnLoginChallengeStore';
import type {
  WebAuthnSyncChallengeRecord,
  WebAuthnSyncChallengeStore,
} from '../WebAuthnSyncChallengeStore';
import type { WebAuthnCredentialBindingStore } from '../WebAuthnCredentialBindingStore';
import type { IdentityStore } from '../IdentityStore';
import type { EmailRecoveryResolvedWalletBinding } from '../EmailRecoveryPreparationStore';
import type { WebAuthnAuthenticationCredential } from '../types';
import {
  parseBoundaryWalletId,
  resolvedEd25519WalletBindingFromCredentialBinding,
  resolveThresholdEd25519SessionPolicyForBinding,
} from './webauthnWalletBinding';
import {
  passkeyThresholdEd25519AuthorityScope,
  requireWebAuthnRpId,
} from './webauthnAuthority';
import {
  normalizeThresholdRuntimePolicyScope,
} from './thresholdRuntimePolicy';
import {
  parseThresholdEd25519RegistrationInput,
  toThresholdEd25519BootstrapSession,
  validateThresholdEd25519SessionPolicyBindings,
  type ThresholdEd25519BootstrapSession,
} from './registrationThresholdHelpers';
import {
  decodeBase64UrlOrBase64,
  isHostWithinRpId,
  loadSimpleWebAuthnServer,
  originHostnameOrEmpty,
  parseClientDataJsonBase64url,
} from './webauthnOidcHelpers';

export type WebAuthnCredentialVerificationResult =
  | {
      ok: true;
      credential: {
        credentialIdB64u: string;
        credentialPublicKeyB64u: string;
        counter: number;
      };
    }
  | { ok: false; code: string; message: string };

export type WebAuthnAuthenticationLiteResult = {
  success: boolean;
  verified: boolean;
  code?: string;
  message?: string;
};

export type WebAuthnAuthenticatorListResult = {
  ok: boolean;
  code?: string;
  message?: string;
  authenticators?: Array<{
    credentialIdB64u: string;
    signerSlot?: number;
    publicKey?: string;
    createdAtMs?: number;
    updatedAtMs?: number;
  }>;
};

export type WebAuthnLoginOptionsResult = {
  ok: boolean;
  challengeId?: string;
  challengeB64u?: string;
  expiresAtMs?: number;
  code?: string;
  message?: string;
};

export type WebAuthnSyncAccountOptionsResult =
  | {
      ok: true;
      challengeId: string;
      challengeB64u: string;
      expiresAtMs: number;
      credentialIds?: string[];
      walletBinding?: EmailRecoveryResolvedWalletBinding;
    }
  | { ok: false; code: string; message: string };

export type WebAuthnSyncAccountVerificationRequest = {
  challengeId?: unknown;
  challenge_id?: unknown;
  webauthn_authentication?: unknown;
  expected_origin?: string;
  threshold_ed25519?: unknown;
};

export type WebAuthnSyncAccountVerificationResult =
  | {
      ok: true;
      verified: true;
      accountId: string;
      walletId: string;
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      walletBinding: EmailRecoveryResolvedWalletBinding;
      rpId: string;
      signerSlot: number;
      publicKey: string;
      relayerKeyId?: string;
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
      thresholdEd25519?: {
        relayerKeyId: string;
        authorityScope: ThresholdEd25519AuthorityScope;
        publicKey: string;
        keyVersion?: string;
        recoveryExportCapable?: boolean;
        clientParticipantId?: number;
        relayerParticipantId?: number;
        participantIds?: number[];
        session?: ThresholdEd25519BootstrapSession;
      };
    }
  | {
      ok: false;
      verified?: false;
      code: string;
      message: string;
    };

export type WebAuthnLoginVerificationResult = {
  ok: boolean;
  verified?: boolean;
  userId?: string;
  rpId?: string;
  code?: string;
  message?: string;
};

function readRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readNestedRecord(
  record: Record<string, unknown>,
  key: string,
): Record<string, unknown> | null {
  return readRecord(record[key]);
}

function readStringField(record: Record<string, unknown>, key: string): string {
  return typeof record[key] === 'string' ? record[key].trim() : '';
}

function normalizeWebAuthnTtlMs(raw: unknown): number {
  const numeric = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(numeric) || numeric <= 0) return 5 * 60_000;
  return Math.min(Math.max(Math.floor(numeric), 10_000), 10 * 60_000);
}

function ensureCryptoRandomValues(): true | { ok: false; code: string; message: string } {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    return true;
  }
  return {
    ok: false,
    code: 'unsupported',
    message: 'crypto.getRandomValues is unavailable in this runtime',
  };
}

function randomWebAuthnB64u(byteLength: number): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function credentialRawIdB64u(credential: Record<string, unknown>):
  | { ok: true; credentialIdB64u: string }
  | { ok: false; code: string; message: string } {
  const credentialId = readStringField(credential, 'id');
  const rawId = readStringField(credential, 'rawId');
  const chosen = rawId || credentialId;
  if (!chosen) {
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
        decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId'),
      ),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(e) || 'Invalid credential rawId',
    };
  }
}

function credentialPublicKeyBytes(record: WebAuthnAuthenticatorRecord):
  | { ok: true; bytes: Uint8Array }
  | { ok: false; code: string; message: string } {
  try {
    return {
      ok: true,
      bytes: decodeBase64UrlOrBase64(
        record.credentialPublicKeyB64u,
        'authenticator.credentialPublicKeyB64u',
      ),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: `Stored credential public key is invalid: ${errorMessage(e) || 'decode failed'}`,
    };
  }
}

function credentialVerificationInput(input: {
  credentialIdB64u: string;
  credentialPublicKeyBytes: Uint8Array;
  counter: number;
}): { id: string; publicKey: Uint8Array | Buffer; counter: number } {
  return {
    id: input.credentialIdB64u,
    publicKey:
      typeof Buffer !== 'undefined'
        ? Buffer.from(input.credentialPublicKeyBytes)
        : input.credentialPublicKeyBytes,
    counter: input.counter,
  };
}

function authenticationNewCounter(verification: unknown): number | null {
  const record = readRecord(verification);
  const authenticationInfo = record ? readNestedRecord(record, 'authenticationInfo') : null;
  const value = authenticationInfo?.newCounter;
  const numeric = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : null;
}

function updatedAuthenticatorRecord(input: {
  latest: WebAuthnAuthenticatorRecord;
  newCounter: number;
}): WebAuthnAuthenticatorRecord {
  return {
    version: 'webauthn_authenticator_v1',
    credentialIdB64u: input.latest.credentialIdB64u,
    credentialPublicKeyB64u: input.latest.credentialPublicKeyB64u,
    counter: input.newCounter,
    createdAtMs: input.latest.createdAtMs,
    updatedAtMs: Date.now(),
  };
}

async function persistAuthenticatorCounter(input: {
  store: WebAuthnAuthenticatorStore;
  userId: string;
  credentialIdB64u: string;
  newCounter: number;
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  try {
    const latest = await input.store.get(input.userId, input.credentialIdB64u);
    if (latest && input.newCounter > latest.counter) {
      await input.store.put(
        input.userId,
        updatedAuthenticatorRecord({ latest, newCounter: input.newCounter }),
      );
    }
    return { ok: true };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: `Failed to persist authenticator counter: ${errorMessage(e) || 'store error'}`,
    };
  }
}

function parseWebAuthnClientDataForRegistration(input: {
  credential: Record<string, unknown>;
  expectedChallenge: string;
  rpId: WebAuthnRpId;
}): WebAuthnCredentialVerificationResult | { ok: true; originHost: string } {
  const response = readNestedRecord(input.credential, 'response');
  const clientDataJSON = response ? readStringField(response, 'clientDataJSON') : '';
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
  const originHost = originHostnameOrEmpty(clientData.origin);
  if (!isHostWithinRpId(originHost, input.rpId)) {
    return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
  }
  return { ok: true, originHost };
}

function registrationCredentialCounter(counter: unknown): number {
  const numeric = typeof counter === 'number' ? counter : Number(counter);
  return Number.isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : 0;
}

function authenticatorListEntry(input: {
  binding: {
    credentialIdB64u: string;
    signerSlot?: number;
    publicKey?: string;
    createdAtMs?: number;
    updatedAtMs?: number;
  };
  authenticator: WebAuthnAuthenticatorRecord | undefined;
}): {
  credentialIdB64u: string;
  signerSlot?: number;
  publicKey?: string;
  createdAtMs?: number;
  updatedAtMs?: number;
} {
  return {
    credentialIdB64u: input.binding.credentialIdB64u,
    signerSlot: input.binding.signerSlot,
    publicKey: input.binding.publicKey,
    createdAtMs: input.authenticator?.createdAtMs ?? input.binding.createdAtMs,
    updatedAtMs: input.authenticator?.updatedAtMs ?? input.binding.updatedAtMs,
  };
}

function compareAuthenticatorListEntries(
  left: ReturnType<typeof authenticatorListEntry>,
  right: ReturnType<typeof authenticatorListEntry>,
): number {
  return (Number(left.signerSlot || 0) || 0) - (Number(right.signerSlot || 0) || 0);
}

async function listCredentialBindingsForUser(input: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}) {
  if (!input.bindingStore.listByUserId) {
    return {
      ok: false as const,
      code: 'not_supported',
      message: 'Credential binding listing is not supported by this store',
    };
  }
  const bindings = input.rpId
    ? await input.bindingStore.listByUserId({ userId: input.userId, rpId: input.rpId })
    : await input.bindingStore.listByUserId({ userId: input.userId });
  return { ok: true as const, bindings };
}

function ignoreIdentityLinkFailure(): void {}

async function linkNearSubjectForWebAuthnLogin(input: {
  identityStore: IdentityStore;
  userId: string;
}): Promise<void> {
  await input.identityStore
    .linkSubjectToUserId({ userId: input.userId, subject: `near:${input.userId}` })
    .catch(ignoreIdentityLinkFailure);
}

export async function verifyWebAuthnRegistrationCredentialForIntent(input: {
  webauthnRegistration: unknown;
  expectedChallenge: string;
  expectedOrigin: string;
  rpId: WebAuthnRpId;
}): Promise<WebAuthnCredentialVerificationResult> {
  const credential = readRecord(input.webauthnRegistration);
  if (!credential) {
    return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };
  }
  const parsedClientData = parseWebAuthnClientDataForRegistration({
    credential,
    expectedChallenge: input.expectedChallenge,
    rpId: input.rpId,
  });
  if (!parsedClientData.ok) return parsedClientData;

  const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
  if (!expectedOrigin) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'expected_origin is required for WebAuthn registration verification',
    };
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
  if (!registration.verified) {
    return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
  }

  const verifiedCredential = registration.registrationInfo?.credential;
  const credentialIdB64u = String(verifiedCredential?.id || '').trim();
  const credentialPublicKey = verifiedCredential?.publicKey;
  if (!credentialIdB64u || !credentialPublicKey) {
    return {
      ok: false,
      code: 'internal',
      message: 'Registration verification did not return credential public key material',
    };
  }
  return {
    ok: true,
    credential: {
      credentialIdB64u,
      credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
      counter: registrationCredentialCounter(verifiedCredential.counter),
    },
  };
}

export async function verifyWebAuthnAuthenticationLiteWithStore(input: {
  userId: string;
  rpId: WebAuthnRpId;
  expectedChallenge: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  expectedOrigin: string;
  authenticatorStore: WebAuthnAuthenticatorStore;
  logger: NormalizedLogger;
}): Promise<WebAuthnAuthenticationLiteResult> {
  try {
    const userId = String(input.userId || '').trim();
    const rpId = input.rpId;
    const expectedChallenge = String(input.expectedChallenge || '').trim();
    const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
    const credential = readRecord(input.webauthnAuthentication);

    if (!userId)
      return { success: false, verified: false, code: 'invalid_body', message: 'Missing userId' };
    if (!expectedChallenge)
      return {
        success: false,
        verified: false,
        code: 'invalid_body',
        message: 'Missing expectedChallenge',
      };
    if (!expectedOrigin)
      return {
        success: false,
        verified: false,
        code: 'invalid_body',
        message: 'expected_origin is required for WebAuthn authentication verification',
      };
    if (!credential)
      return {
        success: false,
        verified: false,
        code: 'invalid_body',
        message: 'Missing webauthn_authentication',
      };

    let clientData: { challenge: string; origin: string; type: string };
    try {
      const response = readNestedRecord(credential, 'response');
      clientData = parseClientDataJsonBase64url(readStringField(response || {}, 'clientDataJSON'));
    } catch (e: unknown) {
      return {
        success: false,
        verified: false,
        code: 'invalid_body',
        message: errorMessage(e) || 'Invalid webauthn_authentication.response.clientDataJSON',
      };
    }

    const originHost = originHostnameOrEmpty(clientData.origin);
    if (!isHostWithinRpId(originHost, rpId)) {
      return {
        success: false,
        verified: false,
        code: 'invalid_origin',
        message: 'WebAuthn origin is not within rpId',
      };
    }

    const credentialId = credentialRawIdB64u(credential);
    if (!credentialId.ok) {
      return {
        success: false,
        verified: false,
        code: credentialId.code,
        message: credentialId.message,
      };
    }

    const matched = await input.authenticatorStore.get(userId, credentialId.credentialIdB64u);
    if (!matched) {
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

    const publicKey = credentialPublicKeyBytes(matched);
    if (!publicKey.ok) {
      return {
        success: false,
        verified: false,
        code: publicKey.code,
        message: publicKey.message,
      };
    }

    let verification: unknown;
    try {
      verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin,
        expectedRPID: rpId,
        credential: credentialVerificationInput({
          credentialIdB64u: credentialId.credentialIdB64u,
          credentialPublicKeyBytes: publicKey.bytes,
          counter: matched.counter,
        }),
        requireUserVerification: false,
      });
    } catch (e: unknown) {
      return {
        success: false,
        verified: false,
        code: 'invalid_assertion',
        message: errorMessage(e) || 'Authentication assertion verification threw',
      };
    }

    const verificationRecord = readRecord(verification);
    if (verificationRecord?.verified !== true) {
      return {
        success: false,
        verified: false,
        code: 'not_verified',
        message: 'Authentication verification failed',
      };
    }

    const newCounter = authenticationNewCounter(verification);
    if (newCounter !== null) {
      const counterUpdate = await persistAuthenticatorCounter({
        store: input.authenticatorStore,
        userId,
        credentialIdB64u: credentialId.credentialIdB64u,
        newCounter,
      });
      if (!counterUpdate.ok) {
        return {
          success: false,
          verified: false,
          code: counterUpdate.code,
          message: counterUpdate.message,
        };
      }
    }

    return { success: true, verified: true };
  } catch (e: unknown) {
    const msg = errorMessage(e) || 'Verification failed';
    input.logger.error('[webauthn] verifyWebAuthnAuthenticationLite internal error', {
      message: msg,
      userId: String(input.userId || ''),
      rpId: String(input.rpId || ''),
    });
    return { success: false, verified: false, code: 'internal', message: msg };
  }
}

export async function listWebAuthnAuthenticatorsForUserWithStores(input: {
  userId: string;
  rpId: string;
  authenticatorStore: WebAuthnAuthenticatorStore;
  credentialBindingStore: WebAuthnCredentialBindingStore;
}): Promise<WebAuthnAuthenticatorListResult> {
  try {
    const userId = String(input.userId || '').trim();
    const rpId = String(input.rpId || '').trim();
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!input.authenticatorStore.list) {
      return {
        ok: false,
        code: 'not_supported',
        message: 'Authenticator listing is not supported by this store',
      };
    }
    const bindingList = await listCredentialBindingsForUser({
      bindingStore: input.credentialBindingStore,
      userId,
      rpId,
    });
    if (!bindingList.ok) return bindingList;

    const [authenticators, bindings] = await Promise.all([
      input.authenticatorStore.list(userId),
      Promise.resolve(bindingList.bindings),
    ]);
    const authByCredentialId = new Map<string, WebAuthnAuthenticatorRecord>();
    for (const authenticator of authenticators) {
      authByCredentialId.set(String(authenticator.credentialIdB64u || '').trim(), authenticator);
    }

    const merged: ReturnType<typeof authenticatorListEntry>[] = [];
    for (const binding of bindings) {
      merged.push(
        authenticatorListEntry({
        binding: {
          credentialIdB64u: String(binding.credentialIdB64u || '').trim(),
          signerSlot: binding.signerSlot,
          publicKey: binding.publicKey,
          createdAtMs: binding.createdAtMs,
          updatedAtMs: binding.updatedAtMs,
        },
        authenticator: authByCredentialId.get(String(binding.credentialIdB64u || '').trim()),
        }),
      );
    }
    merged.sort(compareAuthenticatorListEntries);
    return { ok: true, authenticators: merged };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to list authenticators',
    };
  }
}

export async function createWebAuthnLoginOptionsWithStore(input: {
  request: {
    userId?: unknown;
    user_id?: unknown;
    rpId?: unknown;
    rp_id?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  };
  loginChallengeStore: WebAuthnLoginChallengeStore;
}): Promise<WebAuthnLoginOptionsResult> {
  try {
    const userIdRaw = String(input.request.userId ?? input.request.user_id ?? '').trim();
    const rpId = String(input.request.rpId ?? input.request.rp_id ?? '').trim();
    if (!userIdRaw) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    const userId = parseBoundaryWalletId(userIdRaw);
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Invalid userId' };
    if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rpId' };

    const randomAvailable = ensureCryptoRandomValues();
    if (randomAvailable !== true) return randomAvailable;

    const ttlMsClamped = normalizeWebAuthnTtlMs(input.request.ttlMs ?? input.request.ttl_ms);
    const createdAtMs = Date.now();
    const expiresAtMs = createdAtMs + ttlMsClamped;
    const challengeId = randomWebAuthnB64u(16);
    const challengeB64u = randomWebAuthnB64u(32);

    await input.loginChallengeStore.put({
      version: 'webauthn_login_challenge_v1',
      challengeId,
      userId,
      rpId,
      challengeB64u,
      createdAtMs,
      expiresAtMs,
    });

    return { ok: true, challengeId, challengeB64u, expiresAtMs };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to create login options',
    };
  }
}

export async function createWebAuthnSyncAccountOptionsWithStores(input: {
  request: {
    rp_id?: unknown;
    account_id?: unknown;
    ttl_ms?: unknown;
    ttlMs?: unknown;
  };
  syncChallengeStore: WebAuthnSyncChallengeStore;
  credentialBindingStore: WebAuthnCredentialBindingStore;
}): Promise<WebAuthnSyncAccountOptionsResult> {
  try {
    const rpId = String(input.request.rp_id || '').trim();
    if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };
    const expectedUserIdRaw = toOptionalTrimmedString(input.request.account_id);
    const expectedUserId = expectedUserIdRaw ? parseBoundaryWalletId(expectedUserIdRaw) : null;
    if (expectedUserIdRaw && !expectedUserId) {
      return { ok: false, code: 'invalid_body', message: 'Invalid wallet account_id' };
    }

    const randomAvailable = ensureCryptoRandomValues();
    if (randomAvailable !== true) return randomAvailable;

    const ttlMsClamped = normalizeWebAuthnTtlMs(input.request.ttlMs ?? input.request.ttl_ms);
    const createdAtMs = Date.now();
    const expiresAtMs = createdAtMs + ttlMsClamped;
    const challengeId = randomWebAuthnB64u(16);
    const challengeB64u = randomWebAuthnB64u(32);
    let credentialIds: string[] | undefined;
    let walletBinding: EmailRecoveryResolvedWalletBinding | undefined;

    if (expectedUserId) {
      const bindingList = await listCredentialBindingsForUser({
        bindingStore: input.credentialBindingStore,
        userId: expectedUserId,
        rpId,
      });
      if (!bindingList.ok) return bindingList;
      const resolvedBinding = bindingList.bindings.find((binding) => {
        return Boolean(binding.userId && binding.nearAccountId && binding.nearEd25519SigningKeyId);
      });
      if (resolvedBinding) {
        walletBinding = resolvedEd25519WalletBindingFromCredentialBinding({
          binding: resolvedBinding,
        });
      }
      const seen = new Set<string>();
      credentialIds = [];
      for (const binding of bindingList.bindings) {
        const credentialId = String(binding.credentialIdB64u || '').trim();
        if (!credentialId || seen.has(credentialId)) continue;
        seen.add(credentialId);
        credentialIds.push(credentialId);
      }
    }

    const record: WebAuthnSyncChallengeRecord = expectedUserId
      ? {
          version: 'webauthn_sync_challenge_v1',
          challengeId,
          rpId,
          expectedUserId,
          challengeB64u,
          createdAtMs,
          expiresAtMs,
        }
      : {
          version: 'webauthn_sync_challenge_v1',
          challengeId,
          rpId,
          challengeB64u,
          createdAtMs,
          expiresAtMs,
        };
    await input.syncChallengeStore.put(record);

    const result: Extract<WebAuthnSyncAccountOptionsResult, { ok: true }> = {
      ok: true,
      challengeId,
      challengeB64u,
      expiresAtMs,
    };
    if (credentialIds) result.credentialIds = credentialIds;
    if (walletBinding) result.walletBinding = walletBinding;
    return result;
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to create sync account options',
    };
  }
}

export async function verifyWebAuthnSyncAccountWithStores(input: {
  request: WebAuthnSyncAccountVerificationRequest;
  syncChallengeStore: WebAuthnSyncChallengeStore;
  credentialBindingStore: WebAuthnCredentialBindingStore;
  authenticatorStore: WebAuthnAuthenticatorStore;
  thresholdSigningService: ThresholdSigningService | null;
  logger: NormalizedLogger;
}): Promise<WebAuthnSyncAccountVerificationResult> {
  try {
    const request = input.request;
    const challengeId = String(request.challengeId ?? request.challenge_id ?? '').trim();
    if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

    const challenge = await input.syncChallengeStore.consume(challengeId);
    if (!challenge) {
      return {
        ok: false,
        verified: false,
        code: 'challenge_expired_or_invalid',
        message: 'Sync challenge expired or invalid',
      };
    }

    const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
      request.threshold_ed25519,
    );
    const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
    const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
    if (thresholdEd25519SessionPolicy && !readRecord(thresholdEd25519SessionPolicy)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'threshold_ed25519.session_policy is required',
      };
    }
    if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'threshold_ed25519.session_kind must be jwt',
      };
    }

    const credential = readRecord(request.webauthn_authentication);
    if (!credential) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'Missing webauthn_authentication',
      };
    }
    const credentialId = credentialRawIdB64u(credential);
    if (!credentialId.ok) {
      return {
        ok: false,
        verified: false,
        code: credentialId.code,
        message: credentialId.message,
      };
    }

    const binding = await input.credentialBindingStore.get(
      challenge.rpId,
      credentialId.credentialIdB64u,
    );
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

    const expectedOrigin = toOptionalTrimmedString(request.expected_origin);
    if (!expectedOrigin) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'expected_origin is required for WebAuthn authentication verification',
      };
    }
    const verification = await verifyWebAuthnAuthenticationLiteWithStore({
      userId: binding.userId,
      rpId: requireWebAuthnRpId(binding.rpId, 'sync credential binding rpId'),
      expectedChallenge: challenge.challengeB64u,
      webauthnAuthentication: request.webauthn_authentication as WebAuthnAuthenticationCredential,
      expectedOrigin,
      authenticatorStore: input.authenticatorStore,
      logger: input.logger,
    });
    if (!verification.success || !verification.verified) {
      return {
        ok: false,
        verified: false,
        code: verification.code || 'not_verified',
        message: verification.message || 'Authentication verification failed',
      };
    }

    const auth = await input.authenticatorStore.get(binding.userId, credentialId.credentialIdB64u);
    if (!auth) {
      return {
        ok: false,
        verified: false,
        code: 'unknown_credential',
        message: 'Credential is not registered for user',
      };
    }

    const walletBinding = resolvedEd25519WalletBindingFromCredentialBinding({ binding });
    const walletBindingAuthorityScope = passkeyThresholdEd25519AuthorityScope(
      requireWebAuthnRpId(walletBinding.rpId, 'sync credential binding rpId'),
    );
    const thresholdEd25519 = binding.relayerKeyId
      ? {
          relayerKeyId: binding.relayerKeyId,
          authorityScope: walletBindingAuthorityScope,
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
          ...(Array.isArray(binding.participantIds)
            ? { participantIds: binding.participantIds }
            : {}),
        }
      : undefined;

    let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
    if (thresholdEd25519SessionPolicy) {
      const thresholdService = input.thresholdSigningService;
      if (!thresholdService) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const relayerKeyId = String(binding.relayerKeyId || '').trim();
      if (!relayerKeyId) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Credential is not bound to threshold key material',
        };
      }
      const resolvedSessionPolicy = resolveThresholdEd25519SessionPolicyForBinding({
        requestedSessionPolicy: thresholdEd25519SessionPolicy,
        binding: walletBinding,
        relayerKeyId,
        persistedRuntimePolicyScope: normalizeThresholdRuntimePolicyScope(
          binding.runtimePolicyScope,
        ),
      });
      const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
        requestedSessionPolicy: resolvedSessionPolicy.sessionPolicy,
        expectedWalletId: walletBinding.walletId,
        expectedRelayerKeyId: relayerKeyId,
        expectedNearAccountId: walletBinding.nearAccountId,
        expectedNearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        expectedAuthorityScope: walletBindingAuthorityScope,
      });
      if (policyBindingError) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: policyBindingError,
        };
      }

      const session = await thresholdService.mintEd25519SessionFromRegistration({
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        authorityScope: walletBindingAuthorityScope,
        relayerKeyId,
        sessionPolicy: resolvedSessionPolicy.sessionPolicy,
      });
      if (
        !session.ok ||
        !session.thresholdSessionId ||
        !Number.isFinite(Number(session.expiresAtMs))
      ) {
        return {
          ok: false,
          verified: false,
          code: session.code || 'internal',
          message: session.message || 'threshold-ed25519 session bootstrap failed',
        };
      }
      const normalizedSession = toThresholdEd25519BootstrapSession(session);
      if (!normalizedSession) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'threshold-ed25519 session bootstrap failed',
        };
      }
      thresholdEd25519Session = normalizedSession;
    }

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
      publicKey: binding.publicKey,
      ...(binding.relayerKeyId ? { relayerKeyId: binding.relayerKeyId } : {}),
      credentialIdB64u: credentialId.credentialIdB64u,
      credentialPublicKeyB64u: auth.credentialPublicKeyB64u,
      ...(thresholdEd25519
        ? {
            thresholdEd25519: {
              ...thresholdEd25519,
              ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
            },
          }
        : {}),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      verified: false,
      code: 'internal',
      message: errorMessage(e) || 'Sync verification failed',
    };
  }
}

export async function verifyWebAuthnLoginWithStores(input: {
  request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
  };
  loginChallengeStore: WebAuthnLoginChallengeStore;
  authenticatorStore: WebAuthnAuthenticatorStore;
  identityStore: IdentityStore;
  logger: NormalizedLogger;
}): Promise<WebAuthnLoginVerificationResult> {
  try {
    const challengeId = String(
      input.request.challengeId ?? input.request.challenge_id ?? '',
    ).trim();
    if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

    const record = await input.loginChallengeStore.consume(challengeId);
    if (!record) {
      return {
        ok: false,
        verified: false,
        code: 'challenge_expired_or_invalid',
        message: 'Login challenge expired or invalid',
      };
    }

    const expectedOrigin = toOptionalTrimmedString(input.request.expected_origin);
    if (!expectedOrigin) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'expected_origin is required for WebAuthn authentication verification',
      };
    }
    const verification = await verifyWebAuthnAuthenticationLiteWithStore({
      userId: record.userId,
      rpId: requireWebAuthnRpId(record.rpId, 'login challenge rpId'),
      expectedChallenge: record.challengeB64u,
      webauthnAuthentication:
        input.request.webauthn_authentication as WebAuthnAuthenticationCredential,
      expectedOrigin,
      authenticatorStore: input.authenticatorStore,
      logger: input.logger,
    });

    if (!verification.success || !verification.verified) {
      return {
        ok: false,
        verified: false,
        code: verification.code || 'not_verified',
        message: verification.message || 'Authentication verification failed',
      };
    }

    await linkNearSubjectForWebAuthnLogin({
      identityStore: input.identityStore,
      userId: record.userId,
    });

    return { ok: true, verified: true, userId: record.userId, rpId: record.rpId };
  } catch (e: unknown) {
    return {
      ok: false,
      verified: false,
      code: 'internal',
      message: errorMessage(e) || 'Login verification failed',
    };
  }
}
