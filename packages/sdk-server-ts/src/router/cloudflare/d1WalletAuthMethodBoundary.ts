import { errorMessage } from '@shared/utils/errors';
import {
  base64Decode,
  base64UrlDecode,
  base64UrlEncode,
} from '@shared/utils/encoders';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  walletIdFromString,
  type RegistrationAuthority,
  type WebAuthnRpId,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
} from '../../core/RegistrationCeremonyStore';
import type {
  WalletRegistrationFinalizeAuthMethod,
  WebAuthnAuthenticationCredential,
} from '../../core/types';
import type {
  WalletAuthMethodRecord,
  WalletAuthMethodStore,
} from '../../core/d1WalletAuthMethodStore';
import type { RouterApiAuthService } from '../authServicePort';
import {
  addAuthMethodInputMatches,
  addSignerSelectionMatches,
  runtimePolicyScopeMatches,
} from './d1RegistrationCeremonyRecords';
import {
  parseJsonObject,
  toRecordValue,
} from './d1RouterApiAuthBoundary';

type StartWalletAddSignerInput = Parameters<
  RouterApiAuthService['startWalletAddSigner']
>[0];
type StartWalletAddAuthMethodInput = Parameters<
  RouterApiAuthService['startWalletAddAuthMethod']
>[0];
type RevokeWalletAuthMethodInput = Parameters<
  RouterApiAuthService['revokeWalletAuthMethod']
>[0];
type RevokeWalletAuthMethodResult = Awaited<
  ReturnType<RouterApiAuthService['revokeWalletAuthMethod']>
>;

export type D1RevokeWalletAuthMethodTarget =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: string;
    }
  | {
      readonly kind: 'email_otp';
      readonly email: string;
    };

export type D1RevokeWalletAuthMethodAuth =
  | {
      readonly kind: 'webauthn_assertion';
      readonly rpId: WebAuthnRpId;
      readonly credential: unknown;
    }
  | {
      readonly kind: 'app_session';
      readonly policy: {
        readonly permission: 'wallet_auth_method_revoke';
        readonly walletId: WalletId;
        readonly target: D1RevokeWalletAuthMethodTarget;
        readonly expiresAtMs: number;
      };
    };

export type D1RevokeWalletAuthMethodBoundary =
  | {
      readonly ok: true;
      readonly walletId: WalletId;
      readonly target: D1RevokeWalletAuthMethodTarget;
      readonly auth: D1RevokeWalletAuthMethodAuth;
    }
  | {
      readonly ok: false;
      readonly result: RevokeWalletAuthMethodResult;
    };

export type D1WebAuthnCredentialIdParseResult =
  | { readonly ok: true; readonly credentialIdB64u: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type D1WalletAuthMethodEmailHash = (email: string) => Promise<string>;

export type D1AddSignerExistingAuthResolution =
  | {
      readonly ok: true;
      readonly auth: StoredWalletAddSignerCeremony['auth'];
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export type D1AddAuthMethodExistingAuthResolution =
  | {
      readonly ok: true;
      readonly auth: StoredWalletAddAuthMethodCeremony['auth'];
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export type D1WebAuthnClientDataJson = {
  readonly challenge: string;
  readonly origin: string;
  readonly type: string;
};

export function walletRegistrationFinalizeAuthMethodFromAuthority(
  authority: RegistrationAuthority,
): WalletRegistrationFinalizeAuthMethod {
  switch (authority.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: authority.credentialIdB64u,
        credentialPublicKeyB64u: authority.credentialPublicKeyB64u,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        registrationAuthorityId: authority.registrationAuthorityId,
      };
  }
  return unreachableRegistrationAuthority(authority);
}

export function walletAuthMethodRecordFromRegistrationAuthority(input: {
  readonly authority: RegistrationAuthority;
  readonly now: number;
}): WalletAuthMethodRecord {
  switch (input.authority.kind) {
    case 'passkey':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId: input.authority.walletId,
        rpId: input.authority.rpId,
        credentialIdB64u: input.authority.credentialIdB64u,
        credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
        counter: input.authority.counter,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      };
    case 'email_otp':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: input.authority.walletId,
        emailHashHex: input.authority.emailHashHex,
        registrationAuthorityId: input.authority.registrationAuthorityId,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      };
  }
  return unreachableRegistrationAuthority(input.authority);
}

export function activeWalletAuthMethodRecord(record: WalletAuthMethodRecord): boolean {
  return record.status === 'active';
}

export function revokedD1WalletAuthMethodRecord(input: {
  readonly record: WalletAuthMethodRecord;
  readonly updatedAtMs: number;
}): WalletAuthMethodRecord {
  switch (input.record.kind) {
    case 'passkey':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'revoked',
        walletId: input.record.walletId,
        rpId: input.record.rpId,
        credentialIdB64u: input.record.credentialIdB64u,
        credentialPublicKeyB64u: input.record.credentialPublicKeyB64u,
        counter: input.record.counter,
        createdAtMs: input.record.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
    case 'email_otp':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'revoked',
        walletId: input.record.walletId,
        emailHashHex: input.record.emailHashHex,
        registrationAuthorityId: input.record.registrationAuthorityId,
        createdAtMs: input.record.createdAtMs,
        updatedAtMs: input.updatedAtMs,
      };
  }
}

function unreachableRegistrationAuthority(value: never): never {
  throw new Error(`Unhandled registration authority kind: ${String(value)}`);
}

export function parseD1RevokeWalletAuthMethodInput(
  input: RevokeWalletAuthMethodInput,
): D1RevokeWalletAuthMethodBoundary {
  const raw: Record<string, unknown> = toRecordValue(input) || {};
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) {
    return d1RevokeWalletAuthMethodInvalidBody('rpId belongs on passkey target or WebAuthn auth');
  }
  const walletId = walletIdFromString(toOptionalTrimmedString(raw.walletId));
  if (!walletId) return d1RevokeWalletAuthMethodInvalidBody('walletId is required');
  const target = parseD1RevokeWalletAuthMethodTarget(raw.target);
  if (!target) return d1RevokeWalletAuthMethodInvalidBody('target is required');
  const auth = parseD1RevokeWalletAuthMethodAuth({
    raw: raw.auth,
    walletId,
  });
  if (!auth) return d1RevokeWalletAuthMethodInvalidBody('auth is required');
  return {
    ok: true,
    walletId,
    target,
    auth,
  };
}

export function d1RevokeTargetsEqual(
  left: D1RevokeWalletAuthMethodTarget,
  right: D1RevokeWalletAuthMethodTarget,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u
      );
    case 'email_otp':
      return right.kind === 'email_otp' && left.email === right.email;
  }
}

export function validateD1RevokeWalletAuthMethodPolicy(input: {
  readonly auth: D1RevokeWalletAuthMethodAuth;
  readonly walletId: WalletId;
  readonly target: D1RevokeWalletAuthMethodTarget;
  readonly nowMs: number;
}): RevokeWalletAuthMethodResult | null {
  if (input.auth.kind !== 'app_session') return null;
  if (input.auth.policy.walletId !== input.walletId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke policy wallet mismatch',
    };
  }
  if (!d1RevokeTargetsEqual(input.auth.policy.target, input.target)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke policy target mismatch',
    };
  }
  if (input.auth.policy.expiresAtMs <= input.nowMs) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke policy is expired',
    };
  }
  return null;
}

export async function authorizeD1WalletAuthMethodRevoke(input: {
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
  readonly walletId: WalletId;
  readonly auth: D1RevokeWalletAuthMethodAuth;
}): Promise<RevokeWalletAuthMethodResult | null> {
  if (input.auth.kind !== 'webauthn_assertion') return null;
  const authorizationCredentialId = d1WebAuthnCredentialIdB64uFromCredential(
    input.auth.credential,
  );
  if (!authorizationCredentialId.ok) return authorizationCredentialId;
  const authorizationMethod = await input.walletAuthMethodStore.getPasskey({
    rpId: input.auth.rpId,
    credentialIdB64u: authorizationCredentialId.credentialIdB64u,
  });
  if (
    !authorizationMethod ||
    authorizationMethod.kind !== 'passkey' ||
    authorizationMethod.walletId !== input.walletId ||
    authorizationMethod.status !== 'active'
  ) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'WebAuthn authorization credential is not active for this wallet',
    };
  }
  return null;
}

export async function findD1WalletAuthMethodRecordForRevokeTarget(input: {
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey' | 'getEmailOtp'>;
  readonly walletId: WalletId;
  readonly target: D1RevokeWalletAuthMethodTarget;
  readonly emailHash: D1WalletAuthMethodEmailHash;
}): Promise<WalletAuthMethodRecord | null> {
  switch (input.target.kind) {
    case 'passkey': {
      const record = await input.walletAuthMethodStore.getPasskey({
        rpId: input.target.rpId,
        credentialIdB64u: input.target.credentialIdB64u,
      });
      if (!record || record.kind !== 'passkey' || record.walletId !== input.walletId) {
        return null;
      }
      return record;
    }
    case 'email_otp': {
      const emailHashHex = await input.emailHash(input.target.email);
      const record = await input.walletAuthMethodStore.getEmailOtp({
        walletId: input.walletId,
        emailHashHex,
      });
      if (!record || record.kind !== 'email_otp') return null;
      return record;
    }
  }
}

export async function resolveD1AddSignerExistingAuth(input: {
  readonly auth: StartWalletAddSignerInput['auth'];
  readonly walletId: WalletId;
  readonly intent: AddSignerIntentV1;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
  readonly nowMs: number;
}): Promise<D1AddSignerExistingAuthResolution> {
  if (input.auth.kind === 'app_session') {
    if (input.auth.policy.walletId !== input.walletId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-signer auth.policy wallet mismatch',
      };
    }
    if (
      !addSignerSelectionMatches(input.auth.policy.signerSelection, input.intent.signerSelection)
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-signer auth.policy selection mismatch',
      };
    }
    if (
      !runtimePolicyScopeMatches(
        input.auth.policy.runtimePolicyScope,
        input.intent.runtimePolicyScope,
      )
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-signer auth.policy runtime scope mismatch',
      };
    }
    if (input.auth.policy.expiresAtMs <= input.nowMs) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-signer auth.policy is expired',
      };
    }
    return { ok: true, auth: { kind: 'app_session' } };
  }

  const authorization = await resolveD1WebAuthnExistingWalletAuth({
    credential: input.auth.credential,
    rpId: input.auth.rpId,
    walletId: input.walletId,
    walletAuthMethodStore: input.walletAuthMethodStore,
  });
  if (!authorization.ok) return authorization;
  return {
    ok: true,
    auth: {
      kind: 'webauthn_assertion',
      rpId: input.auth.rpId,
      credentialIdB64u: authorization.credentialIdB64u,
    },
  };
}

export async function resolveD1AddAuthMethodExistingAuth(input: {
  readonly auth: StartWalletAddAuthMethodInput['auth'];
  readonly walletId: WalletId;
  readonly intent: AddAuthMethodIntentV1;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
  readonly nowMs: number;
}): Promise<D1AddAuthMethodExistingAuthResolution> {
  if (input.auth.kind === 'app_session') {
    if (input.auth.policy.walletId !== input.walletId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy wallet mismatch',
      };
    }
    if (!addAuthMethodInputMatches(input.auth.policy.authMethod, input.intent.authMethod)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy method mismatch',
      };
    }
    if (
      !runtimePolicyScopeMatches(
        input.auth.policy.runtimePolicyScope,
        input.intent.runtimePolicyScope,
      )
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy runtime scope mismatch',
      };
    }
    if (input.auth.policy.expiresAtMs <= input.nowMs) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy is expired',
      };
    }
    return { ok: true, auth: { kind: 'app_session' } };
  }

  const authorization = await resolveD1WebAuthnExistingWalletAuth({
    credential: input.auth.credential,
    rpId: input.auth.rpId,
    walletId: input.walletId,
    walletAuthMethodStore: input.walletAuthMethodStore,
  });
  if (!authorization.ok) return authorization;
  return {
    ok: true,
    auth: {
      kind: 'webauthn_assertion',
      rpId: input.auth.rpId,
      credentialIdB64u: authorization.credentialIdB64u,
    },
  };
}

export function decodeD1WebAuthnBase64UrlOrBase64(
  input: string,
  fieldName: string,
): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (error: unknown) {
      throw new Error(
        `Invalid ${fieldName}: expected base64url/base64 string (${
          errorMessage(error) || 'decode failed'
        })`,
      );
    }
  }
}

export function parseD1WebAuthnClientDataJsonBase64url(
  clientDataJSONB64u: string,
): D1WebAuthnClientDataJson {
  const bytes = decodeD1WebAuthnBase64UrlOrBase64(
    clientDataJSONB64u,
    'webauthn_authentication.response.clientDataJSON',
  );
  const json = new TextDecoder().decode(bytes);
  const record = parseJsonObject(json);
  if (!record) throw new Error('Invalid clientDataJSON: expected object');
  const challenge = toOptionalTrimmedString(record.challenge);
  const origin = toOptionalTrimmedString(record.origin);
  const type = toOptionalTrimmedString(record.type);
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

export function d1WebAuthnOriginHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function d1HostIsWithinWebAuthnRpId(host: string, rpId: string): boolean {
  const normalizedHost = host.toLowerCase();
  const normalizedRpId = rpId.toLowerCase();
  if (!normalizedHost || !normalizedRpId) return false;
  const env = typeof process !== 'undefined' ? process.env : {};
  if (
    (env.NO_CADDY === '1' || env.VITE_NO_CADDY === '1') &&
    (normalizedHost === 'localhost' || normalizedHost === '127.0.0.1') &&
    normalizedRpId.endsWith('.localhost')
  ) {
    return true;
  }
  return normalizedHost === normalizedRpId || normalizedHost.endsWith(`.${normalizedRpId}`);
}

export function d1WebAuthnCredentialIdB64uFromCredential(
  input: unknown,
): D1WebAuthnCredentialIdParseResult {
  const credential = toRecordValue(input) || {};
  const rawId = toOptionalTrimmedString(credential.rawId);
  const id = toOptionalTrimmedString(credential.id);
  const selected = rawId || id;
  if (!selected) {
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
        decodeD1WebAuthnBase64UrlOrBase64(selected, 'webauthn_authentication.rawId'),
      ),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(error) || 'Invalid credential rawId',
    };
  }
}

export function parseD1WebAuthnAuthenticationCredential(
  input: unknown,
): WebAuthnAuthenticationCredential | null {
  const credential = toRecordValue(input);
  const response = toRecordValue(credential?.response);
  const id = toOptionalTrimmedString(credential?.id);
  const rawId = toOptionalTrimmedString(credential?.rawId);
  const type = toOptionalTrimmedString(credential?.type);
  const clientDataJSON = toOptionalTrimmedString(response?.clientDataJSON);
  const authenticatorData = toOptionalTrimmedString(response?.authenticatorData);
  const signature = toOptionalTrimmedString(response?.signature);
  const userHandle =
    response?.userHandle === null ? null : toOptionalTrimmedString(response?.userHandle) || null;
  const authenticatorAttachment =
    credential?.authenticatorAttachment === null
      ? null
      : toOptionalTrimmedString(credential?.authenticatorAttachment) || null;
  if (!id || !rawId || type !== 'public-key') return null;
  if (!clientDataJSON || !authenticatorData || !signature) return null;
  return {
    id,
    rawId,
    type,
    authenticatorAttachment,
    response: {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    },
    clientExtensionResults: credential?.clientExtensionResults ?? null,
  };
}

function parseD1RevokeWalletAuthMethodTarget(
  input: unknown,
): D1RevokeWalletAuthMethodTarget | null {
  const record = toRecordValue(input);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind === 'passkey') {
    const rpId = parseWebAuthnRpId(record.rpId);
    const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
    if (!rpId.ok || !credentialIdB64u || Object.prototype.hasOwnProperty.call(record, 'email')) {
      return null;
    }
    return { kind: 'passkey', rpId: rpId.value, credentialIdB64u };
  }
  if (kind === 'email_otp') {
    const email = toOptionalTrimmedString(record.email).toLowerCase();
    if (
      !email ||
      Object.prototype.hasOwnProperty.call(record, 'rpId') ||
      Object.prototype.hasOwnProperty.call(record, 'credentialIdB64u')
    ) {
      return null;
    }
    return { kind: 'email_otp', email };
  }
  return null;
}

async function resolveD1WebAuthnExistingWalletAuth(input: {
  readonly credential: unknown;
  readonly rpId: WebAuthnRpId;
  readonly walletId: WalletId;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
}): Promise<
  | { readonly ok: true; readonly credentialIdB64u: string }
  | { readonly ok: false; readonly code: string; readonly message: string }
> {
  const credentialId = d1WebAuthnCredentialIdB64uFromCredential(input.credential);
  if (!credentialId.ok) return credentialId;
  const authorizationMethod = await input.walletAuthMethodStore.getPasskey({
    rpId: input.rpId,
    credentialIdB64u: credentialId.credentialIdB64u,
  });
  if (
    !authorizationMethod ||
    authorizationMethod.kind !== 'passkey' ||
    authorizationMethod.walletId !== input.walletId ||
    authorizationMethod.status !== 'active'
  ) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'WebAuthn authorization credential is not active for this wallet',
    };
  }
  return { ok: true, credentialIdB64u: credentialId.credentialIdB64u };
}

function d1RevokeWalletAuthMethodInvalidBody(message: string): D1RevokeWalletAuthMethodBoundary {
  return {
    ok: false,
    result: {
      ok: false,
      code: 'invalid_body',
      message,
    },
  };
}

function parseD1RevokeWalletAuthMethodAuth(input: {
  readonly raw: unknown;
  readonly walletId: WalletId;
}): D1RevokeWalletAuthMethodAuth | null {
  const raw = toRecordValue(input.raw);
  if (!raw) return null;
  const kind = toOptionalTrimmedString(raw.kind);
  if (kind === 'webauthn_assertion') {
    const rpId = parseWebAuthnRpId(raw.rpId);
    if (!rpId.ok) return null;
    return {
      kind: 'webauthn_assertion',
      rpId: rpId.value,
      credential: raw.credential,
    };
  }
  if (kind !== 'app_session') return null;
  const rawPolicy = toRecordValue(raw.policy);
  const target = parseD1RevokeWalletAuthMethodTarget(rawPolicy?.target);
  const expiresAtMs = Math.floor(Number(rawPolicy?.expiresAtMs));
  const permission = toOptionalTrimmedString(rawPolicy?.permission);
  const policyWalletId = walletIdFromString(toOptionalTrimmedString(rawPolicy?.walletId));
  if (
    !rawPolicy ||
    permission !== 'wallet_auth_method_revoke' ||
    !policyWalletId ||
    !target ||
    !Number.isSafeInteger(expiresAtMs)
  ) {
    return null;
  }
  return {
    kind: 'app_session',
    policy: {
      permission: 'wallet_auth_method_revoke',
      walletId: policyWalletId,
      target,
      expiresAtMs,
    },
  };
}
