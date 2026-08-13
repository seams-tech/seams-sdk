import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  walletIdFromString,
  type RegistrationAuthority,
  type WebAuthnRpId,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
} from '../../../../core/RegistrationCeremonyStore';
import type {
  WalletAddAuthMethodStartRequest,
  WalletAddSignerStartRequest,
  WalletRegistrationFinalizeAuthMethod,
  WalletRevokeAuthMethodResponse
} from '../../../../core/registrationContracts';
import type {
  WalletAuthMethodRecord,
  WalletAuthMethodStore,
} from '../../../../core/d1WalletAuthMethodStore';
import {
  addAuthMethodInputMatches,
  addSignerSelectionMatches,
  runtimePolicyScopeMatches,
} from '../registration/d1RegistrationCeremonyRecords';
import { toRecordValue } from '../auth/d1RouterApiAuthBoundary';
import type { RevokeWalletAuthMethodCommand } from '../../../framework/authServicePort';
import { webAuthnCredentialIdB64uFromCredential } from '../../../auth/webAuthnCredentialCodecs';

type StartWalletAddSignerInput = WalletAddSignerStartRequest;
type StartWalletAddAuthMethodInput = WalletAddAuthMethodStartRequest;
type RevokeWalletAuthMethodInput = RevokeWalletAuthMethodCommand;
type RevokeWalletAuthMethodResult = WalletRevokeAuthMethodResponse;

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

export function walletAuthAuthorityFromRegistrationAuthority(
  authority: RegistrationAuthority,
): WalletAuthAuthority {
  switch (authority.kind) {
    case 'passkey':
      return buildPasskeyWalletAuthAuthority({
        walletId: authority.walletId,
        rpId: authority.rpId,
        credentialIdB64u: authority.credentialIdB64u,
      });
    case 'email_otp':
      return buildEmailOtpWalletAuthAuthority({
        walletId: authority.walletId,
        provider: authority.proofKind === 'google_sso_registration' ? 'google' : 'email',
        providerUserId: authority.providerSubject,
        emailHashHex: authority.emailHashHex,
      });
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
  const walletId = walletIdFromString(toOptionalTrimmedString(input.subject.walletId));
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
  const authorizationCredentialId = webAuthnCredentialIdB64uFromCredential(input.auth.credential);
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
  if (input.auth.kind === 'email_otp') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Email OTP add-auth authorization requires the wallet auth service boundary',
    };
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
  const credentialId = webAuthnCredentialIdB64uFromCredential(input.credential);
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
