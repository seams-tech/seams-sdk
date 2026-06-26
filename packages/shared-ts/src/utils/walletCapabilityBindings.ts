import {
  formatWebAuthnRpIdForWire,
  parseWalletId,
  parseWebAuthnRpId,
  type WalletId,
  type WebAuthnRpId,
} from './domainIds';
import {
  parseImplicitNearAccountId,
  parseNamedNearAccountId,
  type ImplicitNearAccountId,
  type NamedNearAccountId,
} from './near';
import {
  nearEd25519SigningKeyIdFromString,
  type NearEd25519SigningKeyId,
} from './registrationIntent';

export type { WebAuthnRpId };
export type RpId = WebAuthnRpId;

export type WalletIdentity = {
  readonly walletId: WalletId;
};

export type PasskeyAuthScope = {
  readonly wallet: WalletIdentity;
  readonly rpId: RpId;
};

export type WalletAuthMethodBinding =
  | {
      readonly kind: 'passkey';
      readonly scope: PasskeyAuthScope;
      readonly credentialIdB64u: string;
    }
  | {
      readonly kind: 'email_otp';
      readonly wallet: WalletIdentity;
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly rpId?: never;
    };

export type CurrentWalletAuthMethod =
  | {
      readonly kind: 'none';
    }
  | {
      readonly kind: 'selected';
      readonly binding: WalletAuthMethodBinding;
    };

export type NearAccountBinding =
  | {
      readonly kind: 'implicit_near_account';
      readonly wallet: WalletIdentity;
      readonly nearAccountId: ImplicitNearAccountId;
    }
  | {
      readonly kind: 'named_near_account';
      readonly wallet: WalletIdentity;
      readonly nearAccountId: NamedNearAccountId;
    };

export type NearEd25519SignerBinding = {
  readonly kind: 'near_ed25519_signer';
  readonly account: NearAccountBinding;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly signerSlot: number;
};

export type WalletCapabilityBindingParseError = {
  readonly code: 'missing' | 'invalid';
  readonly message: string;
};

export type WalletCapabilityBindingParseResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: WalletCapabilityBindingParseError };

function objectRecord(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  return raw as Record<string, unknown>;
}

function trimString(raw: unknown): string {
  return typeof raw === 'string' ? raw.trim() : '';
}

function parseStringField(
  raw: unknown,
  fieldName: string,
): WalletCapabilityBindingParseResult<string> {
  const value = trimString(raw);
  if (!value) {
    return {
      ok: false,
      error: { code: 'missing', message: `${fieldName} is required` },
    };
  }
  return { ok: true, value };
}

function parseSignerSlot(raw: unknown): WalletCapabilityBindingParseResult<number> {
  const signerSlot = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'signerSlot must be an integer >= 1',
      },
    };
  }
  return { ok: true, value: signerSlot };
}

function missingObject(typeName: string): WalletCapabilityBindingParseResult<never> {
  return {
    ok: false,
    error: { code: 'invalid', message: `${typeName} must be an object` },
  };
}

export function parseRpId(raw: unknown): WalletCapabilityBindingParseResult<RpId> {
  const parsed = parseWebAuthnRpId(raw);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  return { ok: true, value: parsed.value };
}

export function formatRpIdForWire(value: RpId): string {
  return formatWebAuthnRpIdForWire(value);
}

export function walletIdentityFromRaw(
  raw: unknown,
): WalletCapabilityBindingParseResult<WalletIdentity> {
  const record = objectRecord(raw);
  if (!record) return missingObject('WalletIdentity');
  const parsed = parseWalletId(record.walletId);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  return { ok: true, value: { walletId: parsed.value } };
}

export function buildWalletIdentity(args: { walletId: WalletId }): WalletIdentity {
  return { walletId: args.walletId };
}

export function passkeyAuthScopeFromRaw(
  raw: unknown,
): WalletCapabilityBindingParseResult<PasskeyAuthScope> {
  const record = objectRecord(raw);
  if (!record) return missingObject('PasskeyAuthScope');
  const wallet = walletIdentityFromRaw(record.wallet);
  if (!wallet.ok) return wallet;
  const rpId = parseRpId(record.rpId);
  if (!rpId.ok) return rpId;
  return { ok: true, value: { wallet: wallet.value, rpId: rpId.value } };
}

export function buildPasskeyAuthScope(args: {
  wallet: WalletIdentity;
  rpId: RpId;
}): PasskeyAuthScope {
  return { wallet: args.wallet, rpId: args.rpId };
}

export function buildPasskeyWalletAuthMethodBinding(args: {
  scope: PasskeyAuthScope;
  credentialIdB64u: string;
}): WalletAuthMethodBinding {
  const credentialIdB64u = trimString(args.credentialIdB64u);
  if (!credentialIdB64u) throw new Error('credentialIdB64u is required');
  return {
    kind: 'passkey',
    scope: args.scope,
    credentialIdB64u,
  };
}

export function buildEmailOtpWalletAuthMethodBinding(args: {
  wallet: WalletIdentity;
  emailHashHex: string;
  registrationAuthorityId: string;
}): WalletAuthMethodBinding {
  const emailHashHex = trimString(args.emailHashHex);
  const registrationAuthorityId = trimString(args.registrationAuthorityId);
  if (!emailHashHex) throw new Error('emailHashHex is required');
  if (!registrationAuthorityId) throw new Error('registrationAuthorityId is required');
  return {
    kind: 'email_otp',
    wallet: args.wallet,
    emailHashHex,
    registrationAuthorityId,
  };
}

export function walletAuthMethodBindingFromRaw(
  raw: unknown,
): WalletCapabilityBindingParseResult<WalletAuthMethodBinding> {
  const record = objectRecord(raw);
  if (!record) return missingObject('WalletAuthMethodBinding');
  const kind = trimString(record.kind);
  if (kind === 'passkey') {
    const scope = passkeyAuthScopeFromRaw(record.scope);
    if (!scope.ok) return scope;
    const credentialIdB64u = parseStringField(record.credentialIdB64u, 'credentialIdB64u');
    if (!credentialIdB64u.ok) return credentialIdB64u;
    return {
      ok: true,
      value: buildPasskeyWalletAuthMethodBinding({
        scope: scope.value,
        credentialIdB64u: credentialIdB64u.value,
      }),
    };
  }
  if (kind === 'email_otp') {
    if ('rpId' in record && trimString(record.rpId)) {
      return {
        ok: false,
        error: { code: 'invalid', message: 'Email OTP auth-method binding must not include rpId' },
      };
    }
    const wallet = walletIdentityFromRaw(record.wallet);
    if (!wallet.ok) return wallet;
    const emailHashHex = parseStringField(record.emailHashHex, 'emailHashHex');
    if (!emailHashHex.ok) return emailHashHex;
    const registrationAuthorityId = parseStringField(
      record.registrationAuthorityId,
      'registrationAuthorityId',
    );
    if (!registrationAuthorityId.ok) return registrationAuthorityId;
    return {
      ok: true,
      value: buildEmailOtpWalletAuthMethodBinding({
        wallet: wallet.value,
        emailHashHex: emailHashHex.value,
        registrationAuthorityId: registrationAuthorityId.value,
      }),
    };
  }
  return {
    ok: false,
    error: { code: 'invalid', message: 'WalletAuthMethodBinding kind is invalid' },
  };
}

export function currentWalletAuthMethodFromRaw(
  raw: unknown,
): WalletCapabilityBindingParseResult<CurrentWalletAuthMethod> {
  const record = objectRecord(raw);
  if (!record) return missingObject('CurrentWalletAuthMethod');
  const kind = trimString(record.kind);
  if (kind === 'none') return { ok: true, value: { kind: 'none' } };
  if (kind !== 'selected') {
    return {
      ok: false,
      error: { code: 'invalid', message: 'CurrentWalletAuthMethod kind is invalid' },
    };
  }
  const binding = walletAuthMethodBindingFromRaw(record.binding);
  if (!binding.ok) return binding;
  return { ok: true, value: { kind: 'selected', binding: binding.value } };
}

export function buildNoCurrentWalletAuthMethod(): Extract<
  CurrentWalletAuthMethod,
  { kind: 'none' }
> {
  return { kind: 'none' };
}

export function buildSelectedCurrentWalletAuthMethod(args: {
  binding: WalletAuthMethodBinding;
}): Extract<CurrentWalletAuthMethod, { kind: 'selected' }> {
  return { kind: 'selected', binding: args.binding };
}

export function buildImplicitNearAccountBinding(args: {
  wallet: WalletIdentity;
  nearAccountId: ImplicitNearAccountId;
}): NearAccountBinding {
  return {
    kind: 'implicit_near_account',
    wallet: args.wallet,
    nearAccountId: args.nearAccountId,
  };
}

export function buildNamedNearAccountBinding(args: {
  wallet: WalletIdentity;
  nearAccountId: NamedNearAccountId;
}): NearAccountBinding {
  return {
    kind: 'named_near_account',
    wallet: args.wallet,
    nearAccountId: args.nearAccountId,
  };
}

export function nearAccountBindingFromRaw(
  raw: unknown,
): WalletCapabilityBindingParseResult<NearAccountBinding> {
  const record = objectRecord(raw);
  if (!record) return missingObject('NearAccountBinding');
  const wallet = walletIdentityFromRaw(record.wallet);
  if (!wallet.ok) return wallet;
  const kind = trimString(record.kind);
  if (kind === 'implicit_near_account') {
    const nearAccountId = parseImplicitNearAccountId(record.nearAccountId);
    if (!nearAccountId.ok) {
      return {
        ok: false,
        error: { code: nearAccountId.code, message: nearAccountId.message },
      };
    }
    return {
      ok: true,
      value: buildImplicitNearAccountBinding({
        wallet: wallet.value,
        nearAccountId: nearAccountId.value,
      }),
    };
  }
  if (kind === 'named_near_account') {
    const nearAccountId = parseNamedNearAccountId(record.nearAccountId);
    if (!nearAccountId.ok) {
      return {
        ok: false,
        error: { code: nearAccountId.code, message: nearAccountId.message },
      };
    }
    return {
      ok: true,
      value: buildNamedNearAccountBinding({
        wallet: wallet.value,
        nearAccountId: nearAccountId.value,
      }),
    };
  }
  return {
    ok: false,
    error: { code: 'invalid', message: 'NearAccountBinding kind is invalid' },
  };
}

export function buildNearEd25519SignerBinding(args: {
  account: NearAccountBinding;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
}): NearEd25519SignerBinding {
  const signerSlot = parseSignerSlot(args.signerSlot);
  if (!signerSlot.ok) throw new Error(signerSlot.error.message);
  return {
    kind: 'near_ed25519_signer',
    account: args.account,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    signerSlot: signerSlot.value,
  };
}

export function nearEd25519SignerBindingFromRaw(
  raw: unknown,
): WalletCapabilityBindingParseResult<NearEd25519SignerBinding> {
  const record = objectRecord(raw);
  if (!record) return missingObject('NearEd25519SignerBinding');
  const account = nearAccountBindingFromRaw(record.account);
  if (!account.ok) return account;
  const keyScopeRaw = parseStringField(record.nearEd25519SigningKeyId, 'nearEd25519SigningKeyId');
  if (!keyScopeRaw.ok) return keyScopeRaw;
  const signerSlot = parseSignerSlot(record.signerSlot);
  if (!signerSlot.ok) return signerSlot;
  return {
    ok: true,
    value: buildNearEd25519SignerBinding({
      account: account.value,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(keyScopeRaw.value),
      signerSlot: signerSlot.value,
    }),
  };
}
