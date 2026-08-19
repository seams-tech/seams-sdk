/**
 * Refactor 103 Phase 8 — the exact relationship between one linked-device
 * enrollment and the canonical owner auth method that enrollment created.
 *
 * Device 2 becomes an ordinary owner credential while keeping its narrow
 * linked execution grant (R103C: the grant describes per-device execution and
 * revocation, not the human's status). Everything downstream — unlock, Wallet
 * Session issuance, signing, step-up, export, management, revocation —
 * resolves the device through this binding rather than through the
 * target-credential registration. The binding therefore has to carry every
 * identity those paths compare, and it has to make a disagreement
 * unrepresentable rather than merely unlikely:
 *
 *   tenant -> wallet -> device -> enrollment -> WalletAuthMethodId
 *          -> exact Passkey credential or Email OTP factor
 *          -> verified key-manifest identity
 *          -> lifecycle and revocation state
 *
 * The `WalletAuthMethodId` is never accepted from a caller. It is derived from
 * the factor identity through the same canonical formatter the wallet
 * auth-method table's CHECK constraint encodes, so a binding cannot name one
 * credential and point at another.
 */
import {
  buildEmailOtpWalletAuthMethodBinding,
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildWalletIdentity,
  walletAuthMethodBindingId,
} from '../utils/walletCapabilityBindings';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '../utils/domainIds';
import { parseTenantId, type TenantId } from '../authorization/capabilityKinds';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
} from '../signing-lanes/ids';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { parseUnixMs, requireRecord, rejectUnknownFields } from '../passkey-custody/primitives';

/**
 * The exact factor identity behind one linked-owner credential. A Passkey
 * branch cannot carry Email OTP identity and an Email OTP branch cannot carry
 * WebAuthn identity — the `never` fields are what stops a spread-built record
 * from smuggling the wrong half across.
 *
 * The Email OTP branch names two identities on purpose. The *base* factor
 * (`baseWalletAuthMethodId`, the wallet-wide `email_otp:<wallet>:<hash>` row)
 * answers which email authority authenticates the wallet; it is shared by
 * every linked device enrolled through that email and survives each of them.
 * The derived linked-owner id on the binding is the *principal*: unique per
 * enrollment, so two devices sharing one email never share owner scope,
 * lanes, Wallet Sessions, or revocation identity.
 */
export type LinkedOwnerAuthFactorV1 =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly emailHashHex?: never;
      readonly registrationAuthorityId?: never;
      readonly baseWalletAuthMethodId?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly baseWalletAuthMethodId: WalletAuthMethodId;
      readonly rpId?: never;
      readonly credentialIdB64u?: never;
    };

/**
 * Three states a person can act on, not five a store can be in. `paused`
 * fences use while keeping the device visible and resumable; `revoked` is
 * terminal and fences use permanently.
 */
export type LinkedOwnerAuthBindingLifecycleV1 =
  | {
      readonly state: 'active';
      readonly activatedAtMs: number;
      readonly pausedAtMs?: never;
      readonly revokedAtMs?: never;
    }
  | {
      readonly state: 'paused';
      readonly activatedAtMs: number;
      readonly pausedAtMs: number;
      readonly revokedAtMs?: never;
    }
  | {
      readonly state: 'revoked';
      readonly activatedAtMs: number;
      readonly revokedAtMs: number;
      readonly pausedAtMs?: never;
    };

export type LinkedDeviceOwnerAuthBindingV1 = {
  readonly kind: 'linked_device_owner_auth_binding_v1';
  readonly tenantId: TenantId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly factor: LinkedOwnerAuthFactorV1;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly lifecycle: LinkedOwnerAuthBindingLifecycleV1;
  readonly revocationEpoch: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

export type LinkedOwnerAuthBindingTransitionErrorV1 =
  | { readonly code: 'already_revoked' }
  | { readonly code: 'already_paused' }
  | { readonly code: 'not_paused' }
  | { readonly code: 'timestamp_regressed' };

export type LinkedOwnerAuthBindingTransitionResultV1 =
  | { readonly ok: true; readonly binding: LinkedDeviceOwnerAuthBindingV1 }
  | { readonly ok: false; readonly error: LinkedOwnerAuthBindingTransitionErrorV1 };

const BINDING_FIELDS = [
  'kind',
  'tenantId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'walletAuthMethodId',
  'factor',
  'keyManifestDigestB64u',
  'lifecycle',
  'revocationEpoch',
  'createdAtMs',
  'updatedAtMs',
] as const;

const PASSKEY_FACTOR_FIELDS = ['kind', 'rpId', 'credentialIdB64u'] as const;
const EMAIL_OTP_FACTOR_FIELDS = [
  'kind',
  'emailHashHex',
  'registrationAuthorityId',
  'baseWalletAuthMethodId',
] as const;
const EMAIL_HASH_HEX_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The canonical wallet-wide Email OTP auth-method id an email factor is
 * derived from — the row the linked binding's foreign reference points at.
 * Routed through the shared formatter so it is byte-identical to the id
 * wallet registration writes and the `wallet_auth_methods` CHECK recomputes.
 */
export function linkedOwnerEmailOtpBaseAuthMethodIdV1(input: {
  readonly walletId: WalletId;
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
}): WalletAuthMethodId {
  return walletAuthMethodBindingId(
    buildEmailOtpWalletAuthMethodBinding({
      wallet: buildWalletIdentity({ walletId: input.walletId }),
      emailHashHex: input.emailHashHex,
      registrationAuthorityId: input.registrationAuthorityId,
    }),
  );
}

/**
 * The one place a linked owner credential's `WalletAuthMethodId` is produced.
 *
 * Passkey ids route through the shared canonical formatter — each credential
 * is already unique per device, so the credential id is the identity.
 *
 * Email OTP ids are derived from the wallet, enrollment, device, and base
 * factor, mirrored byte-for-byte by the `linked_device_owner_auth_bindings`
 * CHECK constraint. Wallet + email hash alone is deliberately NOT the
 * identity: that tuple names the shared base factor, and reusing it would
 * make two linked devices enrolled through one email a single revocable
 * principal.
 */
export function linkedOwnerAuthMethodIdV1(input: {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly factor: LinkedOwnerAuthFactorV1;
}): WalletAuthMethodId {
  switch (input.factor.kind) {
    case 'passkey':
      return walletAuthMethodBindingId(
        buildPasskeyWalletAuthMethodBinding({
          scope: buildPasskeyAuthScope({
            wallet: buildWalletIdentity({ walletId: input.walletId }),
            rpId: input.factor.rpId,
          }),
          credentialIdB64u: input.factor.credentialIdB64u,
        }),
      );
    case 'email_otp': {
      const canonicalBase = linkedOwnerEmailOtpBaseAuthMethodIdV1({
        walletId: input.walletId,
        emailHashHex: input.factor.emailHashHex,
        registrationAuthorityId: input.factor.registrationAuthorityId,
      });
      if (input.factor.baseWalletAuthMethodId !== canonicalBase) {
        throw new Error(
          'LinkedOwnerAuthFactorV1.baseWalletAuthMethodId does not name this wallet email factor',
        );
      }
      return requireLinkedOwnerAuthMethodId(
        `email_otp_linked:${String(input.walletId)}:${String(input.enrollmentId)}:${String(
          input.deviceId,
        )}:${input.factor.emailHashHex}`,
      );
    }
  }
  input.factor satisfies never;
  throw new Error('LinkedOwnerAuthFactorV1 kind is unsupported');
}

function requireLinkedOwnerAuthMethodId(raw: string): WalletAuthMethodId {
  const parsed = parseWalletAuthMethodId(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

type LinkedOwnerAuthBindingIdentityInputV1 = {
  readonly tenantId: TenantId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly activatedAtMs: number;
};

function buildActiveBindingV1(
  identity: LinkedOwnerAuthBindingIdentityInputV1,
  factor: LinkedOwnerAuthFactorV1,
): LinkedDeviceOwnerAuthBindingV1 {
  const activatedAtMs = parseUnixMs(
    identity.activatedAtMs,
    'LinkedDeviceOwnerAuthBindingV1.activatedAtMs',
  );
  return {
    kind: 'linked_device_owner_auth_binding_v1',
    tenantId: identity.tenantId,
    walletId: identity.walletId,
    enrollmentId: identity.enrollmentId,
    deviceId: identity.deviceId,
    walletAuthMethodId: linkedOwnerAuthMethodIdV1({
      walletId: identity.walletId,
      enrollmentId: identity.enrollmentId,
      deviceId: identity.deviceId,
      factor,
    }),
    factor,
    keyManifestDigestB64u: identity.keyManifestDigestB64u,
    lifecycle: { state: 'active', activatedAtMs },
    revocationEpoch: 0,
    createdAtMs: activatedAtMs,
    updatedAtMs: activatedAtMs,
  };
}

export function buildLinkedOwnerPasskeyAuthBindingV1(
  input: LinkedOwnerAuthBindingIdentityInputV1 & {
    readonly rpId: WebAuthnRpId;
    readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  },
): LinkedDeviceOwnerAuthBindingV1 {
  return buildActiveBindingV1(input, {
    kind: 'passkey',
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
  });
}

export function buildLinkedOwnerEmailOtpAuthBindingV1(
  input: LinkedOwnerAuthBindingIdentityInputV1 & {
    readonly emailHashHex: string;
    readonly registrationAuthorityId: string;
    readonly baseWalletAuthMethodId: WalletAuthMethodId;
  },
): LinkedDeviceOwnerAuthBindingV1 {
  return buildActiveBindingV1(input, {
    kind: 'email_otp',
    emailHashHex: requireEmailHashHex(input.emailHashHex, 'LinkedOwnerAuthFactorV1.emailHashHex'),
    registrationAuthorityId: requireCanonicalToken(
      input.registrationAuthorityId,
      'LinkedOwnerAuthFactorV1.registrationAuthorityId',
    ),
    // Verified against the canonical wallet-wide derivation inside
    // linkedOwnerAuthMethodIdV1 — a base id naming another wallet's factor
    // cannot produce a binding.
    baseWalletAuthMethodId: input.baseWalletAuthMethodId,
  });
}

/**
 * Pause fences signing without retiring the credential, so the entry stays in
 * management and stays resumable. Revocation is terminal: a revoked binding
 * never returns to a usable state, which is why `pause` refuses it rather than
 * silently succeeding.
 */
export function pauseLinkedOwnerAuthBindingV1(input: {
  readonly binding: LinkedDeviceOwnerAuthBindingV1;
  readonly pausedAtMs: number;
}): LinkedOwnerAuthBindingTransitionResultV1 {
  const pausedAtMs = parseUnixMs(input.pausedAtMs, 'pauseLinkedOwnerAuthBindingV1.pausedAtMs');
  switch (input.binding.lifecycle.state) {
    case 'revoked':
      return { ok: false, error: { code: 'already_revoked' } };
    case 'paused':
      return { ok: false, error: { code: 'already_paused' } };
    case 'active': {
      if (pausedAtMs < input.binding.updatedAtMs) {
        return { ok: false, error: { code: 'timestamp_regressed' } };
      }
      return {
        ok: true,
        binding: withLifecycleV1(input.binding, pausedAtMs, {
          state: 'paused',
          activatedAtMs: input.binding.lifecycle.activatedAtMs,
          pausedAtMs,
        }),
      };
    }
  }
  input.binding.lifecycle satisfies never;
  throw new Error('LinkedOwnerAuthBindingLifecycleV1 state is unsupported');
}

export function resumeLinkedOwnerAuthBindingV1(input: {
  readonly binding: LinkedDeviceOwnerAuthBindingV1;
  readonly resumedAtMs: number;
}): LinkedOwnerAuthBindingTransitionResultV1 {
  const resumedAtMs = parseUnixMs(input.resumedAtMs, 'resumeLinkedOwnerAuthBindingV1.resumedAtMs');
  switch (input.binding.lifecycle.state) {
    case 'revoked':
      return { ok: false, error: { code: 'already_revoked' } };
    case 'active':
      return { ok: false, error: { code: 'not_paused' } };
    case 'paused': {
      if (resumedAtMs < input.binding.updatedAtMs) {
        return { ok: false, error: { code: 'timestamp_regressed' } };
      }
      return {
        ok: true,
        binding: withLifecycleV1(input.binding, resumedAtMs, {
          state: 'active',
          activatedAtMs: input.binding.lifecycle.activatedAtMs,
        }),
      };
    }
  }
  input.binding.lifecycle satisfies never;
  throw new Error('LinkedOwnerAuthBindingLifecycleV1 state is unsupported');
}

/**
 * Revocation advances the epoch. Every fenced consumer compares the epoch it
 * was admitted under against the current one, so advancing it is what makes an
 * already-issued Wallet Session stop being honoured.
 */
export function revokeLinkedOwnerAuthBindingV1(input: {
  readonly binding: LinkedDeviceOwnerAuthBindingV1;
  readonly revokedAtMs: number;
}): LinkedOwnerAuthBindingTransitionResultV1 {
  const revokedAtMs = parseUnixMs(input.revokedAtMs, 'revokeLinkedOwnerAuthBindingV1.revokedAtMs');
  if (input.binding.lifecycle.state === 'revoked') {
    return { ok: false, error: { code: 'already_revoked' } };
  }
  if (revokedAtMs < input.binding.updatedAtMs) {
    return { ok: false, error: { code: 'timestamp_regressed' } };
  }
  const revoked = withLifecycleV1(input.binding, revokedAtMs, {
    state: 'revoked',
    activatedAtMs: input.binding.lifecycle.activatedAtMs,
    revokedAtMs,
  });
  return {
    ok: true,
    binding: {
      kind: revoked.kind,
      tenantId: revoked.tenantId,
      walletId: revoked.walletId,
      enrollmentId: revoked.enrollmentId,
      deviceId: revoked.deviceId,
      walletAuthMethodId: revoked.walletAuthMethodId,
      factor: revoked.factor,
      keyManifestDigestB64u: revoked.keyManifestDigestB64u,
      lifecycle: revoked.lifecycle,
      revocationEpoch: revoked.revocationEpoch + 1,
      createdAtMs: revoked.createdAtMs,
      updatedAtMs: revoked.updatedAtMs,
    },
  };
}

/** True while the binding may authorize an owner operation. */
export function linkedOwnerAuthBindingAdmitsUseV1(
  binding: LinkedDeviceOwnerAuthBindingV1,
): boolean {
  return binding.lifecycle.state === 'active';
}

function withLifecycleV1(
  binding: LinkedDeviceOwnerAuthBindingV1,
  updatedAtMs: number,
  lifecycle: LinkedOwnerAuthBindingLifecycleV1,
): LinkedDeviceOwnerAuthBindingV1 {
  return {
    kind: binding.kind,
    tenantId: binding.tenantId,
    walletId: binding.walletId,
    enrollmentId: binding.enrollmentId,
    deviceId: binding.deviceId,
    walletAuthMethodId: binding.walletAuthMethodId,
    factor: binding.factor,
    keyManifestDigestB64u: binding.keyManifestDigestB64u,
    lifecycle,
    revocationEpoch: binding.revocationEpoch,
    createdAtMs: binding.createdAtMs,
    updatedAtMs,
  };
}

/**
 * The single boundary between a persisted row (or a wire body) and the domain
 * type. It re-derives the auth-method id from the factor rather than trusting
 * the stored column, so a row edited to point at another credential fails here
 * instead of authorizing that credential.
 */
export function parseLinkedDeviceOwnerAuthBindingV1(raw: unknown): LinkedDeviceOwnerAuthBindingV1 {
  const record = requireRecord(raw, 'LinkedDeviceOwnerAuthBindingV1');
  rejectUnknownFields(record, BINDING_FIELDS, 'LinkedDeviceOwnerAuthBindingV1');
  for (const requiredField of BINDING_FIELDS) {
    if (record[requiredField] === undefined) {
      throw new Error(`LinkedDeviceOwnerAuthBindingV1.${requiredField} is required`);
    }
  }
  if (record.kind !== 'linked_device_owner_auth_binding_v1') {
    throw new Error('LinkedDeviceOwnerAuthBindingV1.kind is invalid');
  }
  const walletId = requireParsed(
    parseWalletId(record.walletId),
    'LinkedDeviceOwnerAuthBindingV1.walletId',
  );
  const enrollmentId = requireParsed(
    parseLinkedDeviceEnrollmentId(record.enrollmentId),
    'LinkedDeviceOwnerAuthBindingV1.enrollmentId',
  );
  const deviceId = requireParsed(
    parseLinkedDeviceId(record.deviceId),
    'LinkedDeviceOwnerAuthBindingV1.deviceId',
  );
  const factor = parseLinkedOwnerAuthFactorV1(record.factor);
  const walletAuthMethodId = requireParsed(
    parseWalletAuthMethodId(record.walletAuthMethodId),
    'LinkedDeviceOwnerAuthBindingV1.walletAuthMethodId',
  );
  const derived = linkedOwnerAuthMethodIdV1({ walletId, enrollmentId, deviceId, factor });
  if (walletAuthMethodId !== derived) {
    throw new Error(
      'LinkedDeviceOwnerAuthBindingV1.walletAuthMethodId does not match its factor identity',
    );
  }
  const createdAtMs = parseUnixMs(record.createdAtMs, 'LinkedDeviceOwnerAuthBindingV1.createdAtMs');
  const updatedAtMs = parseUnixMs(record.updatedAtMs, 'LinkedDeviceOwnerAuthBindingV1.updatedAtMs');
  if (updatedAtMs < createdAtMs) {
    throw new Error('LinkedDeviceOwnerAuthBindingV1.updatedAtMs precedes createdAtMs');
  }
  const lifecycle = parseLinkedOwnerAuthBindingLifecycleV1(record.lifecycle, createdAtMs);
  const revocationEpoch = parseRevocationEpoch(record.revocationEpoch);
  if (lifecycle.state === 'revoked' && revocationEpoch < 1) {
    throw new Error('LinkedDeviceOwnerAuthBindingV1 revoked binding requires a revocation epoch');
  }
  return {
    kind: 'linked_device_owner_auth_binding_v1',
    tenantId: requireParsed(
      parseTenantId(record.tenantId),
      'LinkedDeviceOwnerAuthBindingV1.tenantId',
    ),
    walletId,
    enrollmentId,
    deviceId,
    walletAuthMethodId,
    factor,
    keyManifestDigestB64u: parseKeyManifestDigest(record.keyManifestDigestB64u),
    lifecycle,
    revocationEpoch,
    createdAtMs,
    updatedAtMs,
  };
}

export function parseLinkedOwnerAuthFactorV1(raw: unknown): LinkedOwnerAuthFactorV1 {
  const record = requireRecord(raw, 'LinkedOwnerAuthFactorV1');
  switch (record.kind) {
    case 'passkey': {
      rejectUnknownFields(
        record,
        PASSKEY_FACTOR_FIELDS,
        'LinkedOwnerAuthFactorV1',
        EMAIL_OTP_FACTOR_FIELDS,
      );
      return {
        kind: 'passkey',
        rpId: requireParsed(parseWebAuthnRpId(record.rpId), 'LinkedOwnerAuthFactorV1.rpId'),
        credentialIdB64u: requireParsed(
          parseWebAuthnCredentialIdB64u(record.credentialIdB64u),
          'LinkedOwnerAuthFactorV1.credentialIdB64u',
        ),
      };
    }
    case 'email_otp': {
      rejectUnknownFields(
        record,
        EMAIL_OTP_FACTOR_FIELDS,
        'LinkedOwnerAuthFactorV1',
        PASSKEY_FACTOR_FIELDS,
      );
      return {
        kind: 'email_otp',
        emailHashHex: requireEmailHashHex(
          record.emailHashHex,
          'LinkedOwnerAuthFactorV1.emailHashHex',
        ),
        registrationAuthorityId: requireCanonicalToken(
          record.registrationAuthorityId,
          'LinkedOwnerAuthFactorV1.registrationAuthorityId',
        ),
        baseWalletAuthMethodId: requireParsed(
          parseWalletAuthMethodId(record.baseWalletAuthMethodId),
          'LinkedOwnerAuthFactorV1.baseWalletAuthMethodId',
        ),
      };
    }
    default:
      throw new Error('LinkedOwnerAuthFactorV1.kind is unsupported');
  }
}

function parseLinkedOwnerAuthBindingLifecycleV1(
  raw: unknown,
  createdAtMs: number,
): LinkedOwnerAuthBindingLifecycleV1 {
  const record = requireRecord(raw, 'LinkedOwnerAuthBindingLifecycleV1');
  const activatedAtMs = parseUnixMs(
    record.activatedAtMs,
    'LinkedOwnerAuthBindingLifecycleV1.activatedAtMs',
  );
  switch (record.state) {
    case 'active':
      rejectUnknownFields(record, ['state', 'activatedAtMs'], 'LinkedOwnerAuthBindingLifecycleV1', [
        'pausedAtMs',
        'revokedAtMs',
      ]);
      return { state: 'active', activatedAtMs };
    case 'paused': {
      rejectUnknownFields(
        record,
        ['state', 'activatedAtMs', 'pausedAtMs'],
        'LinkedOwnerAuthBindingLifecycleV1',
        ['revokedAtMs'],
      );
      const pausedAtMs = parseUnixMs(
        record.pausedAtMs,
        'LinkedOwnerAuthBindingLifecycleV1.pausedAtMs',
      );
      if (pausedAtMs < activatedAtMs || pausedAtMs < createdAtMs) {
        throw new Error('LinkedOwnerAuthBindingLifecycleV1.pausedAtMs precedes activation');
      }
      return { state: 'paused', activatedAtMs, pausedAtMs };
    }
    case 'revoked': {
      rejectUnknownFields(
        record,
        ['state', 'activatedAtMs', 'revokedAtMs'],
        'LinkedOwnerAuthBindingLifecycleV1',
        ['pausedAtMs'],
      );
      const revokedAtMs = parseUnixMs(
        record.revokedAtMs,
        'LinkedOwnerAuthBindingLifecycleV1.revokedAtMs',
      );
      if (revokedAtMs < activatedAtMs || revokedAtMs < createdAtMs) {
        throw new Error('LinkedOwnerAuthBindingLifecycleV1.revokedAtMs precedes activation');
      }
      return { state: 'revoked', activatedAtMs, revokedAtMs };
    }
    default:
      throw new Error('LinkedOwnerAuthBindingLifecycleV1.state is unsupported');
  }
}

function parseKeyManifestDigest(raw: unknown): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(
      `LinkedDeviceOwnerAuthBindingV1.keyManifestDigestB64u ${
        error instanceof Error ? error.message : 'is invalid'
      }`,
    );
  }
}

function parseRevocationEpoch(raw: unknown): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) {
    throw new Error(
      'LinkedDeviceOwnerAuthBindingV1.revocationEpoch must be a non-negative integer',
    );
  }
  return raw;
}

function requireEmailHashHex(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !EMAIL_HASH_HEX_PATTERN.test(raw)) {
    throw new Error(`${label} must be a lowercase 32-byte hex digest`);
  }
  return raw;
}

function requireCanonicalToken(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return raw;
}

function requireParsed<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}
