import type {
  PasskeyEnvelopeId,
  WalletAuthMethodId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import {
  parseWalletAuthMethodId,
  parsePasskeyEnvelopeId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../utils/domainIds';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type { PasskeyCustodySecretBinding } from './custodySecretBinding';
import { parsePasskeyCustodySecretBinding } from './custodySecretBinding';
import type { EnvelopeCiphertextB64u, EnvelopeNonceB64u, EnvelopeRevision } from './primitives';
import {
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parseUnixMs,
  rejectUnknownFields,
  requireRecord,
} from './primitives';

export const WALLET_CUSTODY_ENVELOPE_VERSION_V2 = 'wallet_custody_envelope_v2' as const;
/** Refactor 109C: an envelope whose owning auth method is part of its AAD. */
export const WALLET_CUSTODY_ENVELOPE_VERSION_V3 = 'wallet_custody_envelope_v3' as const;
export const PASSKEY_PRF_KEK_VERSION_V1 = 'passkey_prf_kek_hkdf_sha256_v1' as const;
export const EMAIL_OTP_FACTOR_KEK_VERSION_V1 = 'email_otp_factor_kek_hkdf_sha256_v1' as const;

export type WalletCustodyEnvelopeVersion = typeof WALLET_CUSTODY_ENVELOPE_VERSION_V2;
export type PasskeyPrfKekVersion = typeof PASSKEY_PRF_KEK_VERSION_V1;
export type EmailOtpFactorKekVersion = typeof EMAIL_OTP_FACTOR_KEK_VERSION_V1;

/**
 * Which enrolled factor sealed this envelope.
 *
 * Factors are interchangeable unwrap paths to the same custody seed: each has
 * its own envelope, KEK derivation, and revocation, so enrolling or revoking
 * one never touches another's ciphertext. Factor-specific identity lives inside
 * the branch rather than at the record's top level, which is what stops an
 * Email OTP envelope from carrying an RP ID or a passkey envelope from
 * carrying an enrollment id.
 */
/**
 * Mirrors `signer_core::PasskeyCustodyEnvelopeOwnershipV1`.
 *
 * `method_bound` is the only shape a new envelope may be written in; `unbound`
 * exists to open envelopes sealed before ownership was authenticated, and a
 * successful open is followed by a reseal once the exact method is known. The
 * two encode different AAD, which is what stops a stored envelope from being
 * relabelled to a sibling method.
 */
export type WalletCustodyEnvelopeOwnership =
  | { readonly kind: 'unbound'; readonly walletAuthMethodId?: never }
  | { readonly kind: 'method_bound'; readonly walletAuthMethodId: WalletAuthMethodId };

export type WalletCustodyEnvelopeFactor =
  | {
      kind: 'passkey';
      rpId: WebAuthnRpId;
      credentialIdB64u: WebAuthnCredentialIdB64u;
      kekVersion: PasskeyPrfKekVersion;
      enrollmentId?: never;
      enrollmentSealKeyVersion?: never;
    }
  | {
      kind: 'email_otp';
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      kekVersion: EmailOtpFactorKekVersion;
      rpId?: never;
      credentialIdB64u?: never;
    };

export type WalletCustodyFactorKind = WalletCustodyEnvelopeFactor['kind'];

export type PasskeyCustodyEnvelopeLifecycle =
  | {
      state: 'active';
      activatedAtMs: number;
      retiredAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'retired';
      activatedAtMs: number;
      retiredAtMs: number;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked';
      activatedAtMs: number;
      revokedAtMs: number;
      retiredAtMs?: never;
    };

/**
 * Ciphertext plus public binding data for one factor-sealed custody secret.
 *
 * This record carries no authorization identity: no `AuthorizationGrantRef`,
 * `WalletSessionId`, `MpcWalletSigningQuotaId`, `AuthorizedOperationId`, or
 * bearer session. Those are resolved per operation at the Refactor 90 boundary.
 * It also carries no `MpcMaterialActivationRef` — activation identity is bound
 * when opened material enters the canonical activation boundary, so an explicit
 * reactivation can mint a fresh activation id without rewriting this envelope.
 */
export type PasskeyCustodyEnvelopeRecord = {
  kind: 'wallet_custody_envelope_v2';
  envelopeId: PasskeyEnvelopeId;
  walletId: WalletId;
  /** Which auth method owns this envelope, and whether that is authenticated. */
  ownership: WalletCustodyEnvelopeOwnership;
  binding: PasskeyCustodySecretBinding;
  factor: WalletCustodyEnvelopeFactor;
  envelopeVersion: WalletCustodyEnvelopeVersion;
  envelopeRevision: EnvelopeRevision;
  nonceB64u: EnvelopeNonceB64u;
  sealedCustodySecretB64u: EnvelopeCiphertextB64u;
  ciphertextDigestB64u: DigestB64u;
  aadHashB64u: DigestB64u;
  lifecycle: PasskeyCustodyEnvelopeLifecycle;
  createdAtMs: number;
  updatedAtMs: number;
};

const ENVELOPE_OWNERSHIP_FIELDS = ['kind', 'walletAuthMethodId'] as const;

export function parseWalletCustodyEnvelopeOwnership(
  raw: unknown,
  label: string,
): WalletCustodyEnvelopeOwnership {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  const record = raw as Record<string, unknown>;
  rejectUnknownFields(record, ENVELOPE_OWNERSHIP_FIELDS, label);
  switch (record.kind) {
    case 'unbound':
      if (record.walletAuthMethodId !== undefined) {
        throw new Error(`${label}.walletAuthMethodId belongs to the method_bound branch`);
      }
      return { kind: 'unbound' };
    case 'method_bound': {
      const parsed = parseWalletAuthMethodId(record.walletAuthMethodId);
      if (!parsed.ok) {
        throw new Error(`${label}.walletAuthMethodId ${parsed.error.message}`);
      }
      return { kind: 'method_bound', walletAuthMethodId: parsed.value };
    }
    default:
      throw new Error(`${label}.kind must be unbound or method_bound`);
  }
}

/**
 * The exact JSON `signer_core::PasskeyCustodyEnvelopeBindingV1` deserialises.
 *
 * Every caller that hands a binding to wasm must build it here. The Rust struct
 * uses `deny_unknown_fields` and now requires `ownership`, so a hand-rolled
 * object that omits it fails to deserialise — and that failure surfaces as an
 * unopenable envelope, not a type error.
 */
export function custodyEnvelopeBindingJsonV1(
  envelope: Pick<
    PasskeyCustodyEnvelopeRecord,
    'walletId' | 'envelopeId' | 'factor' | 'envelopeRevision' | 'binding' | 'ownership'
  >,
): string {
  return JSON.stringify({
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    factor: envelope.factor,
    envelopeRevision: envelope.envelopeRevision,
    binding: envelope.binding,
    ownership: custodyEnvelopeOwnershipWireV1(envelope.ownership),
  });
}

/**
 * Reads the serde shape back — the inverse of `custodyEnvelopeOwnershipWireV1`.
 *
 * The record shape and the wire shape are deliberately different: one is
 * TypeScript's tagged union, the other is what `serde` emits for a Rust enum.
 * Anything that came out of wasm carries the wire shape, and passing it to the
 * record parser would reject a perfectly valid ownership for having no `kind`.
 */
export function parseWalletCustodyEnvelopeOwnershipWireV1(
  raw: unknown,
  label: string,
): WalletCustodyEnvelopeOwnership {
  if (raw === 'unbound') return { kind: 'unbound' };
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${label} must be "unbound" or a methodBound object`);
  }
  const record = raw as Record<string, unknown>;
  rejectUnknownFields(record, ['methodBound'], label);
  const methodBound = record.methodBound;
  if (typeof methodBound !== 'object' || methodBound === null || Array.isArray(methodBound)) {
    throw new Error(`${label}.methodBound must be an object`);
  }
  const fields = methodBound as Record<string, unknown>;
  rejectUnknownFields(fields, ['walletAuthMethodId'], `${label}.methodBound`);
  const parsed = parseWalletAuthMethodId(fields.walletAuthMethodId);
  if (!parsed.ok) {
    throw new Error(`${label}.methodBound.walletAuthMethodId ${parsed.error.message}`);
  }
  return { kind: 'method_bound', walletAuthMethodId: parsed.value };
}

/** Serde's shape for the ownership enum: a bare string, or a one-key object. */
export function custodyEnvelopeOwnershipWireV1(ownership: WalletCustodyEnvelopeOwnership): unknown {
  switch (ownership.kind) {
    case 'unbound':
      return 'unbound';
    case 'method_bound':
      return { methodBound: { walletAuthMethodId: String(ownership.walletAuthMethodId) } };
    default:
      throw new Error(`Unhandled custody envelope ownership: ${String(ownership)}`);
  }
}

export function buildMethodBoundEnvelopeOwnership(
  walletAuthMethodId: WalletAuthMethodId,
): WalletCustodyEnvelopeOwnership {
  return { kind: 'method_bound', walletAuthMethodId };
}

export function buildPasskeyEnvelopeFactor(args: {
  rpId: WebAuthnRpId;
  credentialIdB64u: WebAuthnCredentialIdB64u;
}): Extract<WalletCustodyEnvelopeFactor, { readonly kind: 'passkey' }> {
  return {
    kind: 'passkey',
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
    kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
  };
}

export function buildEmailOtpEnvelopeFactor(args: {
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
}): Extract<WalletCustodyEnvelopeFactor, { readonly kind: 'email_otp' }> {
  return {
    kind: 'email_otp',
    enrollmentId: args.enrollmentId,
    enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
    kekVersion: EMAIL_OTP_FACTOR_KEK_VERSION_V1,
  };
}

export function buildActiveEnvelopeLifecycle(args: {
  activatedAtMs: number;
}): PasskeyCustodyEnvelopeLifecycle {
  return { state: 'active', activatedAtMs: args.activatedAtMs };
}

export function buildRetiredEnvelopeLifecycle(args: {
  activatedAtMs: number;
  retiredAtMs: number;
}): PasskeyCustodyEnvelopeLifecycle {
  return {
    state: 'retired',
    activatedAtMs: args.activatedAtMs,
    retiredAtMs: args.retiredAtMs,
  };
}

export function buildRevokedEnvelopeLifecycle(args: {
  activatedAtMs: number;
  revokedAtMs: number;
}): PasskeyCustodyEnvelopeLifecycle {
  return {
    state: 'revoked',
    activatedAtMs: args.activatedAtMs,
    revokedAtMs: args.revokedAtMs,
  };
}

export function buildPasskeyCustodyEnvelopeRecord(args: {
  envelopeId: PasskeyEnvelopeId;
  walletId: WalletId;
  ownership: WalletCustodyEnvelopeOwnership;
  binding: PasskeyCustodySecretBinding;
  factor: WalletCustodyEnvelopeFactor;
  envelopeRevision: EnvelopeRevision;
  nonceB64u: EnvelopeNonceB64u;
  sealedCustodySecretB64u: EnvelopeCiphertextB64u;
  ciphertextDigestB64u: DigestB64u;
  aadHashB64u: DigestB64u;
  lifecycle: PasskeyCustodyEnvelopeLifecycle;
  createdAtMs: number;
  updatedAtMs: number;
}): PasskeyCustodyEnvelopeRecord {
  return {
    kind: 'wallet_custody_envelope_v2',
    envelopeId: args.envelopeId,
    walletId: args.walletId,
    ownership: args.ownership,
    binding: args.binding,
    factor: args.factor,
    envelopeVersion: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
    envelopeRevision: args.envelopeRevision,
    nonceB64u: args.nonceB64u,
    sealedCustodySecretB64u: args.sealedCustodySecretB64u,
    ciphertextDigestB64u: args.ciphertextDigestB64u,
    aadHashB64u: args.aadHashB64u,
    lifecycle: args.lifecycle,
    createdAtMs: args.createdAtMs,
    updatedAtMs: args.updatedAtMs,
  };
}

const ENVELOPE_LIFECYCLE_FIELDS = ['state', 'activatedAtMs', 'retiredAtMs', 'revokedAtMs'] as const;

export function parsePasskeyCustodyEnvelopeLifecycle(
  raw: unknown,
  label = 'lifecycle',
): PasskeyCustodyEnvelopeLifecycle {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, ENVELOPE_LIFECYCLE_FIELDS, label);
  const activatedAtMs = parseUnixMs(record.activatedAtMs, `${label}.activatedAtMs`);
  switch (record.state) {
    case 'active':
      if (record.retiredAtMs !== undefined || record.revokedAtMs !== undefined) {
        throw new Error(`${label} cannot be active and carry a retired or revoked timestamp`);
      }
      return buildActiveEnvelopeLifecycle({ activatedAtMs });
    case 'retired': {
      if (record.revokedAtMs !== undefined) {
        throw new Error(`${label} cannot be retired and carry a revoked timestamp`);
      }
      const retiredAtMs = parseUnixMs(record.retiredAtMs, `${label}.retiredAtMs`);
      if (retiredAtMs < activatedAtMs) {
        throw new Error(`${label}.retiredAtMs cannot precede activation`);
      }
      return buildRetiredEnvelopeLifecycle({ activatedAtMs, retiredAtMs });
    }
    case 'revoked': {
      if (record.retiredAtMs !== undefined) {
        throw new Error(`${label} cannot be revoked and carry a retired timestamp`);
      }
      const revokedAtMs = parseUnixMs(record.revokedAtMs, `${label}.revokedAtMs`);
      if (revokedAtMs < activatedAtMs) {
        throw new Error(`${label}.revokedAtMs cannot precede activation`);
      }
      return buildRevokedEnvelopeLifecycle({ activatedAtMs, revokedAtMs });
    }
    default:
      throw new Error(`${label}.state must be active, retired, or revoked`);
  }
}

const PASSKEY_FACTOR_FIELDS = ['kind', 'rpId', 'credentialIdB64u', 'kekVersion'] as const;
const EMAIL_OTP_FACTOR_FIELDS = [
  'kind',
  'enrollmentId',
  'enrollmentSealKeyVersion',
  'kekVersion',
] as const;
const ALL_FACTOR_FIELDS: readonly string[] = Array.from(
  new Set([...PASSKEY_FACTOR_FIELDS, ...EMAIL_OTP_FACTOR_FIELDS]),
);

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value;
}

export function parseWalletCustodyEnvelopeFactor(
  raw: unknown,
  label = 'factor',
): WalletCustodyEnvelopeFactor {
  const record = requireRecord(raw, label);
  switch (record.kind) {
    case 'passkey': {
      rejectUnknownFields(record, PASSKEY_FACTOR_FIELDS, label, ALL_FACTOR_FIELDS);
      if (record.kekVersion !== PASSKEY_PRF_KEK_VERSION_V1) {
        throw new Error(`${label}.kekVersion must be ${PASSKEY_PRF_KEK_VERSION_V1}`);
      }
      const rpId = parseWebAuthnRpId(record.rpId);
      if (!rpId.ok) throw new Error(`${label}.rpId ${rpId.error.message}`);
      const credentialIdB64u = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
      if (!credentialIdB64u.ok) {
        throw new Error(`${label}.credentialIdB64u ${credentialIdB64u.error.message}`);
      }
      return buildPasskeyEnvelopeFactor({
        rpId: rpId.value,
        credentialIdB64u: credentialIdB64u.value,
      });
    }
    case 'email_otp': {
      rejectUnknownFields(record, EMAIL_OTP_FACTOR_FIELDS, label, ALL_FACTOR_FIELDS);
      if (record.kekVersion !== EMAIL_OTP_FACTOR_KEK_VERSION_V1) {
        throw new Error(`${label}.kekVersion must be ${EMAIL_OTP_FACTOR_KEK_VERSION_V1}`);
      }
      return buildEmailOtpEnvelopeFactor({
        enrollmentId: requireNonEmptyString(record.enrollmentId, `${label}.enrollmentId`),
        enrollmentSealKeyVersion: requireNonEmptyString(
          record.enrollmentSealKeyVersion,
          `${label}.enrollmentSealKeyVersion`,
        ),
      });
    }
    default:
      throw new Error(`${label}.kind must be passkey or email_otp`);
  }
}

const ENVELOPE_RECORD_FIELDS = [
  'kind',
  'envelopeId',
  'walletId',
  'ownership',
  'binding',
  'factor',
  'envelopeVersion',
  'envelopeRevision',
  'nonceB64u',
  'sealedCustodySecretB64u',
  'ciphertextDigestB64u',
  'aadHashB64u',
  'lifecycle',
  'createdAtMs',
  'updatedAtMs',
] as const;

/**
 * Parses one raw server row, wire payload, or IndexedDB cache entry into the
 * exact envelope record. This is the single boundary: core custody code accepts
 * `PasskeyCustodyEnvelopeRecord`, never a raw shape.
 */
export function parsePasskeyCustodyEnvelopeRecord(
  raw: unknown,
  label = 'walletCustodyEnvelope',
): PasskeyCustodyEnvelopeRecord {
  const record = requireRecord(raw, label);
  if (record.kind !== WALLET_CUSTODY_ENVELOPE_VERSION_V2) {
    throw new Error(`${label}.kind must be ${WALLET_CUSTODY_ENVELOPE_VERSION_V2}`);
  }
  rejectUnknownFields(record, ENVELOPE_RECORD_FIELDS, label);

  if (record.envelopeVersion !== WALLET_CUSTODY_ENVELOPE_VERSION_V2) {
    throw new Error(`${label}.envelopeVersion must be ${WALLET_CUSTODY_ENVELOPE_VERSION_V2}`);
  }

  const envelopeId = parsePasskeyEnvelopeId(record.envelopeId);
  if (!envelopeId.ok) throw new Error(`${label}.envelopeId ${envelopeId.error.message}`);
  const walletId = parseWalletId(record.walletId);
  if (!walletId.ok) throw new Error(`${label}.walletId ${walletId.error.message}`);
  const ownership = parseWalletCustodyEnvelopeOwnership(record.ownership, `${label}.ownership`);

  const createdAtMs = parseUnixMs(record.createdAtMs, `${label}.createdAtMs`);
  const updatedAtMs = parseUnixMs(record.updatedAtMs, `${label}.updatedAtMs`);
  if (updatedAtMs < createdAtMs) {
    throw new Error(`${label}.updatedAtMs cannot precede createdAtMs`);
  }

  return buildPasskeyCustodyEnvelopeRecord({
    envelopeId: envelopeId.value,
    walletId: walletId.value,
    ownership,
    binding: parsePasskeyCustodySecretBinding(record.binding, `${label}.binding`),
    factor: parseWalletCustodyEnvelopeFactor(record.factor, `${label}.factor`),
    envelopeRevision: parseEnvelopeRevision(record.envelopeRevision, `${label}.envelopeRevision`),
    nonceB64u: parseEnvelopeNonceB64u(record.nonceB64u, `${label}.nonceB64u`),
    sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      record.sealedCustodySecretB64u,
      `${label}.sealedCustodySecretB64u`,
    ),
    ciphertextDigestB64u: parseDigestField(
      record.ciphertextDigestB64u,
      `${label}.ciphertextDigestB64u`,
    ),
    aadHashB64u: parseDigestField(record.aadHashB64u, `${label}.aadHashB64u`),
    lifecycle: parsePasskeyCustodyEnvelopeLifecycle(record.lifecycle, `${label}.lifecycle`),
    createdAtMs,
    updatedAtMs,
  });
}

export function isActivePasskeyCustodyEnvelope(envelope: PasskeyCustodyEnvelopeRecord): boolean {
  return envelope.lifecycle.state === 'active';
}

/** Two ownerships name the same owner. */
export function sameWalletCustodyEnvelopeOwnership(
  left: WalletCustodyEnvelopeOwnership,
  right: WalletCustodyEnvelopeOwnership,
): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'unbound') return true;
  return (
    right.kind === 'method_bound' &&
    String(left.walletAuthMethodId) === String(right.walletAuthMethodId)
  );
}

export type WalletCustodyEnvelopeOwnershipReplacementAdmissionV1 =
  | { readonly kind: 'admitted' }
  | { readonly kind: 'refused'; readonly reason: string };

/**
 * Whether a stored envelope's ownership may be replaced by another.
 *
 * Two rules, and both are load-bearing. A replacement is always `method_bound`,
 * because no path may write a new V2 envelope — `unbound` exists only to decode
 * what was sealed before ownership was authenticated. And a stored owner may
 * only be replaced by itself: an envelope already bound to one method is never
 * rebound to a sibling, which is the whole point of putting the owner in the
 * AAD. That leaves exactly one transition that moves anything — the pre-109C
 * upgrade, `unbound` to the method that just proved it can open the envelope.
 */
export function admitWalletCustodyEnvelopeOwnershipReplacementV1(input: {
  readonly stored: WalletCustodyEnvelopeOwnership;
  readonly replacement: WalletCustodyEnvelopeOwnership;
}): WalletCustodyEnvelopeOwnershipReplacementAdmissionV1 {
  if (input.replacement.kind === 'unbound') {
    return {
      kind: 'refused',
      reason: 'a replacement custody envelope must name its owning method',
    };
  }
  switch (input.stored.kind) {
    case 'unbound':
      return { kind: 'admitted' };
    case 'method_bound':
      return String(input.stored.walletAuthMethodId) ===
        String(input.replacement.walletAuthMethodId)
        ? { kind: 'admitted' }
        : {
            kind: 'refused',
            reason: 'a custody envelope owned by one auth method is never rebound to another',
          };
    default:
      return { kind: 'refused', reason: 'unhandled stored custody envelope ownership' };
  }
}
