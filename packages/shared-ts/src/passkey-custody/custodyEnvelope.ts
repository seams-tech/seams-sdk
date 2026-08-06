import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import {
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

export const PASSKEY_CUSTODY_ENVELOPE_VERSION_V1 = 'passkey_custody_envelope_v1' as const;
export const PASSKEY_PRF_KEK_VERSION_V1 = 'passkey_prf_kek_hkdf_sha256_v1' as const;

export type PasskeyCustodyEnvelopeVersion = typeof PASSKEY_CUSTODY_ENVELOPE_VERSION_V1;
export type PasskeyPrfKekVersion = typeof PASSKEY_PRF_KEK_VERSION_V1;

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
 * Ciphertext plus public binding data for one passkey-sealed custody secret.
 *
 * This record carries no authorization identity: no `AuthorizationGrantRef`,
 * `WalletSessionId`, `MpcWalletSigningQuotaId`, `AuthorizedOperationId`, or
 * bearer session. Those are resolved per operation at the Refactor 90 boundary.
 * It also carries no `MpcMaterialActivationRef` — activation identity is bound
 * when opened material enters the canonical activation boundary, so an explicit
 * reactivation can mint a fresh activation id without rewriting this envelope.
 */
export type PasskeyCustodyEnvelopeRecord = {
  kind: 'passkey_custody_envelope_v1';
  envelopeId: PasskeyEnvelopeId;
  walletId: WalletId;
  binding: PasskeyCustodySecretBinding;
  rpId: WebAuthnRpId;
  credentialIdB64u: WebAuthnCredentialIdB64u;
  passkeyEnvelopeVersion: PasskeyCustodyEnvelopeVersion;
  passkeyKekVersion: PasskeyPrfKekVersion;
  envelopeRevision: EnvelopeRevision;
  nonceB64u: EnvelopeNonceB64u;
  sealedCustodySecretB64u: EnvelopeCiphertextB64u;
  ciphertextDigestB64u: DigestB64u;
  aadHashB64u: DigestB64u;
  lifecycle: PasskeyCustodyEnvelopeLifecycle;
  createdAtMs: number;
  updatedAtMs: number;
};

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
  binding: PasskeyCustodySecretBinding;
  rpId: WebAuthnRpId;
  credentialIdB64u: WebAuthnCredentialIdB64u;
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
    kind: 'passkey_custody_envelope_v1',
    envelopeId: args.envelopeId,
    walletId: args.walletId,
    binding: args.binding,
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
    passkeyEnvelopeVersion: PASSKEY_CUSTODY_ENVELOPE_VERSION_V1,
    passkeyKekVersion: PASSKEY_PRF_KEK_VERSION_V1,
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

const ENVELOPE_RECORD_FIELDS = [
  'kind',
  'envelopeId',
  'walletId',
  'binding',
  'rpId',
  'credentialIdB64u',
  'passkeyEnvelopeVersion',
  'passkeyKekVersion',
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
  label = 'passkeyCustodyEnvelope',
): PasskeyCustodyEnvelopeRecord {
  const record = requireRecord(raw, label);
  if (record.kind !== PASSKEY_CUSTODY_ENVELOPE_VERSION_V1) {
    throw new Error(`${label}.kind must be ${PASSKEY_CUSTODY_ENVELOPE_VERSION_V1}`);
  }
  rejectUnknownFields(record, ENVELOPE_RECORD_FIELDS, label);

  if (record.passkeyEnvelopeVersion !== PASSKEY_CUSTODY_ENVELOPE_VERSION_V1) {
    throw new Error(
      `${label}.passkeyEnvelopeVersion must be ${PASSKEY_CUSTODY_ENVELOPE_VERSION_V1}`,
    );
  }
  if (record.passkeyKekVersion !== PASSKEY_PRF_KEK_VERSION_V1) {
    throw new Error(`${label}.passkeyKekVersion must be ${PASSKEY_PRF_KEK_VERSION_V1}`);
  }

  const envelopeId = parsePasskeyEnvelopeId(record.envelopeId);
  if (!envelopeId.ok) throw new Error(`${label}.envelopeId ${envelopeId.error.message}`);
  const walletId = parseWalletId(record.walletId);
  if (!walletId.ok) throw new Error(`${label}.walletId ${walletId.error.message}`);
  const rpId = parseWebAuthnRpId(record.rpId);
  if (!rpId.ok) throw new Error(`${label}.rpId ${rpId.error.message}`);
  const credentialIdB64u = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
  if (!credentialIdB64u.ok) {
    throw new Error(`${label}.credentialIdB64u ${credentialIdB64u.error.message}`);
  }

  const createdAtMs = parseUnixMs(record.createdAtMs, `${label}.createdAtMs`);
  const updatedAtMs = parseUnixMs(record.updatedAtMs, `${label}.updatedAtMs`);
  if (updatedAtMs < createdAtMs) {
    throw new Error(`${label}.updatedAtMs cannot precede createdAtMs`);
  }

  return buildPasskeyCustodyEnvelopeRecord({
    envelopeId: envelopeId.value,
    walletId: walletId.value,
    binding: parsePasskeyCustodySecretBinding(record.binding, `${label}.binding`),
    rpId: rpId.value,
    credentialIdB64u: credentialIdB64u.value,
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
