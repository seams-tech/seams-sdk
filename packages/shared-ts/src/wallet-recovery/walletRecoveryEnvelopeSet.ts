import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import { parseLaneShareEpoch, parseSigningLaneId, parseWalletKeyId } from '../signing-lanes/ids';
import type { WalletId } from '../utils/domainIds';
import { parseWalletId } from '../utils/domainIds';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type {
  EnvelopeCiphertextB64u,
  EnvelopeNonceB64u,
  PasskeyCustodySecretKind,
} from '../passkey-custody';
import {
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseUnixMs,
  rejectUnknownFields,
  requireRecord,
} from '../passkey-custody';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from './recoveryCodeReservation';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import { parseDerivedWalletRecoveryKeyId, WALLET_RECOVERY_CODE_COUNT } from './recoveryCodes';
import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';

/**
 * The recovery-wrapped wallet custody seed, sealed under a key derived from the
 * set's manifest KEK (frozen design: a recovery code wraps a random manifest
 * KEK; it never wraps entries directly). One seed covers every owner key, so a
 * partial recovery can never promote a replacement credential.
 *
 * Lane holder shares are deliberately absent. A linked device's share is sealed
 * under that device's own factor, so it never depended on the owner credential
 * and survives owner recovery untouched; including it here would instead let an
 * owner recovery code reconstruct that device's material. A lost lane is
 * revoked and reprovisioned through Refactor 102, not recovered.
 */
export type WalletRecoveryEnvelopeEntry = {
  custodySecretKind: 'wallet_custody_seed_v1';
  nonceB64u: EnvelopeNonceB64u;
  wrappedCustodySecretB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
};

/**
 * One recovery code's wrap of the set's manifest KEK. Ten of these are issued
 * with the set; consuming or revoking a code touches only its wrap, never the
 * entry ciphertexts. The wrapped payload is a 32-byte KEK, never custody
 * material, a recovery code, or a code digest.
 */
export type WalletRecoveryManifestKekWrap = {
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  nonceB64u: EnvelopeNonceB64u;
  wrappedManifestKekB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
  lifecycle: RecoveryCodeLifecycleState;
};

export type WalletRecoveryEnvelopeSetRecord = {
  kind: 'wallet_recovery_envelope_set_v1';
  walletId: WalletId;
  /**
   * No key manifest digest. A set wraps the wallet's seed, and key sets are
   * provisioned independently with their own manifests, so there is no
   * wallet-level manifest for a set to name. Rotating one key set no longer
   * invalidates the seed the set wraps.
   */
  manifestKekWraps: readonly WalletRecoveryManifestKekWrap[];
  entries: readonly WalletRecoveryEnvelopeEntry[];
  issuedAtMs: number;
  updatedAtMs: number;
};

export function buildWalletCustodySeedRecoveryEntry(args: {
  nonceB64u: EnvelopeNonceB64u;
  wrappedCustodySecretB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
}): WalletRecoveryEnvelopeEntry {
  return {
    custodySecretKind: 'wallet_custody_seed_v1',
    nonceB64u: args.nonceB64u,
    wrappedCustodySecretB64u: args.wrappedCustodySecretB64u,
    aadHashB64u: args.aadHashB64u,
  };
}

export function buildWalletRecoveryManifestKekWrap(args: {
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  nonceB64u: EnvelopeNonceB64u;
  wrappedManifestKekB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
  lifecycle: RecoveryCodeLifecycleState;
}): WalletRecoveryManifestKekWrap {
  return {
    recoveryKeyId: args.recoveryKeyId,
    nonceB64u: args.nonceB64u,
    wrappedManifestKekB64u: args.wrappedManifestKekB64u,
    aadHashB64u: args.aadHashB64u,
    lifecycle: args.lifecycle,
  };
}

export function buildWalletRecoveryEnvelopeSetRecord(args: {
  walletId: WalletId;
  manifestKekWraps: readonly WalletRecoveryManifestKekWrap[];
  entries: readonly WalletRecoveryEnvelopeEntry[];
  issuedAtMs: number;
  updatedAtMs: number;
}): WalletRecoveryEnvelopeSetRecord {
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: args.walletId,
    manifestKekWraps: args.manifestKekWraps,
    entries: args.entries,
    issuedAtMs: args.issuedAtMs,
    updatedAtMs: args.updatedAtMs,
  };
}

function parseRecoveryCodeLifecycleState(raw: unknown, label: string): RecoveryCodeLifecycleState {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, RECOVERY_LIFECYCLE_FIELDS, label);
  const issuedAtMs = parseUnixMs(record.issuedAtMs, `${label}.issuedAtMs`);
  switch (record.state) {
    case 'active':
      if (record.consumedAtMs !== undefined || record.revokedAtMs !== undefined) {
        throw new Error(`${label} cannot be active and carry a consumed or revoked timestamp`);
      }
      if (record.reservationId !== undefined) {
        throw new Error(`${label} cannot be active and hold a reservation`);
      }
      return { state: 'active', issuedAtMs };
    case 'reserved': {
      if (record.consumedAtMs !== undefined || record.revokedAtMs !== undefined) {
        throw new Error(`${label} cannot be reserved and carry a consumed or revoked timestamp`);
      }
      if (typeof record.reservationId !== 'string' || !record.reservationId) {
        throw new Error(`${label}.reservationId is required while reserved`);
      }
      const reservedAtMs = parseUnixMs(record.reservedAtMs, `${label}.reservedAtMs`);
      const reservationExpiresAtMs = parseUnixMs(
        record.reservationExpiresAtMs,
        `${label}.reservationExpiresAtMs`,
      );
      if (reservedAtMs < issuedAtMs) {
        throw new Error(`${label}.reservedAtMs cannot precede issuance`);
      }
      if (reservationExpiresAtMs <= reservedAtMs) {
        throw new Error(`${label}.reservationExpiresAtMs must follow reservedAtMs`);
      }
      return {
        state: 'reserved',
        issuedAtMs,
        reservationId: parseRecoveryCodeReservationId(record.reservationId),
        reservedAtMs,
        reservationExpiresAtMs,
      };
    }
    case 'consumed': {
      if (record.revokedAtMs !== undefined) {
        throw new Error(`${label} cannot be consumed and carry a revoked timestamp`);
      }
      if (typeof record.reservationId !== 'string' || !record.reservationId) {
        throw new Error(`${label}.reservationId is required after consumption`);
      }
      const consumedAtMs = parseUnixMs(record.consumedAtMs, `${label}.consumedAtMs`);
      if (consumedAtMs < issuedAtMs) {
        throw new Error(`${label}.consumedAtMs cannot precede issuance`);
      }
      return {
        state: 'consumed',
        issuedAtMs,
        reservationId: parseRecoveryCodeReservationId(record.reservationId),
        consumedAtMs,
      };
    }
    case 'revoked': {
      if (record.consumedAtMs !== undefined) {
        throw new Error(`${label} cannot be revoked and carry a consumed timestamp`);
      }
      const revokedAtMs = parseUnixMs(record.revokedAtMs, `${label}.revokedAtMs`);
      if (revokedAtMs < issuedAtMs) {
        throw new Error(`${label}.revokedAtMs cannot precede issuance`);
      }
      return { state: 'revoked', issuedAtMs, revokedAtMs };
    }
    default:
      throw new Error(`${label}.state must be active, reserved, consumed, or revoked`);
  }
}

const RECOVERY_ENTRY_FIELDS = [
  'custodySecretKind',
  'nonceB64u',
  'wrappedCustodySecretB64u',
  'aadHashB64u',
] as const;

const MANIFEST_KEK_WRAP_FIELDS = [
  'recoveryKeyId',
  'nonceB64u',
  'wrappedManifestKekB64u',
  'aadHashB64u',
  'lifecycle',
] as const;

/* No `keyManifestDigestB64u`. The manifest moved onto each key set's own
   registration state, so a set carrying one is a record written by a retired
   design — accepting and silently dropping it is a compatibility path, and
   `rejectUnknownFields` now says so. */
const RECOVERY_SET_FIELDS = [
  'kind',
  'walletId',
  'manifestKekWraps',
  'entries',
  'issuedAtMs',
  'updatedAtMs',
] as const;

const RECOVERY_LIFECYCLE_FIELDS = [
  'state',
  'issuedAtMs',
  'reservationId',
  'reservedAtMs',
  'reservationExpiresAtMs',
  'consumedAtMs',
  'revokedAtMs',
] as const;

function parseWalletRecoveryEnvelopeEntry(
  raw: unknown,
  label: string,
): WalletRecoveryEnvelopeEntry {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, RECOVERY_ENTRY_FIELDS, label);

  // Only the wallet custody seed is recoverable. A lane kind here means the
  // caller expects owner recovery to restore a linked device's material, which
  // it deliberately never does.
  if (record.custodySecretKind !== 'wallet_custody_seed_v1') {
    throw new Error(
      `${label}.custodySecretKind must be wallet_custody_seed_v1; lane holder shares are reprovisioned, not recovered`,
    );
  }

  return buildWalletCustodySeedRecoveryEntry({
    nonceB64u: parseEnvelopeNonceB64u(record.nonceB64u, `${label}.nonceB64u`),
    wrappedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      record.wrappedCustodySecretB64u,
      `${label}.wrappedCustodySecretB64u`,
    ),
    aadHashB64u: parseDigestField(record.aadHashB64u, `${label}.aadHashB64u`),
  });
}

function parseWalletRecoveryManifestKekWrap(
  raw: unknown,
  label: string,
): WalletRecoveryManifestKekWrap {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, MANIFEST_KEK_WRAP_FIELDS, label);

  return buildWalletRecoveryManifestKekWrap({
    recoveryKeyId: parseDerivedWalletRecoveryKeyId(record.recoveryKeyId, `${label}.recoveryKeyId`),
    nonceB64u: parseEnvelopeNonceB64u(record.nonceB64u, `${label}.nonceB64u`),
    wrappedManifestKekB64u: parseEnvelopeCiphertextB64u(
      record.wrappedManifestKekB64u,
      `${label}.wrappedManifestKekB64u`,
    ),
    aadHashB64u: parseDigestField(record.aadHashB64u, `${label}.aadHashB64u`),
    lifecycle: parseRecoveryCodeLifecycleState(record.lifecycle, `${label}.lifecycle`),
  });
}

/**
 * Parses one recovery envelope set against the authenticated wallet.
 *
 * `expectedWalletId` is required: a recovery set is only meaningful inside the
 * wallet whose recovery request is being served.
 *
 * Owner coverage is no longer a per-key list. Under single-seed custody the
 * owner entry is one seed covering every owner key, so completeness is the
 * exactly-one-seed rule below. The key manifest that pins which keys the seed
 * must reproduce lives on each key set's own registration state and is
 * verified where the roots are derived — it is deliberately not a field here.
 */
export function parseWalletRecoveryEnvelopeSetRecord(
  raw: unknown,
  options: {
    expectedWalletId: WalletId;
    label?: string;
  },
): WalletRecoveryEnvelopeSetRecord {
  const label = options.label || 'walletRecoveryEnvelopeSet';
  const record = requireRecord(raw, label);
  if (record.kind !== 'wallet_recovery_envelope_set_v1') {
    throw new Error(`${label}.kind must be wallet_recovery_envelope_set_v1`);
  }
  rejectUnknownFields(record, RECOVERY_SET_FIELDS, label);

  const walletId = parseWalletId(record.walletId);
  if (!walletId.ok) throw new Error(`${label}.walletId ${walletId.error.message}`);
  if (String(walletId.value) !== String(options.expectedWalletId)) {
    throw new Error(`${label}.walletId is outside the authenticated wallet`);
  }

  if (!Array.isArray(record.manifestKekWraps)) {
    throw new Error(`${label}.manifestKekWraps must be an array`);
  }
  /* Exactly ten, not one-to-ten. Establishment issues ten and the durable
     invariant keeps ten lifecycle records — a consumed or revoked code keeps
     its wrap and changes its lifecycle state rather than disappearing. So a
     set with fewer rows is a set that lost some, and accepting it would let a
     wallet look recoverable while silently holding fewer codes than its owner
     wrote down. */
  if (record.manifestKekWraps.length !== WALLET_RECOVERY_CODE_COUNT) {
    throw new Error(
      `${label}.manifestKekWraps must carry exactly ${WALLET_RECOVERY_CODE_COUNT} recovery-code wraps`,
    );
  }

  const manifestKekWraps = record.manifestKekWraps.map((wrap, index) =>
    parseWalletRecoveryManifestKekWrap(wrap, `${label}.manifestKekWraps[${index}]`),
  );

  const seenRecoveryKeyIds = new Set<string>();
  for (const wrap of manifestKekWraps) {
    const recoveryKeyId = String(wrap.recoveryKeyId);
    if (seenRecoveryKeyIds.has(recoveryKeyId)) {
      throw new Error(`${label}.manifestKekWraps has duplicate recoveryKeyId ${recoveryKeyId}`);
    }
    seenRecoveryKeyIds.add(recoveryKeyId);
  }

  if (!Array.isArray(record.entries)) {
    throw new Error(`${label}.entries must be an array`);
  }
  if (record.entries.length === 0) {
    throw new Error(`${label}.entries must cover at least one wallet key`);
  }

  const entries = record.entries.map((entry, index) =>
    parseWalletRecoveryEnvelopeEntry(entry, `${label}.entries[${index}]`),
  );

  // Exactly one entry, and it is the seed: zero cannot restore owner custody,
  // and more than one means rival seeds claim the same wallet.
  if (entries.length !== 1) {
    throw new Error(
      `${label}.entries must contain exactly one wallet_custody_seed_v1 entry, found ${entries.length}`,
    );
  }

  const issuedAtMs = parseUnixMs(record.issuedAtMs, `${label}.issuedAtMs`);
  const updatedAtMs = parseUnixMs(record.updatedAtMs, `${label}.updatedAtMs`);
  if (updatedAtMs < issuedAtMs) {
    throw new Error(`${label}.updatedAtMs cannot precede issuedAtMs`);
  }

  return buildWalletRecoveryEnvelopeSetRecord({
    walletId: walletId.value,
    manifestKekWraps,
    entries,
    issuedAtMs,
    updatedAtMs,
  });
}

/** A set is openable while at least one recovery-code wrap remains active. */
export function hasOpenableRecoveryCodeWrap(set: WalletRecoveryEnvelopeSetRecord): boolean {
  return set.manifestKekWraps.some((wrap) => wrap.lifecycle.state === 'active');
}
