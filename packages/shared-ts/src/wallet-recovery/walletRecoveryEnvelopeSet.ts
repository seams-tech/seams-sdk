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
import type { RecoveryCodeReservationId } from './recoveryCodeReservation';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import { parseDerivedWalletRecoveryKeyId, WALLET_RECOVERY_CODE_COUNT } from './recoveryCodes';
import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';

/**
 * One recovery-wrapped custody secret, sealed under a key derived from the
 * set's manifest KEK (frozen design: a recovery code wraps a random manifest
 * KEK; it never wraps entries directly). A recovery code covers the whole
 * mixed-wallet key set, so a partial recovery can never promote a replacement
 * credential.
 *
 * Lane scope is present only on lane holder-share entries. The owner entry
 * carries the wallet custody seed, which is wallet-scoped and covers every
 * owner key at once, so it has no lane to name.
 */
export type WalletRecoveryEnvelopeEntry = {
  custodySecretKind: PasskeyCustodySecretKind;
  walletKeyId?: WalletKeyId;
  laneId?: SigningLaneId;
  laneShareEpoch?: LaneShareEpoch;
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
  keyManifestDigestB64u: DigestB64u;
  manifestKekWraps: readonly WalletRecoveryManifestKekWrap[];
  entries: readonly WalletRecoveryEnvelopeEntry[];
  issuedAtMs: number;
  updatedAtMs: number;
};

/** The wallet-scoped owner entry: one seed covering every owner key. */
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

/** A lane holder-share entry, scoped to exactly one lane. */
export function buildLaneHolderShareRecoveryEntry(args: {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  custodySecretKind: Exclude<PasskeyCustodySecretKind, 'wallet_custody_seed_v1'>;
  nonceB64u: EnvelopeNonceB64u;
  wrappedCustodySecretB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
}): WalletRecoveryEnvelopeEntry {
  return {
    custodySecretKind: args.custodySecretKind,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneShareEpoch: args.laneShareEpoch,
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
  keyManifestDigestB64u: DigestB64u;
  manifestKekWraps: readonly WalletRecoveryManifestKekWrap[];
  entries: readonly WalletRecoveryEnvelopeEntry[];
  issuedAtMs: number;
  updatedAtMs: number;
}): WalletRecoveryEnvelopeSetRecord {
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: args.walletId,
    keyManifestDigestB64u: args.keyManifestDigestB64u,
    manifestKekWraps: args.manifestKekWraps,
    entries: args.entries,
    issuedAtMs: args.issuedAtMs,
    updatedAtMs: args.updatedAtMs,
  };
}

const RECOVERY_ENTRY_FIELDS = [
  'walletKeyId',
  'laneId',
  'laneShareEpoch',
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

const RECOVERY_SET_FIELDS = [
  'kind',
  'walletId',
  'keyManifestDigestB64u',
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

function requireCustodySecretKind(value: unknown, label: string): PasskeyCustodySecretKind {
  if (
    value === 'wallet_custody_seed_v1' ||
    value === 'ed25519_lane_holder_share_v1' ||
    value === 'ecdsa_lane_holder_share_v1'
  ) {
    return value;
  }
  throw new Error(`${label} must be a known passkey custody secret kind`);
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
        reservationId: record.reservationId as RecoveryCodeReservationId,
        reservedAtMs,
        reservationExpiresAtMs,
      };
    }
    case 'consumed': {
      if (record.revokedAtMs !== undefined) {
        throw new Error(`${label} cannot be consumed and carry a revoked timestamp`);
      }
      const consumedAtMs = parseUnixMs(record.consumedAtMs, `${label}.consumedAtMs`);
      if (consumedAtMs < issuedAtMs) {
        throw new Error(`${label}.consumedAtMs cannot precede issuance`);
      }
      return { state: 'consumed', issuedAtMs, consumedAtMs };
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
      throw new Error(`${label}.state must be active, consumed, or revoked`);
  }
}

function parseWalletRecoveryEnvelopeEntry(
  raw: unknown,
  label: string,
): WalletRecoveryEnvelopeEntry {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, RECOVERY_ENTRY_FIELDS, label);

  const custodySecretKind = requireCustodySecretKind(
    record.custodySecretKind,
    `${label}.custodySecretKind`,
  );
  const nonceB64u = parseEnvelopeNonceB64u(record.nonceB64u, `${label}.nonceB64u`);
  const wrappedCustodySecretB64u = parseEnvelopeCiphertextB64u(
    record.wrappedCustodySecretB64u,
    `${label}.wrappedCustodySecretB64u`,
  );
  const aadHashB64u = parseDigestField(record.aadHashB64u, `${label}.aadHashB64u`);

  if (custodySecretKind === 'wallet_custody_seed_v1') {
    // Owner custody is wallet-scoped; a lane on the seed entry would imply the
    // seed belongs to one lane, which it never does.
    if (
      record.walletKeyId !== undefined ||
      record.laneId !== undefined ||
      record.laneShareEpoch !== undefined
    ) {
      throw new Error(`${label} is wallet-scoped and cannot carry lane identity`);
    }
    return buildWalletCustodySeedRecoveryEntry({
      nonceB64u,
      wrappedCustodySecretB64u,
      aadHashB64u,
    });
  }

  const walletKeyId = parseWalletKeyId(record.walletKeyId);
  if (!walletKeyId.ok) throw new Error(`${label}.walletKeyId ${walletKeyId.error.message}`);
  const laneId = parseSigningLaneId(record.laneId);
  if (!laneId.ok) throw new Error(`${label}.laneId ${laneId.error.message}`);
  const laneShareEpoch = parseLaneShareEpoch(record.laneShareEpoch);
  if (!laneShareEpoch.ok) {
    throw new Error(`${label}.laneShareEpoch ${laneShareEpoch.error.message}`);
  }

  return buildLaneHolderShareRecoveryEntry({
    walletKeyId: walletKeyId.value,
    laneId: laneId.value,
    laneShareEpoch: laneShareEpoch.value,
    custodySecretKind,
    nonceB64u,
    wrappedCustodySecretB64u,
    aadHashB64u,
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
 * exactly-one-seed rule below plus `keyManifestDigestB64u`, which pins the
 * owner key set the seed must reproduce and is verified where the roots are
 * actually derived. A per-key allow-list here would only restate that weakly.
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
  if (record.manifestKekWraps.length === 0) {
    throw new Error(`${label}.manifestKekWraps must carry at least one recovery-code wrap`);
  }
  if (record.manifestKekWraps.length > WALLET_RECOVERY_CODE_COUNT) {
    throw new Error(
      `${label}.manifestKekWraps cannot exceed ${WALLET_RECOVERY_CODE_COUNT} recovery codes`,
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

  const seenWalletKeyIds = new Set<string>();
  const seenLaneIds = new Set<string>();
  let seedEntries = 0;
  for (const entry of entries) {
    if (entry.custodySecretKind === 'wallet_custody_seed_v1') {
      seedEntries += 1;
      continue;
    }
    const walletKeyId = String(entry.walletKeyId);
    if (seenWalletKeyIds.has(walletKeyId)) {
      throw new Error(`${label}.entries has duplicate walletKeyId ${walletKeyId}`);
    }
    seenWalletKeyIds.add(walletKeyId);
    const laneId = String(entry.laneId);
    if (seenLaneIds.has(laneId)) {
      throw new Error(`${label}.entries has duplicate laneId ${laneId}`);
    }
    seenLaneIds.add(laneId);
  }

  // Exactly one owner seed: zero means recovery cannot restore owner custody,
  // and more than one means two different seeds claim the same wallet.
  if (seedEntries !== 1) {
    throw new Error(
      `${label}.entries must contain exactly one wallet_custody_seed_v1 entry, found ${seedEntries}`,
    );
  }

  const issuedAtMs = parseUnixMs(record.issuedAtMs, `${label}.issuedAtMs`);
  const updatedAtMs = parseUnixMs(record.updatedAtMs, `${label}.updatedAtMs`);
  if (updatedAtMs < issuedAtMs) {
    throw new Error(`${label}.updatedAtMs cannot precede issuedAtMs`);
  }

  return buildWalletRecoveryEnvelopeSetRecord({
    walletId: walletId.value,
    keyManifestDigestB64u: parseDigestField(
      record.keyManifestDigestB64u,
      `${label}.keyManifestDigestB64u`,
    ),
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
