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
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import { parseDerivedWalletRecoveryKeyId } from './recoveryCodes';
import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';

/**
 * One recovery-wrapped custody secret. Entries are wallet-scoped: a recovery
 * code covers the whole mixed-wallet key set, not one curve at a time, so a
 * partial recovery can never promote a replacement credential.
 */
export type WalletRecoveryEnvelopeEntry = {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  custodySecretKind: PasskeyCustodySecretKind;
  nonceB64u: EnvelopeNonceB64u;
  wrappedCustodySecretB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
};

export type WalletRecoveryEnvelopeSetRecord = {
  kind: 'wallet_recovery_envelope_set_v1';
  walletId: WalletId;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  keyManifestDigestB64u: DigestB64u;
  entries: readonly WalletRecoveryEnvelopeEntry[];
  lifecycle: RecoveryCodeLifecycleState;
  issuedAtMs: number;
  updatedAtMs: number;
};

export function buildWalletRecoveryEnvelopeEntry(args: {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  custodySecretKind: PasskeyCustodySecretKind;
  nonceB64u: EnvelopeNonceB64u;
  wrappedCustodySecretB64u: EnvelopeCiphertextB64u;
  aadHashB64u: DigestB64u;
}): WalletRecoveryEnvelopeEntry {
  return {
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneShareEpoch: args.laneShareEpoch,
    custodySecretKind: args.custodySecretKind,
    nonceB64u: args.nonceB64u,
    wrappedCustodySecretB64u: args.wrappedCustodySecretB64u,
    aadHashB64u: args.aadHashB64u,
  };
}

export function buildWalletRecoveryEnvelopeSetRecord(args: {
  walletId: WalletId;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  keyManifestDigestB64u: DigestB64u;
  entries: readonly WalletRecoveryEnvelopeEntry[];
  lifecycle: RecoveryCodeLifecycleState;
  issuedAtMs: number;
  updatedAtMs: number;
}): WalletRecoveryEnvelopeSetRecord {
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: args.walletId,
    recoveryKeyId: args.recoveryKeyId,
    keyManifestDigestB64u: args.keyManifestDigestB64u,
    entries: args.entries,
    lifecycle: args.lifecycle,
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

const RECOVERY_SET_FIELDS = [
  'kind',
  'walletId',
  'recoveryKeyId',
  'keyManifestDigestB64u',
  'entries',
  'lifecycle',
  'issuedAtMs',
  'updatedAtMs',
] as const;

const RECOVERY_LIFECYCLE_FIELDS = ['state', 'issuedAtMs', 'consumedAtMs', 'revokedAtMs'] as const;

function requireCustodySecretKind(value: unknown, label: string): PasskeyCustodySecretKind {
  if (
    value === 'ed25519_yao_client_root_v1' ||
    value === 'ed25519_lane_holder_share_v1' ||
    value === 'ecdsa_client_root_share_v1' ||
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
      return { state: 'active', issuedAtMs };
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

  const walletKeyId = parseWalletKeyId(record.walletKeyId);
  if (!walletKeyId.ok) throw new Error(`${label}.walletKeyId ${walletKeyId.error.message}`);
  const laneId = parseSigningLaneId(record.laneId);
  if (!laneId.ok) throw new Error(`${label}.laneId ${laneId.error.message}`);
  const laneShareEpoch = parseLaneShareEpoch(record.laneShareEpoch);
  if (!laneShareEpoch.ok) {
    throw new Error(`${label}.laneShareEpoch ${laneShareEpoch.error.message}`);
  }

  return buildWalletRecoveryEnvelopeEntry({
    walletKeyId: walletKeyId.value,
    laneId: laneId.value,
    laneShareEpoch: laneShareEpoch.value,
    custodySecretKind: requireCustodySecretKind(
      record.custodySecretKind,
      `${label}.custodySecretKind`,
    ),
    nonceB64u: parseEnvelopeNonceB64u(record.nonceB64u, `${label}.nonceB64u`),
    wrappedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      record.wrappedCustodySecretB64u,
      `${label}.wrappedCustodySecretB64u`,
    ),
    aadHashB64u: parseDigestField(record.aadHashB64u, `${label}.aadHashB64u`),
  });
}

/**
 * Parses one recovery envelope set against the authenticated wallet.
 *
 * `expectedWalletId` is required: a recovery set is only meaningful inside the
 * wallet whose recovery request is being served. When the caller already knows
 * the active owner key manifest it passes `requiredWalletKeyIds`, and a set that
 * omits any of them is rejected — an incomplete set must never reach the
 * all-or-nothing recovery promotion.
 */
export function parseWalletRecoveryEnvelopeSetRecord(
  raw: unknown,
  options: {
    expectedWalletId: WalletId;
    requiredWalletKeyIds?: readonly WalletKeyId[];
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

  const recoveryKeyId = parseDerivedWalletRecoveryKeyId(
    record.recoveryKeyId,
    `${label}.recoveryKeyId`,
  );

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
  for (const entry of entries) {
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

  for (const required of options.requiredWalletKeyIds || []) {
    if (!seenWalletKeyIds.has(String(required))) {
      throw new Error(`${label}.entries omits required walletKeyId ${String(required)}`);
    }
  }

  const issuedAtMs = parseUnixMs(record.issuedAtMs, `${label}.issuedAtMs`);
  const updatedAtMs = parseUnixMs(record.updatedAtMs, `${label}.updatedAtMs`);
  if (updatedAtMs < issuedAtMs) {
    throw new Error(`${label}.updatedAtMs cannot precede issuedAtMs`);
  }

  return buildWalletRecoveryEnvelopeSetRecord({
    walletId: walletId.value,
    recoveryKeyId,
    keyManifestDigestB64u: parseDigestField(
      record.keyManifestDigestB64u,
      `${label}.keyManifestDigestB64u`,
    ),
    entries,
    lifecycle: parseRecoveryCodeLifecycleState(record.lifecycle, `${label}.lifecycle`),
    issuedAtMs,
    updatedAtMs,
  });
}
