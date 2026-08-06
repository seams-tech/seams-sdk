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
import { parseDerivedWalletRecoveryKeyId, WALLET_RECOVERY_CODE_COUNT } from './recoveryCodes';
import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';

/**
 * One recovery-wrapped custody secret, sealed under a key derived from the
 * set's manifest KEK (frozen design: a recovery code wraps a random manifest
 * KEK; it never wraps entries directly). Entries are wallet-scoped: a recovery
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
