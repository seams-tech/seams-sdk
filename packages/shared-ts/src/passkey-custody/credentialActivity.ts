/**
 * What a user sees when managing the credentials that open their wallet.
 *
 * Purely descriptive: a label they chose and when the credential was last
 * used. It is a *sibling* of the custody envelope, never a field on it —
 * the envelope's AAD covers its own fields, so folding a mutable label into it
 * would mean renaming a device rewrapped custody, and a failed rename could
 * leave a wallet unopenable.
 *
 * It carries no secret, no authorization identity, and nothing that decides
 * anything. Revocation reads the envelope's lifecycle, not this; a record that
 * could withhold or grant access would be a second, weaker gate on custody.
 */

export type WalletCredentialActivityRecordV1 = {
  readonly kind: 'wallet_credential_activity_v1';
  readonly walletId: string;
  /** The envelope this describes. One record per envelope. */
  readonly envelopeId: string;
  /**
   * The user's name for the device. Absent until they set one — a blank label
   * is not a name, and inventing "iPhone" from a user agent would present a
   * guess as something they chose.
   */
  readonly label?: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  /**
   * When custody was last opened with this credential. Absent when it has not
   * been used since registration, which is different from "used at
   * registration time" and should read that way in a list.
   */
  readonly lastUsedAtMs?: number;
  /** How many times, for a user deciding whether a credential is stale. */
  readonly useCount: number;
};

export const MAX_WALLET_CREDENTIAL_LABEL_LENGTH = 64;

export type WalletCredentialActivityParseResult =
  | { readonly ok: true; readonly record: WalletCredentialActivityRecordV1 }
  | { readonly ok: false; readonly reason: string };

export function parseWalletCredentialActivityRecordV1(
  raw: unknown,
  options: { readonly expectedWalletId: string },
): WalletCredentialActivityParseResult {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: 'credential activity record must be an object' };
  }
  const record = raw as Record<string, unknown>;
  if (record.kind !== 'wallet_credential_activity_v1') {
    return { ok: false, reason: 'credential activity record kind is invalid' };
  }

  const walletId = trimmed(record.walletId);
  const envelopeId = trimmed(record.envelopeId);
  if (!walletId || !envelopeId) {
    return { ok: false, reason: 'credential activity record must name its wallet and envelope' };
  }
  /* Bound to the wallet the caller asked for, never to what the row says: a
     row stored under one wallet that names another is a mislabelled device in
     someone else's credential list. */
  if (walletId !== String(options.expectedWalletId).trim()) {
    return { ok: false, reason: 'credential activity record is outside the authenticated wallet' };
  }

  const createdAtMs = timestamp(record.createdAtMs);
  const updatedAtMs = timestamp(record.updatedAtMs);
  if (createdAtMs === null || updatedAtMs === null) {
    return { ok: false, reason: 'credential activity record needs valid timestamps' };
  }

  const useCount = record.useCount;
  if (typeof useCount !== 'number' || !Number.isInteger(useCount) || useCount < 0) {
    return { ok: false, reason: 'credential activity useCount must be a non-negative integer' };
  }

  let lastUsedAtMs: number | undefined;
  if (record.lastUsedAtMs !== undefined && record.lastUsedAtMs !== null) {
    const parsed = timestamp(record.lastUsedAtMs);
    if (parsed === null) {
      return { ok: false, reason: 'credential activity lastUsedAtMs is invalid' };
    }
    lastUsedAtMs = parsed;
  }
  /* A count with no last-use, or a last-use with no count, describes a history
     that cannot have happened — and it is how a partial write shows up. */
  if (useCount > 0 !== (lastUsedAtMs !== undefined)) {
    return { ok: false, reason: 'credential activity useCount and lastUsedAtMs disagree' };
  }

  const label = normalizeLabel(record.label);
  if (label === 'invalid') {
    return { ok: false, reason: 'credential activity label is too long' };
  }

  return {
    ok: true,
    record: {
      kind: 'wallet_credential_activity_v1',
      walletId,
      envelopeId,
      ...(label === undefined ? {} : { label }),
      createdAtMs,
      updatedAtMs,
      ...(lastUsedAtMs === undefined ? {} : { lastUsedAtMs }),
      useCount,
    },
  };
}

/** Records one use of a credential, for the list the user reads. */
export function recordWalletCredentialUseV1(
  record: WalletCredentialActivityRecordV1,
  usedAtMs: number,
): WalletCredentialActivityRecordV1 {
  // Monotonic: an out-of-order or replayed report must not move the clock
  // backwards, which would read as a credential going unused.
  const lastUsedAtMs = Math.max(usedAtMs, record.lastUsedAtMs ?? 0);
  return {
    ...record,
    lastUsedAtMs,
    useCount: record.useCount + 1,
    updatedAtMs: Math.max(usedAtMs, record.updatedAtMs),
  };
}

function trimmed(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function timestamp(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}

function normalizeLabel(value: unknown): string | undefined | 'invalid' {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') return 'invalid';
  const label = value.trim();
  if (!label) return undefined;
  if (label.length > MAX_WALLET_CREDENTIAL_LABEL_LENGTH) return 'invalid';
  return label;
}
