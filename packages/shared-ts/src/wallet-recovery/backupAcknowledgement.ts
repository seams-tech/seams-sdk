/**
 * Whether the user has confirmed they saved their recovery codes.
 *
 * **A sibling of the recovery set, never a field on it.** Acknowledging a
 * backup is a UI action, and the recovery set is the record that gates
 * recovery: putting them together would mean a button press writes to the
 * record holding the wraps, and a version conflict between an acknowledgement
 * and a concurrent code spend would make one of them fail for no reason a user
 * could understand. Worse, a bug in the cosmetic path could corrupt the
 * critical one.
 *
 * It carries no secret and no authority. Nothing consults it to decide whether
 * a recovery may proceed — a user who never acknowledged still has working
 * codes, and one who acknowledged without saving them does not. It exists so
 * the product can stop nagging, and that is all it may ever mean.
 */

export type WalletRecoveryBackupAcknowledgementV1 = {
  readonly kind: 'wallet_recovery_backup_acknowledgement_v1';
  readonly walletId: string;
  /**
   * Which issuance was acknowledged.
   *
   * Rotation issues a new set, and an acknowledgement of the old one must not
   * silently cover it — otherwise rotating codes would leave the user never
   * prompted to save the ones they now depend on.
   */
  readonly issuedAtMs: number;
  readonly acknowledgedAtMs: number;
};

export type WalletRecoveryBackupAcknowledgementParseResult =
  | { readonly ok: true; readonly record: WalletRecoveryBackupAcknowledgementV1 }
  | { readonly ok: false; readonly reason: string };

export function parseWalletRecoveryBackupAcknowledgementV1(
  raw: unknown,
  options: { readonly expectedWalletId: string },
): WalletRecoveryBackupAcknowledgementParseResult {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: 'backup acknowledgement must be an object' };
  }
  const record = raw as Record<string, unknown>;
  if (record.kind !== 'wallet_recovery_backup_acknowledgement_v1') {
    return { ok: false, reason: 'backup acknowledgement kind is invalid' };
  }

  const walletId = String(record.walletId || '').trim();
  if (!walletId) return { ok: false, reason: 'backup acknowledgement must name its wallet' };
  /* Bound to the wallet the caller asked for, never to what the row says: a
     row stored under one wallet naming another would silence the prompt for
     the wrong person. */
  if (walletId !== String(options.expectedWalletId).trim()) {
    return { ok: false, reason: 'backup acknowledgement is outside the requested wallet' };
  }

  const issuedAtMs = timestamp(record.issuedAtMs);
  const acknowledgedAtMs = timestamp(record.acknowledgedAtMs);
  if (issuedAtMs === null || acknowledgedAtMs === null) {
    return { ok: false, reason: 'backup acknowledgement needs valid timestamps' };
  }
  if (acknowledgedAtMs < issuedAtMs) {
    /* Acknowledging codes before they existed describes something that cannot
       have happened, and is how a stale row from a previous issuance shows up. */
    return { ok: false, reason: 'backup acknowledgement predates the issuance it names' };
  }

  return {
    ok: true,
    record: {
      kind: 'wallet_recovery_backup_acknowledgement_v1',
      walletId,
      issuedAtMs,
      acknowledgedAtMs,
    },
  };
}

/**
 * Whether the user should still be asked to save their codes.
 *
 * Takes the set's own `issuedAtMs` rather than trusting the acknowledgement
 * alone, so a rotation re-arms the prompt: the stored acknowledgement names
 * the issuance it covered, and a newer set is by definition unacknowledged.
 */
export function walletRecoveryBackupIsOutstanding(input: {
  readonly setIssuedAtMs: number;
  readonly acknowledgement: WalletRecoveryBackupAcknowledgementV1 | null;
}): boolean {
  if (!input.acknowledgement) return true;
  return input.acknowledgement.issuedAtMs !== input.setIssuedAtMs;
}

export function buildWalletRecoveryBackupAcknowledgementV1(input: {
  readonly walletId: string;
  readonly issuedAtMs: number;
  readonly acknowledgedAtMs: number;
}): WalletRecoveryBackupAcknowledgementV1 {
  return {
    kind: 'wallet_recovery_backup_acknowledgement_v1',
    walletId: String(input.walletId).trim(),
    issuedAtMs: input.issuedAtMs,
    acknowledgedAtMs: input.acknowledgedAtMs,
  };
}

function timestamp(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}
