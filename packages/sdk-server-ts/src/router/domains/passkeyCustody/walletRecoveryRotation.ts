import {
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import type { WalletId } from '@shared/utils/domainIds';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * Replacing a wallet's recovery codes.
 *
 * **Only the wraps rotate; the entries never move.** The entries hold the
 * wallet's seed wrapped under the manifest KEK, and the KEK is unchanged by a
 * rotation — what changes is which codes unwrap it. A rotation that rebuilt
 * the entries would need the seed, which the server does not have and must
 * never need; one that dropped them would destroy the wallet's recovery
 * outright while appearing to refresh it.
 *
 * **`issuedAtMs` must advance.** The backup acknowledgement names the issuance
 * it covers, so a rotation that reused the old timestamp would leave the user
 * still marked as having saved codes that no longer work — the exact silent
 * outcome the acknowledgement model exists to prevent.
 *
 * **Version-guarded.** Rotation and recovery finalization both rewrite the wrap list.
 * Without the guard, rotation could land on top of finalization and resurrect the
 * consumed code, or finalization could land on top of rotation and burn a code
 * from a set the user no longer holds.
 */

export type WalletRecoveryRotationResult =
  | { readonly kind: 'rotated'; readonly issuedAtMs: number; readonly storeVersion: string }
  | { readonly kind: 'no_recovery_set' }
  | { readonly kind: 'rejected'; readonly reason: string }
  /** Recovery finalization or another rotation landed first; re-read and retry. */
  | { readonly kind: 'conflict' };

export async function rotateWalletRecoveryCodesV1(input: {
  readonly store: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: WalletId;
  /** Ten fresh wraps of the *same* manifest KEK, built client-side. */
  readonly manifestKekWraps: WalletRecoveryEnvelopeSetRecord['manifestKekWraps'];
  readonly expectedStoreVersion: string;
  readonly nowMs: number;
}): Promise<WalletRecoveryRotationResult> {
  const stored = await input.store.readRecoveryEnvelopeSet(input.walletId);
  if (!stored) return { kind: 'no_recovery_set' };

  if (stored.storeVersion !== input.expectedStoreVersion) return { kind: 'conflict' };

  if (input.nowMs <= Number(stored.record.issuedAtMs)) {
    /* Refused rather than clamped. A timestamp that does not advance leaves
       the acknowledgement covering codes that no longer work, and silently
       "succeeding" here is how that ships. */
    return {
      kind: 'rejected',
      reason: 'a rotation must be newer than the issuance it replaces',
    };
  }

  const next: WalletRecoveryEnvelopeSetRecord = {
    ...stored.record,
    manifestKekWraps: input.manifestKekWraps,
    /* Untouched, explicitly. The seed wraps are unchanged by a rotation, and
       spelling that out here is cheaper than discovering it from a wallet
       whose recovery stopped working. */
    entries: stored.record.entries,
    issuedAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };

  /* The authoritative parse, before the write rather than after: it is what
     enforces exactly ten wraps, and a set that fails it must never reach the
     store — a wallet with nine codes looks fine until someone counts. */
  try {
    parseWalletRecoveryEnvelopeSetRecord(next, {
      expectedWalletId: input.walletId,
      label: 'walletRecoveryEnvelopeSetRotation',
    });
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      reason: error instanceof Error ? error.message : 'the rotated recovery set is invalid',
    };
  }

  const written = await input.store.writeRecoveryEnvelopeSet({
    record: next,
    expectedStoreVersion: stored.storeVersion,
  });
  if (written.kind === 'conflict') return { kind: 'conflict' };

  return { kind: 'rotated', issuedAtMs: input.nowMs, storeVersion: written.storeVersion };
}
