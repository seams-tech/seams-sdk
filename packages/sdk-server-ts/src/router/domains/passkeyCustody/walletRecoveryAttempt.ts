import {
  deriveWalletRecoveryKeyIdFromBytes,
  runWalletRecoveryWithCode,
} from '@shared/wallet-recovery/recoveryCodes';
import type {
  WalletRecoveryEnvelopeSetRecord,
  WalletRecoveryManifestKekWrap,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import type { WalletId } from '@shared/utils/domainIds';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * Spending one recovery code.
 *
 * **The server never learns the seed.** It returns the wrapped manifest KEK
 * and the entry ciphertexts; opening them needs the code, which stays with the
 * user. So this flow is bookkeeping around an opaque payload — which is what
 * makes the bookkeeping the only thing that can go wrong, and worth the care.
 *
 * **A code is single-use, and that is a concurrency property.** Consuming one
 * is a read-modify-write on the wallet's shared recovery set, so the write is
 * version-guarded: two simultaneous attempts cannot both commit, and the loser
 * is told to retry rather than silently restoring the winner's spent code to
 * the active pool.
 *
 * **An unknown code and a spent code answer alike.** Both come back `refused`
 * with no detail about which wraps exist. Distinguishing them would turn the
 * route into an oracle for which of a user's ten codes remain — useful to
 * exactly one kind of caller.
 */

export type WalletRecoveryAttemptResult =
  | {
      readonly kind: 'committed';
      /** Opaque to the server: the client opens these with the code. */
      readonly wrap: {
        readonly nonceB64u: string;
        readonly wrappedManifestKekB64u: string;
        readonly aadHashB64u: string;
      };
      readonly entries: WalletRecoveryEnvelopeSetRecord['entries'];
      readonly storeVersion: string;
    }
  /** No such wallet, no such code, or a code already spent. Deliberately one shape. */
  | { readonly kind: 'refused'; readonly reason: string }
  /** Another attempt committed first. The caller re-reads and may retry. */
  | { readonly kind: 'conflict' };

export async function attemptWalletRecoveryWithCodeV1(input: {
  readonly store: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: WalletId;
  /** The user's code, decoded. Never logged, never stored. */
  readonly recoveryCodeBytes: Uint8Array;
  readonly reservationId: string;
  readonly nowMs: number;
  readonly reservationTtlMs: number;
}): Promise<WalletRecoveryAttemptResult> {
  const stored = await input.store.readRecoveryEnvelopeSet(input.walletId);
  if (!stored) return refused();

  const recoveryKeyId = await deriveWalletRecoveryKeyIdFromBytes({
    codeBytes: input.recoveryCodeBytes,
    walletId: String(input.walletId),
  });
  const index = stored.record.manifestKekWraps.findIndex(
    (wrap) => String(wrap.recoveryKeyId) === String(recoveryKeyId),
  );
  if (index < 0) return refused();

  const wrap = stored.record.manifestKekWraps[index] as WalletRecoveryManifestKekWrap;

  /* The lifecycle wrapper owns reserve/commit/release, including the case a
     hand-written call site is most likely to miss: a throw inside `activate`
     releases the code rather than burning it. */
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: wrap.lifecycle,
    reservationId: input.reservationId as never,
    nowMs: input.nowMs,
    reservationTtlMs: input.reservationTtlMs,
    activate: async () => ({ kind: 'committed' as const, value: wrap }),
  });

  if (outcome.kind !== 'committed') {
    /* Refused and released are both "this code did not work", and the
       difference between them is about the code's own state — which is what
       must not be reported. */
    return refused();
  }

  const next: WalletRecoveryEnvelopeSetRecord = {
    ...stored.record,
    manifestKekWraps: stored.record.manifestKekWraps.map((entry, entryIndex) =>
      entryIndex === index ? { ...entry, lifecycle: outcome.lifecycle } : entry,
    ),
    updatedAtMs: input.nowMs,
  };

  /* Written before the payload is returned, never after. A caller that
     answered first and recorded the spend afterwards would hand out a working
     recovery payload and then, on a failed write, leave the code spendable
     again — the same code, twice. */
  const written = await input.store.writeRecoveryEnvelopeSet({
    record: next,
    expectedStoreVersion: stored.storeVersion,
  });
  if (written.kind === 'conflict') return { kind: 'conflict' };

  return {
    kind: 'committed',
    wrap: {
      nonceB64u: String(wrap.nonceB64u),
      wrappedManifestKekB64u: String(wrap.wrappedManifestKekB64u),
      aadHashB64u: String(wrap.aadHashB64u),
    },
    entries: stored.record.entries,
    storeVersion: written.storeVersion,
  };
}

function refused(): Extract<WalletRecoveryAttemptResult, { kind: 'refused' }> {
  return { kind: 'refused', reason: 'that recovery code cannot be used' };
}
