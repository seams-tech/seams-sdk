import { deriveWalletRecoveryKeyIdFromBytes } from '@shared/wallet-recovery/recoveryCodes';
import {
  reserveRecoveryCode,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type {
  WalletRecoveryEnvelopeSetRecord,
  WalletRecoveryManifestKekWrap,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import type { WalletId } from '@shared/utils/domainIds';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * Preparing one recovery code for an admitted recovery operation.
 *
 * **The server never learns the seed.** It returns the wrapped manifest KEK
 * and the entry ciphertexts; opening them needs the code, which stays with the
 * user. So this flow is bookkeeping around an opaque payload — which is what
 * makes the bookkeeping the only thing that can go wrong, and worth the care.
 *
 * **A code is single-use, and that is a concurrency property.** Reserving one
 * is a read-modify-write on the wallet's shared recovery set. The
 * version-guard ensures two simultaneous attempts cannot both hold it.
 *
 * **An unknown code and a spent code answer alike.** Both come back `refused`
 * with no detail about which wraps exist. Distinguishing them would turn the
 * route into an oracle for which of a user's ten codes remain — useful to
 * exactly one kind of caller.
 */

export type WalletRecoveryPreparationResult =
  | {
      readonly kind: 'prepared';
      /** Opaque to the server: the client opens these with the code. */
      readonly wrap: {
        readonly nonceB64u: string;
        readonly wrappedManifestKekB64u: string;
        readonly aadHashB64u: string;
      };
      readonly entries: WalletRecoveryEnvelopeSetRecord['entries'];
      readonly reservationId: RecoveryCodeReservationId;
      readonly reservationExpiresAtMs: number;
      readonly storeVersion: string;
    }
  /** No such wallet, no such code, or a code already spent. Deliberately one shape. */
  | { readonly kind: 'refused'; readonly reason: string }
  /** Another attempt changed the shared set first. The caller may retry. */
  | { readonly kind: 'conflict' };

export async function prepareWalletRecoveryWithCodeV1(input: {
  readonly store: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: WalletId;
  /** The user's code, decoded. Never logged, never stored. */
  readonly recoveryCodeBytes: Uint8Array;
  readonly reservationId: RecoveryCodeReservationId;
  readonly nowMs: number;
  readonly reservationTtlMs: number;
}): Promise<WalletRecoveryPreparationResult> {
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

  const reserved = reserveRecoveryCode({
    lifecycle: wrap.lifecycle,
    reservationId: input.reservationId,
    nowMs: input.nowMs,
    reservationTtlMs: input.reservationTtlMs,
  });
  if (!reserved.ok || reserved.lifecycle.state !== 'reserved') return refused();

  const next: WalletRecoveryEnvelopeSetRecord = {
    ...stored.record,
    manifestKekWraps: stored.record.manifestKekWraps.map((entry, entryIndex) =>
      entryIndex === index ? { ...entry, lifecycle: reserved.lifecycle } : entry,
    ),
    updatedAtMs: input.nowMs,
  };

  /* Persist the hold before returning the opaque payload. The code remains
     usable if recovery never finalizes, once this bounded reservation expires. */
  const written = await input.store.writeRecoveryEnvelopeSet({
    record: next,
    expectedStoreVersion: stored.storeVersion,
  });
  if (written.kind === 'conflict') return { kind: 'conflict' };

  return {
    kind: 'prepared',
    wrap: {
      nonceB64u: String(wrap.nonceB64u),
      wrappedManifestKekB64u: String(wrap.wrappedManifestKekB64u),
      aadHashB64u: String(wrap.aadHashB64u),
    },
    entries: stored.record.entries,
    reservationId: input.reservationId,
    reservationExpiresAtMs: reserved.lifecycle.reservationExpiresAtMs,
    storeVersion: written.storeVersion,
  };
}

function refused(): Extract<WalletRecoveryPreparationResult, { kind: 'refused' }> {
  return { kind: 'refused', reason: 'that recovery code cannot be used' };
}
