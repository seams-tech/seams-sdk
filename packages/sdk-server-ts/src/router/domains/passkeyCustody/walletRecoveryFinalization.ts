import {
  admitWalletRecoveryCredentialPromotion,
  type RecoveredKeySetOutcome,
} from '@shared/wallet-recovery/recoveryCodes';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import {
  consumeReservedRecoveryCode,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import type { WalletId } from '@shared/utils/domainIds';

/**
 * Promoting the replacement credential a recovery enrolled.
 *
 * **The order is the safety property.** The new envelope is created first and
 * the old ones retired only after it lands. Retiring first would leave a
 * window — and, if the create then failed, a permanent state — where the
 * wallet has no active envelope and no factor opens its custody seed. The
 * user would be holding a working recovery code they had just spent.
 *
 * So a failed create leaves the wallet exactly as it was: still openable by
 * the credential the user is trying to replace, which is the safe direction to
 * fail in. A failed retire leaves both credentials active, which is worth
 * reporting but is not a lockout — the old one can be revoked again.
 *
 * **Promotion is all-or-nothing across the key set.** A mixed wallet recovers
 * NEAR and EVM-family keys together, and promoting after only some verified
 * would leave a wallet the owner believes is recovered while part of it still
 * answers to a credential they no longer hold. That decision lives in
 * `admitWalletRecoveryCredentialPromotion`; this runs it before touching
 * anything.
 */

export type WalletRecoveryFinalizationResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      /** Retired alongside the promotion. Empty is normal on a first recovery. */
      readonly retiredEnvelopeIds: readonly string[];
      /**
       * Present when the new envelope landed but a retire did not. The wallet
       * is recovered; an old credential still opens it and should be revoked.
       */
      readonly retireFailures?: readonly string[];
    }
  | { readonly kind: 'refused'; readonly reason: string }
  | { readonly kind: 'conflict'; readonly reason: string }
  | { readonly kind: 'envelope_rejected'; readonly reason: string };

export async function finalizeRecoveredWalletCredentialV1(input: {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  /** Sealed under the newly enrolled credential, by the client. */
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly requiredKeySets: readonly string[];
  readonly outcomes: readonly RecoveredKeySetOutcome[];
  readonly nowMs: number;
}): Promise<WalletRecoveryFinalizationResult> {
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: input.requiredKeySets,
    outcomes: input.outcomes,
  });
  if (admission.kind === 'refused') {
    return { kind: 'refused', reason: admission.reason };
  }

  if (String(input.replacementEnvelope.walletId) !== String(input.walletId)) {
    /* An envelope naming another wallet would install a credential that opens
       someone else's custody. Checked here rather than trusted from the body
       the client sent. */
    return {
      kind: 'envelope_rejected',
      reason: 'the replacement envelope names a different wallet',
    };
  }

  const storedRecoverySet = await input.walletCustodyCommits.readRecoveryEnvelopeSet(
    input.walletId as WalletId,
  );
  if (!storedRecoverySet) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const reservedIndex = storedRecoverySet.record.manifestKekWraps.findIndex(
    (wrap) =>
      (wrap.lifecycle.state === 'reserved' || wrap.lifecycle.state === 'consumed') &&
      wrap.lifecycle.reservationId === input.reservationId,
  );
  if (reservedIndex < 0) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const selected = storedRecoverySet.record.manifestKekWraps[reservedIndex];
  if (!selected) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const lifecycle =
    selected.lifecycle.state === 'consumed'
      ? selected.lifecycle
      : consumeReservedRecoveryCode({
          lifecycle: selected.lifecycle,
          reservationId: input.reservationId,
          nowMs: input.nowMs,
        });
  if ('ok' in lifecycle && !lifecycle.ok) {
    return { kind: 'refused', reason: lifecycle.message };
  }
  const consumedLifecycle = 'ok' in lifecycle ? lifecycle.lifecycle : lifecycle;
  if (consumedLifecycle.state !== 'consumed') {
    return { kind: 'refused', reason: 'the recovery code was not consumed' };
  }
  const consumedRecoverySet: WalletRecoveryEnvelopeSetRecord = {
    ...storedRecoverySet.record,
    manifestKekWraps: storedRecoverySet.record.manifestKekWraps.map((wrap, index) =>
      index === reservedIndex ? { ...wrap, lifecycle: consumedLifecycle } : wrap,
    ),
    updatedAtMs: input.nowMs,
  };

  /* Read before the write, so the retire list is the set that was active when
     the promotion was admitted — not whatever exists after it lands, which
     would include the new envelope itself. */
  const existing = await input.envelopeStore.listWalletEnvelopes(
    input.replacementEnvelope.walletId,
  );
  const previouslyActive = existing.filter(
    (envelope) =>
      envelope.lifecycle.state === 'active' &&
      String(envelope.envelopeId) !== String(input.replacementEnvelope.envelopeId),
  );

  const committed = await input.walletCustodyCommits.commitRecoveryPromotion({
    recoverySet: consumedRecoverySet,
    expectedRecoverySetVersion: storedRecoverySet.storeVersion,
    replacementEnvelope: input.replacementEnvelope,
    reservationId: input.reservationId,
  });
  if (committed.kind === 'conflict') {
    return { kind: 'conflict', reason: 'the recovery state changed during finalization' };
  }
  if (committed.kind === 'inconsistent') {
    /* Nothing has been retired yet, so the wallet is untouched. */
    return {
      kind: 'envelope_rejected',
      reason: committed.reason,
    };
  }

  const retiredEnvelopeIds: string[] = [];
  const retireFailures: string[] = [];
  for (const envelope of previouslyActive) {
    const retired = await input.envelopeStore.retireEnvelope({
      locator: {
        walletId: envelope.walletId,
        factor: envelope.factor,
        envelopeId: envelope.envelopeId,
      },
      retiredAtMs: input.nowMs,
    });
    if (retired.kind === 'stored') {
      retiredEnvelopeIds.push(String(envelope.envelopeId));
      continue;
    }
    /* Reported, never fatal. The wallet is recovered and openable by the new
       credential; an old one still working is a cleanup task, not a failure
       of the recovery the user just performed. */
    retireFailures.push(String(envelope.envelopeId));
  }

  return {
    kind: 'promoted',
    storeVersion: committed.envelopeStoreVersion,
    retiredEnvelopeIds,
    ...(retireFailures.length > 0 ? { retireFailures } : {}),
  };
}
