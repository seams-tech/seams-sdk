import {
  admitWalletRecoveryCredentialPromotion,
  type RecoveredKeySetOutcome,
} from '@shared/wallet-recovery/recoveryCodes';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';

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

export type WalletRecoveryPromotionResult =
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
  | { readonly kind: 'envelope_rejected'; readonly reason: string };

export async function promoteRecoveredWalletCredentialV1(input: {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletId: string;
  /** Sealed under the newly enrolled credential, by the client. */
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly requiredKeySets: readonly string[];
  readonly outcomes: readonly RecoveredKeySetOutcome[];
  readonly nowMs: number;
}): Promise<WalletRecoveryPromotionResult> {
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

  const created = await input.envelopeStore.createEnvelope(input.replacementEnvelope);
  if (created.kind !== 'stored') {
    /* Nothing has been retired yet, so the wallet is untouched. */
    return {
      kind: 'envelope_rejected',
      reason: `the replacement envelope was not stored: ${created.kind}`,
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
    storeVersion: created.storeVersion,
    retiredEnvelopeIds,
    ...(retireFailures.length > 0 ? { retireFailures } : {}),
  };
}
