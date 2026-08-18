import {
  buildWalletCustodySeedRecoveryEntry,
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
  type WalletRecoverySetRotationWireV1,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import type { WalletId } from '@shared/utils/domainIds';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * Replaces all ten recovery wraps and the seed entry produced by the active
 * factor's custody worker. The server never opens the ciphertext; it stamps
 * lifecycle state and commits the set plus its backup acknowledgement together.
 */
export type WalletRecoveryRotationResult =
  | { readonly kind: 'rotated'; readonly issuedAtMs: number; readonly storeVersion: string }
  | { readonly kind: 'no_recovery_set' }
  | { readonly kind: 'rejected'; readonly reason: string }
  /** Recovery finalization or another rotation landed first; re-read and retry. */
  | { readonly kind: 'conflict' };

function buildReplacementRecord(input: {
  readonly walletId: WalletId;
  readonly replacement: WalletRecoverySetRotationWireV1;
  readonly nowMs: number;
}): WalletRecoveryEnvelopeSetRecord {
  const manifestKekWraps = input.replacement.manifestKekWraps.map((wrap) =>
    buildWalletRecoveryManifestKekWrap({
      recoveryKeyId: wrap.recoveryKeyId,
      nonceB64u: wrap.nonceB64u,
      wrappedManifestKekB64u: wrap.ciphertextB64u,
      aadHashB64u: wrap.aadHashB64u,
      lifecycle: { state: 'active', issuedAtMs: input.nowMs },
    }),
  );
  return buildWalletRecoveryEnvelopeSetRecord({
    walletId: input.walletId,
    manifestKekWraps,
    entries: [
      buildWalletCustodySeedRecoveryEntry({
        nonceB64u: input.replacement.entry.nonceB64u,
        wrappedCustodySecretB64u: input.replacement.entry.wrappedCustodySecretB64u,
        aadHashB64u: input.replacement.entry.aadHashB64u,
      }),
    ],
    issuedAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  });
}

export async function rotateWalletRecoveryCodesV1(input: {
  readonly store: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: WalletId;
  readonly replacement: WalletRecoverySetRotationWireV1;
  readonly expectedStoreVersion: string;
  readonly nowMs: number;
}): Promise<WalletRecoveryRotationResult> {
  const stored = await input.store.readRecoveryEnvelopeSet(input.walletId);
  if (!stored) return { kind: 'no_recovery_set' };

  if (stored.storeVersion !== input.expectedStoreVersion) return { kind: 'conflict' };
  if (input.nowMs <= Number(stored.record.issuedAtMs)) {
    return {
      kind: 'rejected',
      reason: 'a rotation must be newer than the issuance it replaces',
    };
  }
  if (String(input.replacement.walletId) !== String(input.walletId)) {
    return { kind: 'rejected', reason: 'replacement recovery set names a different wallet' };
  }

  let next: WalletRecoveryEnvelopeSetRecord;
  try {
    next = buildReplacementRecord({
      walletId: input.walletId,
      replacement: input.replacement,
      nowMs: input.nowMs,
    });
    parseWalletRecoveryEnvelopeSetRecord(next, {
      expectedWalletId: input.walletId,
      label: 'walletRecoveryEnvelopeSetRotation',
    });
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      reason: error instanceof Error ? error.message : 'the replacement recovery set is invalid',
    };
  }

  const written = await input.store.replaceRecoveryEnvelopeSetAndPreserveBackupAcknowledgement({
    record: next,
    expectedRecoverySetVersion: stored.storeVersion,
  });
  if (written.kind === 'conflict') return { kind: 'conflict' };
  return { kind: 'rotated', issuedAtMs: input.nowMs, storeVersion: written.storeVersion };
}
