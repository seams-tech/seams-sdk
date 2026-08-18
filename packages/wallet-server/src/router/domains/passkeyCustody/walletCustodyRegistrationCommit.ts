import {
  buildActiveEnvelopeLifecycle,
  buildPasskeyCustodyEnvelopeRecord,
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parsePasskeyCustodySecretBinding,
  parseWalletCustodyEnvelopeFactor,
  type PasskeyCustodyEnvelopeRecord,
  type WalletCustodyCeremonyCommitPayload,
} from '@shared/passkey-custody';
import {
  buildWalletCustodySeedRecoveryEntry,
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  parseDerivedWalletRecoveryKeyId,
  WALLET_RECOVERY_CODE_COUNT,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
import { buildWalletRecoveryBackupAcknowledgementV1 } from '@shared/wallet-recovery/recoveryCodes';
import { isPlainObject } from '@shared/utils/validation';
import { parsePasskeyEnvelopeId, parseWalletId, type WalletId } from '@shared/utils/domainIds';

export type { WalletCustodyCeremonyCommitPayload };
import type {
  CloudflareD1WalletCustodyCommitStore,
  WalletCustodyRegistrationCommitResult,
} from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';

/**
 * Turns a ceremony's commit payload into the two records the store writes.
 *
 * The payload is what `wallet_custody_ceremony`'s `seal` returned: ciphertext
 * and public facts only. This module adds nothing cryptographic — it parses the
 * payload through the same boundary parsers every other reader uses, and
 * assembles records. Anything it cannot parse is rejected here rather than
 * stored for a later reader to choke on.
 *
 * The ten recovery-code wraps and the single seed entry arrive together because
 * the ceremony produced them under one manifest KEK. Splitting that across two
 * requests would let a wallet exist with a partial code set.
 */

export type WalletCustodyRegistrationRecords = {
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
  readonly recoveryBackupAcknowledgement: ReturnType<
    typeof buildWalletRecoveryBackupAcknowledgementV1
  >;
};

export type WalletCustodyRegistrationCommitOutcome =
  | ({ readonly kind: 'committed' } & Omit<
      Extract<WalletCustodyRegistrationCommitResult, { kind: 'committed' }>,
      'kind'
    >)
  | { readonly kind: 'already_exists'; readonly key: string }
  /**
   * Another ceremony established this wallet's custody first. The route should
   * tell the client to discard its run's seed and re-enter as a join of the
   * existing envelope — the key set it was provisioning is still unrecorded.
   */
  | { readonly kind: 'custody_already_established'; readonly walletId: WalletId }
  | { readonly kind: 'rejected'; readonly reason: string };

function requireNonEmpty(value: unknown, label: string): string {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requirePasskeyEnvelopeId(value: unknown) {
  const parsed = parsePasskeyEnvelopeId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

/**
 * Builds both records from the payload.
 *
 * The envelope binding is parsed from the ceremony's own JSON rather than
 * reassembled from loose fields: the binding is what the AAD was computed over,
 * so any field this server re-derived instead of carrying through would produce
 * an envelope that cannot open.
 */
export function buildWalletCustodyRegistrationRecords(args: {
  readonly payload: WalletCustodyCeremonyCommitPayload;
  readonly factor: unknown;
  readonly nowMs: number;
}): WalletCustodyRegistrationRecords {
  const { payload, nowMs } = args;
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) {
    throw new Error('nowMs must be a positive integer');
  }

  const walletId = requireWalletId(payload.walletId);
  if (payload.recoveryBackupAcknowledged !== true) {
    throw new Error('wallet recovery-code backup acknowledgement is required');
  }
  // A joining run writes no custody records: the wallet already has a seed
  // envelope and a recovery set, and issuing more would leave half its keys
  // covered by neither.
  const custody = payload.establishedCustody;
  if (!custody) {
    throw new Error('this ceremony joined existing custody and commits no custody records');
  }

  const rawBinding: unknown = JSON.parse(
    requireNonEmpty(custody.envelopeBindingJson, 'envelopeBindingJson'),
  );
  if (!isPlainObject(rawBinding)) throw new Error('envelopeBindingJson must decode to an object');
  // The ceremony serialises the whole envelope binding, whose `binding` field is
  // the custody-secret branch the parsers own.
  const binding = parsePasskeyCustodySecretBinding(
    (rawBinding as { binding?: unknown }).binding,
    'walletCustodyCommit.binding',
  );
  if (binding.kind !== 'wallet_custody_seed_v1') {
    throw new Error('a registration commit carries a wallet custody seed envelope');
  }
  if (String((rawBinding as { walletId?: unknown }).walletId ?? '') !== String(walletId)) {
    throw new Error('envelope binding does not carry the payload wallet id');
  }

  const factor = parseWalletCustodyEnvelopeFactor(args.factor, 'walletCustodyCommit.factor');
  const envelope = buildPasskeyCustodyEnvelopeRecord({
    envelopeId: requirePasskeyEnvelopeId(custody.envelopeId),
    walletId,
    binding,
    factor,
    // A registration commit is always the first revision. The store refuses
    // anything else, so this is not a place to be lenient.
    envelopeRevision: parseEnvelopeRevision(1),
    nonceB64u: parseEnvelopeNonceB64u(custody.envelopeNonceB64u, 'envelopeNonceB64u'),
    sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      custody.sealedCustodySecretB64u,
      'sealedCustodySecretB64u',
    ),
    ciphertextDigestB64u: parseDigestField(
      custody.envelopeCiphertextDigestB64u,
      'envelopeCiphertextDigestB64u',
    ),
    aadHashB64u: parseDigestField(custody.envelopeAadHashB64u, 'envelopeAadHashB64u'),
    lifecycle: buildActiveEnvelopeLifecycle({ activatedAtMs: nowMs }),
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  });

  const wraps = custody.recoveryManifestKekWraps ?? [];
  if (wraps.length !== WALLET_RECOVERY_CODE_COUNT) {
    throw new Error(`a recovery set carries exactly ${WALLET_RECOVERY_CODE_COUNT} code wraps`);
  }
  const recoveryKeyIds = new Set<string>();
  const manifestKekWraps = wraps.map((wrap) => {
    const recoveryKeyId = requireNonEmpty(wrap.recoveryKeyId, 'recoveryKeyId');
    if (recoveryKeyIds.has(recoveryKeyId)) {
      // Duplicate ids would silently reduce a ten-code set to fewer usable
      // codes, since a code is looked up by its id.
      throw new Error(`duplicate recovery key id ${recoveryKeyId}`);
    }
    recoveryKeyIds.add(recoveryKeyId);
    return buildWalletRecoveryManifestKekWrap({
      recoveryKeyId: parseDerivedWalletRecoveryKeyId(recoveryKeyId),
      nonceB64u: parseEnvelopeNonceB64u(wrap.nonceB64u, 'recoveryWrap.nonceB64u'),
      wrappedManifestKekB64u: parseEnvelopeCiphertextB64u(
        wrap.ciphertextB64u,
        'recoveryWrap.ciphertextB64u',
      ),
      aadHashB64u: parseDigestField(wrap.aadHashB64u, 'recoveryWrap.aadHashB64u'),
      lifecycle: { state: 'active', issuedAtMs: nowMs },
    });
  });

  const recoverySet = buildWalletRecoveryEnvelopeSetRecord({
    walletId,
    manifestKekWraps,
    entries: [
      buildWalletCustodySeedRecoveryEntry({
        nonceB64u: parseEnvelopeNonceB64u(custody.recoveryEntryNonceB64u, 'recoveryEntryNonceB64u'),
        wrappedCustodySecretB64u: parseEnvelopeCiphertextB64u(
          custody.recoveryEntryCiphertextB64u,
          'recoveryEntryCiphertextB64u',
        ),
        aadHashB64u: parseDigestField(custody.recoveryEntryAadHashB64u, 'recoveryEntryAadHashB64u'),
      }),
    ],
    issuedAtMs: nowMs,
    updatedAtMs: nowMs,
  });

  return {
    envelope,
    recoverySet,
    recoveryBackupAcknowledgement: buildWalletRecoveryBackupAcknowledgementV1({
      walletId,
      issuedAtMs: nowMs,
      acknowledgedAtMs: nowMs,
    }),
  };
}

/**
 * Builds and commits in one call.
 *
 * A payload this server cannot parse becomes `rejected` rather than an
 * exception, so a malformed ceremony result is a request outcome and not a
 * route crash. Nothing is written in that case: the records are built before
 * the store is touched.
 */
export async function commitWalletCustodyRegistration(input: {
  readonly payload: WalletCustodyCeremonyCommitPayload;
  readonly factor: unknown;
  readonly nowMs: number;
  readonly store: CloudflareD1WalletCustodyCommitStore;
}): Promise<WalletCustodyRegistrationCommitOutcome> {
  let records: WalletCustodyRegistrationRecords;
  try {
    records = buildWalletCustodyRegistrationRecords(input);
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      reason: error instanceof Error ? error.message : 'invalid wallet custody commit payload',
    };
  }

  const stored = await input.store.commitRegistration(records);
  switch (stored.kind) {
    case 'committed':
      return {
        kind: 'committed',
        envelopeStoreVersion: stored.envelopeStoreVersion,
        recoverySetStoreVersion: stored.recoverySetStoreVersion,
      };
    case 'already_exists':
      return { kind: 'already_exists', key: stored.key };
    case 'custody_already_established':
      return { kind: 'custody_already_established', walletId: stored.walletId };
    case 'inconsistent':
      return { kind: 'rejected', reason: stored.reason };
  }
}
