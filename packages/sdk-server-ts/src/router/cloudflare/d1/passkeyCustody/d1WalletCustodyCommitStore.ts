import {
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import type { WalletId } from '@shared/utils/domainIds';
import type { VersionedJsonObject } from '../../../framework/versionedJsonRecordStore';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  CloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordScopeV1,
} from '../versionedJson/d1VersionedJsonRecordStore';
import {
  PASSKEY_ENVELOPE_KEY_PREFIX,
  passkeyCustodyEnvelopeLocatorOf,
  passkeyCustodyEnvelopeRecordKey,
} from './d1PasskeyCustodyEnvelopeStore';

/**
 * The registration commit: one custody envelope and one recovery envelope set,
 * written together or not at all.
 *
 * Atomicity is the reason this store exists rather than two sequential writes.
 * The two partial outcomes are not equally bad. A recovery set with no envelope
 * leaves a wallet no factor can open, which fails loudly and is retried. An
 * envelope with no recovery set leaves a *working* wallet whose owner believes
 * they hold ten recovery codes that were never stored — silent, and only
 * discovered when recovery is attempted. `putMany` applies both rows in one D1
 * transaction, so neither state is reachable.
 *
 * Both records therefore share the envelope key prefix: a D1 batch is scoped to
 * one store instance, and one instance is one prefix. Their keys cannot collide
 * — an envelope key is a JSON array and so always begins with `[`, while a
 * recovery-set key begins with `recovery-set:`.
 */

type WalletCustodyCommitRecord = PasskeyCustodyEnvelopeRecord | WalletRecoveryEnvelopeSetRecord;

export type CloudflareD1WalletCustodyCommitStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
};

export type WalletCustodyRegistrationCommit = {
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
};

export type WalletCustodyRegistrationCommitResult =
  | {
      readonly kind: 'committed';
      readonly envelopeStoreVersion: string;
      readonly recoverySetStoreVersion: string;
    }
  /**
   * This ceremony's own envelope is already stored: the commit was applied
   * before, and the caller holding this result is done. Never an overwrite —
   * replacing stored custody would strand every key the existing seed controls.
   */
  | { readonly kind: 'already_exists'; readonly key: string }
  /**
   * The wallet already has custody, established by a *different* ceremony —
   * its recovery-set key is occupied while this ceremony's envelope key is
   * free. This is the losing side of the establish race: two key sets each
   * believed they were the wallet's first. The caller must discard this run's
   * seed and re-enter as a join of the existing envelope, committing only its
   * key set's manifest.
   *
   * Distinct from `already_exists` because the correct reactions are opposite:
   * a repeat is finished, a lost race has a key set still to provision.
   */
  | { readonly kind: 'custody_already_established'; readonly walletId: WalletId }
  /** The two records describe different wallets. */
  | { readonly kind: 'inconsistent'; readonly reason: string };

/** Recovery sets are wallet-scoped: one set covers the wallet, not one factor. */
export function walletRecoveryEnvelopeSetRecordKey(walletId: WalletId): string {
  return `recovery-set:${String(walletId)}`;
}

function encodeRecord(record: WalletCustodyCommitRecord): VersionedJsonObject {
  return record as unknown as VersionedJsonObject;
}

/**
 * Routes a row to its record family by its own `kind`, so a row can never be
 * read back as the other family even if a key were somehow reused.
 *
 * Envelopes are fully parsed here. Recovery sets are not: their parser requires
 * the wallet id the caller expects, which is the point of that check and is not
 * knowable at store construction. Passing the row's own wallet id back into its
 * own validation would assert nothing. So a recovery-set row is routed here and
 * validated in `readRecoveryEnvelopeSet`, where a real expectation exists.
 */
function parseRecordOrNull(raw: unknown): WalletCustodyCommitRecord | null {
  const kind = (raw as { kind?: unknown } | null)?.kind;
  if (kind === 'wallet_recovery_envelope_set_v1') {
    return raw as WalletRecoveryEnvelopeSetRecord;
  }
  try {
    return parsePasskeyCustodyEnvelopeRecord(raw);
  } catch {
    return null;
  }
}

/**
 * Rejects a pair that does not describe one wallet's custody.
 *
 * The envelope and the recovery set wrap the same seed, so a pair naming two
 * wallets would leave a set whose codes open a seed that is not the wallet's.
 */
function commitInconsistency(commit: WalletCustodyRegistrationCommit): string | null {
  if (String(commit.envelope.walletId) !== String(commit.recoverySet.walletId)) {
    return 'envelope and recovery set describe different wallets';
  }
  if (commit.envelope.binding.kind !== 'wallet_custody_seed_v1') {
    return 'registration commits a wallet custody seed envelope';
  }
  // No manifest cross-check: neither record names a key manifest now. Key sets
  // carry their own on their own registration state, so the only thing that
  // must agree here is which wallet's seed the pair covers.
  if (commit.recoverySet.entries.length !== 1) {
    return 'a recovery set carries exactly one custody entry';
  }
  return null;
}

export class CloudflareD1WalletCustodyCommitStore {
  private readonly records: CloudflareD1VersionedJsonRecordStore<WalletCustodyCommitRecord>;

  constructor(options: CloudflareD1WalletCustodyCommitStoreOptions) {
    this.records = new CloudflareD1VersionedJsonRecordStore<WalletCustodyCommitRecord>({
      database: options.database,
      scope: options.scope,
      encode: encodeRecord,
      parse: parseRecordOrNull,
      keyPrefix: PASSKEY_ENVELOPE_KEY_PREFIX,
    });
  }

  /**
   * Writes the envelope and the recovery set in one transaction.
   *
   * Both are inserts, never updates: `expectedVersion: null` fails if either
   * key already holds a row, so a repeated registration cannot silently replace
   * an established wallet's custody.
   */
  async commitRegistration(
    commit: WalletCustodyRegistrationCommit,
  ): Promise<WalletCustodyRegistrationCommitResult> {
    const inconsistency = commitInconsistency(commit);
    if (inconsistency !== null) return { kind: 'inconsistent', reason: inconsistency };

    const envelopeKey = passkeyCustodyEnvelopeRecordKey(
      passkeyCustodyEnvelopeLocatorOf(commit.envelope),
    );
    const recoverySetKey = walletRecoveryEnvelopeSetRecordKey(commit.recoverySet.walletId);

    const stored = await this.records.putMany([
      { key: envelopeKey, value: commit.envelope, expectedVersion: null },
      { key: recoverySetKey, value: commit.recoverySet, expectedVersion: null },
    ]);
    if (stored.kind === 'version_mismatch') {
      // Which record is the duplicate decides what the caller does next. The
      // recovery-set key is wallet-scoped — it is the establish mutex — while
      // the envelope key carries this ceremony's own envelope id. The envelope
      // is checked directly rather than trusting which key the batch happened
      // to report first: a replay conflicts on both keys.
      const envelopeTaken =
        stored.key === envelopeKey || (await this.records.read(envelopeKey)).kind !== 'missing';
      if (envelopeTaken) return { kind: 'already_exists', key: stored.key };
      return { kind: 'custody_already_established', walletId: commit.recoverySet.walletId };
    }

    const envelopeVersion = stored.versions.find((entry) => entry.key === envelopeKey);
    const recoverySetVersion = stored.versions.find((entry) => entry.key === recoverySetKey);
    if (!envelopeVersion || !recoverySetVersion) {
      // The batch reported success without both keys, which would mean the
      // store wrote something other than what it was asked to.
      throw new Error('wallet custody commit did not report both record versions');
    }
    return {
      kind: 'committed',
      envelopeStoreVersion: envelopeVersion.version,
      recoverySetStoreVersion: recoverySetVersion.version,
    };
  }

  /**
   * Reads a wallet's recovery envelope set. Returns null when absent, and also
   * when the stored row is not a recovery set — a row that fails its own parser
   * is unusable, and reporting it as present would invite a caller to act on a
   * record nothing validated.
   */
  async readRecoveryEnvelopeSet(
    walletId: WalletId,
  ): Promise<{ record: WalletRecoveryEnvelopeSetRecord; storeVersion: string } | null> {
    const read = await this.records.read(walletRecoveryEnvelopeSetRecordKey(walletId));
    if (read.kind === 'missing') return null;
    if (read.value.kind !== 'wallet_recovery_envelope_set_v1') return null;
    try {
      // The authoritative parse, bound to the wallet the caller asked for: a
      // set stored under one wallet's key that names another is rejected here
      // rather than returned for a caller to trust.
      const record = parseWalletRecoveryEnvelopeSetRecord(read.value, {
        expectedWalletId: walletId,
        label: 'walletRecoveryEnvelopeSet',
      });
      return { record, storeVersion: read.version };
    } catch {
      return null;
    }
  }

  /**
   * Writes a recovery set back, refusing if it changed underneath.
   *
   * The expected version is the whole point. Burning a recovery code is a
   * read-modify-write on one shared record, so two concurrent attempts that
   * both read the same set would otherwise each write their own view — and
   * the second write would silently restore the first attempt's consumed code
   * to the active pool. A single-use code that survives its use is the one
   * failure this record must not have.
   */
  async writeRecoveryEnvelopeSet(input: {
    readonly record: WalletRecoveryEnvelopeSetRecord;
    readonly expectedStoreVersion: string;
  }): Promise<{ kind: 'stored'; storeVersion: string } | { kind: 'conflict' }> {
    const result = await this.records.put(
      walletRecoveryEnvelopeSetRecordKey(input.record.walletId),
      input.record,
      input.expectedStoreVersion,
    );
    if (result.kind !== 'stored') return { kind: 'conflict' };
    return { kind: 'stored', storeVersion: result.version };
  }
}
