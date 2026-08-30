import {
  parseWalletRecoveryBackupAcknowledgementV1,
  type WalletRecoveryBackupAcknowledgementV1,
} from '@shared/wallet-recovery/recoveryCodes';
import {
  parseWalletRecoveryEnvelopeSetRecord,
  type WalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WalletRecoveryOperationId,
} from '@shared/utils/domainIds';
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import {
  parseRecoveryCodeLocatorV1,
  type RecoveryCodeLocatorV1,
} from '@shared/wallet-recovery/recoveryCodeLocator';
import {
  parseDerivedWalletRecoveryKeyId,
  type DerivedWalletRecoveryKeyId,
} from '@shared/wallet-recovery/recoveryKeyId';
import { alphabetizeStringify, sha256HexUtf8 } from '@shared/utils/digests';
import { buildFullOwnerPermissionsV1, type ActiveWalletAuthorityV1 } from '@shared/authorization';
import type { VersionedJsonObject } from '../../../framework/versionedJsonRecordStore';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import {
  CloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordBatchPutResultV1,
  type CloudflareD1VersionedJsonRecordScopeV1,
} from '../versionedJson/d1VersionedJsonRecordStore';
import {
  PASSKEY_ENVELOPE_KEY_PREFIX,
  passkeyCustodyEnvelopeLocatorOf,
  passkeyCustodyEnvelopeRecordKey,
} from './d1PasskeyCustodyEnvelopeStore';
import { prepareD1WebAuthnAuthenticatorInsertStatement } from '../webauthn/d1WebAuthnStore';
import type { WebAuthnAuthenticatorRecord } from '../webauthn/d1WebAuthnRecords';
import {
  prepareD1WebAuthnCredentialBindingInsertStatement,
  type WebAuthnCredentialBindingRecord,
} from '../../../../core/WebAuthnCredentialBindingStore';
import { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  D1WalletAuthorityStore,
  prepareD1WalletAuthorityPutStatement,
} from '../wallet/d1WalletAuthorityStore';
import type { EmailOtpWalletEnrollmentRecord } from '../../../../core/EmailOtpStores';
import { parseEmailOtpWalletEnrollmentRow } from '../emailOtp/d1EmailOtpRecords';
import {
  parseWalletRecoveryGoogleEmailOtpAttemptRecord,
  walletRecoveryGoogleEmailOtpFinalizationInput,
  walletRecoveryGoogleEmailOtpAttemptKey,
  type WalletRecoveryGoogleEmailOtpFinalizationInput,
} from './d1WalletRecoveryGoogleEmailOtpRecords';
import { emailOtpDeviceEnrollmentId, WALLET_EMAIL_OTP_ACTIONS } from '@shared/utils/emailOtpDomain';

type ActivePasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

type ActiveEmailOtpWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'email_otp'; readonly status: 'active' }
>;

function recoverySignerActivationsMatchContinuity(input: {
  readonly recovery: ActiveWalletAuthorityV1['signerActivations'];
  readonly continuity: ActiveWalletAuthorityV1['signerActivations'];
}): boolean {
  if (
    alphabetizeStringify(input.recovery.keyFamilies) !==
    alphabetizeStringify(input.continuity.keyFamilies)
  ) {
    return false;
  }
  const recoveryEcdsa = input.recovery.ecdsa;
  const continuityEcdsa = input.continuity.ecdsa;
  if (
    alphabetizeStringify(recoveryEcdsa ?? null) !== alphabetizeStringify(continuityEcdsa ?? null)
  ) {
    return false;
  }
  const recoveryEd25519 = input.recovery.ed25519;
  const continuityEd25519 = input.continuity.ed25519;
  if (!recoveryEd25519 || !continuityEd25519) {
    return recoveryEd25519 === continuityEd25519;
  }
  return (
    alphabetizeStringify(recoveryEd25519.signer) ===
      alphabetizeStringify(continuityEd25519.signer) &&
    alphabetizeStringify(recoveryEd25519.materialActivation) ===
      alphabetizeStringify(continuityEd25519.materialActivation)
  );
}

const WEB_AUTHN_RECOVERY_CHALLENGE_CAS_GUARD = `
  INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
  SELECT 1
   WHERE changes() = 0
`;

const RECOVERY_CODE_LOCATOR_CAS_GUARD = `
  INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
  SELECT 1
   WHERE changes() = 0
`;

const WALLET_RECOVERY_GOOGLE_EMAIL_OTP_ATTEMPT_CAS_GUARD = `
  INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
  SELECT 1
   WHERE changes() = 0
`;

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

/**
 * The registration commit: one custody envelope, one recovery envelope set,
 * and its backup acknowledgement, written together or not at all.
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

type WalletCustodyCommitRecord =
  | PasskeyCustodyEnvelopeRecord
  | WalletRecoveryEnvelopeSetRecord
  | WalletRecoveryBackupAcknowledgementV1;

export type CloudflareD1WalletCustodyCommitStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
  readonly walletAuthMethodStore?: D1WalletAuthMethodStore;
  readonly walletAuthorityStore?: Pick<D1WalletAuthorityStore, 'readById'>;
};

export type WalletCustodyRegistrationCommit = {
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
  readonly recoveryBackupAcknowledgement: WalletRecoveryBackupAcknowledgementV1;
  readonly recoveryCodeLocators: readonly WalletRecoveryCodeLocatorRecord[];
};

export type WalletRecoveryCodeLocatorRecord = {
  readonly locatorB64u: RecoveryCodeLocatorV1;
  readonly walletId: WalletId;
  readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
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

export type WalletCustodyRecoveryAuthorityInstallCommitResult =
  | { readonly kind: 'committed' | 'already_committed'; readonly envelopeStoreVersion: string }
  | { readonly kind: 'conflict' }
  | { readonly kind: 'inconsistent'; readonly reason: string };

export type WalletRecoveryEmailEnrollmentCommit =
  | {
      readonly kind: 'existing';
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly statements: readonly [];
    }
  | {
      readonly kind: 'create';
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly statements: readonly D1PreparedStatementLike[];
    };

export type WalletRecoveryGoogleEmailOtpAuthorityInstallCommit = {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly recoveryAttemptStoreVersion: string;
  readonly continuityAuthority: ActiveWalletAuthorityV1;
  readonly authority: ActiveWalletAuthorityV1;
  readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
  readonly expectedRecoverySetVersion: string;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
  readonly walletAuthMethod: ActiveEmailOtpWalletAuthMethodRecordV2;
  readonly enrollmentCommit: WalletRecoveryEmailEnrollmentCommit;
};

/** Recovery sets are wallet-scoped: one set covers the wallet, not one factor. */
export function walletRecoveryBackupAcknowledgementRecordKey(walletId: WalletId): string {
  return `wallet-recovery-backup-ack/${String(walletId)}`;
}

export type WalletRecoveryAuthenticatorCommit = {
  readonly userId: string;
  readonly authenticator: WebAuthnAuthenticatorRecord;
  readonly binding: WebAuthnCredentialBindingRecord;
  readonly walletAuthMethod: ActivePasskeyWalletAuthMethodRecordV2;
  readonly challengeDeleteStatement: D1PreparedStatementLike;
};

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
  if (kind === 'wallet_recovery_backup_acknowledgement_v1') {
    return raw as WalletRecoveryBackupAcknowledgementV1;
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
  if (commit.recoveryCodeLocators.length !== commit.recoverySet.manifestKekWraps.length) {
    return 'recovery code locators do not match the recovery wraps';
  }
  const recoveryKeyIds = new Set(
    commit.recoverySet.manifestKekWraps.map((wrap) => String(wrap.recoveryKeyId)),
  );
  if (recoveryKeyIds.size !== commit.recoverySet.manifestKekWraps.length) {
    return 'recovery wraps must have distinct key ids';
  }
  const locatorKeyIds = new Set<string>();
  const locatorValues = new Set<string>();
  for (const locator of commit.recoveryCodeLocators) {
    if (String(locator.walletId) !== String(commit.recoverySet.walletId)) {
      return 'recovery code locator names a different wallet';
    }
    const recoveryKeyId = String(locator.recoveryKeyId);
    const locatorValue = String(locator.locatorB64u);
    if (
      !recoveryKeyIds.has(recoveryKeyId) ||
      locatorKeyIds.has(recoveryKeyId) ||
      locatorValues.has(locatorValue)
    ) {
      return 'recovery code locators do not match the recovery wraps';
    }
    locatorKeyIds.add(recoveryKeyId);
    locatorValues.add(locatorValue);
  }
  if (
    commit.recoveryBackupAcknowledgement.walletId !== String(commit.recoverySet.walletId) ||
    commit.recoveryBackupAcknowledgement.issuedAtMs !== commit.recoverySet.issuedAtMs
  ) {
    return 'recovery backup acknowledgement does not match the issued recovery set';
  }
  return null;
}

function isRecoveryCodeLocatorCollision(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('wallet_recovery_code_locators') && /unique|constraint/i.test(message);
}

export class CloudflareD1WalletCustodyCommitStore {
  private readonly database: D1DatabaseLike;
  private readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
  private readonly records: CloudflareD1VersionedJsonRecordStore<WalletCustodyCommitRecord>;
  private readonly walletAuthMethodStore: D1WalletAuthMethodStore;
  private readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;

  constructor(options: CloudflareD1WalletCustodyCommitStoreOptions) {
    this.database = options.database;
    this.scope = options.scope;
    this.walletAuthMethodStore =
      options.walletAuthMethodStore ??
      new D1WalletAuthMethodStore({
        database: options.database,
        namespace: options.scope.namespace,
        orgId: options.scope.orgId,
        projectId: options.scope.projectId,
        envId: options.scope.envId,
      });
    this.walletAuthorityStore =
      options.walletAuthorityStore ??
      new D1WalletAuthorityStore({
        database: options.database,
        scope: options.scope,
      });
    this.records = new CloudflareD1VersionedJsonRecordStore<WalletCustodyCommitRecord>({
      database: options.database,
      scope: options.scope,
      encode: encodeRecord,
      parse: parseRecordOrNull,
      keyPrefix: PASSKEY_ENVELOPE_KEY_PREFIX,
    });
  }

  async readRecoveryCodeLocator(
    locatorB64u: RecoveryCodeLocatorV1,
  ): Promise<WalletRecoveryCodeLocatorRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT locator_b64u, wallet_id, recovery_key_id
           FROM wallet_recovery_code_locators
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND locator_b64u = ?5`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(locatorB64u),
      )
      .first<{
        readonly locator_b64u?: unknown;
        readonly wallet_id?: unknown;
        readonly recovery_key_id?: unknown;
      }>();
    if (!row) return null;
    const walletId = parseWalletId(row.wallet_id);
    if (!walletId.ok) return null;
    try {
      const parsedLocator = parseRecoveryCodeLocatorV1(row.locator_b64u);
      if (String(parsedLocator) !== String(locatorB64u)) return null;
      return {
        locatorB64u: parsedLocator,
        walletId: walletId.value,
        recoveryKeyId: parseDerivedWalletRecoveryKeyId(row.recovery_key_id),
      };
    } catch {
      return null;
    }
  }

  /** Reads locator metadata without ever materializing a recovery code. */
  async readRecoveryCodeLocatorByRecoveryKey(input: {
    readonly walletId: WalletId;
    readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
  }): Promise<WalletRecoveryCodeLocatorRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT locator_b64u, wallet_id, recovery_key_id
           FROM wallet_recovery_code_locators
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND wallet_id = ?5
            AND recovery_key_id = ?6
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(input.walletId),
        String(input.recoveryKeyId),
      )
      .first<{
        readonly locator_b64u?: unknown;
        readonly wallet_id?: unknown;
        readonly recovery_key_id?: unknown;
      }>();
    if (!row) return null;
    const walletId = parseWalletId(row.wallet_id);
    if (!walletId.ok || walletId.value !== input.walletId) return null;
    try {
      const recoveryKeyId = parseDerivedWalletRecoveryKeyId(row.recovery_key_id);
      return {
        locatorB64u: parseRecoveryCodeLocatorV1(row.locator_b64u),
        walletId: walletId.value,
        recoveryKeyId,
      };
    } catch {
      return null;
    }
  }

  private prepareRecoveryCodeLocatorInsertStatement(
    locator: WalletRecoveryCodeLocatorRecord,
  ): D1PreparedStatementLike {
    return this.database
      .prepare(
        `INSERT INTO wallet_recovery_code_locators
          (namespace, org_id, project_id, env_id, locator_b64u, wallet_id, recovery_key_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(locator.locatorB64u),
        String(locator.walletId),
        String(locator.recoveryKeyId),
      );
  }

  private prepareRecoveryCodeLocatorsDeleteForWalletStatement(
    walletId: WalletId,
  ): D1PreparedStatementLike {
    return this.database
      .prepare(
        `DELETE FROM wallet_recovery_code_locators
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND wallet_id = ?5`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(walletId),
      );
  }

  private prepareRecoveryCodeLocatorCollisionGuardStatement(
    locators: readonly WalletRecoveryCodeLocatorRecord[],
  ): D1PreparedStatementLike {
    if (locators.length === 0) {
      throw new Error('recovery code locator collision guard requires locators');
    }
    const locatorParameters = locators.map((_, index) => `?${5 + index}`).join(', ');
    return this.database
      .prepare(
        `INSERT INTO wallet_recovery_code_locators
          (namespace, org_id, project_id, env_id, locator_b64u, wallet_id, recovery_key_id)
         SELECT namespace, org_id, project_id, env_id, locator_b64u, wallet_id, recovery_key_id
           FROM wallet_recovery_code_locators
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND locator_b64u IN (${locatorParameters})`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        ...locators.map((locator) => String(locator.locatorB64u)),
      );
  }

  /** Retains the locator tombstone while `changes()` proves it existed in the atomic commit. */
  private prepareRecoveryCodeLocatorConsumeStatement(input: {
    readonly walletId: WalletId;
    readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
  }): D1PreparedStatementLike {
    return this.database
      .prepare(
        `UPDATE wallet_recovery_code_locators
            SET locator_b64u = locator_b64u
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND wallet_id = ?5
            AND recovery_key_id = ?6`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(input.walletId),
        String(input.recoveryKeyId),
      );
  }

  private prepareWalletRecoveryGoogleEmailOtpAttemptFinalizeStatement(input: {
    readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
    readonly expectedVersion: string;
    readonly finalizedAtMs: number;
  }): D1PreparedStatementLike {
    return this.database
      .prepare(
        `UPDATE router_ab_yao_versioned_json_records
            SET version = version + 1,
                record_json = json_set(record_json, '$.state', 'finalized'),
                updated_at_ms = ?20
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_key = ?5
            AND version = ?6
            AND json_extract(record_json, '$.version') = ?7
            AND json_extract(record_json, '$.state') = ?8
            AND json_extract(record_json, '$.walletId') = ?9
            AND json_extract(record_json, '$.orgId') = ?10
            AND json_extract(record_json, '$.reservationId') = ?11
            AND json_extract(record_json, '$.recoveryOperationId') = ?12
            AND json_extract(record_json, '$.targetDeviceId') = ?13
            AND json_extract(record_json, '$.targetAuthorityId') = ?14
            AND json_extract(record_json, '$.targetWalletAuthMethodId') = ?15
            AND json_extract(record_json, '$.challengeId') = ?16
            AND json_extract(record_json, '$.providerSubject') = ?17
            AND json_extract(record_json, '$.verifiedEmail') = ?18
            AND json_extract(record_json, '$.ownerProofBindingDigest') = ?19
            AND json_extract(record_json, '$.target.kind') = 'google_email_otp'
            AND json_extract(record_json, '$.target.googleProvider') = 'google'`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        `wallet-recovery-google-email-otp:${walletRecoveryGoogleEmailOtpAttemptKey(
          input.recovery.recoveryOperationId,
        )}`,
        input.expectedVersion,
        'wallet_recovery_google_email_otp_attempt_v1',
        'otp_verified',
        String(input.recovery.walletId),
        input.recovery.orgId,
        String(input.recovery.reservationId),
        String(input.recovery.recoveryOperationId),
        String(input.recovery.targetDeviceId),
        String(input.recovery.targetAuthorityId),
        String(input.recovery.targetWalletAuthMethodId),
        input.recovery.challengeId,
        input.recovery.providerSubject,
        input.recovery.verifiedEmail,
        String(input.recovery.ownerProofBindingDigest),
        input.finalizedAtMs,
      );
  }

  /** The OTP verifier normally consumes this row before finalization. */
  private prepareWalletRecoveryGoogleEmailOtpChallengeDeleteStatement(input: {
    readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  }): D1PreparedStatementLike {
    return this.database
      .prepare(
        `DELETE FROM email_otp_challenges
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND challenge_id = ?5
            AND challenge_subject_id = ?6
            AND wallet_id = ?7
            AND record_org_id = ?8
            AND otp_channel = ?9
            AND owner_proof_binding_digest = ?10
            AND action = ?11
            AND operation = ?12`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        input.recovery.challengeId,
        input.recovery.providerSubject,
        String(input.recovery.walletId),
        input.recovery.orgId,
        'email_otp',
        String(input.recovery.ownerProofBindingDigest),
        WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap,
        'wallet_unlock',
      );
  }

  private async readEmailOtpEnrollment(
    walletId: WalletId,
  ): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT record_json, updated_at_ms
           FROM email_otp_wallet_enrollments
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND wallet_id = ?5
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(walletId),
      )
      .first<{ readonly record_json?: unknown; readonly updated_at_ms?: unknown }>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  private async walletRecoveryGoogleEmailOtpFinalizedAttemptMatches(
    recovery: WalletRecoveryGoogleEmailOtpFinalizationInput,
  ): Promise<boolean> {
    const row = await this.database
      .prepare(
        `SELECT record_json
           FROM router_ab_yao_versioned_json_records
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_key = ?5
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        `wallet-recovery-google-email-otp:${walletRecoveryGoogleEmailOtpAttemptKey(
          recovery.recoveryOperationId,
        )}`,
      )
      .first<{ readonly record_json?: unknown }>();
    if (!row) return false;
    let raw: unknown = row.record_json;
    if (typeof raw === 'string') {
      try {
        raw = JSON.parse(raw);
      } catch {
        return false;
      }
    }
    const attempt = parseWalletRecoveryGoogleEmailOtpAttemptRecord(raw);
    return (
      attempt?.state === 'finalized' &&
      alphabetizeStringify(walletRecoveryGoogleEmailOtpFinalizationInput(attempt)) ===
        alphabetizeStringify(recovery)
    );
  }

  private async walletRecoveryGoogleEmailOtpChallengeExists(challengeId: string): Promise<boolean> {
    const row = await this.database
      .prepare(
        `SELECT 1
           FROM email_otp_challenges
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND challenge_id = ?5
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        challengeId,
      )
      .first<{ readonly one?: unknown }>();
    return row !== null;
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
    const recoveryBackupAcknowledgementKey = walletRecoveryBackupAcknowledgementRecordKey(
      commit.recoverySet.walletId,
    );

    let stored: Awaited<ReturnType<typeof this.records.putManyWithAdditionalStatements>>;
    try {
      stored = await this.records.putManyWithAdditionalStatements(
        [
          { key: envelopeKey, value: commit.envelope, expectedVersion: null },
          { key: recoverySetKey, value: commit.recoverySet, expectedVersion: null },
          {
            key: recoveryBackupAcknowledgementKey,
            value: commit.recoveryBackupAcknowledgement,
            expectedVersion: null,
          },
        ],
        commit.recoveryCodeLocators.map((locator) =>
          this.prepareRecoveryCodeLocatorInsertStatement(locator),
        ),
      );
    } catch (error: unknown) {
      if (isRecoveryCodeLocatorCollision(error)) {
        return { kind: 'inconsistent', reason: 'recovery code locator already exists' };
      }
      throw error;
    }
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
    const recoveryBackupAcknowledgementVersion = stored.versions.find(
      (entry) => entry.key === recoveryBackupAcknowledgementKey,
    );
    if (!envelopeVersion || !recoverySetVersion || !recoveryBackupAcknowledgementVersion) {
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

  async listWalletAuthMethods(walletId: WalletId): Promise<readonly WalletAuthMethodRecordV2[]> {
    return await this.walletAuthMethodStore.listForWalletV2({ walletId: String(walletId) });
  }

  async readWalletAuthMethodById(
    walletAuthMethodId: WalletAuthMethodId,
  ): Promise<WalletAuthMethodRecordV2 | null> {
    return await this.walletAuthMethodStore.readByIdV2({ walletAuthMethodId });
  }

  async readPasskeyWalletAuthMethod(input: {
    readonly rpId: string;
    readonly credentialIdB64u: string;
  }): Promise<Extract<WalletAuthMethodRecordV2, { readonly kind: 'passkey' }> | null> {
    const method = await this.walletAuthMethodStore.getPasskeyV2(input);
    return method?.kind === 'passkey' ? method : null;
  }

  /**
   * Reads the wallet's backup acknowledgement, if any.
   *
   * Absent is the normal state for a wallet whose owner has not confirmed
   * saving their codes, so it is `null` rather than an error.
   */
  async readBackupAcknowledgement(
    walletId: WalletId,
  ): Promise<WalletRecoveryBackupAcknowledgementV1 | null> {
    const read = await this.records.read(walletRecoveryBackupAcknowledgementRecordKey(walletId));
    if (read.kind === 'missing') return null;
    const parsed = parseWalletRecoveryBackupAcknowledgementV1(read.value, {
      expectedWalletId: String(walletId),
    });
    return parsed.ok ? parsed.record : null;
  }

  /**
   * Records that the owner confirmed saving their codes.
   *
   * Written with no expected version, unlike the recovery set: this row is
   * cosmetic, a repeat acknowledgement is not a conflict worth surfacing to
   * someone pressing a button, and it shares no record with the wraps a spend
   * updates — which is exactly why it is a separate key.
   */
  async writeBackupAcknowledgement(
    record: WalletRecoveryBackupAcknowledgementV1,
  ): Promise<{ kind: 'stored' } | { kind: 'conflict' }> {
    const key = walletRecoveryBackupAcknowledgementRecordKey(requireWalletId(record.walletId));
    const existing = await this.records.read(key);
    const result = await this.records.put(
      key,
      record as unknown as WalletCustodyCommitRecord,
      existing.kind === 'missing' ? null : existing.version,
    );
    return result.kind === 'stored' ? { kind: 'stored' } : { kind: 'conflict' };
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

  /**
   * Replaces a complete recovery set and carries the backup-ack row through
   * the same CAS. The acknowledgement still names the previous issuance, so
   * status naturally reports the fresh set as outstanding until the UI calls
   * the explicit acknowledge route. Both rows are guarded against races.
   */
  async replaceRecoveryEnvelopeSetAndPreserveBackupAcknowledgement(input: {
    readonly record: WalletRecoveryEnvelopeSetRecord;
    readonly expectedRecoverySetVersion: string;
    readonly recoveryCodeLocators: readonly WalletRecoveryCodeLocatorRecord[];
  }): Promise<
    { kind: 'stored'; storeVersion: string } | { kind: 'conflict' } | { kind: 'collision' }
  > {
    const acknowledgementKey = walletRecoveryBackupAcknowledgementRecordKey(input.record.walletId);
    const existingAcknowledgement = await this.records.read(acknowledgementKey);
    const mutations = [
      {
        key: walletRecoveryEnvelopeSetRecordKey(input.record.walletId),
        value: input.record,
        expectedVersion: input.expectedRecoverySetVersion,
      },
      ...(existingAcknowledgement.kind === 'present'
        ? [
            {
              key: acknowledgementKey,
              value: existingAcknowledgement.value,
              expectedVersion: existingAcknowledgement.version,
            },
          ]
        : []),
    ] as const;
    let stored: Awaited<ReturnType<typeof this.records.putManyWithAdditionalStatements>>;
    try {
      stored = await this.records.putManyWithAdditionalStatements(mutations, [
        this.prepareRecoveryCodeLocatorCollisionGuardStatement(input.recoveryCodeLocators),
        this.prepareRecoveryCodeLocatorsDeleteForWalletStatement(input.record.walletId),
        ...input.recoveryCodeLocators.map((locator) =>
          this.prepareRecoveryCodeLocatorInsertStatement(locator),
        ),
      ]);
    } catch (error: unknown) {
      if (isRecoveryCodeLocatorCollision(error)) return { kind: 'collision' };
      throw error;
    }
    if (stored.kind === 'version_mismatch') return { kind: 'conflict' };
    const version = stored.versions.find(
      (entry) => entry.key === walletRecoveryEnvelopeSetRecordKey(input.record.walletId),
    );
    if (!version) throw new Error('recovery-set rotation did not report its store version');
    return { kind: 'stored', storeVersion: version.version };
  }

  /**
   * Installs a fresh recovered-device authority and Passkey target while
   * consuming its held code in one D1 transaction. The continuity authority,
   * methods, envelopes, and sessions are deliberately never updated here.
   * Current recovery activation output has no fresh Ed25519 reference, so the
   * first functional slice requires the target authority to reuse the exact
   * anchor signer activation set.
   */
  async commitRecoveryAuthorityInstall(input: {
    readonly continuityAuthority: ActiveWalletAuthorityV1;
    readonly authority: ActiveWalletAuthorityV1;
    readonly recoverySet: WalletRecoveryEnvelopeSetRecord;
    readonly expectedRecoverySetVersion: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly reservationId: RecoveryCodeReservationId;
    readonly recoveryKeyId: DerivedWalletRecoveryKeyId;
    readonly authenticatorCommit: WalletRecoveryAuthenticatorCommit;
  }): Promise<WalletCustodyRecoveryAuthorityInstallCommitResult> {
    const walletId = input.recoverySet.walletId;
    if (
      String(input.authority.walletId) !== String(walletId) ||
      String(input.continuityAuthority.walletId) !== String(walletId)
    ) {
      return { kind: 'inconsistent', reason: 'recovery authority records name different wallets' };
    }
    if (
      input.authority.state !== 'active' ||
      input.authority.provenance.kind !== 'wallet_recovery' ||
      input.authority.provenance.continuityAuthorityId !== input.continuityAuthority.authorityId ||
      input.authority.authorityId === input.continuityAuthority.authorityId ||
      input.authority.principal.deviceId === input.continuityAuthority.principal.deviceId
    ) {
      return {
        kind: 'inconsistent',
        reason: 'recovery authority must be a fresh active device authority',
      };
    }
    if (
      alphabetizeStringify(input.authority.permissions) !==
      alphabetizeStringify(buildFullOwnerPermissionsV1())
    ) {
      return {
        kind: 'inconsistent',
        reason: 'recovery authority must have full-owner permissions',
      };
    }
    if (
      !recoverySignerActivationsMatchContinuity({
        recovery: input.authority.signerActivations,
        continuity: input.continuityAuthority.signerActivations,
      })
    ) {
      return {
        kind: 'inconsistent',
        reason: 'recovery authority signer activations violate custody continuity',
      };
    }
    if (
      input.replacementEnvelope.walletId !== walletId ||
      input.replacementEnvelope.binding.kind !== 'wallet_custody_seed_v1' ||
      input.replacementEnvelope.factor.kind !== 'passkey' ||
      input.replacementEnvelope.lifecycle.state !== 'active' ||
      Number(input.replacementEnvelope.envelopeRevision) !== 1 ||
      input.replacementEnvelope.ownership.kind !== 'method_bound'
    ) {
      return {
        kind: 'inconsistent',
        reason: 'recovery install requires a first-revision active wallet custody envelope',
      };
    }
    if (input.authenticatorCommit.userId !== String(walletId)) {
      return { kind: 'inconsistent', reason: 'replacement authenticator names a different wallet' };
    }
    const targetMethod = input.authenticatorCommit.walletAuthMethod;
    if (
      targetMethod.kind !== 'passkey' ||
      targetMethod.status !== 'active' ||
      targetMethod.walletId !== walletId ||
      targetMethod.walletAuthorityId !== input.authority.authorityId ||
      input.replacementEnvelope.ownership.walletAuthMethodId !== targetMethod.walletAuthMethodId ||
      targetMethod.rpId !== input.replacementEnvelope.factor.rpId ||
      targetMethod.credentialIdB64u !== input.replacementEnvelope.factor.credentialIdB64u ||
      targetMethod.credentialPublicKeyB64u !==
        input.authenticatorCommit.authenticator.credentialPublicKeyB64u ||
      targetMethod.counter !== input.authenticatorCommit.authenticator.counter ||
      input.authenticatorCommit.binding.userId !== String(walletId) ||
      input.authenticatorCommit.binding.rpId !== targetMethod.rpId ||
      input.authenticatorCommit.binding.credentialIdB64u !== targetMethod.credentialIdB64u ||
      input.authenticatorCommit.authenticator.credentialIdB64u !== targetMethod.credentialIdB64u ||
      !String(targetMethod.walletAuthMethodId).startsWith('wallet-auth-method:')
    ) {
      return {
        kind: 'inconsistent',
        reason: 'recovery authority, method, envelope, and authenticator disagree',
      };
    }
    const matchingConsumptions = input.recoverySet.manifestKekWraps.filter(
      (wrap) =>
        wrap.lifecycle.state === 'consumed' && wrap.lifecycle.reservationId === input.reservationId,
    );
    if (matchingConsumptions.length !== 1) {
      return {
        kind: 'inconsistent',
        reason: 'recovery install must consume exactly its reserved recovery code',
      };
    }

    const envelopeKey = passkeyCustodyEnvelopeRecordKey(
      passkeyCustodyEnvelopeLocatorOf(input.replacementEnvelope),
    );
    const recoverySetKey = walletRecoveryEnvelopeSetRecordKey(walletId);
    const authorityStatement = prepareD1WalletAuthorityPutStatement({
      database: this.database,
      scope: {
        namespace: this.scope.namespace,
        orgId: this.scope.orgId,
        projectId: this.scope.projectId,
        envId: this.scope.envId,
      },
      authority: input.authority,
    });
    const authenticatorStatement = prepareD1WebAuthnAuthenticatorInsertStatement({
      database: this.database,
      scope: {
        namespace: this.scope.namespace,
        orgId: this.scope.orgId,
        projectId: this.scope.projectId,
        envId: this.scope.envId,
      },
      userId: input.authenticatorCommit.userId,
      record: input.authenticatorCommit.authenticator,
    });
    const bindingStatement = prepareD1WebAuthnCredentialBindingInsertStatement({
      database: this.database,
      scope: {
        namespace: this.scope.namespace,
        orgId: this.scope.orgId,
        projectId: this.scope.projectId,
        envId: this.scope.envId,
      },
      record: input.authenticatorCommit.binding,
    });
    const walletAuthMethodStatements =
      this.walletAuthMethodStore.prepareV2InsertStatements(targetMethod);
    let stored: CloudflareD1VersionedJsonRecordBatchPutResultV1;
    try {
      stored = await this.records.putManyWithAdditionalStatements(
        [
          {
            key: recoverySetKey,
            value: input.recoverySet,
            expectedVersion: input.expectedRecoverySetVersion,
          },
          { key: envelopeKey, value: input.replacementEnvelope, expectedVersion: null },
        ],
        [
          /* The authority precedes its foreign-keyed active method. Existing
             method/envelope/session rows are absent from this mutation list. */
          authorityStatement,
          ...walletAuthMethodStatements,
          authenticatorStatement,
          bindingStatement,
          input.authenticatorCommit.challengeDeleteStatement,
          this.database.prepare(WEB_AUTHN_RECOVERY_CHALLENGE_CAS_GUARD),
          this.prepareRecoveryCodeLocatorConsumeStatement({
            walletId,
            recoveryKeyId: input.recoveryKeyId,
          }),
          this.database.prepare(RECOVERY_CODE_LOCATOR_CAS_GUARD),
        ],
      );
    } catch {
      /* Insert-only target rows and both consume guards roll back every part
         of the batch. The held reservation remains retryable after a race. */
      return { kind: 'conflict' };
    }
    if (stored.kind === 'version_mismatch') {
      const [recoveryRead, envelopeRead, authorityRead, methodRead, locatorRead] =
        await Promise.all([
          this.readRecoveryEnvelopeSet(walletId),
          this.records.read(envelopeKey),
          this.walletAuthorityStore.readById(input.authority.authorityId),
          this.walletAuthMethodStore.readByIdV2({
            walletAuthMethodId: targetMethod.walletAuthMethodId,
          }),
          this.readRecoveryCodeLocatorByRecoveryKey({
            walletId,
            recoveryKeyId: input.recoveryKeyId,
          }),
        ]);
      const alreadyConsumed = recoveryRead?.record.manifestKekWraps.some(
        (wrap) =>
          wrap.lifecycle.state === 'consumed' &&
          wrap.lifecycle.reservationId === input.reservationId,
      );
      const sameEnvelope =
        envelopeRead.kind === 'present' &&
        envelopeRead.value.kind !== 'wallet_recovery_envelope_set_v1' &&
        alphabetizeStringify(envelopeRead.value) ===
          alphabetizeStringify(input.replacementEnvelope);
      const sameAuthority =
        authorityRead !== null &&
        alphabetizeStringify(authorityRead) === alphabetizeStringify(input.authority);
      const sameMethod =
        methodRead !== null &&
        alphabetizeStringify(methodRead) === alphabetizeStringify(targetMethod);
      if (alreadyConsumed && sameEnvelope && sameAuthority && sameMethod && locatorRead) {
        return {
          kind: 'already_committed',
          envelopeStoreVersion: envelopeRead.version,
        };
      }
      return { kind: 'conflict' };
    }
    const envelopeVersion = stored.versions.find((entry) => entry.key === envelopeKey);
    if (!envelopeVersion) {
      throw new Error('wallet recovery install did not report the envelope version');
    }
    return { kind: 'committed', envelopeStoreVersion: envelopeVersion.version };
  }

  /**
   * Exact readback for a retry after the recovery attempt was deleted. The
   * target rows and the consumed reservation are the durable receipt; no
   * source authority, method, envelope, or session is consulted for mutation.
   */
  async resolveRecoveryGoogleEmailOtpReplay(input: {
    readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
  }): Promise<WalletCustodyRecoveryAuthorityInstallCommitResult> {
    const recovery = input.recovery;
    const walletId = recovery.walletId;
    const replacement = input.replacementEnvelope;
    if (
      replacement.walletId !== walletId ||
      replacement.binding.kind !== 'wallet_custody_seed_v1' ||
      replacement.factor.kind !== 'email_otp' ||
      replacement.lifecycle.state !== 'active' ||
      Number(replacement.envelopeRevision) !== 1 ||
      replacement.ownership.kind !== 'method_bound' ||
      replacement.ownership.walletAuthMethodId !== recovery.targetWalletAuthMethodId
    ) {
      return { kind: 'inconsistent', reason: 'recovery replay envelope is not target-bound' };
    }
    if (
      input.enrollment.walletId !== walletId ||
      input.enrollment.orgId !== recovery.orgId ||
      input.enrollment.providerUserId !== recovery.providerSubject ||
      input.enrollment.verifiedEmail !== recovery.verifiedEmail ||
      replacement.factor.enrollmentId !== input.enrollment.enrollmentId ||
      replacement.factor.enrollmentSealKeyVersion !== input.enrollment.enrollmentSealKeyVersion
    ) {
      return { kind: 'inconsistent', reason: 'recovery replay enrollment is not target-bound' };
    }
    const expectedEmailHashHex = await sha256HexUtf8(recovery.verifiedEmail);
    const recoverySet = await this.readRecoveryEnvelopeSet(walletId);
    if (!recoverySet) return { kind: 'conflict' };
    const consumed = recoverySet.record.manifestKekWraps.filter(
      (wrap) =>
        wrap.lifecycle.state === 'consumed' &&
        wrap.lifecycle.reservationId === recovery.reservationId,
    );
    if (consumed.length !== 1) return { kind: 'conflict' };
    const recoveryKeyId = consumed[0]?.recoveryKeyId;
    if (!recoveryKeyId) return { kind: 'conflict' };
    const envelopeKey = passkeyCustodyEnvelopeRecordKey(
      passkeyCustodyEnvelopeLocatorOf(replacement),
    );
    const [envelopeRead, authority, method, enrollment, finalizedAttemptMatches, challengeExists] =
      await Promise.all([
        this.records.read(envelopeKey),
        this.walletAuthorityStore.readById(recovery.targetAuthorityId),
        this.walletAuthMethodStore.readByIdV2({
          walletAuthMethodId: recovery.targetWalletAuthMethodId,
        }),
        this.readEmailOtpEnrollment(walletId),
        this.walletRecoveryGoogleEmailOtpFinalizedAttemptMatches(recovery),
        this.walletRecoveryGoogleEmailOtpChallengeExists(recovery.challengeId),
      ]);
    const locator = await this.readRecoveryCodeLocatorByRecoveryKey({ walletId, recoveryKeyId });
    const sameEnvelope =
      envelopeRead?.kind === 'present' &&
      envelopeRead.value.kind !== 'wallet_recovery_envelope_set_v1' &&
      alphabetizeStringify(envelopeRead.value) === alphabetizeStringify(replacement);
    const sameAuthority =
      authority !== null &&
      authority.state === 'active' &&
      authority.walletId === walletId &&
      authority.authorityId === recovery.targetAuthorityId &&
      authority.principal.deviceId === recovery.targetDeviceId &&
      authority.provenance.kind === 'wallet_recovery' &&
      authority.provenance.recoveryOperationId === recovery.recoveryOperationId &&
      authority.provenance.continuityAuthorityId !== recovery.targetAuthorityId &&
      alphabetizeStringify(authority.permissions) ===
        alphabetizeStringify(buildFullOwnerPermissionsV1());
    const sameMethod =
      method !== null &&
      method.kind === 'email_otp' &&
      method.status === 'active' &&
      method.walletId === walletId &&
      method.walletAuthorityId === recovery.targetAuthorityId &&
      method.walletAuthMethodId === recovery.targetWalletAuthMethodId &&
      method.emailHashHex === expectedEmailHashHex &&
      method.registrationAuthorityId === recovery.challengeId;
    const sameEnrollment =
      enrollment !== null &&
      alphabetizeStringify(enrollment) === alphabetizeStringify(input.enrollment) &&
      (recovery.targetEnrollment.kind === 'existing'
        ? enrollment.enrollmentId === recovery.targetEnrollment.enrollmentId &&
          enrollment.enrollmentSealKeyVersion === recovery.targetEnrollment.enrollmentSealKeyVersion
        : enrollment.enrollmentId ===
          emailOtpDeviceEnrollmentId(String(walletId), recovery.providerSubject));
    if (
      sameEnvelope &&
      sameAuthority &&
      sameMethod &&
      sameEnrollment &&
      locator !== null &&
      finalizedAttemptMatches &&
      !challengeExists
    ) {
      return { kind: 'already_committed', envelopeStoreVersion: envelopeRead.version };
    }
    return { kind: 'conflict' };
  }

  /** Installs a fresh Email OTP authority and envelope in one D1 transaction. */
  async commitRecoveryGoogleEmailOtpAuthorityInstall(
    input: WalletRecoveryGoogleEmailOtpAuthorityInstallCommit,
  ): Promise<WalletCustodyRecoveryAuthorityInstallCommitResult> {
    const recovery = input.recovery;
    const walletId = recovery.walletId;
    const targetMethod = input.walletAuthMethod;
    const enrollment = input.enrollmentCommit.enrollment;
    if (
      String(input.recoveryAttemptStoreVersion).trim() === '' ||
      input.recoverySet.walletId !== walletId ||
      input.authority.walletId !== walletId ||
      input.continuityAuthority.walletId !== walletId ||
      input.expectedRecoverySetVersion.trim() === ''
    ) {
      return { kind: 'inconsistent', reason: 'recovery Email commit identities are inconsistent' };
    }
    if (
      input.authority.state !== 'active' ||
      input.authority.authorityId !== recovery.targetAuthorityId ||
      input.authority.principal.deviceId !== recovery.targetDeviceId ||
      input.authority.authorityId === input.continuityAuthority.authorityId ||
      input.authority.principal.deviceId === input.continuityAuthority.principal.deviceId ||
      input.authority.provenance.kind !== 'wallet_recovery' ||
      input.authority.provenance.recoveryOperationId !== recovery.recoveryOperationId ||
      input.authority.provenance.continuityAuthorityId !== input.continuityAuthority.authorityId ||
      alphabetizeStringify(input.authority.permissions) !==
        alphabetizeStringify(buildFullOwnerPermissionsV1())
    ) {
      return { kind: 'inconsistent', reason: 'recovery Email authority is not fresh and active' };
    }
    if (
      !recoverySignerActivationsMatchContinuity({
        recovery: input.authority.signerActivations,
        continuity: input.continuityAuthority.signerActivations,
      })
    ) {
      return { kind: 'inconsistent', reason: 'recovery Email signer activations changed' };
    }
    if (
      targetMethod.kind !== 'email_otp' ||
      targetMethod.status !== 'active' ||
      targetMethod.walletId !== walletId ||
      targetMethod.walletAuthorityId !== input.authority.authorityId ||
      targetMethod.walletAuthMethodId !== recovery.targetWalletAuthMethodId ||
      targetMethod.registrationAuthorityId !== recovery.challengeId ||
      !String(targetMethod.walletAuthMethodId).startsWith('wallet-auth-method:')
    ) {
      return { kind: 'inconsistent', reason: 'recovery Email method is not target-bound' };
    }
    const expectedEmailHashHex = await sha256HexUtf8(recovery.verifiedEmail);
    if (targetMethod.emailHashHex !== expectedEmailHashHex) {
      return { kind: 'inconsistent', reason: 'recovery Email method identity changed' };
    }
    if (
      input.replacementEnvelope.walletId !== walletId ||
      input.replacementEnvelope.binding.kind !== 'wallet_custody_seed_v1' ||
      input.replacementEnvelope.factor.kind !== 'email_otp' ||
      input.replacementEnvelope.lifecycle.state !== 'active' ||
      Number(input.replacementEnvelope.envelopeRevision) !== 1 ||
      input.replacementEnvelope.ownership.kind !== 'method_bound' ||
      input.replacementEnvelope.ownership.walletAuthMethodId !== targetMethod.walletAuthMethodId ||
      input.replacementEnvelope.factor.enrollmentId !== enrollment.enrollmentId ||
      input.replacementEnvelope.factor.enrollmentSealKeyVersion !==
        enrollment.enrollmentSealKeyVersion
    ) {
      return { kind: 'inconsistent', reason: 'recovery Email envelope is not target-bound' };
    }
    if (
      enrollment.walletId !== walletId ||
      enrollment.orgId !== recovery.orgId ||
      enrollment.providerUserId !== recovery.providerSubject ||
      enrollment.verifiedEmail !== recovery.verifiedEmail
    ) {
      return { kind: 'inconsistent', reason: 'recovery Email enrollment identity changed' };
    }
    switch (recovery.targetEnrollment.kind) {
      case 'existing':
        if (
          input.enrollmentCommit.kind !== 'existing' ||
          input.enrollmentCommit.statements.length !== 0 ||
          enrollment.enrollmentId !== recovery.targetEnrollment.enrollmentId ||
          enrollment.enrollmentSealKeyVersion !== recovery.targetEnrollment.enrollmentSealKeyVersion
        ) {
          return { kind: 'inconsistent', reason: 'existing recovery Email enrollment changed' };
        }
        break;
      case 'create':
        if (
          input.enrollmentCommit.kind !== 'create' ||
          input.enrollmentCommit.statements.length === 0 ||
          enrollment.providerUserId !== recovery.targetEnrollment.providerSubject ||
          enrollment.verifiedEmail !== recovery.targetEnrollment.verifiedEmail ||
          enrollment.enrollmentId !==
            emailOtpDeviceEnrollmentId(String(walletId), recovery.providerSubject)
        ) {
          return { kind: 'inconsistent', reason: 'new recovery Email enrollment is invalid' };
        }
        break;
    }
    const matchingConsumptions = input.recoverySet.manifestKekWraps.filter(
      (wrap) =>
        wrap.lifecycle.state === 'consumed' &&
        wrap.lifecycle.reservationId === recovery.reservationId &&
        wrap.recoveryKeyId === input.recoveryKeyId,
    );
    if (matchingConsumptions.length !== 1) {
      return {
        kind: 'inconsistent',
        reason: 'recovery Email commit must consume its reserved code',
      };
    }

    const envelopeKey = passkeyCustodyEnvelopeRecordKey(
      passkeyCustodyEnvelopeLocatorOf(input.replacementEnvelope),
    );
    const recoverySetKey = walletRecoveryEnvelopeSetRecordKey(walletId);
    const authorityStatement = prepareD1WalletAuthorityPutStatement({
      database: this.database,
      scope: {
        namespace: this.scope.namespace,
        orgId: this.scope.orgId,
        projectId: this.scope.projectId,
        envId: this.scope.envId,
      },
      authority: input.authority,
    });
    const walletAuthMethodStatements =
      this.walletAuthMethodStore.prepareV2InsertStatements(targetMethod);
    let stored: CloudflareD1VersionedJsonRecordBatchPutResultV1;
    try {
      stored = await this.records.putManyWithAdditionalStatements(
        [
          {
            key: recoverySetKey,
            value: input.recoverySet,
            expectedVersion: input.expectedRecoverySetVersion,
          },
          { key: envelopeKey, value: input.replacementEnvelope, expectedVersion: null },
        ],
        [
          authorityStatement,
          ...input.enrollmentCommit.statements,
          ...walletAuthMethodStatements,
          this.prepareWalletRecoveryGoogleEmailOtpChallengeDeleteStatement({ recovery }),
          this.prepareWalletRecoveryGoogleEmailOtpAttemptFinalizeStatement({
            recovery,
            expectedVersion: input.recoveryAttemptStoreVersion,
            finalizedAtMs: input.authority.updatedAtMs,
          }),
          this.database.prepare(WALLET_RECOVERY_GOOGLE_EMAIL_OTP_ATTEMPT_CAS_GUARD),
          this.prepareRecoveryCodeLocatorConsumeStatement({
            walletId,
            recoveryKeyId: input.recoveryKeyId,
          }),
          this.database.prepare(RECOVERY_CODE_LOCATOR_CAS_GUARD),
        ],
      );
    } catch {
      return { kind: 'conflict' };
    }
    if (stored.kind === 'version_mismatch') {
      return await this.resolveRecoveryGoogleEmailOtpReplay({
        recovery,
        replacementEnvelope: input.replacementEnvelope,
        enrollment,
      });
    }
    const envelopeVersion = stored.versions.find((entry) => entry.key === envelopeKey);
    if (!envelopeVersion) {
      throw new Error('wallet recovery Email install did not report the envelope version');
    }
    return { kind: 'committed', envelopeStoreVersion: envelopeVersion.version };
  }
}
