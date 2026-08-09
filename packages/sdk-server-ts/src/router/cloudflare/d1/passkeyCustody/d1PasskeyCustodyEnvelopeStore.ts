import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import {
  buildRevokedEnvelopeLifecycle,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyDeviceEnvelopeIndexRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  parseWalletCredentialActivityRecordV1,
  type WalletCredentialActivityRecordV1,
} from '@shared/passkey-custody/credentialActivity';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { VersionedJsonObject } from '../../../framework/versionedJsonRecordStore';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import {
  CloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordMutationV1,
  type CloudflareD1VersionedJsonRecordScopeV1,
} from '../versionedJson/d1VersionedJsonRecordStore';
import { admitEnvelopeRevocation } from '../../../domains/passkeyCustody/envelopeRevocationAdmission';

/**
 * Opaque custody storage for factor-sealed custody envelopes.
 *
 * The store validates credential, wallet, lifecycle, revision, and digest
 * facts, and it cannot open an envelope or report its plaintext as live: the
 * KEK only ever exists inside the browser's secure worker. Ciphertext lives
 * here because a browser with empty IndexedDB must be able to retrieve it after
 * an exact WebAuthn assertion — a browser-only record is never the cross-device
 * source of truth.
 *
 * Persistence rides on the shared versioned JSON record store, so CAS, batching,
 * and tenant scoping behave exactly as they do for every other Gateway D1
 * record. Two version identities are deliberately distinct:
 *
 * - the store's opaque `version` string is the transport CAS token;
 * - the domain `envelopeRevision` increments by exactly 1 per rewrap and is
 *   bound into the envelope's AAD, so an old ciphertext cannot be replayed into
 *   a newer revision.
 *
 * A lifecycle transition changes no ciphertext and therefore never bumps
 * `envelopeRevision`.
 */

export const PASSKEY_ENVELOPE_KEY_PREFIX = 'passkey-envelope';
const PASSKEY_CREDENTIAL_ACTIVITY_KEY_PREFIX = 'passkey-credential-activity';

export type CloudflareD1PasskeyCustodyEnvelopeStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
};

/**
 * Identifies the enrolled factor an envelope belongs to.
 *
 * Factors are interchangeable unwrap paths to the same custody seed, so an
 * envelope is addressed by factor rather than by credential alone — otherwise
 * an Email OTP envelope would have no address at all.
 */
export type WalletCustodyFactorRef =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
    }
  | {
      readonly kind: 'email_otp';
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
    };

export type PasskeyCustodyEnvelopeLocator = {
  readonly walletId: WalletId;
  readonly factor: WalletCustodyFactorRef;
  readonly envelopeId: PasskeyEnvelopeId;
};

/** The factor address a stored envelope actually carries. */
function envelopeFactorRef(envelope: PasskeyCustodyEnvelopeRecord): WalletCustodyFactorRef {
  return envelope.factor.kind === 'passkey'
    ? {
        kind: 'passkey',
        rpId: envelope.factor.rpId,
        credentialIdB64u: envelope.factor.credentialIdB64u,
      }
    : {
        kind: 'email_otp',
        enrollmentId: envelope.factor.enrollmentId,
        enrollmentSealKeyVersion: envelope.factor.enrollmentSealKeyVersion,
      };
}

/**
 * The complete factor identity, not a shorthand: RP ID and seal-key version
 * participate in KEK and AAD identity, so a locator that omitted them could
 * resolve an envelope the caller's factor cannot actually open.
 */
function factorKeyPart(factor: WalletCustodyFactorRef): readonly string[] {
  return factor.kind === 'passkey'
    ? ['passkey', String(factor.rpId), String(factor.credentialIdB64u)]
    : ['email_otp', factor.enrollmentId, factor.enrollmentSealKeyVersion];
}

function factorRefsMatch(left: WalletCustodyFactorRef, right: WalletCustodyFactorRef): boolean {
  return JSON.stringify(factorKeyPart(left)) === JSON.stringify(factorKeyPart(right));
}

/**
 * Every terminal outcome of an authenticated envelope lookup. Each non-active
 * branch is an explicit failure the caller must handle: none of them may fall
 * back to deriving a fresh custody root.
 */
export type PasskeyCustodyEnvelopeLookupResult =
  | {
      readonly kind: 'active';
      readonly envelope: PasskeyCustodyEnvelopeRecord;
      /** CAS token for a follow-up rewrap or lifecycle transition. */
      readonly storeVersion: string;
    }
  | {
      readonly kind: 'retired';
      readonly envelopeId: PasskeyEnvelopeId;
      readonly retiredAtMs: number;
    }
  | {
      readonly kind: 'revoked';
      readonly envelopeId: PasskeyEnvelopeId;
      readonly revokedAtMs: number;
    }
  | { readonly kind: 'missing' }
  | {
      readonly kind: 'digest_mismatch';
      readonly envelopeId: PasskeyEnvelopeId;
      readonly storedCiphertextDigestB64u: string;
      readonly actualCiphertextDigestB64u: string;
    };

export type PasskeyCustodyEnvelopeFactorLookupResult =
  | PasskeyCustodyEnvelopeLookupResult
  | { readonly kind: 'conflict' };

/**
 * Whether a browser's cached ciphertext may still be used. A cache is usable
 * only at the exact server revision and digest; anything else must be refetched.
 */
export type PasskeyCustodyEnvelopeCacheValidation =
  | { readonly kind: 'cache_valid'; readonly envelope: PasskeyCustodyEnvelopeRecord }
  | {
      readonly kind: 'cache_stale';
      readonly serverRevision: number;
      readonly serverCiphertextDigestB64u: string;
    }
  | { readonly kind: 'cache_unusable'; readonly lookup: PasskeyCustodyEnvelopeLookupResult };

export type PasskeyCustodyEnvelopePutResult =
  | { readonly kind: 'stored'; readonly storeVersion: string; readonly envelopeRevision: number }
  | { readonly kind: 'version_mismatch' }
  | { readonly kind: 'revision_conflict'; readonly expectedRevision: number }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'terminal_lifecycle'; readonly state: 'revoked' };

export type PasskeyCustodyEnvelopeRevocationResult =
  | {
      readonly kind: 'stored';
      readonly revokedEnvelopeIds: readonly PasskeyEnvelopeId[];
    }
  | { readonly kind: 'refused'; readonly reason: string }
  | { readonly kind: 'version_mismatch' };

export type WalletCredentialActivityProjection = {
  readonly index: PasskeyDeviceEnvelopeIndexRecord;
  readonly activity: WalletCredentialActivityRecordV1;
};

export type WalletCredentialActivityMutationResult =
  | { readonly kind: 'updated'; readonly projection: WalletCredentialActivityProjection }
  | { readonly kind: 'missing' }
  | { readonly kind: 'conflict' }
  | { readonly kind: 'invalid_label'; readonly reason: string };

function encodeEnvelope(envelope: PasskeyCustodyEnvelopeRecord): VersionedJsonObject {
  // The record is already a plain JSON-safe object; round-tripping it through
  // the parser on read is what enforces the schema, not this encoder.
  return envelope as unknown as VersionedJsonObject;
}

function parseEnvelopeOrNull(raw: unknown): PasskeyCustodyEnvelopeRecord | null {
  try {
    return parsePasskeyCustodyEnvelopeRecord(raw);
  } catch {
    return null;
  }
}

function parseActivityRecordOrNull(raw: unknown): WalletCredentialActivityRecordV1 | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const walletId = (raw as Record<string, unknown>).walletId;
  if (typeof walletId !== 'string' || !walletId.trim()) return null;
  const parsed = parseWalletCredentialActivityRecordV1(raw, {
    expectedWalletId: walletId,
  });
  return parsed.ok ? parsed.record : null;
}

async function ciphertextDigestB64u(sealedCustodySecretB64u: string): Promise<string> {
  const ciphertext = base64UrlDecode(sealedCustodySecretB64u);
  return base64UrlEncode(await sha256Bytes(ciphertext));
}

/**
 * The record key for one envelope, exported so the registration commit path
 * addresses envelopes with this exact definition rather than a copy of it. A
 * second spelling of this key would write rows no lookup could ever find.
 *
 * Envelopes are addressed by wallet, factor, and envelope id together, so a
 * lookup can never return an envelope belonging to another factor even if the
 * envelope id were guessed. JSON-encoded so no delimiter inside an id can
 * splice one locator into another: enrollment ids are caller strings and
 * domain ids permit ':'. A joined string would let
 * {enrollment "e", envelope "x:y"} collide with {enrollment "e:x", envelope "y"}.
 */
export function passkeyCustodyEnvelopeRecordKey(locator: PasskeyCustodyEnvelopeLocator): string {
  return JSON.stringify([
    String(locator.walletId),
    ...factorKeyPart(locator.factor),
    String(locator.envelopeId),
  ]);
}

/** The factor address a stored envelope carries, for callers building locators. */
export function passkeyCustodyEnvelopeLocatorOf(
  envelope: PasskeyCustodyEnvelopeRecord,
): PasskeyCustodyEnvelopeLocator {
  return envelopeLocator(envelope);
}

export class CloudflareD1PasskeyCustodyEnvelopeStore {
  private readonly records: CloudflareD1VersionedJsonRecordStore<PasskeyCustodyEnvelopeRecord>;
  private readonly activityRecords: CloudflareD1VersionedJsonRecordStore<WalletCredentialActivityRecordV1>;
  private readonly database: D1DatabaseLike;
  private readonly scope: CloudflareD1VersionedJsonRecordScopeV1;

  constructor(options: CloudflareD1PasskeyCustodyEnvelopeStoreOptions) {
    this.database = options.database;
    this.scope = options.scope;
    this.records = new CloudflareD1VersionedJsonRecordStore<PasskeyCustodyEnvelopeRecord>({
      database: options.database,
      scope: options.scope,
      encode: encodeEnvelope,
      parse: parseEnvelopeOrNull,
      keyPrefix: PASSKEY_ENVELOPE_KEY_PREFIX,
    });
    this.activityRecords = new CloudflareD1VersionedJsonRecordStore<WalletCredentialActivityRecordV1>({
      database: options.database,
      scope: options.scope,
      encode: (value) => value as unknown as VersionedJsonObject,
      parse: parseActivityRecordOrNull,
      keyPrefix: PASSKEY_CREDENTIAL_ACTIVITY_KEY_PREFIX,
    });
  }

  private recordKey(locator: PasskeyCustodyEnvelopeLocator): string {
    return passkeyCustodyEnvelopeRecordKey(locator);
  }

  /**
   * Reads one envelope and classifies it. The caller must have already verified
   * a WebAuthn assertion for this exact wallet, RP, credential, and challenge —
   * this store authenticates nothing on its own.
   */
  async lookupEnvelope(
    locator: PasskeyCustodyEnvelopeLocator,
  ): Promise<PasskeyCustodyEnvelopeLookupResult> {
    const read = await this.records.read(this.recordKey(locator));
    if (read.kind === 'missing') return { kind: 'missing' };

    const envelope = read.value;
    if (
      String(envelope.walletId) !== String(locator.walletId) ||
      !factorRefsMatch(envelopeFactorRef(envelope), locator.factor) ||
      String(envelope.envelopeId) !== String(locator.envelopeId)
    ) {
      // The record key already scopes the read to this wallet and credential,
      // so disagreement means a corrupt row. Report `missing` rather than the
      // row's real identity: a caller holding the wrong locator learns nothing
      // about which wallet or credential the stored envelope belongs to.
      return { kind: 'missing' };
    }

    if (envelope.lifecycle.state === 'retired') {
      return {
        kind: 'retired',
        envelopeId: envelope.envelopeId,
        retiredAtMs: envelope.lifecycle.retiredAtMs,
      };
    }
    if (envelope.lifecycle.state === 'revoked') {
      return {
        kind: 'revoked',
        envelopeId: envelope.envelopeId,
        revokedAtMs: envelope.lifecycle.revokedAtMs,
      };
    }

    const actual = await ciphertextDigestB64u(envelope.sealedCustodySecretB64u);
    if (actual !== String(envelope.ciphertextDigestB64u)) {
      return {
        kind: 'digest_mismatch',
        envelopeId: envelope.envelopeId,
        storedCiphertextDigestB64u: String(envelope.ciphertextDigestB64u),
        actualCiphertextDigestB64u: actual,
      };
    }

    return { kind: 'active', envelope, storeVersion: read.version };
  }

  /**
   * Confirms a browser cache entry against the active server envelope. A cache
   * hit requires the exact revision and ciphertext digest, so a cache that
   * drifted across a rewrap is refetched rather than opened.
   */
  async validateCachedEnvelope(args: {
    readonly locator: PasskeyCustodyEnvelopeLocator;
    readonly cachedRevision: number;
    readonly cachedCiphertextDigestB64u: string;
  }): Promise<PasskeyCustodyEnvelopeCacheValidation> {
    const lookup = await this.lookupEnvelope(args.locator);
    if (lookup.kind !== 'active') return { kind: 'cache_unusable', lookup };

    const { envelope } = lookup;
    const serverRevision = Number(envelope.envelopeRevision);
    const serverDigest = String(envelope.ciphertextDigestB64u);
    if (
      serverRevision !== args.cachedRevision ||
      serverDigest !== args.cachedCiphertextDigestB64u
    ) {
      return {
        kind: 'cache_stale',
        serverRevision,
        serverCiphertextDigestB64u: serverDigest,
      };
    }
    return { kind: 'cache_valid', envelope };
  }

  /**
   * Stores the first revision of a new envelope. Fails with `version_mismatch`
   * if any envelope already exists at this locator.
   */
  /**
   * Every envelope stored for one wallet, in key order.
   *
   * Credential management needs this and cannot be written without it: whether
   * removing a passkey is safe depends on whether *another* active envelope
   * still protects the same custody seed, and that question is unanswerable
   * from a single locator.
   *
   * The scan is bounded by the wallet's own key prefix, so it cannot reach
   * another wallet's rows even if a caller passes a crafted id — the prefix is
   * a JSON-encoded array whose first element is the wallet.
   */
  async listWalletEnvelopes(
    walletId: WalletId,
    options: { readonly limit?: number } = {},
  ): Promise<readonly PasskeyCustodyEnvelopeRecord[]> {
    /* `["<walletId>",` — the encoded key's opening element plus its comma. The
       trailing comma is what stops a wallet whose id is a prefix of another's
       from matching it. */
    const prefix = `[${JSON.stringify(String(walletId))},`;
    const entries = await this.records.listByKeyPrefix(prefix, options);
    const envelopes: PasskeyCustodyEnvelopeRecord[] = [];
    for (const entry of entries) {
      if (entry.result.kind !== 'present') continue;
      // Bound to the wallet the caller asked for, never to what the row says.
      if (String(entry.result.value.walletId) !== String(walletId)) continue;
      envelopes.push(entry.result.value);
    }
    return envelopes;
  }

  /**
   * Revokes every active or retired envelope for one passkey factor while
   * applying the caller's guarded auth-method mutation in the same D1 batch.
   * The final active-envelope guard closes the concurrent last-factor race.
   */
  async revokePasskeyFactorAtomically(input: {
    readonly walletId: WalletId;
    readonly factor: Extract<WalletCustodyFactorRef, { readonly kind: 'passkey' }>;
    readonly revokedAtMs: number;
    readonly additionalStatements: readonly D1PreparedStatementLike[];
  }): Promise<PasskeyCustodyEnvelopeRevocationResult> {
    if (input.additionalStatements.length === 0) {
      throw new Error('Passkey custody revocation requires an auth-method mutation');
    }
    const envelopes = await this.listWalletEnvelopes(input.walletId, { limit: 1000 });
    const matching = envelopes.filter(
      (envelope) =>
        envelope.factor.kind === 'passkey' &&
        factorRefsMatch(envelopeFactorRef(envelope), input.factor),
    );
    const revocable = matching.filter(
      (envelope) =>
        envelope.lifecycle.state === 'active' || envelope.lifecycle.state === 'retired',
    );
    const targetIds = new Set(revocable.map((envelope) => String(envelope.envelopeId)));
    const activeTargets = revocable.filter((envelope) => envelope.lifecycle.state === 'active');

    for (const target of activeTargets) {
      const admission = admitEnvelopeRevocation({
        envelopes,
        envelopeId: target.envelopeId,
      });
      if (admission.kind === 'refused') return admission;
    }
    if (
      activeTargets.length > 0 &&
      !envelopes.some(
        (envelope) =>
          envelope.lifecycle.state === 'active' && !targetIds.has(String(envelope.envelopeId)),
      )
    ) {
      return {
        kind: 'refused',
        reason:
          'revoking the last active envelope would leave the wallet custody seed with no factor that can open it',
      };
    }

    const additionalStatements =
      activeTargets.length > 0
        ? [
            ...input.additionalStatements,
            this.prepareRemainingActiveEnvelopeGuard(input.walletId),
          ]
        : input.additionalStatements;
    if (revocable.length === 0) {
      await this.database.batch(additionalStatements);
      return { kind: 'stored', revokedEnvelopeIds: [] };
    }

    const mutations: CloudflareD1VersionedJsonRecordMutationV1<PasskeyCustodyEnvelopeRecord>[] = [];
    for (const target of revocable) {
      const current = await this.records.read(this.recordKey(envelopeLocator(target)));
      if (current.kind === 'missing') return { kind: 'version_mismatch' };
      if (
        String(current.value.walletId) !== String(input.walletId) ||
        String(current.value.envelopeId) !== String(target.envelopeId) ||
        !factorRefsMatch(envelopeFactorRef(current.value), input.factor)
      ) {
        return { kind: 'version_mismatch' };
      }
      mutations.push({
        key: this.recordKey(envelopeLocator(target)),
        expectedVersion: current.version,
        value: {
          ...current.value,
          lifecycle: buildRevokedEnvelopeLifecycle({
            activatedAtMs: current.value.lifecycle.activatedAtMs,
            revokedAtMs: input.revokedAtMs,
          }),
          updatedAtMs: input.revokedAtMs,
        },
      });
    }
    const stored = await this.records.putManyWithAdditionalStatements(
      mutations,
      additionalStatements,
    );
    if (stored.kind === 'version_mismatch') return stored;
    return {
      kind: 'stored',
      revokedEnvelopeIds: revocable.map((envelope) => envelope.envelopeId),
    };
  }

  /** Returns the public credential-management view; activity never enters envelope AAD. */
  async listWalletCredentialActivity(
    walletId: WalletId,
  ): Promise<readonly WalletCredentialActivityProjection[]> {
    const envelopes = (await this.listWalletEnvelopes(walletId)).filter(
      (envelope) => envelope.factor.kind === 'passkey',
    );
    const projections: WalletCredentialActivityProjection[] = [];
    for (const envelope of envelopes) {
      const activity = await this.readActivity(walletId, envelope);
      projections.push({
        index: credentialEnvelopeIndex(envelope, activity),
        activity,
      });
    }
    return projections;
  }

  async renameWalletCredential(input: {
    readonly walletId: WalletId;
    readonly envelopeId: PasskeyEnvelopeId;
    readonly label?: string;
    readonly nowMs: number;
  }): Promise<WalletCredentialActivityMutationResult> {
    const envelope = await this.findPasskeyEnvelope(input.walletId, input.envelopeId);
    if (!envelope) return { kind: 'missing' };
    return await this.mutateActivity(envelope, (record) => {
      const next = {
        ...record,
        ...(input.label === undefined ? { label: undefined } : { label: input.label }),
        updatedAtMs: input.nowMs,
      };
      const parsed = parseWalletCredentialActivityRecordV1(next, {
        expectedWalletId: String(input.walletId),
      });
      return parsed.ok ? parsed.record : parsed;
    });
  }

  /** Called only after a passkey assertion has successfully opened custody. */
  async recordWalletCredentialUse(input: {
    readonly walletId: WalletId;
    readonly envelopeId: PasskeyEnvelopeId;
    readonly usedAtMs: number;
  }): Promise<WalletCredentialActivityMutationResult> {
    const envelope = await this.findPasskeyEnvelope(input.walletId, input.envelopeId);
    if (!envelope) return { kind: 'missing' };
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const result = await this.mutateActivity(envelope, (record) => {
        const lastUsedAtMs = Math.max(input.usedAtMs, record.lastUsedAtMs ?? 0);
        return {
          ...record,
          lastUsedAtMs,
          useCount: record.useCount + 1,
          updatedAtMs: Math.max(input.usedAtMs, record.updatedAtMs),
        };
      });
      if (result.kind !== 'conflict') return result;
    }
    return { kind: 'conflict' };
  }

  private async findPasskeyEnvelope(
    walletId: WalletId,
    envelopeId: PasskeyEnvelopeId,
  ): Promise<PasskeyCustodyEnvelopeRecord | null> {
    const envelopes = await this.listWalletEnvelopes(walletId);
    return (
      envelopes.find(
        (envelope) =>
          envelope.factor.kind === 'passkey' && String(envelope.envelopeId) === String(envelopeId),
      ) ?? null
    );
  }

  private async readActivity(
    walletId: WalletId,
    envelope: PasskeyCustodyEnvelopeRecord,
  ): Promise<WalletCredentialActivityRecordV1> {
    const read = await this.activityRecords.read(activityRecordKey(walletId, envelope.envelopeId));
    if (read.kind === 'present') return read.value;
    return initialActivityRecord(walletId, envelope);
  }

  private async mutateActivity(
    envelope: PasskeyCustodyEnvelopeRecord,
    mutate: (
      record: WalletCredentialActivityRecordV1,
    ) => WalletCredentialActivityRecordV1 | { readonly ok: false; readonly reason: string },
  ): Promise<WalletCredentialActivityMutationResult> {
    const walletId = envelope.walletId;
    const key = activityRecordKey(walletId, envelope.envelopeId);
    const current = await this.activityRecords.read(key);
    const base =
      current.kind === 'present' ? current.value : initialActivityRecord(walletId, envelope);
    const next = mutate(base);
    if ('ok' in next && next.ok === false) {
      return { kind: 'invalid_label', reason: next.reason };
    }
    const stored = await this.activityRecords.put(
      key,
      next,
      current.kind === 'present' ? current.version : null,
    );
    if (stored.kind === 'version_mismatch') return { kind: 'conflict' };
    return {
      kind: 'updated',
      projection: {
        index: credentialEnvelopeIndex(envelope, next),
        activity: next,
      },
    };
  }

  private prepareRemainingActiveEnvelopeGuard(walletId: WalletId): D1PreparedStatementLike {
    return this.database
      .prepare(`
        INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
        SELECT 1
         WHERE NOT EXISTS (
           SELECT 1
             FROM router_ab_yao_versioned_json_records
            WHERE namespace = ?1
              AND org_id = ?2
              AND project_id = ?3
              AND env_id = ?4
              AND record_key LIKE ?5
              AND json_extract(record_json, '$.walletId') = ?6
              AND json_extract(record_json, '$.lifecycle.state') = 'active'
         )
      `)
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        `${PASSKEY_ENVELOPE_KEY_PREFIX}:%`,
        String(walletId),
      );
  }

  async lookupEnvelopeForFactor(input: {
    readonly walletId: WalletId;
    readonly factor: WalletCustodyFactorRef;
  }): Promise<PasskeyCustodyEnvelopeFactorLookupResult> {
    const envelopes = await this.listWalletEnvelopes(input.walletId);
    const matching = envelopes.filter((envelope) =>
      factorRefsMatch(envelopeFactorRef(envelope), input.factor),
    );
    const active = matching.filter((envelope) => envelope.lifecycle.state === 'active');
    if (active.length > 1) return { kind: 'conflict' };
    const selected = active[0];
    if (selected) return await this.lookupEnvelope(envelopeLocator(selected));
    const terminal = matching[0];
    if (!terminal) return { kind: 'missing' };
    return await this.lookupEnvelope(envelopeLocator(terminal));
  }

  async createEnvelope(
    envelope: PasskeyCustodyEnvelopeRecord,
  ): Promise<PasskeyCustodyEnvelopePutResult> {
    if (Number(envelope.envelopeRevision) !== 1) {
      return { kind: 'revision_conflict', expectedRevision: 1 };
    }
    const locator = envelopeLocator(envelope);
    const stored = await this.records.put(this.recordKey(locator), envelope, null);
    if (stored.kind === 'version_mismatch') return { kind: 'version_mismatch' };
    return {
      kind: 'stored',
      storeVersion: stored.version,
      envelopeRevision: Number(envelope.envelopeRevision),
    };
  }

  /**
   * Replaces an envelope's ciphertext at exactly the next revision.
   *
   * The read-then-CAS window is closed by the store version: a concurrent
   * writer changes it, so the put fails rather than skipping a revision.
   */
  async rewrapEnvelope(
    envelope: PasskeyCustodyEnvelopeRecord,
  ): Promise<PasskeyCustodyEnvelopePutResult> {
    const locator = envelopeLocator(envelope);
    const key = this.recordKey(locator);
    const current = await this.records.read(key);
    if (current.kind === 'missing') return { kind: 'not_found' };
    if (current.value.lifecycle.state === 'revoked') {
      return { kind: 'terminal_lifecycle', state: 'revoked' };
    }

    const nextRevision = Number(current.value.envelopeRevision) + 1;
    if (Number(envelope.envelopeRevision) !== nextRevision) {
      return { kind: 'revision_conflict', expectedRevision: nextRevision };
    }

    const stored = await this.records.put(key, envelope, current.version);
    if (stored.kind === 'version_mismatch') return { kind: 'version_mismatch' };
    return { kind: 'stored', storeVersion: stored.version, envelopeRevision: nextRevision };
  }

  /**
   * Marks an active envelope superseded. Retired rows stay readable so a
   * lookup can report `retired` explicitly instead of `missing`.
   */
  async retireEnvelope(args: {
    readonly locator: PasskeyCustodyEnvelopeLocator;
    readonly retiredAtMs: number;
  }): Promise<PasskeyCustodyEnvelopePutResult> {
    return await this.transitionLifecycle(args.locator, (envelope) => {
      if (envelope.lifecycle.state !== 'active') return null;
      return {
        ...envelope,
        lifecycle: {
          state: 'retired',
          activatedAtMs: envelope.lifecycle.activatedAtMs,
          retiredAtMs: args.retiredAtMs,
        },
        updatedAtMs: args.retiredAtMs,
      };
    });
  }

  /**
   * Revokes an envelope terminally. The row is retained as a credential
   * tombstone — credential replacement needs the prior credential's record —
   * but it is excluded from every active retrieval.
   */
  async revokeEnvelope(args: {
    readonly locator: PasskeyCustodyEnvelopeLocator;
    readonly revokedAtMs: number;
  }): Promise<PasskeyCustodyEnvelopePutResult> {
    return await this.transitionLifecycle(args.locator, (envelope) => {
      if (envelope.lifecycle.state === 'revoked') return null;
      return {
        ...envelope,
        lifecycle: {
          state: 'revoked',
          activatedAtMs: envelope.lifecycle.activatedAtMs,
          revokedAtMs: args.revokedAtMs,
        },
        updatedAtMs: args.revokedAtMs,
      };
    });
  }

  /**
   * Lifecycle transitions never touch ciphertext, so `envelopeRevision` is
   * carried forward unchanged and the sealed AAD stays valid.
   */
  private async transitionLifecycle(
    locator: PasskeyCustodyEnvelopeLocator,
    next: (envelope: PasskeyCustodyEnvelopeRecord) => PasskeyCustodyEnvelopeRecord | null,
  ): Promise<PasskeyCustodyEnvelopePutResult> {
    const key = this.recordKey(locator);
    const current = await this.records.read(key);
    if (current.kind === 'missing') return { kind: 'not_found' };

    const updated = next(current.value);
    if (updated === null) {
      return current.value.lifecycle.state === 'revoked'
        ? { kind: 'terminal_lifecycle', state: 'revoked' }
        : { kind: 'version_mismatch' };
    }

    const stored = await this.records.put(key, updated, current.version);
    if (stored.kind === 'version_mismatch') return { kind: 'version_mismatch' };
    return {
      kind: 'stored',
      storeVersion: stored.version,
      envelopeRevision: Number(updated.envelopeRevision),
    };
  }
}

function envelopeLocator(envelope: PasskeyCustodyEnvelopeRecord): PasskeyCustodyEnvelopeLocator {
  return {
    walletId: envelope.walletId,
    factor: envelopeFactorRef(envelope),
    envelopeId: envelope.envelopeId,
  };
}

function activityRecordKey(walletId: WalletId, envelopeId: PasskeyEnvelopeId): string {
  return JSON.stringify([String(walletId), String(envelopeId)]);
}

function initialActivityRecord(
  walletId: WalletId,
  envelope: PasskeyCustodyEnvelopeRecord,
): WalletCredentialActivityRecordV1 {
  const createdAtMs = Math.max(1, Number(envelope.createdAtMs));
  const updatedAtMs = Math.max(createdAtMs, Number(envelope.updatedAtMs));
  return {
    kind: 'wallet_credential_activity_v1',
    walletId: String(walletId),
    envelopeId: String(envelope.envelopeId),
    createdAtMs,
    updatedAtMs,
    useCount: 0,
  };
}

function credentialEnvelopeIndex(
  envelope: PasskeyCustodyEnvelopeRecord,
  activity: WalletCredentialActivityRecordV1,
): PasskeyDeviceEnvelopeIndexRecord {
  if (envelope.factor.kind !== 'passkey') {
    throw new Error('credential envelope index requires a passkey factor');
  }
  return {
    kind: 'wallet_custody_envelope_index_v2',
    walletId: envelope.walletId,
    custodySecretKind: envelope.binding.kind,
    factor: envelope.factor,
    envelopeId: envelope.envelopeId,
    ...(activity.label === undefined ? {} : { deviceLabel: activity.label }),
    lifecycle: envelope.lifecycle,
    createdAtMs: envelope.createdAtMs,
    updatedAtMs: Math.max(envelope.updatedAtMs, activity.updatedAtMs),
  };
}
