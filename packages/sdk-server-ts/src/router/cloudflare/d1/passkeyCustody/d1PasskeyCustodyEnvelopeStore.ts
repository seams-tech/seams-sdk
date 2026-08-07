import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type { VersionedJsonObject } from '../../../framework/versionedJsonRecordStore';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  CloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordScopeV1,
} from '../versionedJson/d1VersionedJsonRecordStore';

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

const PASSKEY_ENVELOPE_KEY_PREFIX = 'passkey-envelope';

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
  | { readonly kind: 'passkey'; readonly credentialIdB64u: WebAuthnCredentialIdB64u }
  | { readonly kind: 'email_otp'; readonly enrollmentId: string };

export type PasskeyCustodyEnvelopeLocator = {
  readonly walletId: WalletId;
  readonly factor: WalletCustodyFactorRef;
  readonly envelopeId: PasskeyEnvelopeId;
};

/** The factor address a stored envelope actually carries. */
function envelopeFactorRef(envelope: PasskeyCustodyEnvelopeRecord): WalletCustodyFactorRef {
  return envelope.factor.kind === 'passkey'
    ? { kind: 'passkey', credentialIdB64u: envelope.factor.credentialIdB64u }
    : { kind: 'email_otp', enrollmentId: envelope.factor.enrollmentId };
}

function factorKeyPart(factor: WalletCustodyFactorRef): readonly string[] {
  return factor.kind === 'passkey'
    ? ['passkey', String(factor.credentialIdB64u)]
    : ['email_otp', factor.enrollmentId];
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

async function ciphertextDigestB64u(sealedCustodySecretB64u: string): Promise<string> {
  const ciphertext = base64UrlDecode(sealedCustodySecretB64u);
  return base64UrlEncode(await sha256Bytes(ciphertext));
}

export class CloudflareD1PasskeyCustodyEnvelopeStore {
  private readonly records: CloudflareD1VersionedJsonRecordStore<PasskeyCustodyEnvelopeRecord>;

  constructor(options: CloudflareD1PasskeyCustodyEnvelopeStoreOptions) {
    this.records = new CloudflareD1VersionedJsonRecordStore<PasskeyCustodyEnvelopeRecord>({
      database: options.database,
      scope: options.scope,
      encode: encodeEnvelope,
      parse: parseEnvelopeOrNull,
      keyPrefix: PASSKEY_ENVELOPE_KEY_PREFIX,
    });
  }

  /**
   * Envelopes are addressed by wallet, credential, and envelope id together, so
   * a lookup can never return an envelope belonging to another credential even
   * if the envelope id were guessed.
   */
  private recordKey(locator: PasskeyCustodyEnvelopeLocator): string {
    // JSON-encoded so no delimiter inside an id can splice one locator into
    // another: enrollment ids are caller strings and domain ids permit ':'.
    // A joined string would let {enrollment "e", envelope "x:y"} collide with
    // {enrollment "e:x", envelope "y"}.
    return JSON.stringify([
      String(locator.walletId),
      ...factorKeyPart(locator.factor),
      String(locator.envelopeId),
    ]);
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
