import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { IndexedDBManager } from '@/core/indexedDB';

type PasskeyCustodySessionKey = `${string}:${string}`;

const PASSKEY_CUSTODY_ENVELOPE_CACHE_KEY = 'passkeyCustodyEnvelopeCacheV1';
const PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND = 'passkey_custody_envelope_cache_v1' as const;
const MAX_CACHED_PASSKEY_CUSTODY_ENVELOPES = 32;

type PasskeyCustodyEnvelopeCacheV1 = {
  readonly kind: typeof PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND;
  readonly envelopes: readonly PasskeyCustodyEnvelopeRecord[];
};

const activePasskeyCustodyEnvelopes = new Map<
  PasskeyCustodySessionKey,
  PasskeyCustodyEnvelopeRecord
>();

function sessionKey(walletId: string, credentialIdB64u: string): PasskeyCustodySessionKey {
  const wallet = String(walletId || '').trim();
  const credential = String(credentialIdB64u || '').trim();
  if (!wallet || !credential) {
    throw new Error('passkey custody session identity is required');
  }
  return `${wallet}:${credential}`;
}

function emptyEnvelopeCache(): PasskeyCustodyEnvelopeCacheV1 {
  return { kind: PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND, envelopes: [] };
}

function parseEnvelopeCache(value: unknown): PasskeyCustodyEnvelopeCacheV1 {
  if (value === undefined || value === null) return emptyEnvelopeCache();
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('passkey custody envelope cache is invalid');
  }
  const record = value as Record<string, unknown>;
  if (record.kind !== PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND || !Array.isArray(record.envelopes)) {
    throw new Error('passkey custody envelope cache has an invalid shape');
  }
  return {
    kind: PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND,
    envelopes: record.envelopes.map((envelope) => parsePasskeyCustodyEnvelopeRecord(envelope)),
  };
}

async function readEnvelopeCache(): Promise<PasskeyCustodyEnvelopeCacheV1> {
  if (IndexedDBManager.isDisabled()) return emptyEnvelopeCache();
  return parseEnvelopeCache(
    await IndexedDBManager.getAppState<unknown>(PASSKEY_CUSTODY_ENVELOPE_CACHE_KEY),
  );
}

async function writeEnvelopeCache(cache: PasskeyCustodyEnvelopeCacheV1): Promise<void> {
  if (IndexedDBManager.isDisabled()) return;
  await IndexedDBManager.setAppState(PASSKEY_CUSTODY_ENVELOPE_CACHE_KEY, cache);
}

/**
 * Keeps the opaque envelope returned by the authenticated session exchange in
 * this page's memory. The export worker receives it only for the matching
 * wallet/credential and opens it with the fresh PRF output it collected.
 */
export async function rememberPasskeyCustodySessionEnvelope(args: {
  readonly walletId: string;
  readonly credentialIdB64u: string;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
}): Promise<void> {
  if (args.envelope.lifecycle.state !== 'active') {
    throw new Error('passkey custody session envelope is not active');
  }
  if (
    String(args.envelope.walletId) !== String(args.walletId) ||
    args.envelope.factor.kind !== 'passkey' ||
    String(args.envelope.factor.credentialIdB64u) !== String(args.credentialIdB64u)
  ) {
    throw new Error('passkey custody session envelope identity changed');
  }
  const key = sessionKey(String(args.walletId), String(args.credentialIdB64u));
  activePasskeyCustodyEnvelopes.set(key, args.envelope);
  const current = await readEnvelopeCache();
  const envelopes = current.envelopes.filter(
    (envelope) =>
      envelope.factor.kind !== 'passkey' ||
      sessionKey(String(envelope.walletId), String(envelope.factor.credentialIdB64u)) !== key,
  );
  envelopes.push(args.envelope);
  await writeEnvelopeCache({
    kind: PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND,
    envelopes: envelopes.slice(-MAX_CACHED_PASSKEY_CUSTODY_ENVELOPES),
  });
}

export async function readPasskeyCustodySessionEnvelope(args: {
  readonly walletId: string;
  readonly credentialIdB64u: string;
}): Promise<PasskeyCustodyEnvelopeRecord | null> {
  const key = sessionKey(String(args.walletId), String(args.credentialIdB64u));
  const active = activePasskeyCustodyEnvelopes.get(key);
  if (active) return active;
  const cached = (await readEnvelopeCache()).envelopes.find(
    (envelope) =>
      envelope.lifecycle.state === 'active' &&
      envelope.factor.kind === 'passkey' &&
      sessionKey(String(envelope.walletId), String(envelope.factor.credentialIdB64u)) === key,
  );
  if (!cached) return null;
  activePasskeyCustodyEnvelopes.set(key, cached);
  return cached;
}
