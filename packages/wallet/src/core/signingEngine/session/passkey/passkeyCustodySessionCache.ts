import {
  isWalletCustodySeedBinding,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodySecretBinding,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { IndexedDBManager } from '@/core/indexedDB';

type PasskeyCustodySessionKey = `${string}:${string}`;
type Ed25519YaoClientRootEnvelopeKey = string;

const PASSKEY_CUSTODY_ENVELOPE_CACHE_KEY = 'passkeyCustodyEnvelopeCacheV1';
const PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND = 'passkey_custody_envelope_cache_v1' as const;
const ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KEY =
  'ed25519YaoClientRootEnvelopeCacheV1';
const ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KIND =
  'ed25519_yao_client_root_envelope_cache_v1' as const;
const MAX_CACHED_PASSKEY_CUSTODY_ENVELOPES = 32;
const MAX_CACHED_ED25519_YAO_CLIENT_ROOT_ENVELOPES = 32;

type PasskeyCustodyEnvelopeCacheV1 = {
  readonly kind: typeof PASSKEY_CUSTODY_ENVELOPE_CACHE_KIND;
  readonly envelopes: readonly PasskeyCustodyEnvelopeRecord[];
};

export type Ed25519YaoClientRootEnvelopeRecordV1 = PasskeyCustodyEnvelopeRecord & {
  readonly binding: Extract<PasskeyCustodySecretBinding, {
    readonly kind: 'ed25519_yao_client_root_v1';
  }>;
};

type Ed25519YaoClientRootEnvelopeCacheV1 = {
  readonly kind: typeof ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KIND;
  readonly envelopes: readonly Ed25519YaoClientRootEnvelopeRecordV1[];
};

type Ed25519YaoClientRootEnvelopeIdentityBaseV1 = {
  readonly walletId: string;
  readonly linkSessionId: string;
  readonly walletKeyId: string;
  readonly enrollmentId: string;
  readonly deviceId: string;
  readonly applicationBindingDigestB64u: string;
  readonly registeredPublicKeyB64u: string;
  readonly revocationEpoch: number;
};

export type Ed25519YaoClientRootEnvelopeIdentityV1 =
  | (Ed25519YaoClientRootEnvelopeIdentityBaseV1 & {
      readonly targetFactor: {
        readonly kind: 'passkey_prf';
        readonly rpId: string;
        readonly credentialIdB64u: string;
      };
    })
  | (Ed25519YaoClientRootEnvelopeIdentityBaseV1 & {
      readonly targetFactor: {
        readonly kind: 'email_otp';
        readonly enrollmentSealKeyVersion: string;
      };
    });

export type Ed25519YaoClientRootEnvelopeEmailScopeV1 =
  Ed25519YaoClientRootEnvelopeIdentityBaseV1 & {
  readonly targetFactor: { readonly kind: 'email_otp' };
};

const activePasskeyCustodyEnvelopes = new Map<
  PasskeyCustodySessionKey,
  PasskeyCustodyEnvelopeRecord
>();
const activeEd25519YaoClientRootEnvelopes = new Map<
  Ed25519YaoClientRootEnvelopeKey,
  Ed25519YaoClientRootEnvelopeRecordV1
>();

function sessionKey(walletId: string, credentialIdB64u: string): PasskeyCustodySessionKey {
  const wallet = String(walletId || '').trim();
  const credential = String(credentialIdB64u || '').trim();
  if (!wallet || !credential) {
    throw new Error('passkey custody session identity is required');
  }
  return `${wallet}:${credential}`;
}

function rootEnvelopeKey(
  identity: Ed25519YaoClientRootEnvelopeIdentityV1,
): Ed25519YaoClientRootEnvelopeKey {
  const parts = [
    identity.walletId,
    identity.linkSessionId,
    identity.walletKeyId,
    identity.enrollmentId,
    identity.deviceId,
    identity.applicationBindingDigestB64u,
    identity.registeredPublicKeyB64u,
    identity.revocationEpoch,
    identity.targetFactor.kind,
    identity.targetFactor.kind === 'passkey_prf'
      ? String(identity.targetFactor.rpId) + ':' + String(identity.targetFactor.credentialIdB64u)
      : identity.targetFactor.enrollmentSealKeyVersion,
  ].map((part) => encodeURIComponent(String(part ?? '').trim()));
  if (parts.some((part) => !part)) {
    throw new Error('Ed25519 Yao client-root envelope identity is required');
  }
  return parts.join(':');
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
    envelopes: record.envelopes.map((envelope) => {
      const parsed = parsePasskeyCustodyEnvelopeRecord(envelope);
      if (!isWalletCustodySeedBinding(parsed.binding)) {
        throw new Error('generic passkey custody cache cannot contain an Ed25519 export root');
      }
      return parsed;
    }),
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

export function isEd25519YaoClientRootEnvelopeRecordV1(
  envelope: PasskeyCustodyEnvelopeRecord,
): envelope is Ed25519YaoClientRootEnvelopeRecordV1 {
  return envelope.binding.kind === 'ed25519_yao_client_root_v1';
}

function emptyEd25519YaoClientRootEnvelopeCache(): Ed25519YaoClientRootEnvelopeCacheV1 {
  return {
    kind: ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KIND,
    envelopes: [],
  };
}

function parseEd25519YaoClientRootEnvelopeCache(
  value: unknown,
): Ed25519YaoClientRootEnvelopeCacheV1 {
  if (value === undefined || value === null) return emptyEd25519YaoClientRootEnvelopeCache();
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Ed25519 Yao client-root envelope cache is invalid');
  }
  const record = value as Record<string, unknown>;
  if (
    record.kind !== ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KIND ||
    !Array.isArray(record.envelopes)
  ) {
    throw new Error('Ed25519 Yao client-root envelope cache has an invalid shape');
  }
  const parsedEnvelopes = record.envelopes.map((envelope) =>
    parsePasskeyCustodyEnvelopeRecord(envelope),
  );
  if (parsedEnvelopes.some((envelope) => !isEd25519YaoClientRootEnvelopeRecordV1(envelope))) {
    throw new Error('Ed25519 Yao client-root envelope cache contains a different secret kind');
  }
  const envelopes = parsedEnvelopes.filter(isEd25519YaoClientRootEnvelopeRecordV1);
  return {
    kind: ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KIND,
    envelopes,
  };
}

async function readEd25519YaoClientRootEnvelopeCache(): Promise<Ed25519YaoClientRootEnvelopeCacheV1> {
  if (IndexedDBManager.isDisabled()) return emptyEd25519YaoClientRootEnvelopeCache();
  return parseEd25519YaoClientRootEnvelopeCache(
    await IndexedDBManager.getAppState<unknown>(ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KEY),
  );
}

async function writeEd25519YaoClientRootEnvelopeCache(
  cache: Ed25519YaoClientRootEnvelopeCacheV1,
): Promise<void> {
  if (IndexedDBManager.isDisabled()) return;
  await IndexedDBManager.setAppState(ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KEY, cache);
}

function rootEnvelopeMatchesIdentity(
  envelope: Ed25519YaoClientRootEnvelopeRecordV1,
  identity: Ed25519YaoClientRootEnvelopeIdentityV1,
): boolean {
  const binding = envelope.binding;
  if (
    String(envelope.walletId) !== String(identity.walletId) ||
    String(binding.linkSessionId) !== String(identity.linkSessionId) ||
    String(binding.walletKeyId) !== String(identity.walletKeyId) ||
    String(binding.enrollmentId) !== String(identity.enrollmentId) ||
    String(binding.deviceId) !== String(identity.deviceId) ||
    String(binding.applicationBindingDigestB64u) !==
      String(identity.applicationBindingDigestB64u) ||
    String(binding.registeredPublicKeyB64u) !== String(identity.registeredPublicKeyB64u) ||
    binding.revocationEpoch !== identity.revocationEpoch ||
    binding.targetFactor.kind !== identity.targetFactor.kind
  ) {
    return false;
  }
  if (identity.targetFactor.kind === 'passkey_prf') {
    return (
      envelope.factor.kind === 'passkey' &&
      String(envelope.factor.rpId) === String(identity.targetFactor.rpId) &&
      String(envelope.factor.credentialIdB64u) ===
        String(identity.targetFactor.credentialIdB64u)
    );
  }
  return (
    envelope.factor.kind === 'email_otp' &&
    envelope.factor.enrollmentSealKeyVersion === identity.targetFactor.enrollmentSealKeyVersion
  );
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
  if (!isWalletCustodySeedBinding(args.envelope.binding)) {
    throw new Error('generic passkey custody cache accepts wallet custody seeds only');
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

/**
 * Persists the linked Device 2 Ed25519 Yao client root separately from the
 * wallet custody-seed cache. The worker receives this opaque envelope only
 * after standard export admission supplies the matching factor proof.
 */
export async function rememberEd25519YaoClientRootEnvelopeV1(args: {
  readonly identity: Ed25519YaoClientRootEnvelopeIdentityV1;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
}): Promise<void> {
  const identity = args.identity;
  const envelope = args.envelope;
  if (
    envelope.lifecycle.state !== 'active' ||
    !isEd25519YaoClientRootEnvelopeRecordV1(envelope)
  ) {
    throw new Error('Ed25519 Yao client-root envelope is not active or has the wrong secret kind');
  }
  if (!rootEnvelopeMatchesIdentity(envelope, identity)) {
    throw new Error('Ed25519 Yao client-root envelope identity changed');
  }
  const key = rootEnvelopeKey(identity);
  activeEd25519YaoClientRootEnvelopes.set(key, envelope);
  const current = await readEd25519YaoClientRootEnvelopeCache();
  const envelopes = current.envelopes.filter(
    (candidate) => !rootEnvelopeMatchesIdentity(candidate, identity),
  );
  envelopes.push(envelope);
  await writeEd25519YaoClientRootEnvelopeCache({
    kind: ED25519_YAO_CLIENT_ROOT_ENVELOPE_CACHE_KIND,
    envelopes: envelopes.slice(-MAX_CACHED_ED25519_YAO_CLIENT_ROOT_ENVELOPES),
  });
}

export async function readEd25519YaoClientRootEnvelopeV1(
  identity: Ed25519YaoClientRootEnvelopeIdentityV1,
): Promise<Ed25519YaoClientRootEnvelopeRecordV1 | null> {
  const key = rootEnvelopeKey(identity);
  const active = activeEd25519YaoClientRootEnvelopes.get(key);
  if (active && active.lifecycle.state === 'active') return active;
  const cached = (await readEd25519YaoClientRootEnvelopeCache()).envelopes.find(
    (envelope) =>
      envelope.lifecycle.state === 'active' && rootEnvelopeMatchesIdentity(envelope, identity),
  );
  if (!cached) return null;
  activeEd25519YaoClientRootEnvelopes.set(key, cached);
  return cached;
}

function rootEnvelopeMatchesEmailScope(
  envelope: Ed25519YaoClientRootEnvelopeRecordV1,
  scope: Ed25519YaoClientRootEnvelopeEmailScopeV1,
): boolean {
  const binding = envelope.binding;
  return (
    envelope.walletId === scope.walletId &&
    binding.linkSessionId === scope.linkSessionId &&
    binding.walletKeyId === scope.walletKeyId &&
    binding.enrollmentId === scope.enrollmentId &&
    binding.deviceId === scope.deviceId &&
    binding.applicationBindingDigestB64u === scope.applicationBindingDigestB64u &&
    binding.registeredPublicKeyB64u === scope.registeredPublicKeyB64u &&
    binding.revocationEpoch === scope.revocationEpoch &&
    binding.targetFactor.kind === 'email_otp' &&
    envelope.factor.kind === 'email_otp'
  );
}

export async function readEd25519YaoClientRootEnvelopeForEmailScopeV1(
  scope: Ed25519YaoClientRootEnvelopeEmailScopeV1,
): Promise<Ed25519YaoClientRootEnvelopeRecordV1 | null> {
  const candidates = (await readEd25519YaoClientRootEnvelopeCache()).envelopes.filter(
    (envelope) =>
      envelope.lifecycle.state === 'active' && rootEnvelopeMatchesEmailScope(envelope, scope),
  );
  if (candidates.length > 1) {
    throw new Error('multiple active Ed25519 Yao client-root envelopes match the Email OTP scope');
  }
  const envelope = candidates[0] ?? null;
  if (envelope) {
    const key = rootEnvelopeKey({
      ...scope,
      targetFactor: {
        kind: 'email_otp',
        enrollmentSealKeyVersion: envelope.factor.kind === 'email_otp'
          ? envelope.factor.enrollmentSealKeyVersion
          : '',
      },
    });
    activeEd25519YaoClientRootEnvelopes.set(key, envelope);
  }
  return envelope;
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
  if (cached) {
    activePasskeyCustodyEnvelopes.set(key, cached);
    return cached;
  }
  return null;
}
