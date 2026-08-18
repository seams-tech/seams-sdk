import { errorMessage } from '@shared/utils/errors';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { NormalizedLogger } from '../logger';
import type {
  NearPublicKeyAuthBinding,
  NearPublicKeyKind,
  NearPublicKeyRecord,
  NearPublicKeyStore,
} from '../NearPublicKeyStore';

export type RecordNearPublicKeyMetadataResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

export type NearPublicKeyListEntry = {
  publicKey: string;
  kind: NearPublicKeyKind;
  signerSlot?: number;
  createdAtMs: number;
  updatedAtMs: number;
  authBinding?: NearPublicKeyAuthBinding;
};

export type ListNearPublicKeysResult =
  | { ok: true; keys: NearPublicKeyListEntry[] }
  | { ok: false; code: string; message: string };

function optionalPositiveInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(value) && value >= 1 ? Math.floor(value) : null;
}

function optionalPositiveTimestamp(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : null;
}

function nearPublicKeyAuthBinding(input: {
  credentialIdB64u: string;
  rpIdRaw: string;
}): { ok: true; binding?: NearPublicKeyAuthBinding } | { ok: false; message: string } {
  if (!input.credentialIdB64u && !input.rpIdRaw) return { ok: true };
  if (!input.credentialIdB64u || !input.rpIdRaw) {
    return {
      ok: false,
      message: 'passkey near public key binding requires rpId and credentialIdB64u',
    };
  }
  const rpId = parseWebAuthnRpId(input.rpIdRaw);
  if (!rpId.ok) return { ok: false, message: rpId.error.message };
  return {
    ok: true,
    binding: {
      kind: 'passkey',
      rpId: rpId.value,
      credentialIdB64u: input.credentialIdB64u,
    },
  };
}

function nearPublicKeyRecord(input: {
  userId: string;
  publicKey: string;
  kind: NearPublicKeyKind;
  signerSlot: number | null;
  authBinding: NearPublicKeyAuthBinding | undefined;
  addedTxHash: string;
  removedAtMs: number | null;
  nowMs: number;
}): NearPublicKeyRecord {
  const record: NearPublicKeyRecord = {
    version: 'near_public_key_v1',
    userId: input.userId,
    publicKey: input.publicKey,
    kind: input.kind,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };
  if (input.signerSlot !== null) record.signerSlot = input.signerSlot;
  if (input.authBinding) record.authBinding = input.authBinding;
  if (input.addedTxHash) record.addedTxHash = input.addedTxHash;
  if (input.removedAtMs !== null) record.removedAtMs = input.removedAtMs;
  return record;
}

function nearPublicKeyListEntry(record: NearPublicKeyRecord): NearPublicKeyListEntry {
  const entry: NearPublicKeyListEntry = {
    publicKey: record.publicKey,
    kind: record.kind,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
  };
  if (typeof record.signerSlot === 'number') entry.signerSlot = record.signerSlot;
  if (record.authBinding) entry.authBinding = record.authBinding;
  return entry;
}

export async function recordNearPublicKeyMetadataWithStore(input: {
  store: NearPublicKeyStore;
  logger: NormalizedLogger;
  userId?: unknown;
  publicKey?: unknown;
  kind: NearPublicKeyKind;
  signerSlot?: unknown;
  credentialIdB64u?: unknown;
  rpId?: unknown;
  addedTxHash?: unknown;
  removedAtMs?: unknown;
  source?: string;
}): Promise<RecordNearPublicKeyMetadataResult> {
  const userId = toOptionalTrimmedString(input.userId);
  const publicKey = toOptionalTrimmedString(input.publicKey);
  if (!userId || !publicKey) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'userId and publicKey are required',
    };
  }

  const authBinding = nearPublicKeyAuthBinding({
    credentialIdB64u: toOptionalTrimmedString(input.credentialIdB64u),
    rpIdRaw: toOptionalTrimmedString(input.rpId),
  });
  if (!authBinding.ok) {
    return { ok: false, code: 'invalid_args', message: authBinding.message };
  }

  const record = nearPublicKeyRecord({
    userId,
    publicKey,
    kind: input.kind,
    signerSlot: optionalPositiveInteger(input.signerSlot),
    authBinding: authBinding.binding,
    addedTxHash: toOptionalTrimmedString(input.addedTxHash),
    removedAtMs: optionalPositiveTimestamp(input.removedAtMs),
    nowMs: Date.now(),
  });

  try {
    await input.store.put(record);
    return { ok: true };
  } catch (error: unknown) {
    const source = toOptionalTrimmedString(input.source) || 'near-public-key-metadata';
    const message = errorMessage(error) || 'Failed to persist NEAR public key metadata';
    input.logger.warn(`[AuthService] ${source} failed for ${userId}`, error);
    return { ok: false, code: 'internal', message };
  }
}

export async function listNearPublicKeysForUserWithStore(input: {
  store: NearPublicKeyStore;
  userId: string;
}): Promise<ListNearPublicKeysResult> {
  try {
    const userId = String(input.userId || '').trim();
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };

    const records = await input.store.listByUserId(userId);
    const keys: NearPublicKeyListEntry[] = [];
    for (const record of records || []) {
      keys.push(nearPublicKeyListEntry(record));
    }
    return { ok: true, keys };
  } catch (e: unknown) {
    return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to list keys' };
  }
}
