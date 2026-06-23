import { IndexedDBManager } from '../../core/indexedDB';
import { toWalletId, type WalletId } from '../../core/signingEngine/interfaces/ecdsaChainTarget';
import type { FinalExecutionOutcome } from '@near-js/types';
import { base64Decode } from '@shared/utils/base64';
export { EmailRecoveryPendingStore, type PendingStore } from './emailRecoveryPendingStore';

export type RecoveryEmailEntry = {
  hashHex: string;
  email: string;
};

export type RecoveryEmailRecord = {
  walletId: WalletId;
  hashHex: string;
  email: string;
  addedAt: number;
};

export type LinkDeviceRegisterUserResponse = {
  verified?: boolean;
  registration_info?: unknown;
  registrationInfo?: unknown;
  error?: unknown;
};

function getTxSuccessValueBase64(outcome: FinalExecutionOutcome): string | null {
  const status = outcome.status;
  if (!status || typeof status !== 'object') return null;
  if (!('SuccessValue' in status)) return null;
  const value = status.SuccessValue;
  return typeof value === 'string' && value.length > 0 ? value : null;
}

export function parseLinkDeviceRegisterUserResponse(
  outcome: FinalExecutionOutcome,
): LinkDeviceRegisterUserResponse | null {
  try {
    const successValueB64 = getTxSuccessValueBase64(outcome);
    if (!successValueB64) return null;

    const bytes = base64Decode(successValueB64);
    const text = new TextDecoder().decode(bytes);
    if (!text.trim()) return null;

    const parsed = JSON.parse(text) as unknown;
    if (!parsed || typeof parsed !== 'object') return null;
    const candidate = parsed as LinkDeviceRegisterUserResponse;
    return typeof candidate.verified === 'boolean' ? candidate : null;
  } catch {
    return null;
  }
}

export const canonicalizeEmail = (email: string): string => {
  const raw = String(email || '').trim();
  if (!raw) return '';

  // Handle cases where a full header line is passed in (e.g. "From: ...").
  const withoutHeaderName = raw.replace(/^[a-z0-9-]+\s*:\s*/i, '').trim();

  const emailRegex = /([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)/;

  // Prefer the common "Name <email@domain>" format when present, but still
  // validate/extract the actual address via regex.
  const angleMatch = withoutHeaderName.match(/<([^>]+)>/);
  const candidates = [angleMatch?.[1], withoutHeaderName].filter(
    (v): v is string => typeof v === 'string' && v.length > 0,
  );

  for (const candidate of candidates) {
    const cleaned = candidate.replace(/^mailto:\s*/i, '');
    const match = cleaned.match(emailRegex);
    if (match?.[1]) {
      return match[1].trim().toLowerCase();
    }
  }

  return withoutHeaderName.toLowerCase();
};

export const bytesToHex = (bytes: number[] | Uint8Array): string => {
  const arr = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  return `0x${Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
};

async function hashRecoveryEmails(emails: string[], walletId: WalletId): Promise<number[][]> {
  const encoder = new TextEncoder();
  const salt = String(walletId || '').trim().toLowerCase();
  const normalized = (emails || []).map((e) => e.trim()).filter((e) => e.length > 0);

  const hashed: number[][] = [];

  for (const email of normalized) {
    try {
      const canonicalEmail = canonicalizeEmail(email);
      const input = `${canonicalEmail}|${salt}`;
      const data = encoder.encode(input);
      const digest = await crypto.subtle.digest('SHA-256', data);
      const bytes = new Uint8Array(digest);
      hashed.push(Array.from(bytes));
    } catch {
      const bytes = encoder.encode(email.toLowerCase());
      hashed.push(Array.from(bytes));
    }
  }

  return hashed;
}

/**
 * Canonicalize and hash recovery emails for an account, and persist the mapping
 * (hashHex → canonical email) in IndexedDB on a best-effort basis.
 */
export async function prepareRecoveryEmails(
  walletIdInput: WalletId | string,
  recoveryEmails: string[],
): Promise<{
  hashes: number[][];
  pairs: RecoveryEmailEntry[];
}> {
  const walletId = toWalletId(String(walletIdInput));

  const trimmedEmails = (recoveryEmails || []).map((e) => e.trim()).filter((e) => e.length > 0);
  const canonicalEmails = trimmedEmails.map(canonicalizeEmail);
  const recoveryEmailHashes = await hashRecoveryEmails(recoveryEmails, walletId);

  const pairs: RecoveryEmailEntry[] = recoveryEmailHashes.map((hashBytes, idx) => ({
    hashHex: bytesToHex(hashBytes),
    email: canonicalEmails[idx],
  }));

  void (async () => {
    try {
      await IndexedDBManager.upsertRecoveryEmails(walletId, pairs);
    } catch (error) {
      console.warn('[EmailRecovery] Failed to persist local recovery emails', error);
    }
  })();

  return { hashes: recoveryEmailHashes, pairs };
}

export async function getLocalRecoveryEmails(
  walletIdInput: WalletId | string,
): Promise<RecoveryEmailRecord[]> {
  const walletId = toWalletId(String(walletIdInput));
  const rows = await IndexedDBManager.listRecoveryEmails(walletId);
  return rows.map((row) => ({
    walletId,
    hashHex: String(row.hashHex || ''),
    email: String(row.email || ''),
    addedAt: Number(row.addedAt || 0),
  }));
}
