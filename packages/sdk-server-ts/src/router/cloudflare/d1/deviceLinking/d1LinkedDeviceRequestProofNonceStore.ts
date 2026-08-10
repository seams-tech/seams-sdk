import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type {
  LinkedDeviceRequestProofNonceStoreV1,
} from '../../../../core/deviceLinking/requestProof';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

const NONCE_TABLE = 'linked_device_request_proof_nonces';

type D1LinkedDeviceRequestProofNonceRowV1 = {
  readonly link_session_id?: unknown;
  readonly request_nonce_b64u?: unknown;
  readonly proof_digest_b64u?: unknown;
  readonly issued_at_ms?: unknown;
  readonly expires_at_ms?: unknown;
  readonly consumed_at_ms?: unknown;
};

type LinkedDeviceRequestProofNonceRecordV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly requestNonceB64u: string;
  readonly proofDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly consumedAtMs: number;
};

export type D1LinkedDeviceRequestProofNonceStoreOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
};

export class D1LinkedDeviceRequestProofNonceStoreV1
  implements LinkedDeviceRequestProofNonceStoreV1
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(options: D1LinkedDeviceRequestProofNonceStoreOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
  }

  async consumeRequestProofNonceV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly requestNonceB64u: string;
    readonly proofDigestB64u: DigestB64u;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly consumedAtMs: number;
  }): Promise<{ readonly outcome: 'consumed' } | { readonly outcome: 'already_used' }> {
    const normalized = parseNonceRecord({
      linkSessionId: input.linkSessionId,
      requestNonceB64u: input.requestNonceB64u,
      proofDigestB64u: input.proofDigestB64u,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
      consumedAtMs: input.consumedAtMs,
    });
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO ${NONCE_TABLE} (
             namespace, org_id, project_id, env_id,
             link_session_id, request_nonce_b64u, proof_digest_b64u,
             issued_at_ms, expires_at_ms, consumed_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          ...scopeValues(this.scope),
          String(normalized.linkSessionId),
          normalized.requestNonceB64u,
          normalized.proofDigestB64u,
          normalized.issuedAtMs,
          normalized.expiresAtMs,
          normalized.consumedAtMs,
        )
        .run();
      if (changedRows(result) === 1) return { outcome: 'consumed' };
      throw new Error('device request proof nonce insert did not persist');
    } catch (error: unknown) {
      if (!isUniqueConstraintError(error)) throw error;
      const existing = await this.readNonceV1(normalized.linkSessionId, normalized.requestNonceB64u);
      if (!existing) throw error;
      return { outcome: 'already_used' };
    }
  }

  private async readNonceV1(
    linkSessionId: LinkDeviceSessionId,
    requestNonceB64u: string,
  ): Promise<LinkedDeviceRequestProofNonceRecordV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT link_session_id, request_nonce_b64u, proof_digest_b64u,
                issued_at_ms, expires_at_ms, consumed_at_ms
           FROM ${NONCE_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND request_nonce_b64u = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(linkSessionId), requestNonceB64u)
      .first<D1LinkedDeviceRequestProofNonceRowV1>();
    if (!row) return null;
    return parseNonceRowV1(row);
  }
}

function parseNonceRecord(raw: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly requestNonceB64u: string;
  readonly proofDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly consumedAtMs: number;
}): LinkedDeviceRequestProofNonceRecordV1 {
  const linkSessionId = parseSessionId(raw.linkSessionId);
  const requestNonceB64u = parseFixedB64u(raw.requestNonceB64u, 'requestNonceB64u');
  const proofDigestB64u = parseDigest(raw.proofDigestB64u, 'proofDigestB64u');
  const issuedAtMs = requirePositiveInteger(raw.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = requirePositiveInteger(raw.expiresAtMs, 'expiresAtMs');
  const consumedAtMs = requirePositiveInteger(raw.consumedAtMs, 'consumedAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('expiresAtMs must be after issuedAtMs');
  if (consumedAtMs < issuedAtMs) throw new Error('consumedAtMs precedes issuedAtMs');
  if (consumedAtMs >= expiresAtMs) throw new Error('consumedAtMs is at or after expiresAtMs');
  return {
    linkSessionId,
    requestNonceB64u,
    proofDigestB64u,
    issuedAtMs,
    expiresAtMs,
    consumedAtMs,
  };
}

function parseNonceRowV1(row: D1LinkedDeviceRequestProofNonceRowV1): LinkedDeviceRequestProofNonceRecordV1 {
  return parseNonceRecord({
    linkSessionId: parseSessionId(requireString(row.link_session_id, 'link_session_id')),
    requestNonceB64u: requireString(row.request_nonce_b64u, 'request_nonce_b64u'),
    proofDigestB64u: parseDigest(row.proof_digest_b64u, 'proof_digest_b64u'),
    issuedAtMs: requirePositiveInteger(row.issued_at_ms, 'issued_at_ms'),
    expiresAtMs: requirePositiveInteger(row.expires_at_ms, 'expires_at_ms'),
    consumedAtMs: requirePositiveInteger(row.consumed_at_ms, 'consumed_at_ms'),
  });
}

function parseSessionId(raw: unknown): LinkDeviceSessionId {
  const result = parseLinkDeviceSessionId(raw);
  if (!result.ok) throw new Error(`linkSessionId is invalid: ${result.error.message}`);
  return result.value;
}

function parseFixedB64u(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw)) throw new Error(`${field} is invalid`);
  const bytes = base64UrlDecode(raw);
  if (bytes.length !== 32 || base64UrlEncode(bytes) !== raw) throw new Error(`${field} is invalid`);
  return raw;
}

function parseDigest(raw: unknown, field: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
}

function requireString(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) throw new Error(`${field} is invalid`);
  return raw;
}

function requirePositiveInteger(raw: unknown, field: string): number {
  const value = typeof raw === 'number' ? raw : typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} is invalid`);
  return value;
}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  for (const [field, value] of Object.entries(scope)) {
    if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
      throw new Error(`invalid linked-device proof scope ${field}`);
    }
  }
  return { ...scope };
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function changedRows(result: { readonly meta?: { readonly changes?: unknown } }): number {
  const changes = Number(result.meta?.changes ?? 0);
  return Number.isSafeInteger(changes) ? changes : 0;
}

function isUniqueConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /unique|constraint/i.test(message);
}
