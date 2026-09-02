import {
  parseLinkedDeviceSessionRecordV1,
  type LinkedDeviceSessionRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletAuthorityId, type WalletAuthorityId } from '@shared/utils/domainIds';

export type D1LinkedDeviceSessionRowV1 = {
  readonly link_session_id?: unknown;
  readonly link_public_key_b64u?: unknown;
  readonly device_public_key_b64u?: unknown;
  readonly state?: unknown;
  readonly record_json?: unknown;
  readonly revision?: unknown;
  readonly expires_at_ms?: unknown;
  readonly claim_expires_at_ms?: unknown;
  readonly claim_digest_b64u?: unknown;
  readonly approval_digest_b64u?: unknown;
  readonly authority_id?: unknown;
  readonly package_set_digest_b64u?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

export type D1LinkedDeviceSessionTranscriptRowV1 = {
  readonly transcript_kind?: unknown;
  readonly digest_b64u?: unknown;
  readonly transcript_json?: unknown;
  readonly created_at_ms?: unknown;
};

export type ParsedD1LinkedDeviceSessionRowV1 = {
  readonly record: LinkedDeviceSessionRecordV1;
  readonly claimDigestB64u: DigestB64u | null;
  readonly approvalDigestB64u: DigestB64u | null;
};

export function parseD1LinkedDeviceSessionRowV1(
  row: D1LinkedDeviceSessionRowV1,
): ParsedD1LinkedDeviceSessionRowV1 {
  const record = parseLinkedDeviceSessionRecordV1(parseJson(row.record_json, 'record_json'));
  const linkSessionId = requiredString(row.link_session_id, 'link_session_id');
  const linkPublicKeyB64u = requiredString(row.link_public_key_b64u, 'link_public_key_b64u');
  const devicePublicKeyB64u = requiredString(row.device_public_key_b64u, 'device_public_key_b64u');
  const state = requiredString(row.state, 'state');
  const revision = requiredPositiveInteger(row.revision, 'revision');
  const expiresAtMs = requiredPositiveInteger(row.expires_at_ms, 'expires_at_ms');
  const claimExpiresAtMs = optionalPositiveInteger(row.claim_expires_at_ms, 'claim_expires_at_ms');
  const claimDigestB64u = optionalDigest(row.claim_digest_b64u, 'claim_digest_b64u');
  const approvalDigestB64u = optionalDigest(row.approval_digest_b64u, 'approval_digest_b64u');
  const authorityId = optionalAuthorityId(row.authority_id);
  const packageSetDigestB64u = optionalDigest(
    row.package_set_digest_b64u,
    'package_set_digest_b64u',
  );
  const createdAtMs = requiredPositiveInteger(row.created_at_ms, 'created_at_ms');
  const updatedAtMs = requiredPositiveInteger(row.updated_at_ms, 'updated_at_ms');
  if (
    String(record.linkSessionId) !== linkSessionId ||
    record.qrPayload.linkPublicKeyB64u !== linkPublicKeyB64u ||
    record.qrPayload.devicePublicKeyB64u !== devicePublicKeyB64u ||
    record.state.state !== state ||
    record.revision !== revision ||
    record.qrPayload.expiresAtMs !== expiresAtMs ||
    record.createdAtMs !== createdAtMs ||
    record.updatedAtMs !== updatedAtMs
  ) {
    throw new Error('linked-device session columns do not match record_json');
  }
  const expectedClaimExpiry = record.claimTranscript?.value.claimExpiresAtMs ?? null;
  if ((claimExpiresAtMs ?? null) !== expectedClaimExpiry) {
    throw new Error('claim expiry column does not match record_json');
  }
  const expectedClaimDigest = record.claimTranscript?.digestB64u ?? null;
  const expectedApprovalDigest = record.approvalTranscript?.digestB64u ?? null;
  if (claimDigestB64u !== expectedClaimDigest || approvalDigestB64u !== expectedApprovalDigest) {
    throw new Error('transcript digest columns do not match record_json');
  }
  if (
    (record.authorityId ? String(record.authorityId) : null) !==
    (authorityId ? String(authorityId) : null)
  ) {
    throw new Error('authority id column does not match record_json');
  }
  if ((record.packageSetDigestB64u ?? null) !== packageSetDigestB64u) {
    throw new Error('package set digest column does not match record_json');
  }
  return { record, claimDigestB64u, approvalDigestB64u };
}

export function parseD1LinkedDeviceSessionTranscriptRowV1(
  row: D1LinkedDeviceSessionTranscriptRowV1,
): {
  readonly kind: 'claim' | 'approval' | 'source_contribution';
  readonly digestB64u: DigestB64u;
  readonly transcriptJson: unknown;
  readonly createdAtMs: number;
} {
  const kind = requiredString(row.transcript_kind, 'transcript_kind');
  if (kind !== 'claim' && kind !== 'approval' && kind !== 'source_contribution') {
    throw new Error('transcript_kind is invalid');
  }
  return {
    kind,
    digestB64u: requiredDigest(row.digest_b64u, 'digest_b64u'),
    transcriptJson: parseJson(row.transcript_json, 'transcript_json'),
    createdAtMs: requiredPositiveInteger(row.created_at_ms, 'created_at_ms'),
  };
}

function parseJson(raw: unknown, field: string): unknown {
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw) as unknown;
    } catch {
      throw new Error(`${field} is invalid JSON`);
    }
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${field} must be an object`);
  }
  return raw;
}

function requiredString(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) {
    throw new Error(`${field} is invalid`);
  }
  return raw;
}

function optionalAuthorityId(raw: unknown): WalletAuthorityId | null {
  if (raw === null || raw === undefined) return null;
  const parsed = parseWalletAuthorityId(raw);
  if (!parsed.ok) throw new Error('authority_id is invalid');
  return parsed.value;
}

function requiredNonNegativeInteger(raw: unknown, field: string): number {
  const value =
    typeof raw === 'number'
      ? raw
      : typeof raw === 'string' && /^\d+$/.test(raw)
        ? Number(raw)
        : Number.NaN;
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} is invalid`);
  return value;
}

function requiredPositiveInteger(raw: unknown, field: string): number {
  const value = requiredNonNegativeInteger(raw, field);
  if (value < 1) throw new Error(`${field} must be positive`);
  return value;
}

function optionalPositiveInteger(raw: unknown, field: string): number | null {
  if (raw === null || raw === undefined) return null;
  return requiredPositiveInteger(raw, field);
}

function optionalDigest(raw: unknown, field: string): DigestB64u | null {
  if (raw === null || raw === undefined) return null;
  return requiredDigest(raw, field);
}

function requiredDigest(raw: unknown, field: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
}
