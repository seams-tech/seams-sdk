import type { DomainId, DomainIdParseResult } from '../utils/domainIds';
import { hasWhitespaceOrControlCharacters } from '../utils/domainIds';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import { parseDigestB64u } from '../utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';

/** The durable participant identity that owns a lane's holder share. */
export type LaneHolderParticipantId = DomainId<'LaneHolderParticipantId'>;

/** The durable SigningWorker participant that owns a lane's server share. */
export type SigningWorkerParticipantId = DomainId<'SigningWorkerParticipantId'>;

/** The recipient-key identity used to deliver material to one SigningWorker. */
export type SigningWorkerRecipientKeyId = DomainId<'SigningWorkerRecipientKeyId'>;

/** The custody identity to which a holder package is sealed. */
export type LaneHolderCustodyBindingId = DomainId<'LaneHolderCustodyBindingId'>;

/** HPKE public keys are opaque suite-specific bytes carried as canonical base64url. */
export type HpkePublicKeyB64u = string & {
  readonly __signingLaneHpkePublicKeyB64uBrand: 'SigningLaneHpkePublicKeyB64u';
};

export type LaneParticipantBindingDigestB64u = DigestB64u & {
  readonly __laneParticipantBindingDigestB64uBrand: 'LaneParticipantBindingDigestB64u';
};

export type LaneCustodyBindingDigestB64u = DigestB64u & {
  readonly __laneCustodyBindingDigestB64uBrand: 'LaneCustodyBindingDigestB64u';
};

export type HpkePublicKeyDigestB64u = DigestB64u & {
  readonly __hpkePublicKeyDigestB64uBrand: 'HpkePublicKeyDigestB64u';
};

/** Alias retained for callers that need the worker-recipient-specific name. */
export type SigningWorkerRecipientKeyDigestB64u = HpkePublicKeyDigestB64u;

export type LaneHolderCustodyIdentityV1 = {
  readonly kind: 'lane_holder_custody_identity_v1';
  readonly custodyBindingId: LaneHolderCustodyBindingId;
  readonly custodyBindingDigestB64u: LaneCustodyBindingDigestB64u;
};

export type SigningWorkerRecipientIdentityV1 = {
  readonly kind: 'signing_worker_recipient_identity_v1';
  readonly recipientKeyId: SigningWorkerRecipientKeyId;
  readonly hpkePublicKeyB64u: HpkePublicKeyB64u;
  readonly hpkePublicKeyDigestB64u: HpkePublicKeyDigestB64u;
};

/** Complete holder-side participant binding persisted beside a lane. */
export type LaneHolderParticipantRecordV1 = {
  readonly kind: 'lane_holder_participant_v1';
  readonly participantId: LaneHolderParticipantId;
  readonly custodyBindingId: LaneHolderCustodyBindingId;
  readonly custodyBindingDigestB64u: LaneCustodyBindingDigestB64u;
  readonly hpkePublicKeyB64u: HpkePublicKeyB64u;
  readonly hpkePublicKeyDigestB64u: SigningWorkerRecipientKeyDigestB64u;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
};

/** Complete SigningWorker-side participant and recipient binding. */
export type SigningWorkerParticipantRecordV1 = {
  readonly kind: 'signing_worker_participant_v1';
  readonly participantId: SigningWorkerParticipantId;
  readonly recipientKeyId: SigningWorkerRecipientKeyId;
  readonly hpkePublicKeyB64u: HpkePublicKeyB64u;
  readonly hpkePublicKeyDigestB64u: SigningWorkerRecipientKeyDigestB64u;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
};

type ParseError = { readonly code: 'missing' | 'invalid'; readonly message: string };

function missing(field: string): ParseError {
  return { code: 'missing', message: `${field} is required` };
}

function invalid(field: string, reason: string): ParseError {
  return { code: 'invalid', message: `${field} ${reason}` };
}

function parseIdentityId<T extends string>(raw: unknown, field: string): DomainIdParseResult<T> {
  if (raw === undefined || raw === null) return { ok: false, error: missing(field) };
  if (typeof raw !== 'string') return { ok: false, error: invalid(field, 'must be a string') };
  const value = raw.trim();
  if (!value) return { ok: false, error: missing(field) };
  if (hasWhitespaceOrControlCharacters(value)) {
    return { ok: false, error: invalid(field, 'must not contain whitespace or control characters') };
  }
  return { ok: true, value: value as T };
}

function parseHpkePublicKey(
  raw: unknown,
  field: string,
): DomainIdParseResult<HpkePublicKeyB64u> {
  if (raw === undefined || raw === null) return { ok: false, error: missing(field) };
  if (typeof raw !== 'string' || raw.length === 0) {
    return { ok: false, error: invalid(field, 'must be non-empty base64url') };
  }
  try {
    const bytes = base64UrlDecode(raw);
    if (bytes.length === 0 || base64UrlEncode(bytes) !== raw) {
      return { ok: false, error: invalid(field, 'must be canonical unpadded base64url') };
    }
  } catch {
    return { ok: false, error: invalid(field, 'must be canonical unpadded base64url') };
  }
  return { ok: true, value: raw as HpkePublicKeyB64u };
}

function parseDigest<T extends DigestB64u>(
  raw: unknown,
  field: string,
  brand: (value: DigestB64u) => T,
): DomainIdParseResult<T> {
  if (raw === undefined || raw === null) return { ok: false, error: missing(field) };
  try {
    return { ok: true, value: brand(parseDigestB64u(raw)) };
  } catch {
    return { ok: false, error: invalid(field, 'must be canonical base64url for 32 bytes') };
  }
}

function brandLaneCustodyDigest(value: DigestB64u): LaneCustodyBindingDigestB64u {
  return value as LaneCustodyBindingDigestB64u;
}

function brandRecipientDigest(value: DigestB64u): HpkePublicKeyDigestB64u {
  return value as HpkePublicKeyDigestB64u;
}

function brandParticipantDigest(value: DigestB64u): LaneParticipantBindingDigestB64u {
  return value as LaneParticipantBindingDigestB64u;
}

function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  return raw as Record<string, unknown>;
}

function rejectUnknownFields(
  record: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  const allowed = new Set(fields);
  for (const field of Object.keys(record)) {
    if (!allowed.has(field)) throw new Error(`${label}.${field} is not supported`);
  }
  for (const field of fields) {
    if (!(field in record)) throw new Error(`${label}.${field} is required`);
  }
}

export function parseLaneHolderParticipantId(
  raw: unknown,
): DomainIdParseResult<LaneHolderParticipantId> {
  return parseIdentityId<LaneHolderParticipantId>(raw, 'laneHolderParticipantId');
}

export function parseSigningWorkerParticipantId(
  raw: unknown,
): DomainIdParseResult<SigningWorkerParticipantId> {
  return parseIdentityId<SigningWorkerParticipantId>(raw, 'signingWorkerParticipantId');
}

export function parseSigningWorkerRecipientKeyId(
  raw: unknown,
): DomainIdParseResult<SigningWorkerRecipientKeyId> {
  return parseIdentityId<SigningWorkerRecipientKeyId>(raw, 'signingWorkerRecipientKeyId');
}

export function parseLaneHolderCustodyBindingId(
  raw: unknown,
): DomainIdParseResult<LaneHolderCustodyBindingId> {
  return parseIdentityId<LaneHolderCustodyBindingId>(raw, 'laneHolderCustodyBindingId');
}

export function parseHpkePublicKeyB64u(
  raw: unknown,
): DomainIdParseResult<HpkePublicKeyB64u> {
  return parseHpkePublicKey(raw, 'hpkePublicKeyB64u');
}

export function parseLaneParticipantBindingDigestB64u(
  raw: unknown,
): DomainIdParseResult<LaneParticipantBindingDigestB64u> {
  return parseDigest(raw, 'participantBindingDigestB64u', brandParticipantDigest);
}

export function parseLaneCustodyBindingDigestB64u(
  raw: unknown,
): DomainIdParseResult<LaneCustodyBindingDigestB64u> {
  return parseDigest(raw, 'custodyBindingDigestB64u', brandLaneCustodyDigest);
}

export function parseSigningWorkerRecipientKeyDigestB64u(
  raw: unknown,
): DomainIdParseResult<SigningWorkerRecipientKeyDigestB64u> {
  return parseDigest(raw, 'hpkePublicKeyDigestB64u', brandRecipientDigest);
}

export function buildLaneHolderCustodyIdentityV1(args: {
  readonly custodyBindingId: LaneHolderCustodyBindingId;
  readonly custodyBindingDigestB64u: LaneCustodyBindingDigestB64u;
}): LaneHolderCustodyIdentityV1 {
  return {
    kind: 'lane_holder_custody_identity_v1',
    custodyBindingId: args.custodyBindingId,
    custodyBindingDigestB64u: args.custodyBindingDigestB64u,
  };
}

export function buildSigningWorkerRecipientIdentityV1(args: {
  readonly recipientKeyId: SigningWorkerRecipientKeyId;
  readonly hpkePublicKeyB64u: HpkePublicKeyB64u;
  readonly hpkePublicKeyDigestB64u: HpkePublicKeyDigestB64u;
}): SigningWorkerRecipientIdentityV1 {
  return {
    kind: 'signing_worker_recipient_identity_v1',
    recipientKeyId: args.recipientKeyId,
    hpkePublicKeyB64u: args.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: args.hpkePublicKeyDigestB64u,
  };
}

export function parseLaneHolderCustodyIdentityV1(
  raw: unknown,
  label = 'laneHolderCustodyIdentity',
): LaneHolderCustodyIdentityV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, ['kind', 'custodyBindingId', 'custodyBindingDigestB64u'], label);
  if (record.kind !== 'lane_holder_custody_identity_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const custodyBindingId = parseLaneHolderCustodyBindingId(record.custodyBindingId);
  if (!custodyBindingId.ok) throw new Error(`${label}.${custodyBindingId.error.message}`);
  const custodyBindingDigestB64u = parseLaneCustodyBindingDigestB64u(
    record.custodyBindingDigestB64u,
  );
  if (!custodyBindingDigestB64u.ok) {
    throw new Error(`${label}.${custodyBindingDigestB64u.error.message}`);
  }
  return buildLaneHolderCustodyIdentityV1({
    custodyBindingId: custodyBindingId.value,
    custodyBindingDigestB64u: custodyBindingDigestB64u.value,
  });
}

export function parseSigningWorkerRecipientIdentityV1(
  raw: unknown,
  label = 'signingWorkerRecipientIdentity',
): SigningWorkerRecipientIdentityV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(
    record,
    ['kind', 'recipientKeyId', 'hpkePublicKeyB64u', 'hpkePublicKeyDigestB64u'],
    label,
  );
  if (record.kind !== 'signing_worker_recipient_identity_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const recipientKeyId = parseSigningWorkerRecipientKeyId(record.recipientKeyId);
  if (!recipientKeyId.ok) throw new Error(`${label}.${recipientKeyId.error.message}`);
  const hpkePublicKeyB64u = parseHpkePublicKey(record.hpkePublicKeyB64u, `${label}.hpkePublicKeyB64u`);
  if (!hpkePublicKeyB64u.ok) throw new Error(hpkePublicKeyB64u.error.message);
  const hpkePublicKeyDigestB64u = parseSigningWorkerRecipientKeyDigestB64u(
    record.hpkePublicKeyDigestB64u,
  );
  if (!hpkePublicKeyDigestB64u.ok) {
    throw new Error(`${label}.${hpkePublicKeyDigestB64u.error.message}`);
  }
  return buildSigningWorkerRecipientIdentityV1({
    recipientKeyId: recipientKeyId.value,
    hpkePublicKeyB64u: hpkePublicKeyB64u.value,
    hpkePublicKeyDigestB64u: hpkePublicKeyDigestB64u.value,
  });
}

export function buildLaneHolderParticipantRecordV1(args: {
  readonly participantId: LaneHolderParticipantId;
  readonly custody: LaneHolderCustodyIdentityV1;
  readonly hpkePublicKeyB64u: HpkePublicKeyB64u;
  readonly hpkePublicKeyDigestB64u: SigningWorkerRecipientKeyDigestB64u;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
}): LaneHolderParticipantRecordV1 {
  return {
    kind: 'lane_holder_participant_v1',
    participantId: args.participantId,
    custodyBindingId: args.custody.custodyBindingId,
    custodyBindingDigestB64u: args.custody.custodyBindingDigestB64u,
    hpkePublicKeyB64u: args.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: args.hpkePublicKeyDigestB64u,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
  };
}

export function buildSigningWorkerParticipantRecordV1(args: {
  readonly participantId: SigningWorkerParticipantId;
  readonly recipient: SigningWorkerRecipientIdentityV1;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
}): SigningWorkerParticipantRecordV1 {
  return {
    kind: 'signing_worker_participant_v1',
    participantId: args.participantId,
    recipientKeyId: args.recipient.recipientKeyId,
    hpkePublicKeyB64u: args.recipient.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: args.recipient.hpkePublicKeyDigestB64u,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
  };
}

export function parseLaneHolderParticipantRecordV1(
  raw: unknown,
  label = 'laneHolderParticipant',
): LaneHolderParticipantRecordV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(
    record,
    [
      'kind',
      'participantId',
      'custodyBindingId',
      'custodyBindingDigestB64u',
      'hpkePublicKeyB64u',
      'hpkePublicKeyDigestB64u',
      'participantBindingDigestB64u',
    ],
    label,
  );
  if (record.kind !== 'lane_holder_participant_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const participantId = parseLaneHolderParticipantId(record.participantId);
  if (!participantId.ok) throw new Error(`${label}.${participantId.error.message}`);
  const custody = parseLaneHolderCustodyIdentityV1({
    kind: 'lane_holder_custody_identity_v1',
    custodyBindingId: record.custodyBindingId,
    custodyBindingDigestB64u: record.custodyBindingDigestB64u,
  }, `${label}.custody`);
  const hpkePublicKeyB64u = parseHpkePublicKey(record.hpkePublicKeyB64u, `${label}.hpkePublicKeyB64u`);
  if (!hpkePublicKeyB64u.ok) throw new Error(hpkePublicKeyB64u.error.message);
  const hpkePublicKeyDigestB64u = parseSigningWorkerRecipientKeyDigestB64u(
    record.hpkePublicKeyDigestB64u,
  );
  if (!hpkePublicKeyDigestB64u.ok) {
    throw new Error(`${label}.${hpkePublicKeyDigestB64u.error.message}`);
  }
  const participantBindingDigestB64u = parseLaneParticipantBindingDigestB64u(
    record.participantBindingDigestB64u,
  );
  if (!participantBindingDigestB64u.ok) {
    throw new Error(`${label}.${participantBindingDigestB64u.error.message}`);
  }
  return buildLaneHolderParticipantRecordV1({
    participantId: participantId.value,
    custody,
    hpkePublicKeyB64u: hpkePublicKeyB64u.value,
    hpkePublicKeyDigestB64u: hpkePublicKeyDigestB64u.value,
    participantBindingDigestB64u: participantBindingDigestB64u.value,
  });
}

export function parseSigningWorkerParticipantRecordV1(
  raw: unknown,
  label = 'signingWorkerParticipant',
): SigningWorkerParticipantRecordV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(
    record,
    ['kind', 'participantId', 'recipientKeyId', 'hpkePublicKeyB64u', 'hpkePublicKeyDigestB64u', 'participantBindingDigestB64u'],
    label,
  );
  if (record.kind !== 'signing_worker_participant_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const participantId = parseSigningWorkerParticipantId(record.participantId);
  if (!participantId.ok) throw new Error(`${label}.${participantId.error.message}`);
  const recipient = parseSigningWorkerRecipientIdentityV1({
    kind: 'signing_worker_recipient_identity_v1',
    recipientKeyId: record.recipientKeyId,
    hpkePublicKeyB64u: record.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: record.hpkePublicKeyDigestB64u,
  }, `${label}.recipient`);
  const participantBindingDigestB64u = parseLaneParticipantBindingDigestB64u(
    record.participantBindingDigestB64u,
  );
  if (!participantBindingDigestB64u.ok) {
    throw new Error(`${label}.${participantBindingDigestB64u.error.message}`);
  }
  return buildSigningWorkerParticipantRecordV1({
    participantId: participantId.value,
    recipient,
    participantBindingDigestB64u: participantBindingDigestB64u.value,
  });
}
