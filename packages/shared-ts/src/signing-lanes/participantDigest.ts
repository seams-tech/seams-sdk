import { base64UrlEncode, base64UrlDecode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { sha256Bytes } from '../utils/digests';
import {
  buildLaneHolderParticipantRecordV1,
  buildSigningWorkerParticipantRecordV1,
  parseLaneHolderParticipantRecordV1,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantRecordV1,
  type HpkePublicKeyB64u,
  type LaneHolderCustodyIdentityV1,
  type LaneHolderParticipantId,
  type LaneHolderParticipantRecordV1,
  type LaneParticipantBindingDigestB64u,
  type SigningWorkerParticipantId,
  type SigningWorkerParticipantRecordV1,
  type SigningWorkerRecipientIdentityV1,
  type SigningWorkerRecipientKeyDigestB64u,
} from './participants';

/** Domain tags are part of the wire contract and must never be shortened. */
export const LANE_HOLDER_PARTICIPANT_BINDING_DOMAIN_V1 =
  'seams/rotatable-signing-lanes/lane-holder-participant/v1' as const;
export const SIGNING_WORKER_PARTICIPANT_BINDING_DOMAIN_V1 =
  'seams/rotatable-signing-lanes/signing-worker-participant/v1' as const;

export type LaneHolderParticipantBindingInputV1 = {
  readonly participantId: LaneHolderParticipantId;
  readonly custody: LaneHolderCustodyIdentityV1;
  readonly hpkePublicKeyB64u: HpkePublicKeyB64u;
  readonly hpkePublicKeyDigestB64u: SigningWorkerRecipientKeyDigestB64u;
};

export type SigningWorkerParticipantBindingInputV1 = {
  readonly participantId: SigningWorkerParticipantId;
  readonly recipient: SigningWorkerRecipientIdentityV1;
};

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function placeholderParticipantDigest(): LaneParticipantBindingDigestB64u {
  const parsed = parseLaneParticipantBindingDigestB64u(base64UrlEncode(new Uint8Array(32)));
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('canonical u32 must be an integer between 0 and 4294967295');
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

/** LP32(UTF8(value)) from the Refactor 102 canonical encoding. */
export function encodeLaneCanonicalTextV1(value: string): Uint8Array {
  if (typeof value !== 'string') throw new Error('canonical text must be a string');
  const bytes = new TextEncoder().encode(value);
  return concat([u32(bytes.length), bytes]);
}

/** LP32(BASE64URL_DECODE_CANONICAL_32(value)) from the Refactor 102 encoding. */
export function encodeLaneCanonicalDigestV1(value: DigestB64u): Uint8Array {
  const parsed = parseDigestB64u(value);
  return concat([u32(32), base64UrlDecode(parsed)]);
}

/** U64(value), encoded as unsigned big-endian bytes. */
export function encodeLaneCanonicalU64V1(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('canonical u64 must be a non-negative safe integer');
  }
  const output = new Uint8Array(8);
  let remaining = BigInt(value);
  for (let shift = 56; shift >= 0; shift -= 8) {
    output[7 - shift / 8] = Number((remaining >> BigInt(shift)) & 0xffn);
  }
  return output;
}

/** Nonempty array count encoding used by enrollment and receipt records. */
export function encodeLaneCanonicalNonEmptyCountV1(count: number): Uint8Array {
  if (!Number.isInteger(count) || count < 1 || count > 0xffffffff) {
    throw new Error('canonical array count must be a nonempty u32');
  }
  return u32(count);
}

export function laneHolderParticipantCanonicalBytesV1(
  input: LaneHolderParticipantRecordV1,
): Uint8Array {
  const record = parseLaneHolderParticipantRecordV1(input);
  return concat([
    encodeLaneCanonicalTextV1(LANE_HOLDER_PARTICIPANT_BINDING_DOMAIN_V1),
    encodeLaneCanonicalTextV1(record.participantId),
    encodeLaneCanonicalTextV1(record.custodyBindingId),
    encodeLaneCanonicalDigestV1(record.custodyBindingDigestB64u),
    encodeLaneCanonicalTextV1(record.hpkePublicKeyB64u),
    encodeLaneCanonicalDigestV1(record.hpkePublicKeyDigestB64u),
  ]);
}

export function signingWorkerParticipantCanonicalBytesV1(
  input: SigningWorkerParticipantRecordV1,
): Uint8Array {
  const record = parseSigningWorkerParticipantRecordV1(input);
  return concat([
    encodeLaneCanonicalTextV1(SIGNING_WORKER_PARTICIPANT_BINDING_DOMAIN_V1),
    encodeLaneCanonicalTextV1(record.participantId),
    encodeLaneCanonicalTextV1(record.recipientKeyId),
    encodeLaneCanonicalTextV1(record.hpkePublicKeyB64u),
    encodeLaneCanonicalDigestV1(record.hpkePublicKeyDigestB64u),
  ]);
}

async function digestCanonicalBytes(bytes: Uint8Array): Promise<LaneParticipantBindingDigestB64u> {
  const digest = base64UrlEncode(await sha256Bytes(bytes));
  const parsed = parseLaneParticipantBindingDigestB64u(digest);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

export async function computeLaneHolderParticipantBindingDigestV1(
  input: LaneHolderParticipantBindingInputV1,
): Promise<LaneParticipantBindingDigestB64u> {
  return await digestCanonicalBytes(
    laneHolderParticipantCanonicalBytesV1(
      buildLaneHolderParticipantRecordV1({
        ...input,
        participantBindingDigestB64u: placeholderParticipantDigest(),
      }),
    ),
  );
}

export async function computeSigningWorkerParticipantBindingDigestV1(
  input: SigningWorkerParticipantBindingInputV1,
): Promise<LaneParticipantBindingDigestB64u> {
  return await digestCanonicalBytes(
    signingWorkerParticipantCanonicalBytesV1({
      kind: 'signing_worker_participant_v1',
      ...input,
      participantBindingDigestB64u: placeholderParticipantDigest(),
    }),
  );
}

export async function buildLaneHolderParticipantRecordWithDigestV1(
  input: LaneHolderParticipantBindingInputV1,
): Promise<LaneHolderParticipantRecordV1> {
  const draft = buildLaneHolderParticipantRecordV1({
    ...input,
    participantBindingDigestB64u: placeholderParticipantDigest(),
  });
  return buildLaneHolderParticipantRecordV1({
    ...input,
    participantBindingDigestB64u: await digestCanonicalBytes(
      laneHolderParticipantCanonicalBytesV1(draft),
    ),
  });
}

export async function buildSigningWorkerParticipantRecordWithDigestV1(
  input: SigningWorkerParticipantBindingInputV1,
): Promise<SigningWorkerParticipantRecordV1> {
  const draft = buildSigningWorkerParticipantRecordV1({
    ...input,
    participantBindingDigestB64u: placeholderParticipantDigest(),
  });
  return buildSigningWorkerParticipantRecordV1({
    ...input,
    participantBindingDigestB64u: await digestCanonicalBytes(
      signingWorkerParticipantCanonicalBytesV1(draft),
    ),
  });
}

export async function assertLaneHolderParticipantBindingDigestV1(
  record: LaneHolderParticipantRecordV1,
): Promise<LaneHolderParticipantRecordV1> {
  const expected = await digestCanonicalBytes(laneHolderParticipantCanonicalBytesV1(record));
  if (expected !== record.participantBindingDigestB64u) {
    throw new Error('lane holder participant binding digest mismatch');
  }
  return record;
}

export async function assertSigningWorkerParticipantBindingDigestV1(
  record: SigningWorkerParticipantRecordV1,
): Promise<SigningWorkerParticipantRecordV1> {
  const expected = await digestCanonicalBytes(signingWorkerParticipantCanonicalBytesV1(record));
  if (expected !== record.participantBindingDigestB64u) {
    throw new Error('SigningWorker participant binding digest mismatch');
  }
  return record;
}
