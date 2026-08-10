import type { DomainIdParseResult, MpcSigningWorkerRef } from '../utils/domainIds';
import { hasWhitespaceOrControlCharacters, parseMpcSigningWorkerRef } from '../utils/domainIds';
import {
  parseDigestField,
  rejectUnknownFields,
  requireRecord,
} from '../passkey-custody/primitives';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import { base64UrlEncode } from '../utils/base64';
import { sha256Bytes } from '../utils/digests';
import {
  encodeLaneCanonicalDigestV1,
  encodeLaneCanonicalTextV1,
  encodeLaneCanonicalU64V1,
} from './participantDigest';
import {
  parseLaneParticipantBindingDigestB64u,
  type LaneParticipantBindingDigestB64u,
} from './participants';

/** The durable signer identity used by canonical wallet-signer records. */
export type WalletSignerId = string & {
  readonly __ownerLaneWalletSignerIdBrand: 'WalletSignerId';
};

/** Owner lanes bind to signer facts that predate independently provisioned R102 lanes. */
export type OwnerLaneParticipantContinuityV1 = {
  readonly kind: 'owner_lane_participant_continuity_v1';
  readonly signerId: WalletSignerId;
  readonly participantIds: readonly [number, number];
  readonly signingWorkerId: MpcSigningWorkerRef;
  readonly custodyKeyManifestDigestB64u: DigestB64u;
  readonly sourceIdentityDigestB64u: DigestB64u;
};

export const OWNER_LANE_PARTICIPANT_BINDING_DOMAIN_V1 =
  'seams/rotatable-signing-lanes/owner-lane-participant-continuity/v1' as const;

const OWNER_LANE_PARTICIPANT_CONTINUITY_FIELDS = [
  'kind',
  'signerId',
  'participantIds',
  'signingWorkerId',
  'custodyKeyManifestDigestB64u',
  'sourceIdentityDigestB64u',
] as const;

function requireResult<T>(result: DomainIdParseResult<T>, label: string): T {
  if (result.ok) return result.value;
  throw new Error(`${label} ${result.error.message}`);
}

/** Parse the owner signer identity without widening it into a generic string. */
export function parseWalletSignerId(raw: unknown, label = 'walletSignerId'): WalletSignerId {
  if (typeof raw !== 'string') throw new Error(`${label} must be a string`);
  const value = raw.trim();
  if (!value) throw new Error(`${label} is required`);
  if (hasWhitespaceOrControlCharacters(value)) {
    throw new Error(`${label} must not contain whitespace or control characters`);
  }
  return value as WalletSignerId;
}

function parseParticipantId(raw: unknown, label: string): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return raw;
}

function parseParticipantIds(raw: unknown, label: string): readonly [number, number] {
  if (!Array.isArray(raw) || raw.length !== 2) {
    throw new Error(`${label} must contain exactly two participant ids`);
  }
  const first = parseParticipantId(raw[0], `${label}[0]`);
  const second = parseParticipantId(raw[1], `${label}[1]`);
  if (first === second) throw new Error(`${label} must contain distinct participant ids`);
  return [first, second];
}

export function buildOwnerLaneParticipantContinuityV1(args: {
  readonly signerId: WalletSignerId;
  readonly participantIds: readonly [number, number];
  readonly signingWorkerId: MpcSigningWorkerRef;
  readonly custodyKeyManifestDigestB64u: DigestB64u;
  readonly sourceIdentityDigestB64u: DigestB64u;
}): OwnerLaneParticipantContinuityV1 {
  const participantIds = parseParticipantIds(args.participantIds, 'participantIds');
  return {
    kind: 'owner_lane_participant_continuity_v1',
    signerId: parseWalletSignerId(args.signerId),
    participantIds,
    signingWorkerId: requireResult(
      parseMpcSigningWorkerRef(args.signingWorkerId),
      'signingWorkerId',
    ),
    custodyKeyManifestDigestB64u: parseDigestField(
      args.custodyKeyManifestDigestB64u,
      'custodyKeyManifestDigestB64u',
    ),
    sourceIdentityDigestB64u: parseDigestField(
      args.sourceIdentityDigestB64u,
      'sourceIdentityDigestB64u',
    ),
  };
}

export function parseOwnerLaneParticipantContinuityV1(
  raw: unknown,
  label = 'ownerParticipantContinuity',
): OwnerLaneParticipantContinuityV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, OWNER_LANE_PARTICIPANT_CONTINUITY_FIELDS, label);
  if (record.kind !== 'owner_lane_participant_continuity_v1') {
    throw new Error(`${label}.kind must be owner_lane_participant_continuity_v1`);
  }
  return buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId(record.signerId, `${label}.signerId`),
    participantIds: parseParticipantIds(record.participantIds, `${label}.participantIds`),
    signingWorkerId: requireResult(
      parseMpcSigningWorkerRef(record.signingWorkerId),
      `${label}.signingWorkerId`,
    ),
    custodyKeyManifestDigestB64u: parseDigestField(
      record.custodyKeyManifestDigestB64u,
      `${label}.custodyKeyManifestDigestB64u`,
    ),
    sourceIdentityDigestB64u: parseDigestField(
      record.sourceIdentityDigestB64u,
      `${label}.sourceIdentityDigestB64u`,
    ),
  });
}

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

export function ownerLaneParticipantContinuityCanonicalBytesV1(
  input: OwnerLaneParticipantContinuityV1,
): Uint8Array {
  const record = parseOwnerLaneParticipantContinuityV1(input);
  return concat([
    encodeLaneCanonicalTextV1(OWNER_LANE_PARTICIPANT_BINDING_DOMAIN_V1),
    encodeLaneCanonicalTextV1(record.signerId),
    encodeLaneCanonicalU64V1(record.participantIds[0]),
    encodeLaneCanonicalU64V1(record.participantIds[1]),
    encodeLaneCanonicalTextV1(record.signingWorkerId),
    encodeLaneCanonicalDigestV1(record.custodyKeyManifestDigestB64u),
    encodeLaneCanonicalDigestV1(record.sourceIdentityDigestB64u),
  ]);
}

export async function computeOwnerLaneParticipantBindingDigestV1(
  input: OwnerLaneParticipantContinuityV1,
): Promise<LaneParticipantBindingDigestB64u> {
  const digest = base64UrlEncode(
    await sha256Bytes(ownerLaneParticipantContinuityCanonicalBytesV1(input)),
  );
  return requireResult(parseLaneParticipantBindingDigestB64u(digest), 'owner participant digest');
}
