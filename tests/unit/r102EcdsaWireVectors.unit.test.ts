import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import {
  computeEcdsaAdditiveLaneHolderRoundDigestV1,
  computeEcdsaAdditiveLaneServerRoundDigestV1,
  computeEcdsaAdditiveLaneTranscriptDigestV1,
  computeEcdsaAdditiveLaneTranscriptPreambleDigestV1,
  encodeEcdsaAdditiveLaneHolderRoundV1,
  encodeEcdsaAdditiveLaneServerRoundV1,
  encodeEcdsaAdditiveLaneTranscriptPreambleV1,
  encodeEcdsaAdditiveLaneTranscriptV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import {
  parseEcdsaAdditiveLaneHolderRoundV1,
  parseEcdsaAdditiveLaneServerRoundV1,
  parseEcdsaAdditiveLaneTranscriptPreambleV1,
  parseEcdsaAdditiveLaneTranscriptV1,
  parseRotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURE_VERSION = 'r102_ecdsa_wire_vectors_v1';

type FixtureDoc = {
  readonly fixtureVersion: string;
  readonly job: unknown;
  readonly canonicalPreambleB64u: string;
  readonly preambleHashB64u: string;
  readonly holderRound: unknown;
  readonly canonicalHolderRoundB64u: string;
  readonly holderRoundHashB64u: string;
  readonly serverRound: unknown;
  readonly canonicalServerRoundB64u: string;
  readonly serverRoundHashB64u: string;
  readonly tamperedServerRound: unknown;
  readonly tamperedServerRoundHashB64u: string;
  readonly transcript: unknown;
  readonly canonicalTranscriptB64u: string;
  readonly transcriptHashB64u: string;
  readonly substitutionPreambleHashesB64u: Readonly<Record<string, string>>;
};

function fixture(): FixtureDoc {
  const value = JSON.parse(
    readFileSync(
      path.join(
        REPO_ROOT,
        'crates/router-ab-core/fixtures/protocol/r102/ecdsa-wire-vectors-v1.json',
      ),
      'utf8',
    ),
  ) as FixtureDoc;
  expect(value.fixtureVersion).toBe(FIXTURE_VERSION);
  return value;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a record`);
  }
  return value as Record<string, unknown>;
}

function nested(value: Record<string, unknown>, key: string): Record<string, unknown> {
  return record(value[key], key);
}

function digestByte(value: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(value));
}

function substitutedJob(raw: unknown, substitution: string): unknown {
  const value = structuredClone(record(raw, 'job'));
  const source = nested(value, 'source');
  const target = nested(value, 'target');
  const holder = nested(value, 'targetHolder');
  const worker = nested(value, 'targetSigningWorker');
  const authorization = nested(value, 'authorization');
  const targetCapability = nested(value, 'targetCapability');

  switch (substitution) {
    case 'sourceLaneShareEpoch':
      source.laneShareEpoch = 'opaque/source-epoch:B';
      break;
    case 'targetLaneShareEpoch':
      target.laneShareEpoch = 'opaque/target-epoch:Y';
      break;
    case 'holderParticipant':
      holder.participantId = 'holder:substituted';
      break;
    case 'holderParticipantBinding':
      holder.participantBindingDigestB64u = digestByte(20);
      break;
    case 'custodyBindingId':
      holder.custodyBindingId = 'custody-binding:substituted';
      break;
    case 'custodyBindingDigest':
      holder.custodyBindingDigestB64u = digestByte(21);
      break;
    case 'holderRecipientKey':
      holder.hpkePublicKeyB64u = digestByte(22);
      break;
    case 'holderRecipientKeyDigest':
      holder.hpkePublicKeyDigestB64u = digestByte(23);
      break;
    case 'workerParticipant':
      worker.participantId = 'signing-worker:substituted';
      break;
    case 'workerParticipantBinding':
      worker.participantBindingDigestB64u = digestByte(24);
      break;
    case 'workerRecipientKeyId':
      worker.recipientKeyId = 'recipient-key:substituted';
      break;
    case 'workerRecipientKey':
      worker.hpkePublicKeyB64u = digestByte(25);
      break;
    case 'workerRecipientKeyDigest':
      worker.hpkePublicKeyDigestB64u = digestByte(26);
      break;
    case 'authorizationDigest':
      authorization.linkedDevicePermissionDigestB64u = digestByte(27);
      break;
    case 'thresholdSessionOrder': {
      const sessions = targetCapability.orderedThresholdSessions;
      if (!Array.isArray(sessions)) throw new Error('orderedThresholdSessions must be an array');
      sessions.reverse();
      break;
    }
    default:
      throw new Error(`unknown substitution ${substitution}`);
  }
  return value;
}

test('Rust and TypeScript encode every ECDSA lane transcript record byte-for-byte', async () => {
  const vector = fixture();
  const job = parseRotatableSigningLaneJobV1(vector.job);
  expect(job.keyFamily).toBe('ecdsa_secp256k1');
  if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('expected ECDSA job');
  expect(String(job.source.laneShareEpoch)).toBe('opaque/source-epoch:A');
  expect(String(job.target.laneShareEpoch)).toBe(String(job.source.laneShareEpoch));

  const preamble = parseEcdsaAdditiveLaneTranscriptPreambleV1({
    kind: 'ecdsa_additive_lane_transcript_preamble_v1',
    job: vector.job,
  });
  expect(base64UrlEncode(encodeEcdsaAdditiveLaneTranscriptPreambleV1(preamble))).toBe(
    vector.canonicalPreambleB64u,
  );
  expect(await computeEcdsaAdditiveLaneTranscriptPreambleDigestV1(preamble)).toBe(
    vector.preambleHashB64u,
  );

  const holder = parseEcdsaAdditiveLaneHolderRoundV1(vector.holderRound);
  expect(base64UrlEncode(encodeEcdsaAdditiveLaneHolderRoundV1(holder))).toBe(
    vector.canonicalHolderRoundB64u,
  );
  expect(await computeEcdsaAdditiveLaneHolderRoundDigestV1(holder)).toBe(
    vector.holderRoundHashB64u,
  );

  const server = parseEcdsaAdditiveLaneServerRoundV1(vector.serverRound);
  expect(base64UrlEncode(encodeEcdsaAdditiveLaneServerRoundV1(server))).toBe(
    vector.canonicalServerRoundB64u,
  );
  expect(await computeEcdsaAdditiveLaneServerRoundDigestV1(server)).toBe(
    vector.serverRoundHashB64u,
  );

  const tamperedServer = parseEcdsaAdditiveLaneServerRoundV1(vector.tamperedServerRound);
  expect(await computeEcdsaAdditiveLaneServerRoundDigestV1(tamperedServer)).toBe(
    vector.tamperedServerRoundHashB64u,
  );
  expect(tamperedServer.holderRoundHashB64u).not.toBe(vector.holderRoundHashB64u);
  expect(vector.tamperedServerRoundHashB64u).not.toBe(vector.serverRoundHashB64u);

  const transcript = parseEcdsaAdditiveLaneTranscriptV1(vector.transcript);
  expect(base64UrlEncode(encodeEcdsaAdditiveLaneTranscriptV1(transcript))).toBe(
    vector.canonicalTranscriptB64u,
  );
  expect(await computeEcdsaAdditiveLaneTranscriptDigestV1(transcript)).toBe(
    vector.transcriptHashB64u,
  );
});

test('every frozen participant, recipient, custody, epoch, authority, and order substitution changes the preamble identically', async () => {
  const vector = fixture();
  for (const [substitution, expectedHash] of Object.entries(
    vector.substitutionPreambleHashesB64u,
  )) {
    const preamble = parseEcdsaAdditiveLaneTranscriptPreambleV1({
      kind: 'ecdsa_additive_lane_transcript_preamble_v1',
      job: substitutedJob(vector.job, substitution),
    });
    const actualHash = await computeEcdsaAdditiveLaneTranscriptPreambleDigestV1(preamble);
    expect(actualHash, substitution).toBe(expectedHash);
    expect(actualHash, substitution).not.toBe(vector.preambleHashB64u);
  }
});
