import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import {
  computeEd25519YaoLaneJobTranscriptDigestV1,
  computeEd25519YaoLaneSessionDigestV1,
  encodeEd25519YaoLaneJobTranscriptV1,
  encodeLaneProtocolCommitReceiptV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import {
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURE_VERSION = 'r102_ed25519_wire_vectors_v1';

type JobSubstitution = {
  readonly jobTranscriptDigestB64u: string;
  readonly sessionDigestB64u: string;
};

type FixtureDoc = {
  readonly fixtureVersion: string;
  readonly job: unknown;
  readonly canonicalJobTranscriptB64u: string;
  readonly jobTranscriptDigestB64u: string;
  readonly sessionDigestB64u: string;
  readonly jobSubstitutions: Readonly<Record<string, JobSubstitution>>;
  readonly tamperedBindings: JobSubstitution;
  readonly protocolCommitReceipt: unknown;
  readonly canonicalProtocolCommitReceiptB64u: string;
  readonly protocolCommitReceiptDigestB64u: string;
  readonly receiptSubstitutionDigestsB64u: Readonly<Record<string, string>>;
};

function fixture(): FixtureDoc {
  const value = JSON.parse(
    readFileSync(
      path.join(
        REPO_ROOT,
        'crates/router-ab-core/fixtures/protocol/r102/ed25519-wire-vectors-v1.json',
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
  const holder = nested(value, 'targetHolder');
  const worker = nested(value, 'targetSigningWorker');
  switch (substitution) {
    case 'targetCustodyBindingId':
      holder.custodyBindingId = 'custody-binding:substituted';
      break;
    case 'holderParticipant':
      holder.participantId = 'holder:substituted';
      break;
    case 'holderParticipantBinding':
      holder.participantBindingDigestB64u = digestByte(20);
      break;
    case 'holderRecipientKey':
      holder.hpkePublicKeyB64u = digestByte(21);
      break;
    case 'holderRecipientKeyDigest':
      holder.hpkePublicKeyDigestB64u = digestByte(22);
      break;
    case 'workerParticipant':
      worker.participantId = 'signing-worker:substituted';
      break;
    case 'workerParticipantBinding':
      worker.participantBindingDigestB64u = digestByte(23);
      break;
    case 'workerRecipientKeyId':
      worker.recipientKeyId = 'recipient-key:substituted';
      break;
    case 'workerRecipientKey':
      worker.hpkePublicKeyB64u = digestByte(24);
      break;
    case 'workerRecipientKeyDigest':
      worker.hpkePublicKeyDigestB64u = digestByte(25);
      break;
    default:
      throw new Error(`unknown job substitution ${substitution}`);
  }
  return value;
}

function substitutedReceipt(raw: unknown, substitution: string): unknown {
  const value = structuredClone(record(raw, 'receipt'));
  switch (substitution) {
    case 'sourceLaneShareEpoch':
      value.sourceLaneShareEpoch = 'opaque/source-epoch:substituted';
      break;
    case 'targetLaneShareEpoch':
      value.targetLaneShareEpoch = 'opaque/target-epoch:substituted';
      break;
    case 'holderRecipientKeyDigest':
      value.holderRecipientKeyDigestB64u = digestByte(26);
      break;
    case 'serverRecipientKeyDigest':
      value.serverRecipientKeyDigestB64u = digestByte(27);
      break;
    case 'transcriptHash':
      value.transcriptHashB64u = digestByte(28);
      break;
    default:
      throw new Error(`unknown receipt substitution ${substitution}`);
  }
  return value;
}

async function receiptDigest(raw: unknown): Promise<string> {
  const receipt = parseLaneProtocolCommitReceiptV1(raw);
  return base64UrlEncode(await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt)));
}

test('Rust and TypeScript encode the Ed25519 lane job, session, and product receipt byte-for-byte', async () => {
  const vector = fixture();
  const job = parseRotatableSigningLaneJobV1(vector.job);
  expect(job.keyFamily).toBe('ed25519');
  if (job.keyFamily !== 'ed25519') throw new Error('expected Ed25519 job');

  expect(String(job.source.laneShareEpoch)).toBe('opaque/creation-epoch:A');
  expect(String(job.target.laneShareEpoch)).toBe(String(job.source.laneShareEpoch));
  expect(String(job.target.laneId)).not.toBe(String(job.source.laneId));
  expect(base64UrlEncode(encodeEd25519YaoLaneJobTranscriptV1(job))).toBe(
    vector.canonicalJobTranscriptB64u,
  );
  expect(await computeEd25519YaoLaneJobTranscriptDigestV1(job)).toBe(
    vector.jobTranscriptDigestB64u,
  );
  expect(await computeEd25519YaoLaneSessionDigestV1(job)).toBe(vector.sessionDigestB64u);

  const receipt = parseLaneProtocolCommitReceiptV1(vector.protocolCommitReceipt);
  expect(String(receipt.sourceLaneShareEpoch)).toBe(String(receipt.targetLaneShareEpoch));
  expect(base64UrlEncode(encodeLaneProtocolCommitReceiptV1(receipt))).toBe(
    vector.canonicalProtocolCommitReceiptB64u,
  );
  expect(await receiptDigest(vector.protocolCommitReceipt)).toBe(
    vector.protocolCommitReceiptDigestB64u,
  );
});

test('frozen custody, participant, recipient, session, job-digest, and receipt substitutions cannot alias the admitted records', async () => {
  const vector = fixture();
  for (const [substitution, expected] of Object.entries(vector.jobSubstitutions)) {
    const job = parseRotatableSigningLaneJobV1(substitutedJob(vector.job, substitution));
    if (job.keyFamily !== 'ed25519') throw new Error('expected substituted Ed25519 job');
    expect(await computeEd25519YaoLaneJobTranscriptDigestV1(job), substitution).toBe(
      expected.jobTranscriptDigestB64u,
    );
    expect(await computeEd25519YaoLaneSessionDigestV1(job), substitution).toBe(
      expected.sessionDigestB64u,
    );
    expect(expected.jobTranscriptDigestB64u, substitution).not.toBe(vector.jobTranscriptDigestB64u);
    expect(expected.sessionDigestB64u, substitution).not.toBe(vector.sessionDigestB64u);
  }

  expect(vector.tamperedBindings.jobTranscriptDigestB64u).not.toBe(vector.jobTranscriptDigestB64u);
  expect(vector.tamperedBindings.sessionDigestB64u).not.toBe(vector.sessionDigestB64u);

  for (const [substitution, expectedDigest] of Object.entries(
    vector.receiptSubstitutionDigestsB64u,
  )) {
    const actualDigest = await receiptDigest(
      substitutedReceipt(vector.protocolCommitReceipt, substitution),
    );
    expect(actualDigest, substitution).toBe(expectedDigest);
    expect(actualDigest, substitution).not.toBe(vector.protocolCommitReceiptDigestB64u);
  }
});

test('lane creation requires an owner source and refresh preserves the lane kind', () => {
  const vector = fixture();
  const linkedSource = structuredClone(record(vector.job, 'job'));
  nested(linkedSource, 'source').laneKind = 'linked_device';
  expect(() => parseRotatableSigningLaneJobV1(linkedSource)).toThrow(
    'creation requires an owner-controlled source lane',
  );

  const changedKind = structuredClone(record(vector.job, 'job'));
  const source = nested(changedKind, 'source');
  changedKind.yaoRequestKind = 'lane_refresh';
  changedKind.target = {
    operation: 'refresh_lane',
    laneId: source.laneId,
    laneKind: 'owner_email_otp',
    laneShareEpoch: 'opaque/refresh-epoch:B',
    expectedTargetState: 'active_previous_epoch',
    priorMaterialActivation: source.materialActivation,
  };
  changedKind.authorization = {
    kind: 'owner_lane_refresh',
    authorizedOperationId: changedKind.operationId,
    ownerLaneRefreshDigestB64u: digestByte(29),
  };
  expect(() => parseRotatableSigningLaneJobV1(changedKind)).toThrow(
    'laneKind must match source.laneKind for refresh',
  );
});
