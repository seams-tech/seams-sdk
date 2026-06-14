import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const WIRE_MESSAGE_VERSION_V1 = 'router-ab-protocol/wire-message/v1';
const EXPECTED_VECTOR_VERSION = 'router_ab_core_wire_vectors_v1';

type WireKindV1 =
  | 'router_to_signer_a'
  | 'router_to_signer_b'
  | 'signer_a_to_signer_b'
  | 'signer_b_to_signer_a'
  | 'recipient_proof_bundle';

type RouterAbWireVectorCaseV1 = {
  caseId: string;
  kind: WireKindV1;
  transcriptDigestHex: string;
  payloadHex: string;
  canonicalBytesHex: string;
  digestHex: string;
};

type RouterAbWireVectorFileV1 = {
  version: 'router_ab_core_wire_vectors_v1';
  cases: RouterAbWireVectorCaseV1[];
};

function assertNever(value: never): never {
  throw new Error(`Unexpected Router A/B wire kind: ${String(value)}`);
}

function readRouterAbWireVectorsV1(): RouterAbWireVectorFileV1 {
  const raw = readFileSync(
    path.join(REPO_ROOT, 'crates/router-ab-core/fixtures/protocol/wire/wire-vectors-v1.json'),
    'utf8',
  );
  return parseRouterAbWireVectorFileV1(JSON.parse(raw));
}

function parseRouterAbWireVectorFileV1(value: unknown): RouterAbWireVectorFileV1 {
  const record = readRecord(value, 'wire vector file');
  const version = readString(record, 'version');
  if (version !== EXPECTED_VECTOR_VERSION) {
    throw new Error(`wire vector file has unsupported version ${version}`);
  }
  const cases = readArray(record, 'cases').map(parseRouterAbWireVectorCaseV1);
  if (cases.length === 0) throw new Error('wire vector file must contain at least one case');
  return { version, cases };
}

function parseRouterAbWireVectorCaseV1(value: unknown): RouterAbWireVectorCaseV1 {
  const record = readRecord(value, 'wire vector case');
  const kind = parseWireKindV1(readString(record, 'kind'));
  const parsed = {
    caseId: readString(record, 'case_id'),
    kind,
    transcriptDigestHex: readHex(record, 'transcript_digest_hex', 32),
    payloadHex: readHex(record, 'payload_hex'),
    canonicalBytesHex: readHex(record, 'canonical_bytes_hex'),
    digestHex: readHex(record, 'digest_hex', 32),
  };
  return parsed;
}

function parseWireKindV1(value: string): WireKindV1 {
  switch (value) {
    case 'router_to_signer_a':
    case 'router_to_signer_b':
    case 'signer_a_to_signer_b':
    case 'signer_b_to_signer_a':
    case 'recipient_proof_bundle':
      return value;
    default:
      throw new Error(`unknown Router A/B wire kind ${value}`);
  }
}

function readRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) return value;
  throw new Error(`${field} must be an object`);
}

function readArray(record: Record<string, unknown>, field: string): unknown[] {
  const value = record[field];
  if (Array.isArray(value)) return value;
  throw new Error(`${field} must be an array`);
}

function readString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value === 'string' && value.length > 0) return value;
  throw new Error(`${field} must be a non-empty string`);
}

function readHex(record: Record<string, unknown>, field: string, byteLength?: number): string {
  const value = readString(record, field);
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error(`${field} must be lowercase hex bytes`);
  if (byteLength !== undefined && value.length !== byteLength * 2) {
    throw new Error(`${field} must be ${byteLength} bytes`);
  }
  return value;
}

function canonicalWireBytesV1(vector: RouterAbWireVectorCaseV1): Buffer {
  return Buffer.concat([
    lengthPrefixedUtf8(WIRE_MESSAGE_VERSION_V1),
    lengthPrefixedUtf8(canonicalWireKindLabel(vector.kind)),
    lengthPrefixedBytes(hexBytes(vector.transcriptDigestHex)),
    lengthPrefixedBytes(hexBytes(vector.payloadHex)),
  ]);
}

function canonicalWireKindLabel(kind: WireKindV1): string {
  switch (kind) {
    case 'router_to_signer_a':
    case 'router_to_signer_b':
    case 'signer_a_to_signer_b':
    case 'signer_b_to_signer_a':
    case 'recipient_proof_bundle':
      return kind;
    default:
      return assertNever(kind);
  }
}

function lengthPrefixedUtf8(value: string): Buffer {
  return lengthPrefixedBytes(Buffer.from(value, 'utf8'));
}

function lengthPrefixedBytes(bytes: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.byteLength, 0);
  return Buffer.concat([prefix, bytes]);
}

function hexBytes(value: string): Buffer {
  return Buffer.from(value, 'hex');
}

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

test.describe('Router A/B canonical wire vectors', () => {
  test('TypeScript parser verifies Rust wire-message canonical bytes and digests', () => {
    const vectors = readRouterAbWireVectorsV1();
    const caseIds = new Set<string>();

    for (const vector of vectors.cases) {
      expect(caseIds.has(vector.caseId), `${vector.caseId} must be unique`).toBe(false);
      caseIds.add(vector.caseId);

      const canonicalBytes = canonicalWireBytesV1(vector);
      expect(canonicalBytes.toString('hex'), vector.caseId).toBe(vector.canonicalBytesHex);
      expect(sha256Hex(canonicalBytes), vector.caseId).toBe(vector.digestHex);
    }
  });
});
