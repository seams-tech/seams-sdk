import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildRouterAbEd25519DelegateActionPrepareRequestV2,
  buildRouterAbEd25519NearTransactionPrepareRequestV2,
  buildRouterAbEd25519Nep413PrepareRequestV2,
  type RouterAbNearNetworkIdV2Wire,
  type RouterAbNormalSigningPrepareRequestV2BuildResult,
  type RouterAbNormalSigningScopeV1Wire,
  type RouterAbPublicDigest32Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import { base64UrlEncode } from '@shared/utils/base64';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EXPECTED_VERSION = 'router_ab_core_normal_signing_vectors_v2';

type NormalSigningVectorCaseV2 = {
  caseId: 'near_transaction_v1' | 'nep413_v1' | 'near_delegate_action_v1';
  builderArgs: Record<string, unknown>;
  prepareRequestJson: unknown;
  intentDigestB64u: string;
  signingPayloadDigestB64u: string;
  admittedSigningDigestB64u: string;
};

function readNormalSigningVectors(): readonly NormalSigningVectorCaseV2[] {
  const raw = readFileSync(
    path.join(
      REPO_ROOT,
      'crates/router-ab-core/fixtures/protocol/normal-signing/normal-signing-vectors-v2.json',
    ),
    'utf8',
  );
  const fixture = readRecord(JSON.parse(raw), 'normal-signing vector fixture');
  const version = readString(fixture, 'version');
  if (version !== EXPECTED_VERSION) {
    throw new Error(`normal-signing vector version ${version} is unsupported`);
  }
  return readArray(fixture, 'cases').map(parseVectorCase);
}

function parseVectorCase(value: unknown): NormalSigningVectorCaseV2 {
  const record = readRecord(value, 'normal-signing vector case');
  return {
    caseId: readCaseId(record),
    builderArgs: readRecord(record.builder_args_json, 'builder_args_json'),
    prepareRequestJson: record.prepare_request_json,
    intentDigestB64u: readString(record, 'intent_digest_b64u'),
    signingPayloadDigestB64u: readString(record, 'signing_payload_digest_b64u'),
    admittedSigningDigestB64u: readString(record, 'admitted_signing_digest_b64u'),
  };
}

async function buildFromVector(
  vector: NormalSigningVectorCaseV2,
): Promise<RouterAbNormalSigningPrepareRequestV2BuildResult> {
  switch (vector.caseId) {
    case 'near_transaction_v1':
      return buildRouterAbEd25519NearTransactionPrepareRequestV2({
        scope: readScope(vector.builderArgs.scope),
        expiresAtMs: readNumber(vector.builderArgs, 'expiresAtMs'),
        operationId: readString(vector.builderArgs, 'operationId'),
        operationFingerprint: readString(vector.builderArgs, 'operationFingerprint'),
        nearAccountId: readString(vector.builderArgs, 'nearAccountId'),
        nearNetworkId: readNetworkId(vector.builderArgs, 'nearNetworkId'),
        transactions: readArray(vector.builderArgs, 'transactions').map((entry, index) => {
          const transaction = readRecord(entry, `transactions[${index}]`);
          return {
            receiverId: readString(transaction, 'receiverId'),
            actionFingerprint: readString(transaction, 'actionFingerprint'),
          };
        }),
        unsignedTransactionBorshB64u: readString(
          vector.builderArgs,
          'unsignedTransactionBorshB64u',
        ),
        expectedSigningDigestB64u: readString(vector.builderArgs, 'expectedSigningDigestB64u'),
      });
    case 'nep413_v1':
      return buildRouterAbEd25519Nep413PrepareRequestV2({
        scope: readScope(vector.builderArgs.scope),
        expiresAtMs: readNumber(vector.builderArgs, 'expiresAtMs'),
        operationId: readString(vector.builderArgs, 'operationId'),
        operationFingerprint: readString(vector.builderArgs, 'operationFingerprint'),
        nearAccountId: readString(vector.builderArgs, 'nearAccountId'),
        nearNetworkId: readNetworkId(vector.builderArgs, 'nearNetworkId'),
        message: readString(vector.builderArgs, 'message'),
        recipient: readString(vector.builderArgs, 'recipient'),
        nonce: readString(vector.builderArgs, 'nonce'),
        callbackUrl: readString(vector.builderArgs, 'callbackUrl'),
        expectedSigningDigestB64u: readString(vector.builderArgs, 'expectedSigningDigestB64u'),
      });
    case 'near_delegate_action_v1': {
      const delegate = readRecord(vector.builderArgs.delegate, 'delegate');
      return buildRouterAbEd25519DelegateActionPrepareRequestV2({
        scope: readScope(vector.builderArgs.scope),
        expiresAtMs: readNumber(vector.builderArgs, 'expiresAtMs'),
        operationId: readString(vector.builderArgs, 'operationId'),
        operationFingerprint: readString(vector.builderArgs, 'operationFingerprint'),
        nearAccountId: readString(vector.builderArgs, 'nearAccountId'),
        nearNetworkId: readNetworkId(vector.builderArgs, 'nearNetworkId'),
        delegate: {
          senderId: readString(delegate, 'senderId'),
          receiverId: readString(delegate, 'receiverId'),
          publicKey: readString(delegate, 'publicKey'),
          nonce: readString(delegate, 'nonce'),
          maxBlockHeight: readString(delegate, 'maxBlockHeight'),
          actionFingerprint: readString(delegate, 'actionFingerprint'),
          canonicalDelegateBorshB64u: readString(delegate, 'canonicalDelegateBorshB64u'),
        },
        expectedSigningDigestB64u: readString(vector.builderArgs, 'expectedSigningDigestB64u'),
      });
    }
  }
}

function digestB64u(value: RouterAbPublicDigest32Wire): string {
  return base64UrlEncode(Uint8Array.from(value.bytes));
}

function readScope(value: unknown): RouterAbNormalSigningScopeV1Wire {
  const record = readRecord(value, 'scope');
  return {
    request_id: readString(record, 'request_id'),
    account_id: readString(record, 'account_id'),
    session_id: readString(record, 'session_id'),
    signing_worker_id: readString(record, 'signing_worker_id'),
  };
}

function readNetworkId(
  record: Record<string, unknown>,
  field: string,
): RouterAbNearNetworkIdV2Wire {
  const value = readString(record, field);
  if (value === 'testnet' || value === 'mainnet') return value;
  throw new Error(`${field} must be testnet or mainnet`);
}

function readCaseId(record: Record<string, unknown>): NormalSigningVectorCaseV2['caseId'] {
  const value = readString(record, 'case_id');
  switch (value) {
    case 'near_transaction_v1':
    case 'nep413_v1':
    case 'near_delegate_action_v1':
      return value;
    default:
      throw new Error(`unsupported normal-signing vector case ${value}`);
  }
}

function readRecord(value: unknown, label: string): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`${label} must be an object`);
}

function readArray(record: Record<string, unknown>, field: string): readonly unknown[] {
  const value = record[field];
  if (Array.isArray(value)) return value;
  throw new Error(`${field} must be an array`);
}

function readString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value === 'string' && value.length > 0) return value;
  throw new Error(`${field} must be a non-empty string`);
}

function readNumber(record: Record<string, unknown>, field: string): number {
  const value = record[field];
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return value;
  throw new Error(`${field} must be a positive safe integer`);
}

test.describe('Router A/B normal-signing v2 Rust vectors', () => {
  test('SDK builders match Rust request and admission digest vectors', async () => {
    const vectors = readNormalSigningVectors();

    for (const vector of vectors) {
      const built = await buildFromVector(vector);
      expect(built.request, vector.caseId).toEqual(vector.prepareRequestJson);
      expect(digestB64u(built.admissionMaterial.intentDigest), vector.caseId).toBe(
        vector.intentDigestB64u,
      );
      expect(digestB64u(built.admissionMaterial.signingPayloadDigest), vector.caseId).toBe(
        vector.signingPayloadDigestB64u,
      );
      expect(digestB64u(built.admissionMaterial.admittedSigningDigest), vector.caseId).toBe(
        vector.admittedSigningDigestB64u,
      );
    }
  });
});
