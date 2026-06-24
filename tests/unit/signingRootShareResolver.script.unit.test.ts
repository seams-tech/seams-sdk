import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  createHostedSigningRootShareResolver,
  createSelfHostedSigningRootShareResolver,
  deriveEcdsaHssYRelayerFromSigningRootShareResolver,
  deriveEd25519HssServerInputsFromSigningRootShareResolver,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver';
import type { SealedSigningRootShare } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver';
import {
  deriveEcdsaHssYRelayerFromSigningRootShares,
  deriveEd25519HssServerInputsFromSigningRootShares,
  parseSigningRootShareWire,
  type ThresholdPrfPolicy,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm';

type ThresholdPrfFixtureShare = {
  readonly id: number;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly policy: {
    readonly threshold: number;
    readonly share_count: number;
  };
  readonly shares: readonly ThresholdPrfFixtureShare[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(
  __dirname,
  '../../crates/threshold-prf/fixtures/protocol-t-of-n.json',
);
const PROJECT_ID = 'project-alpha:dev';
const SIGNING_ROOT_VERSION = 'root-v1';
const ECDSA_HSS_FIXTURE_PURPOSE = 'ecdsa-hss/y_server';
const ECDSA_HSS_CONTEXT = {
  applicationBindingDigest: new Uint8Array(32).fill(7),
} as const;

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const corpus = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as {
    readonly vectors: readonly ThresholdPrfFixtureVector[];
  };
  const vector = corpus.vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function sealedShareRecord(shareId: number): SealedSigningRootShare {
  return {
    signingRootId: PROJECT_ID,
    shareId,
    signingRootVersion: SIGNING_ROOT_VERSION,
    sealedShare: new Uint8Array([shareId, 0xbb]),
    storageId: `store-share-${shareId}`,
    kekId: `kek-share-${shareId}`,
  };
}

function policyForVector(vector: ThresholdPrfFixtureVector): ThresholdPrfPolicy {
  return {
    protocol: 'threshold-prf',
    threshold: vector.policy.threshold,
    shareCount: vector.policy.share_count,
  };
}

function shareWires(vector: ThresholdPrfFixtureVector, ids: readonly number[]) {
  return ids.map((id) => {
    const share = vector.shares.find((candidate) => candidate.id === id);
    if (!share) throw new Error(`missing share ${id}`);
    return parseSigningRootShareWire(hexToBytes(share.wire_hex));
  });
}

test('self-host signing-root resolver derives ECDSA HSS y_server through policy-shaped shares', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const preferredShareIds = [1, 2] as const;
  const resolver = createSelfHostedSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    policy,
    shares: vector.shares.map((share) => ({
      shareId: share.id,
      shareWireHex: share.wire_hex,
    })),
  });

  const result = await deriveEcdsaHssYRelayerFromSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds,
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });
  const expected = await deriveEcdsaHssYRelayerFromSigningRootShares({
    policy,
    shareWires: shareWires(vector, preferredShareIds),
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(bytesToHex(result.value)).toBe(bytesToHex(expected));
  result.value.fill(0);
  expected.fill(0);

  await expect(
    resolver.resolveSigningRootShareSet({
      signingRootId: PROJECT_ID,
      preferredShareIds,
    }),
  ).resolves.toHaveLength(2);
});

test('hosted signing-root resolver composes storage and decrypt adapters', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const preferredShareIds = [1, 2] as const;
  const decryptedById = new Map<number, Uint8Array>(
    vector.shares.map((share) => [share.id, hexToBytes(share.wire_hex)]),
  );
  const listInputs: unknown[] = [];
  const decryptCalls: number[] = [];
  const resolver = createHostedSigningRootShareResolver({
    policy,
    storageAdapter: {
      listSealedSigningRootShares: async (input) => {
        listInputs.push(input);
        return [sealedShareRecord(1), sealedShareRecord(2), sealedShareRecord(3)];
      },
    },
    decryptAdapter: {
      decryptSigningRootShare: async (record) => {
        decryptCalls.push(record.shareId);
        const share = decryptedById.get(record.shareId);
        if (!share) throw new Error(`missing share ${record.shareId}`);
        return share;
      },
    },
  });

  const result = await deriveEcdsaHssYRelayerFromSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds,
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });
  const expected = await deriveEcdsaHssYRelayerFromSigningRootShares({
    policy,
    shareWires: shareWires(vector, preferredShareIds),
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(bytesToHex(result.value)).toBe(bytesToHex(expected));
  expect(listInputs).toEqual([
    { signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION },
  ]);
  expect(decryptCalls).toEqual([1, 2]);
  expect(Array.from(decryptedById.get(1)!)).toEqual(new Array(34).fill(0));
  expect(Array.from(decryptedById.get(2)!)).toEqual(new Array(34).fill(0));
  expect(bytesToHex(decryptedById.get(3)!)).toBe(vector.shares[2].wire_hex);
  result.value.fill(0);
  expected.fill(0);
});

test('self-host signing-root resolver derives Ed25519 HSS inputs through policy-shaped shares', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const preferredShareIds = [1, 2] as const;
  const context = {
    signingRootId: PROJECT_ID,
    nearAccountId: 'alice.near',
    keyPurpose: 'wallet',
    keyVersion: 'v1',
    participantIds: [1, 2],
    derivationVersion: 1,
  };
  const resolver = createSelfHostedSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    policy,
    shares: vector.shares.map((share) => ({
      shareId: share.id,
      shareWireHex: share.wire_hex,
    })),
  });

  const result = await deriveEd25519HssServerInputsFromSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds,
    context,
  });
  const expected = await deriveEd25519HssServerInputsFromSigningRootShares({
    policy,
    shareWires: shareWires(vector, preferredShareIds),
    context,
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(result.value.contextBindingB64u).toBe(base64UrlEncode(expected.contextBinding));
  expect(result.value.yRelayerB64u).toBe(base64UrlEncode(expected.yRelayer));
  expect(result.value.tauRelayerB64u).toBe(base64UrlEncode(expected.tauRelayer));
  expect(result.value.participantIds).toEqual([1, 2]);
});

test('self-host signing-root resolver rejects wrong scope and duplicate shares', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const resolver = createSelfHostedSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    policy,
    shares: vector.shares.slice(0, 2).map((share) => ({
      shareId: share.id,
      shareWireHex: share.wire_hex,
    })),
  });

  await expect(
    resolver.resolveSigningRootShareSet({
      signingRootId: 'other-project',
      signingRootVersion: SIGNING_ROOT_VERSION,
      preferredShareIds: [1, 2],
    }),
  ).rejects.toThrow(/signingRootId mismatch/);

  expect(() =>
    createSelfHostedSigningRootShareResolver({
      signingRootId: PROJECT_ID,
      policy,
      shares: [
        { shareId: 1, shareWireHex: vector.shares[0].wire_hex },
        { shareId: 1, shareWireHex: vector.shares[0].wire_hex },
      ],
    }),
  ).toThrow(/duplicate signing-root share id/);
});
