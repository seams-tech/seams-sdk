import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createHostedSigningRootShareResolver,
  createSelfHostedSigningRootShareResolver,
  deriveEcdsaHssYRelayerFromSigningRootShareResolver,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver';
import { MissingSigningRootKekError } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootKekProvider';
import type {
  SealedSigningRootShare,
  SigningRootShareDecryptAdapter,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver';
import {
  deriveEcdsaHssYRelayerFromSigningRootShares,
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
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-t-of-n.json');
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

class FixtureSigningRootDecryptAdapter implements SigningRootShareDecryptAdapter {
  readonly decryptCalls: number[] = [];

  constructor(private readonly decryptedById: ReadonlyMap<number, Uint8Array>) {}

  async decryptSigningRootShare(record: SealedSigningRootShare): Promise<Uint8Array> {
    this.decryptCalls.push(record.shareId);
    const share = this.decryptedById.get(record.shareId);
    if (!share) throw new Error(`missing share ${record.shareId}`);
    return share;
  }
}

class ThrowingSigningRootDecryptAdapter implements SigningRootShareDecryptAdapter {
  constructor(private readonly error: unknown) {}

  async decryptSigningRootShare(_record: SealedSigningRootShare): Promise<Uint8Array> {
    throw this.error;
  }
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
  const decryptAdapter = new FixtureSigningRootDecryptAdapter(decryptedById);
  const resolver = createHostedSigningRootShareResolver({
    policy,
    storageAdapter: {
      listSealedSigningRootShares: async (input) => {
        listInputs.push(input);
        return [sealedShareRecord(1), sealedShareRecord(2), sealedShareRecord(3)];
      },
    },
    decryptAdapter,
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
  expect(decryptAdapter.decryptCalls).toEqual([1, 2]);
  expect(Array.from(decryptedById.get(1)!)).toEqual(new Array(34).fill(0));
  expect(Array.from(decryptedById.get(2)!)).toEqual(new Array(34).fill(0));
  expect(bytesToHex(decryptedById.get(3)!)).toBe(vector.shares[2].wire_hex);
  result.value.fill(0);
  expected.fill(0);
});

test('hosted signing-root resolver reports missing KEK with the fail-closed error code', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const preferredShareIds = [1, 2] as const;
  const resolver = createHostedSigningRootShareResolver({
    policy,
    storageAdapter: {
      listSealedSigningRootShares: async () => [sealedShareRecord(1), sealedShareRecord(2)],
    },
    decryptAdapter: new ThrowingSigningRootDecryptAdapter(
      new MissingSigningRootKekError('kek-share-1', 'Worker secret'),
    ),
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

  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('missing KEK resolver result must fail');
  expect(result.code).toBe('missing_signing_root_kek');
  expect(result.message).toContain('kek-share-1');
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
