import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createHostedSigningRootShareResolver,
  createSealedSelfHostedSigningRootShareResolver,
  createSelfHostedSigningRootShareResolver,
  deriveEcdsaHssYRelayerFromSigningRootShareResolver,
} from '../../server/src/core/ThresholdService/signingRootShareResolver';
import type {
  SigningRootSecretShareId,
  SealedSigningRootSecretShare,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';

type ThresholdPrfFixtureShare = {
  readonly id: SigningRootSecretShareId;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly shares: readonly ThresholdPrfFixtureShare[];
  readonly direct_output_hex: string;
};

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-v1.json');
const PROJECT_ID = 'project-alpha:dev';
const SIGNING_ROOT_VERSION = 'root-v1';

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const corpus = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ThresholdPrfFixtureCorpus;
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

function sealedShareRecord(shareId: SigningRootSecretShareId): SealedSigningRootSecretShare {
  return {
    signingRootId: PROJECT_ID,
    shareId,
    signingRootVersion: SIGNING_ROOT_VERSION,
    sealedShare: new Uint8Array([shareId, 0xaa]),
    storageId: `store-${shareId}`,
    kekId: `kek-${shareId}`,
  };
}

test('self-host signing-root resolver derives y_relayer directly from imported shares', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const resolver = createSelfHostedSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shares: vector.shares.map((share) => ({
      shareId: share.id,
      shareWireHex: share.wire_hex,
    })),
  });

  const result = await deriveEcdsaHssYRelayerFromSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds: [1, 2],
    context: {
      signingRootId: PROJECT_ID,
      nearAccountId: 'alice.near',
      keyPurpose: 'wallet',
      keyVersion: 'v1',
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(bytesToHex(result.value)).toBe(vector.direct_output_hex);

  await expect(
    resolver.resolveSigningRootSharePair({
      signingRootId: PROJECT_ID,
      preferredShareIds: [1, 2],
    }),
  ).resolves.toHaveLength(2);
});

test('self-host signing-root resolver rejects wrong scope and duplicate shares', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const resolver = createSelfHostedSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shares: vector.shares.slice(0, 2).map((share) => ({
      shareId: share.id,
      shareWireHex: share.wire_hex,
    })),
  });

  await expect(
    resolver.resolveSigningRootSharePair({
      signingRootId: 'other-project',
      signingRootVersion: SIGNING_ROOT_VERSION,
      preferredShareIds: [1, 2],
    }),
  ).rejects.toThrow(/signingRootId mismatch/);

  expect(() =>
    createSelfHostedSigningRootShareResolver({
      signingRootId: PROJECT_ID,
      shares: [
        { shareId: 1, shareWireHex: vector.shares[0].wire_hex },
        { shareId: 1, shareWireHex: vector.shares[0].wire_hex },
      ],
    }),
  ).toThrow(/duplicate signing-root share id/);
});

test('hosted signing-root resolver composes storage and decrypt adapters', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const decryptedById = new Map<SigningRootSecretShareId, Uint8Array>(
    vector.shares.map((share) => [share.id, hexToBytes(share.wire_hex)]),
  );
  const listInputs: unknown[] = [];
  const decryptCalls: SigningRootSecretShareId[] = [];
  const resolver = createHostedSigningRootShareResolver({
    storageAdapter: {
      listSealedSigningRootSecretShares: async (input) => {
        listInputs.push(input);
        return [sealedShareRecord(1), sealedShareRecord(2), sealedShareRecord(3)];
      },
    },
    decryptAdapter: {
      decryptSigningRootSecretShare: async (record) => {
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
    preferredShareIds: [1, 2],
    context: {
      signingRootId: PROJECT_ID,
      nearAccountId: 'alice.near',
      keyPurpose: 'wallet',
      keyVersion: 'v1',
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(bytesToHex(result.value)).toBe(vector.direct_output_hex);
  expect(listInputs).toEqual([{ signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION }]);
  expect(decryptCalls).toEqual([1, 2]);
});

test('sealed self-host signing-root resolver pins project scope while using caller adapters', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const decryptedById = new Map<SigningRootSecretShareId, Uint8Array>(
    vector.shares.map((share) => [share.id, hexToBytes(share.wire_hex)]),
  );
  const resolver = createSealedSelfHostedSigningRootShareResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    storageAdapter: {
      listSealedSigningRootSecretShares: async () => [
        sealedShareRecord(1),
        sealedShareRecord(2),
        sealedShareRecord(3),
      ],
    },
    decryptAdapter: {
      decryptSigningRootSecretShare: async (record) => {
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
    preferredShareIds: [1, 2],
    context: {
      signingRootId: PROJECT_ID,
      nearAccountId: 'alice.near',
      keyPurpose: 'wallet',
      keyVersion: 'v1',
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(bytesToHex(result.value)).toBe(vector.direct_output_hex);
  await expect(
    resolver.resolveSigningRootSharePair({
      signingRootId: PROJECT_ID,
      signingRootVersion: 'wrong-root',
      preferredShareIds: [1, 2],
    }),
  ).rejects.toThrow(/signingRootVersion mismatch/);
});
