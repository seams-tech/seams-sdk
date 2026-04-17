import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthService } from '../../server/src/core/AuthService';
import { createThresholdSigningService } from '../../server/src/core/ThresholdService';
import {
  parseSigningRootSecretShareWireV1,
  type SigningRootSecretShareId,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import {
  sealSigningRootSecretShareWireV1,
  type SigningRootSecretShareKekResolutionInput,
} from '../../server/src/core/ThresholdService/signingRootSecretSealing';
import { InMemorySigningRootSecretStore } from '../../server/src/core/ThresholdService/stores/SigningRootSecretStore';
import type { ThresholdStoreConfigInput } from '../../server/src/core/types';

type ThresholdPrfFixtureShare = {
  readonly id: SigningRootSecretShareId;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly shares: readonly ThresholdPrfFixtureShare[];
};

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-v1.json');
const ORG_ID = 'org-alpha';
const PROJECT_ID = 'project-alpha';
const ENV_ID = 'dev';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const KEK_ID = 'kek-v1';
const KEK_BYTES = new Uint8Array(32).fill(0x42);
const CONTEXT = {
  signingRootId: SIGNING_ROOT_ID,
  nearAccountId: 'alice.near',
  keyPurpose: 'wallet',
  keyVersion: 'v1',
  participantIds: [1, 2],
  derivationVersion: 1,
};

function createAuthServiceMock(): AuthService {
  return {
    getRelayerAccount: async () => 'relayer.testnet',
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
    viewAccessKeyList: async () => ({ keys: [] }),
  } as unknown as AuthService;
}

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const corpus = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ThresholdPrfFixtureCorpus;
  const vector = corpus.vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

test('Ed25519 HSS prepare uses signing-root resolver when configured and preserves response shape', async () => {
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = async (input: SigningRootSecretShareKekResolutionInput): Promise<Uint8Array> => {
    resolverCalls.push(input);
    return KEK_BYTES;
  };
  const store = new InMemorySigningRootSecretStore();
  const vector = vectorForPurpose('ed25519-hss/y_relayer');
  for (const share of vector.shares.slice(0, 2)) {
    const parsed = parseSigningRootSecretShareWireV1(hexToBytes(share.wire_hex));
    if (!parsed.ok) throw new Error(parsed.message);
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: parsed.value,
      resolveKek,
    });
    parsed.value.fill(0);
    await store.putSealedSigningRootSecretShare({
      signingRootId: SIGNING_ROOT_ID,
      shareId: share.id,
      kekId: KEK_ID,
      sealedShare,
    });
  }

  const thresholdConfig: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    signingRootSecretStore: store,
    signingRootSecretShareKekResolver: resolveKek,
  };
  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: thresholdConfig,
    isNode: true,
  });

  expect(service.hasSigningRootShareResolver()).toBe(true);
  const prepared = await service.ed25519Hss.prepareForRegistration({
    orgId: ORG_ID,
    signingRootId: SIGNING_ROOT_ID,
    request: {
      new_account_id: CONTEXT.nearAccountId,
      rp_id: 'example.localhost',
      context: CONTEXT,
    },
  });

  expect(prepared.ok).toBe(true);
  if (!prepared.ok) throw new Error(prepared.message);
  expect(prepared.ceremonyHandle).toBeTruthy();
  expect(prepared.preparedSession.contextBindingB64u).toBeTruthy();
  expect(prepared.preparedSession.evaluatorDriverStateB64u).toBeTruthy();
  expect(prepared.clientOtOfferMessageB64u).toBeTruthy();
  expect(resolverCalls.map((call) => call.shareId)).toEqual([1, 2, 1, 2]);
  expect(new Set(resolverCalls.map((call) => call.signingRootId))).toEqual(
    new Set([SIGNING_ROOT_ID]),
  );

  const resolverCallCount = resolverCalls.length;
  const mismatchedPrepared = await service.ed25519Hss.prepareForRegistration({
    orgId: ORG_ID,
    signingRootId: `${PROJECT_ID}:staging`,
    request: {
      new_account_id: CONTEXT.nearAccountId,
      rp_id: 'example.localhost',
      context: CONTEXT,
    },
  });

  expect(mismatchedPrepared.ok).toBe(false);
  if (mismatchedPrepared.ok) throw new Error('expected mismatched signing root to fail');
  expect(mismatchedPrepared.code).toBe('unauthorized');
  expect(mismatchedPrepared.message).toContain('context.signingRootId');
  expect(resolverCalls).toHaveLength(resolverCallCount);
});
