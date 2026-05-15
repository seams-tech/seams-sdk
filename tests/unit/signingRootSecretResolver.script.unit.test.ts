import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createSigningRootSecretResolver,
  deriveEcdsaHssYRelayerFromSigningRootSecretResolver,
  deriveEd25519HssServerInputsFromSigningRootSecretResolver,
  resolveSigningRootSecretShareWirePairFromResolver,
  type SigningRootSecretDecryptAdapter,
  type SigningRootSecretResolver,
  type SigningRootSecretShareSource,
  type ResolveSigningRootSecretSharesInput,
} from '../../server/src/core/ThresholdService/signingRootSecretResolverAdapters';
import { signingRootScopeFromRuntimePolicyScope } from '../../shared/src/threshold/signingRootScope';
import type {
  SigningRootSecretShareId,
  SigningRootSecretShareWireResult,
  SealedSigningRootSecretShare,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';

type ThresholdPrfFixtureShare = {
  readonly id: SigningRootSecretShareId;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly context_hex: string;
  readonly shares: readonly ThresholdPrfFixtureShare[];
  readonly direct_output_hex: string;
};

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-v1.json');
const RUNTIME_PROJECT_ID = 'project-alpha';
const RUNTIME_ENV_ID = 'dev';
const PROJECT_ID = `${RUNTIME_PROJECT_ID}:${RUNTIME_ENV_ID}`;
const SIGNING_ROOT_VERSION = 'root-v1';
const ECDSA_HSS_CONTEXT = {
  signingRootId: PROJECT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
  walletSessionUserId: 'alice.near',
  subjectId: 'alice-subject',
  chainTarget: {
    kind: 'evm' as const,
    namespace: 'eip155' as const,
    chainId: 11155111,
  },
  ecdsaThresholdKeyId: 'ecdsa-alpha',
  keyPurpose: 'wallet',
  keyVersion: 'v1',
} as const;

function loadCorpus(): ThresholdPrfFixtureCorpus {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ThresholdPrfFixtureCorpus;
}

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const vector = loadCorpus().vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function sealedShareRecord(
  shareId: SigningRootSecretShareId,
  signingRootId = PROJECT_ID,
): SealedSigningRootSecretShare {
  return {
    signingRootId,
    shareId,
    sealedShare: new Uint8Array([shareId, 0xaa]),
    signingRootVersion: SIGNING_ROOT_VERSION,
    storageId: `store-${shareId}`,
    kekId: `kek-${shareId}`,
  };
}

function createFixtureResolver(
  vector: ThresholdPrfFixtureVector,
  signingRootId = PROJECT_ID,
): {
  readonly resolver: SigningRootSecretResolver;
  readonly decryptedById: Map<SigningRootSecretShareId, Uint8Array>;
  readonly listInputs: ResolveSigningRootSecretSharesInput[];
  readonly decryptCalls: SigningRootSecretShareId[];
} {
  const decryptedById = new Map<SigningRootSecretShareId, Uint8Array>(
    vector.shares.map((share) => [share.id, hexToBytes(share.wire_hex)]),
  );
  const listInputs: ResolveSigningRootSecretSharesInput[] = [];
  const decryptCalls: SigningRootSecretShareId[] = [];
  const store: SigningRootSecretShareSource = {
    listSealedSigningRootSecretShares: async (input) => {
      listInputs.push(input);
      return [
        sealedShareRecord(1, signingRootId),
        sealedShareRecord(2, signingRootId),
        sealedShareRecord(3, signingRootId),
      ];
    },
  };
  const decryptAdapter: SigningRootSecretDecryptAdapter = {
    decryptSigningRootSecretShare: async (record) => {
      decryptCalls.push(record.shareId);
      const decrypted = decryptedById.get(record.shareId);
      if (!decrypted) throw new Error(`missing share ${record.shareId}`);
      return decrypted;
    },
  };

  return {
    decryptedById,
    listInputs,
    decryptCalls,
    resolver: createSigningRootSecretResolver({ store, decryptAdapter }),
  };
}

function expectZeroized(bytes: Uint8Array): void {
  expect(Array.from(bytes)).toEqual(new Array(bytes.length).fill(0));
}

test('signing-root resolver derives ECDSA HSS y_relayer and zeroizes decrypted share scratch buffers', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const { resolver, decryptedById, listInputs, decryptCalls } = createFixtureResolver(vector);

  const result = await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds: [1, 2],
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(bytesToHex(result.value)).toBe(vector.direct_output_hex);
  result.value.fill(0);

  expect(listInputs).toEqual([{ signingRootId: PROJECT_ID, signingRootVersion: SIGNING_ROOT_VERSION }]);
  expect(decryptCalls).toEqual([1, 2]);
  expectZeroized(decryptedById.get(1)!);
  expectZeroized(decryptedById.get(2)!);
  expect(bytesToHex(decryptedById.get(3)!)).toBe(vector.shares[2].wire_hex);
});

test('ECDSA signing-root derivation ignores org ownership and changes with signing root scope', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const sameProjectScopeA = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org-alpha',
    projectId: RUNTIME_PROJECT_ID,
    envId: RUNTIME_ENV_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const sameProjectScopeB = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org-beta',
    projectId: RUNTIME_PROJECT_ID,
    envId: RUNTIME_ENV_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const differentEnvScope = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org-alpha',
    projectId: RUNTIME_PROJECT_ID,
    envId: 'staging',
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(sameProjectScopeA.signingRootId).toBe(sameProjectScopeB.signingRootId);
  expect(differentEnvScope.signingRootId).not.toBe(sameProjectScopeA.signingRootId);

  const derive = async (signingRootId: string): Promise<Uint8Array> => {
    const { resolver } = createFixtureResolver(vector, signingRootId);
    const result = await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
      signingRootId,
      signingRootVersion: SIGNING_ROOT_VERSION,
      resolver,
      preferredShareIds: [1, 2],
      context: {
        ...ECDSA_HSS_CONTEXT,
        signingRootId,
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    return result.value;
  };

  const orgAlphaYRelayer = await derive(sameProjectScopeA.signingRootId);
  const orgBetaYRelayer = await derive(sameProjectScopeB.signingRootId);
  const stagingYRelayer = await derive(differentEnvScope.signingRootId);

  expect(bytesToHex(orgAlphaYRelayer)).toBe(bytesToHex(orgBetaYRelayer));
  expect(bytesToHex(stagingYRelayer)).not.toBe(bytesToHex(orgAlphaYRelayer));

  orgAlphaYRelayer.fill(0);
  orgBetaYRelayer.fill(0);
  stagingYRelayer.fill(0);
});

test('signing-root resolver derives Ed25519 HSS server inputs from canonical threshold-prf vectors', async () => {
  const yVector = vectorForPurpose('ed25519-hss/y_relayer');
  const tauVector = vectorForPurpose('ed25519-hss/tau_relayer');
  const { resolver } = createFixtureResolver(yVector);

  const result = await deriveEd25519HssServerInputsFromSigningRootSecretResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds: [1, 2],
    context: {
      signingRootId: PROJECT_ID,
      nearAccountId: 'alice.near',
      keyPurpose: 'wallet',
      keyVersion: 'v1',
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  expect(result.value.contextBindingB64u).toBe(hexToBase64Url(yVector.context_hex));
  expect(result.value.yRelayerB64u).toBe(hexToBase64Url(yVector.direct_output_hex));
  expect(result.value.tauRelayerB64u).toBe(hexToBase64Url(tauVector.direct_output_hex));
});

test('Ed25519 signing-root derivation ignores org ownership and changes with signing root scope', async () => {
  const vector = vectorForPurpose('ed25519-hss/y_relayer');
  const sameProjectScopeA = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org-alpha',
    projectId: RUNTIME_PROJECT_ID,
    envId: RUNTIME_ENV_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const sameProjectScopeB = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org-beta',
    projectId: RUNTIME_PROJECT_ID,
    envId: RUNTIME_ENV_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const differentProjectScope = signingRootScopeFromRuntimePolicyScope({
    orgId: 'org-alpha',
    projectId: 'project-beta',
    envId: RUNTIME_ENV_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(sameProjectScopeA.signingRootId).toBe(sameProjectScopeB.signingRootId);
  expect(differentProjectScope.signingRootId).not.toBe(sameProjectScopeA.signingRootId);

  const derive = async (signingRootId: string) => {
    const { resolver } = createFixtureResolver(vector, signingRootId);
    const result = await deriveEd25519HssServerInputsFromSigningRootSecretResolver({
      signingRootId,
      signingRootVersion: SIGNING_ROOT_VERSION,
      resolver,
      preferredShareIds: [1, 2],
      context: {
        signingRootId,
        nearAccountId: 'alice.near',
        keyPurpose: 'wallet',
        keyVersion: 'v1',
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    return result.value;
  };

  const orgAlphaInputs = await derive(sameProjectScopeA.signingRootId);
  const orgBetaInputs = await derive(sameProjectScopeB.signingRootId);
  const projectBetaInputs = await derive(differentProjectScope.signingRootId);

  expect(orgAlphaInputs.yRelayerB64u).toBe(orgBetaInputs.yRelayerB64u);
  expect(orgAlphaInputs.tauRelayerB64u).toBe(orgBetaInputs.tauRelayerB64u);
  expect(projectBetaInputs.yRelayerB64u).not.toBe(orgAlphaInputs.yRelayerB64u);
  expect(projectBetaInputs.tauRelayerB64u).not.toBe(orgAlphaInputs.tauRelayerB64u);
});

test('signing-root resolver reports list failures before decrypting shares', async () => {
  let decryptCalls = 0;
  const result = await resolveSigningRootSecretShareWirePairFromResolver({
    signingRootId: PROJECT_ID,
    resolver: {
      listSealedSigningRootSecretShares: async () => {
        throw new Error('store unavailable');
      },
      decryptSigningRootSecretShare: async () => {
        decryptCalls += 1;
        return new Uint8Array(33);
      },
    },
  });

  expect(result).toMatchObject({ ok: false, code: 'resolver_failed' });
  expect(decryptCalls).toBe(0);
});

test('signing-root resolver reports canonical share decode failures as derivation failures', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const { resolver, decryptedById } = createFixtureResolver(vector);

  decryptedById.set(1, new Uint8Array([1, ...new Array(32).fill(0xff)]));

  const result = await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds: [1, 2],
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });

  expect(result).toMatchObject({ ok: false, code: 'derive_failed' });
  expectZeroized(decryptedById.get(1)!);
  expectZeroized(decryptedById.get(2)!);
});

test('signing-root resolver reports public share-wire validation failures before derivation', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const { resolver, decryptedById } = createFixtureResolver(vector);

  decryptedById.set(1, new Uint8Array([4, ...new Array(32).fill(0x11)]));

  const result = await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
    signingRootId: PROJECT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    resolver,
    preferredShareIds: [1, 2],
    context: {
      ...ECDSA_HSS_CONTEXT,
    },
  });

  expect(result).toMatchObject({ ok: false, code: 'invalid_share_id' });
  expectZeroized(decryptedById.get(1)!);
});

test('signing-root resolver preserves typed resolve errors through derivation helpers', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const { resolver } = createFixtureResolver(vector);

  const result: SigningRootSecretShareWireResult<Uint8Array> =
    await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
      signingRootId: PROJECT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      resolver,
      preferredShareIds: [1, 1],
      context: {
        ...ECDSA_HSS_CONTEXT,
      },
    });

  expect(result).toMatchObject({ ok: false, code: 'duplicate_share' });
});
