import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthService } from '../../server/src/core/AuthService';
import { createThresholdSigningService } from '../../server/src/core/ThresholdService';
import {
  deriveEcdsaHssYRelayerFromSigningRootSecretResolver,
  type SigningRootSecretDecryptAdapter,
  type SigningRootSecretShareSource,
} from '../../server/src/core/ThresholdService/signingRootSecretResolverAdapters';
import { createSelfHostedSigningRootShareResolver } from '../../server/src/core/ThresholdService/signingRootShareResolver';
import { deriveEcdsaHssYRelayerFromSigningRootSecretShares } from '../../server/src/core/ThresholdService/thresholdPrfWasm';
import { parseSigningRootSecretShareWireV1 } from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import {
  sealSigningRootSecretShareWireV1,
  type SigningRootSecretShareKekResolutionInput,
} from '../../server/src/core/ThresholdService/signingRootSecretSealing';
import { InMemorySigningRootSecretStore } from '../../server/src/core/ThresholdService/stores/SigningRootSecretStore';
import {
  ecdsaHssBootstrapNonExportSign,
  ecdsaHssExplicitExport,
  prepareThresholdEcdsaHssServerSession,
} from '../../server/src/core/ThresholdService/ethSignerWasm';
import type {
  SigningRootSecretShareId,
  SealedSigningRootSecretShare,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import type {
  ThresholdEcdsaHssPrepareRequest,
  ThresholdStoreConfigInput,
} from '../../server/src/core/types';

type ThresholdPrfFixtureShare = {
  readonly id: SigningRootSecretShareId;
  readonly wire_hex: string;
};

type ThresholdPrfFixturePairwiseOutput = {
  readonly ids: readonly [SigningRootSecretShareId, SigningRootSecretShareId];
  readonly output_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly shares: readonly ThresholdPrfFixtureShare[];
  readonly pairwise_outputs: readonly ThresholdPrfFixturePairwiseOutput[];
};

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-v1.json');
const PROJECT_ID = 'project-alpha';
const ENV_ID = 'dev';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const SIGNING_ROOT_VERSION = 'root-v1';
const KEK_ID = 'kek-v1';
const KEK_BYTES = new Uint8Array(32).fill(0x42);
const ECDSA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
} as const;
const ECDSA_CONTEXT = {
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
  walletSessionUserId: 'alice.near',
  subjectId: 'alice-subject',
  chainTarget: ECDSA_CHAIN_TARGET,
  ecdsaThresholdKeyId: 'ecdsa-alpha',
  keyPurpose: 'wallet',
  keyVersion: 'v1',
};
const ECDSA_SUBJECT_ID = ECDSA_CONTEXT.subjectId;

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

function shareWirePairForIds(
  vector: ThresholdPrfFixtureVector,
  ids: readonly [SigningRootSecretShareId, SigningRootSecretShareId],
) {
  const parsed = ids.map((id) => {
    const share = vector.shares.find((candidate) => candidate.id === id);
    if (!share) throw new Error(`missing fixture share ${id}`);
    const result = parseSigningRootSecretShareWireV1(hexToBytes(share.wire_hex));
    if (!result.ok) throw new Error(result.message);
    return result.value;
  });
  return [parsed[0], parsed[1]] as const;
}

function createAuthServiceMock(): AuthService {
  return {
    getRelayerAccount: async () => 'relayer.testnet',
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
    viewAccessKeyList: async () => ({ keys: [] }),
  } as unknown as AuthService;
}

function sealedShareRecord(shareId: SigningRootSecretShareId): SealedSigningRootSecretShare {
  return {
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId,
    sealedShare: new Uint8Array([shareId, 0xaa]),
    storageId: `store-${shareId}`,
    kekId: `kek-${shareId}`,
  };
}

function createFixtureResolver(vector: ThresholdPrfFixtureVector) {
  const decryptedById = new Map<SigningRootSecretShareId, Uint8Array>(
    vector.shares.map((share) => [share.id, hexToBytes(share.wire_hex)]),
  );
  const store: SigningRootSecretShareSource = {
    listSealedSigningRootSecretShares: async () => [
      sealedShareRecord(1),
      sealedShareRecord(2),
      sealedShareRecord(3),
    ],
  };
  const decryptAdapter: SigningRootSecretDecryptAdapter = {
    decryptSigningRootSecretShare: async (record) => {
      const decrypted = decryptedById.get(record.shareId);
      if (!decrypted) throw new Error(`missing share ${record.shareId}`);
      return decrypted;
    },
  };
  return {
    listSealedSigningRootSecretShares: store.listSealedSigningRootSecretShares,
    decryptSigningRootSecretShare: decryptAdapter.decryptSigningRootSecretShare,
  };
}

test('ECDSA HSS consumes threshold-prf signing-root y_relayer without changing bootstrap/export identity semantics', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const resolver = createFixtureResolver(vector);
  const derivedYRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    preferredShareIds: [1, 2],
    resolver,
    context: ECDSA_CONTEXT,
  });
  expect(derivedYRelayer.ok).toBe(true);
  if (!derivedYRelayer.ok) throw new Error(derivedYRelayer.message);

  const yClient32Le = new Uint8Array(32).fill(0x07);
  const bootstrapped = await ecdsaHssBootstrapNonExportSign({
    ...ECDSA_CONTEXT,
    yClient32Le,
    yRelayer32Le: derivedYRelayer.value,
  });
  const exported = await ecdsaHssExplicitExport({
    ...ECDSA_CONTEXT,
    yClient32Le,
    yRelayer32Le: derivedYRelayer.value,
  });
  const prepared = await prepareThresholdEcdsaHssServerSession({
    ...ECDSA_CONTEXT,
    operation: 'registration_bootstrap',
    yRelayer32Le: derivedYRelayer.value,
  });

  expect(bytesToHex(bootstrapped.groupPublicKey33)).toBe(bytesToHex(exported.canonicalPublicKey33));
  expect(bytesToHex(bootstrapped.ethereumAddress20)).toBe(
    bytesToHex(exported.canonicalEthereumAddress20),
  );
  expect(prepared.preparedServerSessionB64u).toBeTruthy();
  expect(prepared.serverAssistInitMessageB64u).toBeTruthy();

  derivedYRelayer.value.fill(0);
  yClient32Le.fill(0);
});

test('ECDSA wallet identity is stable across local and pairwise partial-combine outputs', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const yClient32Le = new Uint8Array(32).fill(0x07);

  for (const pairwise of vector.pairwise_outputs) {
    const localShareWires = shareWirePairForIds(vector, pairwise.ids);
    const localYRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretShares({
      shareWires: localShareWires,
      context: ECDSA_CONTEXT,
    });
    const pairwiseYRelayer = hexToBytes(pairwise.output_hex);

    expect(bytesToHex(localYRelayer)).toBe(bytesToHex(pairwiseYRelayer));

    const localWallet = await ecdsaHssExplicitExport({
      ...ECDSA_CONTEXT,
      yClient32Le,
      yRelayer32Le: localYRelayer,
    });
    const pairwiseWallet = await ecdsaHssExplicitExport({
      ...ECDSA_CONTEXT,
      yClient32Le,
      yRelayer32Le: pairwiseYRelayer,
    });

    expect(bytesToHex(localWallet.canonicalPublicKey33)).toBe(
      bytesToHex(pairwiseWallet.canonicalPublicKey33),
    );
    expect(bytesToHex(localWallet.canonicalEthereumAddress20)).toBe(
      bytesToHex(pairwiseWallet.canonicalEthereumAddress20),
    );

    localShareWires[0].fill(0);
    localShareWires[1].fill(0);
    localYRelayer.fill(0);
    pairwiseYRelayer.fill(0);
  }

  yClient32Le.fill(0);
});

test('ECDSA HSS prepare uses signing-root resolver when configured and preserves response shape', async () => {
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = async (input: SigningRootSecretShareKekResolutionInput): Promise<Uint8Array> => {
    resolverCalls.push(input);
    return KEK_BYTES;
  };
  const store = new InMemorySigningRootSecretStore();
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  for (const share of vector.shares.slice(0, 2)) {
    const parsed = parseSigningRootSecretShareWireV1(hexToBytes(share.wire_hex));
    if (!parsed.ok) throw new Error(parsed.message);
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: parsed.value,
      resolveKek,
    });
    parsed.value.fill(0);
    await store.putSealedSigningRootSecretShare({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
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
  const sessionPolicy: ThresholdEcdsaHssPrepareRequest['sessionPolicy'] = {
    version: 'threshold_session_v1',
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    subjectId: ECDSA_SUBJECT_ID,
    chainTarget: ECDSA_CHAIN_TARGET,
    rpId: 'example.localhost',
    sessionId: 'ecdsa-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    runtimePolicyScope: {
      orgId: 'org-alpha',
      projectId: PROJECT_ID,
      envId: ENV_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    },
    participantIds: [1, 2],
    ttlMs: 60_000,
    remainingUses: 1,
  };

  expect(service.hasSigningRootShareResolver()).toBe(true);
  const prepared = await service.ecdsaHss.prepare({
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    rpId: 'example.localhost',
    operation: 'registration_bootstrap',
    keygenSessionId: 'keygen-session-1',
    sessionPolicy,
    webauthn_authentication: {} as ThresholdEcdsaHssPrepareRequest['webauthn_authentication'],
  });

  if (!prepared.ok) throw new Error(prepared.message);
  expect(prepared.ok).toBe(true);
  expect(prepared.ceremonyId).toBeTruthy();
  expect(prepared.preparedServerSessionB64u).toBeTruthy();
  expect(prepared.serverAssistInitB64u).toBeTruthy();
  expect(resolverCalls.map((call) => call.shareId)).toEqual([1, 2, 1, 2]);
});

test('ECDSA first bootstrap uses signing-root resolver when configured and no secp256k1 master secret is present', async () => {
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = async (input: SigningRootSecretShareKekResolutionInput): Promise<Uint8Array> => {
    resolverCalls.push(input);
    return KEK_BYTES;
  };
  const store = new InMemorySigningRootSecretStore();
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  for (const share of vector.shares.slice(0, 2)) {
    const parsed = parseSigningRootSecretShareWireV1(hexToBytes(share.wire_hex));
    if (!parsed.ok) throw new Error(parsed.message);
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: parsed.value,
      resolveKek,
    });
    parsed.value.fill(0);
    await store.putSealedSigningRootSecretShare({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
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
  const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(0x07)).toString('base64url');

  const bootstrapped = await service.bootstrapEcdsaFromRegistrationMaterial({
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    rpId: 'example.localhost',
    clientRootShare32B64u,
    sessionPolicy: {
      version: 'threshold_session_v1',
      walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
      subjectId: ECDSA_SUBJECT_ID,
      chainTarget: ECDSA_CHAIN_TARGET,
      rpId: 'example.localhost',
      sessionId: 'ecdsa-bootstrap-session-1',
      walletSigningSessionId: 'wallet-signing-bootstrap-1',
      runtimePolicyScope: {
        orgId: 'org-alpha',
        projectId: PROJECT_ID,
        envId: ENV_ID,
        signingRootVersion: SIGNING_ROOT_VERSION,
      },
      participantIds: [1, 2],
      ttlMs: 60_000,
      remainingUses: 1,
    },
  });

  if (!bootstrapped.ok) throw new Error(bootstrapped.message);
  expect(bootstrapped.ok).toBe(true);
  expect(bootstrapped.ecdsaThresholdKeyId).toBeTruthy();
  expect(bootstrapped.thresholdEcdsaPublicKeyB64u).toBeTruthy();
  expect(bootstrapped.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
  expect(bootstrapped.sessionId).toBe('ecdsa-bootstrap-session-1');
  expect(resolverCalls.map((call) => call.shareId)).toEqual([1, 2, 1, 2]);
});

test('ECDSA self-host signing-root resolver supplies fixed project scope when session policy has no runtime scope', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const signingRootShareResolver = createSelfHostedSigningRootShareResolver({
    signingRootId: SIGNING_ROOT_ID,
    shares: vector.shares.slice(0, 2).map((share) => ({
      shareId: share.id,
      shareWireHex: share.wire_hex,
    })),
  });
  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: {
      kind: 'in-memory',
      signingRootShareResolver,
    },
    isNode: true,
  });
  const sessionPolicy: ThresholdEcdsaHssPrepareRequest['sessionPolicy'] = {
    version: 'threshold_session_v1',
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    subjectId: ECDSA_SUBJECT_ID,
    chainTarget: ECDSA_CHAIN_TARGET,
    rpId: 'example.localhost',
    sessionId: 'ecdsa-self-host-session-1',
    walletSigningSessionId: 'wallet-signing-self-host-1',
    participantIds: [1, 2],
    ttlMs: 60_000,
    remainingUses: 1,
  };

  const prepared = await service.ecdsaHss.prepare({
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    rpId: 'example.localhost',
    operation: 'registration_bootstrap',
    keygenSessionId: 'self-host-keygen-session-1',
    sessionPolicy,
    webauthn_authentication: {} as ThresholdEcdsaHssPrepareRequest['webauthn_authentication'],
  });
  expect(prepared.ok).toBe(true);
  if (!prepared.ok) throw new Error(prepared.message);

  const bootstrapped = await service.bootstrapEcdsaFromRegistrationMaterial({
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    rpId: 'example.localhost',
    clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(0x07)).toString('base64url'),
    sessionPolicy,
  });

  expect(bootstrapped.ok).toBe(true);
  if (!bootstrapped.ok) throw new Error(bootstrapped.message);
  expect(bootstrapped.ecdsaThresholdKeyId).toBeTruthy();
  expect(bootstrapped.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
  expect(bootstrapped.sessionId).toBe('ecdsa-self-host-session-1');
});

test('ECDSA signing-root wallet verification derives the known address from imported root-versioned shares', async () => {
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = async (input: SigningRootSecretShareKekResolutionInput): Promise<Uint8Array> => {
    resolverCalls.push(input);
    return KEK_BYTES;
  };
  const store = new InMemorySigningRootSecretStore();
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  for (const share of vector.shares.slice(0, 2)) {
    const parsed = parseSigningRootSecretShareWireV1(hexToBytes(share.wire_hex));
    if (!parsed.ok) throw new Error(parsed.message);
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: parsed.value,
      resolveKek,
    });
    parsed.value.fill(0);
    await store.putSealedSigningRootSecretShare({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      sealedShare,
    });
  }
  resolverCalls.length = 0;

  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: {
      kind: 'in-memory',
      signingRootSecretStore: store,
      signingRootSecretShareKekResolver: resolveKek,
    },
    isNode: true,
  });
  const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(0x07)).toString('base64url');

  const first = await service.verifyEcdsaSigningRootWalletAddress({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    subjectId: ECDSA_CONTEXT.subjectId,
    chainTarget: ECDSA_CONTEXT.chainTarget,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    rpId: 'example.localhost',
    clientRootShare32B64u,
  });
  expect(first.ok).toBe(true);
  if (!first.ok) throw new Error(first.message);
  expect(first.verified).toBe(true);
  expect(first.canonicalEthereumAddress).toMatch(/^0x[0-9a-f]{40}$/);

  const second = await service.verifyEcdsaSigningRootWalletAddress({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    subjectId: ECDSA_CONTEXT.subjectId,
    chainTarget: ECDSA_CONTEXT.chainTarget,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    rpId: 'example.localhost',
    clientRootShare32B64u,
    expectedEthereumAddress: first.canonicalEthereumAddress,
  });
  expect(second).toMatchObject({
    ok: true,
    verified: true,
    canonicalEthereumAddress: first.canonicalEthereumAddress,
  });

  const mismatch = await service.verifyEcdsaSigningRootWalletAddress({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    walletSessionUserId: ECDSA_CONTEXT.walletSessionUserId,
    subjectId: ECDSA_CONTEXT.subjectId,
    chainTarget: ECDSA_CONTEXT.chainTarget,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    rpId: 'example.localhost',
    clientRootShare32B64u,
    expectedEthereumAddress: `0x${'11'.repeat(20)}`,
  });
  expect(mismatch).toMatchObject({
    ok: true,
    verified: false,
    expectedEthereumAddress: `0x${'11'.repeat(20)}`,
  });
  expect(resolverCalls.map((call) => `${call.shareId}:${call.signingRootVersion}`)).toEqual([
    `1:${SIGNING_ROOT_VERSION}`,
    `2:${SIGNING_ROOT_VERSION}`,
    `1:${SIGNING_ROOT_VERSION}`,
    `2:${SIGNING_ROOT_VERSION}`,
    `1:${SIGNING_ROOT_VERSION}`,
    `2:${SIGNING_ROOT_VERSION}`,
  ]);
});
