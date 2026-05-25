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
  roleLocalThresholdEcdsaHssRelayerBootstrap,
  secp256k1PrivateKey32ToPublicKey33,
} from '../../server/src/core/ThresholdService/ethSignerWasm';
import {
  initSync as initHssClientSignerWasmSync,
  threshold_ecdsa_hss_role_local_client_bootstrap,
  threshold_ecdsa_hss_role_local_export_artifact,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import type {
  SigningRootSecretShareId,
  SealedSigningRootSecretShare,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import type { ThresholdStoreConfigInput } from '../../server/src/core/types';

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
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
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
  walletId: 'alice.near',
  rpId: 'wallet.example.test',
  chainTarget: ECDSA_CHAIN_TARGET,
  ecdsaThresholdKeyId: 'ecdsa-alpha',
  keyPurpose: 'wallet',
  keyVersion: 'v1',
};
const ECDSA_SUBJECT_ID = ECDSA_CONTEXT.walletId;
const ROLE_LOCAL_KEY_PURPOSE = 'evm-signing';
const ROLE_LOCAL_KEY_VERSION = 'v1';
let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

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

function bytesB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function hexToBytesPrefixed(hex: string): Uint8Array {
  return hexToBytes(hex.replace(/^0x/i, ''));
}

async function roleLocalWalletFromShares(input: {
  yClient32Le: Uint8Array;
  yRelayer32Le: Uint8Array;
}) {
  ensureHssClientSignerWasm();
  const context = {
    walletId: ECDSA_CONTEXT.walletId,
    rpId: ECDSA_CONTEXT.rpId,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    signingRootId: ECDSA_CONTEXT.signingRootId,
    signingRootVersion: ECDSA_CONTEXT.signingRootVersion,
    keyPurpose: ROLE_LOCAL_KEY_PURPOSE,
    keyVersion: ROLE_LOCAL_KEY_VERSION,
  };
  const clientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
    ...context,
    clientRootShare32B64u: bytesB64u(input.yClient32Le),
  }) as {
    contextBinding32B64u: string;
    clientPublicKey33B64u: string;
    clientShareRetryCounter: number;
  };
  const relayerBootstrap = await roleLocalThresholdEcdsaHssRelayerBootstrap({
    ...context,
    relayerKeyId: 'ehss-relayer-signing-root-test',
    yRelayer32Le: input.yRelayer32Le,
    clientPublicKey33: Buffer.from(clientBootstrap.clientPublicKey33B64u, 'base64url'),
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
  });
  const exportArtifact = threshold_ecdsa_hss_role_local_export_artifact({
    ...context,
    clientRootShare32: input.yClient32Le,
    serverExportShare32B64u: bytesB64u(relayerBootstrap.relayerShare32),
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
    relayerPublicKey33B64u: bytesB64u(relayerBootstrap.relayerPublicKey33),
    groupPublicKey33B64u: bytesB64u(relayerBootstrap.groupPublicKey33),
    ethereumAddress: `0x${bytesToHex(relayerBootstrap.ethereumAddress20)}`,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
  }) as { publicKeyHex: string; ethereumAddress: string };

  return {
    groupPublicKey33: relayerBootstrap.groupPublicKey33,
    ethereumAddress20: relayerBootstrap.ethereumAddress20,
    exportedPublicKey33: hexToBytesPrefixed(exportArtifact.publicKeyHex),
    exportedEthereumAddress20: hexToBytesPrefixed(exportArtifact.ethereumAddress),
  };
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

async function roleLocalBootstrapWithClientShare(args: {
  service: ReturnType<typeof createThresholdSigningService>;
  clientRootShare32B64u: string;
  sessionId: string;
  walletSigningSessionId: string;
  signingRootId?: string;
  signingRootVersion?: string;
}) {
  ensureHssClientSignerWasm();
  const signingRootId = args.signingRootId || SIGNING_ROOT_ID;
  const signingRootVersion = args.signingRootVersion || SIGNING_ROOT_VERSION;
  const clientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
    walletId: ECDSA_CONTEXT.walletId,
    rpId: ECDSA_CONTEXT.rpId,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyPurpose: ROLE_LOCAL_KEY_PURPOSE,
    keyVersion: ROLE_LOCAL_KEY_VERSION,
    clientRootShare32B64u: args.clientRootShare32B64u,
  }) as {
    contextBinding32B64u: string;
    clientPublicKey33B64u: string;
    clientShareRetryCounter: number;
  };

  return await args.service.ecdsaHssRoleLocalBootstrap({
    formatVersion: 'ecdsa-hss-role-local',
    walletId: ECDSA_CONTEXT.walletId,
    rpId: ECDSA_CONTEXT.rpId,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId: 'ehss-relayer-signing-root-test',
    clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: `request:${args.sessionId}`,
    sessionId: args.sessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    ttlMs: 60_000,
    remainingUses: 1,
    participantIds: [1, 2],
  });
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
  const wallet = await roleLocalWalletFromShares({
    yClient32Le,
    yRelayer32Le: derivedYRelayer.value,
  });

  expect(bytesToHex(wallet.groupPublicKey33)).toBe(bytesToHex(wallet.exportedPublicKey33));
  expect(bytesToHex(wallet.ethereumAddress20)).toBe(bytesToHex(wallet.exportedEthereumAddress20));

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

    const localWallet = await roleLocalWalletFromShares({
      yClient32Le,
      yRelayer32Le: localYRelayer,
    });
    const pairwiseWallet = await roleLocalWalletFromShares({
      yClient32Le,
      yRelayer32Le: pairwiseYRelayer,
    });

    expect(bytesToHex(localWallet.groupPublicKey33)).toBe(
      bytesToHex(pairwiseWallet.groupPublicKey33),
    );
    expect(bytesToHex(localWallet.ethereumAddress20)).toBe(
      bytesToHex(pairwiseWallet.ethereumAddress20),
    );

    localShareWires[0].fill(0);
    localShareWires[1].fill(0);
    localYRelayer.fill(0);
    pairwiseYRelayer.fill(0);
  }

  yClient32Le.fill(0);
});

test('ECDSA role-local bootstrap uses signing-root resolver when configured and preserves response shape', async () => {
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = async (
    input: SigningRootSecretShareKekResolutionInput,
  ): Promise<Uint8Array> => {
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
  expect(service.hasSigningRootShareResolver()).toBe(true);
  const bootstrapped = await roleLocalBootstrapWithClientShare({
    service,
    clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(0x07)).toString('base64url'),
    sessionId: 'ecdsa-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
  });

  if (!bootstrapped.ok) throw new Error(bootstrapped.message);
  expect(bootstrapped.ok).toBe(true);
  expect(bootstrapped.value.keyHandle).toBeTruthy();
  expect(bootstrapped.value.thresholdEcdsaPublicKeyB64u).toBeTruthy();
  expect(bootstrapped.value.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
  expect(bootstrapped.value.sessionId).toBe('ecdsa-session-1');
  expect(bootstrapped.value.walletSigningSessionId).toBe('wallet-signing-session-1');
  expect(resolverCalls.map((call) => call.shareId)).toEqual([1, 2, 1, 2]);
});

test('ECDSA self-host signing-root resolver supplies fixed project scope when session policy has no runtime scope', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const signingRootShareResolver = createSelfHostedSigningRootShareResolver({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
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
  const bootstrapped = await roleLocalBootstrapWithClientShare({
    service,
    clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(0x07)).toString('base64url'),
    sessionId: 'ecdsa-self-host-session-1',
    walletSigningSessionId: 'wallet-signing-self-host-1',
  });

  expect(bootstrapped.ok).toBe(true);
  if (!bootstrapped.ok) throw new Error(bootstrapped.message);
  expect(bootstrapped.value.ecdsaThresholdKeyId).toBeTruthy();
  expect(bootstrapped.value.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
  expect(bootstrapped.value.sessionId).toBe('ecdsa-self-host-session-1');
  expect(bootstrapped.value.signingRootId).toBe(SIGNING_ROOT_ID);
  expect(bootstrapped.value.signingRootVersion).toBe(SIGNING_ROOT_VERSION);
});

test('ECDSA signing-root wallet verification derives the known address from imported root-versioned shares', async () => {
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = async (
    input: SigningRootSecretShareKekResolutionInput,
  ): Promise<Uint8Array> => {
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
  const clientRootShare32 = new Uint8Array(32).fill(0x07);
  const clientPublicKey33B64u = Buffer.from(
    await secp256k1PrivateKey32ToPublicKey33(clientRootShare32),
  ).toString('base64url');

  const first = await service.verifyEcdsaSigningRootWalletAddress({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    walletId: ECDSA_CONTEXT.walletId,
    chainTarget: ECDSA_CONTEXT.chainTarget,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    rpId: 'example.localhost',
    clientPublicKey33B64u,
  });
  expect(first.ok).toBe(true);
  if (!first.ok) throw new Error(first.message);
  expect(first.verified).toBe(true);
  expect(first.canonicalEthereumAddress).toMatch(/^0x[0-9a-f]{40}$/);

  const second = await service.verifyEcdsaSigningRootWalletAddress({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    walletId: ECDSA_CONTEXT.walletId,
    chainTarget: ECDSA_CONTEXT.chainTarget,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    rpId: 'example.localhost',
    clientPublicKey33B64u,
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
    walletId: ECDSA_CONTEXT.walletId,
    chainTarget: ECDSA_CONTEXT.chainTarget,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    rpId: 'example.localhost',
    clientPublicKey33B64u,
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
