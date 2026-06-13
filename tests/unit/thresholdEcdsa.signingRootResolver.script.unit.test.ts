import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthService } from '../../packages/sdk-server-ts/src/core/AuthService';
import { createThresholdSigningService } from '../../packages/sdk-server-ts/src/core/ThresholdService';
import {
  createSelfHostedSigningRootShareResolver,
  type SealedSigningRootShare,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver';
import { secp256k1PrivateKey32ToPublicKey33 } from '../../packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm';
import {
  initSync as initHssClientSignerWasmSync,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';
import type { EcdsaHssClientSharePublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { ThresholdStoreConfigInput } from '../../packages/sdk-server-ts/src/core/types';

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

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(
  __dirname,
  '../../crates/threshold-prf/fixtures/protocol-t-of-n.json',
);
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const PROJECT_ID = 'project-alpha';
const ENV_ID = 'dev';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const SIGNING_ROOT_VERSION = 'root-v1';
const KEK_ID = 'kek-v1';
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
let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function loadFixtureCorpus(): ThresholdPrfFixtureCorpus {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ThresholdPrfFixtureCorpus;
}

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const vector = loadFixtureCorpus().vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function policyFromFixture(vector: ThresholdPrfFixtureVector) {
  return {
    protocol: 'threshold-prf',
    threshold: vector.policy.threshold,
    shareCount: vector.policy.share_count,
  } as const;
}

function hostedResolverConfigFromFixture(input: {
  readonly vector: ThresholdPrfFixtureVector;
  readonly decryptCalls: number[];
}) {
  const sharesById = new Map<number, ThresholdPrfFixtureShare>(
    input.vector.shares.map((share) => [share.id, share]),
  );
  return {
    policy: policyFromFixture(input.vector),
    storageAdapter: {
      listSealedSigningRootShares: async (request: {
        signingRootId: string;
        signingRootVersion?: string;
      }): Promise<readonly SealedSigningRootShare[]> =>
        input.vector.shares.map((share) => ({
          signingRootId: request.signingRootId,
          ...(request.signingRootVersion ? { signingRootVersion: request.signingRootVersion } : {}),
          shareId: share.id,
          sealedShare: new Uint8Array([share.id]),
          storageId: `fixture-share-${share.id}`,
          kekId: KEK_ID,
        })),
    },
    decryptAdapter: {
      decryptSigningRootShare: async (record: SealedSigningRootShare): Promise<Uint8Array> => {
        input.decryptCalls.push(record.shareId);
        const share = sharesById.get(record.shareId);
        if (!share) throw new Error(`missing share ${record.shareId}`);
        return hexToBytes(share.wire_hex);
      },
    },
  };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function toHssClientSharePublicKey33B64uForTest(value: string): EcdsaHssClientSharePublicKey33B64u {
  return value as EcdsaHssClientSharePublicKey33B64u;
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
  const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId: ECDSA_CONTEXT.walletId,
      rpId: ECDSA_CONTEXT.rpId,
      chainTarget: ECDSA_CONTEXT.chainTarget,
      ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
    },
    clientRootShare32B64u: args.clientRootShare32B64u,
  });

  return await args.service.ecdsaHssRoleLocalBootstrap({
    formatVersion: 'ecdsa-hss-role-local',
    walletId: ECDSA_CONTEXT.walletId,
    rpId: ECDSA_CONTEXT.rpId,
    ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId: 'ehss-relayer-signing-root-test',
    hssClientSharePublicKey33B64u: toHssClientSharePublicKey33B64uForTest(
      clientBootstrap.hssClientSharePublicKey33B64u,
    ),
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

test('ECDSA role-local bootstrap uses signing-root resolver when configured and preserves response shape', async () => {
  const decryptCalls: number[] = [];
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const thresholdConfig: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    signingRootShareResolverAdapters: hostedResolverConfigFromFixture({
      vector,
      decryptCalls,
    }),
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
  expect(decryptCalls).toEqual([1, 2]);
});

test('ECDSA self-host signing-root resolver supplies fixed project scope when session policy has no runtime scope', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const signingRootShareResolver = createSelfHostedSigningRootShareResolver({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    policy: policyFromFixture(vector),
    shares: vector.shares.slice(0, vector.policy.threshold).map((share) => ({
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
  const decryptCalls: number[] = [];
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');

  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: {
      kind: 'in-memory',
      signingRootShareResolverAdapters: hostedResolverConfigFromFixture({
        vector,
        decryptCalls,
      }),
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
  expect(decryptCalls).toEqual([1, 2, 1, 2, 1, 2]);
});
