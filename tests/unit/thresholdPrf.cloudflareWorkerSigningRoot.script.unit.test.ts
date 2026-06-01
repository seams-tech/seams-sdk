import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64UrlEncode } from '../../shared/src/utils/encoders';
import { SIGNING_ROOT_RECORD_VERSION_V1 } from '../../server/src/core/ThresholdService/signingRootRecords';
import {
  createSigningRootSecretResolver,
  deriveEcdsaHssYRelayerFromSigningRootSecretResolver,
} from '../../server/src/core/ThresholdService/signingRootSecretResolverAdapters';
import {
  createSigningRootSecretAesGcmDecryptAdapter,
  sealSigningRootSecretShareWireV1,
  type SigningRootSecretShareKekResolutionInput,
} from '../../server/src/core/ThresholdService/signingRootSecretSealing';
import { CloudflareDurableObjectSigningRootSecretStore } from '../../server/src/core/ThresholdService/stores/SigningRootSecretStore';
import { roleLocalThresholdEcdsaHssRelayerBootstrap } from '../../server/src/core/ThresholdService/ethSignerWasm';
import {
  build_ecdsa_role_local_export_artifact_v1,
  threshold_ecdsa_hss_role_local_finalize_client_bootstrap,
  initSync as initHssClientSignerWasmSync,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../server/src/core/types';
import type {
  SigningRootSecretShareId,
  SigningRootSecretShareWireV1,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import { ThresholdStoreDurableObject } from '../../server/src/router/cloudflare/durableObjects/thresholdStore';

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

type DurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
};
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

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
const ROLE_LOCAL_KEY_PURPOSE = 'evm-signing';
const ROLE_LOCAL_KEY_VERSION = 'v1';
let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
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
  const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId: context.walletId,
      rpId: context.rpId,
      chainTarget: ECDSA_CONTEXT.chainTarget,
      ecdsaThresholdKeyId: context.ecdsaThresholdKeyId,
      signingRootId: context.signingRootId,
      signingRootVersion: context.signingRootVersion,
    },
    clientRootShare32B64u: bytesB64u(input.yClient32Le),
  });
  const relayerKeyId = 'ehss-relayer-signing-root-test';
  const relayerBootstrap = await roleLocalThresholdEcdsaHssRelayerBootstrap({
    ...context,
    relayerKeyId,
    yRelayer32Le: input.yRelayer32Le,
    clientPublicKey33: Buffer.from(clientBootstrap.hssClientSharePublicKey33B64u, 'base64url'),
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
  });
  const readyBootstrap = threshold_ecdsa_hss_role_local_finalize_client_bootstrap({
    pendingStateBlobB64u: clientBootstrap.pendingStateBlobB64u,
    relayerKeyId,
    relayerPublicKey33B64u: bytesB64u(relayerBootstrap.relayerPublicKey33),
    groupPublicKey33B64u: bytesB64u(relayerBootstrap.groupPublicKey33),
    ethereumAddress: `0x${bytesToHex(relayerBootstrap.ethereumAddress20)}`,
  }) as { stateBlobB64u: string };
  const exportArtifact = JSON.parse(
    build_ecdsa_role_local_export_artifact_v1(
      JSON.stringify({
        kind: 'build_ecdsa_role_local_export_artifact_v1',
        algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
        stateBlob: {
          kind: 'ecdsa_role_local_state_blob_v1',
          curve: 'secp256k1',
          encoding: 'base64url',
          producer: 'signer_core',
          stateBlobB64u: readyBootstrap.stateBlobB64u,
        },
        publicFacts: {
          walletId: ECDSA_CONTEXT.walletId,
          rpId: ECDSA_CONTEXT.rpId,
          chainTarget: ECDSA_CONTEXT.chainTarget,
          keyHandle: 'cloudflare-signing-root-test-key',
          ecdsaThresholdKeyId: ECDSA_CONTEXT.ecdsaThresholdKeyId,
          signingRootId: ECDSA_CONTEXT.signingRootId,
          signingRootVersion: ECDSA_CONTEXT.signingRootVersion,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
          contextBinding32B64u: clientBootstrap.contextBinding32B64u,
          hssClientSharePublicKey33B64u: clientBootstrap.hssClientSharePublicKey33B64u,
          relayerPublicKey33B64u: bytesB64u(relayerBootstrap.relayerPublicKey33),
          groupPublicKey33B64u: bytesB64u(relayerBootstrap.groupPublicKey33),
          ethereumAddress: `0x${bytesToHex(relayerBootstrap.ethereumAddress20)}`,
        },
        authorization: {
          kind: 'passkey_export_authorized',
          walletId: ECDSA_CONTEXT.walletId,
          rpId: ECDSA_CONTEXT.rpId,
          credentialIdB64u: bytesB64u(new Uint8Array([1])),
        },
        serverExportShare32B64u: bytesB64u(relayerBootstrap.relayerShare32),
      }),
    ),
  ) as { publicKeyHex: string; ethereumAddress: string };

  return {
    groupPublicKey33: relayerBootstrap.groupPublicKey33,
    ethereumAddress20: relayerBootstrap.ethereumAddress20,
    exportedPublicKey33: hexToBytesPrefixed(exportArtifact.publicKeyHex),
    exportedEthereumAddress20: hexToBytesPrefixed(exportArtifact.ethereumAddress),
  };
}

function createMemoryDurableObjectNamespace(input?: {
  readonly onFetch?: (body: unknown) => void;
}): CloudflareDurableObjectNamespaceLike {
  const objects = new Map<string, CloudflareDurableObjectStubLike>();
  return {
    idFromName: (name: string) => name,
    get: (id: unknown) => {
      const key = String(id);
      const existing = objects.get(key);
      if (existing) return existing;

      const storageMap = new Map<string, unknown>();
      const storage: DurableObjectStorageLike = {
        get: async (storageKey) => storageMap.get(storageKey) ?? null,
        put: async (storageKey, value) => {
          storageMap.set(storageKey, value);
        },
        delete: async (storageKey) => storageMap.delete(storageKey),
      };
      const durableObject = new ThresholdStoreDurableObject({ storage }, {});
      const stub: CloudflareDurableObjectStubLike = {
        fetch: async (request, init) => {
          const materializedRequest =
            request instanceof Request ? request : new Request(request, init);
          if (input?.onFetch) {
            let body: unknown = null;
            try {
              body = await materializedRequest.clone().json();
            } catch {
              body = null;
            }
            input.onFetch(body);
          }
          return durableObject.fetch(materializedRequest);
        },
      };
      objects.set(key, stub);
      return stub;
    },
  };
}

async function postDo<T>(
  stub: CloudflareDurableObjectStubLike,
  body: Record<string, unknown>,
): Promise<DoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  expect(response.ok).toBe(true);
  return (await response.json()) as DoResp<T>;
}

test('Cloudflare Durable Object signing-root store feeds sealed-share decrypt, threshold-prf combine, and ECDSA HSS handoff', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const namespace = createMemoryDurableObjectNamespace();
  const store = new CloudflareDurableObjectSigningRootSecretStore({
    namespace,
    objectName: 'signing-root-share-test',
  });
  const resolverCalls: SigningRootSecretShareKekResolutionInput[] = [];
  const resolveKek = (input: SigningRootSecretShareKekResolutionInput): Uint8Array => {
    resolverCalls.push(input);
    return new Uint8Array(KEK_BYTES);
  };

  for (const share of vector.shares.slice(0, 2)) {
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: hexToBytes(share.wire_hex) as SigningRootSecretShareWireV1,
      resolveKek,
    });
    await store.putSealedSigningRootSecretShare({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      sealedShare,
      kekId: KEK_ID,
    });
  }

  const listed = await store.listSealedSigningRootSecretShares({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(listed.map((record) => record.shareId)).toEqual([1, 2]);
  expect(listed.every((record) => record.sealedShare.length > 33)).toBe(true);

  const resolver = createSigningRootSecretResolver({
    store,
    decryptAdapter: createSigningRootSecretAesGcmDecryptAdapter({ resolveKek }),
  });
  const yRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretResolver({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    preferredShareIds: [1, 2],
    resolver,
    context: ECDSA_CONTEXT,
  });
  expect(yRelayer.ok).toBe(true);
  if (!yRelayer.ok) throw new Error(yRelayer.message);

  const yClient32Le = new Uint8Array(32).fill(0x07);
  const wallet = await roleLocalWalletFromShares({
    yClient32Le,
    yRelayer32Le: yRelayer.value,
  });

  expect(bytesToHex(wallet.groupPublicKey33)).toBe(bytesToHex(wallet.exportedPublicKey33));
  expect(bytesToHex(wallet.ethereumAddress20)).toBe(bytesToHex(wallet.exportedEthereumAddress20));
  expect(resolverCalls.map((call) => call.shareId)).toEqual([1, 2, 1, 2]);

  yRelayer.value.fill(0);
  yClient32Le.fill(0);
});

test('Cloudflare Durable Object signing-root protocol stores record status and materializes sealed shares', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');
  const namespace = createMemoryDurableObjectNamespace();
  const objectName = 'signing-root-protocol-test';
  const stub = namespace.get(namespace.idFromName(objectName));
  const sealedSigningRootSecretShares = [];
  const resolveKek = (): Uint8Array => new Uint8Array(KEK_BYTES);

  for (const share of vector.shares.slice(0, 3)) {
    const sealedShare = await sealSigningRootSecretShareWireV1({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      kekId: KEK_ID,
      plaintextShareWire: hexToBytes(share.wire_hex) as SigningRootSecretShareWireV1,
      resolveKek,
    });
    sealedSigningRootSecretShares.push({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      shareId: share.id,
      sealedShareB64u: base64UrlEncode(sealedShare),
      storageId: `storage-${share.id}`,
      kekId: KEK_ID,
    });
  }

  const record = {
    version: SIGNING_ROOT_RECORD_VERSION_V1,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    signingRootId: SIGNING_ROOT_ID,
    walletOrigin: 'https://wallet.example.test',
    rpId: 'wallet.example.test',
    signingRootVersion: SIGNING_ROOT_VERSION,
    rootShareEpoch: 1,
    shareThreshold: 2,
    shareCount: 3,
    sealedSigningRootSecretShares,
    derivationVersion: 1,
    createdAtMs: 10,
    updatedAtMs: 20,
    source: 'customer-import',
  };

  const put = await postDo<{
    shareIds: number[];
    contextHashB64u: string;
  }>(stub, { op: 'signingRootPut', record });
  expect(put.ok).toBe(true);
  if (!put.ok) throw new Error(put.message);
  expect(put.value.shareIds).toEqual([1, 2, 3]);
  expect(put.value.contextHashB64u.length).toBeGreaterThan(20);

  const status = await postDo<Record<string, unknown>>(stub, {
    op: 'signingRootStatus',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(status.ok).toBe(true);
  if (!status.ok) throw new Error(status.message);
  expect(status.value).not.toHaveProperty('sealedSigningRootSecretShares');
  expect(status.value.shareIds).toEqual([1, 2, 3]);

  const get = await postDo<{ sealedSigningRootSecretShares: Array<{ sealedShareB64u: string }> }>(
    stub,
    {
      op: 'signingRootGet',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    },
  );
  expect(get.ok).toBe(true);
  if (!get.ok) throw new Error(get.message);
  expect(get.value.sealedSigningRootSecretShares[0].sealedShareB64u).toBe(
    sealedSigningRootSecretShares[0].sealedShareB64u,
  );

  const store = new CloudflareDurableObjectSigningRootSecretStore({ namespace, objectName });
  const listed = await store.listSealedSigningRootSecretShares({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(listed.map((share) => share.shareId)).toEqual([1, 2, 3]);

  const deleted = await postDo<{ deleted: boolean }>(stub, {
    op: 'signingRootDelete',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(deleted).toEqual({ ok: true, value: { deleted: true } });

  const statusAfterDelete = await postDo<unknown>(stub, {
    op: 'signingRootStatus',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  expect(statusAfterDelete).toEqual({ ok: true, value: null });
  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toEqual([]);
});

test('Cloudflare Durable Object signing-root store optionally caches sealed share listings', async () => {
  const fetchBodies: unknown[] = [];
  const namespace = createMemoryDurableObjectNamespace({
    onFetch: (body) => fetchBodies.push(body),
  });
  const store = new CloudflareDurableObjectSigningRootSecretStore({
    namespace,
    objectName: 'signing-root-cache-test',
    cacheTtlMs: 60_000,
  });

  await store.putSealedSigningRootSecretShare({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    shareId: 1,
    sealedShare: new Uint8Array([1, 2, 3]),
    kekId: KEK_ID,
  });
  fetchBodies.length = 0;

  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toHaveLength(1);
  const firstReadFetchCount = fetchBodies.length;
  expect(firstReadFetchCount).toBeGreaterThan(0);

  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toHaveLength(1);
  expect(fetchBodies).toHaveLength(firstReadFetchCount);

  await store.deleteSigningRootSecretShares({
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  await expect(
    store.listSealedSigningRootSecretShares({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
    }),
  ).resolves.toEqual([]);
  expect(fetchBodies.length).toBeGreaterThan(firstReadFetchCount);
});
