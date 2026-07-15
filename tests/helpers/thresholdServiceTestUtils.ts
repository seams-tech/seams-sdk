import { ThresholdSigningService } from '@server/core/ThresholdService/ThresholdSigningService';
import {
  createThresholdEcdsaSessionStore,
  createThresholdEd25519SessionStore,
} from '@server/core/ThresholdService/stores/SessionStore';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  createWalletSigningBudgetSessionStore,
  type Ed25519WalletSessionStore,
} from '@server/core/ThresholdService/stores/WalletSessionStore';
import { createThresholdEcdsaKeyStore } from '@server/core/ThresholdService/stores/KeyStore';
import { createThresholdEcdsaSigningStores } from '@server/core/ThresholdService/stores/EcdsaSigningStore';
import { parseThresholdEd25519KeyRecord } from '@server/core/ThresholdService/validation';
import { createConfiguredSigningRootShareResolver } from '@server/core/ThresholdService/signingRootSecretConfig';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  RouterAbNormalSigningRuntime,
} from '@server/core/routerAbSigning/RouterAbNormalSigningRuntime';
import { RouterAbLocalSigningSeedRuntime } from '@server/core/routerAbSigning/RouterAbLocalSigningSeedRuntime';
import { RouterAbEcdsaBootstrapExportRuntime } from '@server/core/routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import type {
  ThresholdEd25519AuthorityScope,
  ThresholdStoreConfigInput,
  WebAuthnAuthenticationCredential,
} from '@server/core/types';
import { normalizeLogger, type Logger } from '@server/core/logger';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { initSync as initWasmSignerSync } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  createHostedSigningRootShareResolver,
  type SealedSigningRootShare,
  type SigningRootShareResolver,
} from '@server/core/ThresholdService/signingRootShareResolver';

let signerWasmInitializedForTests = false;
let fixtureSigningRootShareWires: Map<number, Uint8Array> | null = null;
const ED25519_SCALAR_ORDER =
  7_237_005_577_332_262_213_973_186_563_042_994_240_857_116_359_379_907_606_001_950_938_285_454_250_989n;

const FIXTURE_THRESHOLD_PRF_POLICY = {
  protocol: 'threshold-prf',
  threshold: 2,
  shareCount: 3,
} as const;

function littleEndianBytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

function ensureSignerWasmForUnitTests(): void {
  if (signerWasmInitializedForTests) return;
  const wasmBytes = readFileSync(
    new URL('../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm', import.meta.url),
  );
  initWasmSignerSync({ module: wasmBytes });
  signerWasmInitializedForTests = true;
}

export function silentLogger() {
  return { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
}

export function deriveThresholdEd25519VerifyingShareForUnitTests(input: {
  signingShareB64u: string;
}): string {
  const signingShare = base64UrlDecode(input.signingShareB64u);
  if (signingShare.length !== 32) {
    throw new Error('Threshold Ed25519 signing share must be 32 bytes');
  }
  const scalar = littleEndianBytesToBigInt(signingShare) % ED25519_SCALAR_ORDER;
  if (scalar === 0n) {
    throw new Error('Threshold Ed25519 signing share must be non-zero');
  }
  return base64UrlEncode(ed25519.Point.BASE.multiply(scalar).toBytes());
}

function loadFixtureSigningRootShareWiresForUnitTests(): Map<number, Uint8Array> {
  if (fixtureSigningRootShareWires) return fixtureSigningRootShareWires;
  const corpus = JSON.parse(
    readFileSync(
      new URL('../../crates/threshold-prf/fixtures/protocol-t-of-n.json', import.meta.url),
      'utf8',
    ),
  ) as {
    vectors?: Array<{
      purpose?: string;
      policy?: { threshold?: number; share_count?: number };
      shares?: Array<{ id?: number; wire_hex?: string }>;
    }>;
  };
  const vector = corpus.vectors?.find((entry) => entry.purpose === 'ecdsa-hss/y_server');
  if (
    vector?.policy?.threshold !== FIXTURE_THRESHOLD_PRF_POLICY.threshold ||
    vector.policy.share_count !== FIXTURE_THRESHOLD_PRF_POLICY.shareCount
  ) {
    throw new Error('Missing threshold-prf 2-of-3 signing-root fixture policy');
  }
  const shares = new Map<number, Uint8Array>();
  for (const share of vector.shares || []) {
    if (typeof share.id !== 'number' || share.id < 1 || share.id > 3) continue;
    const wireHex = String(share.wire_hex || '').trim();
    if (!wireHex) continue;
    shares.set(share.id, new Uint8Array(Buffer.from(wireHex, 'hex')));
  }
  if (shares.size < FIXTURE_THRESHOLD_PRF_POLICY.threshold) {
    throw new Error('Missing threshold-prf signing-root fixture shares');
  }
  fixtureSigningRootShareWires = shares;
  return shares;
}

export function createFixtureSigningRootShareResolverForUnitTests(): SigningRootShareResolver {
  const shares = loadFixtureSigningRootShareWiresForUnitTests();
  return createHostedSigningRootShareResolver({
    policy: FIXTURE_THRESHOLD_PRF_POLICY,
    storageAdapter: {
      listSealedSigningRootShares: async (input) =>
        Array.from(shares.keys())
          .sort((a, b) => a - b)
          .map(
            (shareId): SealedSigningRootShare => ({
              signingRootId: input.signingRootId,
              ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
              shareId,
              sealedShare: new Uint8Array([shareId]),
              storageId: `fixture-share-${shareId}`,
              kekId: 'fixture-share-kek',
            }),
          ),
    },
    decryptAdapter: {
      decryptSigningRootShare: async (record) => {
        const wire = shares.get(record.shareId);
        if (!wire) throw new Error(`missing fixture signing-root share ${record.shareId}`);
        return new Uint8Array(wire);
      },
    },
  });
}

export function createThresholdSigningServiceForUnitTests(input: {
  config?: ThresholdStoreConfigInput | null;
  logger?: Logger | null;
  keyRecord?: {
    walletId?: string;
    nearAccountId?: string;
    nearEd25519SigningKeyId?: string;
    authorityScope?: ThresholdEd25519AuthorityScope;
    rpId?: string;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u?: string;
    keyVersion?: string;
    recoveryExportCapable?: boolean;
  } | null;
  verifyWebAuthnAuthenticationLite?:
    | ((request: {
        userId: string;
        rpId: string;
        expectedChallenge: string;
        expected_origin: string;
        webauthn_authentication: WebAuthnAuthenticationCredential;
      }) => Promise<{ success: boolean; verified: boolean; code?: string; message?: string }>)
    | null;
  walletSessionStore?: Ed25519WalletSessionStore | null;
  dispatchNearTransaction?:
    | ((request: { signedTransactionBorshB64u: string }) => Promise<{ rpcResult: unknown }>)
    | null;
}): {
  svc: ThresholdSigningService;
  routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
  routerAbLocalSigningSeedRuntime: RouterAbLocalSigningSeedRuntime;
  routerAbEcdsaBootstrapExportRuntime: RouterAbEcdsaBootstrapExportRuntime;
  sessionStore: ReturnType<typeof createThresholdEd25519SessionStore>;
  walletSessionStore: Ed25519WalletSessionStore;
  ecdsaWalletSessionStore: ReturnType<typeof createEcdsaWalletSessionStore>;
  walletBudgetSessionStore: ReturnType<typeof createWalletSigningBudgetSessionStore>;
} {
  const logger = normalizeLogger(input.logger || silentLogger());
  const sessionStore = createThresholdEd25519SessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const ecdsaKeyStore = createThresholdEcdsaKeyStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const ecdsaSessionStore = createThresholdEcdsaSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const ecdsaWalletSessionStore = createEcdsaWalletSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const walletSessionStore =
    input.walletSessionStore ||
    createEd25519WalletSessionStore({
      config: { kind: 'in-memory' },
      logger,
      isNode: true,
    });
  const walletBudgetSessionStore = createWalletSigningBudgetSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const {
    poolFillSessionStore: ecdsaPoolFillSessionStore,
    presignaturePool: ecdsaPresignaturePool,
  } = createThresholdEcdsaSigningStores({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });

  const keyRecord = input.keyRecord ?? null;
  const parsedKeyRecord = parseThresholdEd25519KeyRecord(
    keyRecord
      ? {
          kind: 'ready',
          walletId: keyRecord.walletId || keyRecord.nearAccountId || 'alice.testnet',
          nearAccountId: keyRecord.nearAccountId || 'alice.testnet',
          nearEd25519SigningKeyId:
            keyRecord.nearEd25519SigningKeyId || keyRecord.nearAccountId || 'alice.testnet',
          authorityScope: keyRecord.authorityScope || {
            kind: 'passkey_rp',
            rpId: keyRecord.rpId || 'wallet.example.test',
          },
          publicKey: keyRecord.publicKey,
          routerMaterial: {
            signingShareB64u: keyRecord.relayerSigningShareB64u,
            verifyingShareB64u:
              keyRecord.relayerVerifyingShareB64u ||
              deriveThresholdEd25519VerifyingShareForUnitTests({
                signingShareB64u: keyRecord.relayerSigningShareB64u,
              }),
          },
          ...(keyRecord.keyVersion ? { keyVersion: keyRecord.keyVersion } : {}),
          ...(typeof keyRecord.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keyRecord.recoveryExportCapable }
            : {}),
        }
      : null,
  );
  const verifyWebAuthnAuthenticationLite =
    input.verifyWebAuthnAuthenticationLite || (async () => ({ success: true, verified: true }));
  const config = {
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    ...(input.config || {}),
    ...(input.config?.signingRootShareResolver ||
    input.config?.signingRootShareResolverAdapters ||
    input.config?.signingRootSharePolicy ||
    input.config?.signingRootShareStore ||
    input.config?.signingRootShareDecryptAdapter
      ? {}
      : { signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests() }),
  };
  const signingRootShareResolver =
    createConfiguredSigningRootShareResolver(config) ??
    createFixtureSigningRootShareResolverForUnitTests();
  const routerAbNormalSigningRuntime = new RouterAbNormalSigningRuntime({
    walletSessionStore,
    ecdsaWalletSessionStore,
    walletBudgetSessionStore,
    config: parseRouterAbNormalSigningRuntimeConfig(config),
  });
  const ed25519KeyStore = {
    get: async () => parsedKeyRecord,
    put: async () => {},
    del: async () => {},
  };
  const routerAbLocalSigningSeedRuntime = new RouterAbLocalSigningSeedRuntime({
    ed25519KeyStore,
    ed25519WalletSessionStore: walletSessionStore,
    ecdsaWalletSessionStore,
    normalSigningRuntime: routerAbNormalSigningRuntime,
  });
  const routerAbEcdsaBootstrapExportRuntime = new RouterAbEcdsaBootstrapExportRuntime({
    ecdsaKeyStore,
    ecdsaWalletSessionStore,
    signingRootShareResolver,
    routerAbNormalSigningRuntime,
    participantIds: [1, 2],
  });

  const svc = new ThresholdSigningService({
    logger,
    keyStore: ed25519KeyStore,
    sessionStore,
    walletSessionStore,
    routerAbNormalSigningRuntime,
    ecdsaKeyStore,
    ecdsaSessionStore,
    ecdsaWalletSessionStore,
    ecdsaPoolFillSessionStore,
    ecdsaPresignaturePool,
    signingRootShareResolver,
    config,
    ensureReady: async () => {},
    ensureSignerWasm: async () => {
      ensureSignerWasmForUnitTests();
    },
    verifyWebAuthnAuthenticationLite,
    dispatchNearTransaction:
      input.dispatchNearTransaction ||
      (async () => {
        throw new Error('dispatchNearTransaction was not provided for this unit test');
      }),
  });

  return {
    svc,
    routerAbNormalSigningRuntime,
    routerAbLocalSigningSeedRuntime,
    routerAbEcdsaBootstrapExportRuntime,
    sessionStore,
    walletSessionStore,
    ecdsaWalletSessionStore,
    walletBudgetSessionStore,
  };
}

export async function verifyThresholdEd25519CoordinatorGrantHmac(
  token: string,
  secretB64u: string,
): Promise<any> {
  const [payloadB64u, sigB64u] = token.split('.');
  if (!payloadB64u || !sigB64u) throw new Error('Invalid coordinatorGrant format');

  const payloadBytes = Buffer.from(payloadB64u, 'base64url');
  const sigBytes = Buffer.from(sigB64u, 'base64url');
  if (sigBytes.length !== 32) throw new Error('Invalid coordinatorGrant signature length');

  const secretBytes = Buffer.from(secretB64u, 'base64url');
  if (secretBytes.length !== 32) throw new Error('Invalid coordinatorGrant shared secret length');

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const expected = Buffer.from(await crypto.subtle.sign('HMAC', key, payloadBytes));
  if (Buffer.compare(expected, sigBytes) !== 0)
    throw new Error('Invalid coordinatorGrant signature');

  return JSON.parse(payloadBytes.toString('utf8'));
}
