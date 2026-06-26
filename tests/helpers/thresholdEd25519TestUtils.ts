import { ThresholdSigningService } from '@server/core/ThresholdService/ThresholdSigningService';
import { createThresholdEd25519SessionStore } from '@server/core/ThresholdService/stores/SessionStore';
import { createThresholdEcdsaSessionStore } from '@server/core/ThresholdService/stores/SessionStore';
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
import type { ThresholdStoreConfigInput } from '@server/core/types';
import type { WebAuthnAuthenticationCredential } from '@server/core/types';
import { normalizeLogger, type Logger } from '@server/core/logger';
import { readFileSync } from 'node:fs';
import {
  initSync as initWasmSignerSync,
  threshold_ed25519_hss_verifying_share_from_signing_share,
} from '../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  createHostedSigningRootShareResolver,
  type SealedSigningRootShare,
  type SigningRootShareResolver,
} from '@server/core/ThresholdService/signingRootShareResolver';

let signerWasmInitializedForTests = false;
let fixtureSigningRootShareWires: Map<number, Uint8Array> | null = null;

const FIXTURE_THRESHOLD_PRF_POLICY = {
  protocol: 'threshold-prf',
  threshold: 2,
  shareCount: 3,
} as const;

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
  ensureSignerWasmForUnitTests();
  const result = threshold_ed25519_hss_verifying_share_from_signing_share({
    signingShareB64u: input.signingShareB64u,
  }) as { verifyingShareB64u?: string };
  const verifyingShareB64u = String(result?.verifyingShareB64u || '').trim();
  if (!verifyingShareB64u) {
    throw new Error('Failed to derive threshold-ed25519 verifying share for unit tests');
  }
  return verifyingShareB64u;
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
    rpId?: string;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u?: string;
    keyVersion?: string;
    recoveryExportCapable?: boolean;
  } | null;
  accessKeysOnChain?: Array<string | { publicKey: string; nonce: number | string }> | null;
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
  sessionStore: ReturnType<typeof createThresholdEd25519SessionStore>;
  walletSessionStore: Ed25519WalletSessionStore;
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
          walletId: keyRecord.walletId || keyRecord.nearAccountId || 'alice.testnet',
          nearAccountId: keyRecord.nearAccountId || 'alice.testnet',
          nearEd25519SigningKeyId:
            keyRecord.nearEd25519SigningKeyId || keyRecord.nearAccountId || 'alice.testnet',
          rpId: keyRecord.rpId || 'wallet.example.test',
          publicKey: keyRecord.publicKey,
          relayerSigningShareB64u: keyRecord.relayerSigningShareB64u,
          relayerVerifyingShareB64u:
            keyRecord.relayerVerifyingShareB64u ||
            deriveThresholdEd25519VerifyingShareForUnitTests({
              signingShareB64u: keyRecord.relayerSigningShareB64u,
            }),
          ...(keyRecord.keyVersion ? { keyVersion: keyRecord.keyVersion } : {}),
          ...(typeof keyRecord.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keyRecord.recoveryExportCapable }
            : {}),
        }
      : null,
  );
  const accessKeysOnChain = input.accessKeysOnChain ?? null;
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

  const svc = new ThresholdSigningService({
    logger,
    keyStore: {
      get: async () => parsedKeyRecord,
      put: async () => {},
      del: async () => {},
    },
    sessionStore,
    walletSessionStore,
    walletBudgetSessionStore,
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
    viewAccessKeyList: async () =>
      ({
        keys: (accessKeysOnChain || []).map((entry) => ({
          public_key: typeof entry === 'string' ? entry : entry.publicKey,
          access_key: {
            nonce: typeof entry === 'string' ? 0 : entry.nonce,
            permission: 'FullAccess' as const,
          },
        })),
      }) as any,
    dispatchNearTransaction:
      input.dispatchNearTransaction ||
      (async () => {
        throw new Error('dispatchNearTransaction was not provided for this unit test');
      }),
  });

  return { svc, sessionStore, walletSessionStore, walletBudgetSessionStore };
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
