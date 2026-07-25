import { ed25519 } from '@noble/curves/ed25519.js';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { normalizeLogger, type Logger } from '@server/core/logger';
import {
  createHostedSigningRootShareResolver,
  type SealedSigningRootShare,
  type SigningRootShareResolver,
} from '@server/core/ThresholdService/signingRootShareResolver';
import { createThresholdEcdsaSigningStores } from '@server/core/ThresholdService/stores/EcdsaSigningStore';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  createWalletSigningBudgetSessionStore,
  type Ed25519WalletSessionStore,
} from '@server/core/ThresholdService/stores/WalletSessionStore';
import { parseThresholdEd25519KeyRecord } from '@server/core/ThresholdService/validation';
import type { RouterAbSigningRuntimeBundle } from '@server/core/routerAbSigning/createRouterAbSigningRuntimes';
import {
  parseRouterAbEcdsaPresignRuntimeConfig,
  RouterAbEcdsaPresignRuntime,
} from '@server/core/routerAbSigning/RouterAbEcdsaPresignRuntime';
import { RouterAbLocalSigningSeedRuntime } from '@server/core/routerAbSigning/RouterAbLocalSigningSeedRuntime';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  requireRouterAbConfiguredSigningWorkerPrivateTransport,
  RouterAbNormalSigningRuntime,
} from '@server/core/routerAbSigning/RouterAbNormalSigningRuntime';
import type {
  RouterAbEcdsaStrictRegistrationPort,
  RouterAbEcdsaStrictRegistrationTopology,
} from '@server/router/routerAbEcdsaStrictRegistration';
import type { ThresholdEd25519AuthorityScope, ThresholdStoreConfigInput } from '@server/core/types';
import { readFileSync } from 'node:fs';

let fixtureSigningRootShareWires: Map<number, Uint8Array> | null = null;
const ED25519_SCALAR_ORDER =
  7_237_005_577_332_262_213_973_186_563_042_994_240_857_116_359_379_907_606_001_950_938_285_454_250_989n;
const FIXTURE_THRESHOLD_PRF_POLICY = {
  protocol: 'threshold-prf',
  threshold: 2,
  shareCount: 3,
} as const;

const FIXTURE_ECDSA_STRICT_REGISTRATION_TOPOLOGY: RouterAbEcdsaStrictRegistrationTopology = {
  routerId: 'router-unit-fixture',
  signerSet: {
    signer_set_id: 'signer-set-unit-fixture',
    policy: 'all_2',
    signer_a: {
      role: 'signer_a',
      signer_id: 'deriver-a-unit-fixture',
      key_epoch: 'epoch-unit-fixture',
    },
    signer_b: {
      role: 'signer_b',
      signer_id: 'deriver-b-unit-fixture',
      key_epoch: 'epoch-unit-fixture',
    },
    selected_server: {
      server_id: 'signing-worker-unit-fixture',
      key_epoch: 'epoch-unit-fixture',
      recipient_encryption_key:
        'x25519:1111111111111111111111111111111111111111111111111111111111111111',
    },
  },
  deriverRecipientKeys: {
    deriver_a: {
      role: 'signer_a',
      key_epoch: 'epoch-unit-fixture',
      public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
    },
    deriver_b: {
      role: 'signer_b',
      key_epoch: 'epoch-unit-fixture',
      public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
    },
  },
};

export class FixtureRouterAbEcdsaStrictRegistrationPort implements RouterAbEcdsaStrictRegistrationPort {
  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return FIXTURE_ECDSA_STRICT_REGISTRATION_TOPOLOGY;
  }

  async register(): Promise<never> {
    throw new Error('Strict ECDSA registration is outside this fixture');
  }

  async activate(): Promise<never> {
    throw new Error('Strict ECDSA activation is outside this fixture');
  }
}

function littleEndianBytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

export function silentLogger(): Logger {
  return { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
}

export function deriveThresholdEd25519VerifyingShareForUnitTests(input: {
  readonly signingShareB64u: string;
}): string {
  const signingShare = base64UrlDecode(input.signingShareB64u);
  if (signingShare.length !== 32) {
    throw new Error('Threshold Ed25519 signing share must be 32 bytes');
  }
  const scalar = littleEndianBytesToBigInt(signingShare) % ED25519_SCALAR_ORDER;
  if (scalar === 0n) throw new Error('Threshold Ed25519 signing share must be non-zero');
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
  const vector = corpus.vectors?.find(
    (entry) => entry.purpose === 'router-ab-ecdsa-derivation/y-server/v1',
  );
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
    if (wireHex) shares.set(share.id, new Uint8Array(Buffer.from(wireHex, 'hex')));
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
          .sort((left, right) => left - right)
          .map(
            (shareId): SealedSigningRootShare => ({
              signingRootId: input.signingRootId,
              signingRootVersion: input.signingRootVersion,
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

export function createRouterAbSigningRuntimesForUnitTests(input: {
  readonly config?: ThresholdStoreConfigInput | null;
  readonly logger?: Logger | null;
  readonly keyRecord?: {
    readonly walletId?: string;
    readonly nearAccountId?: string;
    readonly nearEd25519SigningKeyId?: string;
    readonly authorityScope?: ThresholdEd25519AuthorityScope;
    readonly rpId?: string;
    readonly publicKey: string;
    readonly relayerSigningShareB64u: string;
    readonly relayerVerifyingShareB64u?: string;
    readonly keyVersion?: string;
    readonly recoveryExportCapable?: boolean;
  } | null;
  readonly walletSessionStore?: Ed25519WalletSessionStore | null;
}): {
  readonly runtimes: RouterAbSigningRuntimeBundle;
  readonly normalSigning: RouterAbNormalSigningRuntime;
  readonly localSigningSeed: RouterAbLocalSigningSeedRuntime;
  readonly ecdsaPresign: RouterAbEcdsaPresignRuntime;
  readonly routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
  readonly routerAbLocalSigningSeedRuntime: RouterAbLocalSigningSeedRuntime;
  readonly walletSessionStore: Ed25519WalletSessionStore;
  readonly ecdsaWalletSessionStore: ReturnType<typeof createEcdsaWalletSessionStore>;
  readonly walletBudgetSessionStore: ReturnType<typeof createWalletSigningBudgetSessionStore>;
} {
  const logger = normalizeLogger(input.logger || silentLogger());
  const ecdsaWalletSessionStore = createEcdsaWalletSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const walletSessionStore =
    input.walletSessionStore ||
    createEd25519WalletSessionStore({ config: { kind: 'in-memory' }, logger, isNode: true });
  const walletBudgetSessionStore = createWalletSigningBudgetSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const ecdsaSigningStores = createThresholdEcdsaSigningStores({
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
          keyVersion: keyRecord.keyVersion,
          recoveryExportCapable: keyRecord.recoveryExportCapable,
        }
      : null,
  );
  const config = {
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    ROUTER_AB_SIGNING_WORKER_URL: 'https://signing-worker.example.test',
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'test-router-ab-internal-service-auth',
    ...input.config,
  };
  const normalSigning = new RouterAbNormalSigningRuntime({
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
  const localSigningSeed = new RouterAbLocalSigningSeedRuntime({
    ed25519KeyStore,
    ed25519WalletSessionStore: walletSessionStore,
    ecdsaWalletSessionStore,
    normalSigningRuntime: normalSigning,
  });
  const normalSigningConfig = parseRouterAbNormalSigningRuntimeConfig(config);
  const ecdsaPresign = new RouterAbEcdsaPresignRuntime({
    logger,
    config: parseRouterAbEcdsaPresignRuntimeConfig(config),
    ecdsaPoolFillSessionStore: ecdsaSigningStores.poolFillSessionStore,
    signingWorkerTransport: requireRouterAbConfiguredSigningWorkerPrivateTransport(
      normalSigningConfig.signingWorkerTransport,
    ),
    ensureReady: async () => {},
  });

  return {
    runtimes: {
      normalSigning,
      localSigningSeed,
      ecdsaPresign,
    },
    normalSigning,
    localSigningSeed,
    ecdsaPresign,
    routerAbNormalSigningRuntime: normalSigning,
    routerAbLocalSigningSeedRuntime: localSigningSeed,
    walletSessionStore,
    ecdsaWalletSessionStore,
    walletBudgetSessionStore,
  };
}
