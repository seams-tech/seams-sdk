import { ThresholdSigningService } from '@server/core/ThresholdService/ThresholdSigningService';
import { createThresholdEd25519SessionStore } from '@server/core/ThresholdService/stores/SessionStore';
import { createThresholdEcdsaSessionStore } from '@server/core/ThresholdService/stores/SessionStore';
import { createEcdsaAuthSessionStore } from '@server/core/ThresholdService/stores/AuthSessionStore';
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
import type {
  SigningRootSecretShareId,
  SealedSigningRootSecretShare,
} from '@server/core/ThresholdService/signingRootSecretShareWires';
import type { SigningRootSecretResolver } from '@server/core/ThresholdService/signingRootSecretResolverAdapters';
import {
  createHostedSigningRootShareResolver,
  type SigningRootShareResolver,
} from '@server/core/ThresholdService/signingRootShareResolver';

let signerWasmInitializedForTests = false;
let fixtureSigningRootSecretShares: Map<SigningRootSecretShareId, Uint8Array> | null = null;

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

function loadFixtureSigningRootSecretSharesForUnitTests(): Map<SigningRootSecretShareId, Uint8Array> {
  if (fixtureSigningRootSecretShares) return fixtureSigningRootSecretShares;
  const corpus = JSON.parse(
    readFileSync(
      new URL('../../crates/threshold-prf/fixtures/protocol-v1.json', import.meta.url),
      'utf8',
    ),
  ) as {
    vectors?: Array<{
      purpose?: string;
      shares?: Array<{ id?: SigningRootSecretShareId; wire_hex?: string }>;
    }>;
  };
  const vector = corpus.vectors?.find((entry) => entry.purpose === 'ecdsa-hss/y_relayer');
  const shares = new Map<SigningRootSecretShareId, Uint8Array>();
  for (const share of vector?.shares || []) {
    if (share.id !== 1 && share.id !== 2 && share.id !== 3) continue;
    const wireHex = String(share.wire_hex || '').trim();
    if (!wireHex) continue;
    shares.set(share.id, new Uint8Array(Buffer.from(wireHex, 'hex')));
  }
  if (shares.size < 2) throw new Error('Missing threshold-prf signing-root fixture shares');
  fixtureSigningRootSecretShares = shares;
  return shares;
}

export function createFixtureSigningRootSecretResolverForUnitTests(): SigningRootSecretResolver {
  const shares = loadFixtureSigningRootSecretSharesForUnitTests();
  return {
    listSealedSigningRootSecretShares: async (input) =>
      Array.from(shares.keys())
        .sort((a, b) => a - b)
        .map(
          (shareId): SealedSigningRootSecretShare => ({
            signingRootId: input.signingRootId,
            ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
            shareId,
            sealedShare: new Uint8Array([shareId]),
            storageId: `fixture-${shareId}`,
            kekId: 'fixture-kek',
          }),
        ),
    decryptSigningRootSecretShare: async (record) => {
      const wire = shares.get(record.shareId);
      if (!wire) throw new Error(`missing fixture signing-root share ${record.shareId}`);
      return new Uint8Array(wire);
    },
  };
}

export function createFixtureSigningRootShareResolverForUnitTests(): SigningRootShareResolver {
  const provider = createFixtureSigningRootSecretResolverForUnitTests();
  return createHostedSigningRootShareResolver({
    storageAdapter: {
      listSealedSigningRootSecretShares: (request) => provider.listSealedSigningRootSecretShares(request),
    },
    decryptAdapter: {
      decryptSigningRootSecretShare: (record) => provider.decryptSigningRootSecretShare(record),
    },
  });
}

export function createThresholdSigningServiceForUnitTests(input: {
  config?: ThresholdStoreConfigInput | null;
  logger?: Logger | null;
  keyRecord?: {
    nearAccountId?: string;
    rpId?: string;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u?: string;
    keyVersion?: string;
    recoveryExportCapable?: boolean;
  } | null;
  accessKeysOnChain?: string[] | null;
  verifyWebAuthnAuthenticationLite?:
    | ((request: {
        nearAccountId: string;
        rpId: string;
        expectedChallenge: string;
        webauthn_authentication: WebAuthnAuthenticationCredential;
      }) => Promise<{ success: boolean; verified: boolean; code?: string; message?: string }>)
    | null;
}): {
  svc: ThresholdSigningService;
  sessionStore: ReturnType<typeof createThresholdEd25519SessionStore>;
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
  const ecdsaAuthSessionStore = createEcdsaAuthSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
  const {
    signingSessionStore: ecdsaSigningSessionStore,
    presignSessionStore: ecdsaPresignSessionStore,
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
          nearAccountId: keyRecord.nearAccountId || 'alice.testnet',
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
  const fixtureSigningRootSecretResolver = createFixtureSigningRootSecretResolverForUnitTests();
  const config = {
    ...(input.config || {}),
    ...(input.config?.signingRootShareResolver ||
    input.config?.signingRootSecretResolverAdapters ||
    input.config?.signingRootSecretStore ||
    input.config?.signingRootSecretDecryptAdapter ||
    input.config?.signingRootSecretShareKekResolver
      ? {}
      : { signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests() }),
  };
  const signingRootShareResolver =
    createConfiguredSigningRootShareResolver(config) ??
    createHostedSigningRootShareResolver({
      storageAdapter: {
        listSealedSigningRootSecretShares: (request) =>
          fixtureSigningRootSecretResolver.listSealedSigningRootSecretShares(request),
      },
      decryptAdapter: {
        decryptSigningRootSecretShare: (record) =>
          fixtureSigningRootSecretResolver.decryptSigningRootSecretShare(record),
      },
    });

  const svc = new ThresholdSigningService({
    logger,
    keyStore: {
      get: async () => parsedKeyRecord,
      put: async () => {},
      del: async () => {},
    },
    sessionStore,
    authSessionStore: {
      putSession: async () => {},
      getSession: async () => null,
      getSessionStatus: async () => null,
      consumeUseCount: async () => ({ ok: false, code: 'unauthorized', message: 'unused' }),
    },
    ecdsaKeyStore,
    ecdsaSessionStore,
    ecdsaAuthSessionStore,
    ecdsaSigningSessionStore,
    ecdsaPresignSessionStore,
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
        keys: (accessKeysOnChain || []).map((publicKey) => ({
          public_key: publicKey,
          access_key: { nonce: 0, permission: 'FullAccess' as const },
        })),
      }) as any,
  });

  return { svc, sessionStore };
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
