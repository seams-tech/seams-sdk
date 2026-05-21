import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../server/src/core/ThresholdService/schemes/schemeIds';
import {
  initSync as initHssClientSignerWasmSync,
  threshold_ecdsa_hss_role_local_client_bootstrap,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';

const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const TEST_RUNTIME_SCOPE = {
  orgId: 'org-alpha',
  projectId: 'project-alpha',
  envId: 'env-alpha',
  signingRootVersion: 'default',
} as const;
const TEST_SIGNING_ROOT_ID = `${TEST_RUNTIME_SCOPE.projectId}:${TEST_RUNTIME_SCOPE.envId}`;
const KEY_PURPOSE = 'evm-signing';
const KEY_VERSION = 'v1';

let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function rootShare32B64u(byte: number): string {
  const bytes = Buffer.alloc(32, 0);
  bytes[31] = byte;
  return bytes.toString('base64url');
}

function fixedB64u(length: number, fill: number): string {
  return Buffer.alloc(length, fill).toString('base64url');
}

function compressedPublicKeyCandidateB64u(prefix: 0x02 | 0x03, fill: number): string {
  return Buffer.from([prefix, ...Array.from({ length: 32 }, () => fill)]).toString('base64url');
}

function bytesToHex(input: Uint8Array): string {
  return Array.from(input, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function negateCompressedPublicKey33B64u(publicKey33B64u: string): string {
  const pointCtor = ((secp256k1 as any).ProjectivePoint || (secp256k1 as any).Point) as
    | { fromHex: (hex: string | Uint8Array) => any }
    | undefined;
  if (!pointCtor || typeof pointCtor.fromHex !== 'function') {
    throw new Error('secp256k1 point constructor is unavailable');
  }
  const negated = pointCtor.fromHex(bytesToHex(Buffer.from(publicKey33B64u, 'base64url'))).negate();
  const raw = typeof negated.toRawBytes === 'function' ? negated.toRawBytes(true) : negated.toBytes(true);
  return Buffer.from(raw).toString('base64url');
}

function expectNoCanonicalExportMaterial(json: Record<string, unknown>): void {
  expect('canonicalSecp256k1KeyB64u' in json).toBe(false);
  expect('canonical_x32_b64u' in json).toBe(false);
  expect('privateKeyHex' in json).toBe(false);
  expect('exportPrivateKeyHex' in json).toBe(false);
}

async function createRoleLocalBootstrap(args: {
  svc: ReturnType<typeof createThresholdSigningServiceForUnitTests>['svc'];
  walletSessionUserId: string;
  rpId: string;
  clientRootShare32B64u: string;
  sessionId: string;
  walletSigningSessionId?: string;
  participantIds?: number[];
  signingRootId?: string;
  signingRootVersion?: string;
}) {
  ensureHssClientSignerWasm();
  const subjectId = args.walletSessionUserId;
  const signingRootId = args.signingRootId || TEST_SIGNING_ROOT_ID;
  const signingRootVersion = args.signingRootVersion || TEST_RUNTIME_SCOPE.signingRootVersion;
  const participantIds = args.participantIds || [1, 2];
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletSessionUserId: args.walletSessionUserId,
    rpId: args.rpId,
    subjectId,
    signingRootId,
    signingRootVersion,
  });
  const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletSessionUserId: args.walletSessionUserId,
    rpId: args.rpId,
  });
  const clientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
    walletSessionUserId: args.walletSessionUserId,
    subjectId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyPurpose: KEY_PURPOSE,
    keyVersion: KEY_VERSION,
    clientRootShare32B64u: args.clientRootShare32B64u,
  }) as {
    contextBinding32B64u: string;
    clientPublicKey33B64u: string;
    clientShareRetryCounter: number;
  };

  const result = await args.svc.ecdsaHssRoleLocalBootstrap({
    formatVersion: 'ecdsa-hss-role-local',
    walletSessionUserId: args.walletSessionUserId,
    rpId: args.rpId,
    subjectId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: `request:${args.sessionId}`,
    sessionId: args.sessionId,
    walletSigningSessionId: args.walletSigningSessionId || `${args.sessionId}:wallet-signing`,
    ttlMs: 60_000,
    remainingUses: 3,
    participantIds,
  });
  expect(result, JSON.stringify(result)).toMatchObject({ ok: true });
  if (!result.ok) throw new Error(result.message);
  return result.value;
}

test.describe('threshold-ecdsa role-local HSS bootstrap policy', () => {
  test('role-local bootstrap derives one shared key id and owner for evm-family scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-hss-shared-target.near';
    const rpId = 'wallet.example.test';
    const clientRootShare32B64u = rootShare32B64u(42);

    const first = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-hss-first',
    });
    const second = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-hss-second',
    });

    expect(first.ecdsaThresholdKeyId).toBe(second.ecdsaThresholdKeyId);
    expect(first.keyHandle).toBe(second.keyHandle);
    expect(first.thresholdEcdsaPublicKeyB64u).toBe(second.thresholdEcdsaPublicKeyB64u);
    expect(first.ethereumAddress).toBe(second.ethereumAddress);
    expect(first.publicIdentity).toEqual(second.publicIdentity);
    expect(first.sessionId).not.toBe(second.sessionId);
    expect(first.walletSigningSessionId).not.toBe(second.walletSigningSessionId);
    expectNoCanonicalExportMaterial(first as unknown as Record<string, unknown>);
  });

  test('role-local bootstrap changes planned key id when stable shared fields change', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-hss-stable-field-change.near';
    const clientRootShare32B64u = rootShare32B64u(7);
    const base = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId: 'wallet.example.test',
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-hss-stable-base',
    });
    const changedRp = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId: 'wallet.other.test',
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-hss-stable-rp',
    });
    const changedRoot = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId: 'wallet.example.test',
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-hss-stable-root',
      signingRootId: 'project-beta:env-alpha',
    });
    const changedVersion = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId: 'wallet.example.test',
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-hss-stable-version',
      signingRootVersion: 'v2',
    });

    expect(changedRp.ecdsaThresholdKeyId).not.toBe(base.ecdsaThresholdKeyId);
    expect(changedRoot.ecdsaThresholdKeyId).not.toBe(base.ecdsaThresholdKeyId);
    expect(changedVersion.ecdsaThresholdKeyId).not.toBe(base.ecdsaThresholdKeyId);
    expect(changedRp.ethereumAddress).not.toBe(base.ethereumAddress);
    expect(changedRoot.ethereumAddress).not.toBe(base.ethereumAddress);
    expect(changedVersion.ethereumAddress).not.toBe(base.ethereumAddress);
  });

  test('role-local bootstrap maps invalid client public keys to public_key_invalid', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-invalid-public-key.near';
    const rpId = 'wallet.example.test';
    const subjectId = walletSessionUserId;
    const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
      walletSessionUserId,
      rpId,
      subjectId,
      signingRootId: TEST_SIGNING_ROOT_ID,
      signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
    });
    const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
      walletSessionUserId,
      rpId,
    });

    for (const [name, clientPublicKey33B64u] of [
      ['invalid-point', compressedPublicKeyCandidateB64u(0x02, 0)],
      ['non-canonical-x', compressedPublicKeyCandidateB64u(0x02, 0xff)],
    ] as const) {
      const result = await svc.ecdsaHssRoleLocalBootstrap({
        formatVersion: 'ecdsa-hss-role-local',
        walletSessionUserId,
        rpId,
        subjectId,
        ecdsaThresholdKeyId,
        signingRootId: TEST_SIGNING_ROOT_ID,
        signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId,
        clientPublicKey33B64u,
        clientShareRetryCounter: 0,
        contextBinding32B64u: fixedB64u(32, 1),
        requestId: `request:${name}`,
        sessionId: `ecdsa-session-${name}`,
        walletSigningSessionId: `wallet-signing-${name}`,
        ttlMs: 60_000,
        remainingUses: 2,
        participantIds: [1, 2],
      });

      expect(result, `${name}: ${JSON.stringify(result)}`).toMatchObject({
        ok: false,
        code: 'public_key_invalid',
      });
    }
  });

  test('role-local bootstrap rejects client public key changes for an existing key handle', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-identity-sum.near';
    const rpId = 'wallet.example.test';
    const first = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId,
      clientRootShare32B64u: rootShare32B64u(77),
      sessionId: 'ecdsa-session-identity-sum-first',
    });
    const negatedRelayerPublicKey33B64u = negateCompressedPublicKey33B64u(
      first.relayerVerifyingShareB64u,
    );
    const retry = await svc.ecdsaHssRoleLocalBootstrap({
      formatVersion: 'ecdsa-hss-role-local',
      walletSessionUserId,
      rpId,
      subjectId: walletSessionUserId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: first.relayerKeyId,
      clientPublicKey33B64u: negatedRelayerPublicKey33B64u,
      clientShareRetryCounter: 0,
      contextBinding32B64u: first.contextBinding32B64u,
      requestId: 'request:identity-sum-retry',
      sessionId: 'ecdsa-session-identity-sum-retry',
      walletSigningSessionId: 'wallet-signing-identity-sum-retry',
      ttlMs: 60_000,
      remainingUses: 2,
      participantIds: [1, 2],
    });

    expect(retry, JSON.stringify(retry)).toMatchObject({
      ok: false,
      code: 'identity_mismatch',
    });
  });

  test('role-local bootstrap rejects relayer key rotation for an existing key handle', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-relayer-rotation.near';
    const rpId = 'wallet.example.test';
    const clientRootShare32B64u = rootShare32B64u(55);
    const first = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-relayer-rotation-first',
    });

    ensureHssClientSignerWasm();
    const clientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
      walletSessionUserId,
      subjectId: walletSessionUserId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyPurpose: KEY_PURPOSE,
      keyVersion: KEY_VERSION,
      clientRootShare32B64u,
    }) as {
      contextBinding32B64u: string;
      clientPublicKey33B64u: string;
      clientShareRetryCounter: number;
    };

    const rotated = await svc.ecdsaHssRoleLocalBootstrap({
      formatVersion: 'ecdsa-hss-role-local',
      walletSessionUserId,
      rpId,
      subjectId: walletSessionUserId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: `${first.relayerKeyId}:rotated`,
      clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
      clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
      contextBinding32B64u: clientBootstrap.contextBinding32B64u,
      requestId: 'request:relayer-rotation',
      sessionId: 'ecdsa-session-relayer-rotation-second',
      walletSigningSessionId: 'wallet-signing-relayer-rotation-second',
      ttlMs: 60_000,
      remainingUses: 2,
      participantIds: [1, 2],
    });

    expect(rotated).toMatchObject({
      ok: false,
      code: 'relayer_key_mismatch',
    });
  });

  test('role-local bootstrap rejects client share changes for an existing key handle', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-client-share-rotation.near';
    const rpId = 'wallet.example.test';
    const first = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId,
      clientRootShare32B64u: rootShare32B64u(56),
      sessionId: 'ecdsa-session-client-share-first',
    });

    ensureHssClientSignerWasm();
    const changedClientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
      walletSessionUserId,
      subjectId: walletSessionUserId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyPurpose: KEY_PURPOSE,
      keyVersion: KEY_VERSION,
      clientRootShare32B64u: rootShare32B64u(57),
    }) as {
      contextBinding32B64u: string;
      clientPublicKey33B64u: string;
      clientShareRetryCounter: number;
    };

    const changedClient = await svc.ecdsaHssRoleLocalBootstrap({
      formatVersion: 'ecdsa-hss-role-local',
      walletSessionUserId,
      rpId,
      subjectId: walletSessionUserId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: first.relayerKeyId,
      clientPublicKey33B64u: changedClientBootstrap.clientPublicKey33B64u,
      clientShareRetryCounter: changedClientBootstrap.clientShareRetryCounter,
      contextBinding32B64u: changedClientBootstrap.contextBinding32B64u,
      requestId: 'request:client-share-change',
      sessionId: 'ecdsa-session-client-share-second',
      walletSigningSessionId: 'wallet-signing-client-share-second',
      ttlMs: 60_000,
      remainingUses: 2,
      participantIds: [1, 2],
    });

    expect(changedClient).toMatchObject({
      ok: false,
      code: 'identity_mismatch',
    });
  });

  test('authorize resolves keyHandle selector against role-local threshold-session scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const walletSessionUserId = 'alice-authorize-key-handle.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const bootstrapped = await createRoleLocalBootstrap({
      svc,
      walletSessionUserId,
      rpId,
      clientRootShare32B64u: rootShare32B64u(36),
      sessionId: 'ecdsa-session-authorize-key-handle',
      participantIds,
    });
    const scheme = svc.getSchemeModule(THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID);
    if (!scheme || scheme.schemeId !== THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID) {
      throw new Error('missing threshold ECDSA scheme');
    }

    const authorized = await scheme.authorize({
      claims: {
        kind: 'threshold_ecdsa_session_v1',
        sub: walletSessionUserId,
        walletId: walletSessionUserId,
        subjectId: walletSessionUserId,
        keyScope: 'evm-family',
        keyHandle: bootstrapped.keyHandle,
        sessionId: bootstrapped.sessionId,
        walletSigningSessionId: bootstrapped.walletSigningSessionId,
        relayerKeyId: bootstrapped.relayerKeyId,
        rpId,
        thresholdExpiresAtMs: Date.now() + 60_000,
        participantIds,
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
      },
      request: {
        keyHandle: bootstrapped.keyHandle,
        purpose: 'test:key_handle_authorize',
        signing_digest_32: new Array(32).fill(7),
      },
    });

    expect(authorized, JSON.stringify(authorized)).toMatchObject({ ok: true });
    expect(String(authorized.mpcSessionId || '')).toBeTruthy();
    expect(authorized.walletSigningSessionId).toBe(bootstrapped.walletSigningSessionId);
  });
});
