import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  computeEcdsaDerivationRoleLocalRelayerKeyId,
  computeEcdsaDerivationRoleLocalThresholdKeyId,
  type DerivationClientSharePublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { createRouterAbSigningRuntimesForUnitTests } from '../helpers/routerAbSigningRuntimeTestUtils';
import { initSync as initEcdsaDerivationClientWasmSync } from '../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';

const ECDSA_DERIVATION_CLIENT_WASM_URL = new URL(
  '../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client_bg.wasm',
  import.meta.url,
);
const TEST_RUNTIME_SCOPE = {
  orgId: 'org-alpha',
  projectId: 'project-alpha',
  envId: 'env-alpha',
  signingRootVersion: 'default',
} as const;
const TEST_SIGNING_ROOT_ID = `${TEST_RUNTIME_SCOPE.projectId}:${TEST_RUNTIME_SCOPE.envId}`;

let ecdsaDerivationClientWasmInitialized = false;

function ensureEcdsaDerivationClientWasm(): void {
  if (ecdsaDerivationClientWasmInitialized) return;
  initEcdsaDerivationClientWasmSync({ module: readFileSync(ECDSA_DERIVATION_CLIENT_WASM_URL) });
  ecdsaDerivationClientWasmInitialized = true;
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

function toDerivationClientSharePublicKey33B64uForTest(
  value: string,
): DerivationClientSharePublicKey33B64u {
  return value as DerivationClientSharePublicKey33B64u;
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
  const raw =
    typeof negated.toRawBytes === 'function' ? negated.toRawBytes(true) : negated.toBytes(true);
  return Buffer.from(raw).toString('base64url');
}

function expectNoCanonicalExportMaterial(json: Record<string, unknown>): void {
  expect('canonicalSecp256k1KeyB64u' in json).toBe(false);
  expect('canonical_x32_b64u' in json).toBe(false);
  expect('privateKeyHex' in json).toBe(false);
  expect('exportPrivateKeyHex' in json).toBe(false);
}

async function createRoleLocalBootstrap(args: {
  runtime: ReturnType<
    typeof createRouterAbSigningRuntimesForUnitTests
  >['routerAbEcdsaBootstrapExportRuntime'];
  walletId: string;
  clientRootShare32B64u: string;
  sessionId: string;
  signingGrantId?: string;
  participantIds?: number[];
  signingRootId?: string;
  signingRootVersion?: string;
}) {
  ensureEcdsaDerivationClientWasm();
  const signingRootId = args.signingRootId || TEST_SIGNING_ROOT_ID;
  const signingRootVersion = args.signingRootVersion || TEST_RUNTIME_SCOPE.signingRootVersion;
  const participantIds = args.participantIds || [1, 2];
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: args.walletId,
    signingRootId,
    signingRootVersion,
  });
  const ecdsaThresholdKeyId = await computeEcdsaDerivationRoleLocalThresholdKeyId({
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
    signingRootId,
    signingRootVersion,
  });
  const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
  });
  const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId: args.walletId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
    },
    clientRootShare32B64u: args.clientRootShare32B64u,
  });

  const result = await args.runtime.ecdsaDerivationRoleLocalBootstrap({
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    derivationClientSharePublicKey33B64u: toDerivationClientSharePublicKey33B64uForTest(
      clientBootstrap.derivationClientSharePublicKey33B64u,
    ),
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: `request:${args.sessionId}`,
    sessionId: args.sessionId,
    signingGrantId: args.signingGrantId || `${args.sessionId}:wallet-signing`,
    ttlMs: 60_000,
    remainingUses: 3,
    participantIds,
  });
  expect(result, JSON.stringify(result)).toMatchObject({ ok: true });
  if (!result.ok) throw new Error(result.message);
  return result.value;
}

test.describe('threshold ECDSA role-local derivation bootstrap policy', () => {
  test('role-local bootstrap derives one shared key id and owner for evm-family scope', async () => {
    const { routerAbEcdsaBootstrapExportRuntime } = createRouterAbSigningRuntimesForUnitTests({});
    const walletId = 'alice-derivation-shared-target.near';
    const clientRootShare32B64u = rootShare32B64u(42);

    const first = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-derivation-first',
    });
    const second = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-derivation-second',
    });

    expect(first.ecdsaThresholdKeyId).toBe(second.ecdsaThresholdKeyId);
    expect(first.keyHandle).toBe(second.keyHandle);
    expect(first.thresholdEcdsaPublicKeyB64u).toBe(second.thresholdEcdsaPublicKeyB64u);
    expect(first.ethereumAddress).toBe(second.ethereumAddress);
    expect(first.publicIdentity).toEqual(second.publicIdentity);
    expect(first.thresholdSessionId).not.toBe(second.thresholdSessionId);
    expect(first.signingGrantId).not.toBe(second.signingGrantId);
    expectNoCanonicalExportMaterial(first as unknown as Record<string, unknown>);
  });

  test('role-local bootstrap changes planned key id when stable derivation fields change', async () => {
    const { routerAbEcdsaBootstrapExportRuntime } = createRouterAbSigningRuntimesForUnitTests({});
    const walletId = 'alice-derivation-stable-field-change.near';
    const clientRootShare32B64u = rootShare32B64u(7);
    const base = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-derivation-stable-base',
    });
    const changedRoot = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-derivation-stable-root',
      signingRootId: 'project-beta:env-alpha',
    });
    const changedVersion = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-derivation-stable-version',
      signingRootVersion: 'v2',
    });

    expect(changedRoot.ecdsaThresholdKeyId).not.toBe(base.ecdsaThresholdKeyId);
    expect(changedVersion.ecdsaThresholdKeyId).not.toBe(base.ecdsaThresholdKeyId);
    expect(changedRoot.ethereumAddress).not.toBe(base.ethereumAddress);
    expect(changedVersion.ethereumAddress).not.toBe(base.ethereumAddress);
  });

  test('role-local bootstrap maps invalid client public keys to public_key_invalid', async () => {
    const { routerAbEcdsaBootstrapExportRuntime } = createRouterAbSigningRuntimesForUnitTests({});
    const walletId = 'alice-invalid-public-key.near';
    const walletKeyId = `wallet-key-${walletId}`;
    const subjectId = walletId;
    const ecdsaThresholdKeyId = await computeEcdsaDerivationRoleLocalThresholdKeyId({
      walletId,
      walletKeyId,
      signingRootId: TEST_SIGNING_ROOT_ID,
      signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
    });
    const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
      walletId,
      walletKeyId,
    });

    for (const [name, derivationClientSharePublicKey33B64u] of [
      ['invalid-point', compressedPublicKeyCandidateB64u(0x02, 0)],
      ['non-canonical-x', compressedPublicKeyCandidateB64u(0x02, 0xff)],
    ] as const) {
      const result = await routerAbEcdsaBootstrapExportRuntime.ecdsaDerivationRoleLocalBootstrap({
        formatVersion: 'ecdsa-derivation-role-local',
        walletId,
        walletKeyId,
        ecdsaThresholdKeyId,
        signingRootId: TEST_SIGNING_ROOT_ID,
        signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId,
        derivationClientSharePublicKey33B64u: toDerivationClientSharePublicKey33B64uForTest(
          derivationClientSharePublicKey33B64u,
        ),
        clientShareRetryCounter: 0,
        contextBinding32B64u: fixedB64u(32, 1),
        requestId: `request:${name}`,
        sessionId: `ecdsa-session-${name}`,
        signingGrantId: `wallet-signing-${name}`,
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
    const { routerAbEcdsaBootstrapExportRuntime } = createRouterAbSigningRuntimesForUnitTests({});
    const walletId = 'alice-identity-sum.near';
    const first = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u: rootShare32B64u(77),
      sessionId: 'ecdsa-session-identity-sum-first',
    });
    const negatedRelayerPublicKey33B64u = negateCompressedPublicKey33B64u(
      first.relayerVerifyingShareB64u,
    );
    const retry = await routerAbEcdsaBootstrapExportRuntime.ecdsaDerivationRoleLocalBootstrap({
      formatVersion: 'ecdsa-derivation-role-local',
      walletId,
      walletKeyId: first.walletKeyId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: first.relayerKeyId,
      derivationClientSharePublicKey33B64u: toDerivationClientSharePublicKey33B64uForTest(
        negatedRelayerPublicKey33B64u,
      ),
      clientShareRetryCounter: 0,
      contextBinding32B64u: first.contextBinding32B64u,
      requestId: 'request:identity-sum-retry',
      sessionId: 'ecdsa-session-identity-sum-retry',
      signingGrantId: 'wallet-signing-identity-sum-retry',
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
    const { routerAbEcdsaBootstrapExportRuntime } = createRouterAbSigningRuntimesForUnitTests({});
    const walletId = 'alice-relayer-rotation.near';
    const clientRootShare32B64u = rootShare32B64u(55);
    const first = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u,
      sessionId: 'ecdsa-session-relayer-rotation-first',
    });

    ensureEcdsaDerivationClientWasm();
    const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
      context: {
        walletId,
        ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
        signingRootId: first.signingRootId,
        signingRootVersion: first.signingRootVersion,
      },
      clientRootShare32B64u,
    });

    const rotated = await routerAbEcdsaBootstrapExportRuntime.ecdsaDerivationRoleLocalBootstrap({
      formatVersion: 'ecdsa-derivation-role-local',
      walletId,
      walletKeyId: first.walletKeyId,
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      signingRootId: first.signingRootId,
      signingRootVersion: first.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: `${first.relayerKeyId}:rotated`,
      derivationClientSharePublicKey33B64u: toDerivationClientSharePublicKey33B64uForTest(
        clientBootstrap.derivationClientSharePublicKey33B64u,
      ),
      clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
      contextBinding32B64u: clientBootstrap.contextBinding32B64u,
      requestId: 'request:relayer-rotation',
      sessionId: 'ecdsa-session-relayer-rotation-second',
      signingGrantId: 'wallet-signing-relayer-rotation-second',
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
    const { routerAbEcdsaBootstrapExportRuntime } = createRouterAbSigningRuntimesForUnitTests({});
    const walletId = 'alice-client-share-rotation.near';
    const first = await createRoleLocalBootstrap({
      runtime: routerAbEcdsaBootstrapExportRuntime,
      walletId,
      clientRootShare32B64u: rootShare32B64u(56),
      sessionId: 'ecdsa-session-client-share-first',
    });

    ensureEcdsaDerivationClientWasm();
    const changedClientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
      context: {
        walletId,
        ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
        signingRootId: first.signingRootId,
        signingRootVersion: first.signingRootVersion,
      },
      clientRootShare32B64u: rootShare32B64u(57),
    });

    const changedClient =
      await routerAbEcdsaBootstrapExportRuntime.ecdsaDerivationRoleLocalBootstrap({
        formatVersion: 'ecdsa-derivation-role-local',
        walletId,
        walletKeyId: first.walletKeyId,
        ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
        signingRootId: first.signingRootId,
        signingRootVersion: first.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId: first.relayerKeyId,
        derivationClientSharePublicKey33B64u: toDerivationClientSharePublicKey33B64uForTest(
          changedClientBootstrap.derivationClientSharePublicKey33B64u,
        ),
        clientShareRetryCounter: changedClientBootstrap.clientShareRetryCounter,
        contextBinding32B64u: changedClientBootstrap.contextBinding32B64u,
        requestId: 'request:client-share-change',
        sessionId: 'ecdsa-session-client-share-second',
        signingGrantId: 'wallet-signing-client-share-second',
        ttlMs: 60_000,
        remainingUses: 2,
        participantIds: [1, 2],
      });

    expect(changedClient).toMatchObject({
      ok: false,
      code: 'identity_mismatch',
    });
  });
});
