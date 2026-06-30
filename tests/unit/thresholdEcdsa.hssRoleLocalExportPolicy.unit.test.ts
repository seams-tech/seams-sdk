import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type { EcdsaHssClientSharePublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import type {
  EcdsaHssExportShareRequest,
  EcdsaHssPublicIdentity,
} from '../../packages/sdk-server-ts/src/core/types';
import type { RouterAbEcdsaHssWalletSessionClaims } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import {
  parseEcdsaHssClientBootstrapRequest,
  parseEcdsaHssExportShareRequest,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import { initSync as initHssClientSignerWasmSync } from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';

const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const EXPRESS_THRESHOLD_ECDSA_ROUTE_URL = new URL(
  '../../packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts',
  import.meta.url,
);
const EXPORT_CONFIRMATION_DIGEST_VERSION = 'ecdsa-hss:role-local:product-export-confirmation:v2';
const EXPORT_AUTHORIZATION_DIGEST_VERSION = 'ecdsa-hss:role-local:product-export-authorization:v2';

let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function bytesB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function publicKey33B64u(lastByte: number, prefix: 0x02 | 0x03 = 0x02): string {
  const bytes = Buffer.alloc(33, 0);
  bytes[0] = prefix;
  bytes[32] = lastByte;
  return bytesB64u(bytes);
}

function ethereumAddress20B64u(address: string): string {
  const normalized = address.trim().toLowerCase().replace(/^0x/, '');
  return bytesB64u(Buffer.from(normalized, 'hex'));
}

function toHssClientSharePublicKey33B64uForTest(value: string): EcdsaHssClientSharePublicKey33B64u {
  return value as EcdsaHssClientSharePublicKey33B64u;
}

async function digestB64u(value: unknown): Promise<string> {
  return bytesB64u(await sha256BytesUtf8(alphabetizeStringify(value)));
}

async function createRoleLocalExportFixture(input?: { bootstrapTtlMs?: number }) {
  ensureHssClientSignerWasm();
  const { svc } = createThresholdSigningServiceForUnitTests({
    config: {
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'unit-signing-worker',
    },
  });
  const clientRootShare32 = Buffer.alloc(32, 0);
  clientRootShare32[31] = 7;

  const walletId = 'wallet-user-1';
  const rpId = 'wallet.example.test';
  const ecdsaThresholdKeyId = 'ecdsa-key-1';
  const signingRootId = 'signing-root';
  const signingRootVersion = 'default';
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId,
    signingRootVersion,
  });
  const relayerKeyId = 'relayer-key-1';
  const participantIds = [1, 2];

  const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
    },
    clientRootShare32B64u: bytesB64u(clientRootShare32),
  });

  const bootstrap = await svc.ecdsaHssRoleLocalBootstrap({
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    hssClientSharePublicKey33B64u: toHssClientSharePublicKey33B64uForTest(
      clientBootstrap.hssClientSharePublicKey33B64u,
    ),
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: 'bootstrap-request-1',
    sessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    ttlMs: input?.bootstrapTtlMs ?? 60_000,
    remainingUses: 2,
    participantIds,
  });
  expect(bootstrap.ok).toBe(true);
  if (!bootstrap.ok) throw new Error(bootstrap.message);
  const bootstrapValue = bootstrap.value;

  const claims: RouterAbEcdsaHssWalletSessionClaims = {
    sub: walletId,
    walletId: walletId,
    kind: 'router_ab_ecdsa_hss_wallet_session_v1',
    thresholdSessionId: bootstrapValue.thresholdSessionId,
    signingGrantId: bootstrapValue.signingGrantId,
    keyScope: 'evm-family',
    keyHandle: bootstrapValue.keyHandle,
    relayerKeyId,
    evmFamilySigningKeySlotId,
    thresholdExpiresAtMs: bootstrapValue.expiresAtMs,
    participantIds: bootstrapValue.participantIds,
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        wallet_key_id: evmFamilySigningKeySlotId,
        wallet_id: walletId,
        ecdsa_threshold_key_id: ecdsaThresholdKeyId,
        signing_root_id: signingRootId,
        signing_root_version: signingRootVersion,
        context: {
          application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
        },
        public_identity: {
          context_binding_b64u: clientBootstrap.contextBinding32B64u,
          client_public_key33_b64u: clientBootstrap.hssClientSharePublicKey33B64u,
          server_public_key33_b64u: bootstrapValue.publicIdentity.relayerPublicKey33B64u,
          threshold_public_key33_b64u: bootstrapValue.publicIdentity.groupPublicKey33B64u,
          ethereum_address20_b64u: ethereumAddress20B64u(
            bootstrapValue.publicIdentity.ethereumAddress,
          ),
          client_share_retry_counter: clientBootstrap.clientShareRetryCounter,
          server_share_retry_counter: bootstrapValue.relayerShareRetryCounter,
        },
        signing_worker: {
          server_id: 'signing-worker-export-test',
          key_epoch: 'signing-worker-output-epoch',
          recipient_encryption_key: `x25519:${'33'.repeat(32)}`,
        },
        activation_epoch: bootstrapValue.thresholdSessionId,
      },
    },
  };

  async function makeExportRequest(input?: {
    publicIdentity?: EcdsaHssPublicIdentity;
    contextBinding32B64u?: string;
    nonce?: string;
    expiresAtUnixMs?: number;
  }): Promise<EcdsaHssExportShareRequest> {
    const issuedAtUnixMs = Date.now();
    const expiresAtUnixMs = input?.expiresAtUnixMs ?? issuedAtUnixMs + 60_000;
    const publicIdentity = input?.publicIdentity ?? bootstrapValue.publicIdentity;
    const requestWithoutDigests = {
      formatVersion: 'ecdsa-hss-role-local-export' as const,
      walletId,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId,
      relayerKeyId,
      contextBinding32B64u: input?.contextBinding32B64u ?? clientBootstrap.contextBinding32B64u,
      publicIdentity,
      clientDeviceId: 'device-1',
      clientSessionId: 'client-session-1',
      exportRequestNonce32B64u: input?.nonce ?? bytesB64u(Buffer.alloc(32, 9)),
      issuedAtUnixMs,
      expiresAtUnixMs,
    };
    const confirmationDigest32B64u = await digestB64u({
      version: EXPORT_CONFIRMATION_DIGEST_VERSION,
      walletId,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId,
      relayerKeyId,
      contextBinding32B64u: requestWithoutDigests.contextBinding32B64u,
      publicIdentity,
      clientDeviceId: requestWithoutDigests.clientDeviceId,
      clientSessionId: requestWithoutDigests.clientSessionId,
      exportRequestNonce32B64u: requestWithoutDigests.exportRequestNonce32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
    });
    const request = {
      ...requestWithoutDigests,
      confirmationDigest32B64u,
      authorizationDigest32B64u: '',
    };
    return {
      ...request,
      authorizationDigest32B64u: await digestB64u({
        version: EXPORT_AUTHORIZATION_DIGEST_VERSION,
        operation: 'explicit_key_export',
        keyHandle: bootstrapValue.keyHandle,
        walletId,
        evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId,
        relayerKeyId,
        signingRootId: bootstrapValue.signingRootId,
        signingRootVersion: bootstrapValue.signingRootVersion,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        confirmationDigest32B64u,
        issuedAtUnixMs,
        expiresAtUnixMs,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        thresholdSessionId: claims.thresholdSessionId,
        signingGrantId: claims.signingGrantId,
        thresholdExpiresAtMs: claims.thresholdExpiresAtMs,
        participantIds: claims.participantIds,
      }),
    };
  }

  return {
    svc,
    keyHandle: bootstrapValue.keyHandle,
    claims,
    publicIdentity: bootstrapValue.publicIdentity,
    makeExportRequest,
  };
}

test.describe('threshold ECDSA HSS role-local export policy', () => {
  test('rejects stale v1 identity fields at active v2 bootstrap and export boundaries', async () => {
    const fixture = await createRoleLocalExportFixture();
    const bootstrapRequest = {
      formatVersion: 'ecdsa-hss-role-local',
      walletId: 'wallet-user-1',
      evmFamilySigningKeySlotId: String(
        deriveEvmFamilySigningKeySlotId({
          walletId: 'wallet-user-1',
          signingRootId: 'signing-root',
          signingRootVersion: 'default',
        }),
      ),
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
      keyScope: 'evm-family',
      relayerKeyId: 'relayer-key-1',
      hssClientSharePublicKey33B64u: toHssClientSharePublicKey33B64uForTest(publicKey33B64u(1)),
      clientShareRetryCounter: 0,
      contextBinding32B64u: bytesB64u(Buffer.alloc(32, 1)),
      requestId: 'bootstrap-request',
      sessionId: 'threshold-session',
      signingGrantId: 'signing-grant',
      ttlMs: 60_000,
      remainingUses: 2,
      participantIds: [1, 2],
    };
    const exportRequest = await fixture.makeExportRequest({
      nonce: bytesB64u(Buffer.alloc(32, 21)),
    });
    const staleIdentityFields = [
      'subjectId',
      'walletSessionUserId',
      'subject_id',
      'wallet_session_user_id',
      'walletKeyId',
      'wallet_id',
      'wallet_key_id',
      'ecdsa_threshold_key_id',
      'signing_root_id',
      'signing_root_version',
      'keyPurpose',
      'key_purpose',
      'keyVersion',
      'key_version',
      'rpId',
      'rp_id',
    ] as const;

    expect(parseEcdsaHssClientBootstrapRequest(bootstrapRequest)).not.toBeNull();
    expect(parseEcdsaHssExportShareRequest(exportRequest)).not.toBeNull();
    for (const field of staleIdentityFields) {
      expect(
        parseEcdsaHssClientBootstrapRequest({ ...bootstrapRequest, [field]: 'stale' }),
      ).toBeNull();
      expect(parseEcdsaHssExportShareRequest({ ...exportRequest, [field]: 'stale' })).toBeNull();
    }
  });

  test('rejects wallet, key id, and relayer key id mismatches', async () => {
    const fixture = await createRoleLocalExportFixture();
    const mismatchCases: Array<{
      name: string;
      patch: Partial<EcdsaHssExportShareRequest>;
    }> = [
      {
        name: 'walletId',
        patch: { walletId: 'other-wallet-user' },
      },
      {
        name: 'ecdsaThresholdKeyId',
        patch: { ecdsaThresholdKeyId: 'other-threshold-key' },
      },
      {
        name: 'relayerKeyId',
        patch: { relayerKeyId: 'other-relayer-key' },
      },
    ];

    for (const { name, patch } of mismatchCases) {
      const request = {
        ...(await fixture.makeExportRequest({
          nonce: bytesB64u(Buffer.alloc(32, name.length)),
        })),
        ...patch,
      };

      const result = await fixture.svc.ecdsaHssRoleLocalExportShare({
        request,
        keyHandle: fixture.keyHandle,
        claims: fixture.claims,
      });

      expect(result, name).toMatchObject({
        ok: false,
        code: 'identity_mismatch',
      });
      expect('value' in result ? result.value.serverExportShare32B64u : undefined).toBeUndefined();
    }
  });

  test('burns export nonce before identity failure returns', async () => {
    const fixture = await createRoleLocalExportFixture();
    const nonce = bytesB64u(Buffer.alloc(32, 15));
    const request = await fixture.makeExportRequest({ nonce });
    const result = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request,
      keyHandle: fixture.keyHandle,
      claims: {
        ...fixture.claims,
        keyHandle: 'other-key-handle',
      },
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'identity_mismatch',
    });
    expect('value' in result ? result.value.serverExportShare32B64u : undefined).toBeUndefined();

    const retryWithSameNonce = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request: await fixture.makeExportRequest({ nonce }),
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(retryWithSameNonce).toMatchObject({
      ok: false,
      code: 'export_nonce_replay',
    });
  });

  test('rejects public identity mismatch without returning the server export share', async () => {
    const fixture = await createRoleLocalExportFixture();
    const request = await fixture.makeExportRequest({
      publicIdentity: {
        ...fixture.publicIdentity,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });

    const result = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'public_key_invalid',
    });
    expect('value' in result ? result.value.serverExportShare32B64u : undefined).toBeUndefined();
  });

  test('rejects context mismatch without returning the server export share', async () => {
    const fixture = await createRoleLocalExportFixture();
    const nonce = bytesB64u(Buffer.alloc(32, 8));
    const request = await fixture.makeExportRequest({
      contextBinding32B64u: bytesB64u(Buffer.alloc(32, 8)),
      nonce,
    });

    const result = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'context_mismatch',
    });
    expect('value' in result ? result.value.serverExportShare32B64u : undefined).toBeUndefined();

    const retryWithSameNonce = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request: await fixture.makeExportRequest({ nonce }),
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(retryWithSameNonce).toMatchObject({
      ok: false,
      code: 'export_nonce_replay',
    });
  });

  test('burns export nonce before public identity failure returns', async () => {
    const fixture = await createRoleLocalExportFixture();
    const nonce = bytesB64u(Buffer.alloc(32, 14));
    const request = await fixture.makeExportRequest({
      nonce,
      publicIdentity: {
        ...fixture.publicIdentity,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });

    const result = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'public_key_invalid',
    });
    expect('value' in result ? result.value.serverExportShare32B64u : undefined).toBeUndefined();

    const retryWithSameNonce = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request: await fixture.makeExportRequest({ nonce }),
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(retryWithSameNonce).toMatchObject({
      ok: false,
      code: 'export_nonce_replay',
    });
  });

  test('rejects nonce replay after one successful export-share request', async () => {
    const fixture = await createRoleLocalExportFixture();
    const request = await fixture.makeExportRequest({
      nonce: bytesB64u(Buffer.alloc(32, 10)),
    });

    const first = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error(first.message);
    expect(first.value.serverExportShare32B64u).toBeTruthy();

    const replay = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(replay).toMatchObject({
      ok: false,
      code: 'export_nonce_replay',
    });
  });

  test('retains export nonce replay guard beyond the export authorization expiry', async () => {
    const originalNow = Date.now;
    let nowMs = originalNow();
    Date.now = () => nowMs;
    try {
      const fixture = await createRoleLocalExportFixture({ bootstrapTtlMs: 2 * 60 * 60_000 });
      const nonce = bytesB64u(Buffer.alloc(32, 18));
      const first = await fixture.svc.ecdsaHssRoleLocalExportShare({
        request: await fixture.makeExportRequest({ nonce }),
        keyHandle: fixture.keyHandle,
        claims: fixture.claims,
      });
      expect(first.ok).toBe(true);

      nowMs += 2 * 60_000;
      const replayWithFreshAuthorization = await fixture.svc.ecdsaHssRoleLocalExportShare({
        request: await fixture.makeExportRequest({ nonce }),
        keyHandle: fixture.keyHandle,
        claims: fixture.claims,
      });
      expect(replayWithFreshAuthorization).toMatchObject({
        ok: false,
        code: 'export_nonce_replay',
      });
    } finally {
      Date.now = originalNow;
    }
  });

  test('rejects invalid export authorization digest and expired authorization', async () => {
    const fixture = await createRoleLocalExportFixture();
    const invalidDigestRequest = {
      ...(await fixture.makeExportRequest({
        nonce: bytesB64u(Buffer.alloc(32, 11)),
      })),
      authorizationDigest32B64u: bytesB64u(Buffer.alloc(32, 12)),
    };
    const invalidDigest = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request: invalidDigestRequest,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(invalidDigest).toMatchObject({
      ok: false,
      code: 'export_authorization_invalid',
    });
    expect(
      'value' in invalidDigest ? invalidDigest.value.serverExportShare32B64u : undefined,
    ).toBeUndefined();

    const expiredRequest = await fixture.makeExportRequest({
      nonce: bytesB64u(Buffer.alloc(32, 13)),
      expiresAtUnixMs: Date.now() - 1_000,
    });
    const expired = await fixture.svc.ecdsaHssRoleLocalExportShare({
      request: expiredRequest,
      keyHandle: fixture.keyHandle,
      claims: fixture.claims,
    });
    expect(expired).toMatchObject({
      ok: false,
      code: 'export_authorization_expired',
    });
    expect('value' in expired ? expired.value.serverExportShare32B64u : undefined).toBeUndefined();
  });

  test('rejects sensitive export request fields before route handling', async () => {
    const fixture = await createRoleLocalExportFixture();
    const request = await fixture.makeExportRequest();
    const forbiddenFields = [
      'chainTarget',
      'yClient32Le',
      'yClient32LeB64u',
      'yRelayer32Le',
      'yRelayer32LeB64u',
      'clientShare32B64u',
      'relayerShare32B64u',
      'serverExportShare32B64u',
      'canonicalPrivateKeyHex',
      'privateKeyHex',
    ] as const;

    for (const field of forbiddenFields) {
      expect(parseEcdsaHssExportShareRequest({ ...request, [field]: 'secret' })).toBeNull();
    }
  });

  test('keeps Express export-share request log metadata on an explicit allowlist', () => {
    const source = readFileSync(EXPRESS_THRESHOLD_ECDSA_ROUTE_URL, 'utf8');
    const routeStart = source.indexOf('ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH');
    expect(routeStart).toBeGreaterThan(-1);
    const routeLogMeta = source.slice(routeStart, source.indexOf('async () =>', routeStart));
    expect(routeLogMeta).toContain('walletId');
    expect(routeLogMeta).toContain('ecdsaThresholdKeyId');
    expect(routeLogMeta).toContain('relayerKeyId');

    for (const forbidden of [
      'privateKeyHex',
      'serverExportShare32B64u',
      'clientShare32B64u',
      'relayerShare32B64u',
      'canonicalPrivateKeyHex',
      'yClient32Le',
      'yRelayer32Le',
    ]) {
      expect(routeLogMeta).not.toContain(forbidden);
    }
  });
});
