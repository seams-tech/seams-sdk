import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type { EcdsaHssClientSharePublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import type {
  EcdsaHssExportShareRequest,
  EcdsaHssPublicIdentity,
} from '../../packages/sdk-server-ts/src/core/types';
import type { ThresholdEcdsaSessionClaims } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import {
  parseEcdsaHssClientBootstrapRequest,
  parseEcdsaHssExportShareRequest,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import {
  initSync as initHssClientSignerWasmSync,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
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

function toHssClientSharePublicKey33B64uForTest(value: string): EcdsaHssClientSharePublicKey33B64u {
  return value as EcdsaHssClientSharePublicKey33B64u;
}

async function digestB64u(value: unknown): Promise<string> {
  return bytesB64u(await sha256BytesUtf8(alphabetizeStringify(value)));
}

async function createRoleLocalExportFixture(input?: { bootstrapTtlMs?: number }) {
  ensureHssClientSignerWasm();
  const { svc } = createThresholdSigningServiceForUnitTests({});
  const clientRootShare32 = Buffer.alloc(32, 0);
  clientRootShare32[31] = 7;

  const walletId = 'wallet-user-1';
  const rpId = 'wallet.example.test';
  const ecdsaThresholdKeyId = 'ecdsa-key-1';
  const signingRootId = 'signing-root';
  const signingRootVersion = 'default';
  const relayerKeyId = 'relayer-key-1';
  const participantIds = [1, 2];

  const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId,
      rpId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
    },
    clientRootShare32B64u: bytesB64u(clientRootShare32),
  });

  const bootstrap = await svc.ecdsaHssRoleLocalBootstrap({
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    rpId,
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
    walletSigningSessionId: 'wallet-signing-session-1',
    ttlMs: input?.bootstrapTtlMs ?? 60_000,
    remainingUses: 2,
    participantIds,
  });
  expect(bootstrap.ok).toBe(true);
  if (!bootstrap.ok) throw new Error(bootstrap.message);
  const bootstrapValue = bootstrap.value;

  const claims: ThresholdEcdsaSessionClaims = {
    sub: walletId,
    walletId: walletId,
    kind: 'threshold_ecdsa_session_v2',
    sessionId: bootstrapValue.sessionId,
    walletSigningSessionId: bootstrapValue.walletSigningSessionId,
    keyScope: 'evm-family',
    keyHandle: bootstrapValue.keyHandle,
    relayerKeyId,
    rpId,
    thresholdExpiresAtMs: bootstrapValue.expiresAtMs,
    participantIds: bootstrapValue.participantIds,
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
      rpId,
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
      rpId,
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
        rpId,
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
        thresholdSessionId: claims.sessionId,
        walletSigningSessionId: claims.walletSigningSessionId,
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
      rpId: 'wallet.example.test',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
      keyScope: 'evm-family',
      relayerKeyId: 'relayer-key-1',
      hssClientSharePublicKey33B64u: toHssClientSharePublicKey33B64uForTest(
        publicKey33B64u(1),
      ),
      clientShareRetryCounter: 0,
      contextBinding32B64u: bytesB64u(Buffer.alloc(32, 1)),
      requestId: 'bootstrap-request',
      sessionId: 'threshold-session',
      walletSigningSessionId: 'wallet-signing-session',
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
    ] as const;

    expect(parseEcdsaHssClientBootstrapRequest(bootstrapRequest)).not.toBeNull();
    expect(parseEcdsaHssExportShareRequest(exportRequest)).not.toBeNull();
    for (const field of staleIdentityFields) {
      expect(parseEcdsaHssClientBootstrapRequest({ ...bootstrapRequest, [field]: 'stale' })).toBeNull();
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
    const routeStart = source.indexOf("'/threshold-ecdsa/hss/export/share'");
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
