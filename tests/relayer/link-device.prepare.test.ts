import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  callCf,
  fetchJson,
  makeCfCtx,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';

const THRESHOLD_ED25519_TEST_KEY_VERSION = 'threshold-ed25519-v1';

function makeThresholdEd25519PrepareRequest() {
  return {
    key_version: THRESHOLD_ED25519_TEST_KEY_VERSION,
    recovery_export_capable: true,
    public_key: 'ed25519:linked-key',
    relayer_key_id: 'rk-near',
    session_kind: 'jwt',
    session_policy: {
      version: 'threshold_session_v1',
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      relayerKeyId: 'rk-near',
      sessionId: 'near-session-1',
      participantIds: [1, 2],
      ttlMs: 60_000,
      remainingUses: 5,
    },
  };
}

function makePreparedLinkDeviceService() {
  return makeFakeAuthService({
    prepareLinkDevice: async () => ({
      ok: true,
      accountId: 'alice.testnet',
      signerSlot: 7,
      credentialIdB64u: 'cred-b64u',
      thresholdEd25519: {
        relayerKeyId: 'rk-near',
        publicKey: 'ed25519:linked-key',
        keyVersion: THRESHOLD_ED25519_TEST_KEY_VERSION,
        recoveryExportCapable: true,
        participantIds: [1, 2],
        session: {
          sessionKind: 'jwt',
          sessionId: 'near-session-1',
          walletSigningSessionId: 'wallet-signing-session-1',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          remainingUses: 5,
        },
      },
      ecdsa: {
        kind: 'evm_family_ecdsa_keygen',
        chainTargets: [
          {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 11155111,
            networkSlug: 'sepolia',
          },
        ],
        prepare: {
          formatVersion: 'ecdsa-hss-role-local',
          walletSessionUserId: 'alice.testnet',
          rpId: 'wallet.example.test',
          subjectId: 'alice.testnet',
          ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
          signingRootId: 'project:env',
          signingRootVersion: 'v1',
          keyScope: 'evm-family',
          relayerKeyId: 'rk-evm',
          requestId: 'link-device-ecdsa-request-1',
          sessionId: 'tehss-link-device-1',
          walletSigningSessionId: 'wallet-signing-session-1',
          ttlMs: 60_000,
          remainingUses: 1,
          participantIds: [1, 2],
          runtimePolicyScope: {
            orgId: 'org',
            projectId: 'project',
            envId: 'env',
            signingRootVersion: 'v1',
          },
        },
      } as any,
    }),
  });
}

function makeLinkDeviceEcdsaRespondService() {
  return makeFakeAuthService({
    respondLinkDeviceEcdsa: async () => ({
      ok: true,
      sessionId: 'link-device-session-1',
      ecdsa: {
        bootstrap: {
          formatVersion: 'ecdsa-hss-role-local',
          walletSessionUserId: 'alice.testnet',
          rpId: 'wallet.example.test',
          subjectId: 'alice.testnet',
          ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
          relayerKeyId: 'rk-evm',
          contextBinding32B64u: 'context-binding',
          publicIdentity: {
            clientPublicKey33B64u: 'client-public',
            relayerPublicKey33B64u: 'relayer-public',
            groupPublicKey33B64u: 'group-public',
            ethereumAddress: `0x${'11'.repeat(20)}`,
          },
          publicTranscriptDigest32B64u: 'transcript-digest',
          keyHandle: 'key-handle-link-device',
          signingRootId: 'project:env',
          signingRootVersion: 'v1',
          thresholdEcdsaPublicKeyB64u: 'group-public',
          ethereumAddress: `0x${'11'.repeat(20)}`,
          relayerVerifyingShareB64u: 'relayer-public',
          participantIds: [1, 2],
          sessionId: 'tehss-link-device-1',
          walletSigningSessionId: 'wallet-signing-session-1',
          expiresAtMs: Date.now() + 60_000,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          remainingUses: 1,
        },
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'sepolia',
            },
            walletSessionUserId: 'alice.testnet',
            rpId: 'wallet.example.test',
            subjectId: 'alice.testnet',
            keyHandle: 'key-handle-link-device',
            ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
            signingRootId: 'project:env',
            signingRootVersion: 'v1',
            thresholdEcdsaPublicKeyB64u: 'group-public',
            thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
            relayerKeyId: 'rk-evm',
            relayerVerifyingShareB64u: 'relayer-public',
            participantIds: [1, 2],
          },
        ],
      },
    }),
  });
}

function makeEcdsaClientBootstrap() {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletSessionUserId: 'alice.testnet',
    rpId: 'wallet.example.test',
    subjectId: 'alice.testnet',
    ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
    signingRootId: 'project:env',
    signingRootVersion: 'v1',
    keyScope: 'evm-family',
    relayerKeyId: 'rk-evm',
    clientPublicKey33B64u: 'client-public',
    clientShareRetryCounter: 0,
    contextBinding32B64u: 'context-binding',
    requestId: 'link-device-ecdsa-request-1',
    sessionId: 'tehss-link-device-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    ttlMs: 60_000,
    remainingUses: 1,
    participantIds: [1, 2],
  };
}

test.describe('link-device prepare routing', () => {
  test('express route signs and returns threshold Ed25519 session auth token', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) => `jwt:${sub}:${String((claims as any)?.sessionId || '')}`,
    });
    const router = createRelayRouter(makePreparedLinkDeviceService(), { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/link-device/prepare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://wallet.example.test',
        },
        body: JSON.stringify({
          account_id: 'alice.testnet',
          signer_slot: 7,
          rp_id: 'wallet.example.test',
          webauthn_registration: { id: 'cred-1' },
          threshold_ed25519: makeThresholdEd25519PrepareRequest(),
        }),
      });

      expect(res.status).toBe(200);
      expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
      expect(res.json?.thresholdEcdsa).toBeUndefined();
      expect((res.json?.ecdsa as any)?.prepare?.formatVersion).toBe('ecdsa-hss-role-local');
      expect(res.json).not.toHaveProperty('linkedAccounts');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare route signs and returns threshold Ed25519 session auth token', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) => `jwt:${sub}:${String((claims as any)?.sessionId || '')}`,
    });
    const handler = createCloudflareRouter(makePreparedLinkDeviceService(), { session });
    const { ctx } = makeCfCtx();

    const res = await callCf(handler, {
      method: 'POST',
      path: '/link-device/prepare',
      origin: 'https://wallet.example.test',
      headers: { 'Content-Type': 'application/json' },
      ctx,
      body: {
        account_id: 'alice.testnet',
        signer_slot: 7,
        rp_id: 'wallet.example.test',
        webauthn_registration: { id: 'cred-1' },
        threshold_ed25519: makeThresholdEd25519PrepareRequest(),
      },
    });

    expect(res.status).toBe(200);
    expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
    expect(res.json?.thresholdEcdsa).toBeUndefined();
    expect((res.json?.ecdsa as any)?.prepare?.formatVersion).toBe('ecdsa-hss-role-local');
    expect(res.json).not.toHaveProperty('linkedAccounts');
  });

  test('express route returns Link Device ECDSA bootstrap wallet keys', async () => {
    const router = createRelayRouter(makeLinkDeviceEcdsaRespondService(), {
      session: makeSessionAdapter(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/link-device/ecdsa/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: 'link-device-session-1',
          client_bootstrap: makeEcdsaClientBootstrap(),
        }),
      });

      expect(res.status).toBe(200);
      expect(res.json?.thresholdEcdsa).toBeUndefined();
      expect((res.json?.ecdsa as any)?.bootstrap?.keyHandle).toBe('key-handle-link-device');
      expect((res.json?.ecdsa as any)?.walletKeys?.[0]?.keyHandle).toBe(
        'key-handle-link-device',
      );
    } finally {
      await srv.close();
    }
  });

  test('cloudflare route returns Link Device ECDSA bootstrap wallet keys', async () => {
    const handler = createCloudflareRouter(makeLinkDeviceEcdsaRespondService(), {
      session: makeSessionAdapter(),
    });
    const { ctx } = makeCfCtx();

    const res = await callCf(handler, {
      method: 'POST',
      path: '/link-device/ecdsa/respond',
      headers: { 'Content-Type': 'application/json' },
      ctx,
      body: {
        session_id: 'link-device-session-1',
        client_bootstrap: makeEcdsaClientBootstrap(),
      },
    });

    expect(res.status).toBe(200);
    expect(res.json?.thresholdEcdsa).toBeUndefined();
    expect((res.json?.ecdsa as any)?.bootstrap?.keyHandle).toBe('key-handle-link-device');
    expect((res.json?.ecdsa as any)?.walletKeys?.[0]?.thresholdOwnerAddress).toBe(
      `0x${'11'.repeat(20)}`,
    );
  });
});
