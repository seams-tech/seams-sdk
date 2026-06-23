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
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

const THRESHOLD_ED25519_TEST_KEY_VERSION = 'threshold-ed25519-v1';
const ECDSA_CLIENT_PUBLIC_KEY_B64U =
  'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const ECDSA_RELAYER_PUBLIC_KEY_B64U =
  'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaRelayerHssPublicKey33B64u;
const ECDSA_GROUP_PUBLIC_KEY_B64U = 'AgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const ECDSA_CONTEXT_BINDING_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ROUTER_AB_RUNTIME_POLICY_SCOPE = {
  orgId: 'org',
  projectId: 'project',
  envId: 'env',
  signingRootVersion: 'v1',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-local',
} as const;

function makeThresholdEd25519PrepareRequest() {
  return {
    key_version: THRESHOLD_ED25519_TEST_KEY_VERSION,
    recovery_export_capable: true,
    public_key: 'ed25519:linked-key',
    relayer_key_id: 'rk-near',
    session_kind: 'jwt',
    session_policy: {
      version: 'threshold_session_v1',
      walletId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      ed25519KeyScopeId: 'alice.testnet',
      rpId: 'wallet.example.test',
      relayerKeyId: 'rk-near',
      thresholdSessionId: 'near-session-1',
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
      walletId: 'alice.testnet',
      accountId: 'alice.testnet',
      signerSlot: 7,
      credentialIdB64u: 'cred-b64u',
      thresholdEd25519: {
        relayerKeyId: 'rk-near',
        publicKey: 'ed25519:linked-key',
        keyVersion: THRESHOLD_ED25519_TEST_KEY_VERSION,
        recoveryExportCapable: true,
        participantIds: [1, 2],
        nearAccountId: 'alice.testnet',
        ed25519KeyScopeId: 'alice.testnet',
        session: {
          sessionKind: 'jwt',
          walletId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          ed25519KeyScopeId: 'alice.testnet',
          thresholdSessionId: 'near-session-1',
          signingGrantId: 'signing-grant-1',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          remainingUses: 5,
          runtimePolicyScope: ROUTER_AB_RUNTIME_POLICY_SCOPE,
          routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
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
          walletId: 'alice.testnet',
          rpId: 'wallet.example.test',
          ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
          signingRootId: 'project:env',
          signingRootVersion: 'v1',
          keyScope: 'evm-family',
          relayerKeyId: 'rk-evm',
          requestId: 'link-device-ecdsa-request-1',
          thresholdSessionId: 'tehss-link-device-1',
          signingGrantId: 'signing-grant-1',
          ttlMs: 60_000,
          remainingUses: 1,
          participantIds: [1, 2],
          runtimePolicyScope: ROUTER_AB_RUNTIME_POLICY_SCOPE,
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
          walletId: 'alice.testnet',
          rpId: 'wallet.example.test',
          ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
          relayerKeyId: 'rk-evm',
          contextBinding32B64u: ECDSA_CONTEXT_BINDING_B64U,
          publicIdentity: {
            hssClientSharePublicKey33B64u: ECDSA_CLIENT_PUBLIC_KEY_B64U,
            relayerPublicKey33B64u: ECDSA_RELAYER_PUBLIC_KEY_B64U,
            groupPublicKey33B64u: ECDSA_GROUP_PUBLIC_KEY_B64U,
            ethereumAddress: `0x${'11'.repeat(20)}`,
          },
          clientShareRetryCounter: 0,
          relayerShareRetryCounter: 0,
          publicTranscriptDigest32B64u: 'transcript-digest',
          keyHandle: 'key-handle-link-device',
          signingRootId: 'project:env',
          signingRootVersion: 'v1',
          thresholdEcdsaPublicKeyB64u: ECDSA_GROUP_PUBLIC_KEY_B64U,
          ethereumAddress: `0x${'11'.repeat(20)}`,
          relayerVerifyingShareB64u: ECDSA_RELAYER_PUBLIC_KEY_B64U,
          participantIds: [1, 2],
          thresholdSessionId: 'tehss-link-device-1',
          signingGrantId: 'signing-grant-1',
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
            walletId: 'alice.testnet',
            rpId: 'wallet.example.test',
            keyHandle: 'key-handle-link-device',
            ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
            signingRootId: 'project:env',
            signingRootVersion: 'v1',
            thresholdEcdsaPublicKeyB64u: ECDSA_GROUP_PUBLIC_KEY_B64U,
            thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
            relayerKeyId: 'rk-evm',
            relayerVerifyingShareB64u: ECDSA_RELAYER_PUBLIC_KEY_B64U,
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
    walletId: 'alice.testnet',
    rpId: 'wallet.example.test',
    ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
    signingRootId: 'project:env',
    signingRootVersion: 'v1',
    keyScope: 'evm-family',
    relayerKeyId: 'rk-evm',
    hssClientSharePublicKey33B64u: ECDSA_CLIENT_PUBLIC_KEY_B64U,
    clientShareRetryCounter: 0,
    contextBinding32B64u: ECDSA_CONTEXT_BINDING_B64U,
    requestId: 'link-device-ecdsa-request-1',
    thresholdSessionId: 'tehss-link-device-1',
    signingGrantId: 'signing-grant-1',
    ttlMs: 60_000,
    remainingUses: 1,
    participantIds: [1, 2],
  };
}

test.describe('link-device prepare routing', () => {
  test('express route signs and returns threshold Ed25519 session auth token', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) =>
        `jwt:${sub}:${String((claims as any)?.thresholdSessionId || '')}`,
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
      signJwt: async (sub, claims) =>
        `jwt:${sub}:${String((claims as any)?.thresholdSessionId || '')}`,
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
      expect((res.json?.ecdsa as any)?.walletKeys?.[0]?.keyHandle).toBe('key-handle-link-device');
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
