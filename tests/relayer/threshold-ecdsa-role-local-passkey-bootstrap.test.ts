import { expect, test } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import {
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { base64UrlEncode } from '@shared/utils/encoders';
import { fetchJson, makeSessionAdapter, startExpressRouter } from './helpers';

const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-passkey-role-local',
  projectId: 'project-passkey-role-local',
  envId: 'env-passkey-role-local',
  signingRootVersion: 'v1',
};
const WALLET_SESSION_USER_ID = 'passkey-wallet-user';
const RP_ID = 'wallet.example.test';
const SUBJECT_ID = WALLET_SESSION_USER_ID;
const SIGNING_ROOT_ID = `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`;
const SIGNING_ROOT_VERSION = RUNTIME_POLICY_SCOPE.signingRootVersion;
const PARTICIPANT_IDS = [1, 2];

function b64u(bytes: Uint8Array): string {
  return base64UrlEncode(bytes);
}

function fakeWebAuthnAuthentication() {
  return {
    id: 'credential-id',
    rawId: 'credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: b64u(new TextEncoder().encode('{}')),
      authenticatorData: b64u(new Uint8Array([1, 2, 3])),
      signature: b64u(new Uint8Array([4, 5, 6])),
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

async function makeBootstrapBody(overrides?: Record<string, unknown>) {
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletSessionUserId: WALLET_SESSION_USER_ID,
    rpId: RP_ID,
    subjectId: SUBJECT_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletSessionUserId: WALLET_SESSION_USER_ID,
    rpId: RP_ID,
  });
  const body = {
    formatVersion: 'ecdsa-hss-role-local',
    walletSessionUserId: WALLET_SESSION_USER_ID,
    rpId: RP_ID,
    subjectId: SUBJECT_ID,
    ecdsaThresholdKeyId,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    keyScope: 'evm-family',
    relayerKeyId,
    clientPublicKey33B64u: b64u(
      Uint8Array.from([0x02, ...Array.from({ length: 32 }, (_, index) => index)]),
    ),
    clientShareRetryCounter: 0,
    contextBinding32B64u: b64u(Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1))),
    requestId: 'passkey-role-local-request-1',
    sessionId: 'threshold-ecdsa-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    ttlMs: 60_000,
    remainingUses: 2,
    participantIds: PARTICIPANT_IDS,
    passkeyBootstrapAuthorization: {
      kind: 'passkey_bootstrap',
      webauthn_authentication: fakeWebAuthnAuthentication(),
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    },
  };
  return { ...body, ...(overrides || {}) };
}

function makeThresholdAdapter() {
  return {
    getSchemeModule: (schemeId: string) => ({
      schemeId,
      healthz: async () => ({ ok: true }),
    }),
  };
}

async function startPasskeyBootstrapRoute(input: {
  verifyResult: { success: boolean; verified: boolean; code?: string; message?: string };
  parseSession?: ReturnType<typeof makeSessionAdapter>['parse'];
}) {
  const verifyCalls: unknown[] = [];
  const bootstrapCalls: unknown[] = [];
  const service = {
    verifyWebAuthnAuthenticationLite: async (request: unknown) => {
      verifyCalls.push(request);
      return input.verifyResult;
    },
    ecdsaHssRoleLocalBootstrap: async (request: unknown) => {
      bootstrapCalls.push(request);
      const parsedRequest = request as Awaited<ReturnType<typeof makeBootstrapBody>>;
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-hss-role-local',
          walletSessionUserId: WALLET_SESSION_USER_ID,
          rpId: RP_ID,
          subjectId: SUBJECT_ID,
          ecdsaThresholdKeyId: parsedRequest.ecdsaThresholdKeyId,
          relayerKeyId: parsedRequest.relayerKeyId,
          contextBinding32B64u: parsedRequest.contextBinding32B64u,
          publicIdentity: {
            clientPublicKey33B64u: parsedRequest.clientPublicKey33B64u,
            relayerPublicKey33B64u: b64u(
              Uint8Array.from([0x03, ...Array.from({ length: 32 }, (_, index) => index + 2)]),
            ),
            groupPublicKey33B64u: b64u(
              Uint8Array.from([0x02, ...Array.from({ length: 32 }, (_, index) => index + 3)]),
            ),
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          },
          publicTranscriptDigest32B64u: b64u(
            Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 4)),
          ),
          keyHandle: 'ecdsa-hss-role-local-key-handle',
          signingRootId: SIGNING_ROOT_ID,
          signingRootVersion: SIGNING_ROOT_VERSION,
          thresholdEcdsaPublicKeyB64u: b64u(
            Uint8Array.from([0x02, ...Array.from({ length: 32 }, (_, index) => index + 3)]),
          ),
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          relayerVerifyingShareB64u: b64u(
            Uint8Array.from([0x03, ...Array.from({ length: 32 }, (_, index) => index + 2)]),
          ),
          participantIds: PARTICIPANT_IDS,
          sessionId: parsedRequest.sessionId,
          walletSigningSessionId: parsedRequest.walletSigningSessionId,
          expiresAtMs: Date.now() + 60_000,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          remainingUses: parsedRequest.remainingUses,
        },
      };
    },
    readActiveEmailOtpEnrollment: async () => {
      throw new Error('Email OTP enrollment lookup should not run for this test');
    },
  };
  const router = createRelayRouter(service as any, {
    threshold: makeThresholdAdapter() as any,
    session: makeSessionAdapter(input.parseSession ? { parse: input.parseSession } : {}),
    logger: null,
  });
  const server = await startExpressRouter(router);
  return { server, verifyCalls, bootstrapCalls };
}

test.describe('threshold ECDSA role-local passkey bootstrap route', () => {
  test('verifies WebAuthn against the deterministic passkey bootstrap challenge', async () => {
    const body = await makeBootstrapBody();
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      expect(response.json?.ok).toBe(true);
      expect(harness.bootstrapCalls).toHaveLength(1);
      expect(harness.verifyCalls).toHaveLength(1);
      expect(harness.verifyCalls[0]).toMatchObject({
        nearAccountId: WALLET_SESSION_USER_ID,
        rpId: RP_ID,
        expectedChallenge: await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
          walletSessionUserId: WALLET_SESSION_USER_ID,
          rpId: RP_ID,
          subjectId: SUBJECT_ID,
          ecdsaThresholdKeyId: body.ecdsaThresholdKeyId as string,
          signingRootId: SIGNING_ROOT_ID,
          signingRootVersion: SIGNING_ROOT_VERSION,
          keyScope: 'evm-family',
          relayerKeyId: body.relayerKeyId as string,
          requestId: body.requestId as string,
          sessionId: body.sessionId as string,
          walletSigningSessionId: body.walletSigningSessionId as string,
          ttlMs: body.ttlMs as number,
          remainingUses: body.remainingUses as number,
          participantIds: PARTICIPANT_IDS,
        }),
      });
    } finally {
      await harness.server.close();
    }
  });

  test('rejects failed WebAuthn without bootstrapping relayer state', async () => {
    const body = await makeBootstrapBody();
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: {
        success: false,
        verified: false,
        code: 'invalid_assertion',
        message: 'Authentication assertion verification threw',
      },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      expect(response.json).toMatchObject({
        ok: false,
        code: 'invalid_assertion',
      });
      expect(harness.verifyCalls).toHaveLength(1);
      expect(harness.bootstrapCalls).toHaveLength(0);
    } finally {
      await harness.server.close();
    }
  });

  test('allows Ed25519 threshold session auth to reconnect an existing role-local ECDSA key', async () => {
    const body = await makeBootstrapBody({
      passkeyBootstrapAuthorization: undefined,
    });
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
      parseSession: async () => ({
        ok: true,
        claims: {
          kind: 'threshold_ed25519_session_v1',
          sub: WALLET_SESSION_USER_ID,
          walletId: WALLET_SESSION_USER_ID,
          sessionId: 'threshold-ed25519-login-session',
          walletSigningSessionId: body.walletSigningSessionId,
          relayerKeyId: 'ed25519-relayer-key',
          rpId: RP_ID,
          thresholdExpiresAtMs: Date.now() + 60_000,
          participantIds: PARTICIPANT_IDS,
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        },
      }),
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer threshold-ed25519-login-session',
        },
        body: JSON.stringify(body),
      });

      expect(response.json?.ok).toBe(true);
      expect(harness.verifyCalls).toHaveLength(0);
      expect(harness.bootstrapCalls).toHaveLength(1);
      expect(harness.bootstrapCalls[0]).toMatchObject({
        walletSessionUserId: WALLET_SESSION_USER_ID,
        rpId: RP_ID,
        relayerKeyId: body.relayerKeyId,
        ecdsaThresholdKeyId: body.ecdsaThresholdKeyId,
      });
    } finally {
      await harness.server.close();
    }
  });

  test('allows passkey authorization to reconnect after threshold session exhaustion', async () => {
    const bodyWithoutAuthorization = await makeBootstrapBody({
      passkeyBootstrapAuthorization: undefined,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    const body = {
      ...bodyWithoutAuthorization,
      passkeyBootstrapAuthorization: {
        kind: 'passkey_bootstrap',
        webauthn_authentication: fakeWebAuthnAuthentication(),
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      },
    };
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      expect(response.json?.ok).toBe(true);
      expect(harness.verifyCalls).toHaveLength(1);
      expect(harness.bootstrapCalls).toHaveLength(1);
      expect(harness.verifyCalls[0]).toMatchObject({
        nearAccountId: WALLET_SESSION_USER_ID,
        rpId: RP_ID,
        expectedChallenge: await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
          walletSessionUserId: WALLET_SESSION_USER_ID,
          rpId: RP_ID,
          subjectId: SUBJECT_ID,
          ecdsaThresholdKeyId: String(body.ecdsaThresholdKeyId),
          signingRootId: SIGNING_ROOT_ID,
          signingRootVersion: SIGNING_ROOT_VERSION,
          keyScope: 'evm-family',
          relayerKeyId: String(body.relayerKeyId),
          requestId: String(body.requestId),
          sessionId: String(body.sessionId),
          walletSigningSessionId: String(body.walletSigningSessionId),
          ttlMs: Number(body.ttlMs),
          remainingUses: Number(body.remainingUses),
          participantIds: PARTICIPANT_IDS,
        }),
      });
    } finally {
      await harness.server.close();
    }
  });

  test('rejects runtime-scope mismatch before WebAuthn verification', async () => {
    const mismatchedSigningRootVersion = 'wrong-version';
    const body = await makeBootstrapBody({
      signingRootVersion: mismatchedSigningRootVersion,
      ecdsaThresholdKeyId: await computeEcdsaHssRoleLocalThresholdKeyId({
        walletSessionUserId: WALLET_SESSION_USER_ID,
        rpId: RP_ID,
        subjectId: SUBJECT_ID,
        signingRootId: SIGNING_ROOT_ID,
        signingRootVersion: mismatchedSigningRootVersion,
      }),
    });
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      expect(response.json).toMatchObject({
        ok: false,
        code: 'identity_mismatch',
      });
      expect(harness.verifyCalls).toHaveLength(0);
      expect(harness.bootstrapCalls).toHaveLength(0);
    } finally {
      await harness.server.close();
    }
  });

  test('rejects secret-bearing bootstrap fields before WebAuthn verification', async () => {
    const forbiddenFields = [
      'yClient32LeB64u',
      'clientRootShare32B64u',
      'clientShare32B64u',
      'xClient32B64u',
      'yRelayer32LeB64u',
      'xRelayer32B64u',
      'relayerShare32B64u',
      'serverExportShare32B64u',
      'canonicalPrivateKeyHex',
      'privateKeyHex',
    ] as const;
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      for (const field of forbiddenFields) {
        const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(await makeBootstrapBody({ [field]: 'secret-material' })),
        });

        expect(response.json, field).toMatchObject({
          ok: false,
          code: 'invalid_body',
        });
      }
      expect(harness.verifyCalls).toHaveLength(0);
      expect(harness.bootstrapCalls).toHaveLength(0);
    } finally {
      await harness.server.close();
    }
  });

  test('rejects malformed client public keys before WebAuthn verification', async () => {
    const malformedPublicKeys = [
      b64u(Uint8Array.from([0x02, ...Array.from({ length: 31 }, (_, index) => index)])),
      b64u(Uint8Array.from([0x04, ...Array.from({ length: 32 }, (_, index) => index)])),
    ] as const;
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      for (const clientPublicKey33B64u of malformedPublicKeys) {
        const response = await fetchJson(`${harness.server.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(await makeBootstrapBody({ clientPublicKey33B64u })),
        });

        expect(response.json, clientPublicKey33B64u).toMatchObject({
          ok: false,
          code: 'invalid_body',
        });
      }
      expect(harness.verifyCalls).toHaveLength(0);
      expect(harness.bootstrapCalls).toHaveLength(0);
    } finally {
      await harness.server.close();
    }
  });
});
