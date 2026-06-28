import { expect, test } from '@playwright/test';
import { createRouterApiRouter } from '@server/router/express-adaptor';
import {
  computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
  type EcdsaHssClientSharePublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { base64UrlEncode } from '@shared/utils/encoders';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import { fetchJson, makeSessionAdapter, startExpressRouter } from './helpers';

const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-passkey-role-local',
  projectId: 'project-passkey-role-local',
  envId: 'env-passkey-role-local',
  signingRootVersion: 'v1',
};
const WALLET_SESSION_USER_ID = 'passkey-wallet-user';
const WALLET_KEY_ID = 'wallet-key-passkey-role-local';
const NEAR_ACCOUNT_ID = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const ED25519_KEY_SCOPE_ID = 'passkey-wallet-user-ed25519-scope';
const RP_ID = 'wallet.example.test';
const SUBJECT_ID = WALLET_SESSION_USER_ID;
const SIGNING_ROOT_ID = `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`;
const SIGNING_ROOT_VERSION = RUNTIME_POLICY_SCOPE.signingRootVersion;
const PARTICIPANT_IDS = [1, 2];
const PASSKEY_BOOTSTRAP_HEADERS = {
  'Content-Type': 'application/json',
  Origin: `https://${RP_ID}`,
} as const;
const TEST_ROUTER_AB_PUBLIC_KEYSET = {
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: `x25519:${'11'.repeat(32)}`,
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: `x25519:${'22'.repeat(32)}`,
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: { role: 'signer_a', verifying_key_hex: 'aa'.repeat(32) },
    deriver_b: { role: 'signer_b', verifying_key_hex: 'bb'.repeat(32) },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'signing-worker-output-epoch',
    public_key: `x25519:${'33'.repeat(32)}`,
  },
} satisfies RouterAbPublicKeysetV2;

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
    walletId: WALLET_SESSION_USER_ID,
    walletKeyId: WALLET_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletId: WALLET_SESSION_USER_ID,
    walletKeyId: WALLET_KEY_ID,
  });
  const body = {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: WALLET_SESSION_USER_ID,
    walletKeyId: WALLET_KEY_ID,
    ecdsaThresholdKeyId,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    keyScope: 'evm-family',
    relayerKeyId,
    hssClientSharePublicKey33B64u: b64u(
      Uint8Array.from([0x02, ...Array.from({ length: 32 }, (_, index) => index)]),
    ),
    clientShareRetryCounter: 0,
    contextBinding32B64u: b64u(Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1))),
    requestId: 'passkey-role-local-request-1',
    sessionId: 'threshold-ecdsa-session-1',
    signingGrantId: 'signing-grant-1',
    ttlMs: 60_000,
    remainingUses: 2,
    participantIds: PARTICIPANT_IDS,
    passkeyBootstrapAuthorization: {
      kind: 'passkey_bootstrap',
      rpId: RP_ID,
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
  const rootProofCalls: unknown[] = [];
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
          walletId: WALLET_SESSION_USER_ID,
          walletKeyId: WALLET_KEY_ID,
          ecdsaThresholdKeyId: parsedRequest.ecdsaThresholdKeyId,
          relayerKeyId: parsedRequest.relayerKeyId,
          contextBinding32B64u: parsedRequest.contextBinding32B64u,
          publicIdentity: {
            hssClientSharePublicKey33B64u: parsedRequest.hssClientSharePublicKey33B64u,
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
          clientShareRetryCounter: Number(parsedRequest.clientShareRetryCounter),
          relayerShareRetryCounter: 0,
          participantIds: PARTICIPANT_IDS,
          thresholdSessionId: parsedRequest.sessionId,
          signingGrantId: parsedRequest.signingGrantId,
          expiresAtMs: Date.now() + 60_000,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          remainingUses: parsedRequest.remainingUses,
        },
      };
    },
    verifyEcdsaHssRoleLocalClientRootProofForExistingKey: async (request: unknown) => {
      rootProofCalls.push(request);
      return { ok: true, value: { keyHandle: 'ecdsa-hss-role-local-key-handle' } };
    },
    getThresholdSigningService: () => ({
      getRouterAbNormalSigningWorkerId: () => 'signing-worker-passkey-role-local',
    }),
    readActiveEmailOtpEnrollment: async () => {
      throw new Error('Email OTP enrollment lookup should not run for this test');
    },
  };
  const router = createRouterApiRouter(service as any, {
    threshold: makeThresholdAdapter() as any,
    session: makeSessionAdapter(input.parseSession ? { parse: input.parseSession } : {}),
    routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    logger: null,
  });
  const server = await startExpressRouter(router);
  return { server, verifyCalls, bootstrapCalls, rootProofCalls };
}

test.describe('threshold ECDSA role-local passkey bootstrap route', () => {
  test('verifies WebAuthn against the deterministic passkey bootstrap challenge', async () => {
    const body = await makeBootstrapBody();
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: PASSKEY_BOOTSTRAP_HEADERS,
        body: JSON.stringify(body),
      });

      expect(response.json?.ok).toBe(true);
      expect(harness.bootstrapCalls).toHaveLength(1);
      expect(harness.verifyCalls).toHaveLength(1);
      expect(harness.verifyCalls[0]).toMatchObject({
        rpId: RP_ID,
        expectedChallenge: await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
          walletId: WALLET_SESSION_USER_ID,
          walletKeyId: WALLET_KEY_ID,
          rpId: RP_ID,
          ecdsaThresholdKeyId: body.ecdsaThresholdKeyId as string,
          signingRootId: SIGNING_ROOT_ID,
          signingRootVersion: SIGNING_ROOT_VERSION,
          keyScope: 'evm-family',
          relayerKeyId: body.relayerKeyId as string,
          requestId: body.requestId as string,
          sessionId: body.sessionId as string,
          signingGrantId: body.signingGrantId as string,
          ttlMs: body.ttlMs as number,
          remainingUses: body.remainingUses as number,
          participantIds: PARTICIPANT_IDS,
        }),
      });
    } finally {
      await harness.server.close();
    }
  });

  test('rejects cookie sessionKind before bootstrapping relayer state', async () => {
    const body = await makeBootstrapBody({ sessionKind: 'cookie' });
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: PASSKEY_BOOTSTRAP_HEADERS,
        body: JSON.stringify(body),
      });

      expect(response.status).toBe(400);
      expect(response.headers.get('set-cookie')).toBeNull();
      expect(response.json).toMatchObject({
        ok: false,
        code: 'invalid_body',
        message: 'Router A/B ECDSA-HSS bootstrap requires sessionKind=jwt',
      });
      expect(harness.verifyCalls).toHaveLength(0);
      expect(harness.bootstrapCalls).toHaveLength(0);
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
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: PASSKEY_BOOTSTRAP_HEADERS,
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

  test('rejects object-shaped fake WebAuthn before bootstrapping relayer state', async () => {
    const fakeObjectAuthentication = { fake: true, response: { signature: 'unsigned' } };
    const body = await makeBootstrapBody({
      passkeyBootstrapAuthorization: {
        kind: 'passkey_bootstrap',
        rpId: RP_ID,
        webauthn_authentication: fakeObjectAuthentication,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      },
    });
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: {
        success: false,
        verified: false,
        code: 'invalid_assertion',
        message: 'Invalid passkey bootstrap authorization',
      },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: PASSKEY_BOOTSTRAP_HEADERS,
        body: JSON.stringify(body),
      });

      expect(response.json).toMatchObject({
        ok: false,
        code: 'invalid_assertion',
      });
      expect(harness.verifyCalls).toHaveLength(1);
      expect(harness.verifyCalls[0]).toMatchObject({
        webauthn_authentication: fakeObjectAuthentication,
      });
      expect(harness.bootstrapCalls).toHaveLength(0);
    } finally {
      await harness.server.close();
    }
  });

  test('accepts Ed25519 threshold session auth with client-root proof for existing role-local ECDSA key', async () => {
    const bodyWithoutProof = await makeBootstrapBody({
      passkeyBootstrapAuthorization: undefined,
    });
    const body = {
      ...bodyWithoutProof,
      clientRootProof: {
        version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
        clientRootPublicKey33B64u: b64u(
          Uint8Array.from([0x03, ...Array.from({ length: 32 }, (_, index) => index + 9)]),
        ),
        digest32B64u: await computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u({
          walletId: String(bodyWithoutProof.walletId),
          walletKeyId: String(bodyWithoutProof.walletKeyId),
          ecdsaThresholdKeyId: String(bodyWithoutProof.ecdsaThresholdKeyId),
          signingRootId: String(bodyWithoutProof.signingRootId),
          signingRootVersion: String(bodyWithoutProof.signingRootVersion),
          keyScope: 'evm-family',
          relayerKeyId: String(bodyWithoutProof.relayerKeyId),
          hssClientSharePublicKey33B64u: String(
            bodyWithoutProof.hssClientSharePublicKey33B64u,
          ) as EcdsaHssClientSharePublicKey33B64u,
          clientShareRetryCounter: Number(bodyWithoutProof.clientShareRetryCounter),
          contextBinding32B64u: String(bodyWithoutProof.contextBinding32B64u),
          requestId: String(bodyWithoutProof.requestId),
          sessionId: String(bodyWithoutProof.sessionId),
          signingGrantId: String(bodyWithoutProof.signingGrantId),
          ttlMs: Number(bodyWithoutProof.ttlMs),
          remainingUses: Number(bodyWithoutProof.remainingUses),
          participantIds: PARTICIPANT_IDS,
        }),
        signature65B64u: b64u(new Uint8Array(65).fill(9)),
      },
    };
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
      parseSession: async () => ({
        ok: true,
        claims: {
          kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
          sub: WALLET_SESSION_USER_ID,
          walletId: WALLET_SESSION_USER_ID,
          nearAccountId: NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
          thresholdSessionId: 'threshold-ed25519-login-session',
          signingGrantId: body.signingGrantId,
          relayerKeyId: 'ed25519-relayer-key',
          rpId: RP_ID,
          thresholdExpiresAtMs: Date.now() + 60_000,
          participantIds: PARTICIPANT_IDS,
          runtimePolicyScope: RUNTIME_POLICY_SCOPE,
          routerAbNormalSigning: {
            kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
            signingWorkerId: 'signing-worker-passkey-role-local',
          },
        },
      }),
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer threshold-ed25519-login-session',
        },
        body: JSON.stringify(body),
      });

      expect(response.json?.ok).toBe(true);
      expect(harness.verifyCalls).toHaveLength(0);
      expect(harness.rootProofCalls).toHaveLength(1);
      expect(harness.bootstrapCalls).toHaveLength(1);
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
        rpId: RP_ID,
        webauthn_authentication: fakeWebAuthnAuthentication(),
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      },
    };
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: PASSKEY_BOOTSTRAP_HEADERS,
        body: JSON.stringify(body),
      });

      expect(response.json?.ok).toBe(true);
      expect(harness.verifyCalls).toHaveLength(1);
      expect(harness.bootstrapCalls).toHaveLength(1);
      expect(harness.verifyCalls[0]).toMatchObject({
        rpId: RP_ID,
        expectedChallenge: await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
          walletId: WALLET_SESSION_USER_ID,
          walletKeyId: WALLET_KEY_ID,
          rpId: RP_ID,
          ecdsaThresholdKeyId: String(body.ecdsaThresholdKeyId),
          signingRootId: SIGNING_ROOT_ID,
          signingRootVersion: SIGNING_ROOT_VERSION,
          keyScope: 'evm-family',
          relayerKeyId: String(body.relayerKeyId),
          requestId: String(body.requestId),
          sessionId: String(body.sessionId),
          signingGrantId: String(body.signingGrantId),
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
        walletId: WALLET_SESSION_USER_ID,
        walletKeyId: WALLET_KEY_ID,
        signingRootId: SIGNING_ROOT_ID,
        signingRootVersion: mismatchedSigningRootVersion,
      }),
    });
    const harness = await startPasskeyBootstrapRoute({
      verifyResult: { success: true, verified: true },
    });
    try {
      const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
        method: 'POST',
        headers: PASSKEY_BOOTSTRAP_HEADERS,
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
        const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
          method: 'POST',
          headers: PASSKEY_BOOTSTRAP_HEADERS,
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
      for (const hssClientSharePublicKey33B64u of malformedPublicKeys) {
        const response = await fetchJson(`${harness.server.baseUrl}/router-ab/ecdsa-hss/bootstrap`, {
          method: 'POST',
          headers: PASSKEY_BOOTSTRAP_HEADERS,
          body: JSON.stringify(await makeBootstrapBody({ hssClientSharePublicKey33B64u })),
        });

        expect(response.json, hssClientSharePublicKey33B64u).toMatchObject({
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
