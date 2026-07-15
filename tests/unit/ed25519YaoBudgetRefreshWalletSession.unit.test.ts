import { expect, test } from '@playwright/test';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import type { Ed25519SessionPolicy } from '../../packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  mintEd25519WalletSession,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';

const PUBLISHABLE_KEY = 'pk_test_refresh';
const PRF_FIRST_B64U = 'cHJmLWZpcnN0LXNlY3JldA';

type RefreshFetchCapture = {
  authorization: string;
  body: string;
  credentials: RequestCredentials | undefined;
};

let activeRefreshFetchCapture: RefreshFetchCapture | null = null;

async function refreshWalletSessionFetch(
  _input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const capture = activeRefreshFetchCapture;
  if (!capture) throw new Error('refresh fetch capture is unavailable');
  capture.authorization = new Headers(init?.headers).get('Authorization') || '';
  capture.body = String(init?.body || '');
  capture.credentials = init?.credentials;
  return new Response(
    JSON.stringify({
      ok: true,
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'signing-grant-1',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      remainingUses: 3,
      jwt: 'refreshed-wallet-session-jwt',
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

function refreshCredentialFixture(): WebAuthnAuthenticationCredential {
  return {
    id: 'credential-id',
    rawId: 'credential-id-b64u',
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: 'client-data-json-b64u',
      authenticatorData: 'authenticator-data-b64u',
      signature: 'signature-b64u',
      userHandle: undefined,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: PRF_FIRST_B64U,
          second: undefined,
        },
      },
    },
  };
}

function refreshSessionPolicyFixture(): Ed25519SessionPolicy {
  return {
    version: 'threshold_session_v1',
    nearAccountId: 'refresh.testnet',
    nearEd25519SigningKeyId: 'refresh.testnet',
    authority: buildPasskeyWalletAuthAuthority({
      walletId: 'refresh-wallet',
      rpId: 'localhost',
      credentialIdB64u: 'credential-id-b64u',
    }),
    relayerKeyId: 'ed25519:relayer-key',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    runtimePolicyScope: {
      orgId: 'org-refresh',
      projectId: 'project-refresh',
      envId: 'env-refresh',
      signingRootVersion: 'root-version-refresh',
    },
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'local-signing-worker',
    },
    participantIds: [1, 2],
    ttlMs: 60_000,
    remainingUses: 3,
  };
}

test('Yao budget refresh uses environment auth with a PRF-redacted WebAuthn assertion', async () => {
  const originalFetch = globalThis.fetch;
  const capture: RefreshFetchCapture = {
    authorization: '',
    body: '',
    credentials: undefined,
  };
  activeRefreshFetchCapture = capture;
  globalThis.fetch = refreshWalletSessionFetch;

  try {
    const result = await mintEd25519WalletSession({
      relayerUrl: 'https://relay.example.test',
      sessionKind: 'jwt',
      relayerKeyId: 'ed25519:relayer-key',
      sessionPolicy: refreshSessionPolicyFixture(),
      auth: {
        kind: 'router_ab_ed25519_yao_budget_refresh_v1',
        policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: refreshCredentialFixture(),
          rpId: 'localhost',
        }),
      },
      projectEnvironmentId: 'env-refresh',
      publishableKey: PUBLISHABLE_KEY,
    });

    expect(result).toMatchObject({
      ok: true,
      sessionId: 'threshold-session-1',
      signingGrantId: 'signing-grant-1',
      remainingUses: 3,
      jwt: 'refreshed-wallet-session-jwt',
    });
    expect(capture.authorization).toBe(`Bearer ${PUBLISHABLE_KEY}`);
    expect(capture.credentials).toBe('omit');
    expect(capture.body).toContain('"webauthn_authentication"');
    expect(capture.body).toContain('"clientExtensionResults":null');
    expect(capture.body).toContain('"signature":"signature-b64u"');
    expect(capture.body).not.toContain(PRF_FIRST_B64U);
    expect(capture.body).toContain('"projectEnvironmentId":"env-refresh"');
  } finally {
    activeRefreshFetchCapture = null;
    globalThis.fetch = originalFetch;
  }
});
