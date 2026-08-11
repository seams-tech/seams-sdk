import { expect, test } from '@playwright/test';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import type { Ed25519SessionPolicy } from '../../packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy';
import type {
  ThresholdCredentialStorePort,
  ThresholdWebAuthnPromptPort,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/crypto/webauthn';
import { connectEd25519Session } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  issueEd25519OperationStepUpAuthorization,
  mintEd25519WalletSession,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';
import { buildRouterAbEd25519NearTransactionPrepareRequestV2 } from '../../packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning';

const PUBLISHABLE_KEY = 'pk_test_refresh';
const PRF_FIRST_B64U = 'cHJmLWZpcnN0LXNlY3JldA';
/* Refactor 90 replaced the standalone step-up grant row with the evidence set
   the atomic admission binds, so the response names a digest, not a grant id. */
const OPERATION_STEP_UP_EVIDENCE_SET_DIGEST = base64UrlEncode(new Uint8Array(32).fill(9));

type RefreshFetchCapture = {
  authorization: string;
  body: string;
  credentials: RequestCredentials | undefined;
};

let activeRefreshFetchCapture: RefreshFetchCapture | null = null;
let activeRefreshResponseIncludesRuntimePolicyScope = true;
let activeOperationStepUpFetchCapture: RefreshFetchCapture | null = null;
let activeOperationStepUpResponseBody: Record<string, unknown> | null = null;

const unusedCredentialStore: ThresholdCredentialStorePort = {
  async resolveProfileAccountContext() {
    throw new Error('credential store must not be used with supplied authorization');
  },
  async listProfileAuthenticators() {
    throw new Error('credential store must not be used with supplied authorization');
  },
  async listAccountSigners() {
    throw new Error('credential store must not be used with supplied authorization');
  },
  async selectProfileAuthenticatorsForPrompt() {
    throw new Error('credential store must not be used with supplied authorization');
  },
};

const unusedTouchIdPrompt: ThresholdWebAuthnPromptPort = {
  getRpId() {
    return 'localhost';
  },
  async getAuthenticationCredentialsSerializedForChallengeB64u() {
    throw new Error('Touch ID must not be used with supplied authorization');
  },
};

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
      walletSessionId: 'wallet-session-1',
      quotaId: 'quota-1',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      remainingUses: 3,
      ...(activeRefreshResponseIncludesRuntimePolicyScope
        ? {
            runtimePolicyScope: {
              orgId: 'org-refresh',
              projectId: 'project-refresh',
              envId: 'env-refresh',
              signingRootVersion: 'root-version-refresh',
            },
          }
        : {}),
      jwt: 'refreshed-wallet-session-jwt',
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

async function operationStepUpFetch(
  _input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const capture = activeOperationStepUpFetchCapture;
  if (!capture) throw new Error('operation step-up fetch capture is unavailable');
  capture.authorization = new Headers(init?.headers).get('Authorization') || '';
  capture.body = String(init?.body || '');
  capture.credentials = init?.credentials;
  const materialRecovery = { kind: 'not_requested' };
  return new Response(
    JSON.stringify(
      activeOperationStepUpResponseBody || {
        ok: true,
        kind: 'verified_step_up',
        authorization: {
          kind: 'operation_step_up',
          evidence_set_digest: OPERATION_STEP_UP_EVIDENCE_SET_DIGEST,
        },
        expiresAtMs: Date.now() + 60_000,
        materialRecovery,
      },
    ),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

async function operationStepUpPrepareRequest() {
  const digest = base64UrlEncode(new Uint8Array(32).fill(7));
  return (
    await buildRouterAbEd25519NearTransactionPrepareRequestV2({
      scope: {
        request_id: 'operation-step-up-request',
        account_id: 'frost-vermillion-k7p9m2',
        authorization: {
          kind: 'operation_step_up',
        },
        material_activation: {
          kind: 'mpc_material_activation_ref',
          activation_id: 'activation-near-email-otp',
          capability: 'capability-near-email-otp',
          material_owner: 'frost-vermillion-k7p9m2',
          key_binding: 'near-key-binding',
          lifecycle_binding: 'near-lifecycle-binding',
          signing_worker: 'near-signing-worker',
        },
        signing_worker_id: 'near-signing-worker',
      },
      expiresAtMs: Date.now() + 60_000,
      operationId: 'near-operation-email-otp',
      operationFingerprint: 'near-operation-fingerprint',
      displayDigestB64u: digest,
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      transactions: [
        {
          receiverId: 'receiver.testnet',
          actionFingerprint: 'near-action-fingerprint',
        },
      ],
      unsignedTransactionBorshB64u: 'AQID',
      expectedSigningDigestB64u: 'A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc-4E',
    })
  ).request;
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

test('Wallet Session mint uses environment auth with a PRF-redacted WebAuthn assertion', async () => {
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
        kind: 'threshold_session_policy_webauthn',
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
      thresholdSessionId: 'threshold-session-1',
      walletSessionId: 'wallet-session-1',
      quotaId: 'quota-1',
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
    activeRefreshResponseIncludesRuntimePolicyScope = true;
    globalThis.fetch = originalFetch;
  }
});

test('Ed25519 session connection rejects success without a runtime policy scope', async () => {
  const originalFetch = globalThis.fetch;
  const capture: RefreshFetchCapture = {
    authorization: '',
    body: '',
    credentials: undefined,
  };
  activeRefreshFetchCapture = capture;
  activeRefreshResponseIncludesRuntimePolicyScope = false;
  globalThis.fetch = refreshWalletSessionFetch;

  try {
    const authority = buildPasskeyWalletAuthAuthority({
      walletId: 'refresh-wallet',
      rpId: 'localhost',
      credentialIdB64u: 'credential-id-b64u',
    });
    const result = await connectEd25519Session({
      credentialStore: unusedCredentialStore,
      touchIdPrompt: unusedTouchIdPrompt,
      relayerUrl: 'https://relay.example.test',
      relayerKeyId: 'ed25519:relayer-key',
      walletId: 'refresh-wallet',
      nearAccountId: 'refresh.testnet',
      nearEd25519SigningKeyId: 'refresh.testnet',
      authority: {
        kind: 'wallet_auth_authority',
        authority,
      },
      participantIds: [1, 2],
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'local-signing-worker',
      },
      auth: {
        kind: 'threshold_session_policy_webauthn',
        policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: refreshCredentialFixture(),
          rpId: 'localhost',
        }),
      },
    });

    expect(result).toEqual({
      ok: false,
      code: 'invalid_response',
      message: 'Threshold Ed25519 session mint returned incomplete lifecycle metadata',
    });
  } finally {
    activeRefreshFetchCapture = null;
    activeRefreshResponseIncludesRuntimePolicyScope = true;
    globalThis.fetch = originalFetch;
  }
});

test('Email OTP Ed25519 step-up sends exact operation proof without material recovery or a reusable session', async () => {
  const originalFetch = globalThis.fetch;
  const capture: RefreshFetchCapture = {
    authorization: '',
    body: '',
    credentials: undefined,
  };
  activeOperationStepUpFetchCapture = capture;
  globalThis.fetch = operationStepUpFetch;

  try {
    const authority = buildEmailOtpWalletAuthAuthority({
      walletId: 'frost-vermillion-k7p9m2',
      provider: 'email',
      providerUserId: 'email-user-operation-step-up',
      emailHashHex: 'email-hash-operation-step-up',
    });
    const authorityRef = await walletAuthAuthorityRef({ authority });
    const result = await issueEd25519OperationStepUpAuthorization({
      relayerUrl: 'https://relay.example.test',
      credential: { kind: 'app_session_cookie' },
      normalSigningRequest: await operationStepUpPrepareRequest(),
      displayDigest: base64UrlEncode(new Uint8Array(32).fill(7)),
      proof: {
        kind: 'email_otp',
        authorityRef,
        providerSubjectId: authority.factor.providerUserId,
        challengeId: 'email-otp-challenge',
        otpCode: '123456',
      },
      materialRecovery: { kind: 'not_requested' },
    });

    expect(result).toEqual({
      kind: 'verified_step_up',
      authorization: {
        kind: 'operation_step_up',
        evidence_set_digest: OPERATION_STEP_UP_EVIDENCE_SET_DIGEST,
      },
      expiresAtMs: result.expiresAtMs,
      materialRecovery: { kind: 'not_requested' },
    });
    expect(capture.credentials).toBe('include');
    expect(capture.authorization).toBe('');
    const body = JSON.parse(capture.body) as Record<string, unknown>;
    expect(body).toMatchObject({
      kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1',
      proof: {
        kind: 'email_otp',
        authority_ref: authorityRef,
        provider_subject_id: 'email-user-operation-step-up',
        challenge_id: 'email-otp-challenge',
        otp_code: '123456',
      },
      materialRecovery: { kind: 'not_requested' },
    });
    expect(capture.body).not.toContain('walletSessionId');
    expect(capture.body).not.toContain('thresholdSessionId');
    expect(capture.body).not.toContain('remainingUses');
  } finally {
    activeOperationStepUpFetchCapture = null;
    activeOperationStepUpResponseBody = null;
    globalThis.fetch = originalFetch;
  }
});

test('Ed25519 operation step-up rejects unexpected success-response fields', async () => {
  const originalFetch = globalThis.fetch;
  const capture: RefreshFetchCapture = {
    authorization: '',
    body: '',
    credentials: undefined,
  };
  activeOperationStepUpFetchCapture = capture;
  activeOperationStepUpResponseBody = {
    ok: true,
    kind: 'verified_step_up',
    authorization: {
      kind: 'operation_step_up',
      evidence_set_digest: OPERATION_STEP_UP_EVIDENCE_SET_DIGEST,
    },
    expiresAtMs: Date.now() + 60_000,
    materialRecovery: { kind: 'not_requested' },
    thresholdSessionId: 'forbidden-reusable-session',
  };
  globalThis.fetch = operationStepUpFetch;

  try {
    const authority = buildEmailOtpWalletAuthAuthority({
      walletId: 'frost-vermillion-k7p9m2',
      provider: 'email',
      providerUserId: 'email-user-operation-step-up',
      emailHashHex: 'email-hash-operation-step-up',
    });
    const authorityRef = await walletAuthAuthorityRef({ authority });
    await expect(
      issueEd25519OperationStepUpAuthorization({
        relayerUrl: 'https://relay.example.test',
        credential: { kind: 'app_session_cookie' },
        normalSigningRequest: await operationStepUpPrepareRequest(),
        displayDigest: base64UrlEncode(new Uint8Array(32).fill(7)),
        proof: {
          kind: 'email_otp',
          authorityRef,
          providerSubjectId: authority.factor.providerUserId,
          challengeId: 'email-otp-challenge',
          otpCode: '123456',
        },
        materialRecovery: { kind: 'not_requested' },
      }),
    ).rejects.toThrow('operation step-up response contains unexpected fields');
  } finally {
    activeOperationStepUpFetchCapture = null;
    activeOperationStepUpResponseBody = null;
    globalThis.fetch = originalFetch;
  }
});
