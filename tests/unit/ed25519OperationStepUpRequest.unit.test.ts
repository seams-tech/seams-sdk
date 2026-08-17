import { expect, test } from '@playwright/test';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { parseThresholdEd25519OperationStepUpGrantRequest } from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/session/thresholdEd25519RequestValidation';
import { issueEd25519OperationStepUpAuthorization } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';
import { buildRouterAbEd25519NearTransactionPrepareRequestV2 } from '../../packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';

function passkeyCredential(): WebAuthnAuthenticationCredential {
  return {
    id: 'step-up-credential',
    rawId: 'step-up-credential-b64u',
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: 'user-handle',
    },
    clientExtensionResults: {
      prf: { results: { first: undefined, second: undefined } },
    },
  };
}

async function normalSigningRequest() {
  const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  return (
    await buildRouterAbEd25519NearTransactionPrepareRequestV2({
      scope: {
        request_id: 'step-up-request',
        account_id: 'wallet-step-up',
        authorization: { kind: 'operation_step_up' },
        material_activation: {
          kind: 'mpc_material_activation_ref',
          activation_id: 'step-up-activation',
          capability: 'step-up-capability',
          material_owner: 'wallet-step-up',
          key_binding: 'step-up-key-binding',
          lifecycle_binding: 'step-up-lifecycle-binding',
          signing_worker: 'step-up-worker',
        },
        signing_worker_id: 'step-up-worker',
      },
      expiresAtMs: Date.now() + 60_000,
      operationId: 'near-step-up-operation',
      operationFingerprint: 'sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      displayDigestB64u: digest,
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      transactions: [{ receiverId: 'receiver.testnet', actionFingerprint: 'action' }],
      unsignedTransactionBorshB64u: 'AQID',
      expectedSigningDigestB64u: 'A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc-4E',
    })
  ).request;
}

test('Ed25519 operation step-up emits the grant wire kind accepted by its wallet-session route', async () => {
  const originalFetch = globalThis.fetch;
  let requestInit: RequestInit | undefined;
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: 'wallet-step-up',
    rpId: 'localhost',
    credentialIdB64u: 'step-up-credential-b64u',
  });
  const credential = passkeyCredential();

  globalThis.fetch = async (_input, init) => {
    requestInit = init;
    return new Response(
      JSON.stringify({
        ok: true,
        kind: 'verified_step_up',
        authorization: {
          kind: 'operation_step_up',
          evidence_set_digest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
        expiresAtMs: Date.now() + 60_000,
        materialRecovery: { kind: 'not_requested' },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  };

  try {
    const issued = await issueEd25519OperationStepUpAuthorization({
      relayerUrl: 'https://relay.example.test',
      normalSigningRequest: await normalSigningRequest(),
      displayDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      proof: { kind: 'passkey', authority, credential },
      credential: { kind: 'operation_step_up' },
      materialRecovery: { kind: 'not_requested' },
    });

    expect(requestInit?.credentials).toBe('omit');
    expect(new Headers(requestInit?.headers).has('Authorization')).toBe(false);
    const body = JSON.parse(String(requestInit?.body)) as Record<string, unknown>;
    expect(body).toMatchObject({
      kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1',
      proof: {
        kind: 'passkey',
        authority,
        webauthn_authentication: {
          id: credential.id,
          rawId: credential.rawId,
          clientExtensionResults: null,
        },
      },
    });
    expect(body).not.toHaveProperty('sessionKind');

    expect(issued.authorization).toEqual({
      kind: 'operation_step_up',
      evidence_set_digest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    });

    const parsed = parseThresholdEd25519OperationStepUpGrantRequest(body);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error(parsed.body.message);
    expect(parsed.request.proof).toMatchObject({ kind: 'passkey', authority });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
