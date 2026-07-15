import { expect, test } from '@playwright/test';
import type { RouterAbEd25519YaoExportAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import { buildRouterAbEd25519YaoExportAdmissionBodyV1 } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';

const PARTICIPANT_IDS = [11, 29] as const;

function bytes(value: number): number[] {
  return new Array<number>(32).fill(value);
}

function exportAdmissionRequest(): RouterAbEd25519YaoExportAdmissionRequestV1 {
  return {
    scope: {
      lifecycle_id: 'export-lifecycle-1',
      root_share_epoch: 'root-epoch-1',
      account_id: 'wallet-1',
      wallet_session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      signing_worker_id: 'signing-worker-1',
    },
    application_binding: {
      wallet_id: 'wallet-1',
      near_ed25519_signing_key_id: 'near-key-1',
      signing_root_id: 'project:test',
      key_creation_signer_slot: 1,
    },
    participant_ids: PARTICIPANT_IDS,
    registered_public_key: bytes(12),
    state_epoch: 1,
    runtime_policy_binding: bytes(13),
    authorization: {
      confirmation_digest: bytes(14),
      authorization_digest: bytes(15),
      nonce: bytes(16),
      issued_at_ms: 1_000,
      expires_at_ms: 61_000,
    },
  };
}

function authenticationCredential(): WebAuthnAuthenticationCredential {
  return {
    id: 'credential-1',
    rawId: 'credential-1',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: 'user-handle',
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: 'owned-client-root-secret',
          second: 'other-prf-secret',
        },
      },
    },
  };
}

test.describe('Ed25519 Yao export browser boundary', () => {
  test('removes PRF results from the server-bound authentication credential', () => {
    const protocol = exportAdmissionRequest();
    const body = buildRouterAbEd25519YaoExportAdmissionBodyV1({
      protocol,
      authorization: {
        kind: 'passkey',
        webauthnAuthentication: authenticationCredential(),
      },
    });
    const serialized = JSON.stringify(body);

    expect(body.protocol).toBe(protocol);
    expect(body.authorization.kind).toBe('passkey');
    if (body.authorization.kind !== 'passkey') throw new Error('passkey authorization required');
    expect(body.authorization.webauthnAuthentication.clientExtensionResults).toBeNull();
    expect(serialized).not.toContain('owned-client-root-secret');
    expect(serialized).not.toContain('other-prf-secret');
  });

  test('encodes Email OTP factor authorization without passkey fields', () => {
    const protocol = exportAdmissionRequest();
    const body = buildRouterAbEd25519YaoExportAdmissionBodyV1({
      protocol,
      authorization: {
        kind: 'email_otp_factor',
        providerSubjectId: 'google:ed25519-export-user',
      },
    });

    expect(body).toEqual({
      protocol,
      authorization: {
        kind: 'email_otp_factor',
        providerSubjectId: 'google:ed25519-export-user',
      },
    });
    expect(JSON.stringify(body)).not.toContain('webauthn');
  });
});
