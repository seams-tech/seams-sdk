import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from '@/core/signingEngine/threshold/workflows/thresholdEcdsaHssTransport';
import {
  initSync as initHssClientSignerWasmSync,
  threshold_ecdsa_hss_finalize_client_request,
  threshold_ecdsa_hss_prepare_client_request,
  threshold_ecdsa_hss_prepare_session,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';

const TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U = Buffer.from(
  new Uint8Array(32).fill(7),
).toString('base64url');
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function fakeWebAuthnAuthentication(): Record<string, unknown> {
  return {
    id: 'test',
    rawId: 'test',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'test',
      authenticatorData: 'test',
      signature: 'test',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

async function createHiddenEvalBootstrapMessages(args: {
  ceremonyId: string;
  preparedServerSessionB64u: string;
  serverAssistInitB64u: string;
  clientRootShare32B64u: string;
  nearAccountId: string;
}): Promise<{ requestMessageB64u: string; createFinalizeMessage(responseMessageB64u: string): Promise<string> }> {
  ensureHssClientSignerWasm();
  const preparedClientSession = threshold_ecdsa_hss_prepare_session({
    nearAccountId: args.nearAccountId,
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
    clientRootShare32B64u: args.clientRootShare32B64u,
  }) as { evaluatorDriverStateB64u: string };
  const clientRequest = threshold_ecdsa_hss_prepare_client_request({
    evaluatorDriverStateB64u: String(preparedClientSession.evaluatorDriverStateB64u || ''),
    serverAssistInitMessageB64u: args.serverAssistInitB64u,
    clientRootShare32B64u: args.clientRootShare32B64u,
  }) as { clientEvalRequestB64u: string };
  return {
    requestMessageB64u: encodeThresholdEcdsaHssHiddenEvalRequestMessage({
      ceremonyId: args.ceremonyId,
      preparedServerSessionB64u: args.preparedServerSessionB64u,
      serverAssistInitB64u: args.serverAssistInitB64u,
      clientEvalRequestB64u: String(clientRequest.clientEvalRequestB64u || ''),
    }),
    async createFinalizeMessage(responseMessageB64u: string): Promise<string> {
      const parsedResponse =
        parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
      if (!parsedResponse) throw new Error('missing hidden-eval response envelope');
      const clientFinalize = threshold_ecdsa_hss_finalize_client_request({
        evaluatorDriverStateB64u: String(preparedClientSession.evaluatorDriverStateB64u || ''),
        serverEvalResponseB64u: String(parsedResponse.serverEvalResponseB64u || ''),
      }) as { clientEvalFinalizeB64u: string };
      return await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
        ceremonyId: args.ceremonyId,
        requestMessageB64u: encodeThresholdEcdsaHssHiddenEvalRequestMessage({
          ceremonyId: args.ceremonyId,
          preparedServerSessionB64u: args.preparedServerSessionB64u,
          serverAssistInitB64u: args.serverAssistInitB64u,
          clientEvalRequestB64u: String(clientRequest.clientEvalRequestB64u || ''),
        }),
        responseMessageB64u,
        clientEvalFinalizeB64u: String(clientFinalize.clientEvalFinalizeB64u || ''),
      });
    },
  };
}

async function registerThresholdEcdsaKey(args: {
  svc: ReturnType<typeof createThresholdSigningServiceForUnitTests>['svc'];
  userId: string;
  rpId: string;
  participantIds: number[];
  keygenSessionId: string;
  bootstrapSessionId: string;
  clientRootShare32B64u: string;
}): Promise<{ ecdsaThresholdKeyId: string; clientVerifyingShareB64u: string }> {
  const prepare = await args.svc.ecdsaHss.prepare({
    userId: args.userId,
    rpId: args.rpId,
    operation: 'registration_bootstrap',
    keygenSessionId: args.keygenSessionId,
    webauthn_authentication: fakeWebAuthnAuthentication() as any,
    sessionPolicy: {
      version: 'threshold_session_v1',
      userId: args.userId,
      rpId: args.rpId,
      sessionId: args.bootstrapSessionId,
      ttlMs: 60_000,
      remainingUses: 3,
      participantIds: args.participantIds,
    },
  });
  expect(prepare.ok).toBe(true);

  const ceremonyId = String(prepare.ceremonyId || '');
  const staged = await createHiddenEvalBootstrapMessages({
    ceremonyId,
    preparedServerSessionB64u: String(prepare.preparedServerSessionB64u || ''),
    serverAssistInitB64u: String(prepare.serverAssistInitB64u || ''),
    clientRootShare32B64u: args.clientRootShare32B64u,
    nearAccountId: args.userId,
  });

  const respond = await args.svc.ecdsaHss.respond({
    ceremonyId,
    requestMessageB64u: staged.requestMessageB64u,
  });
  expect(respond.ok).toBe(true);

  const finalize = await args.svc.ecdsaHss.finalize({
    ceremonyId,
    clientFinalizeMessageB64u: await staged.createFinalizeMessage(
      String(respond.responseMessageB64u || ''),
    ),
  });
  expect(finalize.ok).toBe(true);

  const ecdsaThresholdKeyId = String(finalize.ecdsaThresholdKeyId || '');
  expect(ecdsaThresholdKeyId).toBeTruthy();
  const clientVerifyingShareB64u = String(finalize.clientVerifyingShareB64u || '');
  expect(clientVerifyingShareB64u).toBeTruthy();
  return { ecdsaThresholdKeyId, clientVerifyingShareB64u };
}

test.describe('threshold-ecdsa hss bootstrap policy', () => {
  test('registration_bootstrap requires WebAuthn and keygen session scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      config: {
        THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
      },
    });

    const missingWebauthn = await svc.ecdsaHss.prepare({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'registration_bootstrap',
      keygenSessionId: 'ecdsa-keygen-1',
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-1',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(missingWebauthn.ok).toBe(false);
    expect(missingWebauthn.message).toContain('webauthn_authentication');

    const missingKeygenSession = await svc.ecdsaHss.prepare({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'registration_bootstrap',
      webauthn_authentication: fakeWebAuthnAuthentication() as any,
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-1',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(missingKeygenSession.ok).toBe(false);
    expect(missingKeygenSession.message).toContain('keygenSessionId');
  });

  test('session_bootstrap requires authenticated threshold-ed25519 session or app session scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      config: {
        THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
      },
    });

    const missingSessionClaims = await svc.ecdsaHss.prepare({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'session_bootstrap',
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-2',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(missingSessionClaims.ok).toBe(false);
    expect(missingSessionClaims.code).toBe('unauthorized');
  });

  test('session_bootstrap app-session path requires explicit ecdsaThresholdKeyId', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      config: {
        THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
      },
    });

    const rejected = await svc.ecdsaHss.prepare({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'session_bootstrap',
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: 'alice.near',
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-app-missing-key',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.code).toBe('invalid_body');
    expect(rejected.message).toContain('ecdsaThresholdKeyId');
  });

  test('session_bootstrap accepts app session scope for an existing ECDSA key', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      config: {
        THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
      },
    });
    const userId = 'alice.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const { ecdsaThresholdKeyId } = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-app-1',
      bootstrapSessionId: 'ecdsa-registration-app-1',
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(9)).toString('base64url'),
    });

    const prepare = await svc.ecdsaHss.prepare({
      userId,
      rpId,
      operation: 'session_bootstrap',
      ecdsaThresholdKeyId,
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: userId,
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId,
        rpId,
        sessionId: 'ecdsa-session-app-2',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });
    expect(prepare.ok).toBe(true);
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
  });

  test('session_bootstrap app-session path no longer requires an explicit verifier hint', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      config: {
        THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
      },
    });
    const userId = 'alice.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const { ecdsaThresholdKeyId } = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-app-2',
      bootstrapSessionId: 'ecdsa-registration-app-2',
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(13)).toString('base64url'),
    });

    const prepare = await svc.ecdsaHss.prepare({
      userId,
      rpId,
      operation: 'session_bootstrap',
      ecdsaThresholdKeyId,
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: userId,
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId,
        rpId,
        sessionId: 'ecdsa-session-app-mismatch',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });

    expect(prepare.ok).toBe(true);
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
  });

  test('non-export finalize never emits canonical export material', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({
      config: {
        THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_THRESHOLD_SECP256K1_MASTER_SECRET_B64U,
      },
    });

    const prepare = await svc.ecdsaHss.prepare({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'registration_bootstrap',
      keygenSessionId: 'ecdsa-keygen-3',
      webauthn_authentication: fakeWebAuthnAuthentication() as any,
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-3',
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(prepare.ok).toBe(true);

    const ceremonyId = String(prepare.ceremonyId || '');
    const staged = await createHiddenEvalBootstrapMessages({
      ceremonyId,
      preparedServerSessionB64u: String(prepare.preparedServerSessionB64u || ''),
      serverAssistInitB64u: String(prepare.serverAssistInitB64u || ''),
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(11)).toString('base64url'),
      nearAccountId: 'alice.near',
    });

    const respond = await svc.ecdsaHss.respond({
      ceremonyId,
      requestMessageB64u: staged.requestMessageB64u,
    });
    expect(respond.ok).toBe(true);

    const finalize = await svc.ecdsaHss.finalize({
      ceremonyId,
      clientFinalizeMessageB64u: await staged.createFinalizeMessage(
        String(respond.responseMessageB64u || ''),
      ),
    });
    expect(finalize.ok).toBe(true);
    expect('canonicalSecp256k1KeyB64u' in finalize).toBe(false);
  });
});
