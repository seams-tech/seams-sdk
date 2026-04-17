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
import {
  initSync as initEthSignerWasmSync,
  secp256k1_private_key_32_to_public_key_33,
} from '../../wasm/eth_signer/pkg/eth_signer.js';

const TEST_RUNTIME_SCOPE = { orgId: 'org-alpha', projectId: 'project-alpha', envId: 'env-alpha' } as const;
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const ETH_SIGNER_WASM_URL = new URL(
  '../../wasm/eth_signer/pkg/eth_signer_bg.wasm',
  import.meta.url,
);
let hssClientSignerWasmInitialized = false;
let ethSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function ensureEthSignerWasm(): void {
  if (ethSignerWasmInitialized) return;
  initEthSignerWasmSync({ module: readFileSync(ETH_SIGNER_WASM_URL) });
  ethSignerWasmInitialized = true;
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

function clientVerifyingShareB64uFromRootShare(clientRootShare32B64u: string): string {
  ensureEthSignerWasm();
  const clientRootShare32 = Buffer.from(clientRootShare32B64u, 'base64url');
  const publicKey33 = secp256k1_private_key_32_to_public_key_33(clientRootShare32);
  return Buffer.from(publicKey33).toString('base64url');
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
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
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
    const { svc } = createThresholdSigningServiceForUnitTests({});

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
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
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
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(missingKeygenSession.ok).toBe(false);
    expect(missingKeygenSession.message).toContain('keygenSessionId');
  });

  test('session_bootstrap requires authenticated threshold-ed25519 session or app session scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});

    const missingSessionClaims = await svc.ecdsaHss.prepare({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'session_bootstrap',
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-2',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(missingSessionClaims.ok).toBe(false);
    expect(missingSessionClaims.code).toBe('unauthorized');
  });

  test('session_bootstrap app-session path requires explicit ecdsaThresholdKeyId', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});

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
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.code).toBe('invalid_body');
    expect(rejected.message).toContain('ecdsaThresholdKeyId');
  });

  test('email_otp_bootstrap accepts app session plus enrollment verifier without an existing ECDSA key id', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'email-wallet.testnet';
    const googleSub = 'google:subject-1';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(21)).toString(
      'base64url',
    );
    const clientVerifyingShareB64u =
      clientVerifyingShareB64uFromRootShare(clientRootShare32B64u);

    const prepare = await svc.ecdsaHss.prepare({
      userId,
      rpId,
      operation: 'email_otp_bootstrap',
      keygenSessionId: 'ecdsa-email-otp-keygen-1',
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: googleSub,
        walletId: userId,
        appSessionVersion: 'app-session-v1',
      },
      emailOtpEnrollmentClaims: {
        walletId: userId,
        userId: googleSub,
        otpChannel: 'email_otp',
        thresholdEcdsaClientVerifyingShareB64u: clientVerifyingShareB64u,
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId,
        rpId,
        sessionId: 'ecdsa-session-email-otp-1',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });
    expect(prepare.ok).toBe(true);

    const ceremonyId = String(prepare.ceremonyId || '');
    const staged = await createHiddenEvalBootstrapMessages({
      ceremonyId,
      preparedServerSessionB64u: String(prepare.preparedServerSessionB64u || ''),
      serverAssistInitB64u: String(prepare.serverAssistInitB64u || ''),
      clientRootShare32B64u,
      nearAccountId: userId,
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
    expect(String(finalize.clientVerifyingShareB64u || '')).toBeTruthy();
    expect(String(finalize.ecdsaThresholdKeyId || '')).toBeTruthy();
    expect(finalize.sessionId).toBe('ecdsa-session-email-otp-1');
  });

  test('email_otp_bootstrap rejects recovered material that does not match the enrollment verifier', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'email-wallet-mismatch.testnet';
    const googleSub = 'google:subject-2';
    const rpId = 'wallet.example.test';
    const enrolledRootShare32B64u = Buffer.from(new Uint8Array(32).fill(22)).toString(
      'base64url',
    );
    const recoveredRootShare32B64u = Buffer.from(new Uint8Array(32).fill(23)).toString(
      'base64url',
    );

    const prepare = await svc.ecdsaHss.prepare({
      userId,
      rpId,
      operation: 'email_otp_bootstrap',
      keygenSessionId: 'ecdsa-email-otp-keygen-mismatch',
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: googleSub,
        walletId: userId,
        appSessionVersion: 'app-session-v1',
      },
      emailOtpEnrollmentClaims: {
        walletId: userId,
        userId: googleSub,
        otpChannel: 'email_otp',
        thresholdEcdsaClientVerifyingShareB64u:
          clientVerifyingShareB64uFromRootShare(enrolledRootShare32B64u),
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId,
        rpId,
        sessionId: 'ecdsa-session-email-otp-mismatch',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
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
      clientRootShare32B64u: recoveredRootShare32B64u,
      nearAccountId: userId,
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

    expect(finalize.ok).toBe(false);
    expect(finalize.code).toBe('unauthorized');
    expect(finalize.message).toContain('enrollment verifier');
  });

  test('session_bootstrap accepts app session scope for an existing ECDSA key', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
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
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });
    expect(prepare.ok).toBe(true);
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
  });

  test('session_bootstrap app-session path no longer requires an explicit verifier hint', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
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
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });

    expect(prepare.ok).toBe(true);
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
  });

  test('non-export finalize never emits canonical export material', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});

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
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
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
