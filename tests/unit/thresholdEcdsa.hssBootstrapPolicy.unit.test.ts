import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from '@/core/signingEngine/threshold/ecdsa/hssTransport';
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
import {
  buildEvmFamilyEcdsaKeyIdentity,
  deriveEvmFamilyKeyFingerprint,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaChainTarget } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../client/src/core/signingEngine/threshold/sessionPolicy';

const TEST_RUNTIME_SCOPE = {
  orgId: 'org-alpha',
  projectId: 'project-alpha',
  envId: 'env-alpha',
  signingRootVersion: 'default',
} as const;
const TEST_ECDSA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
} as const;
const TEST_TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const;
type TestThresholdEcdsaChainTarget =
  ThresholdEcdsaChainTarget;
type TestHssContextChainTarget =
  | {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug?: string;
    }
  | {
      kind: 'tempo';
      chainId: number;
      networkSlug?: string;
    };
type TestThresholdEcdsaHssContext = {
  walletSessionUserId: string;
  subjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
};
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

function thresholdEcdsaHssChainTargetString(target: TestHssContextChainTarget): string {
  return target.kind === 'evm' ? `evm:eip155:${target.chainId}` : `tempo:${target.chainId}`;
}

async function createHiddenEvalBootstrapMessages(args: {
  ceremonyId: string;
  preparedServerSessionB64u: string;
  serverAssistInitB64u: string;
  clientRootShare32B64u: string;
  hssContext: {
    walletSessionUserId: string;
    subjectId: string;
    chainTarget: string | TestHssContextChainTarget;
    ecdsaThresholdKeyId: string;
    signingRootId: string;
    signingRootVersion: string;
    keyPurpose: string;
    keyVersion: string;
  };
}): Promise<{ requestMessageB64u: string; createFinalizeMessage(responseMessageB64u: string): Promise<string> }> {
  ensureHssClientSignerWasm();
  const chainTarget =
    typeof args.hssContext.chainTarget === 'string'
      ? args.hssContext.chainTarget
      : thresholdEcdsaHssChainTargetString(args.hssContext.chainTarget);
  const preparedClientSession = threshold_ecdsa_hss_prepare_session({
    walletSessionUserId: args.hssContext.walletSessionUserId,
    subjectId: args.hssContext.subjectId,
    chainTarget,
    ecdsaThresholdKeyId: args.hssContext.ecdsaThresholdKeyId,
    signingRootId: args.hssContext.signingRootId,
    signingRootVersion: args.hssContext.signingRootVersion,
    keyPurpose: args.hssContext.keyPurpose,
    keyVersion: args.hssContext.keyVersion,
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
  chainTarget?: typeof TEST_ECDSA_CHAIN_TARGET | typeof TEST_TEMPO_CHAIN_TARGET;
}): Promise<{
  chainTarget: TestThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  clientVerifyingShareB64u: string;
  ethereumAddress: string;
  participantIds: number[];
  signingRootId: string;
  signingRootVersion: string;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  remainingUses: number;
}> {
  const chainTarget = args.chainTarget || TEST_ECDSA_CHAIN_TARGET;
  const prepare = await args.svc.ecdsaHss.prepare({
    walletSessionUserId: args.userId,
    rpId: args.rpId,
    operation: 'registration_bootstrap',
    keygenSessionId: args.keygenSessionId,
    webauthn_authentication: fakeWebAuthnAuthentication() as any,
    sessionPolicy: {
      version: 'threshold_session_v1',
      walletSessionUserId: args.userId,
      subjectId: args.userId,
      rpId: args.rpId,
      chainTarget,
      sessionId: args.bootstrapSessionId,
      walletSigningSessionId: `${args.bootstrapSessionId}:wallet-signing`,
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
    hssContext: prepare.hssContext!,
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
  if (!finalize.ok) throw new Error(JSON.stringify(finalize));
  expect(finalize.ok).toBe(true);

  const ecdsaThresholdKeyId = String(finalize.ecdsaThresholdKeyId || '');
  expect(ecdsaThresholdKeyId).toBeTruthy();
  const clientVerifyingShareB64u = String(finalize.clientVerifyingShareB64u || '');
  expect(clientVerifyingShareB64u).toBeTruthy();
  const ethereumAddress = String(finalize.ethereumAddress || '').trim();
  expect(ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
  const participantIds = normalizeParticipantIdsForTest(finalize.participantIds);
  const signingRootId = String(finalize.signingRootId || '').trim();
  expect(signingRootId).toBeTruthy();
  const signingRootVersion = String(finalize.signingRootVersion || '').trim() || 'default';
  const thresholdSessionId = String(finalize.sessionId || '').trim();
  expect(thresholdSessionId).toBeTruthy();
  const walletSigningSessionId = String(finalize.walletSigningSessionId || '').trim();
  expect(walletSigningSessionId).toBeTruthy();
  const remainingUses = Math.max(0, Math.floor(Number(finalize.remainingUses) || 0));
  expect(remainingUses).toBeGreaterThan(0);
  return {
    chainTarget,
    ecdsaThresholdKeyId,
    clientVerifyingShareB64u,
    ethereumAddress,
    participantIds,
    signingRootId,
    signingRootVersion,
    thresholdSessionId,
    walletSigningSessionId,
    remainingUses,
  };
}

function normalizeParticipantIdsForTest(value: unknown): number[] {
  if (!Array.isArray(value)) throw new Error('missing participant ids');
  const participantIds = value.map((id) => Number(id)).filter((id) => Number.isSafeInteger(id));
  if (!participantIds.length) throw new Error('empty participant ids');
  return participantIds;
}

function registrationFingerprint(args: {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: readonly number[];
  thresholdOwnerAddress: string;
}): string {
  return deriveEvmFamilyKeyFingerprint(
    buildEvmFamilyEcdsaKeyIdentity({
      walletId: args.walletId,
      subjectId: args.walletId,
      rpId: args.rpId,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      participantIds: args.participantIds,
      thresholdOwnerAddress: args.thresholdOwnerAddress,
    }),
  );
}

async function prepareRegistrationHssContext(args: {
  svc: ReturnType<typeof createThresholdSigningServiceForUnitTests>['svc'];
  userId: string;
  rpId: string;
  participantIds: number[];
  keygenSessionId: string;
  bootstrapSessionId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  chainTarget?: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId?: string;
}): Promise<TestThresholdEcdsaHssContext> {
  const chainTarget = args.chainTarget || TEST_ECDSA_CHAIN_TARGET;
  const prepare = await args.svc.ecdsaHss.prepare({
    walletSessionUserId: args.userId,
    rpId: args.rpId,
    operation: 'registration_bootstrap',
    keygenSessionId: args.keygenSessionId,
    webauthn_authentication: fakeWebAuthnAuthentication() as any,
    sessionPolicy: {
      version: 'threshold_session_v1',
      walletSessionUserId: args.userId,
      subjectId: args.userId,
      rpId: args.rpId,
      chainTarget,
      ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
      sessionId: args.bootstrapSessionId,
      walletSigningSessionId: `${args.bootstrapSessionId}:wallet-signing`,
      runtimePolicyScope: args.runtimePolicyScope || TEST_RUNTIME_SCOPE,
      ttlMs: 60_000,
      remainingUses: 3,
      participantIds: args.participantIds,
    },
  });
  expect(prepare, JSON.stringify(prepare)).toMatchObject({ ok: true });
  expect(prepare.hssContext).toBeTruthy();
  return prepare.hssContext! as TestThresholdEcdsaHssContext;
}

test.describe('threshold-ecdsa hss bootstrap policy', () => {
  test('registration_bootstrap requires WebAuthn and keygen session scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});

    const missingWebauthn = await svc.ecdsaHss.prepare({
      walletSessionUserId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'registration_bootstrap',
      keygenSessionId: 'ecdsa-keygen-1',
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: 'alice.near',
        subjectId: 'alice.near',
        rpId: 'wallet.example.test',
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });
    expect(missingWebauthn.ok).toBe(false);
    expect(missingWebauthn.message).toContain('webauthn_authentication');

    // @ts-expect-error Boundary validation test intentionally omits keygenSessionId.
    const missingKeygenSession = await svc.ecdsaHss.prepare({
      walletSessionUserId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'registration_bootstrap',
      webauthn_authentication: fakeWebAuthnAuthentication() as any,
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: 'alice.near',
        subjectId: 'alice.near',
        rpId: 'wallet.example.test',
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
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
      walletSessionUserId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'session_bootstrap',
      keygenSessionId: 'keygen-missing-auth',
      ecdsaThresholdKeyId: 'ecdsa-key-missing-auth',
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: 'alice.near',
        subjectId: 'alice.near',
        rpId: 'wallet.example.test',
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId: 'ecdsa-key-missing-auth',
        sessionId: 'ecdsa-session-2',
        walletSigningSessionId: 'wallet-signing-session-2',
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

    // @ts-expect-error Boundary validation test intentionally omits ecdsaThresholdKeyId.
    const rejected = await svc.ecdsaHss.prepare({
      walletSessionUserId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'session_bootstrap',
      keygenSessionId: 'keygen-app-missing-key',
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: 'alice.near',
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: 'alice.near',
        subjectId: 'alice.near',
        rpId: 'wallet.example.test',
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-app-missing-key',
        walletSigningSessionId: 'wallet-signing-session-app-missing-key',
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

  test('session_bootstrap accepts the same ECDSA key id across EVM-family targets', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-target-mismatch.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(31)).toString('base64url');
    const registered = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-tempo-key',
      bootstrapSessionId: 'ecdsa-session-tempo-key',
      clientRootShare32B64u,
      chainTarget: TEST_TEMPO_CHAIN_TARGET,
    });

    const prepare = await svc.ecdsaHss.prepare({
      walletSessionUserId: userId,
      rpId,
      operation: 'session_bootstrap',
      keygenSessionId: 'ecdsa-keygen-evm-with-tempo-key',
      ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: userId,
        walletId: userId,
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
        sessionId: 'ecdsa-session-evm-with-tempo-key',
        walletSigningSessionId: 'wallet-signing-evm-with-tempo-key',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });

    expect(prepare, JSON.stringify(prepare)).toMatchObject({ ok: true });
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
    expect(prepare.hssContext?.ecdsaThresholdKeyId).toBe(registered.ecdsaThresholdKeyId);
    expect(prepare.hssContext?.chainTarget).toEqual(TEST_ECDSA_CHAIN_TARGET);

    const staged = await createHiddenEvalBootstrapMessages({
      ceremonyId: String(prepare.ceremonyId || ''),
      preparedServerSessionB64u: String(prepare.preparedServerSessionB64u || ''),
      serverAssistInitB64u: String(prepare.serverAssistInitB64u || ''),
      clientRootShare32B64u,
      hssContext: prepare.hssContext!,
    });
    const respond = await svc.ecdsaHss.respond({
      ceremonyId: String(prepare.ceremonyId || ''),
      requestMessageB64u: staged.requestMessageB64u,
    });
    expect(respond.ok).toBe(true);
    const finalize = await svc.ecdsaHss.finalize({
      ceremonyId: String(prepare.ceremonyId || ''),
      clientFinalizeMessageB64u: await staged.createFinalizeMessage(
        String(respond.responseMessageB64u || ''),
      ),
    });
    expect(finalize, JSON.stringify(finalize)).toMatchObject({ ok: true });
    expect(finalize.ecdsaThresholdKeyId).toBe(registered.ecdsaThresholdKeyId);
    expect(finalize.ethereumAddress).toBe(registered.ethereumAddress);
  });

  test('registration_bootstrap derives the same shared key id and owner across EVM-family targets', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-hss-shared-target.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(42)).toString(
      'base64url',
    );

    const tempoRegistration = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-hss-tempo-shared',
      bootstrapSessionId: 'ecdsa-session-hss-tempo-shared',
      clientRootShare32B64u,
      chainTarget: TEST_TEMPO_CHAIN_TARGET,
    });
    const evmRegistration = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-hss-evm-shared',
      bootstrapSessionId: 'ecdsa-session-hss-evm-shared',
      clientRootShare32B64u,
      chainTarget: TEST_ECDSA_CHAIN_TARGET,
    });

    expect(evmRegistration.ecdsaThresholdKeyId).toBe(
      tempoRegistration.ecdsaThresholdKeyId,
    );
    expect(evmRegistration.ethereumAddress).toBe(tempoRegistration.ethereumAddress);
    expect(evmRegistration.clientVerifyingShareB64u).toBe(
      tempoRegistration.clientVerifyingShareB64u,
    );
    expect(
      registrationFingerprint({
        walletId: userId,
        rpId,
        ecdsaThresholdKeyId: evmRegistration.ecdsaThresholdKeyId,
        signingRootId: evmRegistration.signingRootId,
        signingRootVersion: evmRegistration.signingRootVersion,
        participantIds: evmRegistration.participantIds,
        thresholdOwnerAddress: evmRegistration.ethereumAddress,
      }),
    ).toBe(
      registrationFingerprint({
        walletId: userId,
        rpId,
        ecdsaThresholdKeyId: tempoRegistration.ecdsaThresholdKeyId,
        signingRootId: tempoRegistration.signingRootId,
        signingRootVersion: tempoRegistration.signingRootVersion,
        participantIds: tempoRegistration.participantIds,
        thresholdOwnerAddress: tempoRegistration.ethereumAddress,
      }),
    );
    expect(evmRegistration.chainTarget).not.toEqual(tempoRegistration.chainTarget);
    expect(evmRegistration.thresholdSessionId).not.toBe(tempoRegistration.thresholdSessionId);
    expect(evmRegistration.walletSigningSessionId).not.toBe(
      tempoRegistration.walletSigningSessionId,
    );
    expect(evmRegistration.remainingUses).toBeGreaterThan(0);
    expect(tempoRegistration.remainingUses).toBeGreaterThan(0);
  });

  test('registration_bootstrap changes planned HSS key id when stable shared fields change', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-hss-stable-field-change.near';
    const participantIds = [1, 2];
    const base = await prepareRegistrationHssContext({
      svc,
      userId,
      rpId: 'wallet.example.test',
      participantIds,
      keygenSessionId: 'ecdsa-keygen-hss-stable-base',
      bootstrapSessionId: 'ecdsa-session-hss-stable-base',
    });
    const variants = await Promise.all([
      prepareRegistrationHssContext({
        svc,
        userId,
        rpId: 'wallet.other.test',
        participantIds,
        keygenSessionId: 'ecdsa-keygen-hss-stable-rp',
        bootstrapSessionId: 'ecdsa-session-hss-stable-rp',
      }),
      prepareRegistrationHssContext({
        svc,
        userId,
        rpId: 'wallet.example.test',
        participantIds,
        keygenSessionId: 'ecdsa-keygen-hss-stable-root',
        bootstrapSessionId: 'ecdsa-session-hss-stable-root',
        runtimePolicyScope: {
          ...TEST_RUNTIME_SCOPE,
          projectId: 'project-beta',
        },
      }),
      prepareRegistrationHssContext({
        svc,
        userId,
        rpId: 'wallet.example.test',
        participantIds,
        keygenSessionId: 'ecdsa-keygen-hss-stable-version',
        bootstrapSessionId: 'ecdsa-session-hss-stable-version',
        runtimePolicyScope: {
          ...TEST_RUNTIME_SCOPE,
          signingRootVersion: 'v2',
        },
      }),
      prepareRegistrationHssContext({
        svc,
        userId,
        rpId: 'wallet.example.test',
        participantIds,
        keygenSessionId: 'ecdsa-keygen-hss-stable-key-id',
        bootstrapSessionId: 'ecdsa-session-hss-stable-key-id',
        ecdsaThresholdKeyId: 'ehss-explicit-stable-key-id',
      }),
    ]);

    for (const variant of variants) {
      expect(variant.ecdsaThresholdKeyId).not.toBe(base.ecdsaThresholdKeyId);
    }
  });

  test('registration_bootstrap changes canonical HSS fingerprint when participant set changes', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-hss-participant-fingerprint.near';
    const rpId = 'wallet.example.test';
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(44)).toString(
      'base64url',
    );

    const twoParticipants = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds: [1, 2],
      keygenSessionId: 'ecdsa-keygen-hss-participants-two',
      bootstrapSessionId: 'ecdsa-session-hss-participants-two',
      clientRootShare32B64u,
    });
    const threeParticipants = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds: [1, 2, 3],
      keygenSessionId: 'ecdsa-keygen-hss-participants-three',
      bootstrapSessionId: 'ecdsa-session-hss-participants-three',
      clientRootShare32B64u,
    });

    expect(twoParticipants.participantIds).toEqual([1, 2]);
    expect(threeParticipants.participantIds).toEqual([1, 2, 3]);
    expect(
      registrationFingerprint({
        walletId: userId,
        rpId,
        ecdsaThresholdKeyId: twoParticipants.ecdsaThresholdKeyId,
        signingRootId: twoParticipants.signingRootId,
        signingRootVersion: twoParticipants.signingRootVersion,
        participantIds: twoParticipants.participantIds,
        thresholdOwnerAddress: twoParticipants.ethereumAddress,
      }),
    ).not.toBe(
      registrationFingerprint({
        walletId: userId,
        rpId,
        ecdsaThresholdKeyId: threeParticipants.ecdsaThresholdKeyId,
        signingRootId: threeParticipants.signingRootId,
        signingRootVersion: threeParticipants.signingRootVersion,
        participantIds: threeParticipants.participantIds,
        thresholdOwnerAddress: threeParticipants.ethereumAddress,
      }),
    );
  });

  test('session_bootstrap accepts threshold-session auth across EVM-family targets for the same key id', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-threshold-session-target-mismatch.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const bootstrapSessionId = 'ecdsa-session-tempo-threshold-auth';
    const walletSigningSessionId = `${bootstrapSessionId}:wallet-signing`;
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(32)).toString(
      'base64url',
    );
    const registered = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-tempo-threshold-auth',
      bootstrapSessionId,
      clientRootShare32B64u,
      chainTarget: TEST_TEMPO_CHAIN_TARGET,
    });

    const prepare = await svc.ecdsaHss.prepare({
      walletSessionUserId: userId,
      rpId,
      operation: 'session_bootstrap',
      keygenSessionId: 'ecdsa-keygen-evm-with-tempo-threshold-auth',
      ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
      ecdsaSessionClaims: {
        kind: 'threshold_ecdsa_session_v1',
        sub: userId,
        walletId: userId,
        subjectId: userId,
        chainTarget: TEST_TEMPO_CHAIN_TARGET,
        ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
        sessionId: bootstrapSessionId,
        walletSigningSessionId,
        relayerKeyId: 'relayer-key-tempo-threshold-auth',
        rpId,
        thresholdExpiresAtMs: Date.now() + 60_000,
        participantIds,
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
        sessionId: bootstrapSessionId,
        walletSigningSessionId,
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });

    expect(prepare, JSON.stringify(prepare)).toMatchObject({ ok: true });
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
    expect(prepare.hssContext?.ecdsaThresholdKeyId).toBe(registered.ecdsaThresholdKeyId);
    expect(prepare.hssContext?.chainTarget).toEqual(TEST_ECDSA_CHAIN_TARGET);
  });

  test('session_bootstrap rejects threshold-session auth across EVM-family targets for a different key id', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-threshold-session-key-mismatch.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const bootstrapSessionId = 'ecdsa-session-tempo-threshold-key-mismatch';
    const walletSigningSessionId = `${bootstrapSessionId}:wallet-signing`;
    const registered = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-tempo-threshold-key-mismatch',
      bootstrapSessionId,
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(33)).toString('base64url'),
      chainTarget: TEST_TEMPO_CHAIN_TARGET,
    });

    const rejected = await svc.ecdsaHss.prepare({
      walletSessionUserId: userId,
      rpId,
      operation: 'session_bootstrap',
      keygenSessionId: 'ecdsa-keygen-evm-with-different-threshold-auth',
      ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
      ecdsaSessionClaims: {
        kind: 'threshold_ecdsa_session_v1',
        sub: userId,
        walletId: userId,
        subjectId: userId,
        chainTarget: TEST_TEMPO_CHAIN_TARGET,
        ecdsaThresholdKeyId: 'different-ecdsa-key-id',
        sessionId: bootstrapSessionId,
        walletSigningSessionId,
        relayerKeyId: 'relayer-key-tempo-threshold-key-mismatch',
        rpId,
        thresholdExpiresAtMs: Date.now() + 60_000,
        participantIds,
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
        sessionId: bootstrapSessionId,
        walletSigningSessionId,
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });

    expect(rejected.ok).toBe(false);
    expect(rejected.code).toBe('unauthorized');
    expect(rejected.message).toContain('lane identity mismatch');
  });

  test('session_bootstrap rejects threshold-session auth when rpId does not match requested signing scope', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'alice-threshold-session-rpid-mismatch.near';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const bootstrapSessionId = 'ecdsa-session-tempo-threshold-rpid-mismatch';
    const walletSigningSessionId = `${bootstrapSessionId}:wallet-signing`;
    const registered = await registerThresholdEcdsaKey({
      svc,
      userId,
      rpId,
      participantIds,
      keygenSessionId: 'ecdsa-keygen-tempo-threshold-rpid-mismatch',
      bootstrapSessionId,
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(37)).toString('base64url'),
      chainTarget: TEST_TEMPO_CHAIN_TARGET,
    });

    const rejected = await svc.ecdsaHss.prepare({
      walletSessionUserId: userId,
      rpId,
      operation: 'session_bootstrap',
      keygenSessionId: 'ecdsa-keygen-evm-rpid-mismatch',
      ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
      ecdsaSessionClaims: {
        kind: 'threshold_ecdsa_session_v1',
        sub: userId,
        walletId: userId,
        subjectId: userId,
        chainTarget: TEST_TEMPO_CHAIN_TARGET,
        ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
        sessionId: bootstrapSessionId,
        walletSigningSessionId,
        relayerKeyId: 'relayer-key-tempo-threshold-rpid-mismatch',
        rpId: 'wallet.other.test',
        thresholdExpiresAtMs: Date.now() + 60_000,
        participantIds,
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId: registered.ecdsaThresholdKeyId,
        sessionId: bootstrapSessionId,
        walletSigningSessionId,
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds,
      },
    });

    expect(rejected.ok).toBe(false);
    expect(rejected.code).toBe('unauthorized');
    expect(rejected.message).toContain('does not match requested signing scope');
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
      walletSessionUserId: userId,
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
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-email-otp-1',
        walletSigningSessionId: 'wallet-signing-session-email-otp-1',
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
      hssContext: prepare.hssContext!,
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

    if (!finalize.ok) throw new Error(JSON.stringify(finalize));
    expect(finalize.ok).toBe(true);
    expect(String(finalize.clientVerifyingShareB64u || '')).toBeTruthy();
    expect(String(finalize.ecdsaThresholdKeyId || '')).toBeTruthy();
    expect(finalize.sessionId).toBe('ecdsa-session-email-otp-1');
    expect(finalize.walletSigningSessionId).toBe('wallet-signing-session-email-otp-1');
  });

  test('email_otp_bootstrap accepts wallet-scoped app session plus provider enrollment verifier', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'email-wallet-app-session.testnet';
    const googleSub = 'google:wallet-scoped-subject';
    const rpId = 'wallet.example.test';
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(26)).toString(
      'base64url',
    );
    const clientVerifyingShareB64u =
      clientVerifyingShareB64uFromRootShare(clientRootShare32B64u);

    const prepare = await svc.ecdsaHss.prepare({
      walletSessionUserId: userId,
      rpId,
      operation: 'email_otp_bootstrap',
      keygenSessionId: 'ecdsa-email-otp-keygen-wallet-scoped-app-session',
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: userId,
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
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-email-otp-wallet-scoped-app-session',
        walletSigningSessionId: 'wallet-signing-email-otp-wallet-scoped-app-session',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 3,
        participantIds: [1, 2],
      },
    });

    expect(prepare.ok).toBe(true);
    expect(String(prepare.ceremonyId || '')).toBeTruthy();
  });

  test('email_otp_bootstrap accepts threshold-session auth for a Google Email OTP enrollment', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});
    const userId = 'email-wallet-restored.testnet';
    const googleSub = 'google:subject-restored';
    const rpId = 'wallet.example.test';
    const participantIds = [1, 2];
    const clientRootShare32B64u = Buffer.from(new Uint8Array(32).fill(24)).toString(
      'base64url',
    );
    const clientVerifyingShareB64u =
      clientVerifyingShareB64uFromRootShare(clientRootShare32B64u);

    const prepare = await svc.ecdsaHss.prepare({
      walletSessionUserId: userId,
      rpId,
      operation: 'email_otp_bootstrap',
      keygenSessionId: 'ecdsa-email-otp-keygen-restored-1',
      ecdsaSessionClaims: {
        kind: 'threshold_ecdsa_session_v1',
        sub: userId,
        walletId: userId,
        subjectId: userId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId: 'existing-ecdsa-key-restored-1',
        sessionId: 'existing-ecdsa-session-restored-1',
        walletSigningSessionId: 'wallet-signing-restored-1',
        relayerKeyId: 'relayer-key-restored-1',
        rpId,
        thresholdExpiresAtMs: Date.now() + 60_000,
        participantIds,
      },
      emailOtpEnrollmentClaims: {
        walletId: userId,
        userId: googleSub,
        otpChannel: 'email_otp',
        thresholdEcdsaClientVerifyingShareB64u: clientVerifyingShareB64u,
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-email-otp-restored-1',
        walletSigningSessionId: 'wallet-signing-session-email-otp-restored-1',
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
      hssContext: prepare.hssContext!,
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

    if (!finalize.ok) throw new Error(JSON.stringify(finalize));
    expect(finalize.ok).toBe(true);
    expect(String(finalize.clientVerifyingShareB64u || '')).toBeTruthy();
    expect(String(finalize.ecdsaThresholdKeyId || '')).toBeTruthy();
    expect(finalize.sessionId).toBe('ecdsa-session-email-otp-restored-1');
    expect(finalize.walletSigningSessionId).toBe(
      'wallet-signing-session-email-otp-restored-1',
    );
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
      walletSessionUserId: userId,
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
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-email-otp-mismatch',
        walletSigningSessionId: 'wallet-signing-session-email-otp-mismatch',
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
      hssContext: prepare.hssContext!,
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
      walletSessionUserId: userId,
      rpId,
      operation: 'session_bootstrap',
      keygenSessionId: 'ecdsa-keygen-app-session-1',
      ecdsaThresholdKeyId,
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: userId,
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId,
        sessionId: 'ecdsa-session-app-2',
        walletSigningSessionId: 'wallet-signing-session-app-2',
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
      walletSessionUserId: userId,
      rpId,
      operation: 'session_bootstrap',
      keygenSessionId: 'ecdsa-keygen-app-session-2',
      ecdsaThresholdKeyId,
      appSessionClaims: {
        kind: 'app_session_v1',
        sub: userId,
        appSessionVersion: 'app-session-v1',
      },
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: userId,
        subjectId: userId,
        rpId,
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        ecdsaThresholdKeyId,
        sessionId: 'ecdsa-session-app-mismatch',
        walletSigningSessionId: 'wallet-signing-session-app-mismatch',
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
      walletSessionUserId: 'alice.near',
      rpId: 'wallet.example.test',
      operation: 'registration_bootstrap',
      keygenSessionId: 'ecdsa-keygen-3',
      webauthn_authentication: fakeWebAuthnAuthentication() as any,
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: 'alice.near',
        subjectId: 'alice.near',
        rpId: 'wallet.example.test',
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-3',
        walletSigningSessionId: 'wallet-signing-session-3',
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
      hssContext: prepare.hssContext!,
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
    if (!finalize.ok) throw new Error(JSON.stringify(finalize));
    expect(finalize.ok).toBe(true);
    expect('canonicalSecp256k1KeyB64u' in finalize).toBe(false);
  });
});
