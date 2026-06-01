import { expect, test } from '@playwright/test';
import { buildEd25519SessionPolicy } from '@/core/signingEngine/threshold/sessionPolicy';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import { signerBoundWalletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import {
  createThresholdSigningServiceForUnitTests,
  deriveThresholdEd25519VerifyingShareForUnitTests,
} from '../helpers/thresholdEd25519TestUtils';

test('threshold-ed25519 passkey session mint verifies the client runtime-scoped policy digest', async () => {
  const nearAccountId = 'alice.testnet';
  const rpId = 'localhost';
  const relayerKeyId = 'ed25519:runtime-scope-relayer';
  const publicKey = 'ed25519:runtime-scope-public-key';
  const relayerSigningShareB64u = Buffer.alloc(32, 11).toString('base64url');
  const relayerVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: relayerSigningShareB64u,
  });
  const { policy, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    nearAccountId,
    rpId,
    relayerKeyId,
    sessionId: 'tsess-runtime-scope-ed25519',
    walletSigningSessionId: 'wsess-runtime-scope',
    participantIds: [1, 2],
    ttlMs: 300_000,
    remainingUses: 5,
    runtimePolicyScope: {
      orgId: 'org-runtime-scope',
      projectId: 'proj-runtime-scope',
      envId: 'dev',
      signingRootVersion: 'default',
    },
  });

  let capturedExpectedChallenge = '';
  const { svc } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      keyVersion: 'threshold-ed25519-hss-v1',
      recoveryExportCapable: true,
    },
    accessKeysOnChain: [publicKey],
    verifyWebAuthnAuthenticationLite: async ({ expectedChallenge }) => {
      capturedExpectedChallenge = expectedChallenge;
      return { success: true, verified: true };
    },
  });

  const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error('threshold-ed25519 scheme missing in test service');
  }

  const result = await scheme.session({
    relayerKeyId,
    sessionPolicy: policy,
    webauthn_authentication: {
      id: 'cred-runtime-scope',
      rawId: 'cred-runtime-scope',
      type: 'public-key',
      authenticatorAttachment: null,
      response: {
        clientDataJSON: 'client-data-json',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: null,
      },
      clientExtensionResults: null,
    },
  });

  expect(result.ok).toBe(true);
  expect(capturedExpectedChallenge).toBe(sessionPolicyDigest32);
  expect(result.code).not.toBe('invalid_assertion');
});

test('threshold-ed25519 passkey reauth mints a signer-bound wallet budget for the new session', async () => {
  const nearAccountId = 'alice.testnet';
  const rpId = 'localhost';
  const relayerKeyId = 'ed25519:wallet-budget-refresh-relayer';
  const walletSigningSessionId = 'wsess-wallet-budget-refresh';
  const publicKey = 'ed25519:wallet-budget-refresh-public-key';
  const relayerSigningShareB64u = Buffer.alloc(32, 12).toString('base64url');
  const relayerVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: relayerSigningShareB64u,
  });
  const { svc, authSessionStore } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      keyVersion: 'threshold-ed25519-hss-v1',
      recoveryExportCapable: true,
    },
    accessKeysOnChain: [publicKey],
  });
  const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error('threshold-ed25519 scheme missing in test service');
  }
  const ed25519Scheme = scheme;

  async function mintSession(sessionId: string, remainingUses: number) {
    const { policy } = await buildEd25519SessionPolicy({
      nearAccountId,
      rpId,
      relayerKeyId,
      sessionId,
      walletSigningSessionId,
      participantIds: [1, 2],
      ttlMs: 300_000,
      remainingUses,
    });
    const result = await ed25519Scheme.session({
      relayerKeyId,
      sessionPolicy: policy,
      webauthn_authentication: {
        id: `cred-${sessionId}`,
        rawId: `cred-${sessionId}`,
        type: 'public-key',
        authenticatorAttachment: null,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: null,
        },
        clientExtensionResults: null,
      },
    });
    expect(result.ok).toBe(true);
  }

  const firstSessionId = 'tsess-wallet-budget-refresh-1';
  const secondSessionId = 'tsess-wallet-budget-refresh-2';
  const firstWalletBudgetSessionId = signerBoundWalletSigningBudgetSessionId({
    walletSigningSessionId,
    curve: 'ed25519',
    thresholdSessionId: firstSessionId,
  });
  const secondWalletBudgetSessionId = signerBoundWalletSigningBudgetSessionId({
    walletSigningSessionId,
    curve: 'ed25519',
    thresholdSessionId: secondSessionId,
  });

  await mintSession(firstSessionId, 2);
  expect(await authSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: true,
    remainingUses: 1,
  });
  expect(await authSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: true,
    remainingUses: 0,
  });
  expect(await authSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: false,
    code: 'unauthorized',
  });

  await mintSession(secondSessionId, 3);
  expect(await authSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: false,
    code: 'unauthorized',
  });
  expect(await authSessionStore.consumeUseCount(secondWalletBudgetSessionId)).toMatchObject({
    ok: true,
    remainingUses: 2,
  });
});
