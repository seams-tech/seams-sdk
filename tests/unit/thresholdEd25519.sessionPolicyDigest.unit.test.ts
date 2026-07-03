import { expect, test } from '@playwright/test';
import {
  buildEd25519SessionPolicy,
  type Ed25519AuthorityScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import { walletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import { base58Encode } from '@shared/utils/encoders';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  createThresholdSigningServiceForUnitTests,
  deriveThresholdEd25519VerifyingShareForUnitTests,
} from '../helpers/thresholdEd25519TestUtils';

const ROUTER_AB_NORMAL_SIGNING = {
  kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  signingWorkerId: 'signing-worker.local',
} as const;

function passkeyPolicyAuthority(walletId: string, rpId: string, credentialIdB64u: string) {
  return {
    kind: 'wallet_auth_authority',
    authority: buildPasskeyWalletAuthAuthority({ walletId, rpId, credentialIdB64u }),
  } as const;
}

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
    walletId: nearAccountId,
    nearAccountId,
    nearEd25519SigningKeyId: nearAccountId,
    authority: passkeyPolicyAuthority(nearAccountId, rpId, 'cred-runtime-scope'),
    relayerKeyId,
    thresholdSessionId: 'tsess-runtime-scope-ed25519',
    signingGrantId: 'wsess-runtime-scope',
    participantIds: [1, 2],
    ttlMs: 300_000,
    remainingUses: 5,
    runtimePolicyScope: {
      orgId: 'org-runtime-scope',
      projectId: 'proj-runtime-scope',
      envId: 'dev',
      signingRootVersion: 'default',
    },
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
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
    auth: {
      kind: 'passkey',
      expected_origin: 'http://localhost',
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
    },
  });

  expect(result.ok).toBe(true);
  expect(capturedExpectedChallenge).toBe(sessionPolicyDigest32);
  expect(result.code).not.toBe('invalid_assertion');
});

test('threshold-ed25519 passkey session mint does not require access-key reads for implicit accounts', async () => {
  const publicKeyBytes = new Uint8Array(32).fill(31);
  const publicKey = `ed25519:${base58Encode(publicKeyBytes)}`;
  const nearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(publicKey);
  const walletId = 'frost-vermillion-k7p9m2';
  const nearEd25519SigningKeyId = 'ed25519ks_implicit_session_scope';
  const rpId = 'localhost';
  const relayerKeyId = 'ed25519:implicit-session-relayer';
  const relayerSigningShareB64u = Buffer.alloc(32, 13).toString('base64url');
  const relayerVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: relayerSigningShareB64u,
  });
  const { policy } = await buildEd25519SessionPolicy({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authority: passkeyPolicyAuthority(walletId, rpId, 'cred-implicit-session'),
    relayerKeyId,
    thresholdSessionId: 'tsess-implicit-session-ed25519',
    signingGrantId: 'wsess-implicit-session',
    participantIds: [1, 2],
    ttlMs: 300_000,
    remainingUses: 5,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
  });

  const { svc } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      rpId,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      keyVersion: 'threshold-ed25519-hss-v1',
      recoveryExportCapable: true,
    },
  });

  const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error('threshold-ed25519 scheme missing in test service');
  }

  const result = await scheme.session({
    relayerKeyId,
    sessionPolicy: policy,
    auth: {
      kind: 'passkey',
      expected_origin: 'http://localhost',
      webauthn_authentication: {
        id: 'cred-implicit-session',
        rawId: 'cred-implicit-session',
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
    },
  });

  expect(result.ok).toBe(true);
});

test('threshold-ed25519 registration session mint accepts Email OTP authority', async () => {
  const walletId = 'violet-raven-c2bgmv';
  const nearAccountId = 'email-otp-registration.testnet';
  const nearEd25519SigningKeyId = 'ed25519ks_email_otp_registration';
  const relayerKeyId = 'ed25519:email-otp-registration-relayer';
  const publicKey = 'ed25519:email-otp-registration-public-key';
  const relayerSigningShareB64u = Buffer.alloc(32, 14).toString('base64url');
  const relayerVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: relayerSigningShareB64u,
  });
  const authorityScope = {
    kind: 'email_otp',
    provider: 'google',
    providerUserId: 'google:alice@example.test',
  } as const satisfies Extract<Ed25519AuthorityScope, { kind: 'email_otp' }>;
  const { policy } = await buildEd25519SessionPolicy({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authority: { kind: 'exact_authority_scope', authorityScope },
    relayerKeyId,
    thresholdSessionId: 'tsess-email-otp-registration',
    signingGrantId: 'wsess-email-otp-registration',
    participantIds: [1, 2],
    ttlMs: 300_000,
    remainingUses: 3,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
  });
  const { svc, walletBudgetSessionStore } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      authorityScope,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      keyVersion: 'threshold-ed25519-hss-v1',
      recoveryExportCapable: true,
    },
  });

  const result = await svc.mintEd25519SessionFromRegistration({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authorityScope,
    relayerKeyId,
    sessionPolicy: policy,
  });

  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(result.message);
  const budgetSession = await walletBudgetSessionStore.getSession(
    walletSigningBudgetSessionId({ signingGrantId: 'wsess-email-otp-registration' }),
  );
  expect(budgetSession?.walletId).toBe(walletId);
});

test('threshold-ed25519 passkey session mint creates wallet budgets per signing grant', async () => {
  const nearAccountId = 'alice.testnet';
  const rpId = 'localhost';
  const relayerKeyId = 'ed25519:wallet-budget-refresh-relayer';
  const publicKey = 'ed25519:wallet-budget-refresh-public-key';
  const relayerSigningShareB64u = Buffer.alloc(32, 12).toString('base64url');
  const relayerVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: relayerSigningShareB64u,
  });
  const { svc, walletBudgetSessionStore } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      keyVersion: 'threshold-ed25519-hss-v1',
      recoveryExportCapable: true,
    },
  });
  const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error('threshold-ed25519 scheme missing in test service');
  }
  const ed25519Scheme = scheme;

  async function mintSession(sessionId: string, signingGrantId: string, remainingUses: number) {
    const { policy } = await buildEd25519SessionPolicy({
      walletId: nearAccountId,
      nearAccountId,
      nearEd25519SigningKeyId: nearAccountId,
      authority: passkeyPolicyAuthority(nearAccountId, rpId, `cred-${sessionId}`),
      relayerKeyId,
      thresholdSessionId: sessionId,
      signingGrantId,
      participantIds: [1, 2],
      ttlMs: 300_000,
      remainingUses,
      routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    });
    const result = await ed25519Scheme.session({
      relayerKeyId,
      sessionPolicy: policy,
      auth: {
        kind: 'passkey',
        expected_origin: 'http://localhost',
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
      },
    });
    expect(result.ok).toBe(true);
  }

  const firstSessionId = 'tsess-wallet-budget-refresh-1';
  const secondSessionId = 'tsess-wallet-budget-refresh-2';
  const firstSigningGrantId = 'wsess-wallet-budget-refresh-1';
  const secondSigningGrantId = 'wsess-wallet-budget-refresh-2';
  const firstWalletBudgetSessionId = walletSigningBudgetSessionId({
    signingGrantId: firstSigningGrantId,
  });
  const secondWalletBudgetSessionId = walletSigningBudgetSessionId({
    signingGrantId: secondSigningGrantId,
  });

  await mintSession(firstSessionId, firstSigningGrantId, 2);
  expect(await walletBudgetSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: true,
    remainingUses: 1,
  });
  expect(await walletBudgetSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: true,
    remainingUses: 0,
  });
  expect(await walletBudgetSessionStore.consumeUseCount(firstWalletBudgetSessionId)).toMatchObject({
    ok: false,
    code: 'wallet_budget_exhausted',
  });

  await mintSession(secondSessionId, secondSigningGrantId, 3);
  expect(await walletBudgetSessionStore.consumeUseCount(secondWalletBudgetSessionId)).toMatchObject({
    ok: true,
    remainingUses: 2,
  });
});
