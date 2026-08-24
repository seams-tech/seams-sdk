import { expect, test } from '@playwright/test';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  commitWorkerProvisionedThresholdEcdsaSession,
  type CommitWorkerProvisionedThresholdEcdsaSessionDeps,
} from '@/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit';
import { buildEmailOtpAuthContextForCanonicalWallet } from '@/core/signingEngine/session/identity/laneIdentity';
import { accountSignerRecordFromActivateInput } from './helpers/accountSignerRecord.fixtures';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

test('Email OTP ECDSA bootstrap commit keeps canonical manifest authority', async () => {
  const { authority: canonicalAuthorityValue, manifest } =
    await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp', {
      targetMemberships: [
        {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 1,
          networkSlug: 'ethereum',
        },
        {
          kind: 'tempo',
          chainId: 42_431,
          networkSlug: 'tempo-testnet',
        },
      ],
    });
  const tempoTarget = manifest.signer.scope.targetMemberships[1];
  if (!tempoTarget) throw new Error('ECDSA fixture must have a sibling Tempo target');
  const walletId = manifest.signer.walletId;
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: String(walletId),
    chain: 'tempo',
    sessionId: 'email-otp-tempo-commit',
    roleLocalAuthMethod: 'email_otp',
    emailOtpAuthSubjectId: 'email:route-subject',
  });
  const routeAuthContext = buildEmailOtpAuthContextForCanonicalWallet({
    policy: 'session',
    retention: 'session',
    reason: 'login',
    walletId,
    provider: 'email',
    providerUserId: 'email:route-subject',
    emailHashHex: 'route-email-hash',
  });
  const canonicalAuthority = manifest.signer.authority;
  const routeAuthority = await walletAuthAuthorityRef({ authority: routeAuthContext.authority });
  expect(canonicalAuthorityValue.factor.provider).toBe('google');
  expect(routeAuthContext.authority.factor.provider).toBe('email');
  expect(routeAuthority.authorityDigest).not.toBe(canonicalAuthority.authorityDigest);

  let persistedProjection: ActiveWalletSessionAuthorizationProjection | undefined;
  const originalRead = walletSessionAuthorizations.readActiveForWallet;
  const originalReplace = walletSessionAuthorizations.replaceActive;
  walletSessionAuthorizations.readActiveForWallet = async () => ({ kind: 'missing' });
  walletSessionAuthorizations.replaceActive = async ({ active }) => {
    persistedProjection = active;
  };

  const deps: CommitWorkerProvisionedThresholdEcdsaSessionDeps = {
    queueByWallet: new Map(),
    bootstrapStore: {
      upsertProfile: async () => ({}),
      activateAccountSigner: async (input) => {
        const signer = accountSignerRecordFromActivateInput(input);
        return { signer, signerSlot: signer.signerSlot };
      },
    },
    persistEcdsaRoleLocalReadyRecord: async () => ({
      ok: true,
      value: { kind: 'persisted' },
    }),
    ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: async () => undefined,
  };

  try {
    const committed = await commitWorkerProvisionedThresholdEcdsaSession(deps, {
      walletId,
      chainTarget: tempoTarget,
      bootstrap,
      source: 'email_otp',
      authority: canonicalAuthority,
      emailOtpAuthContext: routeAuthContext,
    });

    expect(committed.authorization.authority).toEqual(canonicalAuthority);
    expect(persistedProjection?.authority).toEqual(canonicalAuthority);
    expect(persistedProjection?.authority.authorityDigest).not.toBe(routeAuthority.authorityDigest);
  } finally {
    walletSessionAuthorizations.readActiveForWallet = originalRead;
    walletSessionAuthorizations.replaceActive = originalReplace;
  }
});
