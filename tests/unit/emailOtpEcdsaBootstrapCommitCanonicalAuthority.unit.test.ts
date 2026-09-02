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
  const canonicalBootstrap = {
    ...bootstrap,
    session: {
      ...bootstrap.session,
      walletSession: {
        ...bootstrap.session.walletSession,
        authMethodId: canonicalAuthority.walletAuthMethodId,
        authorityDigestB64u: canonicalAuthority.authorityDigest,
      },
    },
  };

  let persistedExact:
    | Parameters<typeof walletSessionAuthorizations.writeExactWithOperationCredential>[0]
    | undefined;
  const originalWriteExact = walletSessionAuthorizations.writeExactWithOperationCredential;
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => {
    persistedExact = input;
    return input.record;
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
      bootstrap: canonicalBootstrap,
      source: 'email_otp',
      authority: canonicalAuthority,
      emailOtpAuthContext: routeAuthContext,
    });

    expect(committed.authorization.record).toEqual(canonicalBootstrap.session.walletSession);
    expect(committed.authorization.operationCredential).toEqual(
      bootstrap.session.operationCredential,
    );
    expect(String(committed.authorization.record.authorityDigestB64u)).toBe(
      String(canonicalAuthority.authorityDigest),
    );
    expect(String(committed.authorization.record.authorityDigestB64u)).not.toBe(
      String(routeAuthority.authorityDigest),
    );
    expect(persistedExact?.record).toEqual(canonicalBootstrap.session.walletSession);
    expect(persistedExact?.operationCredential).toEqual(
      canonicalBootstrap.session.operationCredential,
    );
  } finally {
    walletSessionAuthorizations.writeExactWithOperationCredential = originalWriteExact;
  }
});
