import { expect, test } from '@playwright/test';
import { SIGNER_KINDS } from '@shared/utils/signerDomain';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { commitEvmFamilyThresholdEcdsaSessions } from '@/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '@/core/signingEngine/session/warmCapabilities/sealedRefreshParity';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionTestServices,
  resetWarmSessionFixtureState,
} from './helpers/warmSessionStore.fixtures';

function createBootstrapStore() {
  return {
    upsertProfile: async () => ({}),
    activateAccountSigner: async (input: ActivateAccountSignerInput) => {
      const nowMs = Date.now();
      const signer: AccountSignerRecord = {
        profileId: input.account.profileId,
        chainIdKey: input.account.chainIdKey,
        accountAddress: input.account.accountAddress,
        signerId: input.signer.signerId,
        signerType: input.signer.signerType,
        signerKind: SIGNER_KINDS.thresholdEcdsa,
        signerAuthMethod: input.signer.signerAuthMethod,
        signerSource: input.signer.signerSource,
        signerSlot: input.preferredSlot || 1,
        status: 'active',
        metadata: input.signer.metadata,
        addedAt: nowMs,
        updatedAt: nowMs,
      };
      return {
        signer,
        signerSlot: signer.signerSlot,
      };
    },
  };
}

function withEmailOtpWorkerHandleBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): ThresholdEcdsaSessionBootstrapResult {
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const backendBinding = keyRef.backendBinding;
  if (backendBinding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('test fixture expected role-local ready-state bootstrap binding');
  }
  return {
    ...bootstrap,
    thresholdEcdsaKeyRef: {
      ...keyRef,
      backendBinding: {
        materialKind: 'email_otp_worker_handle',
        relayerKeyId: backendBinding.relayerKeyId,
        clientVerifyingShareB64u: backendBinding.clientVerifyingShareB64u,
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: bootstrap.session.thresholdSessionId,
        },
        ecdsaRoleLocalReadyRecord: backendBinding.ecdsaRoleLocalReadyRecord,
      },
    },
  };
}

test.describe('Email OTP ECDSA bootstrap commit', () => {
  test('marks worker-provisioned Email OTP material ready before warm capability assertion', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const bootstrap = withEmailOtpWorkerHandleBootstrap(
      createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'email-otp-ecdsa-ready.testnet',
        chain: 'tempo',
        roleLocalAuthMethod: 'email_otp',
        remainingUses: 3,
      }),
    );
    const warmCapabilityReader = createWarmSessionTestServices({
      getEmailOtpWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 3,
        expiresAtMs: bootstrap.session.expiresAtMs,
      }),
    });

    const result = await commitEvmFamilyThresholdEcdsaSessions(
      {
        queueByWallet: new Map(),
        bootstrapStore: createBootstrapStore(),
        ecdsaSessions,
        warmCapabilityReader,
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: async (parityArgs) =>
          ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(async () => {
            throw Object.assign(
              new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502'),
              { code: 'sealed_refresh_parity_http_error' },
            );
          }, parityArgs),
      },
      {
        walletId: toWalletId('email-otp-ecdsa-ready.testnet'),
        chainTarget: bootstrap.thresholdEcdsaKeyRef.chainTarget,
        bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
          policy: 'session',
          retention: 'session',
          reason: 'sign',
          provider: 'google',
          providerUserId: 'google:email-otp-ecdsa-ready',
        }),
      },
    );

    expect(result.warmCapability.state).toBe('ready');
    expect(result.warmCapability.record?.thresholdSessionId).toBe(
      bootstrap.session.thresholdSessionId,
    );
  });
});
