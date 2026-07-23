import { expect, test } from '@playwright/test';
import { SIGNER_KINDS } from '@shared/utils/signerDomain';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { commitEvmFamilyThresholdEcdsaSessions } from '@/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from '@/core/signingEngine/session/warmCapabilities/sealedRefreshParity';
import { readPersistedAvailableSigningLanesForTargets } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { listStoredThresholdEcdsaSessionRecordsForWallet } from '@/core/signingEngine/session/persistence/records';
import { accountSignerRecordFromActivateInput } from './helpers/accountSignerRecord.fixtures';
import { createWarmSessionTestServices } from './helpers/warmSessionTestServices.fixtures';
import {
  resetWarmSessionFixtureState,
  createThresholdEcdsaStoreFixture,
} from './helpers/signingSessionRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import type { SigningSessionBudgetStatusCheck } from '@/core/signingEngine/session/budget/budget';
import type { SigningSessionStatus } from '@/core/types/seams';

async function exhaustedEcdsaSharedWalletBudgetStatus(
  check: SigningSessionBudgetStatusCheck,
): Promise<SigningSessionStatus> {
  expect(check).toMatchObject({
    kind: 'authenticated_ecdsa_lane_budget_status_check',
    trustedStatusAuth: {
      relayerUrl: expect.any(String),
      thresholdSessionId: expect.any(String),
      walletSessionJwt: expect.any(String),
    },
  });
  return {
    sessionId: String(check.signingGrantId),
    status: 'exhausted',
    remainingUses: 0,
    expiresAtMs: Date.now() + 60_000,
  };
}

async function activeEcdsaWarmSessionStatus() {
  return {
    ok: true as const,
    remainingUses: 3,
    expiresAtMs: Date.now() + 60_000,
  };
}

function createBootstrapStore() {
  return {
    upsertProfile: async () => ({}),
    activateAccountSigner: async (input: ActivateAccountSignerInput) => {
      const signer = accountSignerRecordFromActivateInput(input, {
        signerKind: SIGNER_KINDS.thresholdEcdsa,
      });
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
        persistEcdsaRoleLocalReadyRecord: async () => ({
          ok: true,
          value: { kind: 'persisted' },
        }),
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
          walletId: toWalletId('email-otp-ecdsa-ready.testnet'),
          emailHashHex: '11'.repeat(32),
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

  test('keeps Email OTP registration ECDSA lane ready in persisted signing availability', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const walletId = toWalletId('email-otp-ecdsa-availability.testnet');
    const bootstrap = withEmailOtpWorkerHandleBootstrap(
      createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'tempo',
        roleLocalAuthMethod: 'email_otp',
        emailOtpAuthSubjectId: 'google:email-otp-ecdsa-availability',
        remainingUses: 3,
      }),
    );
    const chainTarget = bootstrap.thresholdEcdsaKeyRef.chainTarget;
    const warmCapabilityReader = createWarmSessionTestServices({
      getEmailOtpWarmSessionStatus: async (sessionId) => {
        expect(sessionId).toBe(bootstrap.session.thresholdSessionId);
        return {
          ok: true,
          remainingUses: 3,
          expiresAtMs: bootstrap.session.expiresAtMs,
        };
      },
    });

    await commitEvmFamilyThresholdEcdsaSessions(
      {
        queueByWallet: new Map(),
        bootstrapStore: createBootstrapStore(),
        ecdsaSessions,
        warmCapabilityReader,
        persistEcdsaRoleLocalReadyRecord: async () => ({
          ok: true,
          value: { kind: 'persisted' },
        }),
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: async () => undefined,
      },
      {
        walletId,
        chainTarget,
        bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
          policy: 'session',
          walletId,
          emailHashHex: '33'.repeat(32),
          retention: 'session',
          reason: 'sign',
          provider: 'google',
          providerUserId: 'google:email-otp-ecdsa-availability',
        }),
      },
    );

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions,
        statusReader: {
          getWarmSessionStatus: async () => ({
            ok: false,
            code: 'not_found',
            message: 'passkey status is not used for Email OTP ECDSA',
          }),
        },
        getEmailOtpWarmSessionStatus: async (sessionId) => {
          expect(sessionId).toBe(bootstrap.session.thresholdSessionId);
          return {
            ok: true,
            remainingUses: 3,
            expiresAtMs: bootstrap.session.expiresAtMs,
          };
        },
      },
      {
        walletId,
        authMethod: 'email_otp',
        ecdsaChainTargets: [chainTarget],
      },
    );

    expect(lanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(chainTarget)]).toMatchObject({
      auth: { kind: 'email_otp' },
      curve: 'ecdsa',
      state: 'ready',
      source: 'runtime_session_record',
      thresholdSessionId: bootstrap.session.thresholdSessionId,
      signingGrantId: bootstrap.session.signingGrantId,
      remainingUses: 3,
    });

    const exhaustedLanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions,
        statusReader: {
          getWarmSessionStatus: async () => ({
            ok: false,
            code: 'not_found',
            message: 'passkey status is not used for Email OTP ECDSA',
          }),
        },
        getEmailOtpWarmSessionStatus: activeEcdsaWarmSessionStatus,
        getWalletSigningBudgetStatus: exhaustedEcdsaSharedWalletBudgetStatus,
      },
      {
        walletId,
        authMethod: 'email_otp',
        ecdsaChainTargets: [chainTarget],
      },
    );

    expect(
      exhaustedLanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(chainTarget)],
    ).toMatchObject({
      curve: 'ecdsa',
      state: 'exhausted',
      remainingUses: 0,
      thresholdSessionId: bootstrap.session.thresholdSessionId,
      signingGrantId: bootstrap.session.signingGrantId,
    });
  });

  test('keeps sibling Tempo and Arc Email OTP exact records during registration', async () => {
    const ecdsaSessions = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaSessions);
    const walletId = toWalletId('email-otp-ecdsa-siblings.testnet');
    const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      walletId,
      emailHashHex: '22'.repeat(32),
      retention: 'session',
      reason: 'sign',
      provider: 'google',
      providerUserId: 'google:email-otp-ecdsa-siblings',
    });
    const warmCapabilityReader = createWarmSessionTestServices({
      getEmailOtpWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 3,
        expiresAtMs: Date.now() + 120_000,
      }),
    });
    const tempoBootstrap = withEmailOtpWorkerHandleBootstrap(
      createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'tempo',
        roleLocalAuthMethod: 'email_otp',
        emailOtpAuthSubjectId: 'google:email-otp-ecdsa-siblings',
        sessionId: 'sess-tempo-sibling',
        remainingUses: 3,
      }),
    );
    const arcBootstrap = withEmailOtpWorkerHandleBootstrap(
      createThresholdEcdsaBootstrapFixture({
        nearAccountId: walletId,
        chain: 'evm',
        roleLocalAuthMethod: 'email_otp',
        emailOtpAuthSubjectId: 'google:email-otp-ecdsa-siblings',
        sessionId: 'sess-arc-sibling',
        remainingUses: 3,
      }),
    );

    await commitEvmFamilyThresholdEcdsaSessions(
      {
        queueByWallet: new Map(),
        bootstrapStore: createBootstrapStore(),
        ecdsaSessions,
        warmCapabilityReader,
        persistEcdsaRoleLocalReadyRecord: async () => ({
          ok: true,
          value: { kind: 'persisted' },
        }),
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: async () => undefined,
      },
      {
        walletId,
        chainTarget: tempoBootstrap.thresholdEcdsaKeyRef.chainTarget,
        bootstrap: tempoBootstrap,
        source: 'email_otp',
        emailOtpAuthContext,
      },
    );
    await commitEvmFamilyThresholdEcdsaSessions(
      {
        queueByWallet: new Map(),
        bootstrapStore: createBootstrapStore(),
        ecdsaSessions,
        warmCapabilityReader,
        persistEcdsaRoleLocalReadyRecord: async () => ({
          ok: true,
          value: { kind: 'persisted' },
        }),
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: async () => undefined,
      },
      {
        walletId,
        chainTarget: arcBootstrap.thresholdEcdsaKeyRef.chainTarget,
        bootstrap: arcBootstrap,
        source: 'email_otp',
        emailOtpAuthContext,
      },
    );

    const records = listStoredThresholdEcdsaSessionRecordsForWallet(walletId, {
      source: 'email_otp',
    });
    expect(records.map((record) => thresholdEcdsaChainTargetKey(record.chainTarget)).sort()).toEqual(
      [
        thresholdEcdsaChainTargetKey(arcBootstrap.thresholdEcdsaKeyRef.chainTarget),
        thresholdEcdsaChainTargetKey(tempoBootstrap.thresholdEcdsaKeyRef.chainTarget),
      ].sort(),
    );
  });
});
