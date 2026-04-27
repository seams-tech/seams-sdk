import { expect, test } from '@playwright/test';
import { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSigning/persistence';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function appSessionJwt(expSeconds = Math.floor(Date.now() / 1000) + 3600): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    exp: expSeconds,
  })}.sig`;
}

function createCoordinator(overrides?: {
  requestWorkerOperation?: (call: any) => Promise<any>;
  refreshAppSessionJwt?: () => Promise<string>;
  requestUserConfirmation?: (request: any) => Promise<any>;
  configs?: Record<string, any>;
  writeSigningSessionSealedRecord?: (args: any) => Promise<void>;
  readSigningSessionSealedRecord?: (thresholdSessionId: string, purpose?: any) => Promise<any>;
  listSigningSessionSealedRecordsForAccount?: (args: any) => Promise<any[]>;
  getThresholdEcdsaKeyRefForLookup?: (args: any) => any;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (thresholdSessionId: string) => any;
  acquireSigningSessionRestoreLease?: (args: any) => Promise<any>;
  releaseSigningSessionRestoreLease?: (lease: any) => Promise<void>;
}) {
  const workerCalls: any[] = [];
  let refreshCount = 0;
  const worker = {
    requestWorkerOperation: async (call: any) => {
      workerCalls.push(call);
      if (overrides?.requestWorkerOperation) {
        return overrides.requestWorkerOperation(call);
      }
      if (call.request?.type === 'requestEmailOtpChallenge') {
        return { challengeId: 'challenge-1', emailHint: 'a***@example.com' };
      }
      if (call.request?.type === 'loginWithEmailOtpWallet') {
        return { recovery: { thresholdEd25519PrfFirstB64u: 'prf-first' } };
      }
      if (call.request?.type === 'recoverEmailOtpEd25519ExportPrfFirst') {
        return {
          challengeId: call.request.payload.challengeId,
          thresholdEd25519PrfFirstB64u: 'prf-first',
        };
      }
      if (call.request?.type === 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization') {
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: '11'.repeat(32),
          ethereumAddress: '0x'.padEnd(42, 'a'),
        };
      }
      if (call.request?.type === 'loginWithEmailOtpAndBootstrapEcdsaSession') {
        return {
          recovery: {
            loginGrant: 'login-grant',
            challengeId: call.request.payload.challengeId,
            enrollmentSealKeyVersion: 'email-v1',
            unlockChallengeId: 'unlock-challenge',
            unlockChallengeB64u: 'unlock-challenge-b64u',
            clientUnlockPublicKeyB64u: 'unlock-public',
            unlockSignatureB64u: 'unlock-sig',
            thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-login',
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: call.request.payload.walletId,
              relayerUrl: call.request.payload.relayUrl,
              ecdsaThresholdKeyId: 'ecdsa-key',
              signingRootId: 'signing-root',
              thresholdSessionId: call.request.payload.sessionId || 'ecdsa-session',
              walletSigningSessionId:
                call.request.payload.walletSigningSessionId ||
                call.request.payload.sessionId ||
                'ecdsa-session',
              thresholdSessionJwt: 'threshold-session-jwt',
            },
            keygen: { ok: true },
            session: {
              ok: true,
              sessionId: call.request.payload.sessionId || 'ecdsa-session',
              walletSigningSessionId:
                call.request.payload.walletSigningSessionId ||
                call.request.payload.sessionId ||
                'ecdsa-session',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
              jwt: 'threshold-session-jwt',
            },
          },
        };
      }
      if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
        return {
          ok: true,
          sealedSecretB64u: 'sealed-email-otp-session-secret',
          keyVersion: 'seal-v1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        };
      }
      if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
        return {
          ok: true,
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: call.request.payload.restore.userId || call.request.payload.restore.walletId,
              relayerUrl: call.request.payload.transport.relayerUrl,
              ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
              signingRootId: call.request.payload.restore.signingRootId,
              signingRootVersion: call.request.payload.restore.signingRootVersion,
              thresholdSessionId: call.request.payload.restore.sessionId,
              walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
              thresholdSessionJwt: call.request.payload.transport.thresholdSessionJwt,
            },
            keygen: { ok: true },
            session: {
              ok: true,
              sessionId: call.request.payload.restore.sessionId,
              walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 2,
              jwt: call.request.payload.transport.thresholdSessionJwt,
            },
          },
        };
      }
      if (call.request?.type === 'enrollEmailOtpWalletAndBootstrapEcdsaSession') {
        return {
          enrollment: {
            thresholdEcdsaClientVerifyingShareB64u: 'verifying-share',
            challengeId: call.request.payload.challengeId,
            otpChannel: 'email_otp',
            enrollmentSealKeyVersion: 'email-v1',
            clientUnlockPublicKeyB64u: 'unlock-public',
            unlockKeyVersion: 'unlock-v1',
            thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-enroll',
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: call.request.payload.walletId,
              relayerUrl: call.request.payload.relayUrl,
              ecdsaThresholdKeyId: 'ecdsa-key',
              signingRootId: 'signing-root',
              thresholdSessionId: call.request.payload.sessionId || 'ecdsa-session',
              walletSigningSessionId:
                call.request.payload.walletSigningSessionId ||
                call.request.payload.sessionId ||
                'ecdsa-session',
              thresholdSessionJwt: 'threshold-session-jwt',
            },
            keygen: { ok: true },
            session: {
              ok: true,
              sessionId: call.request.payload.sessionId || 'ecdsa-session',
              walletSigningSessionId:
                call.request.payload.walletSigningSessionId ||
                call.request.payload.sessionId ||
                'ecdsa-session',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
              jwt: 'threshold-session-jwt',
            },
          },
        };
      }
      return { ok: true };
    },
  };
  const ecdsaCommitCalls: any[] = [];
  const ed25519ProvisionCalls: any[] = [];
  const ed25519MetadataWrites: any[] = [];
  const ed25519WarmSessionWrites: any[] = [];
  const hydratedSessions: any[] = [];
  const sealedRecordWrites: any[] = [];
  const baseConfigs = {
    network: {
      relayer: { url: 'https://relay.example' },
    },
    signing: {
      emailOtp: { authPolicy: 'per_operation' },
      sessionPersistenceMode: 'none',
      sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
    },
  };
  const coordinator = new EmailOtpThresholdSessionCoordinator({
    configs: {
      ...baseConfigs,
      ...(overrides?.configs || {}),
      network: {
        ...baseConfigs.network,
        ...(overrides?.configs?.network || {}),
      },
      signing: {
        ...baseConfigs.signing,
        ...(overrides?.configs?.signing || {}),
        emailOtp: {
          ...baseConfigs.signing.emailOtp,
          ...(overrides?.configs?.signing?.emailOtp || {}),
        },
        sessionSeal: {
          ...baseConfigs.signing.sessionSeal,
          ...(overrides?.configs?.signing?.sessionSeal || {}),
        },
      },
    } as any,
    signerWorkerManager: worker as any,
    touchIdPrompt: { getRpId: () => 'localhost' } as any,
    requestUserConfirmation:
      overrides?.requestUserConfirmation ||
      (async () => ({
        confirmed: true,
        otpCode: '123456',
      })),
    getSignerWorkerContext: () => worker as any,
    refreshAppSessionJwt: async () => {
      refreshCount += 1;
      return overrides?.refreshAppSessionJwt ? overrides.refreshAppSessionJwt() : appSessionJwt();
    },
    commitWorkerProvisionedThresholdEcdsaSessions: async (args) => {
      ecdsaCommitCalls.push(args);
      return {
        bootstrap: args.bootstrap,
        warmCapability: { capability: 'ecdsa', state: 'ready' } as any,
      };
    },
    getThresholdEcdsaKeyRefForLookup:
      overrides?.getThresholdEcdsaKeyRefForLookup ||
      ((args) =>
        ({
          type: 'threshold-ecdsa-secp256k1',
          userId: String(args.nearAccountId),
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key',
          ethereumAddress: '0xabc',
        }) as any),
    ...(overrides?.getThresholdEcdsaSessionRecordByThresholdSessionId
      ? {
          getThresholdEcdsaSessionRecordByThresholdSessionId:
            overrides.getThresholdEcdsaSessionRecordByThresholdSessionId,
        }
      : {}),
    persistEmailOtpThresholdEd25519LocalMetadata: async (args) => {
      ed25519MetadataWrites.push(args);
    },
    persistWarmSessionEd25519Capability: async (args) => {
      ed25519WarmSessionWrites.push(args);
    },
    hydrateSigningSession: async (args) => {
      hydratedSessions.push(args);
    },
    writeSigningSessionSealedRecord: async (args) => {
      sealedRecordWrites.push(args);
      if (overrides?.writeSigningSessionSealedRecord) {
        await overrides.writeSigningSessionSealedRecord(args);
      }
    },
    readSigningSessionSealedRecord:
      overrides?.readSigningSessionSealedRecord ||
      (async (thresholdSessionId: string) => {
        const record = sealedRecordWrites.find(
          (write) => write.thresholdSessionId === thresholdSessionId,
        );
        if (!record) return null;
        return {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'unit-test-runtime',
          authMethod: record.authMethod || 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: record.walletSigningSessionId,
          thresholdSessionIds: record.thresholdSessionIds,
          sealedSecretB64u: record.sealedSecretB64u,
          curve: record.curve,
          walletId: record.walletId,
          userId: record.userId,
          signingRootId: record.signingRootId,
          signingRootVersion: record.signingRootVersion,
          relayerUrl: record.relayerUrl,
          keyVersion: record.keyVersion,
          shamirPrimeB64u: record.shamirPrimeB64u,
          ecdsaRestore: record.ecdsaRestore,
          issuedAtMs: record.issuedAtMs || Date.now(),
          expiresAtMs: record.expiresAtMs,
          remainingUses: record.remainingUses,
          updatedAtMs: record.updatedAtMs || Date.now(),
        };
      }),
    ...(overrides?.listSigningSessionSealedRecordsForAccount
      ? { listSigningSessionSealedRecordsForAccount: overrides.listSigningSessionSealedRecordsForAccount }
      : {}),
    ...(overrides?.acquireSigningSessionRestoreLease
      ? { acquireSigningSessionRestoreLease: overrides.acquireSigningSessionRestoreLease as any }
      : {}),
    ...(overrides?.releaseSigningSessionRestoreLease
      ? { releaseSigningSessionRestoreLease: overrides.releaseSigningSessionRestoreLease }
      : {}),
  });

  return {
    coordinator,
    workerCalls,
    ecdsaCommitCalls,
    ed25519ProvisionCalls,
    ed25519MetadataWrites,
    ed25519WarmSessionWrites,
    hydratedSessions,
    sealedRecordWrites,
    getRefreshCount: () => refreshCount,
  };
}

test.describe('EmailOtpThresholdSessionCoordinator', () => {
  test('normalizes warm-session status requests and maps worker failures', async () => {
    const invalid = createCoordinator();
    await expect(invalid.coordinator.getWarmSessionStatus('   ')).resolves.toMatchObject({
      ok: false,
      code: 'invalid_args',
    });
    expect(invalid.workerCalls).toHaveLength(0);

    const failing = createCoordinator({
      requestWorkerOperation: async () => {
        throw new Error('worker unavailable');
      },
    });
    await expect(failing.coordinator.getWarmSessionStatus(' session-1 ')).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
      message: 'worker unavailable',
    });
    expect(failing.workerCalls[0].request.payload.sessionId).toBe('session-1');
  });

  test('consumes warm-session uses without returning secret material', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      requestWorkerOperation: async () => ({
        ok: true,
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const result = await coordinator.consumeWarmSessionUses({ sessionId: ' session-1 ', uses: 2 });

    expect(result).toMatchObject({ ok: true, remainingUses: 2 });
    expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'consumeEmailOtpWarmSessionUses',
        payload: {
          sessionId: 'session-1',
          uses: 2,
        },
      },
    });
  });

  test('requests transaction challenges with signing-session auth only', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();
    const thresholdSessionJwt = 'threshold-session-jwt';

    const challenge = await coordinator.requestTransactionSigningChallenge({
      nearAccountId: 'alice.testnet',
      chain: 'near',
      authLane: {
        kind: 'signing_session',
        jwt: thresholdSessionJwt,
        thresholdSessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-signing-session',
        curve: 'ed25519',
      },
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
    });
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: thresholdSessionJwt,
              thresholdSessionId: 'ed25519-session',
              walletSigningSessionId: 'wallet-signing-session',
              curve: 'ed25519',
            },
            operation: 'transaction_sign',
          },
          otpChannel: 'email_otp',
        },
      },
    });
  });

  test('signing-session challenge requests fail closed without signing-session authority', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        nearAccountId: 'alice.testnet',
        chain: 'near',
      }),
    ).rejects.toThrow('Email OTP signing-session authority is unavailable; unlock wallet again');

    expect(getRefreshCount()).toBe(0);
    expect(workerCalls).toHaveLength(0);
  });

  test('Email OTP export resend updates the challenge used for authorization', async () => {
    const challengeRequests: Array<Record<string, unknown>> = [];
    const thresholdSessionJwt = 'threshold-session-jwt';
    const { coordinator } = createCoordinator({
      requestWorkerOperation: async (call) => {
        if (call.request?.type !== 'requestEmailOtpChallenge') return { ok: true };
        challengeRequests.push(call.request.payload);
        const issueNumber = challengeRequests.length;
        return {
          challengeId: `export-challenge-${issueNumber}`,
          emailHint: `a***${issueNumber}@example.test`,
        };
      },
      requestUserConfirmation: async (request) => {
        expect(request.payload.signingAuthPlan.emailOtpPrompt.challengeId).toBe(
          'export-challenge-1',
        );
        const resent = await request.payload.signingAuthPlan.emailOtpPrompt.onResend();
        expect(resent).toEqual({
          challengeId: 'export-challenge-2',
          emailHint: 'a***2@example.test',
        });
        return {
          confirmed: true,
          otpCode: '654321',
          emailOtpChallengeId: resent.challengeId,
        };
      },
    });

    await expect(
      coordinator.requestExportAuthorization({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        publicKey: '02'.padEnd(66, '1'),
        curve: 'ecdsa',
        authLane: {
          kind: 'signing_session',
          jwt: thresholdSessionJwt,
          thresholdSessionId: 'ecdsa-session',
          walletSigningSessionId: 'wallet-signing-session',
          curve: 'ecdsa',
          chain: 'evm',
        },
      }),
    ).resolves.toEqual({
      challengeId: 'export-challenge-2',
      otpCode: '654321',
    });
    expect(challengeRequests).toEqual([
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: thresholdSessionJwt,
            thresholdSessionId: 'ecdsa-session',
            walletSigningSessionId: 'wallet-signing-session',
            curve: 'ecdsa',
            chain: 'evm',
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: thresholdSessionJwt,
            thresholdSessionId: 'ecdsa-session',
            walletSigningSessionId: 'wallet-signing-session',
            curve: 'ecdsa',
            chain: 'evm',
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
    ]);
  });

  test('transaction challenges reject app-session route auth instead of resolving it', async () => {
    const { coordinator, getRefreshCount, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        nearAccountId: 'alice.testnet',
        chain: 'near',
        routeAuth: { kind: 'app_session', jwt },
      }),
    ).rejects.toThrow('Email OTP signing-session authority is unavailable; unlock wallet again');

    expect(getRefreshCount()).toBe(0);
    expect(workerCalls).toHaveLength(0);
  });

  test('logs in Ed25519 Email OTP capability with normalized auth context', async () => {
    const { coordinator, ed25519ProvisionCalls } = createCoordinator();
    const thresholdSessionJwt = 'threshold-jwt';
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt',
      };
    };

    const result = await coordinator.loginWithEd25519CapabilityForSigning({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      record: {
        thresholdSessionId: 'old-session',
        relayerUrl: '',
        rpId: '',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionJwt,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        source: 'email_otp',
      } as any,
    });

    expect(result.sessionId).toBe('ed-session');
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      prfFirstB64u: 'prf-first-ecdsa-login',
      routeAuth: { kind: 'threshold_session', jwt: 'threshold-session-jwt' },
      participantIds: [1, 2],
      remainingUses: 1,
      ecdsaThresholdSessionId: 'ecdsa-session',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
    });
  });

  test('Ed25519 Email OTP refresh mints a fresh wallet signing-session budget', async () => {
    const staleWalletSigningSessionId = 'wallet-signing-session-exhausted';
    const mismatchedEcdsaWalletSigningSessionId = 'wallet-signing-session-other-curve';
    const { coordinator, workerCalls, ed25519ProvisionCalls } = createCoordinator({
      getThresholdEcdsaKeyRefForLookup: (args) =>
        ({
          type: 'threshold-ecdsa-secp256k1',
          userId: String(args.nearAccountId),
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key-from-other-wallet-session',
          ethereumAddress: '0xabc',
          walletSigningSessionId: mismatchedEcdsaWalletSigningSessionId,
          participantIds: [7, 8],
        }) as any,
    });
    const thresholdSessionJwt = 'threshold-jwt';
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session-refreshed',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt-refreshed',
      };
    };

    const result = await coordinator.loginWithEd25519CapabilityForSigning({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      record: {
        thresholdSessionId: 'old-ed25519-session',
        walletSigningSessionId: staleWalletSigningSessionId,
        relayerUrl: '',
        rpId: '',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionJwt,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 0,
        source: 'email_otp',
      } as any,
    });

    const ecdsaLoginCall = workerCalls.find(
      (call) => call.request?.type === 'loginWithEmailOtpAndBootstrapEcdsaSession',
    );
    expect(result.sessionId).toBe('ed-session-refreshed');
    expect(ecdsaLoginCall?.request.payload.ecdsaThresholdKeyId).toBe(
      'ecdsa-key-from-other-wallet-session',
    );
    expect(ecdsaLoginCall?.request.payload.walletSigningSessionId).toBeTruthy();
    expect(ecdsaLoginCall?.request.payload.walletSigningSessionId).not.toBe(
      staleWalletSigningSessionId,
    );
    expect(ecdsaLoginCall?.request.payload.walletSigningSessionId).not.toBe(
      mismatchedEcdsaWalletSigningSessionId,
    );
    expect(ecdsaLoginCall?.request.payload.routePlan.authLane).toMatchObject({
      kind: 'signing_session',
      thresholdSessionId: 'old-ed25519-session',
      walletSigningSessionId: staleWalletSigningSessionId,
      curve: 'ed25519',
    });
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      participantIds: [1, 2],
      ecdsaThresholdSessionId: 'ecdsa-session',
    });
    expect(ed25519ProvisionCalls[0].walletSigningSessionId).toBe(
      ecdsaLoginCall?.request.payload.walletSigningSessionId,
    );
  });

  test('recovers Ed25519 export material without provisioning or hydrating a signing session', async () => {
    const { coordinator, workerCalls, ed25519ProvisionCalls, hydratedSessions, getRefreshCount } =
      createCoordinator();
    const thresholdSessionJwt = `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
      kind: 'threshold_ed25519_session_v1',
      sessionId: 'ed25519-restored-session',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.sig`;
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      throw new Error('Ed25519 export must not provision a signing session');
    };

    const result = await coordinator.recoverEd25519ExportPrfFirst({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      record: {
        thresholdSessionId: 'ed25519-restored-session',
        walletSigningSessionId: 'wallet-signing-session-1',
        relayerUrl: 'https://relay.example',
        rpId: 'localhost',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionJwt,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 4,
        source: 'email_otp',
      } as any,
    });

    expect(result).toEqual({ prfFirstB64u: 'prf-first' });
    expect(ed25519ProvisionCalls).toEqual([]);
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0].request).toMatchObject({
      type: 'recoverEmailOtpEd25519ExportPrfFirst',
      payload: {
        walletId: 'alice.testnet',
        challengeId: 'challenge-1',
        otpCode: '123456',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: thresholdSessionJwt,
            thresholdSessionId: 'ed25519-restored-session',
            walletSigningSessionId: 'wallet-signing-session-1',
            curve: 'ed25519',
          },
          operation: 'export_key',
        },
      },
    });
    expect(hydratedSessions).toEqual([]);
  });

  test('logs in ECDSA Email OTP capability with normalized worker payload and persistence callback', async () => {
    const { coordinator, workerCalls, ecdsaCommitCalls, ed25519ProvisionCalls } =
      createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt',
      };
    };

    const result = await coordinator.loginWithEcdsaCapabilityInternal({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'proj',
        envId: 'dev',
        signingRootVersion: 'v1',
      },
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId).toBe('ecdsa-key');
    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          challengeId: 'challenge-1',
          otpCode: '123456',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
          otpChannel: 'email_otp',
          rpId: 'localhost',
          ecdsaThresholdKeyId: 'ecdsa-key',
          participantIds: [1, 3],
          sessionKind: 'jwt',
          sessionId: 'ecdsa-session',
          remainingUses: 1,
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      primaryChain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    await expect.poll(() => ed25519ProvisionCalls.length).toBe(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      prfFirstB64u: 'prf-first-ecdsa-login',
      appSessionJwt: jwt,
      participantIds: [1, 3],
      remainingUses: 1,
    });
  });

  test('normal ECDSA Email OTP login derives app-session route auth from appSessionJwt', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session',
    });

    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        payload: {
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
        },
      },
    });
  });

  test('Email OTP registration bootstrap derives app-session route auth from appSessionJwt', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });

    await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session',
    });

    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'enrollEmailOtpWalletAndBootstrapEcdsaSession',
        payload: {
          routePlan: {
            routeFamily: 'registration',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
        },
      },
    });
  });

  test('persists sealed Email OTP signing-session refresh only for session-retained ECDSA login', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'loginWithEmailOtpAndBootstrapEcdsaSession') {
          return {
            recovery: {
              loginGrant: 'login-grant',
              challengeId: 'challenge-1',
              enrollmentSealKeyVersion: 'email-v1',
              unlockChallengeId: 'unlock-challenge',
              unlockChallengeB64u: 'unlock-challenge-b64u',
              clientUnlockPublicKeyB64u: 'unlock-public',
              unlockSignatureB64u: 'unlock-sig',
            },
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: 'ecdsa-key',
                signingRootId: 'signing-root',
                signingRootVersion: 'root-v1',
                thresholdSessionId: 'ecdsa-session',
                walletSigningSessionId: call.request.payload.walletSigningSessionId,
                thresholdSessionJwt: 'threshold-session-jwt',
              },
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: 'ecdsa-session',
                walletSigningSessionId: call.request.payload.walletSigningSessionId,
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 9,
                jwt: 'threshold-session-jwt',
              },
            },
          };
        }
        if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
          return {
            ok: true,
            sealedSecretB64u: 'sealed-email-otp-session-secret',
            keyVersion: 'seal-v1',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
          };
        }
        return { ok: true };
      },
    });
    const jwt = appSessionJwt();

    await coordinator.loginWithEcdsaCapabilityInternal({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session',
    });

    const sealCall = workerCalls.find(
      (call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial',
    );
    expect(sealCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'sealEmailOtpWarmSessionMaterial',
        payload: {
          sessionId: 'ecdsa-session',
          transport: {
            relayerUrl: 'https://relay.example',
            thresholdSessionJwt: 'threshold-session-jwt',
            keyVersion: 'seal-v1',
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
    });
    expect(sealedRecordWrites).toHaveLength(1);
    expect(sealedRecordWrites[0]).toMatchObject({
      thresholdSessionId: 'ecdsa-session',
      sealedSecretB64u: 'sealed-email-otp-session-secret',
      curve: 'ecdsa',
      authMethod: 'email_otp',
      thresholdSessionIds: { ecdsa: 'ecdsa-session' },
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime-b64u',
      remainingUses: 9,
    });
  });

  test('fails session-retained Email OTP login when sealed refresh is not durably readable', async () => {
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      readSigningSessionSealedRecord: async () => null,
    });

    await expect(
      coordinator.loginWithEcdsaCapabilityInternal({
        nearAccountId: 'alice.testnet',
        chain: 'tempo',
        challengeId: 'challenge-1',
        otpCode: '123456',
        routeAuth: { kind: 'app_session', jwt: appSessionJwt() },
        ecdsaThresholdKeyId: 'ecdsa-key',
        participantIds: [1, 3],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session',
      }),
    ).rejects.toThrow('Email OTP sealed refresh record was not durably persisted');
  });

  test('does not persist sealed Email OTP refresh records for per-operation ECDSA login', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });
    const jwt = appSessionJwt();

    await coordinator.loginWithEcdsaCapabilityInternal({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session',
    });

    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(false);
    expect(sealedRecordWrites).toHaveLength(0);
  });

  test('export ECDSA reauth uses operation-scoped auth without replacing transaction sealed refresh', async () => {
    const {
      coordinator,
      workerCalls,
      sealedRecordWrites,
      ecdsaCommitCalls,
      ed25519ProvisionCalls,
    } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    coordinator.scheduleEd25519CapabilityProvisioning = () => undefined;
    const thresholdSessionJwt = 'transaction-threshold-session-jwt';

    const artifact = await coordinator.exportEcdsaKeyWithAuthorization({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'export-challenge-1',
      otpCode: '123456',
      rpId: 'localhost',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      record: {
        nearAccountId: 'alice.testnet' as any,
        chain: 'tempo',
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-key' as any,
        signingRootId: 'signing-root',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'transaction-ecdsa-session',
        },
        participantIds: [1, 3],
        thresholdSessionKind: 'jwt',
        thresholdSessionId: 'transaction-ecdsa-session',
        walletSigningSessionId: 'transaction-wallet-signing-session',
        thresholdSessionJwt,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 7,
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        updatedAtMs: Date.now(),
        source: 'email_otp',
      },
    });

    expect(artifact).toMatchObject({
      publicKeyHex: '02'.padEnd(66, '1'),
      privateKeyHex: '11'.repeat(32),
      ethereumAddress: '0x'.padEnd(42, 'a'),
    });
    const exportCall = workerCalls.find(
      (call) => call.request?.type === 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
    );
    expect(exportCall).toMatchObject({
      request: {
        payload: {
          challengeId: 'export-challenge-1',
          otpCode: '123456',
          thresholdSessionJwt,
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: thresholdSessionJwt,
              thresholdSessionId: 'transaction-ecdsa-session',
              walletSigningSessionId: 'transaction-wallet-signing-session',
              curve: 'ecdsa',
              chain: 'tempo',
            },
            operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          },
        },
      },
    });
    expect(exportCall.request.payload).not.toHaveProperty('sessionId', 'transaction-ecdsa-session');
    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(false);
    expect(ecdsaCommitCalls).toEqual([]);
    expect(ed25519ProvisionCalls).toEqual([]);
    expect(sealedRecordWrites).toHaveLength(0);
  });

  test('rehydrates session-retained ECDSA Email OTP material from sealed refresh record', async () => {
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    const expiresAtMs = Date.now() + 60_000;

    const result = await coordinator.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord({
      sealedRecord: {
        v: 1,
        alg: 'shamir3pass-v1',
        storageScope: 'iframe_origin_indexeddb',
        runtimeSessionId: 'runtime-1',
        authMethod: 'email_otp',
        secretKind: 'signing_session_secret32',
        storeKey: 'wallet-session-1:email_otp:ecdsa',
        walletSigningSessionId: 'wallet-session-1',
        thresholdSessionIds: { ecdsa: 'ecdsa-session' },
        sealedSecretB64u: 'sealed-session-secret',
        curve: 'ecdsa',
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerUrl: 'https://relay.example',
        keyVersion: 'seal-v1',
        shamirPrimeB64u: 'prime-b64u',
        issuedAtMs: Date.now(),
        expiresAtMs,
        remainingUses: 2,
        updatedAtMs: Date.now(),
      },
      ecdsaRecord: {
        nearAccountId: 'alice.testnet' as any,
        chain: 'tempo',
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-key' as any,
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'ecdsa-session',
        },
        participantIds: [1, 3],
        thresholdSessionKind: 'jwt',
        thresholdSessionId: 'ecdsa-session',
        walletSigningSessionId: 'wallet-session-1',
        thresholdSessionJwt: 'threshold-session-jwt',
        signingSessionSealKeyVersion: 'seal-v1',
        signingSessionSealShamirPrimeB64u: 'prime-b64u',
        expiresAtMs,
        remainingUses: 2,
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        updatedAtMs: Date.now(),
        source: 'email_otp',
      },
    });

    expect(result).toMatchObject({
      remainingUses: 2,
      warmCapability: { capability: 'ecdsa', state: 'ready' },
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );
    expect(restoreCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        payload: {
          sealedSecretB64u: 'sealed-session-secret',
          remainingUses: 2,
          expiresAtMs,
          transport: {
            relayerUrl: 'https://relay.example',
            thresholdSessionJwt: 'threshold-session-jwt',
            keyVersion: 'seal-v1',
            shamirPrimeB64u: 'prime-b64u',
          },
          restore: {
            sessionId: 'ecdsa-session',
            walletId: 'alice.testnet',
            userId: 'alice.testnet',
            rpId: 'localhost',
            chain: 'tempo',
            walletSigningSessionId: 'wallet-session-1',
            signingRootId: 'signing-root',
            signingRootVersion: 'root-v1',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 3],
            sessionKind: 'jwt',
          },
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      primaryChain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
  });

  test('does not resolve ECDSA sealed refresh from an Ed25519 status read', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = {
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      runtimeSessionId: 'runtime-1',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ed25519: 'ed25519-session',
        ecdsa: 'ecdsa-session',
      },
      sealedSecretB64u: 'sealed-session-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime-b64u',
      issuedAtMs: Date.now(),
      expiresAtMs,
      remainingUses: 2,
      updatedAtMs: Date.now(),
    };
    const sealedReads: Array<{ thresholdSessionId: string; curve?: string }> = [];
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionJwt: call.request.payload.transport.thresholdSessionJwt,
              },
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionJwt,
              },
            },
          };
        }
        return { ok: true };
      },
      readSigningSessionSealedRecord: async (thresholdSessionId, purpose) => {
        sealedReads.push({ thresholdSessionId, curve: purpose?.curve });
        if (purpose?.curve === 'ed25519' && thresholdSessionId === 'ed25519-session') {
          return sealedRecord;
        }
        if (purpose?.curve === 'ecdsa' && thresholdSessionId === 'ecdsa-session') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        thresholdSessionId === 'ecdsa-session'
          ? {
              nearAccountId: 'alice.testnet' as any,
              chain: 'tempo',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ecdsa-key' as any,
              signingRootId: 'signing-root',
              signingRootVersion: 'root-v1',
              relayerKeyId: 'relayer-key',
              clientVerifyingShareB64u: 'client-verifying-share',
              clientAdditiveShareHandle: {
                kind: 'email_otp_worker_session',
                sessionId: 'ed25519-session',
              },
              participantIds: [1, 3],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'ecdsa-session',
              walletSigningSessionId: 'wallet-session-1',
              thresholdSessionJwt: 'threshold-session-jwt',
              signingSessionSealKeyVersion: 'seal-v1',
              signingSessionSealShamirPrimeB64u: 'prime-b64u',
              expiresAtMs,
              remainingUses: 2,
              emailOtpAuthContext: {
                policy: 'session',
                retention: 'session',
                reason: 'login',
                authMethod: 'email_otp',
              },
              updatedAtMs: Date.now(),
              source: 'email_otp',
            }
          : null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    try {
      persistWarmSessionEd25519Capability({
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        jwt: appSessionJwt(),
        xClientBaseB64u: 'x-client-base',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      const status = await coordinator.getWarmSessionStatus('ed25519-session');

      expect(status).toMatchObject({ ok: false, code: 'not_found' });
      expect(
        sealedReads.some(
          (read) => read.thresholdSessionId === 'ed25519-session' && read.curve === 'ecdsa',
        ),
      ).toBe(false);
      expect(
        workerCalls.some(
          (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        ),
      ).toBe(false);
      expect(ecdsaCommitCalls).toHaveLength(0);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('does not warn-spam while sealed ECDSA record waits for session record indexing', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = {
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      runtimeSessionId: 'runtime-1',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ecdsa: 'ecdsa-session',
      },
      sealedSecretB64u: 'sealed-session-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime-b64u',
      issuedAtMs: Date.now(),
      expiresAtMs,
      remainingUses: 2,
      updatedAtMs: Date.now(),
    };
    const warnCalls: any[][] = [];
    const debugCalls: any[][] = [];
    const originalWarn = console.warn;
    const originalDebug = console.debug;
    console.warn = (...args: any[]) => {
      warnCalls.push(args);
    };
    console.debug = (...args: any[]) => {
      debugCalls.push(args);
    };
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        return { ok: true };
      },
      readSigningSessionSealedRecord: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
    });

    try {
      await coordinator.getWarmSessionStatus('ecdsa-session');
      await coordinator.getWarmSessionStatus('ecdsa-session');
    } finally {
      console.warn = originalWarn;
      console.debug = originalDebug;
    }

    expect(
      warnCalls.some((args) =>
        String(args[0] || '').includes('sealed refresh restore missing session-retained ECDSA record'),
      ),
    ).toBe(false);
    expect(
      debugCalls.filter((args) =>
        String(args[0] || '').includes('sealed refresh restore waiting for ECDSA record'),
      ),
    ).toHaveLength(1);
  });

  test('does not probe ECDSA sealed restore for an Ed25519 status miss', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedReads: Array<{ thresholdSessionId: string; curve?: string }> = [];
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'worker reloaded' };
        }
        return { ok: true };
      },
      readSigningSessionSealedRecord: async (thresholdSessionId, purpose) => {
        sealedReads.push({ thresholdSessionId, curve: purpose?.curve });
        return null;
      },
    });

    try {
      persistWarmSessionEd25519Capability({
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        jwt: appSessionJwt(),
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      const status = await coordinator.getWarmSessionStatus('ed25519-session');

      expect(status).toMatchObject({ ok: false, code: 'not_found' });
      expect(sealedReads).toEqual([]);
      expect(
        workerCalls.some(
          (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        ),
      ).toBe(false);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('restores sealed ECDSA Email OTP session from durable sealed metadata after reload', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = {
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      runtimeSessionId: 'runtime-1',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ecdsa: 'ecdsa-session',
      },
      sealedSecretB64u: 'sealed-session-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime-b64u',
      ecdsaRestore: {
        chain: 'tempo',
        thresholdSessionJwt: 'threshold-session-jwt',
        sessionKind: 'jwt',
        ecdsaThresholdKeyId: 'ecdsa-key',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 3],
      },
      issuedAtMs: Date.now(),
      expiresAtMs,
      remainingUses: 2,
      updatedAtMs: Date.now(),
    };
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionJwt: call.request.payload.transport.thresholdSessionJwt,
              },
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionJwt,
              },
            },
          };
        }
        return { ok: true };
      },
      readSigningSessionSealedRecord: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const status = await coordinator.getWarmSessionStatus('ecdsa-session');
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(status).toMatchObject({ ok: true, remainingUses: 2 });
    expect(restoreCall).toMatchObject({
      request: {
        payload: {
          transport: {
            thresholdSessionJwt: 'threshold-session-jwt',
          },
          restore: {
            sessionId: 'ecdsa-session',
            chain: 'tempo',
            walletSigningSessionId: 'wallet-session-1',
            signingRootId: 'signing-root',
            signingRootVersion: 'root-v1',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 3],
            sessionKind: 'jwt',
          },
        },
      },
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
  });

  test('account-scoped restore enumerates durable sealed ECDSA records after reload', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = {
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      runtimeSessionId: 'runtime-1',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'wallet-session-1:email_otp:ecdsa',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ecdsa: 'ecdsa-session',
      },
      sealedSecretB64u: 'sealed-session-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime-b64u',
      ecdsaRestore: {
        chain: 'tempo',
        thresholdSessionJwt: 'threshold-session-jwt',
        sessionKind: 'jwt',
        ecdsaThresholdKeyId: 'ecdsa-key',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 3],
      },
      issuedAtMs: Date.now(),
      expiresAtMs,
      remainingUses: 2,
      updatedAtMs: Date.now(),
    };
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionJwt: call.request.payload.transport.thresholdSessionJwt,
              },
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionJwt,
              },
            },
          };
        }
        return { ok: true };
      },
      listSigningSessionSealedRecordsForAccount: async (args) => {
        expect(args).toMatchObject({
          accountId: 'alice.testnet',
          filter: { authMethod: 'email_otp' },
        });
        return args.filter?.curve === 'ecdsa' ? [sealedRecord] : [];
      },
      readSigningSessionSealedRecord: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    await coordinator.restoreEcdsaWarmSessionsFromSealedRecordsForAccount('alice.testnet');
    await coordinator.restoreEcdsaWarmSessionsFromSealedRecordsForAccount('alice.testnet');
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(restoreCall).toBeTruthy();
    expect(restoreCall.request.payload.restore).toMatchObject({
      sessionId: 'ecdsa-session',
      chain: 'tempo',
      walletSigningSessionId: 'wallet-session-1',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
    expect(
      workerCalls.filter(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toHaveLength(1);
  });

  test('restores sealed Email OTP session when worker status throws during reload', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = {
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      runtimeSessionId: 'runtime-1',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: { ecdsa: 'ecdsa-session' },
      sealedSecretB64u: 'sealed-session-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime-b64u',
      issuedAtMs: Date.now(),
      expiresAtMs,
      remainingUses: 2,
      updatedAtMs: Date.now(),
    };
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionJwt: 'threshold-session-jwt',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          throw new Error('worker still booting');
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: 'ecdsa-key',
                signingRootId: 'signing-root',
                signingRootVersion: 'root-v1',
                thresholdSessionId: 'ecdsa-session',
                walletSigningSessionId: 'wallet-session-1',
                thresholdSessionJwt: 'threshold-session-jwt',
              },
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: 'ecdsa-session',
                walletSigningSessionId: 'wallet-session-1',
                expiresAtMs,
                remainingUses: 2,
                jwt: 'threshold-session-jwt',
              },
            },
          };
        }
        return { ok: true };
      },
      readSigningSessionSealedRecord: async () => sealedRecord,
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
      acquireSigningSessionRestoreLease: async () => ({
        v: 1,
        thresholdSessionId: 'ecdsa-session',
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'unit-test-attempt',
        startedAtMs: Date.now(),
        expiresAtMs: Date.now() + 15_000,
      }),
    });

    await expect(coordinator.getWarmSessionStatus('ecdsa-session')).resolves.toMatchObject({
      ok: true,
      remainingUses: 2,
      expiresAtMs,
    });
    expect(workerCalls.map((call) => call.request?.type)).toEqual([
      'getEmailOtpWarmSessionStatus',
      'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    ]);
  });

  test('fails closed before worker restore when sealed signing-root metadata mismatches session state', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    const expiresAtMs = Date.now() + 60_000;

    await expect(
      coordinator.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord({
        sealedRecord: {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-1',
          authMethod: 'email_otp',
          secretKind: 'signing_session_secret32',
          storeKey: 'wallet-session-1:email_otp:ecdsa',
          walletSigningSessionId: 'wallet-session-1',
          thresholdSessionIds: { ecdsa: 'ecdsa-session' },
          sealedSecretB64u: 'sealed-session-secret',
          curve: 'ecdsa',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'other-signing-root',
          relayerUrl: 'https://relay.example',
          keyVersion: 'seal-v1',
          shamirPrimeB64u: 'prime-b64u',
          issuedAtMs: Date.now(),
          expiresAtMs,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        },
        ecdsaRecord: {
          nearAccountId: 'alice.testnet' as any,
          chain: 'tempo',
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key' as any,
          signingRootId: 'signing-root',
          relayerKeyId: 'relayer-key',
          clientVerifyingShareB64u: 'client-verifying-share',
          clientAdditiveShareHandle: {
            kind: 'email_otp_worker_session',
            sessionId: 'ecdsa-session',
          },
          participantIds: [1, 3],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'ecdsa-session',
          walletSigningSessionId: 'wallet-session-1',
          thresholdSessionJwt: 'threshold-session-jwt',
          signingSessionSealKeyVersion: 'seal-v1',
          signingSessionSealShamirPrimeB64u: 'prime-b64u',
          expiresAtMs,
          remainingUses: 2,
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
          updatedAtMs: Date.now(),
          source: 'email_otp',
        },
      }),
    ).rejects.toThrow('signing-root id mismatch');

    expect(
      workerCalls.some(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toBe(false);
  });

  test('attaches Ed25519 threshold session id to existing Email OTP sealed refresh record', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const { coordinator, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      readSigningSessionSealedRecord: async (thresholdSessionId) => ({
        v: 1,
        alg: 'shamir3pass-v1',
        storageScope: 'iframe_origin_indexeddb',
        runtimeSessionId: 'runtime-1',
        authMethod: 'email_otp',
        secretKind: 'signing_session_secret32',
        walletSigningSessionId: 'wallet-session-1',
        thresholdSessionIds: { ecdsa: thresholdSessionId },
        sealedSecretB64u: 'sealed-session-secret',
        curve: 'ecdsa',
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerUrl: 'https://relay.example',
        keyVersion: 'seal-v1',
        shamirPrimeB64u: 'prime-b64u',
        issuedAtMs: Date.now(),
        expiresAtMs,
        remainingUses: 2,
        updatedAtMs: Date.now(),
      }),
    });

    try {
      persistWarmSessionEd25519Capability({
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        jwt: appSessionJwt(),
        xClientBaseB64u: 'x-client-base',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      await (coordinator as any).attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
        ecdsaThresholdSessionId: 'ecdsa-session',
        ed25519ThresholdSessionId: 'ed25519-session',
      });
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }

    expect(sealedRecordWrites).toHaveLength(1);
    expect(sealedRecordWrites[0]).toMatchObject({
      thresholdSessionId: 'ecdsa-session',
      sealedSecretB64u: 'sealed-session-secret',
      authMethod: 'email_otp',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ecdsa: 'ecdsa-session',
        ed25519: 'ed25519-session',
      },
    });
  });

  test('enrolls ECDSA Email OTP capability and awaits Ed25519 provisioning', async () => {
    const { coordinator, ecdsaCommitCalls, ed25519ProvisionCalls } = createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt',
      };
    };

    const result = await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      clientSecret32: new Uint8Array(32).fill(7),
      registrationAttemptId: 'registration-attempt-1',
    });

    expect(result.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe('verifying-share');
    expect(ecdsaCommitCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      prfFirstB64u: 'prf-first-ecdsa-enroll',
      registrationAttemptId: 'registration-attempt-1',
      ecdsaThresholdSessionId: 'ecdsa-session',
    });
  });
});
