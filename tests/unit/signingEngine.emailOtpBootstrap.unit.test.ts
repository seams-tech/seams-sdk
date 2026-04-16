import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpUnlockAuthSeed,
} from '@shared/utils/emailOtpDerivation';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';

function createHandleShamirRuntime(args?: {
  keyHandle?: string;
  onAddString?: (args: { ciphertextB64u: string; keyHandle: string }) => string | Promise<string>;
  onAddBytes?: (args: { ciphertext: Uint8Array; keyHandle: string }) => string | Promise<string>;
  onRemoveString?: (args: {
    ciphertextB64u: string;
    keyHandle: string;
  }) => string | Promise<string>;
  onRemoveBytes?: (args: {
    ciphertextB64u: string;
    keyHandle: string;
  }) => Uint8Array | Promise<Uint8Array>;
}) {
  const keyHandle = args?.keyHandle || 'kh-test';
  return {
    createClientKeyHandle: async () => ({ keyHandle }),
    destroyClientKeyHandle: async () => undefined,
    addClientSealWithKeyHandle: async (input: {
      ciphertextB64u: string;
      keyHandle: string;
    }) => await (args?.onAddString?.(input) ?? 'wrapped-ciphertext-b64u'),
    ...(args?.onAddBytes
      ? {
          addClientSealBytesWithKeyHandle: async (input: {
            ciphertext: Uint8Array;
            keyHandle: string;
          }) => await args.onAddBytes(input),
        }
      : {}),
    removeClientSealWithKeyHandle: async (input: {
      ciphertextB64u: string;
      keyHandle: string;
    }) => await (args?.onRemoveString?.(input) ?? 'escrow-blob-b64u'),
    ...(args?.onRemoveBytes
      ? {
          removeClientSealWithKeyHandleToBytes: async (input: {
            ciphertextB64u: string;
            keyHandle: string;
          }) => await args.onRemoveBytes(input),
        }
      : {}),
  };
}

function createEmailOtpTestFetch(args: {
  unlockChallengeB64u: string;
}): typeof fetch {
  return async (input) => {
    const url = String(input);
    if (url.endsWith('/wallet/email-otp/challenge')) {
      return new Response(JSON.stringify({ ok: true, challenge: { challengeId: 'rc-1' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.endsWith('/wallet/email-otp/verify')) {
      return new Response(JSON.stringify({ ok: true, loginGrant: 'grant-1', emailOtpEscrowBlob: 'escrow-b64u' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.endsWith('/wallet/email-otp/unseal')) {
      return new Response(
        JSON.stringify({
          ok: true,
          ciphertext: 'client-ciphertext-b64u',
          emailOtpKeyVersion: 'email-otp-kv-1',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (url.endsWith('/wallet/unlock/challenge')) {
      return new Response(
        JSON.stringify({
          ok: true,
          challengeId: 'wu-1',
          challengeB64u: args.unlockChallengeB64u,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (url.endsWith('/wallet/unlock/verify')) {
      return new Response(JSON.stringify({ ok: true, unlocked: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    throw new Error(`Unexpected fetch URL: ${url}`);
  };
}

test.describe('SigningEngine Email OTP bootstrap runtime', () => {
  test('enrollment bridge uses config defaults and worker context for Email OTP enrollment', async () => {
    const walletId = 'alice.testnet';
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 61)),
    );
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u,
      walletId,
      userId: walletId,
    });
    const expectedUnlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeed({
      clientSecretB64u,
      walletId,
    });
    const workerCtx = {
      requestWorkerOperation: async ({ request }: any) => {
        if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
          const privateKey32 = Array.from(new Uint8Array(request.payload.privateKey32));
          if (privateKey32.join(',') === Array.from(expectedUnlockPrivateKey32).join(',')) {
            return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x33)]).buffer.slice(0);
          }
          expect(privateKey32).toEqual(
            Array.from(base64UrlDecode(expectedClientRootShare32B64u)),
          );
          return Uint8Array.from([0x03, ...new Uint8Array(32).fill(0x44)]).buffer.slice(0);
        }
        throw new Error(`Unexpected worker operation: ${request.type}`);
      },
    };

    engineAny.tatchiPasskeyConfigs = {
      network: {
        relayer: {
          url: 'https://relay.example',
        },
      },
      signing: {
        emailOtp: {
          authPolicy: 'session',
        },
        sessionSeal: {
          shamirPrimeB64u: 'prime-b64u',
        },
      },
    };
    engineAny.orchestrationDeps = {
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => workerCtx,
      },
    };

    const result = await engine.enrollEmailOtpInternal({
      nearAccountId: walletId,
      otpCode: '123456',
      appSessionJwt: 'app-session-jwt',
      clientSecretB64u,
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.endsWith('/wallet/email-otp/enroll/challenge')) {
          return new Response(JSON.stringify({ ok: true, challenge: { challengeId: 'enroll-1' } }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (url.endsWith('/wallet/email-otp/enroll/seal')) {
          return new Response(
            JSON.stringify({
              ok: true,
              ciphertext: 'client-ciphertext-b64u',
              emailOtpKeyVersion: 'email-otp-kv-1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url.endsWith('/wallet/email-otp/enroll/verify')) {
          return new Response(
            JSON.stringify({
              ok: true,
              walletId,
              otpChannel: 'email_otp',
              enrollment: {
                createdAt: new Date(0).toISOString(),
                updatedAt: new Date(0).toISOString(),
                emailOtpKeyVersion: 'email-otp-kv-1',
                unlockKeyVersion: 'email-otp-unlock-v1',
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        throw new Error(`Unexpected fetch URL: ${url}`);
      },
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-enroll',
        onAddBytes: async () => 'wrapped-ciphertext-b64u',
        onRemoveString: async () => 'escrow-blob-b64u',
      }),
    });

    expect(result.challengeId).toBe('enroll-1');
    expect(result.emailOtpKeyVersion).toBe('email-otp-kv-1');
    expect(result.unlockKeyVersion).toBe('email-otp-unlock-v1');
    expect(result.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
  });

  test('routes recovered OTP client share through canonical bootstrap and asserts ready state', async () => {
    const walletId = 'alice.testnet';
    const recoveredClientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 21)),
    );
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
      userId: walletId,
    });
    const bootstrapCalls: Array<Record<string, unknown>> = [];
    const readyChecks: Array<Record<string, unknown>> = [];
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;

    engineAny.tatchiPasskeyConfigs = {
      network: {
        relayer: {
          url: 'https://relay.example',
        },
      },
      signing: {
        emailOtp: {
          authPolicy: 'session',
        },
        sessionSeal: {
          shamirPrimeB64u: 'prime-b64u',
        },
      },
    };
    engineAny.orchestrationDeps = {
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x44)]).buffer.slice(0);
            }
            if (request.type === 'signSecp256k1Recoverable') {
              return Uint8Array.from([
                ...new Uint8Array(32).fill(0x55),
                ...new Uint8Array(32).fill(0x66),
                0x01,
              ]).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        }),
      },
    };
    engineAny.bootstrapEcdsaSession = async (args: Record<string, unknown>) => {
      bootstrapCalls.push({ ...args });
      return {
        thresholdEcdsaKeyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: walletId,
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key-1',
          backendBinding: {
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'ecdsa-session-1',
          thresholdSessionJwt: 'jwt-ecdsa',
        },
        keygen: {
          ok: true,
          keygenSessionId: 'keygen-1',
          rpId: 'example.localhost',
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShare32B64u: 'AQ',
          relayerKeyId: 'rk-1',
          thresholdEcdsaPublicKeyB64u: 'AQ',
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          relayerVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
        },
        session: {
          ok: true,
          sessionId: 'ecdsa-session-1',
          jwt: 'jwt-ecdsa',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
          clientVerifyingShareB64u: 'AQ',
        },
      };
    };
    engineAny.assertWarmThresholdEcdsaCapabilityReady = async (args: {
      nearAccountId: string;
      chain: 'evm' | 'tempo';
    }) => {
      readyChecks.push({ ...args });
      return {
        capability: 'ecdsa',
        chain: args.chain,
        record: {
          nearAccountId: args.nearAccountId,
          thresholdSessionId: 'ecdsa-session-1',
          thresholdSessionKind: 'jwt',
          source: 'email_otp',
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
            stepUpRequired: true,
          },
        },
        auth: {
          capability: 'ecdsa',
          chain: args.chain,
          record: {
            nearAccountId: args.nearAccountId,
            thresholdSessionId: 'ecdsa-session-1',
            thresholdSessionKind: 'jwt',
            source: 'email_otp',
            emailOtpAuthContext: {
              policy: 'session',
              retention: 'session',
              reason: 'login',
              authMethod: 'email_otp',
              stepUpRequired: true,
            },
          },
          thresholdSessionJwt: 'jwt-ecdsa',
          thresholdSessionJwtSource: 'app-session',
        },
        prfClaim: {
          state: 'warm',
          sessionId: 'ecdsa-session-1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        },
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
          stepUpRequired: true,
        },
        state: 'ready',
      };
    };

    const result = await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      otpCode: '123456',
      appSessionJwt: 'app-session-jwt',
      authorizationJwt: 'bootstrap-auth-jwt',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-1',
      fetchImpl: createEmailOtpTestFetch({
        unlockChallengeB64u: base64UrlEncode(new Uint8Array(32).fill(0x77)),
      }),
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-login',
        onAddString: async () => 'wrapped-ciphertext-b64u',
        onRemoveString: async () => recoveredClientSecretB64u,
      }),
    });

    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toEqual({
      nearAccountId: walletId,
      chain: 'evm',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-1',
      authorizationJwt: 'bootstrap-auth-jwt',
      clientRootShare32B64u: expectedClientRootShare32B64u,
      source: 'email_otp',
    });
    expect(readyChecks).toEqual([{ nearAccountId: walletId, chain: 'evm' }]);
    expect('clientRootShare32B64u' in result.recovery).toBe(false);
    expect(result.bootstrap.thresholdEcdsaKeyRef.thresholdSessionId).toBe('ecdsa-session-1');
    expect(result.warmCapability.state).toBe('ready');
  });

  test('fails when Email OTP bootstrap does not reach warm-session ready state', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;

    engineAny.tatchiPasskeyConfigs = {
      network: {
        relayer: {
          url: 'https://relay.example',
        },
      },
      signing: {
        emailOtp: {
          authPolicy: 'session',
        },
        sessionSeal: {
          shamirPrimeB64u: 'prime-b64u',
        },
      },
    };
    engineAny.orchestrationDeps = {
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x44)]).buffer.slice(0);
            }
            if (request.type === 'signSecp256k1Recoverable') {
              return Uint8Array.from([
                ...new Uint8Array(32).fill(0x55),
                ...new Uint8Array(32).fill(0x66),
                0x01,
              ]).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        }),
      },
    };
    engineAny.bootstrapEcdsaSession = async () => ({
      thresholdEcdsaKeyRef: {
        type: 'threshold-ecdsa-secp256k1',
        userId: walletId,
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        backendBinding: {
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
        },
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionId: 'ecdsa-session-1',
        thresholdSessionJwt: 'jwt-ecdsa',
      },
      keygen: {
        ok: true,
        keygenSessionId: 'keygen-1',
        rpId: 'example.localhost',
        clientVerifyingShareB64u: 'AQ',
        clientAdditiveShare32B64u: 'AQ',
        relayerKeyId: 'rk-1',
        thresholdEcdsaPublicKeyB64u: 'AQ',
        ethereumAddress: '0x1111111111111111111111111111111111111111',
        relayerVerifyingShareB64u: 'AQ',
        participantIds: [1, 2],
      },
      session: {
        ok: true,
        sessionId: 'ecdsa-session-1',
        jwt: 'jwt-ecdsa',
        remainingUses: 3,
        expiresAtMs: Date.now() + 60_000,
        clientVerifyingShareB64u: 'AQ',
      },
    });
    engineAny.assertWarmThresholdEcdsaCapabilityReady = async () => {
      throw new Error(
        '[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for alice.testnet (evm, state=prf_missing)',
      );
    };

    await expect(
      engine.loginWithEmailOtpEcdsaCapabilityInternal({
        nearAccountId: walletId,
        chain: 'evm',
        otpCode: '123456',
        appSessionJwt: 'app-session-jwt',
        authorizationJwt: 'bootstrap-auth-jwt',
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-1',
        fetchImpl: createEmailOtpTestFetch({
          unlockChallengeB64u: base64UrlEncode(new Uint8Array(32).fill(0x77)),
        }),
        shamirRuntime: createHandleShamirRuntime({
          keyHandle: 'kh-error',
          onAddString: async () => 'wrapped-ciphertext-b64u',
          onRemoveString: async () =>
            base64UrlEncode(Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 9))),
        }),
      }),
    ).rejects.toThrow('did not reach warm-session ready state');
  });

  test('fails closed for ECDSA export when the active session source is email_otp', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;

    engineAny.getThresholdEcdsaSessionRecordForSigning = () => ({
      nearAccountId: walletId,
      source: 'email_otp',
    });

    await expect(
      engineAny.exportThresholdEcdsaKeyWithAuthorization({
        nearAccountId: walletId,
        chain: 'evm',
        keyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: walletId,
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key-1',
          backendBinding: {
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'ecdsa-session-1',
          thresholdSessionJwt: 'jwt-ecdsa',
        },
        options: {},
      }),
    ).rejects.toThrow(
      '[SigningEngine] threshold-ecdsa key export requires fresh passkey authentication after Email OTP login',
    );
  });

  test('uses per-operation Email OTP policy metadata and defaults remainingUses to 1', async () => {
    const walletId = 'alice.testnet';
    const recoveredClientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 31)),
    );
    const bootstrapCalls: Array<Record<string, unknown>> = [];
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;

    engineAny.tatchiPasskeyConfigs = {
      network: {
        relayer: {
          url: 'https://relay.example',
        },
      },
      signing: {
        emailOtp: {
          authPolicy: 'session',
        },
        sessionSeal: {
          shamirPrimeB64u: 'prime-b64u',
        },
      },
    };
    engineAny.orchestrationDeps = {
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x44)]).buffer.slice(0);
            }
            if (request.type === 'signSecp256k1Recoverable') {
              return Uint8Array.from([
                ...new Uint8Array(32).fill(0x55),
                ...new Uint8Array(32).fill(0x66),
                0x01,
              ]).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        }),
      },
    };
    engineAny.bootstrapEcdsaSession = async (args: Record<string, unknown>) => {
      bootstrapCalls.push({ ...args });
      return {
        thresholdEcdsaKeyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: walletId,
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key-1',
          backendBinding: {
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'ecdsa-session-1',
          thresholdSessionJwt: 'jwt-ecdsa',
        },
        keygen: {
          ok: true,
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
        },
        session: {
          ok: true,
          sessionId: 'ecdsa-session-1',
          jwt: 'jwt-ecdsa',
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
          clientVerifyingShareB64u: 'AQ',
        },
      };
    };
    engineAny.assertWarmThresholdEcdsaCapabilityReady = async () => ({
      capability: 'ecdsa',
      chain: 'evm',
      record: {
        nearAccountId: walletId,
        thresholdSessionId: 'ecdsa-session-1',
        thresholdSessionKind: 'jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'login',
          authMethod: 'email_otp',
          stepUpRequired: true,
        },
      },
      auth: null,
      prfClaim: null,
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      state: 'ready',
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      otpCode: '123456',
      emailOtpAuthPolicy: 'per_operation',
      fetchImpl: createEmailOtpTestFetch({
        unlockChallengeB64u: base64UrlEncode(new Uint8Array(32).fill(0x77)),
      }),
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-policy',
        onAddString: async () => 'wrapped-ciphertext-b64u',
        onRemoveString: async () => recoveredClientSecretB64u,
      }),
    });

    expect(bootstrapCalls[0]?.emailOtpAuthContext).toEqual({
      policy: 'per_operation',
      retention: 'single_use',
      reason: 'login',
      authMethod: 'email_otp',
      stepUpRequired: true,
    });
    expect(bootstrapCalls[0]?.remainingUses).toBe(1);
  });
});
