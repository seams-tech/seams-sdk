import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpUnlockAuthSeed,
} from '@shared/utils/emailOtpDerivation';
import {
  enrollEmailOtpWallet,
  loginWithEmailOtpAndBootstrapEcdsaCapability,
  loginWithEmailOtpAndUnlockWallet,
} from '@/core/TatchiPasskey/emailOtp';

function createHandleShamirRuntime(args?: {
  keyHandle?: string;
  onCreate?: (args: { shamirPrimeB64u: string; keyHandle: string }) => void | Promise<void>;
  onDestroy?: (args: { keyHandle: string }) => void | Promise<void>;
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
    createClientKeyHandle: async ({ shamirPrimeB64u }: { shamirPrimeB64u: string }) => {
      await args?.onCreate?.({ shamirPrimeB64u, keyHandle });
      return { keyHandle };
    },
    destroyClientKeyHandle: async ({ keyHandle: destroyedKeyHandle }: { keyHandle: string }) => {
      await args?.onDestroy?.({ keyHandle: destroyedKeyHandle });
    },
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

test.describe('TatchiPasskey Email OTP runtime', () => {
  test('Email OTP login prefers worker-held shamir key handles when available', async () => {
    const walletId = 'alice.testnet';
    const recoveredClientSecret32 = Uint8Array.from(
      Array.from({ length: 32 }, (_, index) => index + 1),
    );
    const recoveredClientSecretB64u = base64UrlEncode(recoveredClientSecret32);
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
      userId: walletId,
    });
    const expectedUnlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeed({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
    });

    let createClientKeyHandleCalled = false;
    let destroyClientKeyHandleCalled = false;

    const result = await loginWithEmailOtpAndUnlockWallet({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode: '123456',
      shamirPrimeB64u: 'prime-b64u',
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.endsWith('/wallet/email-otp/challenge')) {
          return new Response(JSON.stringify({ ok: true, challenge: { challengeId: 'rc-1' } }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (url.endsWith('/wallet/email-otp/verify')) {
          return new Response(
            JSON.stringify({ ok: true, loginGrant: 'grant-1', emailOtpEscrowBlob: 'escrow-b64u' }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
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
              challengeB64u: base64UrlEncode(new Uint8Array(32).fill(0x77)),
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
      },
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            expect(Array.from(new Uint8Array(request.payload.privateKey32))).toEqual(
              Array.from(expectedUnlockPrivateKey32),
            );
            return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)]).buffer.slice(0);
          }
          if (request.type === 'signSecp256k1Recoverable') {
            return Uint8Array.from([
              ...new Uint8Array(32).fill(0x22),
              ...new Uint8Array(32).fill(0x33),
              0x01,
            ]).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-1',
        onCreate: ({ shamirPrimeB64u }) => {
          createClientKeyHandleCalled = true;
          expect(shamirPrimeB64u).toBe('prime-b64u');
        },
        onDestroy: ({ keyHandle }) => {
          destroyClientKeyHandleCalled = true;
          expect(keyHandle).toBe('kh-1');
        },
        onAddString: ({ ciphertextB64u, keyHandle }) => {
          expect(ciphertextB64u).toBe('escrow-b64u');
          expect(keyHandle).toBe('kh-1');
          return 'wrapped-ciphertext-b64u';
        },
        onRemoveBytes: ({ ciphertextB64u, keyHandle }) => {
          expect(ciphertextB64u).toBe('client-ciphertext-b64u');
          expect(keyHandle).toBe('kh-1');
          return recoveredClientSecret32.slice();
        },
      }),
    });

    expect(createClientKeyHandleCalled).toBe(true);
    expect(destroyClientKeyHandleCalled).toBe(true);
    expect(result.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
  });

  test('Email OTP login prefers byte-oriented shamir unseal when available', async () => {
    const walletId = 'alice.testnet';
    const otpCode = '123456';
    const recoveredClientSecret32 = Uint8Array.from(
      Array.from({ length: 32 }, (_, index) => index + 1),
    );
    const recoveredClientSecretB64u = base64UrlEncode(recoveredClientSecret32);
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
      userId: walletId,
    });
    const expectedUnlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeed({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
    });

    let removeClientSealCalled = false;
    let removeClientSealToBytesCalled = false;

    const result = await loginWithEmailOtpAndUnlockWallet({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode,
      shamirPrimeB64u: 'prime-b64u',
      appSessionJwt: 'app-session-jwt',
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.endsWith('/wallet/email-otp/challenge')) {
          return new Response(JSON.stringify({ ok: true, challenge: { challengeId: 'rc-1' } }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (url.endsWith('/wallet/email-otp/verify')) {
          return new Response(
            JSON.stringify({
              ok: true,
              loginGrant: 'grant-1',
              emailOtpEscrowBlob: 'escrow-b64u',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
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
              challengeB64u: base64UrlEncode(new Uint8Array(32).fill(0x77)),
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
      },
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            expect(Array.from(new Uint8Array(request.payload.privateKey32))).toEqual(
              Array.from(expectedUnlockPrivateKey32),
            );
            return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)]).buffer.slice(0);
          }
          if (request.type === 'signSecp256k1Recoverable') {
            expect(Array.from(new Uint8Array(request.payload.privateKey32))).toEqual(
              Array.from(expectedUnlockPrivateKey32),
            );
            return Uint8Array.from([
              ...new Uint8Array(32).fill(0x22),
              ...new Uint8Array(32).fill(0x33),
              0x01,
            ]).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-1',
        onAddString: async () => 'wrapped-ciphertext-b64u',
        onRemoveString: async () => {
          removeClientSealCalled = true;
          throw new Error('removeClientSealWithKeyHandle string path should not be used');
        },
        onRemoveBytes: async (args) => {
          removeClientSealToBytesCalled = true;
          expect(args).toEqual({
            ciphertextB64u: 'client-ciphertext-b64u',
            keyHandle: 'kh-1',
          });
          return recoveredClientSecret32.slice();
        },
      }),
    });

    expect(removeClientSealCalled).toBe(false);
    expect(removeClientSealToBytesCalled).toBe(true);
    expect(result.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
  });

  test('Email OTP challenge, unseal, derivation, and unlock proof flow stay canonical', async () => {
    const walletId = 'alice.testnet';
    const otpCode = '123456';
    const emailOtpEscrowBlob = 'escrow-b64u';
    const shamirPrimeB64u = 'prime-b64u';
    const appSessionJwt = 'app-session-jwt';
    const recoveredClientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1)),
    );
    const unlockChallengeDigest32 = Uint8Array.from(
      Array.from({ length: 32 }, (_, index) => 255 - index),
    );
    const unlockChallengeB64u = base64UrlEncode(unlockChallengeDigest32);
    const derivedUnlockPublicKey33 = Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)]);
    const recoverableSignature65 = Uint8Array.from([
      ...new Uint8Array(32).fill(0x22),
      ...new Uint8Array(32).fill(0x33),
      0x01,
    ]);
    const expectedUnlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeed({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
    });
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
      userId: walletId,
    });

    const requests: Array<{ url: string; body: Record<string, unknown>; headers: Headers }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      const headers = new Headers(init?.headers || {});
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      requests.push({ url, body, headers });

      if (url === 'https://relay.example/wallet/email-otp/challenge') {
        return new Response(
          JSON.stringify({
            ok: true,
            challenge: { challengeId: 'rc-1' },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/wallet/email-otp/verify') {
        return new Response(
          JSON.stringify({
            ok: true,
            loginGrant: 'grant-1',
            emailOtpEscrowBlob: 'escrow-b64u',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/wallet/email-otp/unseal') {
        return new Response(
          JSON.stringify({
            ok: true,
            ciphertext: 'client-ciphertext-b64u',
            emailOtpKeyVersion: 'email-otp-kv-1',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/wallet/unlock/challenge') {
        return new Response(
          JSON.stringify({
            ok: true,
            challengeId: 'wu-1',
            challengeB64u: unlockChallengeB64u,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/wallet/unlock/verify') {
        return new Response(
          JSON.stringify({
            ok: true,
            unlocked: true,
            userId: walletId,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      throw new Error(`Unexpected fetch URL: ${url}`);
    };

    const workerCtx = {
      requestWorkerOperation: async ({ request }: any) => {
        if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
          expect(Array.from(new Uint8Array(request.payload.privateKey32))).toEqual(
            Array.from(expectedUnlockPrivateKey32),
          );
          return derivedUnlockPublicKey33.buffer.slice(0);
        }
        if (request.type === 'signSecp256k1Recoverable') {
          expect(Array.from(new Uint8Array(request.payload.privateKey32))).toEqual(
            Array.from(expectedUnlockPrivateKey32),
          );
          expect(Array.from(new Uint8Array(request.payload.digest32))).toEqual(
            Array.from(unlockChallengeDigest32),
          );
          return recoverableSignature65.buffer.slice(0);
        }
        throw new Error(`Unexpected worker operation: ${request.type}`);
      },
    };

    const shamirRuntime = createHandleShamirRuntime({
      keyHandle: 'kh-canonical',
      onAddString: async (args: {
        ciphertextB64u: string;
        keyHandle: string;
      }) => {
        expect(args).toEqual({
          ciphertextB64u: emailOtpEscrowBlob,
          keyHandle: 'kh-canonical',
        });
        return 'wrapped-ciphertext-b64u';
      },
      onRemoveString: async (args: {
        ciphertextB64u: string;
        keyHandle: string;
      }) => {
        expect(args).toEqual({
          ciphertextB64u: 'client-ciphertext-b64u',
          keyHandle: 'kh-canonical',
        });
        return recoveredClientSecretB64u;
      },
    });

    const result = await loginWithEmailOtpAndUnlockWallet({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode,
      shamirPrimeB64u,
      appSessionJwt,
      workerCtx,
      fetchImpl,
      shamirRuntime,
    });

    expect('clientSecretB64u' in result).toBe(false);
    expect(result.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
    expect(result.loginGrant).toBe('grant-1');
    expect(result.challengeId).toBe('rc-1');
    expect(result.emailOtpKeyVersion).toBe('email-otp-kv-1');
    expect(result.unlockChallengeId).toBe('wu-1');
    expect(result.unlockChallengeB64u).toBe(unlockChallengeB64u);
    expect(result.unlockPublicKeyB64u).toBe(base64UrlEncode(derivedUnlockPublicKey33));
    expect(result.unlockSignatureB64u).toBe(base64UrlEncode(recoverableSignature65));

    expect(requests.map((entry) => entry.url)).toEqual([
      'https://relay.example/wallet/email-otp/challenge',
      'https://relay.example/wallet/email-otp/verify',
      'https://relay.example/wallet/email-otp/unseal',
      'https://relay.example/wallet/unlock/challenge',
      'https://relay.example/wallet/unlock/verify',
    ]);
    expect(requests[0]?.headers.get('Authorization')).toBe(`Bearer ${appSessionJwt}`);
    expect(requests[1]?.headers.get('Authorization')).toBe(`Bearer ${appSessionJwt}`);
    expect(requests[2]?.headers.get('Authorization')).toBe(`Bearer ${appSessionJwt}`);
    expect(requests[0]?.body).toEqual({
      walletId,
      otpChannel: 'email_otp',
    });
    expect(requests[1]?.body).toEqual({
      walletId,
      challengeId: 'rc-1',
      otpCode,
      otpChannel: 'email_otp',
    });
    expect(requests[2]?.body).toEqual({
      loginGrant: 'grant-1',
      wrappedCiphertext: 'wrapped-ciphertext-b64u',
    });
    expect(requests[3]?.body).toEqual({
      unlockBackend: 'email_otp',
      walletId,
    });
    expect(requests[4]?.body).toEqual({
      unlockBackend: 'email_otp',
      walletId,
      challengeId: 'wu-1',
      unlockProof: {
        publicKey: base64UrlEncode(derivedUnlockPublicKey33),
        signature: base64UrlEncode(recoverableSignature65),
      },
    });
    expect(String(requests[4]?.body.clientRootShare32B64u || '')).toBe('');
  });

  test('Email OTP can hand the derived client share into canonical ECDSA bootstrap', async () => {
    const walletId = 'alice.testnet';
    const recoveredClientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 17)),
    );
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u: recoveredClientSecretB64u,
      walletId,
      userId: walletId,
    });

    const bootstrapCalls: Array<Record<string, unknown>> = [];
    const result = await loginWithEmailOtpAndBootstrapEcdsaCapability({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode: '123456',
      shamirPrimeB64u: 'prime-b64u',
      appSessionJwt: 'app-session-jwt',
      authorizationJwt: 'bootstrap-auth-jwt',
      sessionId: 'ecdsa-session-1',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      workerCtx: {
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
      },
      fetchImpl: async (input, init) => {
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
              challengeB64u: base64UrlEncode(new Uint8Array(32).fill(0x77)),
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
        throw new Error(`Unexpected fetch URL: ${url} body=${String(init?.body || '')}`);
      },
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-bootstrap',
        onAddString: async () => 'wrapped-ciphertext-b64u',
        onRemoveString: async () => recoveredClientSecretB64u,
      }),
      bootstrapEcdsaSession: async (args) => {
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
      },
    });

    expect('clientRootShare32B64u' in result.recovery).toBe(false);
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toEqual({
      nearAccountId: walletId,
      chain: 'evm',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-1',
      authorizationJwt: 'bootstrap-auth-jwt',
      clientRootShare32B64u: expectedClientRootShare32B64u,
    });
    expect(result.bootstrap.thresholdEcdsaKeyRef.thresholdSessionId).toBe('ecdsa-session-1');
  });

  test('Email OTP enrollment seals a new client secret and uploads canonical verifier material', async () => {
    const walletId = 'alice.testnet';
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 41)),
    );
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u,
      walletId,
      userId: walletId,
    });
    const expectedUnlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeed({
      clientSecretB64u,
      walletId,
    });
    const expectedThresholdClientRootShare32 = base64UrlDecode(expectedClientRootShare32B64u);
    const requests: Array<{ url: string; body: Record<string, unknown>; headers: Headers }> = [];

    const result = await enrollEmailOtpWallet({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode: '123456',
      shamirPrimeB64u: 'prime-b64u',
      appSessionJwt: 'app-session-jwt',
      clientSecretB64u,
      fetchImpl: async (input, init) => {
        const url = String(input);
        const headers = new Headers(init?.headers || {});
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
        requests.push({ url, body, headers });
        if (url.endsWith('/wallet/email-otp/enroll/challenge')) {
          return new Response(
            JSON.stringify({
              ok: true,
              challenge: { challengeId: 'enroll-rc-1' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
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
        onAddString: async (args) => {
          expect(args).toEqual({
            ciphertextB64u: clientSecretB64u,
            keyHandle: 'kh-enroll',
          });
          return 'wrapped-ciphertext-b64u';
        },
        onRemoveString: async (args) => {
          expect(args).toEqual({
            ciphertextB64u: 'client-ciphertext-b64u',
            keyHandle: 'kh-enroll',
          });
          return 'escrow-blob-b64u';
        },
      }),
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            const privateKey32 = Array.from(new Uint8Array(request.payload.privateKey32));
            if (privateKey32.join(',') === Array.from(expectedUnlockPrivateKey32).join(',')) {
              return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)]).buffer.slice(0);
            }
            expect(privateKey32).toEqual(Array.from(expectedThresholdClientRootShare32));
            return Uint8Array.from([0x03, ...new Uint8Array(32).fill(0x22)]).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
    });

    expect('clientSecretB64u' in result).toBe(false);
    expect('emailOtpEscrowBlob' in result).toBe(false);
    expect(result.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
    expect(result.challengeId).toBe('enroll-rc-1');
    expect(result.emailOtpKeyVersion).toBe('email-otp-kv-1');
    expect(result.unlockKeyVersion).toBe('email-otp-unlock-v1');
    expect(result.unlockPublicKeyB64u).toBe(
      base64UrlEncode(Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)])),
    );
    expect(result.thresholdEcdsaClientVerifyingShareB64u).toBe(
      base64UrlEncode(Uint8Array.from([0x03, ...new Uint8Array(32).fill(0x22)])),
    );

    expect(requests.map((entry) => entry.url)).toEqual([
      'https://relay.example/wallet/email-otp/enroll/challenge',
      'https://relay.example/wallet/email-otp/enroll/seal',
      'https://relay.example/wallet/email-otp/enroll/verify',
    ]);
    expect(requests[0]?.headers.get('Authorization')).toBe('Bearer app-session-jwt');
    expect(requests[1]?.headers.get('Authorization')).toBe('Bearer app-session-jwt');
    expect(requests[2]?.headers.get('Authorization')).toBe('Bearer app-session-jwt');
    expect(requests[0]?.body).toEqual({
      walletId,
      otpChannel: 'email_otp',
    });
    expect(requests[1]?.body).toEqual({
      walletId,
      wrappedCiphertext: 'wrapped-ciphertext-b64u',
    });
    expect(requests[2]?.body).toEqual({
      walletId,
      challengeId: 'enroll-rc-1',
      otpCode: '123456',
      otpChannel: 'email_otp',
      emailOtpEscrowBlob: 'escrow-blob-b64u',
      emailOtpKeyVersion: 'email-otp-kv-1',
      unlockPublicKey: base64UrlEncode(Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)])),
      unlockKeyVersion: 'email-otp-unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: base64UrlEncode(
        Uint8Array.from([0x03, ...new Uint8Array(32).fill(0x22)]),
      ),
    });
  });

  test('Email OTP enrollment prefers byte-oriented shamir seal when available', async () => {
    const walletId = 'alice.testnet';
    const clientSecret32 = Uint8Array.from(
      Array.from({ length: 32 }, (_, index) => index + 41),
    );
    const clientSecretB64u = base64UrlEncode(clientSecret32);
    let addClientSealCalled = false;
    let addClientSealBytesCalled = false;

    await enrollEmailOtpWallet({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode: '123456',
      shamirPrimeB64u: 'prime-b64u',
      appSessionJwt: 'app-session-jwt',
      clientSecretB64u,
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.endsWith('/wallet/email-otp/enroll/challenge')) {
          return new Response(
            JSON.stringify({
              ok: true,
              challenge: { challengeId: 'enroll-rc-1' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
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
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        throw new Error(`Unexpected fetch URL: ${url}`);
      },
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-bytes',
        onAddString: async () => {
          addClientSealCalled = true;
          throw new Error('addClientSealWithKeyHandle string path should not be used');
        },
        onAddBytes: async (args) => {
          addClientSealBytesCalled = true;
          expect(Array.from(args.ciphertext)).toEqual(Array.from(clientSecret32));
          expect(args.keyHandle).toBe('kh-bytes');
          return 'wrapped-ciphertext-b64u';
        },
        onRemoveString: async () => 'escrow-blob-b64u',
      }),
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)]).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
    });

    expect(addClientSealCalled).toBe(false);
    expect(addClientSealBytesCalled).toBe(true);
  });

  test('Email OTP enrollment prefers worker-held shamir key handles when available', async () => {
    const walletId = 'alice.testnet';
    const clientSecret32 = Uint8Array.from(
      Array.from({ length: 32 }, (_, index) => index + 41),
    );
    const clientSecretB64u = base64UrlEncode(clientSecret32);
    let createClientKeyHandleCalled = false;
    let destroyClientKeyHandleCalled = false;

    await enrollEmailOtpWallet({
      relayUrl: 'https://relay.example',
      walletId,
      otpCode: '123456',
      shamirPrimeB64u: 'prime-b64u',
      clientSecretB64u,
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.endsWith('/wallet/email-otp/enroll/challenge')) {
          return new Response(JSON.stringify({ ok: true, challenge: { challengeId: 'enroll-rc-1' } }), {
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
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        throw new Error(`Unexpected fetch URL: ${url}`);
      },
      shamirRuntime: createHandleShamirRuntime({
        keyHandle: 'kh-2',
        onCreate: ({ shamirPrimeB64u }) => {
          createClientKeyHandleCalled = true;
          expect(shamirPrimeB64u).toBe('prime-b64u');
        },
        onDestroy: ({ keyHandle }) => {
          destroyClientKeyHandleCalled = true;
          expect(keyHandle).toBe('kh-2');
        },
        onAddBytes: ({ ciphertext, keyHandle }) => {
          expect(Array.from(ciphertext)).toEqual(Array.from(clientSecret32));
          expect(keyHandle).toBe('kh-2');
          return 'wrapped-ciphertext-b64u';
        },
        onRemoveString: ({ ciphertextB64u, keyHandle }) => {
          expect(ciphertextB64u).toBe('client-ciphertext-b64u');
          expect(keyHandle).toBe('kh-2');
          return 'escrow-blob-b64u';
        },
      }),
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            return Uint8Array.from([0x02, ...new Uint8Array(32).fill(0x11)]).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
    });

    expect(createClientKeyHandleCalled).toBe(true);
    expect(destroyClientKeyHandleCalled).toBe(true);
  });
});
