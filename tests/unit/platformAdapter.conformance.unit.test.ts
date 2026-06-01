import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
  buildRelayerKeyId,
  buildSecureEnclaveWrappedSecretSource,
  buildWebAuthnPrfFirstSecretSourceFromParts,
  createBrowserPlatformRuntime,
  type AuthenticatorPort,
  type DurableRecordStore,
  type EcdsaRoleLocalAuthMethod,
  type EcdsaRelayerPublicIdentity,
  type EcdsaRoleLocalPublicFacts,
  type EcdsaRoleLocalReadyRecord,
  type HttpTransport,
  type SignerCryptoPort,
} from '@/core/platform';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { SignerWorkerOperationError } from '@/core/signingEngine/workerManager/workerTypes';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';

type BrowserRuntimeDeps = NonNullable<Parameters<typeof createBrowserPlatformRuntime>[0]>;

function bytesB64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function publicKeyB64u(prefix: 2 | 3, fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = prefix;
  return base64UrlEncode(bytes);
}

const walletId = toWalletId('wallet.testnet');
const rpId = toRpId('localhost');
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({ chain: 'evm', chainId: 5042002 });
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ehss-key');
const signingRootId = toEcdsaHssSigningRootId('root');
const signingRootVersion = toEcdsaHssSigningRootVersion('v1');
const credentialIdB64u = bytesB64u(16, 1);
const hssClientSharePublicKey33B64u = publicKeyB64u(2, 2);
const relayerPublicKey33B64u = publicKeyB64u(3, 3);
const groupPublicKey33B64u = publicKeyB64u(2, 4);
const ethereumAddress = '0x0000000000000000000000000000000000000001' as const;

const emailOtpStorageKeyFacts = {
  walletId,
  rpId,
  chainTarget,
  keyHandle: 'credential-key',
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2] as const,
  authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
    authSubjectId: 'google:alice',
  }),
};

const storageKeyFacts = {
  walletId,
  rpId,
  chainTarget,
  keyHandle: 'credential-key',
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2] as const,
  authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
    credentialIdB64u,
    rpId,
  }),
};

function prepareInputFor(wallet = walletId) {
  return {
    kind: 'prepare_ecdsa_client_bootstrap_v1' as const,
    algorithm: 'ecdsa_hss_secp256k1_role_local_v1' as const,
    context: {
      walletId: wallet,
      rpId,
      chainTarget,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      keyPurpose: 'evm-signing' as const,
      keyVersion: 'v1' as const,
    },
    participants: {
      clientParticipantId: 1 as const,
      relayerParticipantId: 2 as const,
      participantIds: [1, 2] as const,
    },
    secretSource: buildWebAuthnPrfFirstSecretSourceFromParts({
      prfFirstB64u: bytesB64u(32, 5),
      rpId,
      credentialIdB64u,
    }),
  };
}

const prepareInput = prepareInputFor();

const pendingStateBlob = {
  kind: 'ecdsa_role_local_pending_state_blob_v1' as const,
  curve: 'secp256k1' as const,
  encoding: 'base64url' as const,
  producer: 'signer_core' as const,
  stateBlobB64u: bytesB64u(96, 8),
};

const readyStateBlob = {
  kind: 'ecdsa_role_local_state_blob_v1' as const,
  curve: 'secp256k1' as const,
  encoding: 'base64url' as const,
  producer: 'signer_core' as const,
  stateBlobB64u: bytesB64u(160, 9),
};

function fakeAssertionCredential(args: {
  prfFirst?: string;
  invalidCredential?: boolean;
}): PublicKeyCredential | null {
  if (args.invalidCredential) return null;
  const rawId = new Uint8Array([1, 2, 3, 4]).buffer;
  return {
    id: 'credential',
    rawId,
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults() {
      return {
        prf: {
          results: args.prfFirst ? { first: args.prfFirst } : {},
        },
      };
    },
  } as unknown as PublicKeyCredential;
}

function fakeAttestationCredential(args: {
  prfFirst?: string;
  invalidCredential?: boolean;
}): PublicKeyCredential | null {
  if (args.invalidCredential) return null;
  const rawId = new Uint8Array([5, 6, 7, 8]).buffer;
  return {
    id: 'credential',
    rawId,
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: new Uint8Array([4]).buffer,
      attestationObject: new Uint8Array([5]).buffer,
      getTransports: () => [],
    } as unknown as AuthenticatorAttestationResponse,
    getClientExtensionResults() {
      return {
        prf: {
          results: args.prfFirst ? { first: args.prfFirst } : {},
        },
      };
    },
  } as unknown as PublicKeyCredential;
}

function challengeFirstByte(challenge: BufferSource | undefined): number {
  if (!challenge) return 0;
  if (challenge instanceof Uint8Array) return challenge[0] ?? 0;
  if (challenge instanceof ArrayBuffer) return new Uint8Array(challenge)[0] ?? 0;
  return new Uint8Array(challenge.buffer, challenge.byteOffset, challenge.byteLength)[0] ?? 0;
}

function createBrowserAuthenticatorConformancePort(): AuthenticatorPort {
  const credentials = {
    async get(options?: CredentialRequestOptions) {
      switch (challengeFirstByte(options?.publicKey?.challenge)) {
        case 0x10:
          return fakeAssertionCredential({ prfFirst: bytesB64u(32, 10) });
        case 0x11:
          return fakeAssertionCredential({});
        case 0x12:
          throw new DOMException('User cancelled', 'NotAllowedError');
        case 0x13:
          return fakeAssertionCredential({ invalidCredential: true });
        default:
          return fakeAssertionCredential({ prfFirst: bytesB64u(32, 14) });
      }
    },
    async create(options?: CredentialCreationOptions) {
      return fakeAttestationCredential({
        prfFirst:
          challengeFirstByte(options?.publicKey?.challenge) === 0x11
            ? undefined
            : bytesB64u(32, 15),
      });
    },
  } as CredentialsContainer;
  return createBrowserPlatformRuntime({ credentials }).authenticator;
}

function createBrowserSignerCryptoConformancePort(): SignerCryptoPort {
  const workerCtx: WorkerOperationContext = {
    async requestWorkerOperation({ request }) {
      if (request.type === WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap) {
        const payload = request.payload as typeof prepareInput;
        if (String(payload.context.walletId) === 'timeout.testnet') {
          throw new SignerWorkerOperationError({
            code: 'TIMEOUT',
            message: 'Worker operation timed out after 1000ms',
            workerKind: 'hssClient',
          });
        }
        if (String(payload.context.walletId) === 'native-failure.testnet') {
          throw new SignerWorkerOperationError({
            code: 'WORKER_RUNTIME_ERROR',
            message: 'HSS client WASM initialization failed: failed to instantiate module_or_path',
            workerKind: 'hssClient',
          });
        }
        return {
          type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: {
            pendingStateBlob,
            clientBootstrap: {
              contextBinding32B64u: bytesB64u(32, 11),
              hssClientSharePublicKey33B64u,
              clientShareRetryCounter: 0,
              participantId: 1,
            },
            publicFacts: {
              hssClientSharePublicKey33B64u,
              clientVerifyingShareB64u: hssClientSharePublicKey33B64u,
            },
          },
        };
      }
      if (request.type === WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap) {
        return {
          type: WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: {
            stateBlob: readyStateBlob,
            publicFacts: {
              contextBinding32B64u: bytesB64u(32, 11),
              hssClientSharePublicKey33B64u,
              clientVerifyingShareB64u: hssClientSharePublicKey33B64u,
              relayerPublicKey33B64u,
              groupPublicKey33B64u,
              ethereumAddress,
            },
          },
        };
      }
      throw new Error(`unexpected worker request type: ${String(request.type)}`);
    },
  };
  return createBrowserPlatformRuntime({ workerCtx }).signerCrypto;
}

function createBrowserHttpTransportConformancePort(): HttpTransport {
  const fetchImpl = (async (_url, init) => {
    if (init?.signal) {
      const url = String(_url);
      if (url.includes('/slow')) {
        return new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          );
        });
      }
    }
    if (String(_url).includes('/denied')) {
      return new Response(JSON.stringify({ error: 'denied' }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ accepted: true, auth: init?.headers }), {
      status: 202,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return createBrowserPlatformRuntime({ fetch: fetchImpl }).http;
}

function createMemoryIndexedDB(): NonNullable<BrowserRuntimeDeps['indexedDB']> {
  const appState = new Map<string, unknown>();
  return {
    async getAppState<T>(key: string): Promise<T | undefined> {
      return appState.get(key) as T | undefined;
    },
    async setAppState<T>(key: string, value: T | null): Promise<void> {
      if (value === null) {
        appState.delete(key);
        return;
      }
      appState.set(key, value);
    },
  } as unknown as NonNullable<BrowserRuntimeDeps['indexedDB']>;
}

function createPublicFacts(): EcdsaRoleLocalPublicFacts {
  return buildEcdsaRoleLocalPublicFacts({
    walletId,
    rpId,
    chainTarget,
    keyHandle: storageKeyFacts.keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress,
    contextBinding32B64u: bytesB64u(32, 11),
  });
}

function createReadyRecord(
  authMethod: EcdsaRoleLocalAuthMethod = storageKeyFacts.authMethod,
): EcdsaRoleLocalReadyRecord {
  const publicFacts = createPublicFacts();
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: readyStateBlob,
    publicFacts,
    authMethod,
  });
}

function relayerPublicIdentity(): EcdsaRelayerPublicIdentity {
  const publicFacts = createPublicFacts();
  return {
    relayerKeyId: buildRelayerKeyId('relayer-key'),
    relayerPublicKey33B64u: publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: publicFacts.groupPublicKey33B64u,
    ethereumAddress: publicFacts.ethereumAddress,
  };
}

export function runAuthenticatorPortConformance(factory: () => AuthenticatorPort): void {
  test.describe('AuthenticatorPort conformance', () => {
    test('returns required PRF success', async () => {
      const result = await factory().run({
        kind: 'get_passkey',
        rpId,
        credentialIdB64u,
        challengeB64u: bytesB64u(32, 0x10),
        requirePrfFirst: true,
      });

      expect(result).toMatchObject({
        ok: true,
        operation: 'get_passkey',
        requirePrfFirst: true,
        prf: { kind: 'required' },
      });
    });

    test('returns prf_unavailable for missing required PRF', async () => {
      const result = await factory().run({
        kind: 'get_passkey',
        rpId,
        credentialIdB64u,
        challengeB64u: bytesB64u(32, 0x11),
        requirePrfFirst: true,
      });

      expect(result).toMatchObject({
        ok: false,
        code: 'prf_unavailable',
      });
    });

    test('returns typed user-cancel failure', async () => {
      const result = await factory().run({
        kind: 'get_passkey',
        rpId,
        credentialIdB64u,
        challengeB64u: bytesB64u(32, 0x12),
        requirePrfFirst: true,
      });

      expect(result).toMatchObject({
        ok: false,
        code: 'not_allowed',
      });
    });

    test('returns typed invalid credential failure', async () => {
      const result = await factory().run({
        kind: 'get_passkey',
        rpId,
        credentialIdB64u,
        challengeB64u: bytesB64u(32, 0x13),
        requirePrfFirst: true,
      });

      expect(result).toMatchObject({
        ok: false,
        code: 'invalid_credential',
      });
    });
  });
}

export function runSignerCryptoPortConformance(factory: () => SignerCryptoPort): void {
  test.describe('SignerCryptoPort conformance', () => {
    test('prepares and finalizes command success', async () => {
      const port = factory();
      const prepared = await port.prepareEcdsaClientBootstrap(prepareInput);
      expect(prepared).toMatchObject({
        ok: true,
        value: {
          pendingStateBlob,
          clientBootstrap: {
            hssClientSharePublicKey33B64u,
            participantId: 1,
          },
        },
      });
      if (!prepared.ok) throw new Error(prepared.message);

      const finalized = await port.finalizeEcdsaClientBootstrap({
        kind: 'finalize_ecdsa_client_bootstrap_v1',
        pendingStateBlob: prepared.value.pendingStateBlob,
        relayerPublicIdentity: relayerPublicIdentity(),
      });

      expect(finalized).toMatchObject({
        ok: true,
        value: {
          stateBlob: readyStateBlob,
          publicFacts: {
            relayerPublicKey33B64u,
            groupPublicKey33B64u,
            ethereumAddress,
          },
        },
      });
    });

    test('returns command validation failure', async () => {
      const result = await factory().finalizeEcdsaClientBootstrap({
        kind: 'finalize_ecdsa_client_bootstrap_v1',
        pendingStateBlob,
        relayerPublicIdentity: {
          ...relayerPublicIdentity(),
          relayerKeyId: '' as ReturnType<typeof buildRelayerKeyId>,
        },
      });

      expect(result).toMatchObject({
        ok: false,
        failure: 'command',
        code: 'invalid_relayer_public_identity',
      });
    });

    test('returns invocation timeout failure', async () => {
      const result = await factory().prepareEcdsaClientBootstrap(
        prepareInputFor(toWalletId('timeout.testnet')),
      );

      expect(result).toMatchObject({
        ok: false,
        failure: 'invocation',
        code: 'timeout',
      });
    });

    test('returns invocation native binding failure', async () => {
      const result = await factory().prepareEcdsaClientBootstrap(
        prepareInputFor(toWalletId('native-failure.testnet')),
      );

      expect(result).toMatchObject({
        ok: false,
        failure: 'invocation',
        code: 'native_binding_failure',
      });
    });

    test('returns unsupported secret-source command failure', async () => {
      const result = await factory().prepareEcdsaClientBootstrap({
        ...prepareInput,
        secretSource: buildSecureEnclaveWrappedSecretSource({
          keyId: 'secure-key',
          accessGroup: 'group',
        }),
      });

      expect(result).toMatchObject({
        ok: false,
        failure: 'command',
        code: 'unsupported_secret_source',
      });
    });
  });
}

export function runDurableRecordStoreConformance(factory: () => DurableRecordStore): void {
  test.describe('DurableRecordStore conformance', () => {
    test('loads missing records as not_found', async () => {
      await expect(factory().loadEcdsaRoleLocalReadyRecord(storageKeyFacts)).resolves
        .toMatchObject({
          ok: true,
          value: { kind: 'not_found' },
        });
    });

    test('persists, loads, and cleans up a valid ready record', async () => {
      const store = factory();
      const record = createReadyRecord();

      await expect(
        store.persistEcdsaRoleLocalReadyRecord({
          record,
          storageKeyFacts,
        }),
      ).resolves.toMatchObject({ ok: true, value: { kind: 'persisted' } });

      await expect(store.loadEcdsaRoleLocalReadyRecord(storageKeyFacts)).resolves.toMatchObject({
        ok: true,
        value: {
          kind: 'found',
          record: { kind: 'ecdsa_role_local_ready_passkey_v1' },
        },
      });

      await expect(
        store.cleanupMalformedEcdsaRoleLocalRecord({
          ...storageKeyFacts,
          reason: 'conformance cleanup',
        }),
      ).resolves.toMatchObject({ ok: true, value: { kind: 'deleted' } });

      await expect(store.loadEcdsaRoleLocalReadyRecord(storageKeyFacts)).resolves.toMatchObject({
        ok: true,
        value: { kind: 'not_found' },
      });
    });

    test('keeps same-wallet same-chain passkey and Email OTP records separated', async () => {
      const store = factory();

      await expect(
        store.persistEcdsaRoleLocalReadyRecord({
          record: createReadyRecord(storageKeyFacts.authMethod),
          storageKeyFacts,
        }),
      ).resolves.toMatchObject({ ok: true });

      await expect(
        store.persistEcdsaRoleLocalReadyRecord({
          record: createReadyRecord(emailOtpStorageKeyFacts.authMethod),
          storageKeyFacts: emailOtpStorageKeyFacts,
        }),
      ).resolves.toMatchObject({ ok: true });

      await expect(store.loadEcdsaRoleLocalReadyRecord(storageKeyFacts)).resolves.toMatchObject({
        ok: true,
        value: {
          kind: 'found',
          record: { kind: 'ecdsa_role_local_ready_passkey_v1' },
        },
      });
      await expect(store.loadEcdsaRoleLocalReadyRecord(emailOtpStorageKeyFacts)).resolves
        .toMatchObject({
          ok: true,
          value: {
            kind: 'found',
            record: { kind: 'ecdsa_role_local_ready_email_otp_v1' },
          },
        });
    });

    test('rejects pending or raw record writes', async () => {
      const store = factory();
      const pendingRecord = {
        kind: 'ecdsa_role_local_pending_state_blob_v1',
        stateBlob: pendingStateBlob,
      } as unknown as EcdsaRoleLocalReadyRecord;
      const currentUnbranchedRecord = {
        kind: 'ecdsa_role_local_ready_record_v1',
        stateBlob: readyStateBlob,
        publicFacts: createPublicFacts(),
        authMethod: storageKeyFacts.authMethod,
      } as unknown as EcdsaRoleLocalReadyRecord;
      const rawRecord = {
        kind: 'legacy_raw_role_local_v1',
        clientShare32B64u: bytesB64u(32, 12),
      } as unknown as EcdsaRoleLocalReadyRecord;

      await expect(
        store.persistEcdsaRoleLocalReadyRecord({
          record: pendingRecord,
          storageKeyFacts,
        }),
      ).resolves.toMatchObject({ ok: false, code: 'invalid_record' });
      await expect(
        store.persistEcdsaRoleLocalReadyRecord({
          record: currentUnbranchedRecord,
          storageKeyFacts,
        }),
      ).resolves.toMatchObject({ ok: false, code: 'invalid_record' });
      await expect(
        store.persistEcdsaRoleLocalReadyRecord({
          record: rawRecord,
          storageKeyFacts,
        }),
      ).resolves.toMatchObject({ ok: false, code: 'invalid_record' });
    });
  });
}

export function runHttpTransportConformance(factory: () => HttpTransport): void {
  test.describe('HttpTransport conformance', () => {
    test('returns success responses', async () => {
      await expect(
        factory().request({
          method: 'POST',
          url: 'https://relayer.test/bootstrap',
          body: { command: 'prepare' },
        }),
      ).resolves.toMatchObject({
        ok: true,
        value: { status: 202, body: { accepted: true } },
      });
    });

    test('returns non-2xx responses without throwing', async () => {
      await expect(
        factory().request({
          method: 'GET',
          url: 'https://relayer.test/denied',
        }),
      ).resolves.toMatchObject({
        ok: true,
        value: { status: 403, body: { error: 'denied' } },
      });
    });

    test('returns typed timeout failures', async () => {
      await expect(
        factory().request({
          method: 'GET',
          url: 'https://relayer.test/slow',
          timeoutMs: 1,
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: 'timeout',
      });
    });

    test('propagates auth headers to the transport', async () => {
      await expect(
        factory().request({
          method: 'GET',
          url: 'https://relayer.test/auth',
          headers: { authorization: 'Bearer test-token' },
        }),
      ).resolves.toMatchObject({
        ok: true,
        value: {
          body: {
            auth: { authorization: 'Bearer test-token' },
          },
        },
      });
    });
  });
}

test.describe('browser platform adapter conformance', () => {
  test('exposes the expected runtime and port discriminants', () => {
    const runtime = createBrowserPlatformRuntime({
      indexedDB: createMemoryIndexedDB(),
      nowMs: () => 123,
      crypto: {
        getRandomValues<T extends ArrayBufferView | null>(array: T): T {
          if (array instanceof Uint8Array) array.fill(7);
          return array;
        },
      } as Crypto,
    });

    expect(runtime.kind).toBe('browser');
    expect(runtime.storage.kind).toBe('durable_record_store');
    expect(runtime.secrets.kind).toBe('secure_secret_store');
    expect(runtime.authenticator.kind).toBe('authenticator');
    expect(runtime.signerCrypto.kind).toBe('signer_crypto');
    expect(runtime.http.kind).toBe('http_transport');
    expect(runtime.clock.nowMs()).toBe(123);
    expect([...runtime.random.randomBytes(4)]).toEqual([7, 7, 7, 7]);
  });

  runAuthenticatorPortConformance(createBrowserAuthenticatorConformancePort);
  runSignerCryptoPortConformance(createBrowserSignerCryptoConformancePort);
  runDurableRecordStoreConformance(
    () => createBrowserPlatformRuntime({ indexedDB: createMemoryIndexedDB() }).storage,
  );
  runHttpTransportConformance(createBrowserHttpTransportConformancePort);

  test('returns typed unavailable results for browser secure secret storage', async () => {
    const runtime = createBrowserPlatformRuntime();

    await expect(
      runtime.secrets.seal({ purpose: 'conformance', secretB64u: bytesB64u(32, 8) }),
    ).resolves.toMatchObject({ ok: false, code: 'unavailable' });
    await expect(runtime.secrets.unseal({ handle: 'sealed' })).resolves.toMatchObject({
      ok: false,
      code: 'unavailable',
    });
    await expect(runtime.secrets.delete({ handle: 'sealed' })).resolves.toMatchObject({
      ok: false,
      code: 'unavailable',
    });
  });
});
