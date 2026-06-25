import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import {
  createSigningRuntime,
  createSigningRuntimeStatePorts,
} from '@/core/runtime/createSigningRuntime';
import type { RuntimePorts } from '@/core/platform';
import { toSigningRuntimeConfig } from '@/SeamsWeb/assembly/runtimeConfig';

function createInMemoryRuntimePorts(): RuntimePorts {
  return {
    kind: 'browser',
    storage: {
      kind: 'durable_record_store',
      async loadEcdsaRoleLocalReadyRecord() {
        return { ok: false, code: 'unavailable', message: 'in-memory runtime has no records' };
      },
      async persistEcdsaRoleLocalReadyRecord() {
        return { ok: true, value: { kind: 'persisted' } };
      },
      async cleanupMalformedEcdsaRoleLocalRecord() {
        return { ok: true, value: { kind: 'not_found' } };
      },
    },
    secrets: {
      kind: 'secure_secret_store',
      async seal() {
        return { ok: false, code: 'unavailable', message: 'in-memory runtime has no secret seal' };
      },
      async unseal() {
        return { ok: false, code: 'unavailable', message: 'in-memory runtime has no secret seal' };
      },
      async delete() {
        return { ok: true, value: undefined };
      },
    },
    authenticator: {
      kind: 'authenticator',
      async run() {
        return { ok: false, code: 'unavailable', message: 'in-memory runtime has no authenticator' };
      },
    },
    signerCrypto: {
      kind: 'signer_crypto',
      async prepareEcdsaClientBootstrap() {
        return {
          ok: false,
          failure: 'invocation',
          code: 'unavailable',
          message: 'in-memory runtime has no signer crypto',
        };
      },
      async finalizeEcdsaClientBootstrap() {
        return {
          ok: false,
          failure: 'invocation',
          code: 'unavailable',
          message: 'in-memory runtime has no signer crypto',
        };
      },
      async storeEcdsaRoleLocalSigningMaterial() {
        return {
          ok: false,
          failure: 'invocation',
          code: 'unavailable',
          message: 'in-memory runtime has no signer crypto',
        };
      },
      async buildEcdsaRoleLocalExportArtifact() {
        return {
          ok: false,
          failure: 'invocation',
          code: 'unavailable',
          message: 'in-memory runtime has no signer crypto',
        };
      },
    },
    http: {
      kind: 'http_transport',
      async request() {
        return { ok: false, code: 'network_error', message: 'in-memory runtime has no network' };
      },
    },
    clock: {
      kind: 'clock',
      nowMs() {
        return 1_780_000_000_000;
      },
    },
    random: {
      kind: 'random_source',
      randomBytes(length) {
        return new Uint8Array(length);
      },
    },
  };
}

test.describe('SigningRuntime construction', () => {
  test('constructs with an in-memory platform runtime and explicit state ports', () => {
    const state = createSigningRuntimeStatePorts();
    const runtime = createSigningRuntime({
      runtimePorts: createInMemoryRuntimePorts(),
      relayers: {
        ecdsa: {
          async bootstrapEcdsaSession() {
            return {
              ok: false,
              code: 'unavailable',
              message: 'in-memory runtime has no relayer transport',
              retryable: false,
            };
          },
        },
      },
      workers: {
        emailOtp: {
          async requestWorkerOperation() {
            throw new Error('in-memory runtime has no Email OTP worker');
          },
        },
      },
      nearKeyOps: {
        async signTransactionWithEphemeralNearKeypairHandle() {
          throw new Error('in-memory runtime has no NEAR key signer');
        },
        async generateEphemeralNearKeypairHandle() {
          throw new Error('in-memory runtime has no NEAR key generator');
        },
      },
      signing: {
        near: {
          getDeps() {
            throw new Error('in-memory runtime has no NEAR signing deps');
          },
        },
        evmFamily: {
          getDeps() {
            throw new Error('in-memory runtime has no EVM-family signing deps');
          },
        },
      },
      registration: {
        accountLifecycle: {
          accountStore: {
            async persistWalletSignerFinalize() {
              throw new Error('in-memory runtime has no account store');
            },
            async persistWalletRegistrationFinalize() {
              throw new Error('in-memory runtime has no account store');
            },
          } as any,
          userPreferencesManager: {
            setCurrentWallet() {},
            async reloadUserSettings() {},
          },
          nonceCoordinator: {
            initializeNearAccessKey() {},
            async prefetchNearContext() {},
          },
          async extractCosePublicKey() {
            throw new Error('in-memory runtime has no COSE parser');
          },
        },
        ecdsaBootstrapStore: {
          async upsertProfile() {
            throw new Error('in-memory runtime has no bootstrap store');
          },
          async activateAccountSigner() {
            throw new Error('in-memory runtime has no bootstrap store');
          },
        },
      },
      ui: {
        warmSessions: {
          getWarmSessionMaterialWriter: () => ({
            async putWarmSessionMaterial() {
              throw new Error('in-memory runtime has no warm-session material writer');
            },
          }),
        },
      },
      config: toSigningRuntimeConfig(buildConfigsFromEnv({
        relayer: {
          url: 'http://127.0.0.1:9090',
        },
      })),
      state,
    });

    expect(runtime.runtimePorts.kind).toBe('browser');
    expect(runtime.state.ecdsaSessions.recordsByLane).toBe(state.ecdsaSessions.recordsByLane);
    expect(runtime.state.ecdsaSessions.exportArtifactsByLane).toBe(
      state.ecdsaSessions.exportArtifactsByLane,
    );
  });
});
