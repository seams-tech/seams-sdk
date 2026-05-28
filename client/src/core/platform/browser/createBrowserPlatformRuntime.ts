import { IndexedDBManager } from '../../indexedDB';
import type {
  AuthenticatorOperation,
  AuthenticatorPort,
  ClockPort,
  DurableRecordStore,
  HttpTransport,
  PlatformResult,
  PlatformRuntime,
  RandomSource,
  SecureSecretStore,
  SignerCryptoPort,
} from '../types';

type BrowserPlatformRuntimeDeps = {
  indexedDB?: typeof IndexedDBManager;
  fetch?: typeof fetch;
  crypto?: Crypto;
  nowMs?: () => number;
};

export type BrowserDurableRecordStore = DurableRecordStore & {
  indexedDB: typeof IndexedDBManager;
};

export type BrowserPlatformRuntime = PlatformRuntime & {
  kind: 'browser';
  storage: BrowserDurableRecordStore;
};

function unavailable<T>(message: string): PlatformResult<T, 'unavailable'> {
  return { ok: false, code: 'unavailable', message };
}

function createBrowserDurableRecordStore(
  indexedDB: typeof IndexedDBManager,
): BrowserDurableRecordStore {
  return {
    kind: 'durable_record_store',
    indexedDB,
    async get() {
      return unavailable('Generic durable record access is not wired yet');
    },
    async put() {
      return unavailable('Generic durable record access is not wired yet');
    },
    async delete() {
      return unavailable('Generic durable record access is not wired yet');
    },
  };
}

function createBrowserSecureSecretStore(): SecureSecretStore {
  return {
    kind: 'secure_secret_store',
    async seal() {
      return unavailable('Browser secure secret store is not wired yet');
    },
    async unseal() {
      return unavailable('Browser secure secret store is not wired yet');
    },
    async delete() {
      return unavailable('Browser secure secret store is not wired yet');
    },
  };
}

function createBrowserAuthenticatorPort(): AuthenticatorPort {
  return {
    kind: 'authenticator',
    async run(operation: AuthenticatorOperation) {
      switch (operation.kind) {
        case 'create_passkey':
        case 'get_passkey':
          return { ok: false, code: 'unavailable', message: 'Authenticator adapter is not wired yet' };
      }
    },
  };
}

function createBrowserSignerCryptoPort(): SignerCryptoPort {
  return {
    kind: 'signer_crypto',
    async prepareEcdsaClientBootstrap() {
      return {
        ok: false,
        code: 'unavailable',
        message: 'ECDSA client bootstrap crypto adapter is not wired yet',
      };
    },
  };
}

function createBrowserHttpTransport(fetchImpl: typeof fetch | undefined): HttpTransport {
  return {
    kind: 'http_transport',
    async request(input) {
      if (!fetchImpl) return { ok: false, code: 'network_error', message: 'fetch is unavailable' };
      const controller = new AbortController();
      const timeout =
        input.timeoutMs && input.timeoutMs > 0
          ? setTimeout(() => controller.abort(), input.timeoutMs)
          : null;
      try {
        const response = await fetchImpl(input.url, {
          method: input.method,
          headers: input.headers,
          body: input.body == null ? undefined : JSON.stringify(input.body),
          signal: controller.signal,
        });
        const contentType = response.headers.get('content-type') || '';
        const body = contentType.includes('application/json')
          ? await response.json().catch(() => null)
          : await response.text().catch(() => '');
        return { ok: true, value: { status: response.status, body } };
      } catch (error) {
        const code = controller.signal.aborted ? 'timeout' : 'network_error';
        return { ok: false, code, message: error instanceof Error ? error.message : String(error) };
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    },
  };
}

function createBrowserClock(nowMs: (() => number) | undefined): ClockPort {
  return {
    kind: 'clock',
    nowMs: nowMs || (() => Date.now()),
  };
}

function createBrowserRandomSource(cryptoImpl: Crypto | undefined): RandomSource {
  return {
    kind: 'random_source',
    randomBytes(length) {
      if (!cryptoImpl?.getRandomValues) {
        throw new Error('Browser crypto.getRandomValues is unavailable');
      }
      const bytes = new Uint8Array(length);
      cryptoImpl.getRandomValues(bytes);
      return bytes;
    },
  };
}

export function createBrowserPlatformRuntime(
  deps: BrowserPlatformRuntimeDeps = {},
): BrowserPlatformRuntime {
  const indexedDB = deps.indexedDB || IndexedDBManager;
  return {
    kind: 'browser',
    storage: createBrowserDurableRecordStore(indexedDB),
    secrets: createBrowserSecureSecretStore(),
    authenticator: createBrowserAuthenticatorPort(),
    signerCrypto: createBrowserSignerCryptoPort(),
    http: createBrowserHttpTransport(deps.fetch || globalThis.fetch?.bind(globalThis)),
    clock: createBrowserClock(deps.nowMs),
    random: createBrowserRandomSource(deps.crypto || globalThis.crypto),
  };
}

export function getBrowserPlatformIndexedDB(runtime: PlatformRuntime): typeof IndexedDBManager {
  if (runtime.kind !== 'browser' || !('indexedDB' in runtime.storage)) {
    throw new Error('Browser IndexedDB manager is unavailable for this platform runtime');
  }
  return (runtime.storage as BrowserDurableRecordStore).indexedDB;
}
