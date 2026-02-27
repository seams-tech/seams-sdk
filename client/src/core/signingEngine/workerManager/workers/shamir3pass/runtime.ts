import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';

export type Shamir3PassCipherInput = {
  ciphertextB64u: string;
  exponentB64u: string;
  shamirPrimeB64u: string;
};

export type Shamir3PassClientKeypair = {
  shamirPrimeB64u: string;
  clientEncryptExponentB64u: string;
  clientDecryptExponentB64u: string;
};

export interface Shamir3PassRuntime {
  generateClientKeypair(args: { shamirPrimeB64u: string }): Shamir3PassClientKeypair;
  addClientSeal(input: Shamir3PassCipherInput): string;
  removeClientSeal(input: Shamir3PassCipherInput): string;
}

type Shamir3PassWasmModuleShape = {
  default: (module_or_path?: unknown) => Promise<unknown>;
  init_shamir3pass_runtime?: () => void;
  shamir3pass_generate_client_lock_keys: (shamirPrimeB64u: string) => unknown;
  shamir3pass_add_lock: (
    ciphertextB64u: string,
    exponentB64u: string,
    shamirPrimeB64u: string,
  ) => string;
  shamir3pass_remove_lock: (
    ciphertextB64u: string,
    exponentB64u: string,
    shamirPrimeB64u: string,
  ) => string;
};

let runtimeSingletonPromise: Promise<Shamir3PassRuntime> | null = null;

function normalizeNonEmptyString(input: unknown, label: string): string {
  const value = typeof input === 'string' ? input.trim() : '';
  if (!value) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function normalizeClientKeypair(value: unknown): Shamir3PassClientKeypair {
  if (!value || typeof value !== 'object') {
    throw new Error('Invalid Shamir3Pass keypair response');
  }
  const record = value as Record<string, unknown>;
  return {
    shamirPrimeB64u: normalizeNonEmptyString(record.shamirPrimeB64u, 'shamirPrimeB64u'),
    clientEncryptExponentB64u: normalizeNonEmptyString(
      record.clientEncryptExponentB64u,
      'clientEncryptExponentB64u',
    ),
    clientDecryptExponentB64u: normalizeNonEmptyString(
      record.clientDecryptExponentB64u,
      'clientDecryptExponentB64u',
    ),
  };
}

async function loadShamir3PassWasmModule(): Promise<Shamir3PassWasmModuleShape> {
  const jsUrl = resolveWasmUrl('shamir3pass_runtime.js', 'Shamir3Pass Runtime');
  const wasmUrl = resolveWasmUrl('shamir3pass_runtime_bg.wasm', 'Shamir3Pass Runtime');

  const moduleCandidate = (await import(
    /* @vite-ignore */
    jsUrl.href
  )) as Partial<Shamir3PassWasmModuleShape>;
  if (typeof moduleCandidate.default !== 'function') {
    throw new Error('Invalid Shamir3Pass runtime module: missing wasm init function');
  }

  await moduleCandidate.default(wasmUrl);
  if (typeof moduleCandidate.init_shamir3pass_runtime === 'function') {
    moduleCandidate.init_shamir3pass_runtime();
  }
  if (
    typeof moduleCandidate.shamir3pass_generate_client_lock_keys !== 'function' ||
    typeof moduleCandidate.shamir3pass_add_lock !== 'function' ||
    typeof moduleCandidate.shamir3pass_remove_lock !== 'function'
  ) {
    throw new Error('Invalid Shamir3Pass runtime module: missing lock operations');
  }
  return moduleCandidate as Shamir3PassWasmModuleShape;
}

function createShamir3PassRuntime(module: Shamir3PassWasmModuleShape): Shamir3PassRuntime {
  return {
    generateClientKeypair: ({ shamirPrimeB64u }) =>
      normalizeClientKeypair(module.shamir3pass_generate_client_lock_keys(shamirPrimeB64u)),
    addClientSeal: ({ ciphertextB64u, exponentB64u, shamirPrimeB64u }) =>
      normalizeNonEmptyString(
        module.shamir3pass_add_lock(ciphertextB64u, exponentB64u, shamirPrimeB64u),
        'ciphertextB64u',
      ),
    removeClientSeal: ({ ciphertextB64u, exponentB64u, shamirPrimeB64u }) =>
      normalizeNonEmptyString(
        module.shamir3pass_remove_lock(ciphertextB64u, exponentB64u, shamirPrimeB64u),
        'ciphertextB64u',
      ),
  };
}

export async function getShamir3PassRuntime(): Promise<Shamir3PassRuntime> {
  if (!runtimeSingletonPromise) {
    runtimeSingletonPromise = loadShamir3PassWasmModule()
      .then((module) => createShamir3PassRuntime(module))
      .catch((error) => {
        runtimeSingletonPromise = null;
        throw error;
      });
  }
  return runtimeSingletonPromise;
}
