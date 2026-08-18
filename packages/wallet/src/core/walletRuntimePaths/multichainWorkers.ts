import { resolveWorkerBaseOrigin } from './workers';

export type MultichainWorkerKind = 'evmCrypto' | 'tempoSigner';

function defaultWorkerPath(kind: MultichainWorkerKind): string {
  switch (kind) {
    case 'evmCrypto':
      return '/sdk/workers/evm-crypto.worker.js';
    case 'tempoSigner':
      return '/sdk/workers/tempo-signer.worker.js';
  }
}

function resolveOverride(kind: MultichainWorkerKind): string | undefined {
  const ovAny = (typeof window !== 'undefined' ? (window as any) : {}) as any;
  switch (kind) {
    case 'evmCrypto':
      return typeof ovAny.__W3A_EVM_CRYPTO_WORKER_URL__ === 'string'
        ? ovAny.__W3A_EVM_CRYPTO_WORKER_URL__
        : undefined;
    case 'tempoSigner':
      return typeof ovAny.__W3A_TEMPO_SIGNER_WORKER_URL__ === 'string'
        ? ovAny.__W3A_TEMPO_SIGNER_WORKER_URL__
        : undefined;
  }
}

export function resolveMultichainWorkerUrl(
  kind: MultichainWorkerKind,
  opts?: { baseOrigin?: string },
): string {
  const baseOrigin =
    opts?.baseOrigin ||
    resolveWorkerBaseOrigin() ||
    (typeof window !== 'undefined' ? window.location.origin : '') ||
    'https://invalid.local';

  const candidate = resolveOverride(kind) || defaultWorkerPath(kind);
  if (/^https?:\/\//i.test(candidate)) return candidate;
  return new URL(candidate, baseOrigin).toString();
}
