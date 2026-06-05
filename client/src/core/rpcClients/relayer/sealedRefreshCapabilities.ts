import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';

type SealedRefreshMode = 'none' | 'sealed_refresh_v1';

export type RelayerSigningSessionSealCapabilities =
  | { mode: 'none' }
  | {
      mode: 'sealed_refresh_v1';
      keyVersion?: string;
      shamirPrimeB64u: string;
    };

type VerifySealedRefreshStartupParityArgs = {
  configs: SeamsConfigsReadonly;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
};

type FetchRelayerSigningSessionSealCapabilitiesArgs = {
  relayerUrl: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
};

const DEFAULT_TIMEOUT_MS = 8_000;
const parityCheckByConfigKey = new Map<string, Promise<void>>();

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function normalizeMode(value: unknown): SealedRefreshMode | null {
  const mode = String(value || '')
    .trim()
    .toLowerCase();
  if (mode === 'none') return 'none';
  if (mode === 'sealed_refresh_v1') return 'sealed_refresh_v1';
  return null;
}

function normalizeSigningSessionSealCapabilities(
  value: unknown,
): RelayerSigningSessionSealCapabilities | null {
  const obj = asRecord(value);
  if (!obj) return null;

  const mode = normalizeMode(obj.mode);
  if (!mode) return null;
  if (mode === 'none') return { mode: 'none' };

  const shamirPrimeB64u = normalizeOptionalNonEmptyString(obj.shamirPrimeB64u);
  if (!shamirPrimeB64u) return null;
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);

  return {
    mode: 'sealed_refresh_v1',
    shamirPrimeB64u,
    ...(keyVersion ? { keyVersion } : {}),
  };
}

function parseWellKnownSigningSessionSealCapabilities(
  payload: unknown,
): RelayerSigningSessionSealCapabilities {
  const root = asRecord(payload);
  if (!root) return { mode: 'none' };

  const fromCapabilities = normalizeSigningSessionSealCapabilities(
    asRecord(root.capabilities)?.signingSessionSeal,
  );
  if (fromCapabilities) return fromCapabilities;

  return { mode: 'none' };
}

function shouldEnforceSealedRefreshParity(configs: SeamsConfigsReadonly): boolean {
  if (configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return false;
  const appOriginWalletIframeMode =
    configs.wallet.mode === 'iframe' && !__isWalletIframeHostMode();
  return !appOriginWalletIframeMode;
}

function buildParityConfigKey(configs: SeamsConfigsReadonly): string {
  const relayerUrl = String(configs.network.relayer.url || '').trim();
  const mode = String(configs.signing.sessionPersistenceMode || '').trim().toLowerCase();
  const keyVersion = normalizeOptionalNonEmptyString(configs.signing.sessionSeal.keyVersion) || '';
  const shamirPrimeB64u =
    normalizeOptionalNonEmptyString(configs.signing.sessionSeal.shamirPrimeB64u) || '';
  const hostMode = __isWalletIframeHostMode() ? 'wallet-host' : 'app';
  const walletMode = configs.wallet.mode;
  return [relayerUrl, mode, keyVersion, shamirPrimeB64u, hostMode, walletMode].join('|');
}

function normalizeTimeoutMs(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.max(250, Math.floor(parsed));
}

function createErrorWithCode(message: string, code: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

function withTimeout(input: {
  timeoutMs: number;
  signal?: AbortSignal;
  task: (signal: AbortSignal) => Promise<RelayerSigningSessionSealCapabilities>;
}): Promise<RelayerSigningSessionSealCapabilities> {
  if (input.signal?.aborted) {
    throw createErrorWithCode('Parity check aborted', 'sealed_refresh_parity_aborted');
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort('timeout'), input.timeoutMs);
  const onAbort = () => {
    try {
      controller.abort(input.signal?.reason);
    } catch {}
  };
  input.signal?.addEventListener('abort', onAbort, { once: true });

  return input
    .task(controller.signal)
    .finally(() => {
      clearTimeout(timeoutId);
      input.signal?.removeEventListener('abort', onAbort);
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error || 'Unknown error');
      if (controller.signal.aborted) {
        throw createErrorWithCode(
          `[sealed-refresh-parity] Failed to fetch relayer well-known capabilities: ${message}`,
          'sealed_refresh_parity_fetch_failed',
        );
      }
      throw error;
    });
}

export async function fetchRelayerSigningSessionSealCapabilities(
  args: FetchRelayerSigningSessionSealCapabilitiesArgs,
): Promise<RelayerSigningSessionSealCapabilities> {
  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw createErrorWithCode(
      '[sealed-refresh-parity] Missing relayer URL for capability check',
      'sealed_refresh_parity_invalid_config',
    );
  }

  const fetchImpl = args.fetchImpl || fetch.bind(globalThis);
  const timeoutMs = normalizeTimeoutMs(args.timeoutMs, DEFAULT_TIMEOUT_MS);
  const wellKnownUrl = `${relayerUrl.replace(/\/+$/, '')}/.well-known/webauthn`;

  return await withTimeout({
    timeoutMs,
    task: async (signal) => {
      const response = await fetchImpl(wellKnownUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
        signal,
      });

      if (!response.ok) {
        throw createErrorWithCode(
          `[sealed-refresh-parity] Well-known endpoint returned HTTP ${response.status}`,
          'sealed_refresh_parity_http_error',
        );
      }

      let payload: unknown = {};
      try {
        payload = await response.json();
      } catch {
        throw createErrorWithCode(
          '[sealed-refresh-parity] Well-known response is not valid JSON',
          'sealed_refresh_parity_invalid_payload',
        );
      }

      return parseWellKnownSigningSessionSealCapabilities(payload);
    },
  });
}

export async function verifySealedRefreshStartupParity(
  args: VerifySealedRefreshStartupParityArgs,
): Promise<void> {
  if (!shouldEnforceSealedRefreshParity(args.configs)) return;

  const configKey = buildParityConfigKey(args.configs);
  const existing = parityCheckByConfigKey.get(configKey);
  if (existing) {
    await existing;
    return;
  }

  const task = (async () => {
    const relayerUrl = String(args.configs.network.relayer.url || '').trim();
    const clientMode = args.configs.signing.sessionPersistenceMode;
    const clientKeyVersion = normalizeOptionalNonEmptyString(args.configs.signing.sessionSeal.keyVersion);
    const clientShamirPrimeB64u = normalizeOptionalNonEmptyString(
      args.configs.signing.sessionSeal.shamirPrimeB64u,
    );

    if (!clientShamirPrimeB64u) {
      throw createErrorWithCode(
        '[sealed-refresh-parity] Missing signing.sessionSeal.shamirPrimeB64u in client config',
        'sealed_refresh_parity_invalid_config',
      );
    }

    const server = await fetchRelayerSigningSessionSealCapabilities({
      relayerUrl,
      fetchImpl: args.fetchImpl,
      timeoutMs: args.timeoutMs,
    });

    const serverKeyVersion =
      server.mode === 'sealed_refresh_v1' ? normalizeOptionalNonEmptyString(server.keyVersion) : null;
    const serverShamirPrimeB64u =
      server.mode === 'sealed_refresh_v1'
        ? normalizeOptionalNonEmptyString(server.shamirPrimeB64u)
        : null;

    const mismatches: string[] = [];
    if (server.mode !== clientMode) mismatches.push('mode');
    if (serverKeyVersion !== (clientKeyVersion || null)) mismatches.push('keyVersion');
    if (serverShamirPrimeB64u !== clientShamirPrimeB64u) mismatches.push('shamirPrimeB64u');

    if (mismatches.length > 0) {
      throw createErrorWithCode(
        `[sealed-refresh-parity] Client/server mismatch for fields: ${mismatches.join(', ')}. ` +
          `client={mode:${clientMode},keyVersion:${clientKeyVersion || ''},shamirPrimeB64u:${clientShamirPrimeB64u}} ` +
          `server={mode:${server.mode},keyVersion:${serverKeyVersion || ''},shamirPrimeB64u:${serverShamirPrimeB64u || ''}}`,
        'sealed_refresh_parity_mismatch',
      );
    }
  })().catch((error: unknown) => {
    parityCheckByConfigKey.delete(configKey);
    throw error;
  });

  parityCheckByConfigKey.set(configKey, task);
  await task;
}
