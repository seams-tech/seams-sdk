import initSignerWasm, {
  type InitInput,
} from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { NormalizedLogger } from '../logger';
import type { SignerWasmModuleSupplier } from '../types';
import { getSignerWasmUrls } from './signerWasmUrls';

export type SignerWasmRuntimeState = {
  signerWasmReady: boolean;
};

export function isNodeEnvironment(): boolean {
  const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
    .process;
  const isNode = Boolean(processObj?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

async function resolveSignerWasmOverride(override: SignerWasmModuleSupplier): Promise<InitInput> {
  const candidate =
    typeof override === 'function'
      ? await (override as () => InitInput | Promise<InitInput>)()
      : await override;

  if (!candidate) {
    throw new Error('Signer WASM override resolved to an empty value');
  }

  return candidate;
}

async function initSignerWasmForNode(candidates: readonly URL[]): Promise<void> {
  const { fileURLToPath } = await import('node:url');
  const { readFile } = await import('node:fs/promises');

  for (const url of candidates) {
    try {
      const filePath = fileURLToPath(url);
      const bytes = await readFile(filePath);
      const buffer = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(buffer).set(bytes);
      const module = await WebAssembly.compile(buffer);
      await initSignerWasm({ module_or_path: module });
      return;
    } catch {
      // try the next filesystem candidate
    }
  }

  for (const url of candidates) {
    try {
      const filePath = fileURLToPath(url);
      await initSignerWasm({ module_or_path: filePath as unknown as InitInput });
      return;
    } catch {
      // try the next path candidate
    }
  }

  throw new Error('[AuthService] Failed to initialize signer WASM from filesystem candidates');
}

async function initSignerWasmFromCandidates(input: {
  readonly candidates: readonly URL[];
  readonly logger: NormalizedLogger;
}): Promise<void> {
  if (isNodeEnvironment()) {
    await initSignerWasmForNode(input.candidates);
    return;
  }

  let lastError: unknown = null;
  for (const candidate of input.candidates) {
    try {
      await initSignerWasm({ module_or_path: candidate as InitInput });
      return;
    } catch (error: unknown) {
      lastError = error;
      input.logger.warn(
        `Failed to initialize signer WASM from ${candidate.toString()}, trying next candidate...`,
      );
    }
  }

  throw lastError ?? new Error('Unable to initialize signer WASM from any candidate URL');
}

export async function ensureSignerWasmRuntime(input: {
  readonly state: SignerWasmRuntimeState;
  readonly override?: SignerWasmModuleSupplier;
  readonly logger: NormalizedLogger;
}): Promise<SignerWasmRuntimeState> {
  if (input.state.signerWasmReady) return input.state;

  if (input.override) {
    try {
      const moduleOrPath = await resolveSignerWasmOverride(input.override);
      await initSignerWasm({ module_or_path: moduleOrPath as InitInput });
      return { signerWasmReady: true };
    } catch (error: unknown) {
      input.logger.error('Failed to initialize signer WASM via provided override:', error);
      throw error;
    }
  }

  let candidates: URL[];
  try {
    candidates = getSignerWasmUrls(input.logger);
  } catch (error: unknown) {
    input.logger.error('Failed to resolve signer WASM URLs:', error);
    throw error;
  }

  try {
    await initSignerWasmFromCandidates({
      candidates,
      logger: input.logger,
    });
    return { signerWasmReady: true };
  } catch (error: unknown) {
    input.logger.error('Failed to initialize signer WASM:', error);
    throw error instanceof Error ? error : new Error(String(error));
  }
}
