import initThresholdPrfWasm, {
  init_threshold_prf,
  threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer,
} from '../../../../../wasm/threshold_prf/pkg/threshold_prf.js';
import type { InitInput } from '../../../../../wasm/threshold_prf/pkg/threshold_prf.js';
import type { ThresholdPrfPolicy } from './signingRootShareResolver';

export type { ThresholdPrfPolicy } from './signingRootShareResolver';

const THRESHOLD_PRF_WASM_PATH_CANDIDATES = [
  '../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
];

type ThresholdPrfWasmModuleImport = {
  readonly default?: WebAssembly.Module;
};

let thresholdPrfWasmInitPromise: Promise<void> | null = null;
let thresholdPrfWasmReady = false;
const capturedFetch =
  typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;

const THRESHOLD_PRF_SIGNING_ROOT_SHARE_WIRE_LENGTH = 34;
const MAX_THRESHOLD_PRF_SHARE_COUNT = 255;

export type EcdsaDerivationStableKeyPrfContext = {
  readonly applicationBindingDigest: Uint8Array;
  readonly signingGrantId?: never;
  readonly thresholdSessionId?: never;
};

export type SigningRootShareWire = Uint8Array & {
  readonly __signingRootShareWire: 'SigningRootShareWire';
};

export type SigningRootShareWireSet = readonly SigningRootShareWire[];

function getThresholdPrfWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of THRESHOLD_PRF_WASM_PATH_CANDIDATES) {
    try {
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore invalid candidate
    }
  }
  return resolved;
}

function isNodeEnvironment(): boolean {
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

async function initThresholdPrfFromCompiledModule(module: WebAssembly.Module): Promise<void> {
  await initThresholdPrfWasm({ module_or_path: module as unknown as InitInput });
  init_threshold_prf();
  thresholdPrfWasmReady = true;
}

async function loadBundledThresholdPrfWasmModule(): Promise<WebAssembly.Module | null> {
  try {
    const imported = (await import(
      '../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm'
    )) as ThresholdPrfWasmModuleImport;
    return imported.default instanceof WebAssembly.Module ? imported.default : null;
  } catch {
    return null;
  }
}

async function compileThresholdPrfWasmFromUrl(url: URL): Promise<WebAssembly.Module> {
  const fetchFn =
    capturedFetch ??
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null);
  if (!fetchFn) {
    throw new Error('[threshold-prf] fetch is not available to load WASM');
  }
  const response = await fetchFn(url.toString());
  if (!response || typeof (response as { arrayBuffer?: unknown }).arrayBuffer !== 'function') {
    throw new Error('[threshold-prf] WASM fetch returned a non-Response object');
  }
  const status =
    typeof (response as { status?: unknown }).status === 'number'
      ? (response as { status: number }).status
      : 0;
  const ok =
    typeof (response as { ok?: unknown }).ok === 'boolean'
      ? (response as { ok: boolean }).ok
      : status === 0 || (status >= 200 && status < 300);
  if (!ok) {
    throw new Error(`[threshold-prf] WASM fetch failed with status ${status}`);
  }
  return await WebAssembly.compile(await response.arrayBuffer());
}

async function initThresholdPrfFromNodeFilesystem(urls: readonly URL[]): Promise<boolean> {
  const { fileURLToPath } = await import('node:url');
  const { readFile } = await import('node:fs/promises');
  for (const url of urls) {
    try {
      const bytes = await readFile(fileURLToPath(url));
      const ab = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(ab).set(bytes);
      await initThresholdPrfFromCompiledModule(await WebAssembly.compile(ab));
      return true;
    } catch {
      // try next filesystem candidate
    }
  }
  return false;
}

async function initThresholdPrfFromBundledModule(): Promise<boolean> {
  const module = await loadBundledThresholdPrfWasmModule();
  if (!module) return false;
  await initThresholdPrfFromCompiledModule(module);
  return true;
}

async function initThresholdPrfFromUrls(urls: readonly URL[]): Promise<void> {
  let lastError: unknown = null;
  for (const url of urls) {
    try {
      await initThresholdPrfFromCompiledModule(await compileThresholdPrfWasmFromUrl(url));
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error('[threshold-prf] Failed to initialize WASM');
}

export async function ensureThresholdPrfWasm(): Promise<void> {
  if (thresholdPrfWasmInitPromise) return thresholdPrfWasmInitPromise;
  thresholdPrfWasmInitPromise = (async () => {
    const urls = getThresholdPrfWasmUrls();
    if (isNodeEnvironment()) {
      const loaded = await initThresholdPrfFromNodeFilesystem(urls);
      if (loaded) return;
      throw new Error(
        `[threshold-prf] Failed to initialize WASM from filesystem candidates: ${urls.map((url) => url.toString()).join(', ')}`,
      );
    }

    if (await initThresholdPrfFromBundledModule()) return;
    await initThresholdPrfFromUrls(urls);
  })();
  return thresholdPrfWasmInitPromise;
}

function requireThresholdPrfWasmReady(): void {
  if (!thresholdPrfWasmReady) {
    throw new Error('[threshold-prf] WASM is not initialized');
  }
}

function checkedBytes(label: string, value: Uint8Array, expectedLength: number): Uint8Array {
  if (value.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes (got ${value.length})`);
  }
  return value;
}

function requireU16(label: string, value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > MAX_THRESHOLD_PRF_SHARE_COUNT) {
    throw new Error(`${label} must be an integer between 1 and ${MAX_THRESHOLD_PRF_SHARE_COUNT}`);
  }
  return value;
}

function normalizeThresholdPrfPolicy(policy: ThresholdPrfPolicy): ThresholdPrfPolicy {
  if (policy.protocol !== 'threshold-prf') {
    throw new Error('threshold-prf policy protocol must be threshold-prf');
  }
  const threshold = requireU16('threshold', policy.threshold);
  const shareCount = requireU16('shareCount', policy.shareCount);
  if (threshold > shareCount) {
    throw new Error('threshold must be less than or equal to shareCount');
  }
  return {
    protocol: 'threshold-prf',
    threshold,
    shareCount,
  };
}

function signingRootShareWireShareId(wire: SigningRootShareWire): number {
  return (wire[0] << 8) | wire[1];
}

export function parseSigningRootShareWire(input: unknown): SigningRootShareWire {
  if (!(input instanceof Uint8Array)) {
    throw new Error('SigningRootShareWire must be a Uint8Array');
  }
  if (input.length !== THRESHOLD_PRF_SIGNING_ROOT_SHARE_WIRE_LENGTH) {
    throw new Error(
      `SigningRootShareWire must be ${THRESHOLD_PRF_SIGNING_ROOT_SHARE_WIRE_LENGTH} bytes`,
    );
  }
  const wire = new Uint8Array(input) as SigningRootShareWire;
  if (signingRootShareWireShareId(wire) === 0) {
    wire.fill(0);
    throw new Error('SigningRootShareWire share id must be non-zero');
  }
  return wire;
}

function validateSigningRootShareWireSet(
  policy: ThresholdPrfPolicy,
  shareWires: readonly SigningRootShareWire[],
): SigningRootShareWireSet {
  if (shareWires.length !== policy.threshold) {
    throw new Error(`shareWires must contain exactly ${policy.threshold} share wires`);
  }
  const seen = new Set<number>();
  const out: SigningRootShareWire[] = [];
  try {
    for (const shareWire of shareWires) {
      const wire = parseSigningRootShareWire(shareWire);
      const shareId = signingRootShareWireShareId(wire);
      if (shareId > policy.shareCount) {
        wire.fill(0);
        throw new Error('SigningRootShareWire share id exceeds shareCount');
      }
      if (seen.has(shareId)) {
        wire.fill(0);
        throw new Error('shareWires must contain distinct share ids');
      }
      seen.add(shareId);
      out.push(wire);
    }
  } catch (error) {
    for (const wire of out) wire.fill(0);
    throw error;
  }
  return out;
}

function flattenSigningRootShareWireSet(shareWires: SigningRootShareWireSet): Uint8Array {
  const out = new Uint8Array(shareWires.length * THRESHOLD_PRF_SIGNING_ROOT_SHARE_WIRE_LENGTH);
  shareWires.forEach((wire, index) => {
    out.set(wire, index * THRESHOLD_PRF_SIGNING_ROOT_SHARE_WIRE_LENGTH);
  });
  return out;
}

export async function deriveEcdsaDerivationYRelayerFromSigningRootShares(input: {
  readonly policy: ThresholdPrfPolicy;
  readonly shareWires: readonly SigningRootShareWire[];
  readonly context: EcdsaDerivationStableKeyPrfContext;
}): Promise<Uint8Array> {
  await ensureThresholdPrfWasm();
  requireThresholdPrfWasmReady();

  const policy = normalizeThresholdPrfPolicy(input.policy);
  const shareWires = validateSigningRootShareWireSet(policy, input.shareWires);
  const flattened = flattenSigningRootShareWireSet(shareWires);
  try {
    const out = threshold_prf_derive_router_ab_ecdsa_derivation_y_relayer(
      policy.threshold,
      policy.shareCount,
      flattened,
      checkedBytes(
        'threshold-prf ecdsa-derivation applicationBindingDigest',
        input.context.applicationBindingDigest,
        32,
      ),
    ) as Uint8Array;
    return checkedBytes('threshold-prf ecdsa-derivation y_relayer', out, 32).slice();
  } finally {
    flattened.fill(0);
    for (const wire of shareWires) wire.fill(0);
  }
}
