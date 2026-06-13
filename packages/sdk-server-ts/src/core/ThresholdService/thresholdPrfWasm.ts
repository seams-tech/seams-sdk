import * as thresholdPrfImports from '../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.js';
import {
  __wbg_set_wasm as setThresholdPrfWasm,
  init_threshold_prf,
  threshold_prf_derive_ecdsa_hss_y_relayer,
  threshold_prf_derive_ed25519_hss_server_inputs,
} from '../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.js';
import { createWasmLoader } from '../wasm-loader';
import type {
  ThresholdEd25519HssCanonicalContext,
} from '../types';
import type { ThresholdPrfPolicy } from './signingRootShareResolver';

const THRESHOLD_PRF_WASM_PATH_CANDIDATES = [
  '../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../workers/threshold_prf.wasm',
  '../../../workers/threshold_prf.wasm',
];

let thresholdPrfWasmInitPromise: Promise<void> | null = null;
let thresholdPrfWasmReady = false;

const THRESHOLD_PRF_SIGNING_ROOT_SHARE_WIRE_LENGTH = 34;
const MAX_THRESHOLD_PRF_SHARE_COUNT = 255;

export type EcdsaHssStableKeyPrfContext = {
  readonly walletId: string;
  readonly rpId: string;
  readonly ecdsaThresholdKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly walletSigningSessionId?: never;
  readonly thresholdSessionId?: never;
  readonly keyPurpose: string;
  readonly keyVersion: string;
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

async function compileThresholdPrfWasm(input: unknown): Promise<WebAssembly.Module> {
  if (input instanceof WebAssembly.Module) return input;
  if (input instanceof Response) {
    return WebAssembly.compile(await input.arrayBuffer());
  }
  if (input instanceof URL || typeof input === 'string') {
    const response = await fetch(input);
    if (!response.ok) {
      throw new Error(`failed to fetch threshold-prf WASM: ${response.status}`);
    }
    return WebAssembly.compile(await response.arrayBuffer());
  }
  if (input instanceof ArrayBuffer) {
    return WebAssembly.compile(input);
  }
  if (ArrayBuffer.isView(input)) {
    const view = input as ArrayBufferView;
    return WebAssembly.compile(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
  }
  throw new Error('unsupported threshold-prf WASM module input');
}

async function initThresholdPrfSignerWasm(input: { module_or_path: unknown }): Promise<void> {
  const module = await compileThresholdPrfWasm(input.module_or_path);
  const instance = await WebAssembly.instantiate(module, {
    './threshold_prf_bg.js': thresholdPrfImports,
  });
  setThresholdPrfWasm(instance.exports);
  const start = instance.exports.__wbindgen_start;
  if (typeof start === 'function') start();
  init_threshold_prf();
  thresholdPrfWasmReady = true;
}

export async function ensureThresholdPrfWasm(): Promise<void> {
  if (thresholdPrfWasmInitPromise) return thresholdPrfWasmInitPromise;
  const loader = createWasmLoader(initThresholdPrfSignerWasm, {
    logPrefix: 'threshold-prf',
    baseUrl: import.meta.url,
    fallbackUrls: getThresholdPrfWasmUrls(),
  });
  thresholdPrfWasmInitPromise = loader.load();
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

function checkedResultBytes(label: string, value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array`);
  }
  return checkedBytes(label, value, 32).slice();
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

function sortedSigningRootShareWireSetIds(shareWires: SigningRootShareWireSet): number[] {
  return shareWires.map(signingRootShareWireShareId).sort((a, b) => a - b);
}

function requireMatchingParticipantIds(input: {
  readonly participantIds: readonly number[];
  readonly shareIds: readonly number[];
}): void {
  const participantIds = input.participantIds.map((value) => requireU16('participantIds', value));
  participantIds.sort((a, b) => a - b);
  if (participantIds.length !== input.shareIds.length) {
    throw new Error('participantIds must match the selected share ids');
  }
  for (let i = 0; i < input.shareIds.length; i += 1) {
    if (participantIds[i] !== input.shareIds[i]) {
      throw new Error('participantIds must match the selected share ids');
    }
  }
}

function requiredTrimmed(label: string, value: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) throw new Error(`${label} is required`);
  return trimmed;
}

export async function deriveEcdsaHssYRelayerFromSigningRootShares(input: {
  readonly policy: ThresholdPrfPolicy;
  readonly shareWires: readonly SigningRootShareWire[];
  readonly context: EcdsaHssStableKeyPrfContext;
}): Promise<Uint8Array> {
  await ensureThresholdPrfWasm();
  requireThresholdPrfWasmReady();

  const policy = normalizeThresholdPrfPolicy(input.policy);
  const shareWires = validateSigningRootShareWireSet(policy, input.shareWires);
  const flattened = flattenSigningRootShareWireSet(shareWires);
  try {
    const out = threshold_prf_derive_ecdsa_hss_y_relayer(
      policy.threshold,
      policy.shareCount,
      flattened,
      requiredTrimmed('walletId', input.context.walletId),
      requiredTrimmed('rpId', input.context.rpId),
      requiredTrimmed('ecdsaThresholdKeyId', input.context.ecdsaThresholdKeyId),
      requiredTrimmed('signingRootId', input.context.signingRootId),
      requiredTrimmed('signingRootVersion', input.context.signingRootVersion),
      requiredTrimmed('keyPurpose', input.context.keyPurpose),
      requiredTrimmed('keyVersion', input.context.keyVersion),
    ) as Uint8Array;
    return checkedBytes('threshold-prf ecdsa-hss y_relayer', out, 32).slice();
  } finally {
    flattened.fill(0);
    for (const wire of shareWires) wire.fill(0);
  }
}

export async function deriveEd25519HssServerInputsFromSigningRootShares(input: {
  readonly policy: ThresholdPrfPolicy;
  readonly shareWires: readonly SigningRootShareWire[];
  readonly context: ThresholdEd25519HssCanonicalContext;
}): Promise<
  ThresholdEd25519HssCanonicalContext & {
    readonly contextBinding: Uint8Array;
    readonly yRelayer: Uint8Array;
    readonly tauRelayer: Uint8Array;
  }
> {
  await ensureThresholdPrfWasm();
  requireThresholdPrfWasmReady();

  const policy = normalizeThresholdPrfPolicy(input.policy);
  const shareWires = validateSigningRootShareWireSet(policy, input.shareWires);
  const shareIds = sortedSigningRootShareWireSetIds(shareWires);
  requireMatchingParticipantIds({
    participantIds: input.context.participantIds,
    shareIds,
  });

  const flattened = flattenSigningRootShareWireSet(shareWires);
  try {
    const result = threshold_prf_derive_ed25519_hss_server_inputs(
      policy.threshold,
      policy.shareCount,
      flattened,
      requiredTrimmed('signingRootId', input.context.signingRootId),
      requiredTrimmed('nearAccountId', input.context.nearAccountId),
      requiredTrimmed('keyPurpose', input.context.keyPurpose),
      requiredTrimmed('keyVersion', input.context.keyVersion),
      Number(input.context.derivationVersion),
    ) as {
      contextBinding?: Uint8Array;
      yRelayer?: Uint8Array;
      tauRelayer?: Uint8Array;
    };

    return {
      signingRootId: requiredTrimmed('signingRootId', input.context.signingRootId),
      nearAccountId: requiredTrimmed('nearAccountId', input.context.nearAccountId),
      keyPurpose: requiredTrimmed('keyPurpose', input.context.keyPurpose),
      keyVersion: requiredTrimmed('keyVersion', input.context.keyVersion),
      participantIds: shareIds,
      derivationVersion: Number(input.context.derivationVersion),
      contextBinding: checkedResultBytes('contextBinding', result.contextBinding),
      yRelayer: checkedResultBytes('yRelayer', result.yRelayer),
      tauRelayer: checkedResultBytes('tauRelayer', result.tauRelayer),
    };
  } finally {
    flattened.fill(0);
    for (const wire of shareWires) wire.fill(0);
  }
}
