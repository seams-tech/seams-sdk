import { base64UrlDecode } from '@shared/utils/encoders';
import initThresholdPrfWasm, {
  init_threshold_prf,
  threshold_prf_derive_ecdsa_hss_y_relayer,
  threshold_prf_derive_ed25519_hss_server_inputs,
} from '../../../../wasm/threshold_prf/pkg/threshold_prf.js';
import type { InitInput } from '../../../../wasm/threshold_prf/pkg/threshold_prf.js';
import { createWasmLoader } from '../wasm-loader';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssServerInputs,
} from '../types';
import type { SigningRootSecretShareWirePair } from './signingRootSecretShareWires';

const THRESHOLD_PRF_WASM_PATH_CANDIDATES = [
  '../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  '../../../../workers/threshold_prf.wasm',
  '../../../workers/threshold_prf.wasm',
];

let thresholdPrfWasmInitPromise: Promise<void> | null = null;
let thresholdPrfWasmReady = false;

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

async function initThresholdPrfSignerWasm(input: { module_or_path: InitInput }): Promise<void> {
  await initThresholdPrfWasm(input);
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

function requiredTrimmed(label: string, value: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) throw new Error(`${label} is required`);
  return trimmed;
}

function checkedB64u32(label: string, value: unknown): string {
  const text = requiredTrimmed(label, String(value || ''));
  const decoded = base64UrlDecode(text);
  try {
    checkedBytes(label, decoded, 32);
  } finally {
    decoded.fill(0);
  }
  return text;
}

export async function deriveEcdsaHssYRelayerFromSigningRootSecretShares(input: {
  readonly shareWires: SigningRootSecretShareWirePair;
  readonly context: EcdsaHssStableKeyPrfContext;
}): Promise<Uint8Array> {
  await ensureThresholdPrfWasm();
  requireThresholdPrfWasmReady();

  const out = threshold_prf_derive_ecdsa_hss_y_relayer(
    new Uint8Array(input.shareWires[0]),
    new Uint8Array(input.shareWires[1]),
    requiredTrimmed('walletId', input.context.walletId),
    requiredTrimmed('rpId', input.context.rpId),
    requiredTrimmed('ecdsaThresholdKeyId', input.context.ecdsaThresholdKeyId),
    requiredTrimmed('signingRootId', input.context.signingRootId),
    requiredTrimmed('signingRootVersion', input.context.signingRootVersion),
    requiredTrimmed('keyPurpose', input.context.keyPurpose),
    requiredTrimmed('keyVersion', input.context.keyVersion),
  ) as Uint8Array;
  return checkedBytes('threshold-prf ecdsa-hss y_relayer', out, 32).slice();
}

export async function deriveEd25519HssServerInputsFromSigningRootSecretShares(input: {
  readonly shareWires: SigningRootSecretShareWirePair;
  readonly context: ThresholdEd25519HssCanonicalContext;
}): Promise<
  ThresholdEd25519HssCanonicalContext &
    ThresholdEd25519HssServerInputs & { contextBindingB64u: string }
> {
  await ensureThresholdPrfWasm();
  requireThresholdPrfWasmReady();

  const result = threshold_prf_derive_ed25519_hss_server_inputs(
    new Uint8Array(input.shareWires[0]),
    new Uint8Array(input.shareWires[1]),
    requiredTrimmed('signingRootId', input.context.signingRootId),
    requiredTrimmed('nearAccountId', input.context.nearAccountId),
    requiredTrimmed('keyPurpose', input.context.keyPurpose),
    requiredTrimmed('keyVersion', input.context.keyVersion),
    new Uint32Array(input.context.participantIds.map((value) => Number(value))),
    Number(input.context.derivationVersion),
  ) as {
    contextBindingB64u?: string;
    yRelayerB64u?: string;
    tauRelayerB64u?: string;
  };

  return {
    signingRootId: requiredTrimmed('signingRootId', input.context.signingRootId),
    nearAccountId: requiredTrimmed('nearAccountId', input.context.nearAccountId),
    keyPurpose: requiredTrimmed('keyPurpose', input.context.keyPurpose),
    keyVersion: requiredTrimmed('keyVersion', input.context.keyVersion),
    participantIds: input.context.participantIds.map((value) => Number(value)),
    derivationVersion: Number(input.context.derivationVersion),
    contextBindingB64u: checkedB64u32('contextBindingB64u', result.contextBindingB64u),
    yRelayerB64u: checkedB64u32('yRelayerB64u', result.yRelayerB64u),
    tauRelayerB64u: checkedB64u32('tauRelayerB64u', result.tauRelayerB64u),
  };
}
