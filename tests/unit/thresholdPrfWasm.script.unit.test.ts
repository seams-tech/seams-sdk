import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveEcdsaHssYRelayerFromSigningRootShares,
  deriveEd25519HssServerInputsFromSigningRootShares,
  parseSigningRootShareWire,
  type SigningRootShareWire,
  type ThresholdPrfPolicy,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm';
import {
  initSync as initThresholdPrfWasmSync,
  init_threshold_prf,
  threshold_prf_combine_verified_partials,
  threshold_prf_derive_ecdsa_hss_y_relayer,
  threshold_prf_derive_ed25519_hss_server_inputs,
  threshold_prf_evaluate_partial_with_dleq_proof,
} from '../../wasm/threshold_prf/pkg/threshold_prf.js';

type ThresholdPrfFixtureShare = {
  readonly id: number;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly context_hex: string;
  readonly shares: readonly ThresholdPrfFixtureShare[];
  readonly direct_output_hex: string;
  readonly policy: {
    readonly threshold: number;
    readonly share_count: number;
  };
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(
  __dirname,
  '../../crates/threshold-prf/fixtures/protocol-t-of-n.json',
);
const THRESHOLD_PRF_WASM_PATH = resolve(
  __dirname,
  '../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
);
const ECDSA_HSS_FIXTURE_PURPOSE = 'ecdsa-hss/y_server';

test.beforeAll(() => {
  initThresholdPrfWasmSync({ module: readFileSync(THRESHOLD_PRF_WASM_PATH) });
  init_threshold_prf();
});

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function loadFixtureCorpus(): { readonly vectors: readonly ThresholdPrfFixtureVector[] } {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as {
    readonly vectors: readonly ThresholdPrfFixtureVector[];
  };
}

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const vector = loadFixtureCorpus().vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function policyForVector(vector: ThresholdPrfFixtureVector): ThresholdPrfPolicy {
  return {
    protocol: 'threshold-prf',
    threshold: vector.policy.threshold,
    shareCount: vector.policy.share_count,
  };
}

function shareWires(
  vector: ThresholdPrfFixtureVector,
  ids: readonly number[],
): readonly SigningRootShareWire[] {
  return ids.map((id) => {
    const share = vector.shares.find((candidate) => candidate.id === id);
    if (!share) throw new Error(`missing share ${id}`);
    return parseSigningRootShareWire(hexToBytes(share.wire_hex));
  });
}

function flattenShareWires(
  vector: ThresholdPrfFixtureVector,
  ids: readonly number[],
): Uint8Array {
  const chunks = ids.map((id) => {
    const share = vector.shares.find((candidate) => candidate.id === id);
    if (!share) throw new Error(`missing share ${id}`);
    return hexToBytes(share.wire_hex);
  });
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

test('threshold-prf WASM wrapper evaluates Router A/B proof bundles and combines verified partials', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const selectedIds = [1, 2] as const;
  const routerAbPurpose = 'router-ab/x_client_base/v1';
  const routerAbContext = new TextEncoder().encode('router-ab-threshold-prf-script-test/v1');
  const proofBundleWires = concatBytes(
    selectedIds.map((id) => {
      const share = vector.shares.find((candidate) => candidate.id === id);
      if (!share) throw new Error(`missing share ${id}`);
      return threshold_prf_evaluate_partial_with_dleq_proof(
        hexToBytes(share.wire_hex),
        routerAbPurpose,
        routerAbContext,
      );
    }),
  );

  const output = threshold_prf_combine_verified_partials(
    policy.threshold,
    policy.shareCount,
    proofBundleWires,
    routerAbPurpose,
    routerAbContext,
  );

  expect(proofBundleWires.byteLength).toBe(328);
  expect(output.byteLength).toBe(32);
});

test('threshold-prf WASM wrapper derives ECDSA HSS y_server through policy-shaped shares', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const selectedIds = [1, 2] as const;
  const context = {
    applicationBindingDigest: new Uint8Array(32).fill(7),
  };

  const yServer = await deriveEcdsaHssYRelayerFromSigningRootShares({
    policy,
    shareWires: shareWires(vector, selectedIds),
    context,
  });
  const expected = threshold_prf_derive_ecdsa_hss_y_relayer(
    policy.threshold,
    policy.shareCount,
    flattenShareWires(vector, selectedIds),
    context.applicationBindingDigest,
  );

  expect(bytesToHex(yServer)).toBe(bytesToHex(expected));
});

test('threshold-prf WASM wrapper derives Ed25519 HSS server inputs through policy-shaped shares', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const selectedIds = [1, 2] as const;
  const applicationBindingDigest = new Uint8Array(32).fill(9);
  const context = {
    applicationBindingDigestB64u: base64UrlEncode(applicationBindingDigest),
    participantIds: [1, 2],
  };

  const serverInputs = await deriveEd25519HssServerInputsFromSigningRootShares({
    policy,
    shareWires: shareWires(vector, selectedIds),
    context,
  });
  const expected = threshold_prf_derive_ed25519_hss_server_inputs(
    policy.threshold,
    policy.shareCount,
    flattenShareWires(vector, selectedIds),
    applicationBindingDigest,
  ) as {
    contextBinding: Uint8Array;
    yRelayer: Uint8Array;
    tauRelayer: Uint8Array;
  };

  expect(base64UrlEncode(serverInputs.contextBinding)).toBe(base64UrlEncode(expected.contextBinding));
  expect(base64UrlEncode(serverInputs.yRelayer)).toBe(base64UrlEncode(expected.yRelayer));
  expect(base64UrlEncode(serverInputs.tauRelayer)).toBe(base64UrlEncode(expected.tauRelayer));
  expect(serverInputs.participantIds).toEqual([1, 2]);
});

test('threshold-prf WASM wrapper rejects duplicate signing-root share ids', async () => {
  const vector = vectorForPurpose(ECDSA_HSS_FIXTURE_PURPOSE);
  const policy = policyForVector(vector);
  const duplicate = shareWires(vector, [1, 1]);

  await expect(
    deriveEcdsaHssYRelayerFromSigningRootShares({
      policy,
      shareWires: duplicate,
      context: {
        applicationBindingDigest: new Uint8Array(32).fill(7),
      },
    }),
  ).rejects.toThrow('distinct share ids');
});
