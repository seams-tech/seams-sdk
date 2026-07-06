import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as HssClientSignerWasm from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import * as NearSignerWasm from '../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import * as ThresholdPrfWasm from '../../wasm/threshold_prf/pkg/threshold_prf.js';

const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const NEAR_SIGNER_SERVER_WASM_URL = new URL(
  '../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  import.meta.url,
);
const THRESHOLD_PRF_WASM_URL = new URL(
  '../../wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  import.meta.url,
);

const APPLICATION_BINDING_DOMAIN = 'seams-sdk:ed25519-hss:application-binding:v1';
const CANONICAL_CONTEXT = {
  signingRootId: 'project_single_key_hss:env_single_key_hss',
  nearAccountId: 'single-key-hss-boundary-test.testnet',
  keyPurpose: 'near-ed25519-signing',
  keyVersion: 'root-v1',
  participantIds: [1, 2],
  derivationVersion: 1,
  applicationBindingDigestB64u: applicationBindingDigestB64u({
    nearEd25519SigningKeyId: 'near-ed25519:hss-boundary-test',
    signingRootId: 'project_single_key_hss:env_single_key_hss',
    signingRootVersion: 'root-v1',
  }),
};
const RELAYER_KEY_ID = 'registration:hss-boundary-test';
const PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const DIFFERENT_PRF_FIRST_B64U = Buffer.alloc(32, 12).toString('base64url');
const THRESHOLD_PRF_THRESHOLD = 2;
const THRESHOLD_PRF_SHARE_COUNT = 3;
const SIGNING_ROOT_SHARE_WIRE_HEX = [
  '0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702',
  '0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f',
] as const;

let hssClientSignerWasmInitialized = false;
let nearSignerWasmInitialized = false;
let thresholdPrfWasmInitialized = false;

type Ed25519HssBoundaryFixture = {
  readonly contextBindingB64u: string;
  readonly evaluatorDriverStateB64u: string;
  readonly garblerDriverStateB64u: string;
  readonly stagedEvaluatorArtifactB64u: string;
  readonly advancedServerEvalStateB64u: string;
  readonly finalizeContextB64u: string;
  readonly priorStageResponseMessageB64u: string;
};

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  HssClientSignerWasm.initSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function ensureNearSignerWasm(): void {
  if (nearSignerWasmInitialized) return;
  NearSignerWasm.initSync({ module: readFileSync(NEAR_SIGNER_SERVER_WASM_URL) });
  NearSignerWasm.init_worker();
  nearSignerWasmInitialized = true;
}

function ensureThresholdPrfWasm(): void {
  if (thresholdPrfWasmInitialized) return;
  ThresholdPrfWasm.initSync({ module: readFileSync(THRESHOLD_PRF_WASM_URL) });
  ThresholdPrfWasm.init_threshold_prf();
  thresholdPrfWasmInitialized = true;
}

function ensureEd25519HssWasm(): void {
  ensureHssClientSignerWasm();
  ensureNearSignerWasm();
  ensureThresholdPrfWasm();
}

function applicationBindingDigestB64u(input: {
  readonly nearEd25519SigningKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): string {
  return createHash('sha256').update(encodeApplicationBindingFacts(input)).digest('base64url');
}

function encodeApplicationBindingFacts(input: {
  readonly nearEd25519SigningKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): Uint8Array {
  const out: number[] = [];
  const domainBytes = new TextEncoder().encode(APPLICATION_BINDING_DOMAIN);
  pushU32(out, domainBytes.length);
  out.push(...domainBytes);
  pushLengthDelimitedField(out, 'nearEd25519SigningKeyId', input.nearEd25519SigningKeyId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return new Uint8Array(out);
}

function pushLengthDelimitedField(out: number[], label: string, value: string): void {
  const labelBytes = new TextEncoder().encode(label);
  const valueBytes = new TextEncoder().encode(value);
  pushU32(out, labelBytes.length);
  out.push(...labelBytes);
  pushU32(out, valueBytes.length);
  out.push(...valueBytes);
}

function pushU32(out: number[], value: number): void {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function b64uBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function bytesB64u(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function hexBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'hex'));
}

function shareWireSetBytes(hexValues: readonly string[]): Uint8Array {
  const chunks = hexValues.map(hexBytes);
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function createEd25519HssBoundaryFixture(prfFirstB64u: string): Ed25519HssBoundaryFixture {
  const preparedServerSession =
    NearSignerWasm.threshold_ed25519_hss_prepare_server_session(CANONICAL_CONTEXT);
  const clientInputs = HssClientSignerWasm.derive_threshold_ed25519_hss_client_inputs({
    ...CANONICAL_CONTEXT,
    prfFirstB64u,
  });
  const serverInputs = ThresholdPrfWasm.threshold_prf_derive_ed25519_hss_server_inputs(
    THRESHOLD_PRF_THRESHOLD,
    THRESHOLD_PRF_SHARE_COUNT,
    shareWireSetBytes(SIGNING_ROOT_SHARE_WIRE_HEX),
    b64uBytes(CANONICAL_CONTEXT.applicationBindingDigestB64u),
  );
  const clientOutputMask = HssClientSignerWasm.threshold_ed25519_hss_derive_client_output_mask({
    ...CANONICAL_CONTEXT,
    contextBindingB64u: preparedServerSession.contextBindingB64u,
    operation: 'registration',
    relayerKeyId: RELAYER_KEY_ID,
    clientRecoverableSecretB64u: prfFirstB64u,
  });
  const clientRequest = HssClientSignerWasm.threshold_ed25519_hss_prepare_client_request({
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
    yClientB64u: clientInputs.yClientB64u,
    tauClientB64u: clientInputs.tauClientB64u,
  });
  const delivery =
    NearSignerWasm.threshold_ed25519_hss_prepare_role_separated_server_input_delivery({
      operation: 'registration',
      preparedSessionHandle: preparedServerSession.preparedSessionHandle,
      garblerDriverStateBytes: b64uBytes(preparedServerSession.garblerDriverStateB64u),
      clientRequestMessageBytes: b64uBytes(clientRequest.clientRequestMessageB64u),
      yRelayerBytes: serverInputs.yRelayer,
      tauRelayerBytes: serverInputs.tauRelayer,
    });
  const addStage = HssClientSignerWasm.threshold_ed25519_hss_prepare_add_stage_request_message({
    sessionSource: 'serialized_state',
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: delivery.serverInputDeliveryB64u,
  });
  const artifact =
    HssClientSignerWasm.threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact({
      sessionSource: 'serialized_state',
      evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
      evaluatorOtStateB64u: clientRequest.evaluatorOtStateB64u,
      serverInputDeliveryB64u: delivery.serverInputDeliveryB64u,
      clientOutputMaskB64u: clientOutputMask.clientOutputMaskB64u,
      expectedAddStageRequestMessageB64u: addStage.addStageRequestMessageB64u,
    });
  const advanced = NearSignerWasm.threshold_ed25519_hss_advance_server_eval_state({
    preparedSessionHandle: '',
    evaluatorDriverStateBytes: b64uBytes(preparedServerSession.evaluatorDriverStateB64u),
    garblerDriverStateBytes: b64uBytes(preparedServerSession.garblerDriverStateB64u),
    serverEvalStateBytes: b64uBytes(delivery.serverEvalStateB64u),
    addStageRequestMessageBytes: b64uBytes(addStage.addStageRequestMessageB64u),
    projectionMode: 'registration_seed_and_output',
  });

  return {
    contextBindingB64u: preparedServerSession.contextBindingB64u,
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    garblerDriverStateB64u: preparedServerSession.garblerDriverStateB64u,
    stagedEvaluatorArtifactB64u: artifact.stagedEvaluatorArtifactB64u,
    advancedServerEvalStateB64u: advanced.advancedServerEvalStateB64u,
    finalizeContextB64u: advanced.finalizeContextB64u,
    priorStageResponseMessageB64u: advanced.priorStageResponseMessageB64u,
  };
}

function finalizeAdvancedReport(fixture: Ed25519HssBoundaryFixture) {
  return NearSignerWasm.threshold_ed25519_hss_finalize_advanced_report({
    preparedSessionHandle: '',
    evaluatorDriverStateBytes: b64uBytes(fixture.evaluatorDriverStateB64u),
    garblerDriverStateBytes: b64uBytes(fixture.garblerDriverStateB64u),
    stagedEvaluatorArtifactBytes: b64uBytes(fixture.stagedEvaluatorArtifactB64u),
    advancedServerEvalStateBytes: b64uBytes(fixture.advancedServerEvalStateB64u),
    finalizeContextBytes: b64uBytes(fixture.finalizeContextB64u),
    priorStageResponseMessageBytes: b64uBytes(fixture.priorStageResponseMessageB64u),
    openSeedOutput: true,
  });
}

function truncateB64u(value: string): string {
  const bytes = b64uBytes(value);
  return bytesB64u(bytes.slice(0, Math.max(1, bytes.length - 8)));
}

test.describe('threshold Ed25519 HSS WASM surface', () => {
  test('durable advanced finalize rejects mismatched artifact and corrupt state bytes', () => {
    ensureEd25519HssWasm();
    const fixture = createEd25519HssBoundaryFixture(PRF_FIRST_B64U);
    const mismatchedArtifactFixture = createEd25519HssBoundaryFixture(DIFFERENT_PRF_FIRST_B64U);

    const valid = finalizeAdvancedReport(fixture);
    expect(valid.contextBindingB64u).toBe(fixture.contextBindingB64u);
    expect(String(valid.xRelayerBaseB64u || '')).not.toBe('');
    expect(String(valid.canonicalSeedB64u || '')).not.toBe('');
    expect(Number(valid.timings?.advanceOutputProjectionMs || 0)).toBe(0);

    expect(() =>
      finalizeAdvancedReport({
        ...fixture,
        stagedEvaluatorArtifactB64u: mismatchedArtifactFixture.stagedEvaluatorArtifactB64u,
      }),
    ).toThrow();
    expect(() =>
      finalizeAdvancedReport({
        ...fixture,
        advancedServerEvalStateB64u: truncateB64u(fixture.advancedServerEvalStateB64u),
      }),
    ).toThrow();
    expect(() =>
      finalizeAdvancedReport({
        ...fixture,
        finalizeContextB64u: truncateB64u(fixture.finalizeContextB64u),
      }),
    ).toThrow();
  });
});
