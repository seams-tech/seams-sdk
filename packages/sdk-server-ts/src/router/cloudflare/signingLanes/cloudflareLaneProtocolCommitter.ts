import type {
  Ed25519YaoLaneJobV1,
  LaneEnrollmentGatewayV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
} from '@shared/signing-lanes';
import {
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import type { RouterAbEd25519YaoCeremonyBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  LaneLifecycleApplicationService,
  type LaneLifecycleAuthorizationPortV1,
  type LaneLifecycleCurveExecutionPortsV1,
} from '../../../core/signingLanes/LaneLifecycleApplicationService';

export const ROUTER_AB_ED25519_YAO_LANE_EXECUTE_PATH_V1 =
  '/router-ab/internal/ed25519-yao/lane/execute' as const;

const INTERNAL_SERVICE_AUTH_HEADER = 'x-router-ab-internal-service-auth';
const REPLAY_HEADER = 'x-seams-lane-replay';
const INTERNAL_ROUTER_ORIGIN = 'https://router.router-ab.internal';

type JsonRecord = Readonly<Record<string, unknown>>;

export interface CloudflareLaneServiceBindingV1 {
  fetch(request: Request): Promise<Response>;
}

export type PreparedEd25519YaoLaneSourceV1 = {
  readonly binding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly deriverAInput: JsonRecord;
  readonly deriverBInput: JsonRecord;
};

/**
 * Resolves the active source capability and creates recipient-bound Deriver
 * inputs inside the private server topology. Browser input is only an intent.
 */
export interface Ed25519YaoLaneSourcePreparationPortV1 {
  prepareSourceV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
  }): Promise<PreparedEd25519YaoLaneSourceV1>;
}

export type CloudflareEd25519LaneProtocolTransportOptionsV1 = {
  readonly router: CloudflareLaneServiceBindingV1;
  readonly internalServiceAuth: string;
  readonly sourcePreparation: Ed25519YaoLaneSourcePreparationPortV1;
};

export type CloudflareEd25519LaneProtocolExecutionV1 = {
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly responseJson: string;
};

export class CloudflareEd25519LaneProtocolTransportV1 {
  private readonly internalServiceAuth: string;

  constructor(private readonly options: CloudflareEd25519LaneProtocolTransportOptionsV1) {
    this.internalServiceAuth = requireNonEmpty(
      options.internalServiceAuth,
      'internalServiceAuth',
    );
  }

  async executeProtocolCommitV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
    readonly requestJson: string;
  }): Promise<CloudflareEd25519LaneProtocolExecutionV1> {
    const intentJob = parseClientLaneIntent(input.requestJson);
    assertSameLaneJob(input.job, intentJob);
    const prepared = await this.options.sourcePreparation.prepareSourceV1({ job: input.job });
    const request = {
      job: input.job,
      deriverAInput: requireJsonRecord(prepared.deriverAInput, 'deriverAInput'),
      deriverBInput: requireJsonRecord(prepared.deriverBInput, 'deriverBInput'),
    };
    const response = await postAuthenticatedJsonWithReplayV1({
      binding: this.options.router,
      internalServiceAuth: this.internalServiceAuth,
      path: ROUTER_AB_ED25519_YAO_LANE_EXECUTE_PATH_V1,
      body: {
        binding: requireJsonRecord(prepared.binding, 'binding'),
        request,
      },
    });
    return parseEd25519LaneExecuteResponse(response, input.job);
  }
}

export type CloudflareLaneProtocolCommitterOptionsV1 = {
  readonly gateway: LaneEnrollmentGatewayV1;
  readonly authorization: LaneLifecycleAuthorizationPortV1;
  readonly execution: LaneLifecycleCurveExecutionPortsV1;
  readonly ed25519Transport: CloudflareEd25519LaneProtocolTransportV1;
};

export type CloudflareEd25519LaneProtocolCommitResultV1 = {
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly protocolCasResult: LaneProtocolCasResultV1;
  readonly responseJson: string;
};

/**
 * Runs one private MPC effect, then records its exact receipt through Gateway
 * CAS. A transport retry submits byte-identical input and relies on the
 * operation-scoped worker journal for replay.
 */
export class CloudflareLaneProtocolCommitterV1 {
  constructor(private readonly options: CloudflareLaneProtocolCommitterOptionsV1) {}

  async executeAndRecordEd25519YaoLaneV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
    readonly requestJson: string;
    readonly expectedVersion: number;
  }): Promise<CloudflareEd25519LaneProtocolCommitResultV1> {
    const capture: { value?: CloudflareEd25519LaneProtocolExecutionV1 } = {};
    const execution: LaneLifecycleCurveExecutionPortsV1 = {
      ed25519: {
        ...this.options.execution.ed25519,
        executeProtocolCommitV1: async (request) => {
          if (capture.value) throw new Error('Ed25519 lane protocol effect executed twice');
          const value = await this.options.ed25519Transport.executeProtocolCommitV1(request);
          capture.value = value;
          return value.receipt;
        },
      },
      ecdsa: this.options.execution.ecdsa,
    };
    const service = new LaneLifecycleApplicationService({
      gateway: this.options.gateway,
      authorization: this.options.authorization,
      execution,
    });
    const protocolCasResult = await service.recordLaneProtocolCommitV1({
      curve: 'ed25519_yao',
      job: input.job,
      requestJson: input.requestJson,
      expectedVersion: input.expectedVersion,
    });
    const committed = capture.value;
    if (!committed) throw new Error('Ed25519 lane protocol effect returned no committed result');
    return {
      receipt: committed.receipt,
      protocolCasResult,
      responseJson: committed.responseJson,
    };
  }
}

async function postAuthenticatedJsonWithReplayV1(input: {
  readonly binding: CloudflareLaneServiceBindingV1;
  readonly internalServiceAuth: string;
  readonly path: string;
  readonly body: JsonRecord;
}): Promise<unknown> {
  const body = JSON.stringify(input.body);
  let response: Response;
  try {
    response = await fetchInternal(input, body, false);
  } catch {
    response = await fetchInternal(input, body, true);
  }
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`lane worker ${input.path} returned HTTP ${response.status}`);
  }
  try {
    return text.length === 0 ? null : JSON.parse(text);
  } catch {
    throw new Error(`lane worker ${input.path} returned invalid JSON`);
  }
}

async function fetchInternal(
  input: {
    readonly binding: CloudflareLaneServiceBindingV1;
    readonly internalServiceAuth: string;
    readonly path: string;
  },
  body: string,
  replay: boolean,
): Promise<Response> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    [INTERNAL_SERVICE_AUTH_HEADER]: input.internalServiceAuth,
  };
  if (replay) headers[REPLAY_HEADER] = '1';
  return await input.binding.fetch(
    new Request(`${INTERNAL_ROUTER_ORIGIN}${input.path}`, {
      method: 'POST',
      headers,
      body,
    }),
  );
}

function parseClientLaneIntent(requestJson: string): Ed25519YaoLaneJobV1 {
  let raw: unknown;
  try {
    raw = JSON.parse(requireNonEmpty(requestJson, 'requestJson'));
  } catch {
    throw new Error('requestJson must contain valid JSON');
  }
  const record = exactJsonRecord(
    raw,
    ['kind', 'job'],
    'ed25519YaoLaneClientPrepare',
  );
  if (record.kind !== 'ed25519_yao_lane_client_prepare_v1') {
    throw new Error('ed25519YaoLaneClientPrepare.kind is invalid');
  }
  const job = parseRotatableSigningLaneJobV1(record.job, 'ed25519YaoLaneClientPrepare.job');
  if (job.keyFamily !== 'ed25519') {
    throw new Error('ed25519YaoLaneClientPrepare.job key family is invalid');
  }
  return job;
}

function parseEd25519LaneExecuteResponse(
  raw: unknown,
  job: Ed25519YaoLaneJobV1,
): CloudflareEd25519LaneProtocolExecutionV1 {
  const wrapper = exactJsonRecord(raw, ['result', 'receipt'], 'ed25519LaneExecuteResponse');
  const result = exactJsonRecord(
    wrapper.result,
    [
      'job',
      'transcriptHashB64u',
      'publicIdentityDigestB64u',
      'targetHolderPublicCommitmentB64u',
      'targetServerPublicCommitmentB64u',
      'targetHolderCiphertextDigestSetB64u',
      'targetServerCiphertextDigestSetB64u',
      'holderRecipientKeyDigestB64u',
      'serverRecipientKeyDigestB64u',
      'deriverAHolderPackage',
      'deriverBHolderPackage',
      'deriverASigningWorkerPackage',
      'deriverBSigningWorkerPackage',
      'committedAtMs',
    ],
    'ed25519LaneExecuteResponse.result',
  );
  const resultJob = parseRotatableSigningLaneJobV1(
    result.job,
    'ed25519LaneExecuteResponse.result.job',
  );
  if (resultJob.keyFamily !== 'ed25519') {
    throw new Error('ed25519LaneExecuteResponse.result.job key family is invalid');
  }
  assertSameLaneJob(job, resultJob);
  for (const packageField of [
    'deriverAHolderPackage',
    'deriverBHolderPackage',
    'deriverASigningWorkerPackage',
    'deriverBSigningWorkerPackage',
  ] as const) {
    requireJsonRecord(result[packageField], `ed25519LaneExecuteResponse.result.${packageField}`);
  }
  const receipt = parseLaneProtocolCommitReceiptV1(
    wrapper.receipt,
    'ed25519LaneExecuteResponse.receipt',
  );
  assertReceiptMatchesJob(receipt, job);
  assertReceiptMatchesResult(receipt, result);
  return { receipt, responseJson: JSON.stringify(result) };
}

function assertReceiptMatchesJob(
  receipt: LaneProtocolCommitReceiptV1,
  job: Ed25519YaoLaneJobV1,
): void {
  if (
    receipt.operationId !== job.operationId ||
    receipt.enrollmentId !== job.enrollmentId ||
    receipt.walletId !== job.walletId ||
    receipt.walletKeyId !== job.walletKeyId ||
    receipt.sourceLaneId !== job.source.laneId ||
    receipt.sourceLaneShareEpoch !== job.source.laneShareEpoch ||
    receipt.sourceRevocationEpoch !== job.source.revocationEpoch ||
    receipt.targetLaneId !== job.target.laneId ||
    receipt.targetLaneShareEpoch !== job.target.laneShareEpoch ||
    receipt.targetMaterialActivationId !== job.targetMaterialActivationId ||
    receipt.keyFamily !== job.keyFamily ||
    JSON.stringify(receipt.sourceMaterialActivation) !==
      JSON.stringify(job.source.materialActivation)
  ) {
    throw new Error('Ed25519 lane protocol receipt does not match the admitted job');
  }
}

function assertReceiptMatchesResult(
  receipt: LaneProtocolCommitReceiptV1,
  result: JsonRecord,
): void {
  if (
    receipt.transcriptHashB64u !== result.transcriptHashB64u ||
    receipt.publicIdentityDigestB64u !== result.publicIdentityDigestB64u ||
    receipt.targetHolderPublicCommitmentB64u !== result.targetHolderPublicCommitmentB64u ||
    receipt.targetServerPublicCommitmentB64u !== result.targetServerPublicCommitmentB64u ||
    receipt.targetHolderCiphertextDigestSetB64u !==
      result.targetHolderCiphertextDigestSetB64u ||
    receipt.targetServerCiphertextDigestSetB64u !==
      result.targetServerCiphertextDigestSetB64u ||
    receipt.holderRecipientKeyDigestB64u !== result.holderRecipientKeyDigestB64u ||
    receipt.serverRecipientKeyDigestB64u !== result.serverRecipientKeyDigestB64u ||
    receipt.committedAtMs !== result.committedAtMs
  ) {
    throw new Error('Ed25519 lane protocol receipt does not match the committed result');
  }
}

function assertSameLaneJob(expected: Ed25519YaoLaneJobV1, actual: Ed25519YaoLaneJobV1): void {
  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    throw new Error('Ed25519 lane request changed the admitted job');
  }
}

function exactJsonRecord(
  raw: unknown,
  fields: readonly string[],
  label: string,
): JsonRecord {
  const record = requireJsonRecord(raw, label);
  const allowed = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is not supported`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) throw new Error(`${label}.${field} is required`);
  }
  return record;
}

function requireJsonRecord(raw: unknown, label: string): JsonRecord {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  return Object.fromEntries(Object.entries(raw));
}

function requireNonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label} is required`);
  }
  return value;
}
