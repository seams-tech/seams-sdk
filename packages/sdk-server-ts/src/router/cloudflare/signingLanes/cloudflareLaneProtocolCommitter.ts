import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
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
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
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

/**
 * Resolves the public admitted binding for an already-encrypted client lane
 * dispatch. Client-root contributions and Deriver envelopes stay client-side.
 */
export interface Ed25519YaoLaneBindingResolverPortV1 {
  resolveBindingV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
  }): Promise<RouterAbEd25519YaoCeremonyBindingV1>;
}

export type CloudflareEd25519LaneProtocolTransportOptionsV1 = {
  readonly router: CloudflareLaneServiceBindingV1;
  readonly internalServiceAuth: string;
  readonly bindingResolver: Ed25519YaoLaneBindingResolverPortV1;
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
    const request = parseClientLaneDispatch(input.requestJson);
    assertSameLaneJob(input.job, request.job);
    const binding = await this.options.bindingResolver.resolveBindingV1({ job: input.job });
    const response = await postAuthenticatedJsonWithReplayV1({
      binding: this.options.router,
      internalServiceAuth: this.internalServiceAuth,
      path: ROUTER_AB_ED25519_YAO_LANE_EXECUTE_PATH_V1,
      body: {
        binding: requireJsonRecord(binding, 'binding'),
        request: request.wire,
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

export type CloudflareEcdsaLaneProtocolCommitResultV1 = {
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly protocolCasResult: LaneProtocolCasResultV1;
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
    const execution = ed25519ExecutionWithCaptureV1({
      execution: this.options.execution,
      transport: this.options.ed25519Transport,
      capture,
    });
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

  async executeAndRecordEcdsaAdditiveLaneV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly encryptedDeltaPackageJson: string;
    readonly expectedVersion: number;
  }): Promise<CloudflareEcdsaLaneProtocolCommitResultV1> {
    const capture: { value?: LaneProtocolCommitReceiptV1 } = {};
    const execution = ecdsaExecutionWithCaptureV1({
      execution: this.options.execution,
      capture,
    });
    const service = new LaneLifecycleApplicationService({
      gateway: this.options.gateway,
      authorization: this.options.authorization,
      execution,
    });
    const protocolCasResult = await service.recordLaneProtocolCommitV1({
      curve: 'ecdsa_additive',
      job: input.job,
      holderRound: input.holderRound,
      encryptedDeltaPackageJson: input.encryptedDeltaPackageJson,
      expectedVersion: input.expectedVersion,
    });
    const receipt = capture.value;
    if (!receipt) throw new Error('ECDSA lane protocol effect returned no committed receipt');
    return { receipt, protocolCasResult };
  }
}

function ed25519ExecutionWithCaptureV1(input: {
  readonly execution: LaneLifecycleCurveExecutionPortsV1;
  readonly transport: CloudflareEd25519LaneProtocolTransportV1;
  readonly capture: { value?: CloudflareEd25519LaneProtocolExecutionV1 };
}): LaneLifecycleCurveExecutionPortsV1 {
  const ed25519 = input.execution.ed25519;
  return {
    ed25519: {
      async executeProtocolCommitV1(request) {
        if (input.capture.value) throw new Error('Ed25519 lane protocol effect executed twice');
        const value = await input.transport.executeProtocolCommitV1(request);
        input.capture.value = value;
        return value.receipt;
      },
      executeServerActivationV1(request) {
        return ed25519.executeServerActivationV1(request);
      },
      executeServerRetirementV1(request) {
        return ed25519.executeServerRetirementV1(request);
      },
    },
    ecdsa: input.execution.ecdsa,
  };
}

function ecdsaExecutionWithCaptureV1(input: {
  readonly execution: LaneLifecycleCurveExecutionPortsV1;
  readonly capture: { value?: LaneProtocolCommitReceiptV1 };
}): LaneLifecycleCurveExecutionPortsV1 {
  const ecdsa = input.execution.ecdsa;
  return {
    ed25519: input.execution.ed25519,
    ecdsa: {
      async executeProtocolCommitV1(request) {
        if (input.capture.value) throw new Error('ECDSA lane protocol effect executed twice');
        const receipt = parseLaneProtocolCommitReceiptV1(
          await ecdsa.executeProtocolCommitV1(request),
        );
        input.capture.value = receipt;
        return receipt;
      },
      executeServerActivationV1(request) {
        return ecdsa.executeServerActivationV1(request);
      },
      executeServerRetirementV1(request) {
        return ecdsa.executeServerRetirementV1(request);
      },
    },
  };
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

function parseClientLaneDispatch(requestJson: string): {
  readonly job: Ed25519YaoLaneJobV1;
  readonly wire: JsonRecord;
} {
  let raw: unknown;
  try {
    raw = JSON.parse(requireNonEmpty(requestJson, 'requestJson'));
  } catch {
    throw new Error('requestJson must contain valid JSON');
  }
  const record = exactJsonRecord(
    raw,
    ['job', 'deriverAInput', 'deriverBInput'],
    'ed25519YaoLaneClientDispatch',
  );
  const job = parseRotatableSigningLaneJobV1(record.job, 'ed25519YaoLaneClientDispatch.job');
  if (job.keyFamily !== 'ed25519') {
    throw new Error('ed25519YaoLaneClientDispatch.job key family is invalid');
  }
  requireJsonRecord(record.deriverAInput, 'ed25519YaoLaneClientDispatch.deriverAInput');
  requireJsonRecord(record.deriverBInput, 'ed25519YaoLaneClientDispatch.deriverBInput');
  return { job, wire: record };
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
    !mpcMaterialActivationRefsEqual(receipt.sourceMaterialActivation, job.source.materialActivation)
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
  if (!ed25519LaneJobsEqual(expected, actual)) {
    throw new Error('Ed25519 lane request changed the admitted job');
  }
}

function ed25519LaneJobsEqual(
  left: Ed25519YaoLaneJobV1,
  right: Ed25519YaoLaneJobV1,
): boolean {
  return (
    left.kind === right.kind &&
    left.keyFamily === right.keyFamily &&
    left.operationId === right.operationId &&
    left.enrollmentId === right.enrollmentId &&
    left.idempotencyKey === right.idempotencyKey &&
    left.walletId === right.walletId &&
    left.walletKeyId === right.walletKeyId &&
    activeLaneSourcesEqual(left.source, right.source) &&
    targetHoldersEqual(left.targetHolder, right.targetHolder) &&
    targetSigningWorkersEqual(left.targetSigningWorker, right.targetSigningWorker) &&
    left.targetMaterialActivationId === right.targetMaterialActivationId &&
    left.protocolVersion === right.protocolVersion &&
    left.expiresAtMs === right.expiresAtMs &&
    laneTargetsEqual(left.target, right.target) &&
    laneAuthorizationsEqual(left.authorization, right.authorization) &&
    left.yaoRequestKind === right.yaoRequestKind &&
    left.registeredPublicKeyB64u === right.registeredPublicKeyB64u &&
    left.nearEd25519SigningKeyId === right.nearEd25519SigningKeyId &&
    left.keyCreationSignerSlot === right.keyCreationSignerSlot &&
    left.stableContextBindingB64u === right.stableContextBindingB64u &&
    left.yaoSuiteId === right.yaoSuiteId &&
    left.circuitDigestB64u === right.circuitDigestB64u
  );
}

function activeLaneSourcesEqual(
  left: Ed25519YaoLaneJobV1['source'],
  right: Ed25519YaoLaneJobV1['source'],
): boolean {
  return (
    left.laneId === right.laneId &&
    left.laneKind === right.laneKind &&
    left.laneShareEpoch === right.laneShareEpoch &&
    left.revocationEpoch === right.revocationEpoch &&
    left.holderParticipantId === right.holderParticipantId &&
    left.signingWorkerParticipantId === right.signingWorkerParticipantId &&
    left.signingWorkerRecipientKeyId === right.signingWorkerRecipientKeyId &&
    left.participantBindingDigestB64u === right.participantBindingDigestB64u &&
    mpcMaterialActivationRefsEqual(left.materialActivation, right.materialActivation)
  );
}

function targetHoldersEqual(
  left: Ed25519YaoLaneJobV1['targetHolder'],
  right: Ed25519YaoLaneJobV1['targetHolder'],
): boolean {
  return (
    left.participantId === right.participantId &&
    left.participantBindingDigestB64u === right.participantBindingDigestB64u &&
    left.custodyBindingId === right.custodyBindingId &&
    left.custodyBindingDigestB64u === right.custodyBindingDigestB64u &&
    left.hpkePublicKeyB64u === right.hpkePublicKeyB64u &&
    left.hpkePublicKeyDigestB64u === right.hpkePublicKeyDigestB64u
  );
}

function targetSigningWorkersEqual(
  left: Ed25519YaoLaneJobV1['targetSigningWorker'],
  right: Ed25519YaoLaneJobV1['targetSigningWorker'],
): boolean {
  return (
    left.participantId === right.participantId &&
    left.participantBindingDigestB64u === right.participantBindingDigestB64u &&
    left.recipientKeyId === right.recipientKeyId &&
    left.hpkePublicKeyB64u === right.hpkePublicKeyB64u &&
    left.hpkePublicKeyDigestB64u === right.hpkePublicKeyDigestB64u
  );
}

function laneTargetsEqual(
  left: Ed25519YaoLaneJobV1['target'],
  right: Ed25519YaoLaneJobV1['target'],
): boolean {
  if (
    left.operation !== right.operation ||
    left.laneId !== right.laneId ||
    left.laneKind !== right.laneKind ||
    left.laneShareEpoch !== right.laneShareEpoch ||
    left.expectedTargetState !== right.expectedTargetState
  ) {
    return false;
  }
  if (left.operation === 'create_lane') return true;
  if (right.operation !== 'refresh_lane') return false;
  return mpcMaterialActivationRefsEqual(
    left.priorMaterialActivation,
    right.priorMaterialActivation,
  );
}

function laneAuthorizationsEqual(
  left: Ed25519YaoLaneJobV1['authorization'],
  right: Ed25519YaoLaneJobV1['authorization'],
): boolean {
  if (left.kind !== right.kind || left.authorizedOperationId !== right.authorizedOperationId) {
    return false;
  }
  if (left.kind === 'linked_device_enrollment') {
    return (
      right.kind === 'linked_device_enrollment' &&
      left.linkedDeviceEnrollmentId === right.linkedDeviceEnrollmentId &&
      left.linkedDevicePermissionDigestB64u === right.linkedDevicePermissionDigestB64u
    );
  }
  return (
    right.kind === 'owner_lane_refresh' &&
    left.ownerLaneRefreshDigestB64u === right.ownerLaneRefreshDigestB64u
  );
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
