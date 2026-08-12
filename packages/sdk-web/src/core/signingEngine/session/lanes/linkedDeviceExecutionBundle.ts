import {
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceEnrollmentReceiptV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceWalletSessionDeliveryV1,
} from '@shared/device-linking';
import { linkedDeviceEnrollmentBindingMatchesSourceV1 } from '@shared/device-linking/contracts';
import { assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1 } from '@shared/device-linking/digests';
import {
  buildActiveSigningLaneLifecycle,
  buildActiveWalletKeyLifecycle,
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildLinkedDeviceSigningLaneRecord,
  parseWalletKeyVersion,
} from '@shared/signing-lanes/recordParsers';
import type {
  Ed25519WalletKeyRecord,
  EvmFamilyWalletKeyRecord,
  LinkedDeviceSigningLaneRecord,
} from '@shared/signing-lanes/records';
import {
  parseLaneHolderParticipantRecordV1,
  parseSigningWorkerParticipantRecordV1,
} from '@shared/signing-lanes/participants';
import { computeLaneParticipantSetBindingDigestV1 } from '@shared/signing-lanes/participantDigest';
import type {
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneEnrollmentManifestV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneEnrollmentManifestV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  computeLaneEnrollmentManifestDigestV1,
  computeLaneProtocolCommitReceiptDigestV1,
} from '@shared/signing-lanes/rotationDigests';
import {
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';

type ActiveLinkedDeviceExecutionChildCommonV1 = {
  readonly operationId: Ed25519YaoLaneJobV1['operationId'];
  readonly walletKeyId: Ed25519YaoLaneJobV1['walletKeyId'];
  readonly laneId: Ed25519YaoLaneJobV1['target']['laneId'];
  readonly laneShareEpoch: Ed25519YaoLaneJobV1['target']['laneShareEpoch'];
  readonly materialActivation: MpcMaterialActivationRef;
  readonly lane: LinkedDeviceSigningLaneRecord;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly protocolCommitReceiptDigestB64u: DigestB64u;
  readonly publicIdentityDigestB64u: DigestB64u;
  readonly serverActivationReceiptDigestB64u: DigestB64u;
  readonly holderRecordLookup: {
    readonly operationId: Ed25519YaoLaneJobV1['operationId'];
    readonly enrollmentId: Ed25519YaoLaneJobV1['enrollmentId'];
    readonly targetLaneId: Ed25519YaoLaneJobV1['target']['laneId'];
    readonly targetLaneShareEpoch: Ed25519YaoLaneJobV1['target']['laneShareEpoch'];
    readonly targetMaterialActivationId: Ed25519YaoLaneJobV1['targetMaterialActivationId'];
  };
};

export type ActiveLinkedDeviceExecutionChildV1 =
  | (ActiveLinkedDeviceExecutionChildCommonV1 & {
      readonly kind: 'active_linked_device_ed25519_execution_v1';
      readonly keyFamily: 'ed25519';
      readonly walletKey: Ed25519WalletKeyRecord;
      readonly job: Ed25519YaoLaneJobV1;
    })
  | (ActiveLinkedDeviceExecutionChildCommonV1 & {
      readonly kind: 'active_linked_device_ecdsa_execution_v1';
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly walletKey: EvmFamilyWalletKeyRecord;
      readonly job: EcdsaAdditiveLaneJobV1;
    });

export type ActiveLinkedDeviceExecutionBundleV1 = {
  readonly kind: 'active_linked_device_execution_bundle_v1';
  readonly linkSessionId: ReturnType<typeof parseLinkedDeviceApprovalV1>['linkSessionId'];
  readonly tenantId: ReturnType<typeof parseLinkedDeviceWalletSessionDeliveryV1>['tenantId'];
  readonly walletId: ReturnType<typeof parseLinkedDeviceApprovalV1>['walletId'];
  readonly enrollmentId: ReturnType<typeof parseLinkedDeviceApprovalV1>['enrollmentId'];
  readonly deviceId: ReturnType<typeof parseLinkedDeviceApprovalV1>['deviceId'];
  readonly targetPreparation: ReturnType<typeof parseLinkedDeviceTargetPreparationV1>;
  readonly targetCredentialRegistration: ReturnType<
    typeof parseLinkedDeviceTargetCredentialRegistrationV1
  >;
  readonly manifest: ReturnType<typeof parseLinkedDeviceProvisioningDeliveriesV1>['manifest'];
  readonly authorizationId: ReturnType<
    typeof parseLinkedDeviceWalletSessionDeliveryV1
  >['authorizationId'];
  readonly walletSessionId: ReturnType<
    typeof parseLinkedDeviceWalletSessionDeliveryV1
  >['walletSessionId'];
  readonly quotaId: ReturnType<typeof parseLinkedDeviceWalletSessionDeliveryV1>['quotaId'];
  readonly keyManifestDigestB64u: DigestB64u;
  readonly aggregateReceiptDigestB64u: DigestB64u;
  readonly permission: ReturnType<typeof parseLinkedDeviceApprovalV1>['permission'];
  readonly revocationEpoch: number;
  readonly activatedAtMs: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly orderedExecutions: readonly [
    ActiveLinkedDeviceExecutionChildV1,
    ...ActiveLinkedDeviceExecutionChildV1[],
  ];
};

export type LinkedDeviceProvisionedExecutionEvidenceV1 = {
  readonly kind: 'linked_device_provisioned_execution_evidence_v1';
  readonly approval: ReturnType<typeof parseLinkedDeviceApprovalV1>;
  readonly targetPreparation: ReturnType<typeof parseLinkedDeviceTargetPreparationV1>;
  readonly targetCredentialRegistration: ReturnType<
    typeof parseLinkedDeviceTargetCredentialRegistrationV1
  >;
  readonly provisioning: LinkedDeviceProvisionedExecutionPublicR102V1;
  readonly enrollmentReceipt: ReturnType<typeof parseLinkedDeviceEnrollmentReceiptV1>;
};

export type LinkedDeviceProvisionedExecutionChildEvidenceV1 = {
  readonly kind: 'linked_device_provisioned_execution_child_evidence_v1';
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
};

export type LinkedDeviceProvisionedExecutionPublicR102V1 = {
  readonly kind: 'linked_device_provisioned_execution_public_r102_v1';
  readonly manifest: LaneEnrollmentManifestV1;
  readonly orderedChildren: readonly [
    LinkedDeviceProvisionedExecutionChildEvidenceV1,
    ...LinkedDeviceProvisionedExecutionChildEvidenceV1[],
  ];
};

const EVIDENCE_FIELDS = [
  'kind',
  'approval',
  'targetPreparation',
  'targetCredentialRegistration',
  'provisioning',
  'enrollmentReceipt',
] as const;
const PUBLIC_PROVISIONING_FIELDS = ['kind', 'manifest', 'orderedChildren'] as const;
const PUBLIC_CHILD_FIELDS = ['kind', 'job', 'protocolCommitReceipt'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactRecord(
  raw: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isRecord(raw)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(raw);
  if (actual.length !== fields.length || actual.some((field) => !fields.includes(field))) {
    throw new Error(`${label} fields are invalid`);
  }
  return raw;
}

function publicProvisioningChild(
  child: ReturnType<typeof parseLinkedDeviceProvisioningDeliveriesV1>['orderedChildren'][number],
): LinkedDeviceProvisionedExecutionChildEvidenceV1 {
  return {
    kind: 'linked_device_provisioned_execution_child_evidence_v1',
    job: child.job,
    protocolCommitReceipt: child.protocolCommitReceipt,
  };
}

function parsePublicProvisioning(raw: unknown): LinkedDeviceProvisionedExecutionPublicR102V1 {
  const record = exactRecord(
    raw,
    PUBLIC_PROVISIONING_FIELDS,
    'LinkedDeviceProvisionedExecutionPublicR102V1',
  );
  if (record.kind !== 'linked_device_provisioned_execution_public_r102_v1') {
    throw new Error('LinkedDeviceProvisionedExecutionPublicR102V1.kind is invalid');
  }
  if (!Array.isArray(record.orderedChildren) || record.orderedChildren.length === 0) {
    throw new Error('LinkedDeviceProvisionedExecutionPublicR102V1.orderedChildren is empty');
  }
  const children = record.orderedChildren.map(parsePublicProvisioningChild);
  const first = children[0];
  if (!first) throw new Error('LinkedDeviceProvisionedExecutionPublicR102V1 is empty');
  return {
    kind: 'linked_device_provisioned_execution_public_r102_v1',
    manifest: parseLaneEnrollmentManifestV1(
      record.manifest,
      'LinkedDeviceProvisionedExecutionPublicR102V1.manifest',
    ),
    orderedChildren: [first, ...children.slice(1)],
  };
}

function parsePublicProvisioningChild(
  raw: unknown,
  index: number,
): LinkedDeviceProvisionedExecutionChildEvidenceV1 {
  const label = `LinkedDeviceProvisionedExecutionPublicR102V1.orderedChildren[${index}]`;
  const record = exactRecord(raw, PUBLIC_CHILD_FIELDS, label);
  if (record.kind !== 'linked_device_provisioned_execution_child_evidence_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const job = parseRotatableSigningLaneJobV1(record.job, `${label}.job`);
  const protocolCommitReceipt = parseLaneProtocolCommitReceiptV1(
    record.protocolCommitReceipt,
    `${label}.protocolCommitReceipt`,
  );
  assertProtocolReceiptMatchesJob({ job, receipt: protocolCommitReceipt, label });
  return {
    kind: 'linked_device_provisioned_execution_child_evidence_v1',
    job,
    protocolCommitReceipt,
  };
}

function assertProtocolReceiptMatchesJob(input: {
  readonly job: RotatableSigningLaneJobV1;
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly label: string;
}): void {
  const { job, receipt } = input;
  if (
    String(job.operationId) !== String(receipt.operationId) ||
    String(job.enrollmentId) !== String(receipt.enrollmentId) ||
    String(job.walletId) !== String(receipt.walletId) ||
    String(job.walletKeyId) !== String(receipt.walletKeyId) ||
    job.keyFamily !== receipt.keyFamily ||
    String(job.source.laneId) !== String(receipt.sourceLaneId) ||
    String(job.source.laneShareEpoch) !== String(receipt.sourceLaneShareEpoch) ||
    String(job.source.revocationEpoch) !== String(receipt.sourceRevocationEpoch) ||
    alphabetizeStringify(job.source.materialActivation) !==
      alphabetizeStringify(receipt.sourceMaterialActivation) ||
    String(job.target.laneId) !== String(receipt.targetLaneId) ||
    String(job.target.laneShareEpoch) !== String(receipt.targetLaneShareEpoch) ||
    String(job.targetMaterialActivationId) !== String(receipt.targetMaterialActivationId) ||
    job.targetHolder.hpkePublicKeyDigestB64u !== receipt.holderRecipientKeyDigestB64u ||
    job.targetSigningWorker.hpkePublicKeyDigestB64u !== receipt.serverRecipientKeyDigestB64u
  ) {
    throw new Error(`${input.label} protocol receipt does not match its job`);
  }
}

export async function buildLinkedDeviceProvisionedExecutionEvidenceV1(input: {
  readonly approval: unknown;
  readonly targetPreparation: unknown;
  readonly targetCredentialRegistration: unknown;
  readonly provisioningDeliveries: unknown;
  readonly enrollmentReceipt: unknown;
}): Promise<LinkedDeviceProvisionedExecutionEvidenceV1> {
  const approval = parseLinkedDeviceApprovalV1(input.approval);
  const targetPreparation = parseLinkedDeviceTargetPreparationV1(input.targetPreparation);
  const targetCredentialRegistration = parseLinkedDeviceTargetCredentialRegistrationV1(
    input.targetCredentialRegistration,
  );
  const provisioningDeliveries = parseLinkedDeviceProvisioningDeliveriesV1(
    input.provisioningDeliveries,
  );
  const enrollmentReceipt = parseLinkedDeviceEnrollmentReceiptV1(input.enrollmentReceipt);
  const firstDelivery = provisioningDeliveries.orderedChildren[0];
  if (!firstDelivery) throw new Error('linked-device provisioning evidence is empty');
  const provisioning: LinkedDeviceProvisionedExecutionPublicR102V1 = {
    kind: 'linked_device_provisioned_execution_public_r102_v1',
    manifest: provisioningDeliveries.manifest,
    orderedChildren: [
      publicProvisioningChild(firstDelivery),
      ...provisioningDeliveries.orderedChildren.slice(1).map(publicProvisioningChild),
    ],
  };

  await assertProvisionedEvidenceIdentity({
    approval,
    preparation: targetPreparation,
    registration: targetCredentialRegistration,
    provisioning,
    receipt: enrollmentReceipt,
  });

  return {
    kind: 'linked_device_provisioned_execution_evidence_v1',
    approval,
    targetPreparation,
    targetCredentialRegistration,
    provisioning,
    enrollmentReceipt,
  };
}

export async function parseLinkedDeviceProvisionedExecutionEvidenceV1(
  raw: unknown,
): Promise<LinkedDeviceProvisionedExecutionEvidenceV1> {
  const record = exactRecord(raw, EVIDENCE_FIELDS, 'LinkedDeviceProvisionedExecutionEvidenceV1');
  if (record.kind !== 'linked_device_provisioned_execution_evidence_v1') {
    throw new Error('LinkedDeviceProvisionedExecutionEvidenceV1.kind is invalid');
  }
  const evidence: LinkedDeviceProvisionedExecutionEvidenceV1 = {
    kind: 'linked_device_provisioned_execution_evidence_v1',
    approval: parseLinkedDeviceApprovalV1(record.approval),
    targetPreparation: parseLinkedDeviceTargetPreparationV1(record.targetPreparation),
    targetCredentialRegistration: parseLinkedDeviceTargetCredentialRegistrationV1(
      record.targetCredentialRegistration,
    ),
    provisioning: parsePublicProvisioning(record.provisioning),
    enrollmentReceipt: parseLinkedDeviceEnrollmentReceiptV1(record.enrollmentReceipt),
  };
  await assertProvisionedEvidenceIdentity({
    approval: evidence.approval,
    preparation: evidence.targetPreparation,
    registration: evidence.targetCredentialRegistration,
    provisioning: evidence.provisioning,
    receipt: evidence.enrollmentReceipt,
  });
  return evidence;
}

export async function buildActiveLinkedDeviceExecutionBundleV1(input: {
  readonly approval: unknown;
  readonly targetPreparation: unknown;
  readonly targetCredentialRegistration: unknown;
  readonly provisioningDeliveries: unknown;
  readonly enrollmentReceipt: unknown;
  readonly walletSessionDelivery: unknown;
}): Promise<ActiveLinkedDeviceExecutionBundleV1> {
  const evidence = await buildLinkedDeviceProvisionedExecutionEvidenceV1(input);
  return await buildActiveLinkedDeviceExecutionBundleFromEvidenceV1({
    evidence,
    walletSessionDelivery: input.walletSessionDelivery,
  });
}

export async function buildActiveLinkedDeviceExecutionBundleFromEvidenceV1(input: {
  readonly evidence: unknown;
  readonly walletSessionDelivery: unknown;
}): Promise<ActiveLinkedDeviceExecutionBundleV1> {
  const evidence = await parseLinkedDeviceProvisionedExecutionEvidenceV1(input.evidence);
  const approval = evidence.approval;
  const preparation = evidence.targetPreparation;
  const registration = evidence.targetCredentialRegistration;
  const provisioning = evidence.provisioning;
  const receipt = evidence.enrollmentReceipt;
  const walletSession = parseLinkedDeviceWalletSessionDeliveryV1(input.walletSessionDelivery);
  assertWalletSessionIdentity({
    approval,
    receipt,
    walletSession,
  });

  const executions = await Promise.all(
    provisioning.orderedChildren.map(async (deliveryChild, index) => {
      const receiptChild = receipt.orderedChildReceipts[index];
      const token = walletSession.orderedTokens[index];
      if (!receiptChild || !token) {
        throw new Error('linked-device active execution child set is incomplete');
      }
      assertChildIdentity({
        deliveryChild,
        token,
        walletSessionRevocationEpoch: walletSession.revocationEpoch,
      });
      return await buildActiveExecutionChild({
        deviceId: approval.deviceId,
        activatedAtMs: receipt.activatedAtMs,
        aggregateReceiptDigestB64u: receipt.aggregateReceiptDigestB64u,
        deliveryChild,
        receiptChild,
        token,
        revocationEpoch: walletSession.revocationEpoch,
      });
    }),
  );
  const first = executions[0];
  if (!first) throw new Error('linked-device active execution child set is empty');

  return {
    kind: 'active_linked_device_execution_bundle_v1',
    linkSessionId: approval.linkSessionId,
    tenantId: walletSession.tenantId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    targetPreparation: preparation,
    targetCredentialRegistration: registration,
    manifest: provisioning.manifest,
    authorizationId: walletSession.authorizationId,
    walletSessionId: walletSession.walletSessionId,
    quotaId: walletSession.quotaId,
    keyManifestDigestB64u: walletSession.keyManifestDigestB64u,
    aggregateReceiptDigestB64u: receipt.aggregateReceiptDigestB64u,
    permission: walletSession.permission,
    revocationEpoch: walletSession.revocationEpoch,
    activatedAtMs: receipt.activatedAtMs,
    issuedAtMs: walletSession.issuedAtMs,
    expiresAtMs: walletSession.expiresAtMs,
    orderedExecutions: [first, ...executions.slice(1)],
  };
}

async function assertProvisionedEvidenceIdentity(input: {
  readonly approval: ReturnType<typeof parseLinkedDeviceApprovalV1>;
  readonly preparation: ReturnType<typeof parseLinkedDeviceTargetPreparationV1>;
  readonly registration: ReturnType<typeof parseLinkedDeviceTargetCredentialRegistrationV1>;
  readonly provisioning: LinkedDeviceProvisionedExecutionPublicR102V1;
  readonly receipt: ReturnType<typeof parseLinkedDeviceEnrollmentReceiptV1>;
}): Promise<void> {
  const identity = [input.preparation, input.registration, input.receipt];
  if (
    identity.some(
      (value) =>
        value.walletId !== input.approval.walletId ||
        value.enrollmentId !== input.approval.enrollmentId ||
        value.deviceId !== input.approval.deviceId,
    ) ||
    input.preparation.linkSessionId !== input.approval.linkSessionId ||
    input.registration.linkSessionId !== input.approval.linkSessionId ||
    input.provisioning.manifest.walletId !== input.approval.walletId ||
    String(input.provisioning.manifest.enrollmentId) !== String(input.approval.enrollmentId)
  ) {
    throw new Error('linked-device provisioned execution identity does not match');
  }
  await assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1({
    preparation: input.preparation,
    registration: input.registration,
  });
  const manifestDigest = await computeLaneEnrollmentManifestDigestV1(input.provisioning.manifest);
  if (manifestDigest !== input.receipt.manifestDigestB64u) {
    throw new Error('linked-device R102 manifest digest does not match enrollment receipt');
  }
  const counts = [
    input.approval.orderedKeyBindings.length,
    input.preparation.orderedChildren.length,
    input.registration.orderedHolderRegistrations.length,
    input.provisioning.orderedChildren.length,
    input.receipt.orderedChildReceipts.length,
  ];
  if (counts.some((count) => count !== counts[0])) {
    throw new Error('linked-device provisioned execution child counts do not match');
  }
  for (let index = 0; index < input.provisioning.orderedChildren.length; index += 1) {
    const binding = input.approval.orderedKeyBindings[index];
    const preparationChild = input.preparation.orderedChildren[index];
    const registrationChild = input.registration.orderedHolderRegistrations[index];
    const deliveryChild = input.provisioning.orderedChildren[index];
    const receiptChild = input.receipt.orderedChildReceipts[index];
    const protocolVersion = input.approval.protocolVersions.find(
      (candidate) => candidate.keyFamily === deliveryChild?.job.keyFamily,
    );
    if (
      !binding ||
      !preparationChild ||
      !registrationChild ||
      !deliveryChild ||
      !receiptChild ||
      !protocolVersion
    ) {
      throw new Error('linked-device provisioned execution child set is incomplete');
    }
    assertProvisionedChildIdentity({
      approval: input.approval,
      binding,
      preparationChild,
      registrationChild,
      deliveryChild,
      receiptChild,
      protocolVersion,
    });
  }
}

function assertWalletSessionIdentity(input: {
  readonly approval: ReturnType<typeof parseLinkedDeviceApprovalV1>;
  readonly receipt: ReturnType<typeof parseLinkedDeviceEnrollmentReceiptV1>;
  readonly walletSession: ReturnType<typeof parseLinkedDeviceWalletSessionDeliveryV1>;
}): void {
  if (
    input.walletSession.walletId !== input.approval.walletId ||
    input.walletSession.enrollmentId !== input.approval.enrollmentId ||
    input.walletSession.deviceId !== input.approval.deviceId ||
    input.walletSession.keyManifestDigestB64u !== input.receipt.manifestDigestB64u ||
    input.walletSession.issuedAtMs !== input.receipt.activatedAtMs ||
    input.walletSession.orderedTokens.length !== input.approval.orderedKeyBindings.length ||
    alphabetizeStringify(input.walletSession.permission) !==
      alphabetizeStringify(input.approval.permission)
  ) {
    throw new Error('linked-device Wallet Session does not match provisioned execution');
  }
}

function assertProvisionedChildIdentity(input: {
  readonly approval: ReturnType<typeof parseLinkedDeviceApprovalV1>;
  readonly binding: ReturnType<typeof parseLinkedDeviceApprovalV1>['orderedKeyBindings'][number];
  readonly preparationChild: ReturnType<
    typeof parseLinkedDeviceTargetPreparationV1
  >['orderedChildren'][number];
  readonly registrationChild: ReturnType<
    typeof parseLinkedDeviceTargetCredentialRegistrationV1
  >['orderedHolderRegistrations'][number];
  readonly deliveryChild: LinkedDeviceProvisionedExecutionChildEvidenceV1;
  readonly receiptChild: ReturnType<
    typeof parseLinkedDeviceEnrollmentReceiptV1
  >['orderedChildReceipts'][number];
  readonly protocolVersion: ReturnType<
    typeof parseLinkedDeviceApprovalV1
  >['protocolVersions'][number];
}): void {
  const job = input.deliveryChild.job;
  const same =
    job.target.operation === 'create_lane' &&
    job.target.laneKind === 'linked_device' &&
    job.authorization.kind === 'linked_device_enrollment' &&
    String(job.authorization.authorizedOperationId) === String(input.approval.operationId) &&
    String(job.idempotencyKey) === String(input.approval.idempotencyKey) &&
    String(job.authorization.linkedDeviceEnrollmentId) === String(input.approval.enrollmentId) &&
    job.authorization.linkedDevicePermissionDigestB64u === input.approval.policyDigestB64u &&
    job.walletId === input.approval.walletId &&
    String(job.enrollmentId) === String(input.approval.enrollmentId) &&
    job.walletKeyId === input.binding.walletKeyId &&
    job.keyFamily === input.binding.keyFamily &&
    job.keyFamily === input.protocolVersion.keyFamily &&
    job.protocolVersion === input.protocolVersion.version &&
    job.source.laneId === input.binding.sourceLaneId &&
    job.source.laneShareEpoch === input.binding.sourceLaneShareEpoch &&
    job.source.revocationEpoch === input.binding.sourceRevocationEpoch &&
    linkedDeviceEnrollmentBindingMatchesSourceV1(input.binding, job.source) &&
    job.target.laneId === input.binding.targetLaneId &&
    job.target.laneShareEpoch === input.binding.targetLaneShareEpoch &&
    input.preparationChild.operationId === job.operationId &&
    input.preparationChild.walletKeyId === job.walletKeyId &&
    input.preparationChild.keyFamily === job.keyFamily &&
    input.preparationChild.targetLaneId === job.target.laneId &&
    input.preparationChild.targetLaneShareEpoch === job.target.laneShareEpoch &&
    input.preparationChild.targetMaterialActivationId === job.targetMaterialActivationId &&
    input.preparationChild.targetHolderParticipantId === job.targetHolder.participantId &&
    input.registrationChild.operationId === job.operationId &&
    input.registrationChild.walletKeyId === job.walletKeyId &&
    input.registrationChild.keyFamily === job.keyFamily &&
    input.registrationChild.targetLaneId === job.target.laneId &&
    input.registrationChild.targetLaneShareEpoch === job.target.laneShareEpoch &&
    input.registrationChild.targetMaterialActivationId === job.targetMaterialActivationId &&
    alphabetizeStringify(input.registrationChild.holderParticipant) ===
      alphabetizeStringify({ kind: 'lane_holder_participant_v1', ...job.targetHolder }) &&
    input.receiptChild.walletId === job.walletId &&
    input.receiptChild.walletKeyId === job.walletKeyId &&
    input.receiptChild.keyFamily === job.keyFamily &&
    input.receiptChild.targetLaneId === job.target.laneId &&
    input.receiptChild.targetLaneShareEpoch === job.target.laneShareEpoch &&
    input.receiptChild.materialActivation.activationId === job.targetMaterialActivationId &&
    input.receiptChild.materialActivation.capability === job.source.materialActivation.capability &&
    input.receiptChild.materialActivation.materialOwner ===
      job.source.materialActivation.materialOwner &&
    input.receiptChild.materialActivation.keyBinding === job.source.materialActivation.keyBinding &&
    input.receiptChild.materialActivation.lifecycleBinding ===
      job.source.materialActivation.lifecycleBinding &&
    String(input.receiptChild.materialActivation.signingWorker) ===
      String(job.targetSigningWorker.participantId) &&
    input.receiptChild.transcriptHashB64u ===
      input.deliveryChild.protocolCommitReceipt.transcriptHashB64u;
  if (!same) throw new Error('linked-device provisioned execution child identity does not match');
}

function assertChildIdentity(input: {
  readonly deliveryChild: LinkedDeviceProvisionedExecutionChildEvidenceV1;
  readonly token: ReturnType<
    typeof parseLinkedDeviceWalletSessionDeliveryV1
  >['orderedTokens'][number];
  readonly walletSessionRevocationEpoch: number;
}): void {
  const job = input.deliveryChild.job;
  if (
    input.token.walletKeyId !== job.walletKeyId ||
    input.token.keyFamily !== job.keyFamily ||
    input.walletSessionRevocationEpoch !== job.source.revocationEpoch
  ) {
    throw new Error('linked-device active execution authorization does not match child');
  }
}

async function buildActiveExecutionChild(input: {
  readonly deviceId: ReturnType<typeof parseLinkedDeviceApprovalV1>['deviceId'];
  readonly activatedAtMs: number;
  readonly aggregateReceiptDigestB64u: DigestB64u;
  readonly deliveryChild: LinkedDeviceProvisionedExecutionChildEvidenceV1;
  readonly receiptChild: ReturnType<
    typeof parseLinkedDeviceEnrollmentReceiptV1
  >['orderedChildReceipts'][number];
  readonly token: ReturnType<
    typeof parseLinkedDeviceWalletSessionDeliveryV1
  >['orderedTokens'][number];
  readonly revocationEpoch: number;
}): Promise<ActiveLinkedDeviceExecutionChildV1> {
  const job = input.deliveryChild.job;
  const holderParticipant = parseLaneHolderParticipantRecordV1({
    kind: 'lane_holder_participant_v1',
    ...job.targetHolder,
  });
  const serverParticipant = parseSigningWorkerParticipantRecordV1({
    kind: 'signing_worker_participant_v1',
    ...job.targetSigningWorker,
  });
  const participantBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
    holderParticipant,
    signingWorkerParticipant: serverParticipant,
  });
  const lane = buildLinkedDeviceSigningLaneRecord({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    participantBindingDigestB64u,
    holderParticipant,
    serverParticipant,
    lifecycle: buildActiveSigningLaneLifecycle({
      revocationEpoch: input.revocationEpoch,
      activatedAtMs: input.activatedAtMs,
      activationReceiptDigestB64u: input.aggregateReceiptDigestB64u,
    }),
    linkedDeviceId: input.deviceId,
  });
  const common = {
    operationId: job.operationId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    materialActivation: input.receiptChild.materialActivation,
    lane,
    protocolCommitReceipt: input.deliveryChild.protocolCommitReceipt,
    protocolCommitReceiptDigestB64u: await computeLaneProtocolCommitReceiptDigestV1(
      input.deliveryChild.protocolCommitReceipt,
    ),
    publicIdentityDigestB64u: parseDigestB64u(
      input.deliveryChild.protocolCommitReceipt.publicIdentityDigestB64u,
    ),
    serverActivationReceiptDigestB64u: input.receiptChild.receiptDigestB64u,
    holderRecordLookup: {
      operationId: job.operationId,
      enrollmentId: job.enrollmentId,
      targetLaneId: job.target.laneId,
      targetLaneShareEpoch: job.target.laneShareEpoch,
      targetMaterialActivationId: job.targetMaterialActivationId,
    },
  };
  const walletKeyVersion = parseWalletKeyVersion(
    `wallet-key-version:linked-device:${String(job.target.laneShareEpoch)}`,
  );
  if (job.keyFamily === 'ed25519') {
    if (input.token.keyFamily !== 'ed25519') {
      throw new Error('linked-device Ed25519 execution token curve does not match');
    }
    const walletKey = buildEd25519WalletKeyRecord({
      walletId: job.walletId,
      walletKeyId: job.walletKeyId,
      walletKeyVersion,
      nearEd25519SigningKeyId: job.nearEd25519SigningKeyId,
      keyCreationSignerSlot: job.keyCreationSignerSlot,
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(job.registeredPublicKeyB64u),
      lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: input.activatedAtMs }),
    });
    return {
      kind: 'active_linked_device_ed25519_execution_v1',
      keyFamily: 'ed25519',
      walletKey,
      job,
      ...common,
    };
  }
  if (input.token.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked-device ECDSA execution token curve does not match');
  }
  const walletKey = buildEvmFamilyWalletKeyRecord({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    walletKeyVersion,
    evmFamilySigningKeySlotId: job.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(job.thresholdPublicKey33B64u),
    evmAddress: job.evmAddress,
    lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: input.activatedAtMs }),
  });
  return {
    kind: 'active_linked_device_ecdsa_execution_v1',
    keyFamily: 'ecdsa_secp256k1',
    walletKey,
    job,
    ...common,
  };
}
