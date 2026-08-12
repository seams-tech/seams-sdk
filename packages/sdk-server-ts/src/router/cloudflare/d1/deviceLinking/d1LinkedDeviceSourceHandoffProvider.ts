import {
  parseLinkedDeviceProvisioningDeliveriesSubmissionV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceTargetReadyR102InputV1,
} from '@shared/device-linking/parsers';
import { linkedDeviceEnrollmentBindingMatchesSourceV1 } from '@shared/device-linking/contracts';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesSubmissionV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetReadyR102InputV1,
} from '@shared/device-linking/contracts';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking/digests';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { DeviceLinkingOwnerSourceHandoffProviderV1 } from '../../../transport/fetch/routes/deviceLinking';
import type { LinkedDeviceR102SourcePreparationPortV1 } from './linkedDeviceR102ProvisioningExecution';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

const SOURCE_HANDOFF_TABLE = 'linked_device_source_handoffs';

type SourceHandoffRowV1 = {
  readonly enrollment_id?: unknown;
  readonly wallet_id?: unknown;
  readonly device_id?: unknown;
  readonly target_ready_json?: unknown;
  readonly target_ready_digest_b64u?: unknown;
  readonly manifest_digest_b64u?: unknown;
  readonly deliveries_json?: unknown;
  readonly deliveries_digest_b64u?: unknown;
};

type PersistedSourceHandoffV1 = {
  readonly enrollmentId: string;
  readonly walletId: string;
  readonly deviceId: string;
  readonly targetReadyDigestB64u: DigestB64u;
  readonly manifestDigestB64u: DigestB64u;
  readonly targetReady: LinkedDeviceTargetReadyR102InputV1;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1 | null;
  readonly deliveriesDigestB64u: DigestB64u | null;
};

type RegisteredTargetCredentialV1 = {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly keyManifestDigestB64u: DigestB64u;
};

type SourceHandoffValidationModeV1 = 'fresh' | 'durable_replay';

/**
 * Durable owner source handoff and Device 2 R102 preparation source. The
 * trusted target committer calls persistTargetReadyV1; public callers only
 * receive the owner-authenticated target-ready GET and submit deliveries.
 */
export class D1LinkedDeviceSourceHandoffProviderV1
  implements DeviceLinkingOwnerSourceHandoffProviderV1, LinkedDeviceR102SourcePreparationPortV1
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(input.scope);
  }

  async getTargetReadyV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetReadyR102InputV1 | null> {
    const persisted = await this.readV1(input.session.linkSessionId);
    if (!persisted) return null;
    assertPersistedIdentity(
      persisted,
      input.session,
      input.approval,
      input.requestedAtMs,
      'durable_replay',
    );
    return persisted.targetReady;
  }

  /** Persist the exact manifest/jobs produced by the trusted target committer. */
  async persistTargetReadyV1(input: {
    readonly targetReady: LinkedDeviceTargetReadyR102InputV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetReadyR102InputV1> {
    const targetReady = parseLinkedDeviceTargetReadyR102InputV1(input.targetReady);
    assertTargetReadyIdentity(
      targetReady,
      input.session,
      input.approval,
      input.requestedAtMs,
      'fresh',
    );
    const targetRegistration = await this.readRegisteredTargetCredentialV1(
      input.session.linkSessionId,
    );
    if (!targetRegistration) {
      throw new Error('linked-device target credential registration is missing');
    }
    assertTargetHolderRegistrationBindings(
      targetReady,
      targetRegistration,
      input.session,
      input.approval,
      input.requestedAtMs,
    );
    const targetReadyDigestB64u = await targetReadyDigestV1(targetReady);
    const manifestDigestB64u = parseDigestB64u(
      await computeLaneEnrollmentManifestDigestV1(targetReady.manifest),
    );
    if (targetRegistration.keyManifestDigestB64u !== manifestDigestB64u) {
      throw new Error('R102 target-ready manifest differs from registered credential manifest');
    }
    assertManifestDigestMatchesSession(manifestDigestB64u, input.session);
    const persisted = await this.readV1(input.session.linkSessionId);
    if (persisted) {
      assertPersistedIdentity(
        persisted,
        input.session,
        input.approval,
        input.requestedAtMs,
        'durable_replay',
      );
      if (
        persisted.targetReadyDigestB64u !== targetReadyDigestB64u ||
        alphabetizeStringify(persisted.targetReady) !== alphabetizeStringify(targetReady)
      ) {
        throw new Error('linked-device target-ready input conflicts with durable replay');
      }
      if (persisted.manifestDigestB64u !== manifestDigestB64u) {
        throw new Error('linked-device target-ready manifest digest changed');
      }
      return persisted.targetReady;
    }
    await this.database
      .prepare(
        `INSERT OR IGNORE INTO ${SOURCE_HANDOFF_TABLE} (
           namespace, org_id, project_id, env_id, link_session_id,
           enrollment_id, wallet_id, device_id, target_ready_json,
           target_ready_digest_b64u, manifest_digest_b64u,
           deliveries_json, deliveries_digest_b64u, created_at_ms, updated_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(input.session.linkSessionId),
        String(input.approval.enrollmentId),
        String(input.approval.walletId),
        String(input.approval.deviceId),
        JSON.stringify(targetReady),
        targetReadyDigestB64u,
        manifestDigestB64u,
        input.requestedAtMs,
        input.requestedAtMs,
      )
      .run();
    const stored = await this.readV1(input.session.linkSessionId);
    if (!stored) throw new Error('linked-device target-ready input did not persist');
    assertPersistedIdentity(
      stored,
      input.session,
      input.approval,
      input.requestedAtMs,
      'durable_replay',
    );
    if (
      stored.targetReadyDigestB64u !== targetReadyDigestB64u ||
      alphabetizeStringify(stored.targetReady) !== alphabetizeStringify(targetReady)
    ) {
      throw new Error('linked-device target-ready input conflicts with durable replay');
    }
    return stored.targetReady;
  }

  async submitPreparedProvisioningDeliveriesV1(input: {
    readonly submission: LinkedDeviceProvisioningDeliveriesSubmissionV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesSubmissionV1> {
    const submission = parseLinkedDeviceProvisioningDeliveriesSubmissionV1(input.submission);
    assertSubmissionIdentity(submission, input.session, input.approval);
    const persisted = await this.readV1(input.session.linkSessionId);
    if (!persisted) throw new Error('linked-device target-ready input is missing');
    assertPersistedIdentity(
      persisted,
      input.session,
      input.approval,
      input.requestedAtMs,
      persisted.deliveries ? 'durable_replay' : 'fresh',
    );
    if (submission.manifestDigestB64u !== persisted.manifestDigestB64u) {
      throw new Error('prepared deliveries manifest digest differs from target-ready input');
    }
    assertDeliveriesMatchTargetReady(submission.deliveries, persisted.targetReady);
    const deliveriesDigestB64u = await deliveriesDigestV1(submission.deliveries);
    if (persisted.deliveries) {
      if (
        persisted.deliveriesDigestB64u !== deliveriesDigestB64u ||
        alphabetizeStringify(persisted.deliveries) !== alphabetizeStringify(submission.deliveries)
      ) {
        throw new Error('prepared deliveries conflict with durable replay');
      }
      return submissionWithDeliveries(persisted, input.approval);
    }
    await this.database
      .prepare(
        `UPDATE ${SOURCE_HANDOFF_TABLE}
            SET deliveries_json = ?, deliveries_digest_b64u = ?, updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND deliveries_json IS NULL
            AND target_ready_digest_b64u = ? AND manifest_digest_b64u = ?`,
      )
      .bind(
        JSON.stringify(submission.deliveries),
        deliveriesDigestB64u,
        input.requestedAtMs,
        ...scopeValues(this.scope),
        String(input.session.linkSessionId),
        persisted.targetReadyDigestB64u,
        persisted.manifestDigestB64u,
      )
      .run();
    const stored = await this.readV1(input.session.linkSessionId);
    if (!stored?.deliveries) throw new Error('linked-device prepared deliveries did not persist');
    assertPersistedIdentity(
      stored,
      input.session,
      input.approval,
      input.requestedAtMs,
      'durable_replay',
    );
    if (
      stored.deliveriesDigestB64u !== deliveriesDigestB64u ||
      alphabetizeStringify(stored.deliveries) !== alphabetizeStringify(submission.deliveries)
    ) {
      throw new Error('prepared deliveries conflict with durable replay');
    }
    return submissionWithDeliveries(stored, input.approval);
  }

  async prepareProvisioningDeliveriesV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1> {
    const persisted = await this.readV1(input.session.linkSessionId);
    if (!persisted?.deliveries) {
      throw new Error('linked-device prepared deliveries are missing');
    }
    assertPersistedIdentity(
      persisted,
      input.session,
      input.approval,
      input.requestedAtMs,
      'durable_replay',
    );
    if (
      input.command.linkSessionId !== input.session.linkSessionId ||
      input.command.enrollmentId !== input.approval.enrollmentId ||
      input.command.deviceId !== input.approval.deviceId
    ) {
      throw new Error('linked-device provisioning command differs from source handoff');
    }
    return persisted.deliveries;
  }

  private async readV1(linkSessionId: string): Promise<PersistedSourceHandoffV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT enrollment_id, wallet_id, device_id, target_ready_json,
                target_ready_digest_b64u, manifest_digest_b64u,
                deliveries_json, deliveries_digest_b64u
           FROM ${SOURCE_HANDOFF_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), linkSessionId)
      .first<SourceHandoffRowV1>();
    if (!row) return null;
    const targetReady = parseLinkedDeviceTargetReadyR102InputV1(
      JSON.parse(requiredString(row.target_ready_json, 'target_ready_json')),
    );
    const deliveries =
      row.deliveries_json === null || row.deliveries_json === undefined
        ? null
        : parseLinkedDeviceProvisioningDeliveriesV1(
            JSON.parse(requiredString(row.deliveries_json, 'deliveries_json')),
          );
    const deliveriesDigestB64u =
      row.deliveries_digest_b64u === null || row.deliveries_digest_b64u === undefined
        ? null
        : parseDigestB64u(row.deliveries_digest_b64u);
    if (!deliveries && deliveriesDigestB64u) {
      throw new Error('linked-device source handoff has a dangling delivery digest');
    }
    const targetReadyDigestB64u = parseDigestB64u(row.target_ready_digest_b64u);
    const manifestDigestB64u = parseDigestB64u(row.manifest_digest_b64u);
    if ((await targetReadyDigestV1(targetReady)) !== targetReadyDigestB64u) {
      throw new Error('linked-device target-ready digest does not match its JSON');
    }
    if (
      parseDigestB64u(await computeLaneEnrollmentManifestDigestV1(targetReady.manifest)) !==
      manifestDigestB64u
    ) {
      throw new Error('linked-device source handoff manifest digest does not match its JSON');
    }
    if (
      deliveries &&
      (!deliveriesDigestB64u || (await deliveriesDigestV1(deliveries)) !== deliveriesDigestB64u)
    ) {
      throw new Error('linked-device prepared deliveries digest does not match its JSON');
    }
    return {
      enrollmentId: requiredString(row.enrollment_id, 'enrollment_id'),
      walletId: requiredString(row.wallet_id, 'wallet_id'),
      deviceId: requiredString(row.device_id, 'device_id'),
      targetReadyDigestB64u,
      manifestDigestB64u,
      targetReady,
      deliveries,
      deliveriesDigestB64u,
    };
  }

  private async readRegisteredTargetCredentialV1(
    linkSessionId: string,
  ): Promise<RegisteredTargetCredentialV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT state, enrollment_id, wallet_id, device_id,
                preparation_digest_b64u, preparation_json,
                registration_json, key_manifest_digest_b64u
           FROM linked_device_target_credentials
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), linkSessionId)
      .first<{
        readonly state?: unknown;
        readonly enrollment_id?: unknown;
        readonly wallet_id?: unknown;
        readonly device_id?: unknown;
        readonly preparation_digest_b64u?: unknown;
        readonly preparation_json?: unknown;
        readonly registration_json?: unknown;
        readonly key_manifest_digest_b64u?: unknown;
      }>();
    if (!row) return null;
    if (
      row.state !== 'registered' ||
      typeof row.preparation_json !== 'string' ||
      typeof row.registration_json !== 'string'
    ) {
      return null;
    }
    const preparation = parseLinkedDeviceTargetPreparationV1(JSON.parse(row.preparation_json));
    const registration = parseLinkedDeviceTargetCredentialRegistrationV1(
      JSON.parse(row.registration_json),
    );
    const preparationDigestB64u = parseDigestB64u(row.preparation_digest_b64u);
    const computedPreparationDigestB64u = parseDigestB64u(
      await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    );
    if (
      preparationDigestB64u !== computedPreparationDigestB64u ||
      registration.targetPreparationDigestB64u !== preparationDigestB64u ||
      registration.linkSessionId !== preparation.linkSessionId ||
      registration.walletId !== preparation.walletId ||
      registration.enrollmentId !== preparation.enrollmentId ||
      registration.deviceId !== preparation.deviceId ||
      String(row.enrollment_id) !== String(registration.enrollmentId) ||
      String(row.wallet_id) !== String(registration.walletId) ||
      String(row.device_id) !== String(registration.deviceId)
    ) {
      throw new Error('linked-device target credential records differ from their durable bindings');
    }
    return {
      preparation,
      registration,
      keyManifestDigestB64u: parseDigestB64u(row.key_manifest_digest_b64u),
    };
  }
}

function assertPersistedIdentity(
  persisted: PersistedSourceHandoffV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
  mode: SourceHandoffValidationModeV1,
): void {
  if (
    persisted.enrollmentId !== String(approval.enrollmentId) ||
    persisted.walletId !== String(approval.walletId) ||
    persisted.deviceId !== String(approval.deviceId)
  ) {
    throw new Error('linked-device source handoff replay identity changed');
  }
  assertTargetReadyIdentity(persisted.targetReady, session, approval, requestedAtMs, mode);
  if (persisted.deliveries) {
    assertDeliveriesMatchTargetReady(persisted.deliveries, persisted.targetReady);
  }
  if (
    (session.state.state === 'provisioning' ||
      session.state.state === 'awaiting_aggregate_receipt') &&
    persisted.manifestDigestB64u !== session.state.keyManifestDigestB64u
  ) {
    throw new Error('linked-device source handoff manifest digest changed');
  }
  if (
    session.state.state === 'active' &&
    (!session.aggregateReceipt ||
      persisted.manifestDigestB64u !== session.aggregateReceipt.manifestDigestB64u)
  ) {
    throw new Error('linked-device active session manifest digest changed');
  }
}

function assertTargetReadyIdentity(
  targetReady: LinkedDeviceTargetReadyR102InputV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
  mode: SourceHandoffValidationModeV1,
): void {
  const authorization = targetReady.manifest.authorization;
  const allowExpiredReplay =
    mode === 'durable_replay' &&
    (session.state.state === 'committed_completion_required' || session.state.state === 'active');
  if (
    targetReady.linkSessionId !== session.linkSessionId ||
    targetReady.linkSessionId !== approval.linkSessionId ||
    targetReady.walletId !== approval.walletId ||
    targetReady.enrollmentId !== approval.enrollmentId ||
    targetReady.deviceId !== approval.deviceId ||
    targetReady.manifest.walletId !== approval.walletId ||
    String(targetReady.manifest.enrollmentId) !== String(approval.enrollmentId) ||
    authorization.kind !== 'linked_device_enrollment' ||
    targetReady.manifest.orderedChildren.length !== approval.orderedKeyBindings.length ||
    targetReady.children.length !== approval.orderedKeyBindings.length ||
    targetReady.manifest.expiresAtMs > approval.expiresAtMs ||
    (!allowExpiredReplay && targetReady.manifest.expiresAtMs <= requestedAtMs) ||
    session.claimTranscript?.value.deviceId !== targetReady.deviceId
  ) {
    throw new Error('R102 target-ready input does not match approved session');
  }
  if (
    authorization.linkedDeviceEnrollmentId !== approval.enrollmentId ||
    authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u ||
    String(authorization.authorizedOperationId) !== String(approval.operationId)
  ) {
    throw new Error('R102 target-ready authorization differs from approval');
  }
  for (let index = 0; index < targetReady.children.length; index += 1) {
    const job = targetReady.children[index];
    const manifestChild = targetReady.manifest.orderedChildren[index];
    const approvedChild = approval.orderedKeyBindings[index];
    const approvedProtocol = approval.protocolVersions.find(
      (entry) => entry.keyFamily === approvedChild?.keyFamily,
    );
    if (!job || !manifestChild || !approvedChild || !approvedProtocol) {
      throw new Error('R102 target-ready child coverage is incomplete');
    }
    if (
      job.operationId !== manifestChild.operationId ||
      job.walletKeyId !== approvedChild.walletKeyId ||
      job.keyFamily !== approvedChild.keyFamily ||
      job.source.laneId !== approvedChild.sourceLaneId ||
      job.source.laneShareEpoch !== approvedChild.sourceLaneShareEpoch ||
      job.source.revocationEpoch !== approvedChild.sourceRevocationEpoch ||
      !linkedDeviceEnrollmentBindingMatchesSourceV1(approvedChild, job.source) ||
      job.target.operation !== 'create_lane' ||
      job.target.laneKind !== 'linked_device' ||
      job.target.laneId !== approvedChild.targetLaneId ||
      job.target.laneShareEpoch !== approvedChild.targetLaneShareEpoch ||
      job.expiresAtMs > approval.expiresAtMs ||
      (!allowExpiredReplay && job.expiresAtMs <= requestedAtMs) ||
      job.protocolVersion !== approvedProtocol.version ||
      job.authorization.kind !== 'linked_device_enrollment' ||
      job.authorization.authorizedOperationId !== authorization.authorizedOperationId ||
      job.authorization.linkedDeviceEnrollmentId !== approval.enrollmentId ||
      job.authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u
    ) {
      throw new Error('R102 target-ready job differs from approved manifest');
    }
  }
}

function assertSubmissionIdentity(
  submission: LinkedDeviceProvisioningDeliveriesSubmissionV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    submission.linkSessionId !== session.linkSessionId ||
    submission.linkSessionId !== approval.linkSessionId ||
    submission.walletId !== approval.walletId ||
    submission.enrollmentId !== approval.enrollmentId ||
    submission.deviceId !== approval.deviceId
  ) {
    throw new Error('prepared deliveries identity does not match approved session');
  }
}

function assertTargetHolderRegistrationBindings(
  targetReady: LinkedDeviceTargetReadyR102InputV1,
  registered: RegisteredTargetCredentialV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
): void {
  const { preparation, registration } = registered;
  if (
    registration.linkSessionId !== targetReady.linkSessionId ||
    registration.walletId !== targetReady.walletId ||
    registration.enrollmentId !== targetReady.enrollmentId ||
    registration.deviceId !== targetReady.deviceId ||
    registration.linkSessionId !== session.linkSessionId ||
    registration.linkSessionId !== approval.linkSessionId ||
    registration.walletId !== approval.walletId ||
    registration.enrollmentId !== approval.enrollmentId ||
    registration.deviceId !== approval.deviceId ||
    preparation.linkSessionId !== targetReady.linkSessionId ||
    preparation.walletId !== targetReady.walletId ||
    preparation.enrollmentId !== targetReady.enrollmentId ||
    preparation.deviceId !== targetReady.deviceId ||
    preparation.expiresAtMs > approval.expiresAtMs ||
    preparation.expiresAtMs <= requestedAtMs ||
    registration.registeredAtMs > requestedAtMs ||
    preparation.orderedChildren.length !== targetReady.children.length
  ) {
    throw new Error('R102 target-ready credential records differ from approved session');
  }
  if (registration.orderedHolderRegistrations.length !== targetReady.children.length) {
    throw new Error('R102 target-ready holder coverage differs from registered credential');
  }
  for (let index = 0; index < targetReady.children.length; index += 1) {
    const job = targetReady.children[index];
    const holder = registration.orderedHolderRegistrations[index];
    const prepared = preparation.orderedChildren[index];
    if (!job || !holder || !prepared)
      throw new Error('R102 target-ready holder order is incomplete');
    const record = holder.holderParticipant;
    if (
      job.operationId !== holder.operationId ||
      job.walletKeyId !== holder.walletKeyId ||
      job.keyFamily !== holder.keyFamily ||
      job.target.laneId !== holder.targetLaneId ||
      job.target.laneShareEpoch !== holder.targetLaneShareEpoch ||
      job.targetMaterialActivationId !== holder.targetMaterialActivationId ||
      prepared.operationId !== job.operationId ||
      prepared.walletKeyId !== job.walletKeyId ||
      prepared.keyFamily !== job.keyFamily ||
      prepared.targetLaneId !== job.target.laneId ||
      prepared.targetLaneShareEpoch !== job.target.laneShareEpoch ||
      prepared.targetMaterialActivationId !== job.targetMaterialActivationId ||
      prepared.targetHolderParticipantId !== job.targetHolder.participantId ||
      job.targetHolder.participantId !== record.participantId ||
      job.targetHolder.custodyBindingId !== record.custodyBindingId ||
      job.targetHolder.custodyBindingDigestB64u !== record.custodyBindingDigestB64u ||
      job.targetHolder.hpkePublicKeyB64u !== record.hpkePublicKeyB64u ||
      job.targetHolder.hpkePublicKeyDigestB64u !== record.hpkePublicKeyDigestB64u ||
      job.targetHolder.participantBindingDigestB64u !== record.participantBindingDigestB64u
    ) {
      throw new Error('R102 target-ready job differs from registered holder participant');
    }
  }
}

function assertManifestDigestMatchesSession(
  manifestDigestB64u: DigestB64u,
  session: LinkedDeviceSessionRecordV1,
): void {
  if (
    (session.state.state === 'provisioning' ||
      session.state.state === 'awaiting_aggregate_receipt') &&
    session.state.keyManifestDigestB64u !== manifestDigestB64u
  ) {
    throw new Error('R102 target-ready manifest differs from the persisted session manifest');
  }
  if (
    session.state.state === 'active' &&
    (!session.aggregateReceipt ||
      session.aggregateReceipt.manifestDigestB64u !== manifestDigestB64u)
  ) {
    throw new Error('R102 target-ready manifest differs from the active aggregate receipt');
  }
}

function assertDeliveriesMatchTargetReady(
  deliveries: LinkedDeviceProvisioningDeliveriesV1,
  targetReady: LinkedDeviceTargetReadyR102InputV1,
): void {
  if (
    deliveries.linkSessionId !== targetReady.linkSessionId ||
    deliveries.enrollmentId !== targetReady.enrollmentId ||
    deliveries.deviceId !== targetReady.deviceId ||
    deliveries.orderedChildren.length !== targetReady.children.length
  ) {
    throw new Error('prepared deliveries coverage differs from target-ready input');
  }
  for (let index = 0; index < deliveries.orderedChildren.length; index += 1) {
    const delivery = deliveries.orderedChildren[index];
    const job = targetReady.children[index];
    if (!delivery || !job || alphabetizeStringify(delivery.job) !== alphabetizeStringify(job)) {
      throw new Error(`prepared delivery child ${index} differs from target-ready job`);
    }
  }
}

function submissionWithDeliveries(
  persisted: PersistedSourceHandoffV1,
  approval: LinkedDeviceApprovalV1,
): LinkedDeviceProvisioningDeliveriesSubmissionV1 {
  if (!persisted.deliveries) throw new Error('linked-device prepared deliveries are missing');
  return {
    kind: 'linked_device_provisioning_deliveries_submission_v1',
    linkSessionId: persisted.targetReady.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    manifestDigestB64u: persisted.manifestDigestB64u,
    deliveries: persisted.deliveries,
  };
}

async function targetReadyDigestV1(
  targetReady: LinkedDeviceTargetReadyR102InputV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(targetReady))));
}

async function deliveriesDigestV1(
  deliveries: LinkedDeviceProvisioningDeliveriesV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(deliveries))));
}

function scopeValues(
  scope: D1LinkedDeviceSessionScopeV1,
): readonly [string, string, string, string] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  const values = [scope.namespace, scope.orgId, scope.projectId, scope.envId];
  if (values.some((value) => typeof value !== 'string' || !value.trim())) {
    throw new Error('linked-device source handoff scope is invalid');
  }
  return {
    namespace: scope.namespace,
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
  };
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}
