import {
  buildLaneProductEpochPendingVisibilityV1,
  buildLaneProductEpochRevokedV1,
  parseAggregateLaneActivationReceiptV1,
  parseAggregateLaneRevocationReceiptV1,
  parseCompleteSigningLaneRevocationV1,
  parseLaneEnrollmentManifestV1,
  parseLaneProtocolCommitReceiptV1,
  parseLaneHolderDeliveryReceiptV1,
  parseLaneServerActivationReceiptV1,
  parseLaneServerRetirementReceiptV1,
  parseRevokeSigningLaneV1,
  parseLaneProductEpochRecordV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  activateLaneProductEpochV1,
  beginLaneProductEpochRevocationV1,
  completeLaneProductEpochRevocationV1,
  retireLaneProductEpochV1,
  transitionLaneEnrollmentLifecycleV1,
} from '@shared/signing-lanes/rotationLifecycle';
import {
  computeAggregateLaneActivationReceiptDigestV1,
  computeAggregateLaneRevocationReceiptDigestV1,
  computeLaneEnrollmentManifestDigestV1,
  computeRevokeSigningLaneDigestV1,
  encodeLaneHolderDeliveryReceiptV1,
  encodeLaneProtocolCommitReceiptV1,
  encodeLaneServerActivationReceiptV1,
  computeEcdsaServerRetirementReceiptDigestV1,
  computeEd25519ServerRetirementReceiptDigestV1,
} from '@shared/signing-lanes/rotationDigests';
import { computeLaneParticipantSetBindingDigestV1 } from '@shared/signing-lanes/participantDigest';
import { sha256Bytes } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import type {
  AggregateLaneActivationReceiptV1,
  AggregateLaneRevocationReceiptV1,
  CommitLaneEnrollmentActivationV1,
  LaneEnrollmentManifestV1,
  LaneEnrollmentLifecycleV1,
  LaneHolderDeliveryReceiptV1,
  LaneProductEpochRecordV1,
  LaneProtocolCommitReceiptV1,
  LaneProtocolLifecycle,
  LaneProtocolRecordV1,
  LaneProtocolCasResultV1,
  LaneServerActivationReceiptV1,
  LaneServerRetirementReceiptV1,
  RevokeLaneEnrollmentV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import type {
  LaneEnrollmentId,
  LaneOperationId,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';
import type { MpcMaterialActivationRef, WalletId } from '@shared/utils/domainIds';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import type {
  LaneAdmissionMutationResult,
  LaneEnrollmentAdmissionInput,
  LaneEnrollmentAdmissionRecord,
  LaneEnrollmentLifecycleCasInput,
  LaneEnrollmentRevocationCommitInput,
  LaneEnrollmentRevocationCommitResult,
  LaneEnrollmentVisibilityCommitResult,
  LaneLifecycleStore,
  LaneProductEpochLookup,
  LaneActiveProductEpochLookup,
  LaneProtocolAdmissionInput,
  LaneProtocolAdmissionRecord,
  LaneProtocolLifecycleCasInput,
  LaneSigningLaneRevocationCommitInput,
  LaneSigningLaneRevocationFenceMutationResult,
  LaneSigningLaneRevocationMutationResult,
} from '../../../../core/signingLanes/LaneLifecycleStore';
import { d1ChangedRows } from '../../../../storage/d1Sql';
import {
  assertD1Success,
  digestLaneEnrollmentRevocationCommand,
  equalLaneRecords,
  firstBatchResult,
  LANE_CAS_GUARD_SQL,
  parseEnrollmentRow,
  parseJsonRecord,
  parseProductEpochRow,
  parseProtocolRow,
  parseRequiredString,
  parseVersion,
  requireD1LaneStoreOptions,
  scopeValues,
  type CloudflareD1LaneScopeV1,
  type CloudflareD1LaneStoreOptions,
  type LaneEnrollmentRow,
  type LaneProductEpochRow,
  type LaneProtocolRow,
} from './d1LaneRecords';

const ENROLLMENT_TABLE = 'lane_enrollments';
const OPERATION_TABLE = 'lane_protocol_operations';
const PRODUCT_TABLE = 'lane_product_epochs';
const RECEIPT_TABLE = 'lane_receipts';

type D1LaneLifecycleRow = LaneEnrollmentRow & { readonly manifest_json?: unknown };

export type CloudflareD1LaneLifecycleStoreOptions = CloudflareD1LaneStoreOptions;

export class CloudflareD1LaneLifecycleStore implements LaneLifecycleStore {
  private readonly database: CloudflareD1LaneStoreOptions['database'];
  private readonly scope: CloudflareD1LaneScopeV1;
  private readonly now: () => number;

  constructor(options: CloudflareD1LaneLifecycleStoreOptions) {
    const normalized = requireD1LaneStoreOptions(options);
    this.database = normalized.database;
    this.scope = normalized.scope;
    this.now = normalized.now;
  }

  async getEnrollment(
    enrollmentId: LaneEnrollmentId,
  ): Promise<LaneEnrollmentAdmissionRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT enrollment_id, wallet_id, manifest_digest_b64u, manifest_json,
                lifecycle_json, version, command_digest_b64u, created_at_ms, updated_at_ms
           FROM ${ENROLLMENT_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND enrollment_id = ?5`,
      )
      .bind(...scopeValues(this.scope), String(enrollmentId))
      .first<D1LaneLifecycleRow>();
    if (!row) return null;
    const parsed = parseEnrollmentRow(row);
    return {
      version: parsed.version,
      commandDigestB64u: parsed.commandDigestB64u,
      value: { manifest: parsed.manifest, lifecycle: parsed.lifecycle },
    };
  }

  async getProtocol(operationId: LaneOperationId): Promise<LaneProtocolAdmissionRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT operation_id, enrollment_id, wallet_id, wallet_key_id,
                source_lane_id, source_lane_share_epoch, source_revocation_epoch,
                target_lane_id, target_lane_share_epoch, target_material_activation_id,
                job_json, lifecycle_json, version, command_digest_b64u,
                created_at_ms, updated_at_ms
           FROM ${OPERATION_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND operation_id = ?5`,
      )
      .bind(...scopeValues(this.scope), String(operationId))
      .first<LaneProtocolRow>();
    if (!row) return null;
    const parsed = parseProtocolRow(row);
    return {
      version: parsed.version,
      commandDigestB64u: parsed.commandDigestB64u,
      value: parsed.record,
    };
  }

  async putEnrollmentAdmission(
    input: LaneEnrollmentAdmissionInput,
  ): Promise<LaneAdmissionMutationResult<LaneEnrollmentAdmissionRecord['value']>> {
    const manifest = parseLaneEnrollmentManifestV1(input.manifest);
    if (manifest.orderedChildren.length !== input.children.length) {
      throw new Error('lane enrollment manifest and protocol child count differ');
    }
    validateChildrenAgainstManifest(manifest, input.children);

    const existing = await this.getEnrollment(manifest.enrollmentId);
    if (existing) {
      if (
        existing.commandDigestB64u === input.commandDigestB64u &&
        equalLaneRecords(existing.value.manifest, manifest) &&
        equalLaneRecords(existing.value.lifecycle, input.lifecycle) &&
        (await admissionChildrenMatch(this, input.children))
      ) {
        return {
          outcome: 'replayed',
          version: existing.version,
          commandDigestB64u: existing.commandDigestB64u,
          value: existing.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: null,
        actualVersion: existing.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: existing.commandDigestB64u,
      };
    }

    const now = this.now();
    const manifestJson = JSON.stringify(manifest);
    const lifecycleJson = JSON.stringify(input.lifecycle);
    const statementValues = scopeValues(this.scope);
    const statements: D1PreparedStatementLike[] = [
      this.database
        .prepare(
          `INSERT INTO ${ENROLLMENT_TABLE} (
             namespace, org_id, project_id, env_id, enrollment_id, wallet_id,
             manifest_digest_b64u, manifest_json, lifecycle_json, version,
             command_digest_b64u, created_at_ms, updated_at_ms
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?11)`,
        )
        .bind(
          ...statementValues,
          String(manifest.enrollmentId),
          String(manifest.walletId),
          input.commandDigestB64u,
          manifestJson,
          lifecycleJson,
          input.commandDigestB64u,
          now,
        ),
      this.database.prepare(LANE_CAS_GUARD_SQL),
    ];
    for (const child of input.children) {
      statements.push(this.protocolInsertStatement(child, input.commandDigestB64u, now));
      statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    }
    try {
      const results = await this.database.batch(statements);
      for (let index = 0; index < results.length; index += 1) {
        assertD1Success(
          firstBatchResult(results, index),
          `lane enrollment admission statement ${index}`,
        );
      }
    } catch (error: unknown) {
      const raced = await this.getEnrollment(manifest.enrollmentId);
      if (
        raced &&
        raced.commandDigestB64u === input.commandDigestB64u &&
        equalLaneRecords(raced.value.manifest, manifest)
      ) {
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          value: raced.value,
        };
      }
      if (raced) {
        return {
          outcome: 'conflict',
          expectedVersion: null,
          actualVersion: raced.version,
          requestedCommandDigestB64u: input.commandDigestB64u,
          storedCommandDigestB64u: raced.commandDigestB64u,
        };
      }
      for (const child of input.children) {
        const racedChild = await this.getProtocol(child.job.operationId);
        if (racedChild) {
          return {
            outcome: 'conflict',
            expectedVersion: null,
            actualVersion: racedChild.version,
            requestedCommandDigestB64u: input.commandDigestB64u,
            storedCommandDigestB64u: racedChild.commandDigestB64u,
          };
        }
      }
      throw error;
    }
    return {
      outcome: 'applied',
      version: 1,
      commandDigestB64u: input.commandDigestB64u,
      value: { manifest, lifecycle: input.lifecycle },
    };
  }

  async putProtocolAdmission(
    input: LaneProtocolAdmissionInput,
  ): Promise<LaneAdmissionMutationResult<LaneProtocolRecordV1>> {
    const record = input.record;
    const existing = await this.getProtocol(record.job.operationId);
    if (existing) {
      if (
        existing.commandDigestB64u === input.commandDigestB64u &&
        equalLaneRecords(existing.value, record)
      ) {
        return {
          outcome: 'replayed',
          version: existing.version,
          commandDigestB64u: existing.commandDigestB64u,
          value: existing.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: null,
        actualVersion: existing.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: existing.commandDigestB64u,
      };
    }
    const now = this.now();
    const statements = [
      this.protocolInsertStatement(record, input.commandDigestB64u, now),
      this.database.prepare(LANE_CAS_GUARD_SQL),
    ];
    try {
      const results = await this.database.batch(statements);
      assertD1Success(firstBatchResult(results, 0), 'lane protocol admission');
    } catch (error: unknown) {
      const raced = await this.getProtocol(record.job.operationId);
      if (
        raced &&
        raced.commandDigestB64u === input.commandDigestB64u &&
        equalLaneRecords(raced.value, record)
      ) {
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          value: raced.value,
        };
      }
      if (raced) {
        return {
          outcome: 'conflict',
          expectedVersion: null,
          actualVersion: raced.version,
          requestedCommandDigestB64u: input.commandDigestB64u,
          storedCommandDigestB64u: raced.commandDigestB64u,
        };
      }
      throw error;
    }
    return {
      outcome: 'applied',
      version: 1,
      commandDigestB64u: input.commandDigestB64u,
      value: record,
    };
  }

  async compareAndSetProtocolLifecycle(
    input: LaneProtocolLifecycleCasInput,
  ): Promise<LaneProtocolCasResultV1> {
    const current = await this.getProtocol(input.operationId);
    if (!current) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    }
    if (
      current.commandDigestB64u === input.commandDigestB64u &&
      equalLaneRecords(current.value.lifecycle, input.lifecycle)
    ) {
      return {
        outcome: 'replayed',
        version: current.version,
        commandDigestB64u: current.commandDigestB64u,
        record: current.value,
      };
    }
    const updated = await this.updateProtocolLifecycle(input);
    if (!updated) {
      const raced = await this.getProtocol(input.operationId);
      if (!raced) {
        return {
          outcome: 'conflict',
          expectedVersion: input.expectedVersion,
          actualVersion: 0,
          requestedCommandDigestB64u: input.commandDigestB64u,
          storedCommandDigestB64u: '',
        };
      }
      if (
        raced.commandDigestB64u === input.commandDigestB64u &&
        equalLaneRecords(raced.value.lifecycle, input.lifecycle)
      ) {
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          record: raced.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: raced.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: raced.commandDigestB64u,
      };
    }
    const result = await this.getProtocol(input.operationId);
    if (!result) throw new Error('lane protocol disappeared after CAS');
    return {
      outcome: 'applied',
      version: result.version,
      commandDigestB64u: result.commandDigestB64u,
      record: result.value,
    };
  }

  async compareAndSetEnrollmentLifecycle(
    input: LaneEnrollmentLifecycleCasInput,
  ): Promise<LaneAdmissionMutationResult<LaneEnrollmentAdmissionRecord['value']>> {
    const current = await this.getEnrollment(input.enrollmentId);
    if (!current) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    }
    if (
      current.commandDigestB64u === input.commandDigestB64u &&
      equalLaneRecords(current.value.lifecycle, input.lifecycle)
    ) {
      return {
        outcome: 'replayed',
        version: current.version,
        commandDigestB64u: current.commandDigestB64u,
        value: current.value,
      };
    }
    const updated = await this.updateEnrollmentLifecycle(input);
    if (!updated) {
      const raced = await this.getEnrollment(input.enrollmentId);
      if (!raced) {
        return {
          outcome: 'conflict',
          expectedVersion: input.expectedVersion,
          actualVersion: 0,
          requestedCommandDigestB64u: input.commandDigestB64u,
          storedCommandDigestB64u: '',
        };
      }
      if (
        raced.commandDigestB64u === input.commandDigestB64u &&
        equalLaneRecords(raced.value.lifecycle, input.lifecycle)
      ) {
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          value: raced.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: raced.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: raced.commandDigestB64u,
      };
    }
    const result = await this.getEnrollment(input.enrollmentId);
    if (!result) throw new Error('lane enrollment disappeared after CAS');
    return {
      outcome: 'applied',
      version: result.version,
      commandDigestB64u: result.commandDigestB64u,
      value: result.value,
    };
  }

  async putProtocolCommitReceipt(
    receipt: LaneProtocolCommitReceiptV1,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneProtocolCommitReceiptV1>> {
    const protocol = await this.getProtocol(receipt.operationId);
    if (!protocol) throw new Error('protocol commit receipt names an unknown operation');
    assertProtocolCommitReceiptIdentity(protocol.value, receipt);
    if (
      protocol.value.lifecycle.state !== 'awaiting_protocol_commitment' &&
      protocol.value.lifecycle.state !== 'committed_awaiting_holder_delivery' &&
      protocol.value.lifecycle.state !== 'awaiting_server_activation' &&
      protocol.value.lifecycle.state !== 'ready_for_parent_visibility' &&
      protocol.value.lifecycle.state !== 'active'
    ) {
      throw new Error('protocol commit receipt is not valid for this lifecycle');
    }
    return await this.putReceipt(
      receipt.operationId,
      receipt.enrollmentId,
      'lane_protocol_commit',
      receipt,
      commandDigestB64u,
    );
  }

  async putHolderDeliveryReceipt(
    receipt: LaneHolderDeliveryReceiptV1,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneHolderDeliveryReceiptV1>> {
    const protocol = await this.getProtocol(receipt.operationId);
    if (!protocol) throw new Error('holder delivery receipt names an unknown operation');
    assertHolderDeliveryReceiptIdentity(protocol.value, receipt);
    return await this.putReceipt(
      receipt.operationId,
      receipt.enrollmentId,
      'lane_holder_delivery',
      receipt,
      commandDigestB64u,
    );
  }

  async putServerActivationReceipt(
    receipt: LaneServerActivationReceiptV1,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneServerActivationReceiptV1>> {
    const protocol = await this.getProtocol(receipt.operationId);
    if (!protocol) throw new Error('server activation receipt names an unknown operation');
    assertServerActivationReceiptIdentity(protocol.value, receipt);
    const commitReceipt = await this.readReceipt(receipt.operationId, 'lane_protocol_commit');
    const holderReceipt = await this.readReceipt(receipt.operationId, 'lane_holder_delivery');
    if (
      commitReceipt?.kind !== 'lane_protocol_commit_receipt_v1' ||
      holderReceipt?.kind !== 'lane_holder_delivery_receipt_v1'
    ) {
      throw new Error('server activation requires protocol and holder receipts');
    }
    const commitReceiptDigest = await exactReceiptDigest('lane_protocol_commit', commitReceipt);
    const holderReceiptDigest = await exactReceiptDigest('lane_holder_delivery', holderReceipt);
    if (
      (protocol.value.lifecycle.state !== 'awaiting_server_activation' &&
        protocol.value.lifecycle.state !== 'ready_for_parent_visibility' &&
        protocol.value.lifecycle.state !== 'active') ||
      protocol.value.lifecycle.protocolCommitReceiptDigestB64u !== commitReceiptDigest ||
      protocol.value.lifecycle.holderDeliveryReceiptDigestB64u !== holderReceiptDigest
    ) {
      throw new Error('server activation receipts do not match the committed protocol lifecycle');
    }
    const enrollment = await this.getEnrollment(receipt.enrollmentId);
    if (!enrollment) throw new Error('server activation receipt names an unknown enrollment');
    const pending = await buildPendingProductEpoch({
      protocol: protocol.value,
      protocolReceipt: commitReceipt,
      holderReceipt,
      serverReceipt: receipt,
      manifestDigestB64u: await computeLaneEnrollmentManifestDigestV1(enrollment.value.manifest),
    });
    const result = await this.putReceipt(
      receipt.operationId,
      receipt.enrollmentId,
      'lane_server_activation',
      receipt,
      commandDigestB64u,
    );
    const pendingResult = await this.putProductEpochPending(pending, commandDigestB64u);
    if (pendingResult.outcome === 'conflict') {
      throw new Error('server activation receipt conflicts with the stored lane product epoch');
    }
    return result;
  }

  async putProductEpochPending(
    productEpoch: Extract<LaneProductEpochRecordV1, { state: 'pending_visibility' }>,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneProductEpochRecordV1>> {
    const existing = await this.getProductEpoch({
      walletId: productEpoch.walletId,
      walletKeyId: productEpoch.walletKeyId,
      laneId: productEpoch.laneId,
      laneShareEpoch: productEpoch.laneShareEpoch,
    });
    if (existing) {
      const stored = await this.getProductEpochStored({
        walletId: productEpoch.walletId,
        walletKeyId: productEpoch.walletKeyId,
        laneId: productEpoch.laneId,
        laneShareEpoch: productEpoch.laneShareEpoch,
      });
      if (
        stored &&
        stored.commandDigestB64u === commandDigestB64u &&
        equalLaneRecords(stored.product, productEpoch)
      ) {
        return {
          outcome: 'replayed',
          version: stored.version,
          commandDigestB64u: stored.commandDigestB64u,
          value: stored.product,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: null,
        actualVersion: stored?.version ?? 1,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: stored?.commandDigestB64u ?? '',
      };
    }
    const now = this.now();
    const values = scopeValues(this.scope);
    const insert = this.database
      .prepare(
        `INSERT INTO ${PRODUCT_TABLE} (
           namespace, org_id, project_id, env_id, wallet_id, wallet_key_id,
           lane_id, lane_share_epoch, enrollment_id, operation_id,
           target_material_activation_id, material_activation_json,
           holder_participant_json, signing_worker_participant_json,
           participant_set_binding_digest_b64u, revocation_epoch,
           lane_kind, key_family, public_identity_digest_b64u, state, product_json,
           version, command_digest_b64u, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, 1, ?22, ?23, ?23)`,
      )
      .bind(
        ...values,
        String(productEpoch.walletId),
        String(productEpoch.walletKeyId),
        String(productEpoch.laneId),
        String(productEpoch.laneShareEpoch),
        String(productEpoch.enrollmentId),
        String(productEpoch.operationId),
        String(productEpoch.targetMaterialActivationId),
        JSON.stringify(productEpoch.materialActivation),
        JSON.stringify(productEpoch.holderParticipant),
        JSON.stringify(productEpoch.signingWorkerParticipant),
        productEpoch.participantSetBindingDigestB64u,
        productEpoch.revocationEpoch,
        productEpoch.laneKind,
        productEpoch.keyFamily,
        productEpoch.publicIdentityDigestB64u,
        productEpoch.state,
        JSON.stringify(productEpoch),
        commandDigestB64u,
        now,
      );
    try {
      const results = await this.database.batch([
        insert,
        this.database.prepare(LANE_CAS_GUARD_SQL),
      ]);
      assertD1Success(firstBatchResult(results, 0), 'lane product epoch admission');
    } catch (error: unknown) {
      const raced = await this.getProductEpochStored({
        walletId: productEpoch.walletId,
        walletKeyId: productEpoch.walletKeyId,
        laneId: productEpoch.laneId,
        laneShareEpoch: productEpoch.laneShareEpoch,
      });
      if (
        raced &&
        raced.commandDigestB64u === commandDigestB64u &&
        equalLaneRecords(raced.product, productEpoch)
      ) {
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: raced.commandDigestB64u,
          value: raced.product,
        };
      }
      if (raced) {
        return {
          outcome: 'conflict',
          expectedVersion: null,
          actualVersion: raced.version,
          requestedCommandDigestB64u: commandDigestB64u,
          storedCommandDigestB64u: raced.commandDigestB64u,
        };
      }
      throw error;
    }
    return { outcome: 'applied', version: 1, commandDigestB64u, value: productEpoch };
  }

  async getProductEpoch(lookup: LaneProductEpochLookup): Promise<LaneProductEpochRecordV1 | null> {
    const stored = await this.getProductEpochStored(lookup);
    return stored?.product ?? null;
  }

  private async getProductEpochStored(lookup: LaneProductEpochLookup): Promise<{
    readonly product: LaneProductEpochRecordV1;
    readonly version: number;
    readonly commandDigestB64u: string;
  } | null> {
    const row = await this.database
      .prepare(
        `SELECT product_json, version, command_digest_b64u
           FROM ${PRODUCT_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND wallet_id = ?5 AND wallet_key_id = ?6 AND lane_id = ?7 AND lane_share_epoch = ?8`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(lookup.walletId),
        String(lookup.walletKeyId),
        String(lookup.laneId),
        String(lookup.laneShareEpoch),
      )
      .first<LaneProductEpochRow>();
    if (!row) return null;
    return {
      product: parseProductEpochRow(row),
      version: parseVersion(row.version, 'lane product epoch version'),
      commandDigestB64u: parseRequiredString(
        row.command_digest_b64u,
        'lane product epoch command digest',
      ),
    };
  }

  async getActiveProductEpoch(
    lookup: LaneActiveProductEpochLookup,
  ): Promise<Extract<LaneProductEpochRecordV1, { state: 'active' }> | null> {
    const value = await this.getProductEpoch(lookup);
    if (!value || value.state !== 'active') return null;
    if (!mpcMaterialActivationRefsEqual(value.materialActivation, lookup.materialActivation))
      return null;
    return value;
  }

  async listEnrollmentProductEpochs(
    enrollmentId: LaneEnrollmentId,
  ): Promise<readonly LaneProductEpochRecordV1[]> {
    const rows = await this.database
      .prepare(
        `SELECT product_json
           FROM ${PRODUCT_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND enrollment_id = ?5
          ORDER BY wallet_key_id, lane_id, lane_share_epoch`,
      )
      .bind(...scopeValues(this.scope), String(enrollmentId))
      .all<LaneProductEpochRow>();
    return (rows.results ?? []).map(parseProductEpochRow);
  }

  async commitEnrollmentVisibility(
    input: CommitLaneEnrollmentActivationV1,
  ): Promise<LaneEnrollmentVisibilityCommitResult> {
    const parent = await this.getEnrollment(input.enrollmentId);
    const manifestDigest = parent
      ? await computeLaneEnrollmentManifestDigestV1(parent.value.manifest)
      : '';
    if (
      !parent ||
      String(parent.value.manifest.walletId) !== String(input.walletId) ||
      (parent.commandDigestB64u !== input.manifestDigestB64u &&
        manifestDigest !== input.manifestDigestB64u)
    ) {
      return {
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: 1,
        actualVersion: parent?.version ?? 0,
        requestedCommandDigestB64u: input.manifestDigestB64u,
        storedCommandDigestB64u: parent?.commandDigestB64u ?? '',
      };
    }
    const receipt = parseAggregateLaneActivationReceiptV1({
      kind: 'aggregate_lane_activation_receipt_v1',
      enrollmentId: input.enrollmentId,
      walletId: input.walletId,
      manifestDigestB64u: input.manifestDigestB64u,
      orderedChildReceipts: input.orderedChildReceipts,
      activatedAtMs: input.activatedAtMs,
    });
    validateActivationReceiptAgainstManifest(parent.value.manifest, receipt);
    const aggregateDigest = await computeAggregateLaneActivationReceiptDigestV1(receipt);
    if (parent.value.lifecycle.state === 'active') {
      if (parent.value.lifecycle.aggregateReceiptDigestB64u === aggregateDigest) {
        const productEpochs = await activeProductEpochs(this, input.enrollmentId);
        if (productEpochs.length === 0) throw new Error('active enrollment has no product epochs');
        return {
          outcome: 'replayed',
          version: parent.version,
          commandDigestB64u: aggregateDigest,
          receipt,
          lifecycle: parent.value.lifecycle,
          productEpochs,
        };
      }
      return {
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: parent.version,
        actualVersion: parent.version,
        requestedCommandDigestB64u: aggregateDigest,
        storedCommandDigestB64u: parent.value.lifecycle.aggregateReceiptDigestB64u,
      };
    }
    const readyLifecycle = resolveReadyEnrollmentLifecycle(
      parent.value.lifecycle,
      input,
      aggregateDigest,
    );
    if (!readyLifecycle) {
      return {
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: parent.version,
        actualVersion: parent.version,
        requestedCommandDigestB64u: aggregateDigest,
        storedCommandDigestB64u: parent.commandDigestB64u,
      };
    }
    if (readyLifecycle.aggregateReceiptDigestB64u !== aggregateDigest) {
      return {
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: parent.version,
        actualVersion: parent.version,
        requestedCommandDigestB64u: aggregateDigest,
        storedCommandDigestB64u: readyLifecycle.aggregateReceiptDigestB64u,
      };
    }
    const activeLifecycle = transitionLaneEnrollmentLifecycleV1(readyLifecycle, {
      action: 'activate',
      activatedAtMs: input.activatedAtMs,
    });
    if (activeLifecycle.state !== 'active')
      throw new Error('lane visibility transition did not produce active enrollment');
    const protocols: Array<{
      readonly operationId: LaneOperationId;
      readonly row: LaneProtocolAdmissionRecord;
    }> = [];
    const products = await this.listEnrollmentProductEpochs(input.enrollmentId);
    const retirements: Array<{
      readonly previous: Extract<LaneProductEpochRecordV1, { state: 'active' }>;
      readonly version: number;
    }> = [];
    for (const child of input.orderedChildReceipts) {
      const protocol = await this.getProtocol(child.operationId);
      if (!protocol || protocol.value.lifecycle.state !== 'ready_for_parent_visibility')
        throw new Error('lane child is not ready for parent visibility');
      const readyLifecycle = protocol.value.lifecycle;
      if (
        String(protocol.value.job.walletId) !== String(input.walletId) ||
        String(protocol.value.job.walletKeyId) !== String(child.walletKeyId) ||
        String(protocol.value.job.target.laneId) !== String(child.targetLaneId) ||
        String(protocol.value.job.target.laneShareEpoch) !== String(child.targetLaneShareEpoch) ||
        String(protocol.value.job.targetMaterialActivationId) !==
          String(child.targetMaterialActivation.activationId) ||
        readyLifecycle.protocolCommitReceiptDigestB64u !== child.protocolCommitReceiptDigestB64u ||
        readyLifecycle.holderDeliveryReceiptDigestB64u !== child.holderDeliveryReceiptDigestB64u ||
        readyLifecycle.serverActivationReceiptDigestB64u !== child.serverActivationReceiptDigestB64u
      )
        throw new Error('lane child identity or receipt digest differs from aggregate receipt');
      const product = products.find(
        (candidate) => String(candidate.operationId) === String(child.operationId),
      );
      if (
        !product ||
        product.state !== 'pending_visibility' ||
        String(product.walletId) !== String(input.walletId) ||
        String(product.walletKeyId) !== String(child.walletKeyId) ||
        String(product.laneId) !== String(child.targetLaneId) ||
        String(product.laneShareEpoch) !== String(child.targetLaneShareEpoch) ||
        String(product.targetMaterialActivationId) !==
          String(child.targetMaterialActivation.activationId) ||
        !mpcMaterialActivationRefsEqual(product.materialActivation, child.targetMaterialActivation)
      )
        throw new Error(
          'lane child product epoch is not pending or differs from aggregate receipt',
        );
      if (protocol.value.job.target.operation === 'refresh_lane') {
        const previous = await this.getActiveProductEpochByActivation(
          protocol.value.job.walletKeyId,
          protocol.value.job.target.laneId,
          protocol.value.job.target.priorMaterialActivation.activationId,
        );
        if (!previous) throw new Error('lane refresh target has no active prior product epoch');
        retirements.push({ previous: previous.product, version: previous.version });
      }
      protocols.push({ operationId: child.operationId, row: protocol });
    }
    const now = this.now();
    const values = scopeValues(this.scope);
    const statements: D1PreparedStatementLike[] = [];
    statements.push(
      this.database
        .prepare(
          `UPDATE ${ENROLLMENT_TABLE} SET lifecycle_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND enrollment_id = ?8 AND version = ?9 AND lifecycle_json = ?10`,
        )
        .bind(
          ...values,
          JSON.stringify(activeLifecycle),
          aggregateDigest,
          now,
          String(input.enrollmentId),
          parent.version,
          JSON.stringify(parent.value.lifecycle),
        ),
    );
    statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    for (const protocol of protocols) {
      const readyLifecycle = protocol.row.value.lifecycle;
      if (readyLifecycle.state !== 'ready_for_parent_visibility')
        throw new Error('lane child lifecycle changed before visibility commit');
      const lifecycle: LaneProtocolLifecycle = {
        state: 'active',
        transcriptHashB64u: readyLifecycle.transcriptHashB64u,
        protocolCommitReceiptDigestB64u: readyLifecycle.protocolCommitReceiptDigestB64u,
        holderDeliveryReceiptDigestB64u: readyLifecycle.holderDeliveryReceiptDigestB64u,
        serverActivationReceiptDigestB64u: readyLifecycle.serverActivationReceiptDigestB64u,
        aggregateActivationReceiptDigestB64u: aggregateDigest,
        activatedAtMs: input.activatedAtMs,
      };
      statements.push(
        this.database
          .prepare(
            `UPDATE ${OPERATION_TABLE} SET lifecycle_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?8 AND version = ?9`,
          )
          .bind(
            ...values,
            JSON.stringify(lifecycle),
            aggregateDigest,
            now,
            String(protocol.operationId),
            protocol.row.version,
          ),
      );
      statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    }
    for (const retirement of retirements) {
      const retired = retireLaneProductEpochV1(retirement.previous, {
        retirementReason: 'rotation',
        retirementReceiptDigestB64u: aggregateDigest,
        retiredAtMs: input.activatedAtMs,
      });
      statements.push(
        this.database
          .prepare(
            `UPDATE ${PRODUCT_TABLE} SET state = 'retired', product_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?8 AND lane_id = ?9 AND target_material_activation_id = ?10 AND version = ?11 AND state = 'active'`,
          )
          .bind(
            ...values,
            JSON.stringify(retired),
            aggregateDigest,
            input.activatedAtMs,
            String(retirement.previous.walletKeyId),
            String(retirement.previous.laneId),
            String(retirement.previous.targetMaterialActivationId),
            retirement.version,
          ),
      );
      statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    }
    for (const child of input.orderedChildReceipts) {
      const pending = products.find(
        (candidate) => String(candidate.operationId) === String(child.operationId),
      );
      if (!pending || pending.state !== 'pending_visibility')
        throw new Error('lane product epoch is not pending');
      const active = activateLaneProductEpochV1(pending, {
        aggregateActivationReceiptDigestB64u: aggregateDigest,
        activatedAtMs: input.activatedAtMs,
      });
      statements.push(
        this.database
          .prepare(
            `UPDATE ${PRODUCT_TABLE} SET state = 'active', product_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?8 AND state = 'pending_visibility'`,
          )
          .bind(
            ...values,
            JSON.stringify(active),
            aggregateDigest,
            input.activatedAtMs,
            String(child.operationId),
          ),
      );
      statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    }
    statements.push(
      this.database
        .prepare(
          `INSERT INTO ${RECEIPT_TABLE} (namespace, org_id, project_id, env_id, receipt_id, enrollment_id, operation_id, receipt_kind, receipt_digest_b64u, receipt_json, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'aggregate_activation', ?7, ?8, ?9)`,
        )
        .bind(
          ...values,
          `${String(input.enrollmentId)}:aggregate_activation`,
          String(input.enrollmentId),
          aggregateDigest,
          JSON.stringify(receipt),
          input.activatedAtMs,
        ),
    );
    statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    try {
      const results = await this.database.batch(statements);
      for (let index = 0; index < results.length; index += 1)
        assertD1Success(firstBatchResult(results, index), `lane visibility statement ${index}`);
    } catch (error: unknown) {
      const raced = await this.getEnrollment(input.enrollmentId);
      if (
        raced?.value.lifecycle.state === 'active' &&
        raced.value.lifecycle.aggregateReceiptDigestB64u === aggregateDigest
      ) {
        const productEpochs = await activeProductEpochs(this, input.enrollmentId);
        if (productEpochs.length === 0) throw error;
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: aggregateDigest,
          receipt,
          lifecycle: raced.value.lifecycle,
          productEpochs,
        };
      }
      throw error;
    }
    const productEpochs = await activeProductEpochs(this, input.enrollmentId);
    if (productEpochs.length === 0)
      throw new Error('lane visibility commit produced no active product epochs');
    return {
      outcome: 'applied',
      version: parent.version + 1,
      commandDigestB64u: aggregateDigest,
      receipt,
      lifecycle: activeLifecycle,
      productEpochs,
    };
  }

  async fenceLaneRevocation(
    input: RevokeSigningLaneV1,
  ): Promise<LaneSigningLaneRevocationFenceMutationResult> {
    const command = parseRevokeSigningLaneV1(input);
    const commandDigestB64u = await computeRevokeSigningLaneDigestV1(command);
    const row = await this.database
      .prepare(
        `SELECT product_json, version, command_digest_b64u
           FROM ${PRODUCT_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND wallet_key_id = ?5 AND lane_id = ?6 AND lane_share_epoch = ?7`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(command.walletKeyId),
        String(command.laneId),
        String(command.laneShareEpoch),
      )
      .first<{
        readonly product_json?: unknown;
        readonly version?: unknown;
        readonly command_digest_b64u?: unknown;
      }>();
    if (!row) {
      return {
        outcome: 'conflict',
        expectedVersion: 1,
        actualVersion: 0,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    }
    const product = parseProductEpochRecordV1(row.product_json);
    const version = parseVersion(row.version, 'lane product epoch version');
    const storedDigest = parseRequiredString(
      row.command_digest_b64u,
      'lane product epoch command digest',
    );
    if (String(product.walletId) !== String(command.walletId)) {
      return {
        outcome: 'conflict',
        expectedVersion: version,
        actualVersion: version,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    if (product.state === 'revoked') {
      if (storedDigest === commandDigestB64u) {
        const retirementReceipt = await this.readAndVerifyServerRetirementReceipt(product, command);
        return {
          outcome: 'already_completed',
          version,
          commandDigestB64u: storedDigest,
          productEpoch: product,
          retirementReceipt,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: version,
        actualVersion: version,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    if (product.state === 'revocation_pending') {
      if (storedDigest === commandDigestB64u) {
        return {
          outcome: 'replayed',
          version,
          commandDigestB64u: storedDigest,
          productEpoch: product,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: version,
        actualVersion: version,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    return await this.commitLaneRevocationFence({
      command,
      expectedVersion: version,
      commandDigestB64u,
    });
  }

  async fenceEnrollmentRevocation(
    input: RevokeLaneEnrollmentV1,
  ): Promise<LaneAdmissionMutationResult<LaneEnrollmentAdmissionRecord['value']>> {
    const commandDigestB64u = await digestLaneEnrollmentRevocationCommand(input);
    const parent = await this.getEnrollment(input.enrollmentId);
    if (!parent)
      return {
        outcome: 'conflict',
        expectedVersion: 1,
        actualVersion: 0,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    if (String(parent.value.manifest.walletId) !== String(input.walletId)) {
      return {
        outcome: 'conflict',
        expectedVersion: parent.version,
        actualVersion: parent.version,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: parent.commandDigestB64u,
      };
    }
    const manifestDigest = await computeLaneEnrollmentManifestDigestV1(parent.value.manifest);
    if (manifestDigest !== input.manifestDigestB64u) {
      return {
        outcome: 'conflict',
        expectedVersion: parent.version,
        actualVersion: parent.version,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: manifestDigest,
      };
    }
    const storedFenceDigest = await this.getEnrollmentRevocationFenceDigest(input.enrollmentId);
    if (parent.value.lifecycle.state === 'revoked') {
      if (storedFenceDigest !== commandDigestB64u) {
        return {
          outcome: 'conflict',
          expectedVersion: parent.version,
          actualVersion: parent.version,
          requestedCommandDigestB64u: commandDigestB64u,
          storedCommandDigestB64u: storedFenceDigest ?? parent.commandDigestB64u,
        };
      }
      return {
        outcome: 'replayed',
        version: parent.version,
        commandDigestB64u,
        value: parent.value,
      };
    }
    const reason: Extract<
      LaneEnrollmentLifecycleV1,
      { state: 'revoking_committed_targets' }
    >['reason'] =
      input.reason === 'cancelled_after_commit' ||
      input.reason === 'expired_after_commit' ||
      input.reason === 'revoked_during_activation'
        ? input.reason
        : 'revoked_during_activation';
    let lifecycle: LaneEnrollmentLifecycleV1;
    switch (parent.value.lifecycle.state) {
      case 'committed_completion_required':
      case 'ready_for_visibility':
      case 'active':
        lifecycle = transitionLaneEnrollmentLifecycleV1(parent.value.lifecycle, {
          action: 'begin_revocation',
          reason,
          markedAtMs: input.requestedAtMs,
        });
        break;
      case 'revoking_committed_targets':
        if (
          parent.value.lifecycle.reason === reason &&
          parent.value.lifecycle.manifestDigestB64u === input.manifestDigestB64u &&
          storedFenceDigest === commandDigestB64u
        ) {
          return {
            outcome: 'replayed',
            version: parent.version,
            commandDigestB64u,
            value: parent.value,
          };
        }
        return {
          outcome: 'conflict',
          expectedVersion: parent.version,
          actualVersion: parent.version,
          requestedCommandDigestB64u: commandDigestB64u,
          storedCommandDigestB64u: storedFenceDigest ?? parent.commandDigestB64u,
        };
      case 'preparing':
      case 'cancelled_precommit':
        return {
          outcome: 'conflict',
          expectedVersion: parent.version,
          actualVersion: parent.version,
          requestedCommandDigestB64u: commandDigestB64u,
          storedCommandDigestB64u: parent.commandDigestB64u,
        };
      default:
        return assertNeverEnrollmentLifecycle(parent.value.lifecycle);
    }
    if (lifecycle.state !== 'revoking_committed_targets')
      throw new Error('lane enrollment revocation fence did not produce revoking state');
    const updated = await this.updateEnrollmentRevocationFence(
      input.enrollmentId,
      parent.version,
      commandDigestB64u,
      lifecycle,
    );
    if (!updated) {
      const raced = await this.getEnrollment(input.enrollmentId);
      const racedFenceDigest = await this.getEnrollmentRevocationFenceDigest(input.enrollmentId);
      if (
        raced?.value.lifecycle.state === 'revoking_committed_targets' &&
        raced.value.lifecycle.reason === reason &&
        raced.value.lifecycle.manifestDigestB64u === input.manifestDigestB64u &&
        racedFenceDigest === commandDigestB64u
      ) {
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u,
          value: raced.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: parent.version,
        actualVersion: raced?.version ?? 0,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: racedFenceDigest ?? raced?.commandDigestB64u ?? '',
      };
    }
    const result = await this.getEnrollment(input.enrollmentId);
    if (!result) throw new Error('lane enrollment disappeared after revocation fence');
    return {
      outcome: 'applied',
      version: result.version,
      commandDigestB64u,
      value: result.value,
    };
  }

  private async commitLaneRevocationFence(input: {
    readonly command: RevokeSigningLaneV1;
    readonly expectedVersion: number;
    readonly commandDigestB64u: string;
  }): Promise<LaneSigningLaneRevocationFenceMutationResult> {
    const command = parseRevokeSigningLaneV1(input.command);
    const row = await this.database
      .prepare(
        `SELECT product_json, version, command_digest_b64u FROM ${PRODUCT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?5 AND lane_id = ?6 AND lane_share_epoch = ?7`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(command.walletKeyId),
        String(command.laneId),
        String(command.laneShareEpoch),
      )
      .first<{
        readonly product_json?: unknown;
        readonly version?: unknown;
        readonly command_digest_b64u?: unknown;
      }>();
    if (!row)
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    const product = parseProductEpochRecordV1(row.product_json);
    const currentVersion = Number(row.version);
    const storedDigest = typeof row.command_digest_b64u === 'string' ? row.command_digest_b64u : '';
    if (String(product.walletId) !== String(command.walletId)) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: Number.isSafeInteger(currentVersion) ? currentVersion : 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    if (product.state === 'revoked' && storedDigest === input.commandDigestB64u) {
      const retirementReceipt = await this.readAndVerifyServerRetirementReceipt(product, command);
      return {
        outcome: 'already_completed',
        version: currentVersion,
        commandDigestB64u: storedDigest,
        productEpoch: product,
        retirementReceipt,
      };
    }
    if (product.state === 'revocation_pending' && storedDigest === input.commandDigestB64u)
      return {
        outcome: 'replayed',
        version: currentVersion,
        commandDigestB64u: storedDigest,
        productEpoch: product,
      };
    if (
      product.state !== 'revoked' &&
      product.state !== 'revocation_pending' &&
      product.revocationEpoch !== command.expectedRevocationEpoch
    ) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: Number.isSafeInteger(currentVersion) ? currentVersion : 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    if (
      !Number.isSafeInteger(currentVersion) ||
      currentVersion < 1 ||
      currentVersion !== input.expectedVersion
    )
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: Number.isSafeInteger(currentVersion) ? currentVersion : 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    if (product.state !== 'active' && product.state !== 'pending_visibility') {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: currentVersion,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    const pending = beginLaneProductEpochRevocationV1(product, {
      revocationEpoch: command.expectedRevocationEpoch + 1,
      revocationReason: command.reason,
      retirementEffectBindingDigestB64u: command.retirementEffectBindingDigestB64u,
      revocationRequestedAtMs: command.requestedAtMs,
    });
    const result = await this.database
      .prepare(
        `UPDATE ${PRODUCT_TABLE} SET state = 'revocation_pending', revocation_epoch = ?5, product_json = ?6, version = version + 1, command_digest_b64u = ?7, updated_at_ms = ?8 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?9 AND lane_id = ?10 AND lane_share_epoch = ?11 AND version = ?12 AND state IN ('active', 'pending_visibility')`,
      )
      .bind(
        ...scopeValues(this.scope),
        command.expectedRevocationEpoch + 1,
        JSON.stringify(pending),
        input.commandDigestB64u,
        command.requestedAtMs,
        String(command.walletKeyId),
        String(command.laneId),
        String(command.laneShareEpoch),
        input.expectedVersion,
      )
      .run();
    if (d1ChangedRows(result) !== 1) {
      const raced = await this.database
        .prepare(
          `SELECT product_json, version, command_digest_b64u FROM ${PRODUCT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?5 AND lane_id = ?6 AND lane_share_epoch = ?7`,
        )
        .bind(
          ...scopeValues(this.scope),
          String(command.walletKeyId),
          String(command.laneId),
          String(command.laneShareEpoch),
        )
        .first<{
          readonly product_json?: unknown;
          readonly version?: unknown;
          readonly command_digest_b64u?: unknown;
        }>();
      const racedProduct = raced ? parseProductEpochRecordV1(raced.product_json) : null;
      const racedDigest =
        typeof raced?.command_digest_b64u === 'string' ? raced.command_digest_b64u : '';
      if (racedProduct?.state === 'revocation_pending' && racedDigest === input.commandDigestB64u)
        return {
          outcome: 'replayed',
          version: Number(raced?.version),
          commandDigestB64u: racedDigest,
          productEpoch: racedProduct,
        };
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: Number(raced?.version ?? 0),
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: racedDigest,
      };
    }
    return {
      outcome: 'applied',
      version: input.expectedVersion + 1,
      commandDigestB64u: input.commandDigestB64u,
      productEpoch: pending,
    };
  }

  async commitLaneRevocation(
    input: LaneSigningLaneRevocationCommitInput,
  ): Promise<LaneSigningLaneRevocationMutationResult> {
    const completion = parseCompleteSigningLaneRevocationV1(input.completion);
    const command = parseRevokeSigningLaneV1(completion.command);
    const computedCommandDigest = await computeRevokeSigningLaneDigestV1(command);
    if (computedCommandDigest !== completion.commandDigestB64u)
      throw new Error('lane revocation completion command digest is invalid');
    const row = await this.database
      .prepare(
        `SELECT product_json, version, command_digest_b64u FROM ${PRODUCT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?5 AND lane_id = ?6 AND lane_share_epoch = ?7`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(command.walletKeyId),
        String(command.laneId),
        String(command.laneShareEpoch),
      )
      .first<{
        readonly product_json?: unknown;
        readonly version?: unknown;
        readonly command_digest_b64u?: unknown;
      }>();
    if (!row)
      return {
        outcome: 'conflict',
        expectedVersion: completion.expectedVersion,
        actualVersion: 0,
        requestedCommandDigestB64u: completion.commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    const product = parseLaneProductEpochRecordV1(
      parseJsonRecord(row.product_json, 'product_json'),
    );
    const currentVersion = parseVersion(row.version, 'lane product epoch version');
    const storedDigest = parseRequiredString(
      row.command_digest_b64u,
      'lane product epoch command digest',
    );
    if (product.state !== 'revocation_pending' && product.state !== 'revoked') {
      return {
        outcome: 'conflict',
        expectedVersion: completion.expectedVersion,
        actualVersion: currentVersion,
        requestedCommandDigestB64u: completion.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    const retirementReceipt = parseLaneServerRetirementReceiptV1(
      completion.retirementReceipt,
      'lane revocation completion retirement receipt',
    );
    const retirementReceiptDigestB64u = await verifyServerRetirementReceiptV1({
      store: this,
      product,
      command,
      receipt: retirementReceipt,
    });
    if (
      product.state === 'revoked' &&
      storedDigest === completion.commandDigestB64u &&
      product.retirementEffectBindingDigestB64u === command.retirementEffectBindingDigestB64u &&
      product.revocationReceiptDigestB64u === retirementReceiptDigestB64u
    ) {
      const storedReceipt = await this.readAndVerifyServerRetirementReceipt(product, command);
      if (!equalLaneRecords(storedReceipt, retirementReceipt)) {
        return {
          outcome: 'conflict',
          expectedVersion: completion.expectedVersion,
          actualVersion: currentVersion,
          requestedCommandDigestB64u: retirementReceiptDigestB64u,
          storedCommandDigestB64u: product.revocationReceiptDigestB64u,
        };
      }
      return {
        outcome: 'replayed',
        version: currentVersion,
        commandDigestB64u: storedDigest,
        productEpoch: product,
        retirementReceipt: storedReceipt,
      };
    }
    if (
      product.state !== 'revocation_pending' ||
      currentVersion !== completion.expectedVersion ||
      storedDigest !== completion.commandDigestB64u ||
      product.retirementEffectBindingDigestB64u !== command.retirementEffectBindingDigestB64u ||
      product.revocationEpoch !== command.expectedRevocationEpoch + 1
    )
      return {
        outcome: 'conflict',
        expectedVersion: completion.expectedVersion,
        actualVersion: currentVersion,
        requestedCommandDigestB64u: completion.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    const revoked = parseLaneProductEpochRecordV1(
      completeLaneProductEpochRevocationV1(product, {
        revocationReceiptDigestB64u: retirementReceiptDigestB64u,
        revokedAtMs: completion.revokedAtMs,
      }),
    );
    if (revoked.state !== 'revoked') throw new Error('lane revocation completion state changed');
    const update = this.database
      .prepare(
        `UPDATE ${PRODUCT_TABLE} SET state = 'revoked', product_json = ?5, version = version + 1, updated_at_ms = ?6 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?7 AND lane_id = ?8 AND lane_share_epoch = ?9 AND version = ?10 AND state = 'revocation_pending' AND command_digest_b64u = ?11`,
      )
      .bind(
        ...scopeValues(this.scope),
        JSON.stringify(revoked),
        completion.revokedAtMs,
        String(command.walletKeyId),
        String(command.laneId),
        String(command.laneShareEpoch),
        completion.expectedVersion,
        completion.commandDigestB64u,
      );
    const receiptInsert = this.database
      .prepare(
        `INSERT INTO ${RECEIPT_TABLE} (namespace, org_id, project_id, env_id, receipt_id, enrollment_id, operation_id, receipt_kind, receipt_digest_b64u, receipt_json, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
      )
      .bind(
        ...scopeValues(this.scope),
        serverRetirementReceiptId(product),
        String(product.enrollmentId),
        String(product.operationId),
        serverRetirementReceiptKind(product),
        retirementReceiptDigestB64u,
        JSON.stringify(retirementReceipt),
        completion.revokedAtMs,
      );
    let applied = false;
    try {
      const results = await this.database.batch([
        update,
        this.database.prepare(LANE_CAS_GUARD_SQL),
        receiptInsert,
        this.database.prepare(LANE_CAS_GUARD_SQL),
      ]);
      assertD1Success(firstBatchResult(results, 0), 'lane revocation completion');
      assertD1Success(firstBatchResult(results, 2), 'lane retirement receipt persistence');
      applied = d1ChangedRows(firstBatchResult(results, 0)) === 1;
    } catch {
      applied = false;
    }
    if (!applied) {
      const raced = await this.getProductEpoch({
        walletId: command.walletId,
        walletKeyId: command.walletKeyId,
        laneId: command.laneId,
        laneShareEpoch: command.laneShareEpoch,
      });
      if (
        raced?.state === 'revoked' &&
        raced.retirementEffectBindingDigestB64u === command.retirementEffectBindingDigestB64u &&
        raced.revocationReceiptDigestB64u === retirementReceiptDigestB64u
      ) {
        const storedReceipt = await this.readAndVerifyServerRetirementReceipt(raced, command);
        if (!equalLaneRecords(storedReceipt, retirementReceipt)) {
          throw new Error('stored lane retirement receipt differs from completion receipt');
        }
        return {
          outcome: 'replayed',
          version: completion.expectedVersion + 1,
          commandDigestB64u: completion.commandDigestB64u,
          productEpoch: raced,
          retirementReceipt: storedReceipt,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: completion.expectedVersion,
        actualVersion: completion.expectedVersion,
        requestedCommandDigestB64u: completion.commandDigestB64u,
        storedCommandDigestB64u: storedDigest,
      };
    }
    return {
      outcome: 'applied',
      version: completion.expectedVersion + 1,
      commandDigestB64u: completion.commandDigestB64u,
      productEpoch: revoked,
      retirementReceipt,
    };
  }

  async commitEnrollmentRevocation(
    input: LaneEnrollmentRevocationCommitInput,
  ): Promise<LaneEnrollmentRevocationCommitResult> {
    const parent = await this.getEnrollment(input.command.enrollmentId);
    if (!parent)
      return {
        outcome: 'conflict',
        enrollmentId: input.command.enrollmentId,
        expectedVersion: input.expectedVersion,
        actualVersion: 0,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: '',
      };
    const receipt = parseAggregateLaneRevocationReceiptV1(input.command.receipt);
    const aggregateDigest = await computeAggregateLaneRevocationReceiptDigestV1(receipt);
    if (parent.value.lifecycle.state === 'revoked') {
      if (parent.value.lifecycle.aggregateRevocationReceiptDigestB64u === aggregateDigest) {
        const productEpochs = await revokedProductEpochs(this, input.command.enrollmentId);
        if (productEpochs.length === 0) throw new Error('revoked enrollment has no product epochs');
        return {
          outcome: 'replayed',
          version: parent.version,
          commandDigestB64u: input.commandDigestB64u,
          receipt,
          lifecycle: parent.value.lifecycle,
          productEpochs,
        };
      }
      return {
        outcome: 'conflict',
        enrollmentId: input.command.enrollmentId,
        expectedVersion: input.expectedVersion,
        actualVersion: parent.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: parent.value.lifecycle.aggregateRevocationReceiptDigestB64u,
      };
    }
    if (parent.version !== input.expectedVersion)
      return {
        outcome: 'conflict',
        enrollmentId: input.command.enrollmentId,
        expectedVersion: input.expectedVersion,
        actualVersion: parent.version,
        requestedCommandDigestB64u: input.commandDigestB64u,
        storedCommandDigestB64u: parent.commandDigestB64u,
      };
    const productEpochs = (
      await this.listEnrollmentProductEpochs(input.command.enrollmentId)
    ).filter(
      (
        product,
      ): product is Extract<
        LaneProductEpochRecordV1,
        { state: 'pending_visibility' | 'active' | 'revocation_pending' | 'revoked' }
      > => product.state !== 'retired',
    );
    if (productEpochs.length !== receipt.orderedChildReceipts.length)
      throw new Error('revocation receipt child count differs from enrollment');
    const revoked: Array<Extract<LaneProductEpochRecordV1, { state: 'revoked' }>> = [];
    for (const product of productEpochs) {
      const child = receipt.orderedChildReceipts.find(
        (candidate) => String(candidate.operationId) === String(product.operationId),
      );
      if (!child) throw new Error('revocation receipt omits a product epoch');
      const expectedRevocationEpoch =
        product.state === 'revocation_pending' || product.state === 'revoked'
          ? product.revocationEpoch
          : product.revocationEpoch + 1;
      if (
        String(child.walletKeyId) !== String(product.walletKeyId) ||
        String(child.targetLaneId) !== String(product.laneId) ||
        String(child.targetLaneShareEpoch) !== String(product.laneShareEpoch) ||
        !mpcMaterialActivationRefsEqual(
          child.targetMaterialActivation,
          product.materialActivation,
        ) ||
        child.revocationEpoch !== expectedRevocationEpoch
      ) {
        throw new Error('revocation receipt child differs from its product epoch');
      }
      if (product.state === 'revoked') {
        if (
          product.revocationEpoch !== child.revocationEpoch ||
          product.revocationReceiptDigestB64u !== child.retirementReceiptDigestB64u
        ) {
          throw new Error('revocation receipt differs from the already revoked product epoch');
        }
        revoked.push(product);
        continue;
      }
      revoked.push(
        buildLaneProductEpochRevokedV1({
          walletId: product.walletId,
          walletKeyId: product.walletKeyId,
          laneId: product.laneId,
          laneKind: product.laneKind,
          laneShareEpoch: product.laneShareEpoch,
          keyFamily: product.keyFamily,
          enrollmentId: product.enrollmentId,
          operationId: product.operationId,
          targetMaterialActivationId: product.targetMaterialActivationId,
          materialActivation: product.materialActivation,
          publicIdentityDigestB64u: product.publicIdentityDigestB64u,
          holderParticipant: product.holderParticipant,
          signingWorkerParticipant: product.signingWorkerParticipant,
          participantSetBindingDigestB64u: product.participantSetBindingDigestB64u,
          createdAtMs: product.createdAtMs,
          revocationEpoch: child.revocationEpoch,
          revocationReason: 'user_revoked',
          retirementEffectBindingDigestB64u:
            product.state === 'revocation_pending'
              ? product.retirementEffectBindingDigestB64u
              : aggregateDigest,
          revocationReceiptDigestB64u: child.retirementReceiptDigestB64u,
          revokedAtMs: input.command.revokedAtMs,
        }),
      );
    }
    const lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'revoked' }> = {
      state: 'revoked',
      manifestDigestB64u: input.command.manifestDigestB64u,
      aggregateRevocationReceiptDigestB64u: aggregateDigest,
      revokedAtMs: input.command.revokedAtMs,
    };
    const values = scopeValues(this.scope);
    const statements: D1PreparedStatementLike[] = [
      this.database
        .prepare(
          `UPDATE ${ENROLLMENT_TABLE} SET lifecycle_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND enrollment_id = ?8 AND version = ?9`,
        )
        .bind(
          ...values,
          JSON.stringify(lifecycle),
          input.commandDigestB64u,
          input.command.revokedAtMs,
          String(input.command.enrollmentId),
          input.expectedVersion,
        ),
      this.database.prepare(LANE_CAS_GUARD_SQL),
    ];
    for (const product of revoked) {
      if (
        productEpochs.find(
          (candidate) => String(candidate.operationId) === String(product.operationId),
        )?.state === 'revoked'
      )
        continue;
      statements.push(
        this.database
          .prepare(
            `UPDATE ${PRODUCT_TABLE} SET state = 'revoked', revocation_epoch = ?5, product_json = ?6, version = version + 1, command_digest_b64u = ?7, updated_at_ms = ?8 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND wallet_key_id = ?9 AND lane_id = ?10 AND lane_share_epoch = ?11 AND state IN ('active', 'pending_visibility')`,
          )
          .bind(
            ...values,
            product.revocationEpoch,
            JSON.stringify(product),
            input.commandDigestB64u,
            input.command.revokedAtMs,
            String(product.walletKeyId),
            String(product.laneId),
            String(product.laneShareEpoch),
          ),
      );
      statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    }
    statements.push(
      this.database
        .prepare(
          `INSERT INTO ${RECEIPT_TABLE} (namespace, org_id, project_id, env_id, receipt_id, enrollment_id, operation_id, receipt_kind, receipt_digest_b64u, receipt_json, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'aggregate_revocation', ?7, ?8, ?9)`,
        )
        .bind(
          ...values,
          `${String(input.command.enrollmentId)}:aggregate_revocation`,
          String(input.command.enrollmentId),
          aggregateDigest,
          JSON.stringify(receipt),
          input.command.revokedAtMs,
        ),
    );
    statements.push(this.database.prepare(LANE_CAS_GUARD_SQL));
    try {
      const results = await this.database.batch(statements);
      for (let index = 0; index < results.length; index += 1)
        assertD1Success(firstBatchResult(results, index), `lane revocation statement ${index}`);
    } catch (error: unknown) {
      const raced = await this.getEnrollment(input.command.enrollmentId);
      if (
        raced?.value.lifecycle.state === 'revoked' &&
        raced.value.lifecycle.aggregateRevocationReceiptDigestB64u === aggregateDigest
      ) {
        const active = await revokedProductEpochs(this, input.command.enrollmentId);
        if (active.length === 0) throw error;
        return {
          outcome: 'replayed',
          version: raced.version,
          commandDigestB64u: input.commandDigestB64u,
          receipt,
          lifecycle: raced.value.lifecycle,
          productEpochs: active,
        };
      }
      throw error;
    }
    const outputEpochs = await revokedProductEpochs(this, input.command.enrollmentId);
    if (outputEpochs.length === 0)
      throw new Error('lane revocation commit produced no product epochs');
    return {
      outcome: 'applied',
      version: input.expectedVersion + 1,
      commandDigestB64u: input.commandDigestB64u,
      receipt,
      lifecycle,
      productEpochs: outputEpochs,
    };
  }

  private async getActiveProductEpochByActivation(
    walletKeyId: WalletKeyId,
    laneId: SigningLaneId,
    activationId: string,
  ): Promise<{
    readonly product: Extract<LaneProductEpochRecordV1, { state: 'active' }>;
    readonly version: number;
  } | null> {
    const row = await this.database
      .prepare(
        `SELECT product_json, version
           FROM ${PRODUCT_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND wallet_key_id = ?5 AND lane_id = ?6 AND target_material_activation_id = ?7
            AND state = 'active'`,
      )
      .bind(...scopeValues(this.scope), String(walletKeyId), String(laneId), activationId)
      .first<{ readonly product_json?: unknown; readonly version?: unknown }>();
    if (!row) return null;
    const product = parseProductEpochRecordV1(row.product_json);
    if (product.state !== 'active') return null;
    return { product, version: parseVersion(row.version, 'prior lane product epoch version') };
  }

  private protocolInsertStatement(
    record: LaneProtocolRecordV1,
    commandDigestB64u: string,
    now: number,
  ): D1PreparedStatementLike {
    const job = record.job;
    return this.database
      .prepare(
        `INSERT INTO ${OPERATION_TABLE} (
      namespace, org_id, project_id, env_id, operation_id, enrollment_id, wallet_id,
      wallet_key_id, source_lane_id, source_lane_share_epoch, source_revocation_epoch,
      target_lane_id, target_lane_share_epoch, target_material_activation_id,
      key_family, job_json, lifecycle_json, version, command_digest_b64u, created_at_ms, updated_at_ms
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 1, ?18, ?19, ?19)`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(job.operationId),
        String(job.enrollmentId),
        String(job.walletId),
        String(job.walletKeyId),
        String(job.source.laneId),
        String(job.source.laneShareEpoch),
        job.source.revocationEpoch,
        String(job.target.laneId),
        String(job.target.laneShareEpoch),
        String(job.targetMaterialActivationId),
        job.keyFamily,
        JSON.stringify(job),
        JSON.stringify(record.lifecycle),
        commandDigestB64u,
        now,
      );
  }

  private async updateProtocolLifecycle(input: LaneProtocolLifecycleCasInput): Promise<boolean> {
    const result = await this.database
      .prepare(
        `UPDATE ${OPERATION_TABLE} SET lifecycle_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?8 AND version = ?9`,
      )
      .bind(
        ...scopeValues(this.scope),
        JSON.stringify(input.lifecycle),
        input.commandDigestB64u,
        this.now(),
        String(input.operationId),
        input.expectedVersion,
      )
      .run();
    return d1ChangedRows(result) === 1;
  }

  private async updateEnrollmentLifecycle(
    input: LaneEnrollmentLifecycleCasInput,
  ): Promise<boolean> {
    const result = await this.database
      .prepare(
        `UPDATE ${ENROLLMENT_TABLE} SET lifecycle_json = ?5, version = version + 1, command_digest_b64u = ?6, updated_at_ms = ?7 WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND enrollment_id = ?8 AND version = ?9`,
      )
      .bind(
        ...scopeValues(this.scope),
        JSON.stringify(input.lifecycle),
        input.commandDigestB64u,
        this.now(),
        String(input.enrollmentId),
        input.expectedVersion,
      )
      .run();
    return d1ChangedRows(result) === 1;
  }

  private async getEnrollmentRevocationFenceDigest(
    enrollmentId: LaneEnrollmentId,
  ): Promise<string | null> {
    const row = await this.database
      .prepare(
        `SELECT revocation_fence_command_digest_b64u
           FROM ${ENROLLMENT_TABLE}
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND enrollment_id = ?5`,
      )
      .bind(...scopeValues(this.scope), String(enrollmentId))
      .first<{ readonly revocation_fence_command_digest_b64u?: unknown }>();
    if (!row || row.revocation_fence_command_digest_b64u === null) return null;
    return parseRequiredString(
      row.revocation_fence_command_digest_b64u,
      'revocation fence command digest',
    );
  }

  private async updateEnrollmentRevocationFence(
    enrollmentId: LaneEnrollmentId,
    expectedVersion: number,
    commandDigestB64u: string,
    lifecycle: LaneEnrollmentLifecycleV1,
  ): Promise<boolean> {
    const values = scopeValues(this.scope);
    try {
      const results = await this.database.batch([
        this.database
          .prepare(
            `UPDATE ${ENROLLMENT_TABLE}
                SET lifecycle_json = ?5,
                    version = version + 1,
                    command_digest_b64u = ?6,
                    revocation_fence_command_digest_b64u = ?7,
                    updated_at_ms = ?8
              WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
                AND enrollment_id = ?9 AND version = ?10`,
          )
          .bind(
            ...values,
            JSON.stringify(lifecycle),
            commandDigestB64u,
            commandDigestB64u,
            this.now(),
            String(enrollmentId),
            expectedVersion,
          ),
        this.database.prepare(LANE_CAS_GUARD_SQL),
      ]);
      assertD1Success(firstBatchResult(results, 0), 'lane enrollment revocation fence');
      return true;
    } catch {
      return false;
    }
  }

  private async putReceipt<
    T extends
      | LaneProtocolCommitReceiptV1
      | LaneHolderDeliveryReceiptV1
      | LaneServerActivationReceiptV1,
  >(
    operationId: LaneOperationId,
    enrollmentId: LaneEnrollmentId,
    kind: string,
    receipt: T,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<T>> {
    const row = await this.database
      .prepare(
        `SELECT receipt_id, receipt_kind, receipt_digest_b64u, receipt_json FROM ${RECEIPT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?5 AND receipt_kind = ?6`,
      )
      .bind(...scopeValues(this.scope), String(operationId), kind)
      .first<{
        readonly receipt_id?: unknown;
        readonly receipt_kind?: unknown;
        readonly receipt_digest_b64u?: unknown;
        readonly receipt_json?: unknown;
      }>();
    const digest = await exactReceiptDigest(kind, receipt);
    if (row) {
      if (
        parseRequiredString(row.receipt_digest_b64u, 'receipt digest') === digest &&
        equalLaneRecords(parseJsonRecord(row.receipt_json, 'receipt'), receipt)
      )
        return { outcome: 'replayed', version: 1, commandDigestB64u, value: receipt };
      return {
        outcome: 'conflict',
        expectedVersion: null,
        actualVersion: 1,
        requestedCommandDigestB64u: commandDigestB64u,
        storedCommandDigestB64u: parseRequiredString(row.receipt_digest_b64u, 'receipt digest'),
      };
    }
    const insert = this.database
      .prepare(
        `INSERT INTO ${RECEIPT_TABLE} (namespace, org_id, project_id, env_id, receipt_id, enrollment_id, operation_id, receipt_kind, receipt_digest_b64u, receipt_json, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
      )
      .bind(
        ...scopeValues(this.scope),
        `${String(operationId)}:${kind}`,
        String(enrollmentId),
        String(operationId),
        kind,
        digest,
        JSON.stringify(receipt),
        this.now(),
      );
    try {
      const results = await this.database.batch([
        insert,
        this.database.prepare(LANE_CAS_GUARD_SQL),
      ]);
      assertD1Success(firstBatchResult(results, 0), `lane ${kind} receipt admission`);
      return { outcome: 'applied', version: 1, commandDigestB64u, value: receipt };
    } catch (error: unknown) {
      const raced = await this.database
        .prepare(
          `SELECT receipt_digest_b64u, receipt_json FROM ${RECEIPT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?5 AND receipt_kind = ?6`,
        )
        .bind(...scopeValues(this.scope), String(operationId), kind)
        .first<{ readonly receipt_digest_b64u?: unknown; readonly receipt_json?: unknown }>();
      if (raced && parseRequiredString(raced.receipt_digest_b64u, 'receipt digest') === digest)
        return { outcome: 'replayed', version: 1, commandDigestB64u, value: receipt };
      if (raced)
        return {
          outcome: 'conflict',
          expectedVersion: null,
          actualVersion: 1,
          requestedCommandDigestB64u: commandDigestB64u,
          storedCommandDigestB64u: parseRequiredString(raced.receipt_digest_b64u, 'receipt digest'),
        };
      throw error;
    }
  }

  private async readAndVerifyServerRetirementReceipt(
    product: Extract<LaneProductEpochRecordV1, { state: 'revoked' }>,
    command: RevokeSigningLaneV1,
  ): Promise<LaneServerRetirementReceiptV1> {
    const row = await this.database
      .prepare(
        `SELECT receipt_id, receipt_digest_b64u, receipt_json FROM ${RECEIPT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?5 AND receipt_kind = ?6`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(product.operationId),
        serverRetirementReceiptKind(product),
      )
      .first<{
        readonly receipt_id?: unknown;
        readonly receipt_digest_b64u?: unknown;
        readonly receipt_json?: unknown;
      }>();
    if (!row) throw new Error('revoked lane has no persisted server retirement receipt');
    if (
      parseRequiredString(row.receipt_id, 'server retirement receipt id') !==
      serverRetirementReceiptId(product)
    ) {
      throw new Error('server retirement receipt id differs from the revoked lane epoch');
    }
    const receipt = parseLaneServerRetirementReceiptV1(
      parseJsonRecord(row.receipt_json, 'server retirement receipt'),
    );
    const digest = await verifyServerRetirementReceiptV1({
      store: this,
      product,
      command,
      receipt,
    });
    if (
      parseRequiredString(row.receipt_digest_b64u, 'server retirement receipt digest') !== digest ||
      product.revocationReceiptDigestB64u !== digest
    ) {
      throw new Error('persisted server retirement receipt digest is invalid');
    }
    return receipt;
  }

  private async readReceipt(
    operationId: LaneOperationId,
    kind: string,
  ): Promise<
    LaneProtocolCommitReceiptV1 | LaneHolderDeliveryReceiptV1 | LaneServerActivationReceiptV1 | null
  > {
    const row = await this.database
      .prepare(
        `SELECT receipt_json FROM ${RECEIPT_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND operation_id = ?5 AND receipt_kind = ?6`,
      )
      .bind(...scopeValues(this.scope), String(operationId), kind)
      .first<{ readonly receipt_json?: unknown }>();
    if (!row) return null;
    const receiptRecord = parseJsonRecord(row.receipt_json, 'lane receipt');
    switch (kind) {
      case 'lane_protocol_commit':
        return parseLaneProtocolCommitReceiptV1(receiptRecord);
      case 'lane_holder_delivery':
        return parseLaneHolderDeliveryReceiptV1(receiptRecord);
      case 'lane_server_activation':
        return parseLaneServerActivationReceiptV1(receiptRecord);
      default:
        throw new Error(`unknown lane receipt kind ${kind}`);
    }
  }
}

async function verifyServerRetirementReceiptV1(input: {
  readonly store: Pick<CloudflareD1LaneLifecycleStore, 'getProtocol'>;
  readonly product: Extract<LaneProductEpochRecordV1, { state: 'revocation_pending' | 'revoked' }>;
  readonly command: RevokeSigningLaneV1;
  readonly receipt: LaneServerRetirementReceiptV1;
}): Promise<string> {
  const protocol = await input.store.getProtocol(input.product.operationId);
  if (protocol === null)
    throw new Error('server retirement receipt has no exact protocol operation');
  const job = protocol.value.job;
  const receipt = input.receipt;
  if (receipt.kind === 'ed25519_server_retirement_receipt_v1') {
    if (
      job.keyFamily !== 'ed25519' ||
      input.product.keyFamily !== 'ed25519' ||
      protocol.value.lifecycle.state !== 'active'
    ) {
      throw new Error('Ed25519 server retirement receipt has no active protocol operation');
    }
    const identity = receipt.identity;
    if (
      String(input.product.walletId) !== String(input.command.walletId) ||
      identity.operationId !== input.product.operationId ||
      identity.enrollmentId !== input.product.enrollmentId ||
      identity.walletId !== input.product.walletId ||
      identity.walletKeyId !== input.command.walletKeyId ||
      identity.targetLaneId !== input.command.laneId ||
      identity.targetLaneShareEpoch !== input.command.laneShareEpoch ||
      identity.targetMaterialActivationId !== input.product.targetMaterialActivationId ||
      identity.keyFamily !== 'ed25519' ||
      identity.holderParticipantBindingDigestB64u !==
        input.product.holderParticipant.participantBindingDigestB64u ||
      identity.signingWorkerParticipantBindingDigestB64u !==
        input.product.signingWorkerParticipant.participantBindingDigestB64u ||
      identity.holderRecipientKeyDigestB64u !== job.targetHolder.hpkePublicKeyDigestB64u ||
      identity.serverRecipientKeyDigestB64u !== job.targetSigningWorker.hpkePublicKeyDigestB64u ||
      identity.transcriptHashB64u !== protocol.value.lifecycle.transcriptHashB64u ||
      identity.protocolCommitReceiptDigestB64u !==
        protocol.value.lifecycle.protocolCommitReceiptDigestB64u ||
      receipt.revocationEpoch !== input.command.expectedRevocationEpoch ||
      receipt.retirementReason !== retirementReceiptReasonV1(input.command.reason) ||
      receipt.retirementCorrelationId !== input.command.retirementCorrelationId ||
      receipt.retirementRequestDigestB64u !== input.command.retirementRequestDigestB64u ||
      input.product.revocationEpoch !== input.command.expectedRevocationEpoch + 1
    ) {
      throw new Error('Ed25519 server retirement receipt differs from the frozen lane epoch');
    }
    const digest = await computeEd25519ServerRetirementReceiptDigestV1(receipt);
    if (receipt.receiptDigestB64u !== digest) {
      throw new Error('Ed25519 server retirement receipt self-digest is invalid');
    }
    return digest;
  }
  if (job.keyFamily !== 'ecdsa_secp256k1' || input.product.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA server retirement receipt has no exact protocol operation');
  }
  if (
    String(input.product.walletId) !== String(input.command.walletId) ||
    String(receipt.manifest.manifestId) !== String(job.targetCapability.manifestId) ||
    receipt.manifest.manifestRevision !== job.targetCapability.manifestRevision ||
    !mpcMaterialActivationRefsEqual(receipt.materialActivation, input.product.materialActivation) ||
    String(receipt.walletKeyId) !== String(input.command.walletKeyId) ||
    String(receipt.laneId) !== String(input.command.laneId) ||
    String(receipt.laneShareEpoch) !== String(input.command.laneShareEpoch) ||
    receipt.revocationEpoch !== input.command.expectedRevocationEpoch ||
    receipt.retirementReason !== retirementReceiptReasonV1(input.command.reason) ||
    String(receipt.retirementCorrelationId) !== String(input.command.retirementCorrelationId) ||
    receipt.retirementRequestDigestB64u !== input.command.retirementRequestDigestB64u ||
    String(receipt.serverGeneration) !== String(job.sourceCapability.serverGeneration) ||
    String(receipt.lifecycleId) !== String(input.product.materialActivation.lifecycleBinding) ||
    input.product.revocationEpoch !== input.command.expectedRevocationEpoch + 1
  ) {
    throw new Error('ECDSA server retirement receipt differs from the frozen lane epoch');
  }
  const digest = await computeEcdsaServerRetirementReceiptDigestV1(receipt);
  if (receipt.receiptDigestB64u !== digest) {
    throw new Error('ECDSA server retirement receipt self-digest is invalid');
  }
  return digest;
}

function retirementReceiptReasonV1(
  reason: RevokeSigningLaneV1['reason'],
): LaneServerRetirementReceiptV1['retirementReason'] {
  switch (reason) {
    case 'user_revoked':
    case 'policy_revoked':
      return 'lane_revoked';
    case 'device_compromise':
      return 'device_compromise';
    case 'agent_compromise':
      return 'agent_compromise';
    case 'rotation':
      return 'rotation';
  }
}

function serverRetirementReceiptId(product: LaneProductEpochRecordV1): string {
  return `${String(product.operationId)}:${serverRetirementReceiptKind(product)}:${String(product.laneId)}:${String(product.laneShareEpoch)}`;
}

function serverRetirementReceiptKind(
  product: LaneProductEpochRecordV1,
): 'ed25519_server_retirement' | 'ecdsa_server_retirement' {
  switch (product.keyFamily) {
    case 'ed25519':
      return 'ed25519_server_retirement';
    case 'ecdsa_secp256k1':
      return 'ecdsa_server_retirement';
  }
}

async function admissionChildrenMatch(
  store: Pick<LaneLifecycleStore, 'getProtocol'>,
  children: readonly LaneProtocolRecordV1[],
): Promise<boolean> {
  for (const child of children) {
    const stored = await store.getProtocol(child.job.operationId);
    if (!stored || !equalLaneRecords(stored.value, child)) return false;
  }
  return true;
}

function validateChildrenAgainstManifest(
  manifest: LaneEnrollmentManifestV1,
  children: readonly LaneProtocolRecordV1[],
): void {
  for (const entry of manifest.orderedChildren) {
    const child = children.find(
      (candidate) => String(candidate.job.operationId) === String(entry.operationId),
    );
    if (!child) throw new Error(`lane enrollment child ${String(entry.operationId)} is missing`);
    if (
      String(child.job.walletId) !== String(manifest.walletId) ||
      String(child.job.walletKeyId) !== String(entry.walletKeyId) ||
      String(child.job.source.laneId) !== String(entry.sourceLaneId) ||
      String(child.job.target.laneId) !== String(entry.targetLaneId) ||
      String(child.job.targetMaterialActivationId) !== String(entry.targetMaterialActivationId)
    )
      throw new Error(`lane enrollment child ${String(entry.operationId)} does not match manifest`);
  }
}

function assertNeverEnrollmentLifecycle(value: never): never {
  throw new Error(`Unhandled lane enrollment lifecycle ${JSON.stringify(value)}`);
}

function resolveReadyEnrollmentLifecycle(
  current: LaneEnrollmentLifecycleV1,
  input: CommitLaneEnrollmentActivationV1,
  aggregateDigest: string,
): Extract<LaneEnrollmentLifecycleV1, { state: 'ready_for_visibility' }> | null {
  if (current.state === 'ready_for_visibility') {
    if (current.manifestDigestB64u !== input.manifestDigestB64u) return null;
    return current;
  }
  if (current.state === 'preparing') {
    const operationIds = input.orderedChildReceipts.map((child) => child.operationId);
    const first = operationIds[0];
    if (!first) return null;
    const committed = transitionLaneEnrollmentLifecycleV1(current, {
      action: 'mark_committed_completion_required',
      committedChildOperationIds: [first, ...operationIds.slice(1)],
      markedAtMs: input.activatedAtMs,
    });
    if (committed.state !== 'committed_completion_required') return null;
    const ready = transitionLaneEnrollmentLifecycleV1(committed, {
      action: 'mark_ready_for_visibility',
      aggregateReceiptDigestB64u: aggregateDigest,
      readyAtMs: input.activatedAtMs,
    });
    return ready.state === 'ready_for_visibility' ? ready : null;
  }
  if (current.state === 'committed_completion_required') {
    const ready = transitionLaneEnrollmentLifecycleV1(current, {
      action: 'mark_ready_for_visibility',
      aggregateReceiptDigestB64u: aggregateDigest,
      readyAtMs: input.activatedAtMs,
    });
    return ready.state === 'ready_for_visibility' ? ready : null;
  }
  return null;
}

function validateActivationReceiptAgainstManifest(
  manifest: LaneEnrollmentManifestV1,
  receipt: AggregateLaneActivationReceiptV1,
): void {
  if (manifest.orderedChildren.length !== receipt.orderedChildReceipts.length) {
    throw new Error('aggregate activation child count differs from enrollment manifest');
  }
  for (let index = 0; index < manifest.orderedChildren.length; index += 1) {
    const expected = manifest.orderedChildren[index];
    const actual = receipt.orderedChildReceipts[index];
    if (!expected || !actual) throw new Error('aggregate activation child order is invalid');
    if (
      String(expected.operationId) !== String(actual.operationId) ||
      String(expected.walletKeyId) !== String(actual.walletKeyId) ||
      String(expected.targetLaneId) !== String(actual.targetLaneId) ||
      String(expected.targetLaneShareEpoch) !== String(actual.targetLaneShareEpoch) ||
      String(expected.targetMaterialActivationId) !==
        String(actual.targetMaterialActivation.activationId)
    ) {
      throw new Error('aggregate activation child differs from enrollment manifest');
    }
  }
}

function assertProtocolCommitReceiptIdentity(
  protocol: LaneProtocolRecordV1,
  receipt: LaneProtocolCommitReceiptV1,
): void {
  const job = protocol.job;
  if (
    String(receipt.enrollmentId) !== String(job.enrollmentId) ||
    String(receipt.walletId) !== String(job.walletId) ||
    String(receipt.walletKeyId) !== String(job.walletKeyId) ||
    String(receipt.sourceLaneId) !== String(job.source.laneId) ||
    String(receipt.sourceLaneShareEpoch) !== String(job.source.laneShareEpoch) ||
    receipt.sourceRevocationEpoch !== job.source.revocationEpoch ||
    !mpcMaterialActivationRefsEqual(
      receipt.sourceMaterialActivation,
      job.source.materialActivation,
    ) ||
    String(receipt.targetLaneId) !== String(job.target.laneId) ||
    String(receipt.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(receipt.targetMaterialActivationId) !== String(job.targetMaterialActivationId) ||
    receipt.keyFamily !== job.keyFamily
  ) {
    throw new Error('lane protocol commit receipt does not match its admitted operation');
  }
}

function assertHolderDeliveryReceiptIdentity(
  protocol: LaneProtocolRecordV1,
  receipt: LaneHolderDeliveryReceiptV1,
): void {
  const job = protocol.job;
  if (
    String(receipt.enrollmentId) !== String(job.enrollmentId) ||
    String(receipt.targetLaneId) !== String(job.target.laneId) ||
    String(receipt.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(receipt.targetMaterialActivationId) !== String(job.targetMaterialActivationId) ||
    receipt.holderParticipantBindingDigestB64u !== job.targetHolder.participantBindingDigestB64u ||
    receipt.holderRecipientKeyDigestB64u !== job.targetHolder.hpkePublicKeyDigestB64u
  ) {
    throw new Error('lane holder delivery receipt does not match its admitted operation');
  }
  if (
    protocol.lifecycle.state !== 'committed_awaiting_holder_delivery' &&
    protocol.lifecycle.state !== 'awaiting_server_activation' &&
    protocol.lifecycle.state !== 'ready_for_parent_visibility' &&
    protocol.lifecycle.state !== 'active'
  ) {
    throw new Error('lane holder delivery receipt is not valid for this lifecycle');
  }
  if (protocol.lifecycle.transcriptHashB64u !== receipt.transcriptHashB64u) {
    throw new Error(
      'lane holder delivery receipt transcript differs from the committed transcript',
    );
  }
}

function assertServerActivationReceiptIdentity(
  protocol: LaneProtocolRecordV1,
  receipt: LaneServerActivationReceiptV1,
): void {
  const job = protocol.job;
  if (
    String(receipt.enrollmentId) !== String(job.enrollmentId) ||
    String(receipt.targetLaneId) !== String(job.target.laneId) ||
    String(receipt.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(receipt.targetMaterialActivation.activationId) !==
      String(job.targetMaterialActivationId) ||
    String(receipt.targetMaterialActivation.signingWorker) !==
      String(job.targetSigningWorker.participantId) ||
    receipt.signingWorkerParticipantBindingDigestB64u !==
      job.targetSigningWorker.participantBindingDigestB64u
  ) {
    throw new Error('lane server activation receipt does not match its admitted operation');
  }
  if (
    protocol.lifecycle.state !== 'awaiting_server_activation' &&
    protocol.lifecycle.state !== 'ready_for_parent_visibility' &&
    protocol.lifecycle.state !== 'active'
  ) {
    throw new Error('lane server activation receipt is not valid for this lifecycle');
  }
  if (protocol.lifecycle.transcriptHashB64u !== receipt.transcriptHashB64u) {
    throw new Error(
      'lane server activation receipt transcript differs from the committed transcript',
    );
  }
}

async function exactReceiptDigest(
  kind: string,
  receipt:
    | LaneProtocolCommitReceiptV1
    | LaneHolderDeliveryReceiptV1
    | LaneServerActivationReceiptV1,
): Promise<string> {
  switch (kind) {
    case 'lane_protocol_commit':
      if (receipt.kind !== 'lane_protocol_commit_receipt_v1')
        throw new Error('receipt kind does not match lane protocol commit');
      return base64UrlEncode(await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt)));
    case 'lane_holder_delivery':
      if (receipt.kind !== 'lane_holder_delivery_receipt_v1')
        throw new Error('receipt kind does not match holder delivery');
      return base64UrlEncode(await sha256Bytes(encodeLaneHolderDeliveryReceiptV1(receipt)));
    case 'lane_server_activation':
      if (receipt.kind !== 'lane_server_activation_receipt_v1')
        throw new Error('receipt kind does not match server activation');
      return base64UrlEncode(await sha256Bytes(encodeLaneServerActivationReceiptV1(receipt)));
    default:
      throw new Error(`unknown receipt kind ${kind}`);
  }
}

function parseProductEpochRecordV1(raw: unknown): LaneProductEpochRecordV1 {
  return parseLaneProductEpochRecordV1(
    parseJsonRecord(raw, 'lane product epoch'),
    'lane product epoch',
  );
}

async function buildPendingProductEpoch(input: {
  readonly protocol: LaneProtocolRecordV1;
  readonly protocolReceipt: LaneProtocolCommitReceiptV1;
  readonly holderReceipt: LaneHolderDeliveryReceiptV1;
  readonly serverReceipt: LaneServerActivationReceiptV1;
  readonly manifestDigestB64u: string;
}): Promise<Extract<LaneProductEpochRecordV1, { state: 'pending_visibility' }>> {
  const target = input.protocol.job.target;
  const holderParticipant = {
    kind: 'lane_holder_participant_v1' as const,
    participantId: input.protocol.job.targetHolder.participantId,
    custodyBindingId: input.protocol.job.targetHolder.custodyBindingId,
    custodyBindingDigestB64u: input.protocol.job.targetHolder.custodyBindingDigestB64u,
    hpkePublicKeyB64u: input.protocol.job.targetHolder.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: input.protocol.job.targetHolder.hpkePublicKeyDigestB64u,
    participantBindingDigestB64u: input.protocol.job.targetHolder.participantBindingDigestB64u,
  };
  const signingWorkerParticipant = {
    kind: 'signing_worker_participant_v1' as const,
    participantId: input.protocol.job.targetSigningWorker.participantId,
    recipientKeyId: input.protocol.job.targetSigningWorker.recipientKeyId,
    hpkePublicKeyB64u: input.protocol.job.targetSigningWorker.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: input.protocol.job.targetSigningWorker.hpkePublicKeyDigestB64u,
    participantBindingDigestB64u:
      input.protocol.job.targetSigningWorker.participantBindingDigestB64u,
  };
  const participantSetBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
    holderParticipant,
    signingWorkerParticipant,
  });
  return buildLaneProductEpochPendingVisibilityV1({
    walletId: input.protocol.job.walletId,
    walletKeyId: input.protocol.job.walletKeyId,
    laneId: target.laneId,
    laneKind: target.laneKind,
    laneShareEpoch: target.laneShareEpoch,
    keyFamily: input.protocol.job.keyFamily,
    enrollmentId: input.protocol.job.enrollmentId,
    operationId: input.protocol.job.operationId,
    targetMaterialActivationId: input.protocol.job.targetMaterialActivationId,
    materialActivation: input.serverReceipt.targetMaterialActivation,
    publicIdentityDigestB64u: input.protocolReceipt.publicIdentityDigestB64u,
    holderParticipant,
    signingWorkerParticipant,
    participantSetBindingDigestB64u,
    revocationEpoch: input.protocol.job.source.revocationEpoch,
    createdAtMs: input.protocolReceipt.committedAtMs,
    aggregateManifestDigestB64u: input.manifestDigestB64u,
    protocolCommitReceiptDigestB64u: base64UrlEncode(
      await sha256Bytes(encodeLaneProtocolCommitReceiptV1(input.protocolReceipt)),
    ),
    holderDeliveryReceiptDigestB64u: base64UrlEncode(
      await sha256Bytes(encodeLaneHolderDeliveryReceiptV1(input.holderReceipt)),
    ),
    serverActivationReceiptDigestB64u: base64UrlEncode(
      await sha256Bytes(encodeLaneServerActivationReceiptV1(input.serverReceipt)),
    ),
    pendingSinceMs: input.serverReceipt.activatedAtMs,
  });
}

async function activeProductEpochs(
  store: CloudflareD1LaneLifecycleStore,
  enrollmentId: LaneEnrollmentId,
): Promise<
  readonly [
    Extract<LaneProductEpochRecordV1, { state: 'active' }>,
    ...Extract<LaneProductEpochRecordV1, { state: 'active' }>[],
  ]
> {
  const values = (await store.listEnrollmentProductEpochs(enrollmentId)).filter(
    (value): value is Extract<LaneProductEpochRecordV1, { state: 'active' }> =>
      value.state === 'active',
  );
  if (values.length === 0) throw new Error('no active product epochs');
  return values as [
    Extract<LaneProductEpochRecordV1, { state: 'active' }>,
    ...Extract<LaneProductEpochRecordV1, { state: 'active' }>[],
  ];
}

async function revokedProductEpochs(
  store: CloudflareD1LaneLifecycleStore,
  enrollmentId: LaneEnrollmentId,
): Promise<
  readonly [
    Extract<LaneProductEpochRecordV1, { state: 'revoked' }>,
    ...Extract<LaneProductEpochRecordV1, { state: 'revoked' }>[],
  ]
> {
  const values = (await store.listEnrollmentProductEpochs(enrollmentId)).filter(
    (value): value is Extract<LaneProductEpochRecordV1, { state: 'revoked' }> =>
      value.state === 'revoked',
  );
  if (values.length === 0) throw new Error('no revoked product epochs');
  return values as [
    Extract<LaneProductEpochRecordV1, { state: 'revoked' }>,
    ...Extract<LaneProductEpochRecordV1, { state: 'revoked' }>[],
  ];
}
