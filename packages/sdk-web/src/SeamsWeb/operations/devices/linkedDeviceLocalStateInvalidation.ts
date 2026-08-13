import type { LinkedDeviceRevokeResultV1 } from '@shared/device-linking';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import { parseLaneEnrollmentId, type LaneEnrollmentId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type { LaneSealedHolderMaterialRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type { LinkedDeviceWalletSessionRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type { LinkedDeviceExecutionEvidenceRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore';

export type LinkedDeviceSuccessfulRevokeResultV1 = Extract<
  LinkedDeviceRevokeResultV1,
  { readonly kind: 'revoked' | 'replayed' }
>;

export type LinkedDeviceLocalStateInvalidationPortV1 = {
  invalidateLinkedDeviceStateV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
    readonly requestedAtMs: number;
    readonly result: LinkedDeviceSuccessfulRevokeResultV1;
  }): Promise<void>;
};

export type LinkedDeviceLocalStateInvalidationOptionsV1 = {
  readonly holderRepository: Pick<
    LaneSealedHolderMaterialRepositoryV1,
    'listForEnrollmentV1' | 'delete'
  >;
  readonly walletSessionRepository: Pick<
    LinkedDeviceWalletSessionRepositoryV1,
    'readActiveForEnrollmentV1' | 'clearEnrollmentV1'
  >;
  readonly executionEvidenceRepository: Pick<
    LinkedDeviceExecutionEvidenceRepositoryV1,
    'readForEnrollmentV1' | 'clearEnrollmentV1'
  >;
};

function laneEnrollmentId(value: LinkedDeviceEnrollmentId): LaneEnrollmentId {
  const parsed = parseLaneEnrollmentId(String(value));
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function assertIdentity(input: {
  readonly walletId: WalletId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly result: LinkedDeviceSuccessfulRevokeResultV1;
  readonly evidence: {
    readonly approval: {
      readonly walletId: WalletId;
      readonly deviceId: LinkedDeviceId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
    };
    readonly enrollmentReceipt: {
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly walletId: WalletId;
      readonly deviceId: LinkedDeviceId;
      readonly aggregateReceiptDigestB64u: string;
    };
  };
}): void {
  if (
    input.evidence.approval.walletId !== input.walletId ||
    input.evidence.approval.deviceId !== input.deviceId ||
    String(input.evidence.approval.enrollmentId) !== String(input.enrollmentId) ||
    input.evidence.enrollmentReceipt.walletId !== input.walletId ||
    input.evidence.enrollmentReceipt.deviceId !== input.deviceId ||
    String(input.evidence.enrollmentReceipt.enrollmentId) !== String(input.enrollmentId) ||
    input.evidence.enrollmentReceipt.aggregateReceiptDigestB64u !==
      input.result.aggregateReceiptDigestB64u
  ) {
    throw new Error('linked-device local invalidation identity does not match revocation');
  }
}

export function createLinkedDeviceLocalStateInvalidationPortV1(
  options: LinkedDeviceLocalStateInvalidationOptionsV1,
): LinkedDeviceLocalStateInvalidationPortV1 {
  return {
    invalidateLinkedDeviceStateV1: async (input) => {
      const enrollmentId = input.result.enrollmentId;
      const evidence = await options.executionEvidenceRepository.readForEnrollmentV1(enrollmentId);
      if (evidence.kind === 'corrupt' || evidence.kind === 'persistence_unavailable') {
        throw new Error(`linked-device execution evidence cannot be invalidated: ${evidence.kind}`);
      }

      const walletSession = await options.walletSessionRepository.readActiveForEnrollmentV1({
        enrollmentId,
        nowMs: input.requestedAtMs,
      });
      if (walletSession.kind === 'corrupt' || walletSession.kind === 'persistence_unavailable') {
        throw new Error(
          `linked-device Wallet Session cannot be invalidated: ${walletSession.kind}`,
        );
      }

      const holderRecords = await options.holderRepository.listForEnrollmentV1({
        enrollmentId: laneEnrollmentId(enrollmentId),
      });
      if (evidence.kind === 'missing') {
        if (walletSession.kind === 'found' || holderRecords.length > 0) {
          throw new Error('linked-device execution evidence is required for exact invalidation');
        }
        return;
      }

      if (evidence.kind !== 'found') {
        throw new Error(`linked-device execution evidence cannot be invalidated: ${evidence.kind}`);
      }
      assertIdentity({
        walletId: input.walletId,
        deviceId: input.deviceId,
        enrollmentId,
        result: input.result,
        evidence: evidence.evidence,
      });
      if (
        walletSession.kind === 'found' &&
        (walletSession.delivery.walletId !== input.walletId ||
          walletSession.delivery.deviceId !== input.deviceId ||
          String(walletSession.delivery.enrollmentId) !== String(enrollmentId))
      ) {
        throw new Error('linked-device Wallet Session identity does not match revocation');
      }
      for (const record of holderRecords) {
        if (
          record.walletId !== input.walletId ||
          String(record.enrollmentId) !== String(enrollmentId)
        ) {
          throw new Error('linked-device holder identity does not match revocation');
        }
      }

      for (const record of holderRecords) {
        await options.holderRepository.delete({
          operationId: record.operationId,
          enrollmentId: record.enrollmentId,
          targetLaneId: record.laneId,
          targetLaneShareEpoch: record.laneShareEpoch,
          targetMaterialActivationId: record.targetMaterialActivationId,
        });
      }
      await options.walletSessionRepository.clearEnrollmentV1(enrollmentId);
      await options.executionEvidenceRepository.clearEnrollmentV1(enrollmentId);
    },
  };
}
