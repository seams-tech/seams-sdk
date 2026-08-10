import { expect, test } from '@playwright/test';
import { deliverLaneHolderPackageV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/operations/holderDeliveryCoordinator';
import {
  prepareLaneHolderRecipientV1,
  sealLaneHolderMaterialV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/lanes/operations/recipientPreparation';
import type {
  LaneEnrollmentGatewayV1,
  LaneHolderPackageWireV1,
  LaneHolderRecipientWorkerV1,
  LaneProtocolCasResultV1,
} from '../../packages/shared-ts/src/signing-lanes/rotation';
import type { LaneSealedHolderRecordV1 } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import { LaneSealedHolderMaterialRepository } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import { SigningSessionSealsRepository } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/signingSessionSeals';
import { parseLaneHolderPackageWireV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { parseLaneHolderRecipientHandleV1 } from '../../packages/shared-ts/src/utils/domainIds';
import {
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';

const DIGEST_B64U = Buffer.alloc(32, 0).toString('base64url');
const SEALED_MATERIAL_B64U = Buffer.from('sealed-holder-material').toString('base64url');

function value<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function holderPackage(): LaneHolderPackageWireV1 {
  return parseLaneHolderPackageWireV1({
    kind: 'ed25519_yao_lane_holder_package_set_v1',
    deriverAEncryptedPackageJson: '{}',
    deriverBEncryptedPackageJson: '{}',
  });
}

function casResult(): LaneProtocolCasResultV1 {
  return {
    outcome: 'conflict',
    expectedVersion: 1,
    actualVersion: 2,
    requestedCommandDigestB64u: DIGEST_B64U,
    storedCommandDigestB64u: DIGEST_B64U,
  };
}

function unsupported(): Promise<never> {
  return Promise.reject(new Error('unsupported test gateway operation'));
}

class UnavailableSigningSessionSealsRepository extends SigningSessionSealsRepository {
  override async putSealedRecord(): Promise<boolean> {
    return false;
  }
}

function gateway(calls: { holderDeliveries: number[] }): LaneEnrollmentGatewayV1 {
  return {
    prepareLaneEnrollmentV1: unsupported,
    resumeLaneProtocolOperationV1: unsupported,
    recordLaneProtocolCommitV1: unsupported,
    recordLaneHolderDeliveryV1: async () => {
      calls.holderDeliveries.push(1);
      return casResult();
    },
    activateLaneServerMaterialV1: unsupported,
    commitLaneEnrollmentActivationV1: unsupported,
    revokeSigningLaneV1: unsupported,
    revokeLaneEnrollmentV1: unsupported,
  };
}

test.describe('R102 holder delivery worker boundary', () => {
  test('replays through worker verification and frees the handle on persistence failure', async () => {
    const job = buildR102LaneJob('holder-delivery');
    const commit = buildR102ProtocolCommitReceipt(job);
    const packageWire = holderPackage();
    const recipientHandle = value(parseLaneHolderRecipientHandleV1('recipient-handle:r102'));
    const discardCalls: string[] = [];
    const verifyCalls: number[] = [];
    const openCalls: number[] = [];
    const worker: LaneHolderRecipientWorkerV1 = {
      createLaneHolderRecipientV1: async () => ({
        recipientHandle,
        hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
        hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      }),
      openAndSealLaneHolderPackageV1: async () => {
        openCalls.push(1);
        return {
          sealedHolderMaterialB64u: SEALED_MATERIAL_B64U,
          sealedHolderRecordDigestB64u: DIGEST_B64U,
          verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U,
        };
      },
      verifyLaneHolderPackageCommitmentV1: async () => {
        verifyCalls.push(1);
        return { verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U };
      },
      discardLaneHolderRecipientV1: async () => {
        discardCalls.push('discard');
      },
      invalidateLaneMaterialV1: async () => undefined,
    };
    const prepared = await prepareLaneHolderRecipientV1({
      input: {
        operationId: job.operationId,
        enrollmentId: job.enrollmentId,
        targetLaneId: job.target.laneId,
        targetLaneShareEpoch: job.target.laneShareEpoch,
        targetHolderParticipantId: job.targetHolder.participantId,
        targetHolderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
        custodyBindingId: job.targetHolder.custodyBindingId,
        custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      },
      worker,
    });
    const repository = {
      async put(): Promise<void> {
        throw new Error('persistence unavailable');
      },
      async get(): Promise<null> {
        return null;
      },
      async delete(): Promise<void> {},
    };
    await expect(
      sealLaneHolderMaterialV1({
        state: prepared,
        job,
        protocolCommitReceipt: commit,
        holderPackage: packageWire,
        repository,
        worker,
        acknowledgedAtMs: 4_000,
      }),
    ).rejects.toThrow('persistence unavailable');
    expect(openCalls).toHaveLength(1);
    expect(discardCalls).toHaveLength(1);

    const replayRepository = {
      record: null as LaneSealedHolderRecordV1 | null,
      async put(record: LaneSealedHolderRecordV1): Promise<void> {
        this.record = record;
      },
      async get(): Promise<LaneSealedHolderRecordV1 | null> {
        return this.record;
      },
      async delete(): Promise<void> {},
    };
    const secondPrepared = await prepareLaneHolderRecipientV1({
      input: {
        operationId: job.operationId,
        enrollmentId: job.enrollmentId,
        targetLaneId: job.target.laneId,
        targetLaneShareEpoch: job.target.laneShareEpoch,
        targetHolderParticipantId: job.targetHolder.participantId,
        targetHolderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
        custodyBindingId: job.targetHolder.custodyBindingId,
        custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      },
      worker,
    });
    await sealLaneHolderMaterialV1({
      state: secondPrepared,
      job,
      protocolCommitReceipt: commit,
      holderPackage: packageWire,
      repository: replayRepository,
      worker,
      acknowledgedAtMs: 4_000,
    });
    const holderDeliveries: number[] = [];
    const replay = await deliverLaneHolderPackageV1({
      job,
      protocolCommitReceipt: commit,
      holderPackage: packageWire,
      expectedVersion: 1,
      worker,
      gateway: gateway({ holderDeliveries }),
      repository: replayRepository,
      nowMs: () => 5_000,
    });
    expect(replay.replayed).toBe(true);
    expect(verifyCalls).toHaveLength(1);
    expect(openCalls).toHaveLength(2);
    expect(holderDeliveries).toEqual([1]);

    if (!replayRepository.record) throw new Error('expected sealed holder material fixture');
    const durableRepository = new LaneSealedHolderMaterialRepository(
      new UnavailableSigningSessionSealsRepository(),
    );
    await expect(durableRepository.put(replayRepository.record)).rejects.toThrow(
      'Canonical lane holder material persistence is unavailable',
    );
  });
});
