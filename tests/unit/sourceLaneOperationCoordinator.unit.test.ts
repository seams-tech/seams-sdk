import { expect, test } from '@playwright/test';
import { prepareAndCommitSourceLaneOperationV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/operations/sourceLaneOperationCoordinator';
import type { LaneOperationSourcePortsV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/operations/ports';
import { encodeLaneProtocolCommitReceiptV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import type {
  EcdsaAdditiveLaneHolderRoundV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotation';
import { parseEcdsaAdditiveLaneHolderRoundV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import {
  buildR102MixedLaneEnrollmentFixture,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32));
const SECP256K1_GENERATOR_B64U = base64UrlEncode(
  Uint8Array.from(
    Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'),
  ),
);

function ecdsaHolderRound(): EcdsaAdditiveLaneHolderRoundV1 {
  return parseEcdsaAdditiveLaneHolderRoundV1({
    kind: 'ecdsa_additive_lane_holder_round_v1',
    preambleHashB64u: DIGEST_B64U,
    targetHolderPublicCommitment33B64u: SECP256K1_GENERATOR_B64U,
    encryptedDeltaCiphertextDigestB64u: DIGEST_B64U,
    sealedTargetHolderMaterialDigestB64u: DIGEST_B64U,
    holderAttestationB64u: 'holder-attestation-r102',
    holderCommittedAtMs: 2_000,
  });
}

async function committedResult(
  job: RotatableSigningLaneJobV1,
  receipt: LaneProtocolCommitReceiptV1,
): Promise<LaneProtocolCasResultV1> {
  const commandDigestB64u = base64UrlEncode(
    await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt)),
  );
  return {
    outcome: 'applied',
    version: 2,
    commandDigestB64u,
    record: {
      job,
      lifecycle: {
        state: 'committed_awaiting_holder_delivery',
        startedAtMs: 1_000,
        committedAtMs: receipt.committedAtMs,
        transcriptHashB64u: receipt.transcriptHashB64u,
        protocolCommitReceiptDigestB64u: commandDigestB64u,
      },
    },
  };
}

function sourcePorts(args: {
  readonly calls: string[];
  readonly substituteEdReceipt?: boolean;
}): LaneOperationSourcePortsV1 {
  const fixture = buildR102MixedLaneEnrollmentFixture();
  return {
    nowMs: () => 2_000,
    reconcileEcdsaActivationJournalV1: async () => {
      args.calls.push('reconcile:ecdsa');
    },
    gateway: {
      prepareLaneEnrollmentV1: async () => {
        args.calls.push('gateway:prepare');
        return {
          kind: 'lane_enrollment_preparation_result_v1',
          outcome: 'applied',
          enrollmentId: fixture.manifest.enrollmentId,
          version: 1,
          commandDigestB64u: parseDigestB64u(DIGEST_B64U),
          lifecycle: {
            state: 'preparing',
            manifestDigestB64u: DIGEST_B64U,
            startedAtMs: 1_000,
          },
          orderedProtocols: [
            {
              version: 1,
              commandDigestB64u: parseDigestB64u(DIGEST_B64U),
              record: {
                job: fixture.children[0],
                lifecycle: { state: 'awaiting_protocol_commitment', startedAtMs: 1_000 },
              },
            },
            {
              version: 1,
              commandDigestB64u: parseDigestB64u(DIGEST_B64U),
              record: {
                job: fixture.children[1],
                lifecycle: { state: 'awaiting_protocol_commitment', startedAtMs: 1_000 },
              },
            },
          ],
        };
      },
      resumeLaneProtocolOperationV1: async () => {
        throw new Error('unexpected resume');
      },
      recordLaneProtocolCommitV1: async () => {
        throw new Error('browser must not record protocol receipts directly');
      },
      recordLaneHolderDeliveryV1: async () => {
        throw new Error('unexpected holder delivery');
      },
      activateLaneServerMaterialV1: async () => {
        throw new Error('unexpected server activation');
      },
      commitLaneEnrollmentActivationV1: async () => {
        throw new Error('unexpected aggregate activation');
      },
      fenceSigningLaneRevocationV1: async () => {
        throw new Error('unexpected lane revocation');
      },
      completeSigningLaneRevocationV1: async () => {
        throw new Error('unexpected lane revocation completion');
      },
    },
    wasm: {
      ecdsa: {
        prepareEcdsaAdditiveLaneHolderRoundV1: async () => {
          args.calls.push('wasm:ecdsa-holder');
          return {
            kind: 'ecdsa_additive_lane_holder_preparation_v1',
            holderRound: ecdsaHolderRound(),
            holderPackage: {
              kind: 'ecdsa_additive_lane_holder_package_v1',
              ecdsaEncryptedMaterialEnvelopeJson: '{"ecdsa":"holder"}',
            },
            encryptedDeltaPackageJson: '{"ecdsa":"delta"}',
          };
        },
      },
      ed25519Yao: {
        prepare: async () => {
          args.calls.push('wasm:ed25519-prepare');
          return { requestJson: '{"ed25519":"request"}' };
        },
        complete: async ({ job }) => {
          args.calls.push('wasm:ed25519-complete');
          return {
            protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
            holderPackage: {
              kind: 'ed25519_yao_lane_holder_package_set_v1',
              deriverAEncryptedPackageJson: '{"deriver":"a"}',
              deriverBEncryptedPackageJson: '{"deriver":"b"}',
            },
          };
        },
      },
    },
    protocolCommitter: {
      executeAndRecordEcdsaAdditiveLaneV1: async ({ job }) => {
        args.calls.push('server:ecdsa-commit');
        const receipt = buildR102ProtocolCommitReceipt(job);
        return { receipt, protocolCasResult: await committedResult(job, receipt) };
      },
      executeAndRecordEd25519YaoLaneV1: async ({ job }) => {
        args.calls.push('server:ed25519-commit');
        const receipt = buildR102ProtocolCommitReceipt(job);
        const returnedReceipt = args.substituteEdReceipt
          ? { ...receipt, targetLaneId: fixture.children[1].target.laneId }
          : receipt;
        return {
          responseJson: '{"ed25519":"response"}',
          receipt: returnedReceipt,
          protocolCasResult: await committedResult(job, receipt),
        };
      },
    },
  };
}

test.describe('R102 source lane protocol coordinator', () => {
  test('reconciles ECDSA first and commits mixed children through authenticated server ports', async () => {
    const fixture = buildR102MixedLaneEnrollmentFixture();
    const calls: string[] = [];
    const result = await prepareAndCommitSourceLaneOperationV1({
      manifest: fixture.manifest,
      children: fixture.children,
      ports: sourcePorts({ calls }),
    });

    expect(result.committedChildren.map((child) => child.job.keyFamily)).toEqual([
      'ed25519',
      'ecdsa_secp256k1',
    ]);
    expect(calls).toEqual([
      'reconcile:ecdsa',
      'gateway:prepare',
      'wasm:ed25519-prepare',
      'server:ed25519-commit',
      'wasm:ed25519-complete',
      'wasm:ecdsa-holder',
      'server:ecdsa-commit',
    ]);
  });

  test('rejects a server receipt substituted across child lanes', async () => {
    const fixture = buildR102MixedLaneEnrollmentFixture();
    await expect(
      prepareAndCommitSourceLaneOperationV1({
        manifest: fixture.manifest,
        children: fixture.children,
        ports: sourcePorts({ calls: [], substituteEdReceipt: true }),
      }),
    ).rejects.toThrow('lane protocol commit receipt does not match its job');
  });
});
