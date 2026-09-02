import { expect, test } from '@playwright/test';
import type { EcdsaAdditiveLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotation';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  createEcdsaLaneDerivationWorkerWasmV1,
  parseEcdsaAdditiveLaneHolderPreparationV1,
} from '../../packages/wallet/src/core/signingEngine/threshold/crypto/ecdsaLaneWasm';
import { prepareLinkedDeviceEcdsaSourceContributionWasm } from '../../packages/wallet/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import type { WorkerOperationContext } from '../../packages/wallet/src/core/signingEngine/workerManager/executeWorkerOperation';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '../../packages/wallet/src/core/signingEngine/workerManager/workerTypes';
import { buildMpcMaterialActivationRef } from '../../packages/shared-ts/src/utils/domainIds';
import {
  parsePrepareEcdsaAdditiveLaneHolderRequestV1,
  parsePrepareLinkedDeviceEcdsaSourceContributionRequestV1,
  parsePrepareLinkedDeviceEcdsaSourceContributionResultV1,
} from '../../packages/wallet/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels';
import {
  prepareEcdsaLaneHolderInWorkerV1,
  resolveExactEcdsaLaneSourceMaterialV1,
  type EcdsaLaneHolderSessionFactoryV1,
  type EcdsaLaneHolderSessionPortV1,
} from '../../packages/wallet/src/core/signingEngine/workerManager/workers/ecdsaLaneHolderWorkerRuntime';
import {
  buildR102EcdsaLaneJob,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import { LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1 } from '../../packages/shared-ts/src/device-linking/sourceContribution';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32));
const SECP256K1_GENERATOR_B64U = base64UrlEncode(
  Uint8Array.from(
    Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'),
  ),
);
const SOURCE_RECIPIENT_B64U = base64UrlEncode(new Uint8Array(32).fill(9));
const TARGET_RECIPIENT_B64U = base64UrlEncode(new Uint8Array(32).fill(10));
const ENVELOPE_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(11));
const ENVELOPE_CIPHERTEXT_B64U = base64UrlEncode(new Uint8Array(32).fill(12));

function ecdsaJob(): EcdsaAdditiveLaneJobV1 {
  const job = buildR102EcdsaLaneJob('derivation-worker');
  if (job.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('R102 ECDSA lane fixture changed key family');
  }
  return job;
}

function holderPreparation(): unknown {
  return {
    kind: 'ecdsa_additive_lane_holder_preparation_v1',
    holderRound: {
      kind: 'ecdsa_additive_lane_holder_round_v1',
      preambleHashB64u: DIGEST_B64U,
      targetHolderPublicCommitment33B64u: SECP256K1_GENERATOR_B64U,
      encryptedDeltaCiphertextDigestB64u: DIGEST_B64U,
      sealedTargetHolderMaterialDigestB64u: DIGEST_B64U,
      holderAttestationB64u: 'holder-attestation-r102',
      holderCommittedAtMs: 2_000,
    },
    holderPackage: {
      kind: 'ecdsa_additive_lane_holder_package_v1',
      ecdsaEncryptedMaterialEnvelopeJson: '{"ecdsa":"holder"}',
    },
    encryptedDeltaPackageJson: '{"ecdsa":"delta"}',
  };
}

function laneRequest(job: EcdsaAdditiveLaneJobV1) {
  return parsePrepareEcdsaAdditiveLaneHolderRequestV1({
    kind: 'prepare_ecdsa_additive_lane_holder_v1',
    job,
    holderCommittedAtMs: 2_000,
  });
}

function sourceContributionRequest() {
  const job = ecdsaJob();
  const targetActivationId =
    buildR102ServerActivationReceipt(job).targetMaterialActivation.activationId;
  const targetActivation = buildMpcMaterialActivationRef({
    activationId: targetActivationId,
    capability: job.source.materialActivation.capability,
    materialOwner: job.source.materialActivation.materialOwner,
    keyBinding: job.source.materialActivation.keyBinding,
    lifecycleBinding: job.source.materialActivation.lifecycleBinding,
    signingWorker: job.source.materialActivation.signingWorker,
  });
  return parsePrepareLinkedDeviceEcdsaSourceContributionRequestV1({
    kind: 'prepare_linked_device_ecdsa_source_contribution_v1',
    preparation: {
      linkSessionId: 'link-session-r103-ecdsa',
      enrollmentId: 'enrollment-r103-ecdsa',
      sourceAuthorityId: 'authority-r103-ecdsa',
      source: {
        activation: job.source.materialActivation,
        clientPublicKey33B64u: SECP256K1_GENERATOR_B64U,
        relayerPublicKey33B64u: SECP256K1_GENERATOR_B64U,
        thresholdPublicKey33B64u: SECP256K1_GENERATOR_B64U,
        thresholdEthereumAddress20B64u: base64UrlEncode(new Uint8Array(20).fill(13)),
      },
      target: {
        activation: targetActivation,
        targetDeviceId: 'device-r103-ecdsa',
        targetFactorVerificationDigestB64u: DIGEST_B64U,
        clientRecipientPublicKeyB64u: SOURCE_RECIPIENT_B64U,
        signingWorkerRecipientPublicKeyB64u: TARGET_RECIPIENT_B64U,
      },
    },
  });
}

function sourceContributionResult(
  request: ReturnType<typeof sourceContributionRequest>,
): ReturnType<typeof parsePrepareLinkedDeviceEcdsaSourceContributionResultV1> {
  const { preparation } = request;
  const binding = {
    linkSessionId: preparation.linkSessionId,
    enrollmentId: preparation.enrollmentId,
    sourceAuthorityId: preparation.sourceAuthorityId,
    source: preparation.source,
    target: preparation.target,
    targetClientPublicKey33B64u: SECP256K1_GENERATOR_B64U,
  };
  const envelope = (recipientPublicKeyB64u: string) => ({
    kind: LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
    recipientPublicKeyB64u,
    bindingDigestB64u: DIGEST_B64U,
    encappedKeyB64u: ENVELOPE_KEY_B64U,
    ciphertextB64u: ENVELOPE_CIPHERTEXT_B64U,
  });
  return parsePrepareLinkedDeviceEcdsaSourceContributionResultV1({
    kind: 'linked_device_ecdsa_source_contribution_package_v1',
    package: {
      binding,
      encryptedDelta: envelope(TARGET_RECIPIENT_B64U),
      encryptedTargetClientShare: envelope(SOURCE_RECIPIENT_B64U),
    },
  });
}

class RecordingLaneHolderSession implements EcdsaLaneHolderSessionPortV1 {
  constructor(private readonly owner: RecordingLaneHolderSessionFactory) {}

  prepare(): string {
    if (this.owner.prepareError) throw this.owner.prepareError;
    return JSON.stringify(this.owner.prepareResult);
  }

  free(): void {
    this.owner.freeCalls += 1;
  }
}

class RecordingLaneHolderSessionFactory implements EcdsaLaneHolderSessionFactoryV1 {
  readonly openedStateBlobs: string[] = [];
  freeCalls = 0;

  constructor(
    readonly prepareResult: unknown,
    readonly prepareError: Error | null = null,
  ) {}

  create(stateBlobB64u: string): EcdsaLaneHolderSessionPortV1 {
    this.openedStateBlobs.push(stateBlobB64u);
    return new RecordingLaneHolderSession(this);
  }
}

function recordingWorkerContext(args: {
  readonly calls: unknown[];
  readonly payload: unknown;
}): WorkerOperationContext {
  return {
    async requestWorkerOperation(call) {
      args.calls.push(call);
      return {
        type: EcdsaDerivationClientCustomResponseType.PrepareEcdsaAdditiveLaneHolderSuccess,
        payload: args.payload,
      } as never;
    },
  };
}

function recordingSourceWorkerContext(args: {
  readonly calls: unknown[];
  readonly payload: ReturnType<typeof sourceContributionResult>;
}): WorkerOperationContext {
  return {
    async requestWorkerOperation(call) {
      args.calls.push(call);
      return {
        type: EcdsaDerivationClientCustomResponseType.PrepareLinkedDeviceEcdsaSourceContributionSuccess,
        payload: args.payload,
      } as never;
    },
  };
}

test.describe('ECDSA lane derivation-worker WASM port', () => {
  test('sends only the exact public lane job and holder commitment time', async () => {
    const calls: unknown[] = [];
    const job = ecdsaJob();
    const port = createEcdsaLaneDerivationWorkerWasmV1({
      workerCtx: recordingWorkerContext({ calls, payload: holderPreparation() }),
      nowMs: () => 2_000,
    });

    const result = await port.prepareEcdsaAdditiveLaneHolderRoundV1(job);

    expect(result.kind).toBe('ecdsa_additive_lane_holder_preparation_v1');
    expect(calls).toEqual([
      {
        kind: 'ecdsaDerivationClient',
        request: {
          type: EcdsaDerivationClientCustomRequestType.PrepareEcdsaAdditiveLaneHolder,
          payload: {
            kind: 'prepare_ecdsa_additive_lane_holder_v1',
            job,
            holderCommittedAtMs: 2_000,
          },
          timeoutMs: 20_000,
        },
      },
    ]);
  });

  test('rejects secret-bearing request and response extensions', async () => {
    const job = ecdsaJob();
    expect(() =>
      parsePrepareEcdsaAdditiveLaneHolderRequestV1({
        kind: 'prepare_ecdsa_additive_lane_holder_v1',
        job,
        holderCommittedAtMs: 2_000,
        stateBlobB64u: 'forbidden-secret',
      }),
    ).toThrow('invalid fields');

    expect(() =>
      parseEcdsaAdditiveLaneHolderPreparationV1({
        ...holderPreparation(),
        sourceShare32B64u: 'forbidden-secret',
      }),
    ).toThrow('sourceShare32B64u is not allowed');
  });

  test('rejects wrong and ambiguous source material activations', () => {
    const request = laneRequest(ecdsaJob());
    const wrongJob = buildR102EcdsaLaneJob('wrong-source-activation');

    expect(() =>
      resolveExactEcdsaLaneSourceMaterialV1(request, [
        {
          materialActivation: wrongJob.source.materialActivation,
          stateBlobB64u: 'wrong-state',
        },
      ]),
    ).toThrow('not loaded for the exact activation');

    expect(() =>
      resolveExactEcdsaLaneSourceMaterialV1(request, [
        {
          materialActivation: request.job.source.materialActivation,
          stateBlobB64u: 'first-state',
        },
        {
          materialActivation: request.job.source.materialActivation,
          stateBlobB64u: 'duplicate-state',
        },
      ]),
    ).toThrow('resolves to multiple loaded materials');
  });

  test('frees the one-use WASM session after success and failure', () => {
    const request = laneRequest(ecdsaJob());
    const candidates = [
      {
        materialActivation: request.job.source.materialActivation,
        stateBlobB64u: 'worker-local-ready-state',
      },
    ];
    const successFactory = new RecordingLaneHolderSessionFactory(holderPreparation());
    const result = prepareEcdsaLaneHolderInWorkerV1({
      request,
      candidates,
      sessionFactory: successFactory,
    });
    expect(result.kind).toBe('ecdsa_additive_lane_holder_preparation_v1');
    expect(successFactory.openedStateBlobs).toEqual(['worker-local-ready-state']);
    expect(successFactory.freeCalls).toBe(1);

    const failureFactory = new RecordingLaneHolderSessionFactory(
      holderPreparation(),
      new Error('WASM preparation failed'),
    );
    expect(() =>
      prepareEcdsaLaneHolderInWorkerV1({
        request,
        candidates,
        sessionFactory: failureFactory,
      }),
    ).toThrow('WASM preparation failed');
    expect(failureFactory.freeCalls).toBe(1);
  });

  test('rejects numeric strings at the worker request boundary', () => {
    expect(() =>
      parsePrepareEcdsaAdditiveLaneHolderRequestV1({
        kind: 'prepare_ecdsa_additive_lane_holder_v1',
        job: ecdsaJob(),
        holderCommittedAtMs: '2000',
      }),
    ).toThrow('holderCommittedAtMs is invalid');
  });

  test('routes linked-device ECDSA source preparation through the derivation worker', async () => {
    const calls: unknown[] = [];
    const preparation = sourceContributionRequest();
    const result = await prepareLinkedDeviceEcdsaSourceContributionWasm({
      preparation: preparation.preparation,
      workerCtx: recordingSourceWorkerContext({
        calls,
        payload: sourceContributionResult(preparation),
      }),
    });

    expect(result.kind).toBe('linked_device_ecdsa_source_contribution_package_v1');
    expect(calls).toEqual([
      {
        kind: 'ecdsaDerivationClient',
        request: {
          type: EcdsaDerivationClientCustomRequestType.PrepareLinkedDeviceEcdsaSourceContribution,
          payload: preparation,
          timeoutMs: 20_000,
        },
      },
    ]);
    expect(JSON.stringify(calls)).not.toContain('stateBlobB64u');
  });

  test('rejects a state blob extension at the linked-device source boundary', () => {
    const preparation = sourceContributionRequest();
    expect(() =>
      parsePrepareLinkedDeviceEcdsaSourceContributionRequestV1({
        ...preparation,
        stateBlobB64u: 'forbidden-secret',
      }),
    ).toThrow('invalid fields');
  });
});
