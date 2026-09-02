import { expect, test } from '@playwright/test';
import type {
  Ed25519YaoLaneClientCompletionV1,
  Ed25519YaoLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotation';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoCeremonyBindingV1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import {
  createEd25519YaoLaneDerivationWorkerWasmV1,
  openEd25519YaoLaneWorkerSourceV1,
} from '../../packages/wallet/src/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
import type { WorkerOperationContext } from '../../packages/wallet/src/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationType,
} from '../../packages/wallet/src/core/signingEngine/workerManager/workerTypes';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';

const BYTES_32 = Array.from({ length: 32 }, (_, index) => index + 1);
const PUBLIC_KEY_B64U = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';

function edJob(): Ed25519YaoLaneJobV1 {
  const job = buildR102LaneJob('worker-source');
  if (job.keyFamily !== 'ed25519') throw new Error('R102 fixture changed key family');
  return job;
}

function ceremonyBinding(): RouterAbEd25519YaoCeremonyBindingV1 {
  return {
    lifecycle: {
      lifecycle_id: 'operation-r102-worker-source',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'source-epoch-r102-worker-source',
      account_id: 'wallet-r102-lifecycle',
      session_id: 'lane-session-worker-source',
      signer_set_id: 'lane-signer-set-worker-source',
      selected_server_id: 'worker-r102-source-worker-source',
    },
    operation: 'lane_provisioning',
    session_id: BYTES_32,
    stable_key_context_binding: BYTES_32,
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: 'activation-r102-source-worker-source',
      capability: 'capability-r102-source-worker-source',
      material_owner: 'wallet-r102-lifecycle',
      key_binding: 'key-binding-r102-source-worker-source',
      lifecycle_binding: 'lifecycle-binding-r102-source-worker-source',
      signing_worker: 'worker-r102-source-worker-source',
    },
  };
}

function applicationBinding(): RouterAbEd25519YaoApplicationBindingFactsV1 {
  return {
    wallet_id: 'wallet-r102-lifecycle',
    near_ed25519_signing_key_id: 'near-key-r102-worker-source',
    signing_root_id: 'signing-root-r102-worker-source',
    key_creation_signer_slot: 1,
  };
}

function completion(job: Ed25519YaoLaneJobV1): Ed25519YaoLaneClientCompletionV1 {
  return {
    protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
    holderPackage: {
      kind: 'ed25519_yao_lane_holder_package_set_v1',
      deriverAEncryptedPackageJson: '{"role":"deriver_a"}',
      deriverBEncryptedPackageJson: '{"role":"deriver_b"}',
    },
  };
}

type WalletCustodyCall = {
  readonly kind: string;
  readonly request: {
    readonly type: string;
    readonly payload: unknown;
  };
};

class RecordingWalletCustodyWorker implements WorkerOperationContext {
  readonly calls: WalletCustodyCall[] = [];
  readonly job = edJob();

  async requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(call: { kind: K; request: SignerWorkerOperationRequest<K, T> }): Promise<never> {
    if (call.kind !== 'walletCustodyCeremony') {
      throw new Error(`unexpected worker kind ${call.kind}`);
    }
    this.calls.push({
      kind: String(call.kind),
      request: {
        type: String(call.request.type),
        payload: call.request.payload,
      },
    });
    switch (call.request.type) {
      case 'openEd25519YaoLaneSource':
        return { sourceHandle: 'opaque-source-handle' } as never;
      case 'prepareEd25519YaoLane':
        return {
          sessionHandle: 'opaque-session-handle',
          requestJson: '{"kind":"lane-dispatch"}',
        } as never;
      case 'completeEd25519YaoLane':
        return completion(this.job) as never;
      case 'discardEd25519YaoLaneSource':
        return { discarded: true } as never;
      default:
        throw new Error(`unexpected wallet custody operation ${String(call.request.type)}`);
    }
  }
}

test('keeps the Ed25519 stable root and lane seal seeds behind opaque worker handles', async () => {
  const worker = new RecordingWalletCustodyWorker();
  const factorSecret = new Uint8Array(32).fill(9).buffer;
  const envelope = passkeyCustodyEnvelope();
  const source = await openEd25519YaoLaneWorkerSourceV1({
    workerCtx: worker,
    factorSecret,
    envelope,
    applicationBindingDigestB64u: PUBLIC_KEY_B64U,
  });
  const client = createEd25519YaoLaneDerivationWorkerWasmV1({
    workerCtx: worker,
    source,
    ceremonyBinding: ceremonyBinding(),
    applicationBinding: applicationBinding(),
    participantIds: [1, 2],
    deriverAInputPublicKeyB64u: PUBLIC_KEY_B64U,
    deriverBInputPublicKeyB64u: PUBLIC_KEY_B64U,
  });

  await client.prepare(worker.job);
  await client.complete({ job: worker.job, responseJson: '{"kind":"lane-response"}' });
  await source.discard();

  expect(worker.calls.map((call) => call.request.type)).toEqual([
    'openEd25519YaoLaneSource',
    'prepareEd25519YaoLane',
    'completeEd25519YaoLane',
    'discardEd25519YaoLaneSource',
  ]);
  const prepareCall = worker.calls[1];
  expect(prepareCall.request.payload).toEqual({
    sourceHandle: 'opaque-source-handle',
    job: worker.job,
    ceremonyBinding: ceremonyBinding(),
    applicationBinding: applicationBinding(),
    participantIds: [1, 2],
    deriverAInputPublicKeyB64u: PUBLIC_KEY_B64U,
    deriverBInputPublicKeyB64u: PUBLIC_KEY_B64U,
  });
  expect(JSON.stringify(prepareCall)).not.toContain('factorSecret');
  expect(JSON.stringify(prepareCall)).not.toContain('clientRoot');
  expect(JSON.stringify(prepareCall)).not.toContain('sealSeed');
  expect(JSON.stringify(prepareCall)).not.toContain('privateKey');
});

test('consumes preparation and source-discard typestate exactly once', async () => {
  const worker = new RecordingWalletCustodyWorker();
  const source = await openEd25519YaoLaneWorkerSourceV1({
    workerCtx: worker,
    factorSecret: new Uint8Array(32).fill(4).buffer,
    envelope: passkeyCustodyEnvelope(),
    applicationBindingDigestB64u: PUBLIC_KEY_B64U,
  });
  const client = createEd25519YaoLaneDerivationWorkerWasmV1({
    workerCtx: worker,
    source,
    ceremonyBinding: ceremonyBinding(),
    applicationBinding: applicationBinding(),
    participantIds: [1, 2],
    deriverAInputPublicKeyB64u: PUBLIC_KEY_B64U,
    deriverBInputPublicKeyB64u: PUBLIC_KEY_B64U,
  });

  await client.prepare(worker.job);
  await expect(client.prepare(worker.job)).rejects.toThrow('already prepared');
  await client.complete({ job: worker.job, responseJson: '{"kind":"lane-response"}' });
  await expect(
    client.complete({ job: worker.job, responseJson: '{"kind":"lane-response"}' }),
  ).rejects.toThrow('not prepared');
  await source.discard();
  await source.discard();

  expect(
    worker.calls.filter((call) => call.request.type === 'discardEd25519YaoLaneSource'),
  ).toHaveLength(1);
});
