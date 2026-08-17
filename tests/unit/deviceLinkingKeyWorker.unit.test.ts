import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { installDeviceLinkingKeyWorkerV1 } from '../../packages/sdk-web/src/core/signingEngine/workerManager/workers/device-linking-key.worker';
import {
  buildR102EcdsaLaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
  buildR103SealedHolderRecord,
} from './helpers/r102LaneGateway.fixtures';
import { EcdsaClientWorkerControlKind } from '../../packages/sdk-web/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels';

class FakeWorkerScope {
  readonly responses: unknown[] = [];
  private listener: ((event: MessageEvent) => void) | null = null;

  postMessage(message: unknown): void {
    this.responses.push(message);
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listener = listener;
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    if (this.listener === listener) this.listener = null;
  }

  send(message: unknown): void {
    this.listener?.({ data: message } as MessageEvent);
  }
}

function digest(seed: number): string {
  return base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => seed + index));
}

async function waitForResponse(scope: FakeWorkerScope): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = scope.responses.at(0);
    if (response && typeof response === 'object') return response as Record<string, unknown>;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('worker response timed out');
}

test.describe('device-linking key worker', () => {
  test('runs linked-holder ECDSA presign behind an opaque worker capability', async () => {
    const scope = new FakeWorkerScope();
    let presignSessionCreates = 0;
    let presignSessionFrees = 0;
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      openSigningMaterial() {
        return {
          key_family: () => 'ecdsa_secp256k1',
          create_ed25519_signing_share: () => {
            throw new Error('Ed25519 signing is outside this ECDSA test');
          },
          create_ecdsa_presign_session: () => {
            presignSessionCreates += 1;
            return {
              stage: () => 'triples',
              poll: () => ({
                stage: 'triples',
                event: 'none',
                outgoing: [new Uint8Array([7, 8, 9])],
              }),
              message: () => undefined,
              start_presign: () => undefined,
              presignature_big_r_33: () => {
                throw new Error('presign is not complete');
              },
              compute_signature_share: () => {
                throw new Error('presign is not complete');
              },
              free: () => {
                presignSessionFrees += 1;
              },
            };
          },
          destroy: () => undefined,
          free: () => undefined,
        };
      },
    });
    const job = buildR102EcdsaLaneJob('device-linking-holder-presign');
    if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('ECDSA fixture changed branch');
    const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
    const materialActivation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
    const holderRecord = buildR103SealedHolderRecord(job, protocolCommitReceipt);
    const factorSecret = new Uint8Array(32).fill(29).buffer;
    scope.send({
      id: 'open-ecdsa-signing-material',
      request: {
        kind: 'device_linking_holder_signing_material_open_v1',
        factorSecret,
        job,
        protocolCommitReceipt,
        materialActivation,
        holderRecord,
      },
    });
    const opened = await waitForResponse(scope);
    expect(opened).toMatchObject({
      ok: true,
      result: { keyFamily: 'ecdsa_secp256k1' },
    });
    expect(new Uint8Array(factorSecret)).toEqual(new Uint8Array(32));
    const holderHandleId = String((opened.result as Record<string, unknown>).handleId);

    const channel = new MessageChannel();
    scope.send({
      kind: EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign,
      port: channel.port1,
    });
    const response = new Promise<Record<string, unknown>>((resolve) => {
      channel.port2.onmessage = (event) => resolve(event.data as Record<string, unknown>);
      channel.port2.start();
    });
    const groupPublicKey33 = base64UrlDecode(job.thresholdPublicKey33B64u);
    channel.port2.postMessage(
      {
        kind: 'opaque_ecdsa_presign_session_init_v1',
        requestId: 'linked-presign-1',
        sessionId: 'linked-presign-session-1',
        authority: {
          kind: 'linked_holder_signing_material',
          holderHandleId,
        },
        poolIdentity: {
          poolKey: 'linked-holder-pool',
          materialActivationId: materialActivation.activationId,
          capability: materialActivation.capability,
          keyBinding: materialActivation.keyBinding,
          walletId: job.walletId,
          signingScopeB64u: digest(42),
          pairRole: 'client',
          keyEpoch: 'linked-holder-key-epoch-1',
          activationEpoch: 'linked-holder-activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1',
        },
        groupPublicKey33: groupPublicKey33.buffer,
        materialExpiresAtMs: Date.now() + 60_000,
      },
      [groupPublicKey33.buffer],
    );
    const progress = await response;
    expect(progress).toMatchObject({
      kind: 'opaque_ecdsa_presign_authority_result_v1',
      requestId: 'linked-presign-1',
      ok: true,
      result: {
        kind: 'progress',
        progress: { stage: 'triples', event: 'none' },
      },
    });
    expect(presignSessionCreates).toBe(1);
    expect(scope.responses).toHaveLength(1);
    channel.port2.close();
    await installed.close();
    expect(presignSessionFrees).toBe(1);
  });

});
