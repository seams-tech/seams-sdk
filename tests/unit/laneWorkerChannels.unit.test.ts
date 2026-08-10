import { expect, test } from '@playwright/test';
import {
  createLaneHolderWorkerTransportV1,
  type LaneHolderWorkerEndpointV1,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/laneWorkerChannels';
import { buildR102LaneJob } from './helpers/r102LaneGateway.fixtures';

class FakeLaneHolderWorkerEndpoint implements LaneHolderWorkerEndpointV1 {
  private messageListener: ((event: MessageEvent) => void) | null = null;
  private errorListener: ((event: ErrorEvent) => void) | null = null;
  private readonly pending = new Set<string>();

  postMessage(message: unknown): void {
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      throw new Error('test frame is invalid');
    }
    const frame = message as { id?: unknown };
    if (typeof frame.id !== 'string') throw new Error('test frame id is missing');
    this.pending.add(frame.id);
  }

  addEventListener(
    type: 'message' | 'error',
    listener: ((event: MessageEvent) => void) | ((event: ErrorEvent) => void),
  ): void {
    if (type === 'message') this.messageListener = listener as (event: MessageEvent) => void;
    else this.errorListener = listener as (event: ErrorEvent) => void;
  }

  removeEventListener(type: 'message' | 'error'): void {
    if (type === 'message') this.messageListener = null;
    else this.errorListener = null;
  }

  terminate(): void {
    this.messageListener = null;
    this.errorListener = null;
  }

  resolve(result: unknown): void {
    const [id] = this.pending;
    if (!id || !this.messageListener) return;
    this.pending.delete(id);
    this.messageListener({ data: { id, ok: true, result } } as MessageEvent);
  }

  reject(message: string): void {
    const [id] = this.pending;
    if (!id || !this.messageListener) return;
    this.pending.delete(id);
    this.messageListener({ data: { id, ok: false, error: message } } as MessageEvent);
  }
}

test.describe('R102 lane holder worker transport', () => {
  test('carries only request frames and resolves the exact response id', async () => {
    const endpoint = new FakeLaneHolderWorkerEndpoint();
    const transport = createLaneHolderWorkerTransportV1({ endpoint, timeoutMs: 500 });
    const job = buildR102LaneJob('worker-transport');
    const response = transport.request({
      kind: 'lane_holder_recipient_create_v1',
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
    });
    endpoint.resolve({ kind: 'opaque-worker-result-v1' });
    await expect(response).resolves.toEqual({ kind: 'opaque-worker-result-v1' });
    transport.close();
  });

  test('rejects pending requests when the transport closes', async () => {
    const endpoint = new FakeLaneHolderWorkerEndpoint();
    const transport = createLaneHolderWorkerTransportV1({ endpoint, timeoutMs: 500 });
    const job = buildR102LaneJob('worker-close');
    const response = transport.request({
      kind: 'lane_holder_recipient_create_v1',
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
    });
    transport.close();
    await expect(response).rejects.toThrow('transport is closed');
  });
});
