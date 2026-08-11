import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { installDeviceLinkingKeyWorkerV1 } from '../../packages/sdk-web/src/core/signingEngine/workerManager/workers/device-linking-key.worker';

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

function challenge(): string {
  return base64UrlEncode(new Uint8Array(32).fill(7));
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
  test('keeps key material in the worker and signs the canonical request bytes', async () => {
    const scope = new FakeWorkerScope();
    const installed = installDeviceLinkingKeyWorkerV1(scope);
    scope.send({ id: 'create', request: { kind: 'device_linking_key_material_create_v1' } });
    const created = await waitForResponse(scope);
    expect(created.ok).toBe(true);
    const result = created.result as Record<string, unknown>;
    expect(Object.keys(result).sort()).toEqual(['devicePublicKeyB64u', 'handleId', 'linkPublicKeyB64u']);
    expect(typeof result.handleId).toBe('string');
    expect(typeof result.linkPublicKeyB64u).toBe('string');
    expect(typeof result.devicePublicKeyB64u).toBe('string');

    scope.responses.length = 0;
    scope.send({
      id: 'sign',
      request: {
        kind: 'device_linking_request_sign_v1',
        handleId: result.handleId,
        linkSessionId: 'link-session-1',
        method: 'POST',
        canonicalPath: '/wallet/device-linking/v1/sessions/link-session-1/credential',
        bodyDigestB64u: digest(3),
        devicePublicKeyDigestB64u: digest(9),
        challengeB64u: challenge(),
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
      },
    });
    const signed = await waitForResponse(scope);
    expect(signed.ok).toBe(true);
    const signature = (signed.result as Record<string, unknown>).signatureB64u;
    expect(typeof signature).toBe('string');
    expect(base64UrlEncode(new Uint8Array(64))).not.toBe(signature);

    scope.responses.length = 0;
    scope.send({
      id: 'discard',
      request: { kind: 'device_linking_key_material_discard_v1', handleId: result.handleId },
    });
    await waitForResponse(scope);
    scope.responses.length = 0;
    scope.send({
      id: 'sign-after-discard',
      request: {
        kind: 'device_linking_request_sign_v1',
        handleId: result.handleId,
        linkSessionId: 'link-session-1',
        method: 'GET',
        canonicalPath: '/wallet/device-linking/v1/sessions/link-session-1',
        bodyDigestB64u: digest(3),
        devicePublicKeyDigestB64u: digest(9),
        challengeB64u: challenge(),
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
      },
    });
    const discarded = await waitForResponse(scope);
    expect(discarded.ok).toBe(false);
    expect(discarded.error).toContain('unknown or discarded');
    installed.close();
  });
});
