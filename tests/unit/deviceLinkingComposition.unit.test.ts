import { expect, test } from '@playwright/test';
import type { AuthenticatorPort } from '../../packages/wallet/src/core/platform';
import type { HttpTransport } from '../../packages/wallet/src/core/platform/http';
import {
  createDeviceLinkingFlowPortsV1,
  type DeviceLinkingFlowPortsAssemblyOptionsV1,
} from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingComposition';
import {
  createDeviceLinkingKeyMaterialPortV1,
  type DeviceLinkingWorkerEndpointV1,
} from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingWorkerChannels';
import {
  resolveWalletHostInternalOptionsV1,
} from '../../packages/wallet/src/SeamsWeb/walletIframe/host/context';
import type { DeviceLinkingOwnerAuthorizationPortV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import type {
  LinkSessionOwnerApprovalUpdatesPortV1,
  LinkSessionOwnerAuthenticatedRequestPortV1,
} from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingOwnerTransport';

class IdleWorkerEndpoint {
  addEventListener(): void {}
  removeEventListener(): void {}
  postMessage(): void {}
  terminate(): void {}
}

class CountingWorkerEndpoint extends IdleWorkerEndpoint {
  terminateCalls = 0;

  override terminate(): void {
    this.terminateCalls += 1;
  }
}

class RespondingWorkerEndpoint extends IdleWorkerEndpoint {
  private readonly messageListeners = new Set<(event: MessageEvent) => void>();

  override addEventListener(type: 'message' | 'error', listener: (event: MessageEvent) => void): void {
    if (type === 'message') this.messageListeners.add(listener);
  }

  override removeEventListener(
    type: 'message' | 'error',
    listener: (event: MessageEvent) => void,
  ): void {
    if (type === 'message') this.messageListeners.delete(listener);
  }

  override postMessage(message: { readonly id?: string }): void {
    if (!message.id) return;
    for (const listener of this.messageListeners) {
      listener({
        data: {
          id: message.id,
          ok: true,
          result: {
            handleId: 'handle-1',
            linkPublicKeyB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            devicePublicKeyB64u: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
          },
        },
      } as MessageEvent);
    }
  }
}

const unsupported = async (): Promise<never> => {
  throw new Error('operation is outside this composition test');
};

function ownerAuthorization(): DeviceLinkingOwnerAuthorizationPortV1 {
  return { authenticateOwnerForLinkingV1: unsupported };
}

function ownerRequest(): LinkSessionOwnerAuthenticatedRequestPortV1 {
  return { requestOwnerV1: unsupported };
}

function approvalUpdates(): LinkSessionOwnerApprovalUpdatesPortV1 {
  return { getApprovalV1: unsupported, subscribeApprovalV1: unsupported };
}

function assemblyOptions(
  workerEndpoint: DeviceLinkingWorkerEndpointV1 = new IdleWorkerEndpoint(),
): DeviceLinkingFlowPortsAssemblyOptionsV1 {
  const authenticator: AuthenticatorPort = {
    kind: 'authenticator',
    run: unsupported,
  };
  const http: HttpTransport = {
    kind: 'http_transport',
    request: unsupported,
  };
  return {
    authenticator,
    http,
    relayerUrl: 'https://relay.example.test',
    ownerRequest: ownerRequest(),
    ownerApprovalUpdates: approvalUpdates(),
    ownerAuthorization: ownerAuthorization(),
    workerEndpoint,
    nowMs: () => 1,
    pollIntervalMs: 1_000,
  };
}

test('composes direct device-linking ports only from explicit trust-boundary providers', () => {
  const ports = createDeviceLinkingFlowPortsV1(assemblyOptions());

  expect(ports.transport).toBeDefined();
  expect(ports.keyMaterial).toBeDefined();
  expect(ports.targetCredential).toBeDefined();
  expect(JSON.stringify(ports)).not.toContain('privateKey');
  expect(JSON.stringify(ports)).not.toContain('prf');
});

test('wallet-host bootstrap selects the internal composition mode', () => {
  expect(resolveWalletHostInternalOptionsV1()).toEqual({ kind: 'wallet_host' });
});

test('device-linking worker creation is lazy and disposal is idempotent', () => {
  const originalWorker = globalThis.Worker;
  let workerConstructed = 0;
  class LazyWorkerEndpoint extends IdleWorkerEndpoint {
    constructor() {
      super();
      workerConstructed += 1;
    }
  }
  (globalThis as unknown as { Worker: typeof Worker }).Worker =
    LazyWorkerEndpoint as unknown as typeof Worker;
  try {
    const lazyPort = createDeviceLinkingKeyMaterialPortV1();
    expect(workerConstructed).toBe(0);
    lazyPort.close();
    lazyPort.close();
    expect(workerConstructed).toBe(0);

    const endpoint = new CountingWorkerEndpoint();
    const ports = createDeviceLinkingFlowPortsV1(assemblyOptions(endpoint));
    ports.dispose();
    ports.dispose();
    expect(endpoint.terminateCalls).toBe(1);
  } finally {
    (globalThis as unknown as { Worker: typeof Worker }).Worker = originalWorker;
  }
});

test('injected device-linking worker endpoints receive responses', async () => {
  const endpoint = new RespondingWorkerEndpoint();
  const port = createDeviceLinkingKeyMaterialPortV1({ endpoint });

  const result = await port.createBootstrapKeyMaterialV1();

  expect(result.handle.handleId).toBe('handle-1');
  expect(result.linkPublicKeyB64u).toBe('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  port.close();
});
