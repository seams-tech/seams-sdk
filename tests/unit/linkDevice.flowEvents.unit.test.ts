import { expect, test } from '@playwright/test';
import { LinkDeviceFlow } from '@/SeamsWeb/operations/devices/linkDevice';
import { linkDeviceWithScannedQRData } from '@/SeamsWeb/operations/devices/scanDevice';
import { LinkDeviceEventPhase } from '@/core/types/sdkSentEvents';

function createDisplayContext() {
  return {
    configs: {
      network: {
        relayer: {
          url: '',
        },
      },
    },
    signingRuntime: {
      services: {
        nearKeyOperations: {
          generateEphemeralNearKeypair: async () => ({
            publicKey: 'ed25519:device2-public-key',
            privateKey: 'device2-private-key',
          }),
        },
      },
    },
    signingEngine: {
      generateEphemeralNearKeypair: async () => ({
        publicKey: 'ed25519:device2-public-key',
        privateKey: 'device2-private-key',
      }),
    },
  } as any;
}

test.describe('link-device wallet flow events', () => {
  test('emits QR-display role sequence for device2', async () => {
    const events: any[] = [];
    const flow = new LinkDeviceFlow(createDisplayContext(), {
      signerSlot: 3,
      options: {
        onEvent: (event: any) => events.push(event),
      },
    } as any);

    (flow as any).registerSessionOnRelay = async () => undefined;
    (flow as any).waitForClaimAndComplete = async () => undefined;

    const result = await flow.generateQR();
    flow.cancel();

    expect(result.qrData).toMatchObject({
      device2PublicKey: 'ed25519:device2-public-key',
      version: 'v3',
    });
    expect(result.qrCodeDataURL).toContain('data:image/');

    expect(events.map((event) => event.phase)).toEqual([
      LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
      LinkDeviceEventPhase.STEP_01_QR_DISPLAYED,
      LinkDeviceEventPhase.CANCELLED,
    ]);
    expect(events.map((event) => event.flow)).toEqual([
      'link_device',
      'link_device',
      'link_device',
    ]);
    expect(events.map((event) => event.step)).toEqual([1, 1, 0]);
    expect(events.map((event) => event.data?.role)).toEqual(['display', 'display', undefined]);
    expect(events.map((event) => event.interaction?.overlay)).toEqual([undefined, 'hide', 'hide']);
    expect(events.at(-1)).toMatchObject({
      status: 'cancelled',
      interaction: {
        kind: 'qr_display',
        overlay: 'hide',
      },
    });
  });

  test('emits QR-scanner role sequence for invalid scanned data', async () => {
    const events: any[] = [];
    const errors: Error[] = [];
    const originalConsoleError = console.error;
    console.error = () => undefined;

    try {
      await expect(
        linkDeviceWithScannedQRData(
          {} as any,
          {
            sessionId: 'ldsess-invalid',
            timestamp: Date.now(),
            version: 'v3',
          },
          {
            fundingAmount: '0',
            onEvent: (event: any) => events.push(event),
            onError: (error: Error) => errors.push(error),
          },
        ),
      ).rejects.toThrow('Failed to scan and link device');
    } finally {
      console.error = originalConsoleError;
    }

    expect(events.map((event) => event.phase)).toEqual([
      LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      LinkDeviceEventPhase.FAILED,
    ]);
    expect(events.map((event) => event.flow)).toEqual(['link_device', 'link_device']);
    expect(events.map((event) => event.step)).toEqual([2, 0]);
    expect(events.map((event) => event.data?.role)).toEqual(['scanner', 'scanner']);
    expect(events.map((event) => event.interaction?.overlay)).toEqual(['none', 'hide']);
    expect(events.at(-1)).toMatchObject({
      status: 'failed',
      error: {
        retryable: true,
      },
    });
    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toContain('Failed to scan and link device');
  });
});
