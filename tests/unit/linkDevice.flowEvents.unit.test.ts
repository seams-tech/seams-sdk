import { expect, test } from '@playwright/test';
import { LinkDeviceFlow } from '@/SeamsWeb/operations/devices/linkDevice';
import { linkDeviceWithScannedQRData } from '@/SeamsWeb/operations/devices/scanDevice';
import { DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import { LinkDeviceEventPhase } from '@/core/types/sdkSentEvents';

function createDisplayContext() {
  return {} as any;
}

test.describe('link-device stubs', () => {
  test('device2 QR flow fails with the refactor-84 stub error', async () => {
    const events: any[] = [];
    const errors: Error[] = [];
    const flow = new LinkDeviceFlow(createDisplayContext(), {
      options: {
        onEvent: (event: any) => events.push(event),
        onError: (error: Error) => errors.push(error),
      },
    } as any);

    await expect(flow.generateQR()).rejects.toThrow(
      'Linked-device lane creation is disabled until refactor 84 lands',
    );

    expect(events.map((event) => event.phase)).toEqual([LinkDeviceEventPhase.FAILED]);
    expect(events.at(-1)).toMatchObject({
      flow: 'link_device',
      status: 'failed',
      error: {
        code: DeviceLinkingErrorCode.UNSUPPORTED,
        retryable: false,
      },
    });
    expect(errors).toHaveLength(1);
    expect(flow.getState()).toMatchObject({
      phase: LinkDeviceEventPhase.FAILED,
      cancelled: false,
    });
  });

  test('scanner flow validates QR envelope then fails with the refactor-84 stub error', async () => {
    const events: any[] = [];
    const errors: Error[] = [];

    await expect(
      linkDeviceWithScannedQRData(
        {} as any,
        {
          sessionId: 'ldsess-valid',
          timestamp: Date.now(),
          version: 'refactor-84-stub',
        },
        {
          fundingAmount: '0',
          onEvent: (event: any) => events.push(event),
          onError: (error: Error) => errors.push(error),
        },
      ),
    ).rejects.toThrow('Linked-device lane creation is disabled until refactor 84 lands');

    expect(events.map((event) => event.phase)).toEqual([
      LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      LinkDeviceEventPhase.FAILED,
    ]);
    expect(events.map((event) => event.flow)).toEqual(['link_device', 'link_device']);
    expect(events.at(-1)).toMatchObject({
      status: 'failed',
      data: {
        role: 'scanner',
      },
      error: {
        code: DeviceLinkingErrorCode.UNSUPPORTED,
        retryable: false,
      },
    });
    expect(errors).toHaveLength(1);
  });
});
