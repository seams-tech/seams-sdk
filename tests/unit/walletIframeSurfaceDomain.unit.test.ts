import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const SURFACE_DOMAIN_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/domain.js';

test.describe('wallet iframe surface domain', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('opens registration as a viewport-owned modal and arbitrates foreground requests', async ({
    page,
  }) => {
    const result = await page.evaluate(async (path) => {
      const domain = await import(path);
      const connectionId = domain.walletIframeConnectionIdFromBoundary('connection-a');
      const identity = domain.requestSurfaceIdentity({
        surfaceId: 'surface-a',
        requestId: 'request-a',
      });
      const competingIdentity = domain.requestSurfaceIdentity({
        surfaceId: 'surface-b',
        requestId: 'request-b',
      });
      const event = {
        kind: 'registration_modal_request_started',
        connectionId,
        identity,
        preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
      };
      const started = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), event);
      if (started.kind !== 'applied') throw new Error('registration modal did not start');
      const replay = domain.reduceWalletIframeSurface(started.surface, event);
      const competing = domain.reduceWalletIframeSurface(started.surface, {
        ...event,
        identity: competingIdentity,
      });
      return { started, replay, competing };
    }, SURFACE_DOMAIN_PATH);

    expect(result.started.surface.kind).toBe('modal_registration_confirm');
    expect(result.replay.kind).toBe('ignored');
    expect(result.competing).toMatchObject({
      kind: 'rejected',
      error: {
        kind: 'wallet_iframe_surface_busy',
        activeSurfaceKind: 'modal_registration_confirm',
        attemptedSurfaceKind: 'modal_registration_confirm',
      },
    });
  });

  test('ignores stale request completion and renders every current surface fullscreen', async ({
    page,
  }) => {
    const result = await page.evaluate(async (path) => {
      const domain = await import(path);
      const renderer =
        await import('/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/renderer.js');
      const connectionId = domain.walletIframeConnectionIdFromBoundary('connection-a');
      const identity = domain.requestSurfaceIdentity({
        surfaceId: 'surface-a',
        requestId: 'request-a',
      });
      const staleIdentity = domain.requestSurfaceIdentity({
        surfaceId: 'surface-b',
        requestId: 'request-b',
      });
      const preparation = domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000);
      const registration = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'registration_modal_request_started',
        connectionId,
        identity,
        preparation,
      });
      if (registration.kind !== 'applied') throw new Error('registration modal did not start');
      const surface = registration.surface;
      const staleFinish = domain.reduceWalletIframeSurface(surface, {
        kind: 'request_finished',
        connectionId,
        identity: staleIdentity,
      });
      const hidden = domain.reduceWalletIframeSurface(surface, {
        kind: 'request_surface_hidden',
        connectionId,
        identity,
      });
      const staleHidden = domain.reduceWalletIframeSurface(surface, {
        kind: 'request_surface_hidden',
        connectionId,
        identity: staleIdentity,
      });
      const transaction = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'transaction_modal_request_started',
        connectionId,
        identity,
      });
      const keyExport = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'key_export_modal_request_started',
        connectionId,
        identity,
        exportKind: 'near_keypair',
      });
      const unlock = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'unlock_modal_request_started',
        connectionId,
        identity,
        unlockKind: 'passkey',
      });
      const recoveryCodes = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'recovery_codes_modal_request_started',
        connectionId,
        identity,
        operation: 'show',
      });
      const deviceLink = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'device_link_qr_modal_request_started',
        connectionId,
        identity,
      });
      if (
        transaction.kind !== 'applied' ||
        keyExport.kind !== 'applied' ||
        unlock.kind !== 'applied' ||
        recoveryCodes.kind !== 'applied' ||
        deviceLink.kind !== 'applied'
      ) {
        throw new Error('expected every request-owned modal to start');
      }
      const renderModes: string[] = [];
      const surfaceRenderer = new renderer.WalletIframeSurfaceRenderer({
        applyHidden() {
          renderModes.push('hidden');
        },
        applyViewportModal() {
          renderModes.push('viewport_modal');
        },
      });
      const surfaces = [
        domain.hiddenWalletIframeSurface(),
        surface,
        transaction.surface,
        keyExport.surface,
        unlock.surface,
        recoveryCodes.surface,
        deviceLink.surface,
      ];
      for (const candidate of surfaces) {
        surfaceRenderer.render(candidate);
      }
      return { staleFinish, hidden, staleHidden, modes: renderModes };
    }, SURFACE_DOMAIN_PATH);

    expect(result.staleFinish.kind).toBe('ignored');
    expect(result.staleFinish.surface.kind).toBe('modal_registration_confirm');
    expect(result.hidden).toMatchObject({ kind: 'applied', surface: { kind: 'hidden' } });
    expect(result.staleHidden).toMatchObject({
      kind: 'ignored',
      surface: { kind: 'modal_registration_confirm' },
    });
    expect(result.modes).toEqual([
      'hidden',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
    ]);
  });
});
