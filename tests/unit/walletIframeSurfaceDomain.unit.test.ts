import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const SURFACE_DOMAIN_PATH =
  '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/domain.js';

test.describe('wallet iframe surface domain', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('arbitrates one foreground owner and redacts busy details', async ({ page }) => {
    const result = await page.evaluate(async (path) => {
      const domain = await import(path);
      const connection = domain.walletIframeConnectionIdFromBoundary('connection-a');
      const identity = domain.parseRegistrationActivationSurfaceIdentity({
        surfaceId: 'surface-a',
        requestId: 'request-a',
        activationId: 'activation-a',
      });
      if (!identity) throw new Error('identity parse failed');
      const event = {
        kind: 'registration_activation_prepared',
        connectionId: connection,
        identity,
        wallet: { kind: 'provided', walletId: 'wallet-a' },
        preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
        presentation: {
          kind: 'outline_overlay',
          label: 'Create passkey',
          busyLabel: 'Creating passkey...',
          accessibleLabel: 'Create passkey',
        },
        placement: domain.interactiveRegistrationPlacement({
          top: 10,
          left: 20,
          width: 120,
          height: 48,
        }),
      };
      const started = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), event);
      if (started.kind !== 'applied') throw new Error('surface did not start');
      const replay = domain.reduceWalletIframeSurface(started.surface, event);
      const competingIdentity = domain.parseRegistrationActivationSurfaceIdentity({
        surfaceId: 'surface-a',
        requestId: 'request-a',
        activationId: 'activation-b',
      });
      if (!competingIdentity) throw new Error('competing identity parse failed');
      const competing = domain.reduceWalletIframeSurface(started.surface, {
        ...event,
        identity: competingIdentity,
      });
      return { started, replay, competing };
    }, SURFACE_DOMAIN_PATH);

    expect(result.started.kind).toBe('applied');
    expect(result.started.surface.kind).toBe('anchored_registration_activation');
    expect(result.replay.kind).toBe('ignored');
    expect(result.competing.kind).toBe('rejected');
    if (result.competing.kind !== 'rejected') throw new Error('expected rejection');
    expect(result.competing.error).toEqual({
      kind: 'wallet_iframe_surface_busy',
      activeSurfaceKind: 'anchored_registration_activation',
      attemptedSurfaceKind: 'anchored_registration_activation',
      retry: 'after_active_surface_finishes',
    });
    expect(JSON.stringify(result.competing.error)).not.toContain('activation-a');
  });

  test('wire identity parsing cannot supply trusted connection ownership', async ({ page }) => {
    const parsed = await page.evaluate(async (path) => {
      const domain = await import(path);
      return domain.parseRegistrationActivationSurfaceIdentity({
        surfaceId: 'surface-a',
        requestId: 'request-a',
        activationId: 'activation-a',
        connectionId: 'attacker-connection',
      });
    }, SURFACE_DOMAIN_PATH);

    expect(parsed).toEqual({
      kind: 'registration_activation_surface_identity_v1',
      surfaceId: 'surface-a',
      requestId: 'request-a',
      activationId: 'activation-a',
    });
    expect(parsed).not.toHaveProperty('connectionId');
  });

  test('ignores stale connection, surface, request, and activation events', async ({ page }) => {
    const result = await page.evaluate(async (path) => {
      const domain = await import(path);
      const connection = domain.walletIframeConnectionIdFromBoundary('connection-a');
      const parse = (surfaceId: string, requestId: string, activationId: string) => {
        const parsed = domain.parseRegistrationActivationSurfaceIdentity({
          surfaceId,
          requestId,
          activationId,
        });
        if (!parsed) throw new Error('identity parse failed');
        return parsed;
      };
      const identity = parse('surface-a', 'request-a', 'activation-a');
      const started = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'registration_activation_prepared',
        connectionId: connection,
        identity,
        wallet: { kind: 'provided', walletId: 'wallet-a' },
        preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
        presentation: {
          kind: 'outline_overlay',
          label: 'Create passkey',
          busyLabel: 'Creating passkey...',
          accessibleLabel: 'Create passkey',
        },
        placement: domain.interactiveRegistrationPlacement({
          top: 10,
          left: 20,
          width: 120,
          height: 48,
        }),
      });
      if (started.kind !== 'applied') throw new Error('surface did not start');
      const changedRect = domain.interactiveRegistrationPlacement({
        top: 100,
        left: 200,
        width: 120,
        height: 48,
      });
      const stale = [
        {
          connectionId: domain.walletIframeConnectionIdFromBoundary('connection-b'),
          identity,
        },
        { connectionId: connection, identity: parse('surface-b', 'request-a', 'activation-a') },
        { connectionId: connection, identity: parse('surface-a', 'request-b', 'activation-a') },
        { connectionId: connection, identity: parse('surface-a', 'request-a', 'activation-b') },
      ].map((owner) =>
        domain.reduceWalletIframeSurface(started.surface, {
          kind: 'registration_activation_placement_changed',
          ...owner,
          placement: changedRect,
        }),
      );
      const active = domain.reduceWalletIframeSurface(started.surface, {
        kind: 'registration_activation_placement_changed',
        connectionId: connection,
        identity,
        placement: changedRect,
      });
      return { stale, active };
    }, SURFACE_DOMAIN_PATH);

    expect(result.stale.map((entry) => entry.kind)).toEqual([
      'ignored',
      'ignored',
      'ignored',
      'ignored',
    ]);
    expect(result.active.kind).toBe('applied');
    expect(result.active.surface.kind).toBe('anchored_registration_activation');
    if (result.active.surface.kind !== 'anchored_registration_activation') {
      throw new Error('expected anchored surface');
    }
    expect(result.active.surface.placement).toMatchObject({
      kind: 'interactive',
      targetRect: { top: 100, left: 200 },
    });
  });

  test('stale cleanup cannot hide a successor', async ({ page }) => {
    const result = await page.evaluate(async (path) => {
      const domain = await import(path);
      const connection = domain.walletIframeConnectionIdFromBoundary('connection-a');
      const successorIdentity = domain.parseRegistrationActivationSurfaceIdentity({
        surfaceId: 'surface-b',
        requestId: 'request-b',
        activationId: 'activation-b',
      });
      if (!successorIdentity) throw new Error('identity parse failed');
      const successor = {
        kind: 'anchored_registration_activation',
        connectionId: connection,
        identity: successorIdentity,
        wallet: { kind: 'provided', walletId: 'wallet-b' },
        preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
        presentation: {
          kind: 'outline_overlay',
          label: 'Create passkey',
          busyLabel: 'Creating passkey...',
          accessibleLabel: 'Create passkey',
        },
        placement: domain.interactiveRegistrationPlacement({
          top: 10,
          left: 20,
          width: 120,
          height: 48,
        }),
        focusOwner: { kind: 'outside' },
      };
      const staleIdentity = domain.parseRegistrationActivationSurfaceIdentity({
        surfaceId: 'surface-a',
        requestId: 'request-a',
        activationId: 'activation-a',
      });
      if (!staleIdentity) throw new Error('stale identity parse failed');
      return domain.reduceWalletIframeSurface(successor, {
        kind: 'registration_activation_finished',
        connectionId: connection,
        identity: staleIdentity,
      });
    }, SURFACE_DOMAIN_PATH);

    expect(result.kind).toBe('ignored');
    expect(result.surface.kind).toBe('anchored_registration_activation');
  });

  test('renderer maps every surface branch to one render mode', async ({ page }) => {
    const modes = await page.evaluate(async (path) => {
      const domain = await import(path);
      const renderer = await import(
        '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/renderer.js'
      );
      const connectionId = domain.walletIframeConnectionIdFromBoundary('connection-a');
      const requestIdentity = {
        kind: 'request_surface_identity_v1',
        surfaceId: 'surface-a',
        requestId: 'request-a',
      };
      const registrationIdentity = {
        kind: 'registration_activation_surface_identity_v1',
        surfaceId: 'surface-a',
        requestId: 'request-a',
        activationId: 'activation-a',
      };
      const common = {
        connectionId,
        identity: requestIdentity,
        userActivation: 'wallet_confirm_button_required',
      };
      const surfaces = [
        domain.hiddenWalletIframeSurface(),
        {
          kind: 'anchored_registration_activation',
          connectionId,
          identity: registrationIdentity,
          wallet: { kind: 'provided', walletId: 'wallet-a' },
          preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
          presentation: {
            kind: 'outline_overlay',
            label: 'Create passkey',
            busyLabel: 'Creating passkey...',
            accessibleLabel: 'Create passkey',
          },
          placement: domain.suspendedRegistrationPlacement({
            top: 10,
            left: 20,
            width: 120,
            height: 48,
          }),
          focusOwner: { kind: 'outside' },
        },
        {
          kind: 'modal_registration_confirm',
          ...common,
          preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
        },
        {
          kind: 'modal_transaction_confirm',
          ...common,
        },
        { kind: 'modal_key_export_confirm', ...common, exportKind: 'near_keypair' },
        { kind: 'modal_unlock_confirm', ...common, unlockKind: 'passkey' },
        { kind: 'modal_recovery_codes', ...common, operation: 'show' },
        { kind: 'modal_device_link_qr', connectionId, identity: requestIdentity },
      ];
      return surfaces.map((surface) => {
        let mode = '';
        const controller = {
          applyHidden: () => {
            mode = 'hidden';
          },
          applyAnchored: () => {
            mode = 'anchored_interactive';
          },
          applyAnchoredSuspended: () => {
            mode = 'anchored_suspended';
          },
          applyViewportModal: () => {
            mode = 'viewport_modal';
          },
        };
        new renderer.WalletIframeSurfaceRenderer(controller).render(surface);
        return mode;
      });
    }, SURFACE_DOMAIN_PATH);

    expect(modes).toEqual([
      'hidden',
      'anchored_suspended',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
      'viewport_modal',
    ]);
  });
});
