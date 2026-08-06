import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const SURFACE_DOMAIN_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/domain.js';
const SURFACE_RENDERER_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/renderer.js';
const SURFACE_GEOMETRY_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/geometry.js';

test.describe('wallet iframe surface domain', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('opens registration as a compact modal and arbitrates foreground requests', async ({
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
        presentation: domain.modalWalletIframeSurfacePresentation('Create your wallet'),
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
    expect(result.started.surface.presentation).toEqual({
      kind: 'modal',
      title: 'Create your wallet',
    });
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

  test('ignores stale request completion and renders every current surface compactly', async ({
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
        presentation: domain.modalWalletIframeSurfacePresentation('Create your wallet'),
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
        presentation: domain.modalWalletIframeSurfacePresentation('Confirm transaction'),
      });
      const keyExport = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'key_export_modal_request_started',
        connectionId,
        identity,
        presentation: domain.modalWalletIframeSurfacePresentation('Export key'),
        exportKind: 'near_keypair',
      });
      const unlock = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'unlock_modal_request_started',
        connectionId,
        identity,
        presentation: domain.modalWalletIframeSurfacePresentation('Unlock wallet'),
        unlockKind: 'passkey',
      });
      const recoveryCodes = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'recovery_codes_modal_request_started',
        connectionId,
        identity,
        presentation: domain.modalWalletIframeSurfacePresentation('Recovery codes'),
        operation: 'show',
      });
      const deviceLink = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'device_link_qr_modal_request_started',
        connectionId,
        identity,
        presentation: domain.modalWalletIframeSurfacePresentation('Link device'),
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
        apply(mode: { kind: string }) {
          renderModes.push(mode.kind);
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
      'compact_request_modal',
      'compact_request_modal',
      'compact_request_modal',
      'compact_request_modal',
      'compact_request_modal',
      'compact_request_modal',
    ]);
  });

  test('maps every request-owned surface to compact modal and drawer render modes', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ domainPath, rendererPath, geometryPath }) => {
        const domain = await import(domainPath);
        const renderer = await import(rendererPath);
        const geometry = await import(geometryPath);
        const connectionId = domain.walletIframeConnectionIdFromBoundary('connection-matrix');
        const viewport = {
          widthCssPx: 1024,
          heightCssPx: 768,
          offsetLeftCssPx: 0,
          offsetTopCssPx: 0,
        };
        const measuredSize = { widthCssPx: 344, heightCssPx: 400 };
        const renderSurface = (surface, surfaceGeometry) => {
          let mode;
          const surfaceRenderer = new renderer.WalletIframeSurfaceRenderer({
            apply(nextMode) {
              mode = nextMode;
            },
          });
          surfaceRenderer.render(surface, surfaceGeometry);
          if (!mode) throw new Error('surface renderer did not apply a mode');
          return mode;
        };
        const definitions = [
          { name: 'registration', kind: 'registration_modal_request_started' },
          { name: 'transaction', kind: 'transaction_modal_request_started' },
          { name: 'key_export', kind: 'key_export_modal_request_started' },
          { name: 'unlock', kind: 'unlock_modal_request_started' },
          { name: 'recovery_codes', kind: 'recovery_codes_modal_request_started' },
          { name: 'device_link', kind: 'device_link_qr_modal_request_started' },
          { name: 'auth_menu', kind: 'auth_menu_request_started' },
        ] as const;
        const renderMatrix = [];

        for (const definition of definitions) {
          const identity = domain.requestSurfaceIdentity({
            surfaceId: `surface-${definition.name}`,
            requestId: `request-${definition.name}`,
          });
          const modalPresentation =
            definition.kind === 'auth_menu_request_started'
              ? domain.authMenuWalletIframeSurfacePresentation('Sign in')
              : domain.modalWalletIframeSurfacePresentation(`${definition.name} modal`);
          const modalEvent = (() => {
            switch (definition.kind) {
              case 'registration_modal_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                  preparation: domain.passkeyRegistrationPreparationReceipt(Date.now() + 60_000),
                };
              case 'transaction_modal_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                };
              case 'key_export_modal_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                  exportKind: 'near_keypair',
                };
              case 'unlock_modal_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                  unlockKind: 'passkey',
                };
              case 'recovery_codes_modal_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                  operation: 'show',
                };
              case 'device_link_qr_modal_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                };
              case 'auth_menu_request_started':
                return {
                  kind: definition.kind,
                  connectionId,
                  identity,
                  presentation: modalPresentation,
                  authMenuSessionId: `session-${definition.name}`,
                };
              default: {
                const exhaustive: never = definition.kind;
                throw new Error(`Unhandled surface definition: ${exhaustive}`);
              }
            }
          })();
          const modalStarted = domain.reduceWalletIframeSurface(
            domain.hiddenWalletIframeSurface(),
            modalEvent,
          );
          if (modalStarted.kind !== 'applied') {
            throw new Error(`${definition.name} modal surface did not start`);
          }
          const modalMeasuredGeometry = geometry.measuredWalletIframeSurfaceGeometry(
            modalPresentation,
            viewport,
            measuredSize,
          );
          const modalProvisionalMode = renderSurface(modalStarted.surface);
          const modalMeasuredMode = renderSurface(modalStarted.surface, modalMeasuredGeometry);

          let drawerProvisionalMode = null;
          let drawerMeasuredMode = null;
          if (definition.kind !== 'auth_menu_request_started') {
            const drawerPresentation = domain.drawerWalletIframeSurfacePresentation(
              `${definition.name} drawer`,
            );
            const drawerEvent = { ...modalEvent, presentation: drawerPresentation };
            const drawerStarted = domain.reduceWalletIframeSurface(
              domain.hiddenWalletIframeSurface(),
              drawerEvent,
            );
            if (drawerStarted.kind !== 'applied') {
              throw new Error(`${definition.name} drawer surface did not start`);
            }
            const drawerMeasuredGeometry = geometry.measuredWalletIframeSurfaceGeometry(
              drawerPresentation,
              viewport,
              measuredSize,
            );
            drawerProvisionalMode = renderSurface(drawerStarted.surface);
            drawerMeasuredMode = renderSurface(drawerStarted.surface, drawerMeasuredGeometry);
          }

          renderMatrix.push({
            name: definition.name,
            surfaceKind: modalStarted.surface.kind,
            modalProvisional: {
              mode: modalProvisionalMode.kind,
              geometry: modalProvisionalMode.geometry.kind,
            },
            modalMeasured: {
              mode: modalMeasuredMode.kind,
              geometry: modalMeasuredMode.geometry.kind,
            },
            drawerProvisional: drawerProvisionalMode
              ? {
                  mode: drawerProvisionalMode.kind,
                  geometry: drawerProvisionalMode.geometry.kind,
                  edge: drawerProvisionalMode.geometry.edge,
                }
              : null,
            drawerMeasured: drawerMeasuredMode
              ? {
                  mode: drawerMeasuredMode.kind,
                  geometry: drawerMeasuredMode.geometry.kind,
                  edge: drawerMeasuredMode.geometry.edge,
                }
              : null,
          });
        }

        return {
          hiddenDomain: domain.hiddenWalletIframeSurface(),
          hiddenMode: renderSurface(domain.hiddenWalletIframeSurface()),
          renderMatrix,
        };
      },
      {
        domainPath: SURFACE_DOMAIN_PATH,
        rendererPath: SURFACE_RENDERER_PATH,
        geometryPath: SURFACE_GEOMETRY_PATH,
      },
    );

    expect(result.hiddenDomain).toEqual({ kind: 'hidden' });
    expect(result.hiddenMode).toEqual({ kind: 'hidden' });
    expect(result.renderMatrix).toEqual([
      {
        name: 'registration',
        surfaceKind: 'modal_registration_confirm',
        modalProvisional: { mode: 'compact_request_modal', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_request_modal', geometry: 'centered_modal' },
        drawerProvisional: {
          mode: 'compact_request_drawer',
          geometry: 'provisional_bottom_drawer',
          edge: 'bottom',
        },
        drawerMeasured: {
          mode: 'compact_request_drawer',
          geometry: 'bottom_drawer',
          edge: 'bottom',
        },
      },
      {
        name: 'transaction',
        surfaceKind: 'modal_transaction_confirm',
        modalProvisional: { mode: 'compact_request_modal', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_request_modal', geometry: 'centered_modal' },
        drawerProvisional: {
          mode: 'compact_request_drawer',
          geometry: 'provisional_bottom_drawer',
          edge: 'bottom',
        },
        drawerMeasured: {
          mode: 'compact_request_drawer',
          geometry: 'bottom_drawer',
          edge: 'bottom',
        },
      },
      {
        name: 'key_export',
        surfaceKind: 'modal_key_export_confirm',
        modalProvisional: { mode: 'compact_request_modal', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_request_modal', geometry: 'centered_modal' },
        drawerProvisional: {
          mode: 'compact_request_drawer',
          geometry: 'provisional_bottom_drawer',
          edge: 'bottom',
        },
        drawerMeasured: {
          mode: 'compact_request_drawer',
          geometry: 'bottom_drawer',
          edge: 'bottom',
        },
      },
      {
        name: 'unlock',
        surfaceKind: 'modal_unlock_confirm',
        modalProvisional: { mode: 'compact_request_modal', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_request_modal', geometry: 'centered_modal' },
        drawerProvisional: {
          mode: 'compact_request_drawer',
          geometry: 'provisional_bottom_drawer',
          edge: 'bottom',
        },
        drawerMeasured: {
          mode: 'compact_request_drawer',
          geometry: 'bottom_drawer',
          edge: 'bottom',
        },
      },
      {
        name: 'recovery_codes',
        surfaceKind: 'modal_recovery_codes',
        modalProvisional: { mode: 'compact_request_modal', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_request_modal', geometry: 'centered_modal' },
        drawerProvisional: {
          mode: 'compact_request_drawer',
          geometry: 'provisional_bottom_drawer',
          edge: 'bottom',
        },
        drawerMeasured: {
          mode: 'compact_request_drawer',
          geometry: 'bottom_drawer',
          edge: 'bottom',
        },
      },
      {
        name: 'device_link',
        surfaceKind: 'modal_device_link_qr',
        modalProvisional: { mode: 'compact_request_modal', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_request_modal', geometry: 'centered_modal' },
        drawerProvisional: {
          mode: 'compact_request_drawer',
          geometry: 'provisional_bottom_drawer',
          edge: 'bottom',
        },
        drawerMeasured: {
          mode: 'compact_request_drawer',
          geometry: 'bottom_drawer',
          edge: 'bottom',
        },
      },
      {
        name: 'auth_menu',
        surfaceKind: 'modal_auth_menu',
        modalProvisional: { mode: 'compact_auth_menu', geometry: 'provisional_centered_modal' },
        modalMeasured: { mode: 'compact_auth_menu', geometry: 'centered_modal' },
        drawerProvisional: null,
        drawerMeasured: null,
      },
    ]);
  });

  test('owns auth-menu visibility by exact session identity', async ({ page }) => {
    const result = await page.evaluate(async (path) => {
      const domain = await import(path);
      const connectionId = domain.walletIframeConnectionIdFromBoundary('connection-auth-menu');
      const identity = domain.requestSurfaceIdentity({
        surfaceId: 'surface-auth-menu',
        requestId: 'request-auth-menu',
      });
      const sessionId = 'auth-menu-session';
      const staleSessionId = 'stale-auth-menu-session';
      const started = domain.reduceWalletIframeSurface(domain.hiddenWalletIframeSurface(), {
        kind: 'auth_menu_request_started',
        connectionId,
        identity,
        presentation: domain.authMenuWalletIframeSurfacePresentation('Sign in'),
        authMenuSessionId: sessionId,
      });
      if (started.kind !== 'applied') throw new Error('auth-menu surface did not start');
      const staleStart = domain.reduceWalletIframeSurface(started.surface, {
        kind: 'auth_menu_request_started',
        connectionId,
        identity,
        presentation: domain.authMenuWalletIframeSurfacePresentation('Sign in'),
        authMenuSessionId: staleSessionId,
      });
      const staleClose = domain.reduceWalletIframeSurface(started.surface, {
        kind: 'auth_menu_request_closed',
        connectionId,
        identity,
        authMenuSessionId: staleSessionId,
      });
      const closed = domain.reduceWalletIframeSurface(started.surface, {
        kind: 'auth_menu_request_closed',
        connectionId,
        identity,
        authMenuSessionId: sessionId,
      });
      return { started, staleStart, staleClose, closed };
    }, '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/domain.js');

    expect(result.started.surface.kind).toBe('modal_auth_menu');
    expect(result.started.surface.presentation).toEqual({
      kind: 'auth_menu_modal',
      title: 'Sign in',
    });
    expect(result.staleStart).toMatchObject({
      kind: 'rejected',
      surface: { kind: 'modal_auth_menu', authMenuSessionId: 'auth-menu-session' },
    });
    expect(result.staleClose).toMatchObject({
      kind: 'ignored',
      surface: { kind: 'modal_auth_menu' },
    });
    expect(result.closed).toMatchObject({ kind: 'applied', surface: { kind: 'hidden' } });
  });
});
