import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  overlay: '/_test-sdk/esm/SeamsWeb/walletIframe/client/overlay/overlay-controller.js',
} as const;

const modalMode = (requestId: string, surfaceId: string) => ({
  kind: 'compact_request_modal' as const,
  presentation: { kind: 'modal' as const, title: 'Confirm transaction' },
  geometry: {
    kind: 'centered_modal' as const,
    widthCssPx: 360,
    heightCssPx: 320,
    topCssPx: 224,
    leftCssPx: 332,
  },
  focusTrap: true,
  identity: {
    kind: 'request_surface_identity_v1' as const,
    surfaceId,
    requestId,
  },
});

const drawerMode = (requestId: string, surfaceId: string) => ({
  kind: 'compact_request_drawer' as const,
  presentation: { kind: 'drawer' as const, title: 'Choose account' },
  geometry: {
    kind: 'bottom_drawer' as const,
    edge: 'bottom' as const,
    widthCssPx: 1024,
    heightCssPx: 768,
    topCssPx: 0,
    leftCssPx: 0,
  },
  focusTrap: true,
  identity: {
    kind: 'request_surface_identity_v1' as const,
    surfaceId,
    requestId,
  },
});

test.describe('OverlayController', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('native dialog owns compact modal geometry and exact outside dismissal', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.overlay);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const dismissals: unknown[] = [];
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
          onDismiss: (event: unknown) => dismissals.push(event),
        });

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 360,
            heightCssPx: 320,
            topCssPx: 224,
            leftCssPx: 332,
          },
          focusTrap: true,
          identity: {
            kind: 'request_surface_identity_v1',
            surfaceId: 'surface-a',
            requestId: 'request-a',
          },
        });
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        const modal = {
          ...overlay.getState(),
          dialogOpen: dialog.open,
          iframeParent: iframe.parentElement === dialog,
          title: iframe.getAttribute('title'),
          pointerEvents: getComputedStyle(iframe).pointerEvents,
          dialogBackground: getComputedStyle(dialog).backgroundColor,
          dialogOutline: getComputedStyle(dialog).outlineStyle,
          iframeBackground: getComputedStyle(iframe).backgroundColor,
          iframeOutline: getComputedStyle(iframe).outlineStyle,
          ariaHidden: iframe.getAttribute('aria-hidden'),
          hasInlineIframeStyle: iframe.hasAttribute('style'),
          hasInlineDialogStyle: dialog.hasAttribute('style'),
        };

        const rect = dialog.getBoundingClientRect();
        dialog.dispatchEvent(
          new PointerEvent('pointerdown', {
            bubbles: true,
            pointerId: 1,
            clientX: rect.left + 20,
            clientY: rect.top + 20,
          }),
        );
        window.dispatchEvent(
          new PointerEvent('pointerup', {
            bubbles: true,
            pointerId: 1,
            clientX: -100,
            clientY: -100,
          }),
        );
        const dragDismissals = dismissals.length;

        dialog.dispatchEvent(
          new PointerEvent('pointerdown', {
            bubbles: true,
            pointerId: 2,
            clientX: -100,
            clientY: -100,
          }),
        );
        window.dispatchEvent(
          new PointerEvent('pointerup', {
            bubbles: true,
            pointerId: 2,
            clientX: -100,
            clientY: -100,
          }),
        );
        const outsideDismissals = dismissals.length;

        overlay.apply({ kind: 'hidden' });
        const hidden = {
          ...overlay.getState(),
          width: getComputedStyle(iframe).width,
          height: getComputedStyle(iframe).height,
          pointerEvents: getComputedStyle(iframe).pointerEvents,
          ariaHidden: iframe.getAttribute('aria-hidden'),
          tabIndex: iframe.getAttribute('tabindex'),
          title: iframe.getAttribute('title'),
          hiddenClass: iframe.classList.contains('is-hidden'),
        };

        return { modal, hidden, dragDismissals, outsideDismissals };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.modal.visible).toBe(true);
    expect(res.modal.mode).toBe('compact_modal');
    expect(res.modal.dialogOpen).toBe(true);
    expect(res.modal.iframeParent).toBe(true);
    expect(res.modal.title).toBe('Confirm transaction');
    expect(res.modal.pointerEvents).toBe('auto');
    expect(res.modal.dialogBackground).toBe('rgba(0, 0, 0, 0)');
    expect(res.modal.dialogOutline).toBe('none');
    expect(res.modal.iframeBackground).toBe('rgba(0, 0, 0, 0)');
    expect(res.modal.iframeOutline).toBe('none');
    expect(res.modal.ariaHidden).toBe('false');
    expect(res.modal.hasInlineIframeStyle).toBe(false);
    expect(res.modal.hasInlineDialogStyle).toBe(false);
    expect(res.dragDismissals).toBe(0);
    expect(res.outsideDismissals).toBe(1);
    expect(res.hidden.visible).toBe(false);
    expect(res.hidden.mode).toBe('hidden');
    expect(res.hidden.dialogOpen).toBe(false);
    expect(res.hidden.width).toBe('0px');
    expect(res.hidden.height).toBe('0px');
    expect(res.hidden.pointerEvents).toBe('none');
    expect(res.hidden.ariaHidden).toBe('true');
    expect(res.hidden.tabIndex).toBe('-1');
    expect(res.hidden.title).toBeNull();
    expect(res.hidden.hiddenClass).toBe(true);
  });

  test('keeps the host backdrop transparent until modal geometry is measured', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
        });
        const identity = {
          kind: 'request_surface_identity_v1' as const,
          surfaceId: 'provisional-surface',
          requestId: 'provisional-request',
        };
        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'provisional_centered_modal',
            widthCssPx: 416,
            heightCssPx: 128,
            topCssPx: 320,
            leftCssPx: 304,
          },
          focusTrap: true,
          identity,
        });
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        const provisionalBackdrop = getComputedStyle(dialog, '::backdrop').backgroundColor;

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'viewport_fallback',
            reason: 'measurement_unavailable',
            widthCssPx: 1024,
            heightCssPx: 768,
            topCssPx: 0,
            leftCssPx: 0,
          },
          focusTrap: true,
          identity,
        });
        const fallbackBackdrop = getComputedStyle(dialog, '::backdrop').backgroundColor;

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 416,
            heightCssPx: 320,
            topCssPx: 224,
            leftCssPx: 304,
          },
          focusTrap: true,
          identity,
        });
        await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
        const measuredAnimationName = getComputedStyle(dialog, '::backdrop').animationName;
        await new Promise<void>((resolve) => window.setTimeout(resolve, 220));
        const measuredBackdrop = getComputedStyle(dialog, '::backdrop').backgroundColor;
        overlay.dispose();
        return {
          provisionalBackdrop,
          fallbackBackdrop,
          measuredBackdrop,
          measuredAnimationName,
        };
      },
      { path: IMPORT_PATHS.overlay },
    );

    expect(result.provisionalBackdrop).toBe('rgba(0, 0, 0, 0)');
    expect(result.fallbackBackdrop).toBe('rgba(0, 0, 0, 0)');
    expect(result.measuredAnimationName).toBe('w3a-wallet-overlay-backdrop-in');
    expect(result.measuredBackdrop).toBe('rgba(0, 0, 0, 0.26)');
  });

  test('reveals a measured request modal from the existing wallet card geometry', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ path }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
        });
        overlay.apply({
          kind: 'compact_auth_menu',
          presentation: { kind: 'auth_menu_modal', title: 'Wallet recovery codes' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 460,
            heightCssPx: 360,
            topCssPx: 164,
            leftCssPx: 282,
          },
          focusTrap: true,
          identity: {
            kind: 'request_surface_identity_v1',
            surfaceId: 'auth-menu-surface',
            requestId: 'auth-menu-request',
          },
          authMenuSessionId: 'auth-menu-session',
        });
        const identity = {
          kind: 'request_surface_identity_v1' as const,
          surfaceId: 'recovery-surface',
          requestId: 'recovery-request',
        };
        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Back up recovery codes' },
          geometry: {
            kind: 'provisional_centered_modal',
            widthCssPx: 560,
            heightCssPx: 320,
            topCssPx: 224,
            leftCssPx: 232,
          },
          focusTrap: true,
          identity,
        });
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        const provisional = {
          open: dialog.open,
          visibility: getComputedStyle(dialog).visibility,
        };

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Back up recovery codes' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 560,
            heightCssPx: 580,
            topCssPx: 94,
            leftCssPx: 232,
          },
          focusTrap: true,
          identity,
        });
        const beforeReveal = {
          open: dialog.open,
          visibility: getComputedStyle(dialog).visibility,
          pending: dialog.classList.contains('is-reveal-pending'),
        };

        await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
        const animation = dialog
          .getAnimations()
          .find(
            (candidate) =>
              candidate.effect instanceof KeyframeEffect && candidate.effect.target === dialog,
          );
        if (!animation || !(animation.effect instanceof KeyframeEffect)) {
          throw new Error('surface morph animation missing');
        }
        animation.pause();
        animation.currentTime = 0;
        const firstVisibleRect = dialog.getBoundingClientRect().toJSON();
        const firstKeyframe = animation.effect.getKeyframes()[0];
        const revealed = {
          visibility: getComputedStyle(dialog).visibility,
          pending: dialog.classList.contains('is-reveal-pending'),
          transitionOrigin: dialog.classList.contains('has-transition-origin'),
          backdrop: getComputedStyle(dialog, '::backdrop').backgroundColor,
        };

        animation.finish();
        await Promise.resolve();
        const finalRect = dialog.getBoundingClientRect().toJSON();
        overlay.dispose();
        return { provisional, beforeReveal, revealed, firstVisibleRect, finalRect, firstKeyframe };
      },
      { path: IMPORT_PATHS.overlay },
    );

    expect(result.provisional).toEqual({ open: false, visibility: 'hidden' });
    expect(result.beforeReveal).toEqual({ open: true, visibility: 'hidden', pending: true });
    expect(result.revealed).toEqual({
      visibility: 'visible',
      pending: false,
      transitionOrigin: true,
      backdrop: 'rgba(0, 0, 0, 0)',
    });
    expect(result.firstVisibleRect).toMatchObject({
      top: 164,
      left: 282,
      width: 460,
      height: 360,
    });
    expect(result.finalRect).toMatchObject({
      top: 94,
      left: 232,
      width: 560,
      height: 580,
    });
    expect(result.firstKeyframe.transform).toContain('translate(50px, 70px)');
    expect(result.firstKeyframe.opacity).toBeUndefined();
  });

  test('morphs one measured request modal when its content size changes', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
        });
        const identity = {
          kind: 'request_surface_identity_v1' as const,
          surfaceId: 'recovery-surface',
          requestId: 'recovery-request',
        };
        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Wallet recovery codes' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 460,
            heightCssPx: 360,
            topCssPx: 164,
            leftCssPx: 282,
          },
          focusTrap: true,
          identity,
        });
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
        const dialogBeforeResize = dialog;

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Wallet recovery codes' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 560,
            heightCssPx: 580,
            topCssPx: 94,
            leftCssPx: 232,
          },
          focusTrap: true,
          identity,
        });
        const animation = dialog
          .getAnimations()
          .find(
            (candidate) =>
              candidate.effect instanceof KeyframeEffect && candidate.effect.target === dialog,
          );
        if (!animation || !(animation.effect instanceof KeyframeEffect)) {
          throw new Error('surface morph animation missing');
        }
        animation.pause();
        animation.currentTime = 0;
        const firstVisibleRect = dialog.getBoundingClientRect().toJSON();
        const firstKeyframe = animation.effect.getKeyframes()[0];
        animation.finish();
        await Promise.resolve();
        const finalRect = dialog.getBoundingClientRect().toJSON();
        const sameDialog = dialogBeforeResize === dialog;

        overlay.dispose();
        return { firstVisibleRect, finalRect, firstKeyframe, sameDialog };
      },
      { path: IMPORT_PATHS.overlay },
    );

    expect(result.sameDialog).toBe(true);
    expect(result.firstVisibleRect).toMatchObject({
      top: 164,
      left: 282,
      width: 460,
      height: 360,
    });
    expect(result.finalRect).toMatchObject({
      top: 94,
      left: 232,
      width: 560,
      height: 580,
    });
    expect(result.firstKeyframe.transform).toContain('translate(50px, 70px)');
    expect(result.firstKeyframe.opacity).toBeUndefined();
  });

  test('keeps a provisional drawer visible for the inner slide-in animation', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent)
              mountParent.appendChild(iframe);
            return iframe;
          },
        });
        const identity = {
          kind: 'request_surface_identity_v1' as const,
          surfaceId: 'provisional-drawer-surface',
          requestId: 'provisional-drawer-request',
        };
        const applyDrawer = (kind: 'provisional_bottom_drawer' | 'bottom_drawer') => {
          overlay.apply({
            kind: 'compact_request_drawer',
            presentation: { kind: 'drawer', title: 'Confirm transaction' },
            geometry: {
              kind,
              edge: 'bottom',
              widthCssPx: 1024,
              heightCssPx: 768,
              topCssPx: 0,
              leftCssPx: 0,
            },
            focusTrap: true,
            identity,
          });
        };

        applyDrawer('provisional_bottom_drawer');
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        const initial = {
          provisional: dialog.classList.contains('is-provisional'),
          dialogVisibility: getComputedStyle(dialog).visibility,
          iframeVisibility: getComputedStyle(iframe).visibility,
          iframePointerEvents: getComputedStyle(iframe).pointerEvents,
        };

        applyDrawer('bottom_drawer');
        const settled = {
          provisional: dialog.classList.contains('is-provisional'),
          dialogVisibility: getComputedStyle(dialog).visibility,
          iframeVisibility: getComputedStyle(iframe).visibility,
          iframePointerEvents: getComputedStyle(iframe).pointerEvents,
          rect: iframe.getBoundingClientRect().toJSON(),
        };
        overlay.dispose();
        return { initial, settled };
      },
      { path: IMPORT_PATHS.overlay },
    );

    expect(result.initial).toEqual({
      provisional: true,
      dialogVisibility: 'visible',
      iframeVisibility: 'visible',
      iframePointerEvents: 'auto',
    });
    expect(result.settled.provisional).toBe(false);
    expect(result.settled.dialogVisibility).toBe('visible');
    expect(result.settled.iframeVisibility).toBe('visible');
    expect(result.settled.iframePointerEvents).toBe('auto');
    expect(result.settled.rect).toMatchObject({
      top: 0,
      left: 0,
      width: 1024,
      height: 768,
    });
  });

  test('paints compact modal elevation in the host after measurement', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent)
              mountParent.appendChild(iframe);
            return iframe;
          },
        });
        const identity = {
          kind: 'request_surface_identity_v1' as const,
          surfaceId: 'shadow-surface',
          requestId: 'shadow-request',
        };
        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'provisional_centered_modal',
            widthCssPx: 360,
            heightCssPx: 320,
            topCssPx: 224,
            leftCssPx: 332,
          },
          focusTrap: true,
          identity,
        });
        const provisionalFilter = getComputedStyle(iframe).filter;

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'viewport_fallback',
            reason: 'measurement_unavailable',
            widthCssPx: 1024,
            heightCssPx: 768,
            topCssPx: 0,
            leftCssPx: 0,
          },
          focusTrap: true,
          identity,
        });
        const fallbackFilter = getComputedStyle(iframe).filter;

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 360,
            heightCssPx: 320,
            topCssPx: 224,
            leftCssPx: 332,
          },
          focusTrap: true,
          identity,
        });
        const measuredFilter = getComputedStyle(iframe).filter;

        overlay.apply({
          kind: 'compact_auth_menu',
          presentation: { kind: 'modal', title: 'Choose account' },
          geometry: {
            kind: 'centered_modal',
            widthCssPx: 360,
            heightCssPx: 320,
            topCssPx: 224,
            leftCssPx: 332,
          },
          focusTrap: true,
          identity: {
            kind: 'request_surface_identity_v1',
            surfaceId: 'auth-menu-shadow-surface',
            requestId: 'auth-menu-shadow-request',
          },
          authMenuSessionId: 'auth-menu-shadow-session',
        });
        const authMenuFilter = getComputedStyle(iframe).filter;
        const rect = iframe.getBoundingClientRect();
        overlay.dispose();
        return {
          provisionalFilter,
          fallbackFilter,
          measuredFilter,
          authMenuFilter,
          measuredWidth: rect.width,
          measuredHeight: rect.height,
        };
      },
      { path: IMPORT_PATHS.overlay },
    );

    expect(result.provisionalFilter).toBe('none');
    expect(result.fallbackFilter).toBe('none');
    expect(result.measuredFilter).toContain('drop-shadow');
    expect(result.authMenuFilter).toContain('drop-shadow');
    expect(result.measuredWidth).toBeCloseTo(360, 0);
    expect(result.measuredHeight).toBeCloseTo(320, 0);
  });

  test('auth menu renders in the host stacking context while modals keep the overlay escape', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ path }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent)
              mountParent.appendChild(iframe);
            return iframe;
          },
        });
        const authMenuGeometry = {
          kind: 'provisional_centered_modal' as const,
          widthCssPx: 416,
          heightCssPx: 450,
          topCssPx: 159,
          leftCssPx: 304,
        };
        const measuredGeometry = {
          kind: 'centered_modal' as const,
          widthCssPx: 360,
          heightCssPx: 320,
          topCssPx: 224,
          leftCssPx: 332,
        };

        overlay.apply({
          kind: 'compact_auth_menu',
          presentation: { kind: 'modal', title: 'Choose account' },
          geometry: authMenuGeometry,
          focusTrap: true,
          identity: {
            kind: 'request_surface_identity_v1',
            surfaceId: 'auth-menu-layer-surface',
            requestId: 'auth-menu-layer-request',
          },
          authMenuSessionId: 'auth-menu-layer-session',
        });
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog') as HTMLDialogElement;
        const authMenu = {
          inlineClass: dialog.classList.contains('w3a-wallet-inline-dialog'),
          zIndex: getComputedStyle(dialog).zIndex,
          // Absolute (document-coordinate) positioning scrolls with the page;
          // fixed would float over it.
          position: getComputedStyle(dialog).position,
          visibility: getComputedStyle(dialog).visibility,
          provisional: dialog.classList.contains('is-provisional'),
          // A non-modal dialog never enters the top layer, so host chrome can
          // paint above it.
          topLayer: dialog.matches(':modal'),
        };

        overlay.apply({
          kind: 'compact_request_modal',
          presentation: { kind: 'modal', title: 'Confirm transaction' },
          geometry: measuredGeometry,
          focusTrap: true,
          identity: {
            kind: 'request_surface_identity_v1',
            surfaceId: 'modal-layer-surface',
            requestId: 'modal-layer-request',
          },
        });
        const modal = {
          inlineClass: dialog.classList.contains('w3a-wallet-inline-dialog'),
          zIndex: getComputedStyle(dialog).zIndex,
          position: getComputedStyle(dialog).position,
          topLayer: dialog.matches(':modal'),
        };

        overlay.dispose();
        return { authMenu, modal };
      },
      { path: IMPORT_PATHS.overlay },
    );

    expect(result.authMenu.inlineClass).toBe(true);
    expect(result.authMenu.zIndex).toBe('auto');
    expect(result.authMenu.position).toBe('absolute');
    expect(result.authMenu.visibility).toBe('visible');
    expect(result.authMenu.provisional).toBe(true);
    expect(result.authMenu.topLayer).toBe(false);
    expect(result.modal.inlineClass).toBe(false);
    expect(result.modal.zIndex).toBe('2147483646');
    expect(result.modal.position).toBe('fixed');
    expect(result.modal.topLayer).toBe(true);
  });

  test('Escape dispatches the exact active cancellation event', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path, mode }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const dismissals: unknown[] = [];
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
          onDismiss: (event: unknown) => dismissals.push(event),
        });

        overlay.apply(mode);
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        const cancelEvent = new Event('cancel', { bubbles: true, cancelable: true });
        const dispatchResult = dialog.dispatchEvent(cancelEvent);

        return {
          dispatchResult,
          defaultPrevented: cancelEvent.defaultPrevented,
          dismissals,
        };
      },
      { path: IMPORT_PATHS.overlay, mode: modalMode('escape-request', 'escape-surface') },
    );

    expect(result.dispatchResult).toBe(false);
    expect(result.defaultPrevented).toBe(true);
    expect(result.dismissals).toEqual([
      {
        identity: {
          kind: 'request_surface_identity_v1',
          surfaceId: 'escape-surface',
          requestId: 'escape-request',
        },
        reason: 'escape',
        generation: 1,
      },
    ]);
  });

  test('restores the opener focus when a visible dialog is hidden', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path, mode }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const opener = document.createElement('button');
        opener.type = 'button';
        opener.textContent = 'Open wallet';
        document.body.appendChild(opener);
        opener.focus();

        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
        });
        overlay.apply(mode);
        overlay.apply({ kind: 'hidden' });
        const restored = document.activeElement === opener;
        const state = overlay.getState();
        overlay.dispose();
        opener.remove();
        return { restored, state };
      },
      { path: IMPORT_PATHS.overlay, mode: modalMode('focus-request', 'focus-surface') },
    );

    expect(result.restored).toBe(true);
    expect(result.state.visible).toBe(false);
    expect(result.state.dialogOpen).toBe(false);
  });

  test('uses a full-viewport drawer with transparent backdrop and native modal blocking', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ path, mode }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
        });
        overlay.apply(mode);
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        const backdrop = getComputedStyle(dialog, '::backdrop');
        return {
          drawerClass: dialog.classList.contains('is-drawer'),
          modalClass: dialog.classList.contains('is-modal'),
          open: dialog.open,
          nativeModal: dialog.matches(':modal'),
          ariaModal: dialog.getAttribute('aria-modal'),
          backdropColor: backdrop.backgroundColor,
          boxShadow: getComputedStyle(dialog).boxShadow,
          transform: getComputedStyle(dialog).transform,
          top: getComputedStyle(dialog).top,
          left: getComputedStyle(dialog).left,
          width: getComputedStyle(dialog).width,
          height: getComputedStyle(dialog).height,
        };
      },
      { path: IMPORT_PATHS.overlay, mode: drawerMode('drawer-request', 'drawer-surface') },
    );

    expect(result.drawerClass).toBe(true);
    expect(result.modalClass).toBe(false);
    expect(result.open).toBe(true);
    expect(result.nativeModal).toBe(true);
    expect(result.ariaModal).toBe('true');
    expect(result.backdropColor).toBe('rgba(0, 0, 0, 0)');
    expect(result.boxShadow).toBe('none');
    expect(result.transform).toBe('none');
    expect(result.top).toBe('0px');
    expect(result.left).toBe('0px');
    expect(result.width).toBe('1024px');
    expect(result.height).toBe('768px');
  });

  test('ignores a stale pointerup after replacing the active generation', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path, firstMode, replacementMode }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const dismissals: unknown[] = [];
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
          onDismiss: (event: unknown) => dismissals.push(event),
        });

        overlay.apply(firstMode);
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        dialog.dispatchEvent(
          new PointerEvent('pointerdown', {
            bubbles: true,
            pointerId: 19,
            clientX: -100,
            clientY: -100,
          }),
        );
        overlay.apply(replacementMode);
        const replacementGeneration = overlay.getState().generation;
        window.dispatchEvent(
          new PointerEvent('pointerup', {
            bubbles: true,
            pointerId: 19,
            clientX: -100,
            clientY: -100,
          }),
        );
        const staleDismissalCount = dismissals.length;

        dialog.dispatchEvent(
          new PointerEvent('pointerdown', {
            bubbles: true,
            pointerId: 20,
            clientX: -100,
            clientY: -100,
          }),
        );
        window.dispatchEvent(
          new PointerEvent('pointerup', {
            bubbles: true,
            pointerId: 20,
            clientX: -100,
            clientY: -100,
          }),
        );

        return { replacementGeneration, staleDismissalCount, dismissals };
      },
      {
        path: IMPORT_PATHS.overlay,
        firstMode: modalMode('first-request', 'first-surface'),
        replacementMode: modalMode('replacement-request', 'replacement-surface'),
      },
    );

    expect(result.replacementGeneration).toBe(2);
    expect(result.staleDismissalCount).toBe(0);
    expect(result.dismissals).toEqual([
      {
        identity: {
          kind: 'request_surface_identity_v1',
          surfaceId: 'replacement-surface',
          requestId: 'replacement-request',
        },
        reason: 'backdrop',
        generation: 2,
      },
    ]);
  });

  test('dispose removes the dialog and disconnects dismissal listeners', async ({ page }) => {
    const result = await page.evaluate(
      async ({ path, mode }) => {
        const mod = await import(path);
        const OverlayController = (mod as any).OverlayController || (mod as any).default;
        const iframe = document.createElement('iframe');
        const dismissals: unknown[] = [];
        const overlay = new OverlayController({
          ensureIframe: (mountParent?: HTMLElement) => {
            if (mountParent && iframe.parentElement !== mountParent) {
              mountParent.appendChild(iframe);
            }
            return iframe;
          },
          onDismiss: (event: unknown) => dismissals.push(event),
        });
        overlay.apply(mode);
        const dialog = iframe.closest('dialog.w3a-wallet-overlay-dialog');
        if (!(dialog instanceof HTMLDialogElement)) throw new Error('overlay dialog missing');
        overlay.dispose();

        dialog.dispatchEvent(new Event('cancel', { bubbles: true, cancelable: true }));
        dialog.dispatchEvent(
          new PointerEvent('pointerdown', {
            bubbles: true,
            pointerId: 21,
            clientX: -100,
            clientY: -100,
          }),
        );
        window.dispatchEvent(
          new PointerEvent('pointerup', {
            bubbles: true,
            pointerId: 21,
            clientX: -100,
            clientY: -100,
          }),
        );

        return {
          dialogConnected: dialog.isConnected,
          iframeConnected: iframe.isConnected,
          state: overlay.getState(),
          dismissals,
        };
      },
      { path: IMPORT_PATHS.overlay, mode: modalMode('dispose-request', 'dispose-surface') },
    );

    expect(result.dialogConnected).toBe(false);
    expect(result.iframeConnected).toBe(false);
    expect(result.state).toEqual({
      visible: false,
      mode: 'hidden',
      dialogOpen: false,
      generation: 2,
    });
    expect(result.dismissals).toEqual([]);
  });
});
