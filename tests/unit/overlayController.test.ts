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
    widthCssPx: 360,
    heightCssPx: 320,
    topCssPx: 448,
    leftCssPx: 332,
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

  test('native dialog owns compact modal geometry and exact outside dismissal', async ({ page }) => {
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

  test('uses a transparent drawer backdrop while retaining native modal blocking', async ({
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
        };
      },
      { path: IMPORT_PATHS.overlay, mode: drawerMode('drawer-request', 'drawer-surface') },
    );

    expect(result.drawerClass).toBe(true);
    expect(result.modalClass).toBe(false);
    expect(result.open).toBe(true);
    expect(result.nativeModal).toBe(true);
    expect(result.ariaModal).toBe('true');
    expect(['transparent', 'rgba(0, 0, 0, 0)']).toContain(result.backdropColor);
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
