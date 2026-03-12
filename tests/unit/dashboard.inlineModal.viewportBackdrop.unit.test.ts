import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  react: '/node_modules/.vite/deps/react.js',
  reactDomClient: '/node_modules/.vite/deps/react-dom_client.js',
  reactDom: '/node_modules/.vite/deps/react-dom.js',
  dashboardInlineModal: '/src/pages/dashboard/components/DashboardInlineModal.tsx',
} as const;

test.describe('DashboardInlineModal viewport backdrop', () => {
  test('anchors to the dashboard overlay layer while scroll-locking dashboard-main', async ({
    page,
  }) => {
    await page.goto('/dashboard/login');

    const result = await page.evaluate(async ({ paths }) => {
      const reactMod: any = await import(paths.react);
      const reactDomClientMod: any = await import(paths.reactDomClient);
      const reactDomMod: any = await import(paths.reactDom);
      const inlineModalMod: any = await import(paths.dashboardInlineModal);

      const React = reactMod.default || reactMod;
      const ReactDOMClient = reactDomClientMod.default || reactDomClientMod;
      const ReactDOM = reactDomMod.default || reactDomMod;
      const DashboardInlineModal =
        inlineModalMod.DashboardInlineModal || inlineModalMod.default || null;

      if (typeof DashboardInlineModal !== 'function') {
        throw new Error('DashboardInlineModal export missing');
      }

      const waitFor = async (
        predicate: () => boolean,
        timeoutMs = 3000,
        intervalMs = 10,
      ): Promise<void> => {
        const started = Date.now();
        while (Date.now() - started < timeoutMs) {
          if (predicate()) return;
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
        throw new Error('Timed out waiting for inline modal state');
      };

      const shell = document.createElement('main');
      shell.className = 'dashboard-shell';
      shell.setAttribute('aria-label', 'Test dashboard shell');

      const topbar = document.createElement('header');
      topbar.className = 'dashboard-topbar';
      shell.appendChild(topbar);

      const sidebar = document.createElement('aside');
      sidebar.className = 'dashboard-sidebar';
      shell.appendChild(sidebar);

      const main = document.createElement('section');
      main.className = 'dashboard-main';
      shell.appendChild(main);

      const filler = document.createElement('div');
      filler.style.height = '2400px';
      main.appendChild(filler);

      const overlayLayer = document.createElement('div');
      overlayLayer.className = 'dashboard-overlay-layer';
      shell.appendChild(overlayLayer);

      const mount = document.createElement('div');
      mount.id = 'dashboard-inline-modal-test-root';
      main.appendChild(mount);
      document.body.appendChild(shell);
      main.scrollTop = 640;

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(
          React.createElement(
            DashboardInlineModal,
            {
              isOpen: true,
              ariaLabel: 'Inline modal viewport test',
              onRequestClose: () => {},
            },
            React.createElement('div', null, 'Modal body'),
          ),
        );
      });

      await waitFor(() => Boolean(document.querySelector('.dashboard-inline-modal-backdrop')));
      await new Promise((resolve) => window.requestAnimationFrame(() => resolve(undefined)));

      const backdrop = document.querySelector('.dashboard-inline-modal-backdrop') as HTMLElement | null;
      const dialog = document.querySelector('[aria-label="Inline modal viewport test"]') as
        | HTMLElement
        | null;

      if (!backdrop || !dialog) {
        throw new Error('Inline modal elements not found');
      }

      const backdropStyles = getComputedStyle(backdrop);
      const backdropRect = backdrop.getBoundingClientRect();
      const dialogRect = dialog.getBoundingClientRect();
      const overlayRect = overlayLayer.getBoundingClientRect();
      const lockedWhileOpen = main.classList.contains('dashboard-main--modal-open');
      const overlayStyledWhileOpen = overlayLayer.classList.contains(
        'dashboard-overlay-layer--modal-open',
      );
      const bodyOverflowWhileOpen = document.body.style.overflow;
      const positionWhileOpen = backdropStyles.position;
      const backdropParentClassName = backdrop.parentElement?.className || '';
      const backdropClassName = backdrop.className;

      ReactDOM.flushSync(() => {
        root.unmount();
      });
      await new Promise((resolve) => window.requestAnimationFrame(() => resolve(undefined)));

      const lockedAfterClose = main.classList.contains('dashboard-main--modal-open');
      const overlayStyledAfterClose = overlayLayer.classList.contains(
        'dashboard-overlay-layer--modal-open',
      );

      shell.remove();

      return {
        position: positionWhileOpen,
        backdropParentClassName,
        backdropClassName,
        backdropTopPx: backdropRect.top,
        overlayTopPx: overlayRect.top,
        dialogTopPx: dialogRect.top,
        lockedWhileOpen,
        lockedAfterClose,
        overlayStyledWhileOpen,
        overlayStyledAfterClose,
        bodyOverflowWhileOpen,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.position).toBe('absolute');
    expect(result.backdropParentClassName).toContain('dashboard-overlay-layer');
    expect(result.backdropClassName).not.toContain('dashboard-inline-modal-backdrop--self-styled');
    expect(Math.abs(result.backdropTopPx - result.overlayTopPx)).toBeLessThan(1);
    expect(result.dialogTopPx).toBeGreaterThan(0);
    expect(result.lockedWhileOpen).toBe(true);
    expect(result.lockedAfterClose).toBe(false);
    expect(result.overlayStyledWhileOpen).toBe(true);
    expect(result.overlayStyledAfterClose).toBe(false);
    expect(result.bodyOverflowWhileOpen).toBe('');
  });
});
