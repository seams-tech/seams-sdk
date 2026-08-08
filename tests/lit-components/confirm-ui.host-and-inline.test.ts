import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { waitFor as harnessWaitFor } from '../wallet-iframe/harness';
import { ActionType, type TransactionInputWasm, type ActionArgsWasm } from '@/core/types/actions';

const SECURITY_CONTEXT = {
  rpId: 'example.com',
  blockHeight: '1',
  blockHash: 'h',
};

const PASSKEY_REGISTRATION_SECURITY_CONTEXT = {
  rpId: 'example.com',
  passkeyRegistration: {
    kind: 'passkey_registration_confirm_display_v1',
    intendedUserName: 'alice.testnet',
    accountId: 'alice.testnet',
    rpId: 'example.com',
    signerSlot: 1,
  },
};

const SUMMARY = { intentDigest: 'intent-xyz' } as any;
const WAIT_FOR_SOURCE = `(${harnessWaitFor.toString()})`;
const IMPORT_PATHS = {
  confirmUi: SDK_ESM_PATHS.confirmUi,
  events: SDK_ESM_PATHS.walletEvents,
} as const;

test.describe('confirm-ui inline confirmer', () => {
  test.describe.configure({ timeout: 20_000 });

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('modal confirm resolves with confirmed=true', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.getElementById('w3a-confirm-portal')?.firstElementChild);
        const portalChild = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        await waitFor(() => !!portalChild?.querySelector?.('w3a-drawer-tx-confirmer'));
        portalChild?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
            detail: { confirmed: true },
            bubbles: true,
            composed: true,
          } as any),
        );

        const { confirmed } = await decisionPromise;
        return { confirmed };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result.confirmed).toBe(true);
  });

  test('registration preparation becomes interactive without remounting the modal', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ securityContext, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision, mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const ctx = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
        };
        const preparationHandle = await mountConfirmUI({
          ctx,
          summary: {
            title: 'Create your passkey',
            body: 'Preparing secure registration…',
          },
          securityContext: securityContext as any,
          loading: true,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });
        const preparationElement = preparationHandle.element as any;
        const decisionPromise = awaitConfirmUIDecision({
          ctx,
          surface: {
            kind: 'reuse_mounted',
            handle: preparationHandle,
          },
          summary: {
            title: 'Create your passkey',
            body: 'Use Touch ID or your device passkey to create credentials for this account.',
          },
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(
          () =>
            preparationElement.loading === false &&
            preparationElement.body.startsWith('Use Touch ID'),
        );
        const interactiveElement = document.querySelector('w3a-tx-confirmer');
        const modalCount = document.querySelectorAll('w3a-tx-confirmer').length;
        preparationElement.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
            bubbles: true,
            composed: true,
          }),
        );
        const decision = await decisionPromise;
        decision.handle.close(false);
        return {
          sameElement: preparationElement === interactiveElement,
          modalCount,
          confirmed: decision.confirmed,
        };
      },
      {
        securityContext: SECURITY_CONTEXT,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result).toEqual({
      sameElement: true,
      modalCount: 1,
      confirmed: false,
    });
  });

  test('drawer cancel resolves with confirmed=false', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx =
          (window as any).ctxStub ||
          ((window as any).ctxStub = buildCtxStub({
            userPreferencesManager: {
              getCurrentWalletId: () => 'alice.testnet',
              getConfirmationConfig: () => ({
                uiMode: 'drawer',
                behavior: 'requireClick',
                autoProceedDelay: 0,
                theme: 'dark',
              }),
            },
          }));

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'drawer',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.getElementById('w3a-confirm-portal')?.firstElementChild);
        const portalChild = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        portalChild?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
            bubbles: true,
            composed: true,
          } as any),
        );

        const { confirmed } = await decisionPromise;
        return { confirmed };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result.confirmed).toBe(false);
  });

  test('modal loading state still allows cancel button click', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          loading: true,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.querySelector('w3a-tx-confirm-content .cancel'));
        const cancelButton = document.querySelector(
          'w3a-tx-confirm-content .cancel',
        ) as HTMLButtonElement | null;
        const cancelDisabled = cancelButton?.disabled ?? null;

        cancelButton?.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));

        const { confirmed, handle } = await decisionPromise;
        handle?.close?.(confirmed);
        return { confirmed, cancelDisabled };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result.cancelDisabled).toBe(false);
    expect(result.confirmed).toBe(false);
  });

  test('passkey registration modal allows cancel during loading', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          loading: true,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.querySelector('.passkey-registration-confirm .btn-cancel'));
        const cancelButton = document.querySelector(
          '.passkey-registration-confirm .btn-cancel',
        ) as HTMLButtonElement | null;
        const cancelDisabled = cancelButton?.disabled ?? null;

        cancelButton?.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));

        const { confirmed, handle } = await decisionPromise;
        handle?.close?.(confirmed);
        return { confirmed, cancelDisabled };
      },
      {
        securityContext: PASSKEY_REGISTRATION_SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result.cancelDisabled).toBe(false);
    expect(result.confirmed).toBe(false);
  });

  test('surface binding keeps wallet overlays in the host and preserves standalone dismissal', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const walletCtx = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: {
            kind: 'wallet_iframe',
            requestId: 'request-a',
            postMeasurement: () => undefined,
          },
        };

        const walletDecisionPromise = awaitConfirmUIDecision({
          ctx: walletCtx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(
          () =>
            document
              .getElementById('w3a-confirm-portal')
              ?.firstElementChild?.getAttribute('data-w3a-confirm-surface') === 'wallet-iframe',
        );
        await waitFor(
          () =>
            !!document
              .getElementById('w3a-confirm-portal')
              ?.firstElementChild?.querySelector('w3a-modal-tx-confirmer'),
        );
        const walletHost = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        const walletModal = walletHost?.querySelector('w3a-modal-tx-confirmer');
        const walletHasStandaloneBackdrop = Boolean(
          walletModal?.querySelector('.standalone-surface-backdrop'),
        );
        walletHost?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
            bubbles: true,
            composed: true,
          }),
        );
        const walletDecision = await walletDecisionPromise;
        walletDecision.handle.close(false);

        const standaloneCtx = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
        };
        const standaloneDecisionPromise = awaitConfirmUIDecision({
          ctx: standaloneCtx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(
          () =>
            document
              .getElementById('w3a-confirm-portal')
              ?.firstElementChild?.getAttribute('data-w3a-confirm-surface') === 'standalone',
        );
        await waitFor(
          () =>
            !!document
              .getElementById('w3a-confirm-portal')
              ?.firstElementChild?.querySelector('.standalone-surface-backdrop'),
        );
        const standaloneHost = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        const standaloneModal = standaloneHost?.querySelector('w3a-modal-tx-confirmer');
        const standaloneBackdrop = standaloneModal?.querySelector(
          '.standalone-surface-backdrop',
        ) as HTMLElement | null;
        standaloneBackdrop?.dispatchEvent(
          new MouseEvent('click', { bubbles: true, composed: true }),
        );

        const standaloneDecision = await standaloneDecisionPromise;
        standaloneDecision.handle.close(false);
        return {
          walletSurface: walletHost?.getAttribute('data-w3a-confirm-surface'),
          walletHasStandaloneBackdrop,
          standaloneSurface: standaloneHost?.getAttribute('data-w3a-confirm-surface'),
          standaloneHasBackdrop: Boolean(standaloneBackdrop),
          standaloneConfirmed: standaloneDecision.confirmed,
        };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result).toEqual({
      walletSurface: 'wallet-iframe',
      walletHasStandaloneBackdrop: false,
      standaloneSurface: 'standalone',
      standaloneHasBackdrop: true,
      standaloneConfirmed: false,
    });
  });

  /**
   * Key export pins its host box to a full-viewport drawer for the whole request
   * (the key viewer is always a drawer) while the Email OTP prompt inside that
   * same box still follows the Confirmer UI setting. A modal prompt therefore
   * has to self-centre on the full-viewport canvas — inferring the box shape
   * from the prompt's own 'modal' variant makes it a hugging `wallet-iframe`
   * surface with nothing sizing it, which strands the card in the top-left
   * corner of the screen. See walletIframe/README.md.
   */
  test('a modal confirmation in a drawer-pinned host box takes the standalone surface', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const ctx = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: {
            kind: 'wallet_iframe',
            requestId: 'request-export',
            postMeasurement: () => undefined,
            hostSurfaceVariant: 'drawer',
          },
        };

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(
          () =>
            document
              .getElementById('w3a-confirm-portal')
              ?.firstElementChild?.getAttribute('data-w3a-confirm-surface') === 'standalone',
        );
        await waitFor(
          () =>
            !!document
              .getElementById('w3a-confirm-portal')
              ?.firstElementChild?.querySelector('.standalone-surface-backdrop'),
        );
        const host = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        const surface = host?.getAttribute('data-w3a-confirm-surface');
        const variant = host?.getAttribute('data-w3a-confirm-variant');
        // The centring rule is keyed on both attributes together.
        const centred = host ? getComputedStyle(host).placeItems.includes('center') : false;
        const hasBackdrop = Boolean(
          host?.querySelector('w3a-modal-tx-confirmer .standalone-surface-backdrop'),
        );

        host?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CANCEL, {
            bubbles: true,
            composed: true,
          }),
        );
        const decision = await decisionPromise;
        decision.handle.close(false);
        return { surface, variant, centred, hasBackdrop };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result).toEqual({
      surface: 'standalone',
      variant: 'modal',
      centred: true,
      hasBackdrop: true,
    });
  });

  test('drawer confirm renders inline wrapper (no iframe fallback)', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'light',
          uiMode: 'drawer',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.getElementById('w3a-confirm-portal')?.firstElementChild);
        const portalChild = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        portalChild?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
            detail: { confirmed: true },
            bubbles: true,
            composed: true,
          } as any),
        );

        const { confirmed } = await decisionPromise;
        const tagName = portalChild?.tagName;
        const variantAttr = portalChild?.getAttribute?.('variant');
        const hasIframe = !!portalChild?.querySelector('iframe');
        return { confirmed, tagName, variantAttr, hasIframe };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result.confirmed).toBe(true);
    expect(result.tagName).toBe('W3A-TX-CONFIRMER');
    expect(result.variantAttr ?? 'drawer').toBe('drawer');
    expect(result.hasIframe).toBe(false);
  });

  test('confirm event flagged false resolves as cancel with error detail', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, summary, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.getElementById('w3a-confirm-portal')?.firstElementChild);
        const portalChild = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        portalChild?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
            detail: { confirmed: false, error: 'INTENT_DIGEST_MISMATCH' },
            bubbles: true,
            composed: true,
          } as any),
        );

        const { confirmed, error, handle } = await decisionPromise;
        handle?.close?.(confirmed);
        return { confirmed, error: error || null };
      },
      {
        securityContext: SECURITY_CONTEXT,
        summary: SUMMARY,
        waitForSource: WAIT_FOR_SOURCE,
        paths: IMPORT_PATHS,
      },
    );

    expect(result.confirmed).toBe(false);
    expect(result.error).toBe('INTENT_DIGEST_MISMATCH');
  });

  test('intent digest mismatch triggers wrapper validation cancel path', async ({ page }) => {
    const transferType = ActionType.Transfer;

    const result = await page.evaluate(
      async ({ waitForSource, paths, transferType }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const txSigningRequests: TransactionInputWasm[] = [
          {
            receiverId: 'merchant.testnet',
            actions: [
              {
                action_type: transferType,
                deposit: '1000000000000000000000000',
              } as ActionArgsWasm,
            ],
          },
        ];

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx,
          surface: { kind: 'mount_new' },
          summary: { intentDigest: 'bogus-digest' },
          txSigningRequests,
          securityContext: {
            rpId: 'example.com',
            blockHeight: '1',
            blockHash: 'hash',
          } as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.querySelector('w3a-tx-confirmer'));
        const wrapper = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        // Dispatch on the wrapper itself so the capture-phase handler performs
        // digest validation reliably, independent of child listener timing.
        await new Promise((r) => setTimeout(r, 50));
        wrapper?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
            detail: { confirmed: true },
            bubbles: true,
            composed: true,
          } as any),
        );

        const { confirmed, error, handle } = await decisionPromise;
        handle?.close?.(confirmed);
        const dataError = wrapper?.getAttribute?.('data-error-message') || null;
        return { confirmed, error: error || null, dataError };
      },
      { waitForSource: WAIT_FOR_SOURCE, paths: IMPORT_PATHS, transferType },
    );
    console.log('Expect intent digest mismatch: ', result);

    expect(result.confirmed).toBe(false);
    expect(result.error).toBe('INTENT_DIGEST_MISMATCH');
    expect(result.dataError).toBe('INTENT_DIGEST_MISMATCH');
  });

  test('raw fallback model still allows confirmation (non-blocking UX)', async ({ page }) => {
    const result = await page.evaluate(
      async ({ securityContext, waitForSource, paths }) => {
        const waitFor = eval(waitForSource) as typeof harnessWaitFor;
        const mod = await import(paths.confirmUi);
        const events = await import(paths.events);
        const { awaitConfirmUIDecision } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const buildCtxStub = (overrides: Record<string, unknown> = {}) => ({
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
            getConfirmationConfig: () => ({
              uiMode: 'modal',
              behavior: 'requireClick',
              autoProceedDelay: 0,
              theme: 'dark',
            }),
          },
          surfaceMeasurementBinding: { kind: 'disabled' },
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          surface: { kind: 'mount_new' },
          summary: { intentDigest: 'fallback-intent' },
          txSigningRequests: [],
          model: {
            chain: 'unknown',
            title: 'Unknown Payload',
            operations: [
              {
                id: 'unknown-op',
                kind: 'raw.fallback',
                label: 'Unsupported Payload',
                raw: '{"kind":"unknown"}',
              },
            ],
          } as any,
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.getElementById('w3a-confirm-portal')?.firstElementChild);
        const portalChild = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        portalChild?.dispatchEvent(
          new CustomEvent(events.WalletIframeDomEvents.TX_CONFIRMER_CONFIRM, {
            detail: { confirmed: true },
            bubbles: true,
            composed: true,
          } as any),
        );

        const { confirmed } = await decisionPromise;
        return { confirmed };
      },
      { securityContext: SECURITY_CONTEXT, waitForSource: WAIT_FOR_SOURCE, paths: IMPORT_PATHS },
    );

    expect(result.confirmed).toBe(true);
  });
});
