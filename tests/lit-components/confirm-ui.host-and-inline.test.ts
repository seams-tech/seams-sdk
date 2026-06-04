import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { waitFor as harnessWaitFor } from '../wallet-iframe/harness';
import { ActionType, type TransactionInputWasm, type ActionArgsWasm } from '@/core/types/actions';

const SECURITY_CONTEXT = {
  rpId: 'example.com',
  blockHeight: '1',
  blockHash: 'h',
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
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
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
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
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

  test('modal backdrop click resolves as cancel', async ({ page }) => {
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
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
          summary,
          txSigningRequests: [],
          securityContext: securityContext as any,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.querySelector('w3a-modal-tx-confirmer'));
        const modalEl = document.querySelector('w3a-modal-tx-confirmer') as any;
        await waitFor(() => Boolean(modalEl && modalEl._backdropArmed === true));
        const backdrop = modalEl?.querySelector?.('.modal-backdrop-blur') as HTMLElement | null;
        backdrop?.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));

        const { confirmed, handle } = await decisionPromise;
        handle?.close?.(confirmed);
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
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
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
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
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
          ...overrides,
        });
        const ctx = (window as any).ctxStub || ((window as any).ctxStub = buildCtxStub());

        const decisionPromise = awaitConfirmUIDecision({
          ctx: ctx as any,
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
