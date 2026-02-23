import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';

const IMPORT_PATHS = {
  confirmUi: SDK_ESM_PATHS.confirmUi
} as const;

test.describe('confirm-ui mountConfirmUI handle', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('mounts from TxDisplayModel without txSigningRequests', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.confirmUi);
      const { mountConfirmUI } = mod as typeof import('@/core/signingEngine/touchConfirm/ui/confirm-ui');

      const ctx: any = {
        userPreferencesManager: {
          getCurrentUserAccountId: () => 'alice.testnet'
        },
      };

      const model = {
        chain: 'evm',
        intentDigest: '0x11',
        title: 'Model-only Confirmation',
        operations: [{
          id: 'op-1',
          kind: 'generic.contractCall',
          label: 'Contract Call',
          fields: [
            { label: 'To', value: `0x${'11'.repeat(20)}` },
            { label: 'Value (wei)', value: '7' },
            { label: 'Selector', value: '0xa9059cbb' },
          ],
        }],
      };

      const handle = await mountConfirmUI({
        ctx,
        summary: { intentDigest: 'digest-model-only' } as any,
        model: model as any,
        securityContext: {
          blockHeight: '1',
          blockHash: 'h'
        } as any,
        loading: false,
        theme: 'dark',
        uiMode: 'modal',
        nearAccountIdOverride: 'alice.testnet',
      });

      const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
        const start = Date.now();
        while (!predicate()) {
          if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI mount');
          await new Promise((resolve) => setTimeout(resolve, 16));
        }
      };

      await waitFor(() => !!document.querySelector('w3a-tx-confirm-content'));
      await waitFor(() => !!document.querySelector('w3a-tx-tree'));

      const portalChild = document.getElementById('w3a-confirm-portal')?.firstElementChild as any;
      const contentEl = document.querySelector('w3a-tx-confirm-content') as any;
      const treeEl = document.querySelector('w3a-tx-tree') as any;
      const treeNode = contentEl?._treeNode;

      const firstOperation = Array.isArray(treeNode?.children) ? treeNode.children[0] : null;
      const fieldLabels = Array.isArray(firstOperation?.children)
        ? firstOperation.children.map((child: any) => String(child?.label || ''))
        : [];

      handle.close(true);

      return {
        hasPortalChild: !!portalChild,
        hasContentElement: !!contentEl,
        hasTreeElement: !!treeEl,
        hasTreeNode: !!treeNode,
        operationLabel: String(firstOperation?.label || ''),
        fieldLabels,
        hasIntentDigestValue: !!portalChild?.intentDigest,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.hasPortalChild).toBe(true);
    expect(result.hasContentElement).toBe(true);
    expect(result.hasTreeElement).toBe(true);
    expect(result.hasTreeNode).toBe(true);
    expect(result.operationLabel).toBe('Contract Call');
    expect(result.fieldLabels.some((label: string) => label.includes('To:'))).toBe(true);
    expect(result.hasIntentDigestValue).toBe(false);
  });

  test('same mountConfirmUI API renders NEAR, EVM, and Tempo display models', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.confirmUi);
      const { mountConfirmUI } = mod as typeof import('@/core/signingEngine/touchConfirm/ui/confirm-ui');

      const ctx: any = {
        userPreferencesManager: {
          getCurrentUserAccountId: () => 'alice.testnet'
        },
      };

      const models = [
        {
          chain: 'near',
          operations: [{
            id: 'near-op',
            kind: 'near.action',
            actionType: 'transfer',
            label: 'NEAR Transfer',
            fields: [{ label: 'Amount (yoctoNEAR)', value: '1' }],
          }],
          expectedLabel: 'NEAR Transfer',
        },
        {
          chain: 'evm',
          operations: [{
            id: 'evm-op',
            kind: 'evm.erc4337',
            label: 'ERC-4337 UserOperation',
            children: [{
              id: 'evm-call',
              kind: 'generic.contractCall',
              label: 'Call',
              fields: [{ label: 'Selector', value: '0xa9059cbb' }],
            }],
          }],
          expectedLabel: 'ERC-4337 UserOperation',
        },
        {
          chain: 'tempo',
          operations: [{
            id: 'tempo-op',
            kind: 'tempo.eip2718',
            label: 'Tempo Transaction',
            children: [{
              id: 'tempo-call',
              kind: 'generic.contractCall',
              label: 'Call',
              fields: [{ label: 'Selector', value: '0xabcdef12' }],
            }],
          }],
          expectedLabel: 'Tempo Transaction',
        },
      ] as const;

      const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
        const start = Date.now();
        while (!predicate()) {
          if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI');
          await new Promise((resolve) => setTimeout(resolve, 16));
        }
      };

      const checks: Array<{ chain: string; matchesExpected: boolean; hasTree: boolean }> = [];
      for (const fixture of models) {
        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: `digest-${fixture.chain}` } as any,
          model: fixture as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h'
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        await waitFor(() => !!document.querySelector('w3a-tx-confirm-content'));
        await waitFor(() => !!document.querySelector('w3a-tx-tree'));

        const contentEl = document.querySelector('w3a-tx-confirm-content') as any;
        const treeNode = contentEl?._treeNode;
        const firstOperation = Array.isArray(treeNode?.children) ? treeNode.children[0] : null;
        const operationLabel = String(firstOperation?.label || '');

        checks.push({
          chain: fixture.chain,
          matchesExpected: operationLabel === fixture.expectedLabel,
          hasTree: !!treeNode && Array.isArray(treeNode.children) && treeNode.children.length > 0,
        });

        handle.close(true);
        await waitFor(() => (document.getElementById('w3a-confirm-portal')?.childElementCount || 0) === 0);
      }

      return { checks };
    }, { paths: IMPORT_PATHS });

    for (const entry of result.checks) {
      expect(entry.hasTree).toBe(true);
      expect(entry.matchesExpected).toBe(true);
    }
  });

  test('host modal: handle.update and handle.close work', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.confirmUi);
      const { mountConfirmUI } = mod as typeof import('@/core/signingEngine/touchConfirm/ui/confirm-ui');

      const ctx: any = {
        userPreferencesManager: {
          getCurrentUserAccountId: () => 'alice.testnet'
        },
      };

      const handle = await mountConfirmUI({
        ctx,
        summary: { intentDigest: 'digest' } as any,
        txSigningRequests: [],
        securityContext: {
          blockHeight: '1',
          blockHash: 'h'
        } as any,
        loading: true,
        theme: 'dark',
        uiMode: 'modal',
        nearAccountIdOverride: 'alice.testnet',
      });

      const portal = document.getElementById('w3a-confirm-portal');
      const initialEl = portal?.firstElementChild as HTMLElement | null;
      const initial = !!initialEl && (getComputedStyle(initialEl).display !== 'none');
      const hasTreeBeforeUpdate = !!document.querySelector('w3a-tx-tree');
      const hasNoActionsTextBeforeUpdate = /no actions/i.test(String(portal?.textContent || ''));

      // Update loading to false and set error message
      handle.update({ loading: false, errorMessage: 'Oops' });
      const el = document.getElementById('w3a-confirm-portal')?.firstElementChild as HTMLElement | null;
      const updated = {
        hasPortal: !!portal,
        hasChild: !!el,
        loading: el ? (el as any).loading : undefined,
        errorMessage: el ? (el as any).errorMessage : undefined,
        dataError: el ? el.getAttribute('data-error-message') : undefined,
        hasTree: !!document.querySelector('w3a-tx-tree'),
        hasNoActionsText: /no actions/i.test(String(document.getElementById('w3a-confirm-portal')?.textContent || '')),
      };

      // Close should remove the element
      handle.close(true);
      const afterClose = {
        portalExists: !!document.getElementById('w3a-confirm-portal'),
        childCount: (document.getElementById('w3a-confirm-portal')?.childElementCount) || 0
      };

      return { initial, updated, afterClose, hasTreeBeforeUpdate, hasNoActionsTextBeforeUpdate };
    }, { paths: IMPORT_PATHS });

    expect(result.initial).toBe(true);
    expect(result.updated.hasPortal).toBe(true);
    expect(result.updated.hasChild).toBe(true);
    expect(result.updated.loading).toBe(false);
    expect(result.updated.errorMessage).toBe('Oops');
    expect(result.updated.dataError).toBe('Oops');
    expect(result.hasTreeBeforeUpdate).toBe(false);
    expect(result.hasNoActionsTextBeforeUpdate).toBe(false);
    expect(result.updated.hasTree).toBe(false);
    expect(result.updated.hasNoActionsText).toBe(false);
    expect(result.afterClose.portalExists).toBe(true);
    expect(result.afterClose.childCount).toBe(0);
  });

  test('host drawer: mount + update theme and loading', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.confirmUi);
      const { mountConfirmUI } = mod as typeof import('@/core/signingEngine/touchConfirm/ui/confirm-ui');

      const ctx: any = {
        userPreferencesManager: {
          getCurrentUserAccountId: () => 'bob.testnet'
        },
      };

      const handle = await mountConfirmUI({
        ctx,
        summary: { intentDigest: 'digest' } as any,
        txSigningRequests: [],
        securityContext: {
          blockHeight: '1',
          blockHash: 'h'
        } as any,
        loading: true,
        theme: 'light',
        uiMode: 'drawer',
        nearAccountIdOverride: 'bob.testnet',
      });

      const portal = document.getElementById('w3a-confirm-portal');
      const initialEl = portal?.firstElementChild as any;
      const exists = !!initialEl;
      handle.update({ loading: false, theme: 'dark' });
      const el = document.getElementById('w3a-confirm-portal')?.firstElementChild as any;
      const stillThere = !!el;
      const afterUpdate = {
        loading: el ? el.loading : undefined,
        theme: el ? el.theme : undefined,
      };
      handle.close(false);
      const gone = (document.getElementById('w3a-confirm-portal')?.childElementCount || 0) === 0;
      return { exists, stillThere, gone, afterUpdate };
    }, { paths: IMPORT_PATHS });

    expect(result.exists).toBe(true);
    expect(result.stillThere).toBe(true);
    expect(result.gone).toBe(true);
    expect(result.afterUpdate.loading).toBe(false);
    expect(result.afterUpdate.theme).toBe('dark');
  });

  test('inline drawer: handle.update reflects loading, theme, error message', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.confirmUi);
      const { mountConfirmUI } = mod as typeof import('@/core/signingEngine/touchConfirm/ui/confirm-ui');

      const ctx: any = {
        userPreferencesManager: {
          getCurrentUserAccountId: () => 'carol.testnet'
        },
      };

      const handle = await mountConfirmUI({
        ctx,
        summary: { intentDigest: 'digest' } as any,
        txSigningRequests: [],
        securityContext: {
          blockHeight: '1',
          blockHash: 'h'
        } as any,
        loading: true,
        theme: 'light',
        uiMode: 'drawer',
        nearAccountIdOverride: 'carol.testnet',
      });

      const portal = document.getElementById('w3a-confirm-portal');
      const initialEl = portal?.firstElementChild as any;
      const exists = !!initialEl;
      handle.update({ loading: false, theme: 'dark', errorMessage: 'Denied' });
      const el = document.getElementById('w3a-confirm-portal')?.firstElementChild as any;
      (el as any)?.requestUpdate?.();
      await new Promise((resolve) => setTimeout(resolve, 20));
      const portalChild = document.getElementById('w3a-confirm-portal')?.firstElementChild as any;
      const variantEl = portalChild && portalChild.tagName?.toLowerCase() === 'w3a-drawer-tx-confirmer'
        ? portalChild
        : portalChild?.querySelector?.('w3a-drawer-tx-confirmer');
      const afterUpdate = {
        dataError: portalChild ? portalChild.getAttribute?.('data-error-message') : undefined,
      };
      handle.close(true);
      const gone = (document.getElementById('w3a-confirm-portal')?.childElementCount || 0) === 0;
      return { exists, afterUpdate, gone };
    }, { paths: IMPORT_PATHS });

    expect(result.exists).toBe(true);
    expect(result.afterUpdate.dataError).toBe('Denied');
    expect(result.gone).toBe(true);
  });
});
