import { test, expect } from '@playwright/test';
import { encodeFunctionData, parseAbi } from 'viem';
import { setupBasicPasskeyTest, SDK_ESM_PATHS, sdkEsmPath } from '../setup';

const IMPORT_PATHS = {
  confirmUi: SDK_ESM_PATHS.confirmUi,
  evmBuilder: sdkEsmPath('core/signingEngine/chains/evm/display/evmTx.js'),
} as const;

test.describe('confirm-ui mountConfirmUI handle', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('mounts from TxDisplayModel without txSigningRequests', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const model = {
          chain: 'evm',
          intentDigest: '0x11',
          title: 'Model-only Confirmation',
          operations: [
            {
              id: 'op-1',
              kind: 'generic.contractCall',
              label: 'Contract Call',
              fields: [
                { label: 'To', value: `0x${'11'.repeat(20)}` },
                { label: 'Value (wei)', value: '7' },
                { label: 'Selector', value: '0xa9059cbb' },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-model-only' } as any,
          model: model as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
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
          operationHideChevron: !!firstOperation?.hideChevron,
          fieldLabels,
          hasIntentDigestValue: !!portalChild?.intentDigest,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.hasPortalChild).toBe(true);
    expect(result.hasContentElement).toBe(true);
    expect(result.hasTreeElement).toBe(true);
    expect(result.hasTreeNode).toBe(true);
    expect(result.operationLabel).toBe('Contract Call');
    expect(result.operationHideChevron).toBe(true);
    expect(result.fieldLabels.some((label: string) => label.includes('To:'))).toBe(true);
    expect(result.hasIntentDigestValue).toBe(false);
  });

  test('lazily enriches ABI hints in tx-tree rendering', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const contractAddress = '0xbb442b54c85efba2d7b81ea52990ad638cdba483';
        const model = {
          chain: 'evm',
          intentDigest: '0x22',
          title: 'Lazy ABI Decode',
          operations: [
            {
              id: 'evm.eip1559',
              kind: 'generic.contractCall',
              label: `Transaction to contract ${contractAddress}`,
              to: contractAddress,
              value: '0',
              children: [
                {
                  id: 'evm.eip1559.call',
                  kind: 'generic.contractCall',
                  label: 'Calling contract function using 200k gas',
                  to: contractAddress,
                  value: '0',
                  selector: '0xa4136862',
                  fields: [
                    {
                      label: 'Data',
                      value:
                        'data: 0xa41368620000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d68656c6c6f2c20776f726c642100000000000000000000000000000000000000',
                      copyValue:
                        '0xa41368620000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d68656c6c6f2c20776f726c642100000000000000000000000000000000000000',
                      renderAs: 'file-content',
                      hideLabel: true,
                      hideChevron: true,
                    },
                  ],
                  abiDecodeHint: {
                    dataHex:
                      '0xa41368620000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d68656c6c6f2c20776f726c642100000000000000000000000000000000000000',
                    abi: [
                      {
                        type: 'function',
                        name: 'setGreeting',
                        inputs: [{ name: 'greeting', type: 'string' }],
                      },
                    ],
                  },
                },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-lazy-abi' } as any,
          model: model as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) {
              throw new Error('Timed out waiting for lazy ABI enrichment');
            }
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        const findNode = (node: any, predicate: (candidate: any) => boolean): any => {
          if (!node) return null;
          if (predicate(node)) return node;
          const children = Array.isArray(node.children) ? node.children : [];
          for (const child of children) {
            const found = findNode(child, predicate);
            if (found) return found;
          }
          return null;
        };

        await waitFor(() => !!document.querySelector('w3a-tx-confirm-content'));
        const contentEl = document.querySelector('w3a-tx-confirm-content') as any;
        await waitFor(() => {
          const root = contentEl?._treeNode;
          const callNode = findNode(root, (candidate) =>
            String(candidate?.label || '').includes('Calling setGreeting() using 200k gas'),
          );
          if (!callNode || !Array.isArray(callNode.children)) return false;
          const dataNode = callNode.children.find((child: any) => String(child?.label || '') === 'Data:');
          return String(dataNode?.content || '').includes('"greeting": "hello, world!"');
        });

        const treeNode = contentEl?._treeNode;
        const callNode = findNode(treeNode, (candidate) =>
          String(candidate?.label || '').includes('Calling setGreeting() using 200k gas'),
        );
        const fieldLabels = Array.isArray(callNode?.children)
          ? callNode.children.map((child: any) => String(child?.label || ''))
          : [];
        const dataNode = Array.isArray(callNode?.children)
          ? callNode.children.find((child: any) => String(child?.label || '') === 'Data:')
          : null;

        handle.close(true);

        return {
          callLabel: String(callNode?.label || ''),
          fieldLabels,
          decodedContent: String(dataNode?.content || ''),
          rawContent: String(dataNode?.contentVariants?.raw || ''),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.callLabel).toContain('Calling setGreeting() using 200k gas');
    expect(result.fieldLabels.some((label: string) => label.includes('Function:'))).toBe(false);
    expect(result.decodedContent).toContain('"greeting": "hello, world!"');
    expect(result.rawContent).toContain('0xa4136862');
  });

  test('ABI decoded address arrays keep 2-space indentation with no blank line', async ({ page }) => {
    const faucetAbi = parseAbi(['function drip(address[] tokenAddresses)']);
    const dripDataHex = encodeFunctionData({
      abi: faucetAbi,
      functionName: 'drip',
      args: [['0x20c0000000000000000000000000000000000000']],
    });

    const result = await page.evaluate(
      async ({ paths, dataHexArg, abiArg }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const contractAddress = '0xbb442b54c85efba2d7b81ea52990ad638cdba483';
        const model = {
          chain: 'evm',
          intentDigest: '0x33',
          title: 'Address Array Decode',
          operations: [
            {
              id: 'evm.eip1559',
              kind: 'generic.contractCall',
              label: `Transaction to contract ${contractAddress}`,
              to: contractAddress,
              value: '0',
              children: [
                {
                  id: 'evm.eip1559.call',
                  kind: 'generic.contractCall',
                  label: 'Calling contract function using 300k gas',
                  to: contractAddress,
                  value: '0',
                  selector: '0x867ae9d4',
                  fields: [
                    {
                      label: 'Data',
                      value: dataHexArg,
                      copyValue: dataHexArg,
                      renderAs: 'file-content',
                      hideLabel: true,
                      hideChevron: true,
                    },
                  ],
                  abiDecodeHint: {
                    dataHex: dataHexArg,
                    abi: abiArg,
                  },
                },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-address-array' } as any,
          model: model as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) {
              throw new Error('Timed out waiting for address-array ABI enrichment');
            }
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        const findNode = (node: any, predicate: (candidate: any) => boolean): any => {
          if (!node) return null;
          if (predicate(node)) return node;
          const children = Array.isArray(node.children) ? node.children : [];
          for (const child of children) {
            const found = findNode(child, predicate);
            if (found) return found;
          }
          return null;
        };

        await waitFor(() => !!document.querySelector('w3a-tx-confirm-content'));
        const contentEl = document.querySelector('w3a-tx-confirm-content') as any;
        await waitFor(() => {
          const root = contentEl?._treeNode;
          const callNode = findNode(root, (candidate) =>
            String(candidate?.label || '').includes('Calling drip() using 300k gas'),
          );
          if (!callNode || !Array.isArray(callNode.children)) return false;
          const dataNode = callNode.children.find((child: any) => String(child?.label || '') === 'Data:');
          return String(dataNode?.content || '').includes('"tokenAddresses"');
        });

        const treeNode = contentEl?._treeNode;
        const callNode = findNode(treeNode, (candidate) =>
          String(candidate?.label || '').includes('Calling drip() using 300k gas'),
        );
        const dataNode = Array.isArray(callNode?.children)
          ? callNode.children.find((child: any) => String(child?.label || '') === 'Data:')
          : null;

        handle.close(true);

        return {
          callLabel: String(callNode?.label || ''),
          decodedContent: String(dataNode?.content || ''),
        };
      },
      { paths: IMPORT_PATHS, dataHexArg: dripDataHex, abiArg: faucetAbi },
    );

    expect(result.callLabel).toContain('Calling drip() using 300k gas');
    expect(result.decodedContent).toBe(
      '{\n' +
        '  "tokenAddresses": [\n' +
        '    "0x20c0000000000000000000000000000000000000"\n' +
        '  ]\n' +
        '}',
    );
    expect(result.decodedContent).not.toContain('[\n\n');
  });

  test('same mountConfirmUI API renders NEAR, EVM, and Tempo display models', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const models = [
          {
            chain: 'near',
            operations: [
              {
                id: 'near-op',
                kind: 'near.action',
                actionType: 'transfer',
                label: 'NEAR Transfer',
                fields: [{ label: 'Amount (yoctoNEAR)', value: '1' }],
              },
            ],
            expectedLabel: 'NEAR Transfer',
          },
          {
            chain: 'evm',
            operations: [
              {
                id: 'evm-op',
                kind: 'generic.contractCall',
                label: 'EVM Contract Call',
                children: [
                  {
                    id: 'evm-call',
                    kind: 'generic.contractCall',
                    label: 'Call',
                    fields: [{ label: 'Selector', value: '0xa9059cbb' }],
                  },
                ],
              },
            ],
            expectedLabel: 'EVM Contract Call',
          },
          {
            chain: 'tempo',
            operations: [
              {
                id: 'tempo-op',
                kind: 'tempo.eip2718',
                label: 'Tempo Transaction',
                children: [
                  {
                    id: 'tempo-call',
                    kind: 'generic.contractCall',
                    label: 'Call',
                    fields: [{ label: 'Selector', value: '0xabcdef12' }],
                  },
                ],
              },
            ],
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

        const checks: Array<{
          chain: string;
          matchesExpected: boolean;
          hasTree: boolean;
          operationHideChevron: boolean;
        }> = [];
        for (const fixture of models) {
          const handle = await mountConfirmUI({
            ctx,
            summary: { intentDigest: `digest-${fixture.chain}` } as any,
            model: fixture as any,
            securityContext: {
              blockHeight: '1',
              blockHash: 'h',
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
            operationHideChevron: !!firstOperation?.hideChevron,
          });

          handle.close(true);
          await waitFor(
            () => (document.getElementById('w3a-confirm-portal')?.childElementCount || 0) === 0,
          );
        }

        return { checks };
      },
      { paths: IMPORT_PATHS },
    );

    for (const entry of result.checks) {
      expect(entry.hasTree).toBe(true);
      expect(entry.matchesExpected).toBe(true);
      if (entry.chain === 'evm' || entry.chain === 'tempo') {
        expect(entry.operationHideChevron).toBe(true);
      }
    }
  });

  test('EVM preview tree ends with an L-shaped connector on the last field row', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const model = {
          chain: 'evm',
          operations: [
            {
              id: 'evm-op',
              kind: 'generic.contractCall',
              label: 'Contract Call',
              fields: [
                { label: 'Kind', value: 'EIP-1559 (0x02)' },
                { label: 'To', value: `0x${'22'.repeat(20)}` },
                { label: 'Value (wei)', value: '12345' },
                { label: 'Nonce', value: '7' },
                { label: 'Gas Limit', value: '21000' },
                { label: 'Chain ID', value: '11155111' },
                { label: 'Data', value: '0x' },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-connector-check' } as any,
          model: model as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI');
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        await waitFor(() => !!document.querySelector('w3a-tx-tree .folder-children'));

        const rows = Array.from(
          document.querySelectorAll('w3a-tx-tree .folder-children > .row.file-row'),
        ) as HTMLElement[];
        const lastRow = rows[rows.length - 1] || null;
        const indent = lastRow?.querySelector('.indent') as HTMLElement | null;
        const afterContent = indent ? getComputedStyle(indent, '::after').content : '';
        const beforeHeight = indent
          ? parseFloat(getComputedStyle(indent, '::before').height || '0')
          : 0;
        const rowHeight = lastRow ? lastRow.getBoundingClientRect().height : 0;

        handle.close(true);

        return {
          rowCount: rows.length,
          afterContent,
          beforeHeight,
          rowHeight,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.rowCount).toBeGreaterThan(0);
    expect(result.afterContent).not.toBe('none');
    expect(result.beforeHeight).toBeLessThan(result.rowHeight);
  });

  test('tx-tree preview expands to fit modal content width', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const model = {
          chain: 'tempo',
          operations: [
            {
              id: 'tempo-op',
              kind: 'tempo.eip2718',
              label: 'Tempo Transaction',
              fields: [
                { label: 'Nonce', value: '1' },
                { label: 'Gas Limit', value: '21000' },
                { label: 'To', value: `0x${'11'.repeat(20)}` },
                { label: 'Value (wei)', value: '0' },
                { label: 'Input', value: '0x' },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-width-check' } as any,
          model: model as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI');
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        await waitFor(() => !!document.querySelector('w3a-tx-tree'));
        await waitFor(() => !!document.querySelector('.tooltip-width'));
        await waitFor(() => !!document.querySelector('.modal-container-root'));

        const treeEl = document.querySelector('w3a-tx-tree') as HTMLElement | null;
        const tooltipEl = document.querySelector('.tooltip-width') as HTMLElement | null;
        const modalEl = document.querySelector('.modal-container-root') as HTMLElement | null;
        const responsiveCardEl = document.querySelector('.responsive-card') as HTMLElement | null;

        const treeWidth = treeEl ? treeEl.getBoundingClientRect().width : 0;
        const tooltipWidth = tooltipEl ? tooltipEl.getBoundingClientRect().width : 0;
        const modalWidth = modalEl ? modalEl.getBoundingClientRect().width : 0;
        const responsiveCardWidth = responsiveCardEl
          ? responsiveCardEl.getBoundingClientRect().width
          : 0;
        const fillRatio = modalWidth > 0 ? tooltipWidth / modalWidth : 0;

        handle.close(true);

        return {
          treeWidth,
          tooltipWidth,
          modalWidth,
          responsiveCardWidth,
          fillRatio,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.modalWidth).toBeGreaterThan(0);
    expect(result.tooltipWidth).toBeGreaterThan(0);
    expect(result.treeWidth).toBeGreaterThan(0);
    expect(Math.abs(result.treeWidth - result.tooltipWidth)).toBeLessThanOrEqual(1.5);
    expect(Math.abs(result.tooltipWidth - result.responsiveCardWidth)).toBeLessThanOrEqual(1.5);
    expect(result.fillRatio).toBeGreaterThan(0.92);
  });

  test('tx-tree collapse keeps modal width stable during animation', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const model = {
          chain: 'tempo',
          operations: [
            {
              id: 'tempo-op',
              kind: 'tempo.eip2718',
              label: 'Tempo Transaction',
              fields: [
                { label: 'Nonce', value: '1' },
                { label: 'Gas Limit', value: '21000' },
                { label: 'To', value: `0x${'11'.repeat(20)}` },
                { label: 'Value (wei)', value: '0' },
                { label: 'Input', value: '0x12345678' },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-collapse-width-stability' } as any,
          model: model as any,
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI');
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        await waitFor(() => !!document.querySelector('.modal-container-root'));
        await waitFor(
          () => !!document.querySelector('w3a-tx-tree details.tree-node.folder > summary'),
        );

        const modalEl = document.querySelector('.modal-container-root') as HTMLElement | null;
        const summaryEl = document.querySelector(
          'w3a-tx-tree details.tree-node.folder > summary',
        ) as HTMLElement | null;
        const detailsEl = summaryEl?.closest('details') as HTMLDetailsElement | null;
        if (!modalEl || !summaryEl || !detailsEl) {
          handle.close(false);
          throw new Error('Missing modal or tx-tree nodes for collapse test');
        }

        const toggleTree = () => {
          summaryEl.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));
        };

        if (!detailsEl.open) {
          toggleTree();
          await waitFor(() => detailsEl.open, 2000);
          await new Promise((resolve) => setTimeout(resolve, 120));
        }
        // Let initial mount animation settle; otherwise width sampling picks up fade-in scale.
        await new Promise((resolve) => setTimeout(resolve, 80));

        const initialWidth = modalEl.getBoundingClientRect().width;
        const initialHeight = modalEl.getBoundingClientRect().height;

        const widths: number[] = [];
        const heights: number[] = [initialHeight];
        const startedAt = performance.now();
        const durationMs = 260;
        const collectUntil = startedAt + durationMs;
        const collectFrames = () =>
          new Promise<void>((resolve) => {
            const tick = () => {
              widths.push(modalEl.getBoundingClientRect().width);
              heights.push(modalEl.getBoundingClientRect().height);
              if (performance.now() < collectUntil) {
                requestAnimationFrame(tick);
                return;
              }
              resolve();
            };
            requestAnimationFrame(tick);
          });

        const collectPromise = collectFrames();
        toggleTree();
        await collectPromise;

        await waitFor(() => !detailsEl.open, 2000);

        const firstWidth = initialWidth;
        const lastWidth = widths[widths.length - 1] ?? modalEl.getBoundingClientRect().width;
        const minWidth = widths.length > 0 ? Math.min(firstWidth, ...widths) : firstWidth;
        const maxWidth = widths.length > 0 ? Math.max(firstWidth, ...widths) : lastWidth;
        const lastHeight = heights[heights.length - 1] ?? modalEl.getBoundingClientRect().height;

        handle.close(true);

        return {
          firstWidth,
          lastWidth,
          widthRange: maxWidth - minWidth,
          heightDrop: initialHeight - lastHeight,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.heightDrop).toBeGreaterThan(20);
    expect(result.widthRange).toBeLessThanOrEqual(2.5);
    expect(Math.abs(result.firstWidth - result.lastWidth)).toBeLessThanOrEqual(2.5);
  });

  test('shows chain context when block height is missing and hides zero wei value rows', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const model = {
          chain: 'tempo',
          chainId: 111555,
          operations: [
            {
              id: 'tempo-op',
              kind: 'tempo.eip2718',
              label: 'Tempo Transaction',
              fields: [
                { label: 'Nonce', value: '1' },
                { label: 'Value (wei)', value: '0' },
                { label: 'Input', value: '0x' },
              ],
            },
          ],
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-security-context' } as any,
          model: model as any,
          securityContext: {
            rpId: 'example.localhost',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI');
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        await waitFor(() => !!document.querySelector('.security-details'));
        await waitFor(() => !!document.querySelector('w3a-tx-tree'));

        const securityDetails = document.querySelector('.security-details');
        const securityDetailsText = String(securityDetails?.textContent || '')
          .replace(/\s+/g, ' ')
          .trim();

        const allLabelTexts = Array.from(document.querySelectorAll('w3a-tx-tree .label-text')).map(
          (el) =>
            String(el.textContent || '')
              .replace(/\s+/g, ' ')
              .trim(),
        );
        const hasZeroWeiValueRow = allLabelTexts.some((txt) => txt.includes('Value (wei): 0'));

        handle.close(true);

        return {
          securityDetailsText,
          hasZeroWeiValueRow,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.securityDetailsText).toContain('Tempo | ChainID: 111555');
    expect(result.hasZeroWeiValueRow).toBe(false);
  });

  test('tx confirmer blue accents are driven by theme tokens', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const txSigningRequests = [
          {
            receiverId: 'w3a-v1.testnet',
            actions: [
              {
                action_type: 'FunctionCall',
                method_name: 'set_greeting',
                args: JSON.stringify({ greeting: 'hello' }),
                gas: '30000000000000',
                deposit: '0',
              },
            ],
          },
        ];

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest-theme-accent' } as any,
          txSigningRequests: txSigningRequests as any,
          securityContext: {
            blockHeight: '238436644',
            blockHash: 'h',
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for UI');
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        await waitFor(() => !!document.querySelector('w3a-tx-tree'));
        await waitFor(() => !!document.querySelector('w3a-tx-tree .highlight-method-name'));
        await waitFor(() => !!document.querySelector('.padlock-icon'));

        const treeEl = document.querySelector('w3a-tx-tree') as HTMLElement | null;
        const modalEl = document.querySelector('w3a-modal-tx-confirmer') as HTMLElement | null;

        modalEl?.style.setProperty('--w3a-colors-info', 'rgb(255, 0, 0)', 'important');
        modalEl?.style.setProperty('--w3a-colors-highlightHalo', 'rgb(255, 0, 0)', 'important');
        treeEl?.style.setProperty(
          '--w3a-colors-highlightMethodName',
          'rgb(0, 255, 0)',
          'important',
        );
        treeEl?.style.setProperty(
          '--w3a-colors-highlightReceiver',
          'rgb(0, 170, 255)',
          'important',
        );
        treeEl?.style.setProperty('--w3a-colors-highlightAmount', 'rgb(255, 120, 0)', 'important');

        await new Promise((resolve) => requestAnimationFrame(() => resolve(undefined)));

        const methodHighlight = document.querySelector(
          'w3a-tx-tree .highlight-method-name',
        ) as HTMLElement | null;
        const receiverHighlight = document.querySelector(
          'w3a-tx-tree .highlight-receiver-id',
        ) as HTMLElement | null;
        const padlockIcon = document.querySelector('.padlock-icon') as HTMLElement | null;
        const blockHeightIcon = document.querySelector('.block-height-icon') as HTMLElement | null;
        const output = {
          methodColor: methodHighlight ? getComputedStyle(methodHighlight).color : '',
          receiverColor: receiverHighlight ? getComputedStyle(receiverHighlight).color : '',
          padlockColor: padlockIcon ? getComputedStyle(padlockIcon).color : '',
          blockHeightColor: blockHeightIcon ? getComputedStyle(blockHeightIcon).color : '',
          ringBackground: modalEl
            ? getComputedStyle(modalEl)
                .getPropertyValue('--w3a-modal__passkey-halo-loading__ring-background')
                .trim()
            : '',
        };

        modalEl?.style.removeProperty('--w3a-colors-info');
        modalEl?.style.removeProperty('--w3a-colors-highlightHalo');
        treeEl?.style.removeProperty('--w3a-colors-highlightMethodName');
        treeEl?.style.removeProperty('--w3a-colors-highlightReceiver');
        treeEl?.style.removeProperty('--w3a-colors-highlightAmount');
        handle.close(true);

        return output;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.methodColor).toBe('rgb(0, 255, 0)');
    expect(result.receiverColor).toBe('rgb(0, 170, 255)');
    expect(result.padlockColor).toBe('rgb(255, 0, 0)');
    expect(result.blockHeightColor).toBe('rgb(255, 0, 0)');
    expect(result.ringBackground).toContain('rgb(255, 0, 0)');
    expect(result.ringBackground).not.toContain('#4DAFFE');
  });

  test('explorer links resolve by family + chainId across mixed EVM networks', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const confirmUiMod = await import(paths.confirmUi);
        const evmBuilderMod = await import(paths.evmBuilder);
        const { mountConfirmUI } =
          confirmUiMod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');
        const { buildEvmDisplayModel } =
          evmBuilderMod as typeof import('@/core/signingEngine/chains/evm/display/evmTx');

        const contractAddress = '0x1111111111111111111111111111111111111111' as const;
        const summary = { intentDigest: 'digest-explorer-chainid' } as any;

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
          // Intentionally keep Arc as generic family fallback so chainId-specific override is testable.
          evmExplorerUrl: 'https://arc-explorer.example',
          chains: [
            {
              network: 'near-testnet',
              rpcUrl: 'https://near-rpc.example',
              explorerUrl: 'https://near-explorer.example',
            },
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://tempo-rpc.example',
              explorerUrl: 'https://tempo-explorer.example',
              chainId: 111555,
            },
            {
              network: 'arc-testnet',
              rpcUrl: 'https://arc-rpc.example',
              explorerUrl: 'https://arc-explorer.example',
              chainId: 5042002,
            },
            {
              network: 'ethereum-sepolia',
              rpcUrl: 'https://sepolia-rpc.example',
              explorerUrl: 'https://sepolia-explorer.example',
              chainId: 11155111,
            },
          ],
        };

        const waitFor = async (predicate: () => boolean, timeoutMs = 5000): Promise<void> => {
          const start = Date.now();
          while (!predicate()) {
            if (Date.now() - start > timeoutMs)
              throw new Error('Timed out waiting for explorer link');
            await new Promise((resolve) => setTimeout(resolve, 16));
          }
        };

        const resolveHrefForChainId = async (chainId: number): Promise<string> => {
          const model = buildEvmDisplayModel({
            request: {
              chain: 'evm',
              kind: 'eip1559',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId,
                nonce: 1n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: contractAddress,
                value: 1n,
                data: '0x',
                accessList: [],
              },
            },
          });

          const handle = await mountConfirmUI({
            ctx,
            summary,
            model: model as any,
            loading: false,
            theme: 'dark',
            uiMode: 'modal',
            nearAccountIdOverride: 'alice.testnet',
          });

          await waitFor(() => !!document.querySelector('w3a-tx-tree .highlight-receiver-id[href]'));
          const href =
            (
              document.querySelector(
                'w3a-tx-tree .highlight-receiver-id[href]',
              ) as HTMLAnchorElement | null
            )?.href || '';
          handle.close(true);
          return href;
        };

        const sepoliaHref = await resolveHrefForChainId(11155111);
        const arcHref = await resolveHrefForChainId(5042002);
        const fallbackHref = await resolveHrefForChainId(1);

        return {
          sepoliaHref,
          arcHref,
          fallbackHref,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.sepoliaHref).toContain('/address/0x1111111111111111111111111111111111111111');
    expect(result.sepoliaHref.startsWith('https://sepolia-explorer.example')).toBe(true);

    expect(result.arcHref).toContain('/address/0x1111111111111111111111111111111111111111');
    expect(result.arcHref.startsWith('https://arc-explorer.example')).toBe(true);

    // Unknown chainId falls back to the primary/family-level EVM explorer.
    expect(result.fallbackHref).toContain('/address/0x1111111111111111111111111111111111111111');
    expect(result.fallbackHref.startsWith('https://arc-explorer.example')).toBe(true);
  });

  test('host modal: handle.update and handle.close work', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest' } as any,
          txSigningRequests: [],
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
          } as any,
          loading: true,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        const portal = document.getElementById('w3a-confirm-portal');
        const initialEl = portal?.firstElementChild as HTMLElement | null;
        const initial = !!initialEl && getComputedStyle(initialEl).display !== 'none';
        const hasTreeBeforeUpdate = !!document.querySelector('w3a-tx-tree');
        const hasNoActionsTextBeforeUpdate = /no actions/i.test(String(portal?.textContent || ''));

        // Update loading to false and set error message
        handle.update({ loading: false, errorMessage: 'Oops' });
        const el = document.getElementById('w3a-confirm-portal')
          ?.firstElementChild as HTMLElement | null;
        const updated = {
          hasPortal: !!portal,
          hasChild: !!el,
          loading: el ? (el as any).loading : undefined,
          errorMessage: el ? (el as any).errorMessage : undefined,
          dataError: el ? el.getAttribute('data-error-message') : undefined,
          hasTree: !!document.querySelector('w3a-tx-tree'),
          hasNoActionsText: /no actions/i.test(
            String(document.getElementById('w3a-confirm-portal')?.textContent || ''),
          ),
        };

        // Close should remove the element
        handle.close(true);
        const afterClose = {
          portalExists: !!document.getElementById('w3a-confirm-portal'),
          childCount: document.getElementById('w3a-confirm-portal')?.childElementCount || 0,
        };

        return { initial, updated, afterClose, hasTreeBeforeUpdate, hasNoActionsTextBeforeUpdate };
      },
      { paths: IMPORT_PATHS },
    );

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

  test('host modal: passkey registration renders identity details without transaction tree', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'alice.testnet',
          },
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'register:alice.testnet:1' } as any,
          txSigningRequests: [],
          securityContext: {
            passkeyRegistration: {
              kind: 'passkey_registration_confirm_display_v1',
              intendedUserName: 'alice.testnet',
              accountId: 'alice.testnet',
              rpId: 'wallet.example.test',
              signerSlot: 1,
            },
          } as any,
          loading: false,
          theme: 'dark',
          uiMode: 'modal',
          nearAccountIdOverride: 'alice.testnet',
        });

        (globalThis as any).__passkeyRegistrationHandle = handle;
      },
      { paths: IMPORT_PATHS },
    );

    await page.waitForSelector('.passkey-registration-confirm__identity');

    const identity = page.locator('.passkey-registration-confirm__identity');
    await expect(page.locator('.passkey-registration-confirm .hero-heading')).toHaveText(
      'Create your passkey',
    );
    await expect(identity).toContainText('Account');
    await expect(identity).toContainText('alice.testnet');
    await expect(identity).toContainText('Website');
    await expect(identity).toContainText('wallet.example.test');
    await expect(page.locator('.passkey-registration-confirm__value').first()).toHaveAttribute(
      'title',
      'alice.testnet',
    );
    await expect(page.locator('.passkey-registration-confirm__value').nth(1)).toHaveAttribute(
      'title',
      'wallet.example.test',
    );
    expect(await page.locator('w3a-tx-tree').count()).toBe(0);

    await page.evaluate(() => {
      (globalThis as any).__passkeyRegistrationHandle?.update({ loading: true });
    });

    await expect(page.locator('.passkey-registration-confirm .btn-confirm')).toContainText(
      'Creating passkey...',
    );
    const busyLabel = page.locator('.passkey-registration-confirm__busy-label');
    await expect(busyLabel).toHaveCSS('white-space', 'nowrap');
    expect(
      await busyLabel.evaluate((element) => {
        const labelSize = Number.parseFloat(getComputedStyle(element).fontSize);
        const button = element.closest('button');
        if (!button) throw new Error('Busy label must be rendered inside its button');
        const buttonSize = Number.parseFloat(getComputedStyle(button).fontSize);
        return labelSize < buttonSize;
      }),
    ).toBe(true);
    await expect(page.locator('.passkey-registration-confirm [role="progressbar"]')).toHaveCount(
      1,
    );

    await page.evaluate(() => {
      (globalThis as any).__passkeyRegistrationHandle?.close(true);
      delete (globalThis as any).__passkeyRegistrationHandle;
    });
  });

  test('host drawer: mount + update theme and loading', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'bob.testnet',
          },
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest' } as any,
          txSigningRequests: [],
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
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
        await new Promise((resolve) => setTimeout(resolve, 300));
        const gone = (document.getElementById('w3a-confirm-portal')?.childElementCount || 0) === 0;
        return { exists, stillThere, gone, afterUpdate };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.exists).toBe(true);
    expect(result.stillThere).toBe(true);
    expect(result.gone).toBe(true);
    expect(result.afterUpdate.loading).toBe(false);
    expect(result.afterUpdate.theme).toBe('dark');
  });

  test('inline drawer: handle.update reflects loading, theme, error message', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.confirmUi);
        const { mountConfirmUI } =
          mod as typeof import('@/core/signingEngine/uiConfirm/ui/confirm-ui');

        const ctx: any = {
          userPreferencesManager: {
            getCurrentWalletId: () => 'carol.testnet',
          },
        };

        const handle = await mountConfirmUI({
          ctx,
          summary: { intentDigest: 'digest' } as any,
          txSigningRequests: [],
          securityContext: {
            blockHeight: '1',
            blockHash: 'h',
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
        const variantEl =
          portalChild && portalChild.tagName?.toLowerCase() === 'w3a-drawer-tx-confirmer'
            ? portalChild
            : portalChild?.querySelector?.('w3a-drawer-tx-confirmer');
        const afterUpdate = {
          dataError: portalChild ? portalChild.getAttribute?.('data-error-message') : undefined,
        };
        handle.close(true);
        await new Promise((resolve) => setTimeout(resolve, 300));
        const gone = (document.getElementById('w3a-confirm-portal')?.childElementCount || 0) === 0;
        return { exists, afterUpdate, gone };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.exists).toBe(true);
    expect(result.afterUpdate.dataError).toBe('Denied');
    expect(result.gone).toBe(true);
  });
});
