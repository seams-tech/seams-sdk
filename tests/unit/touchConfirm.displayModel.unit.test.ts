import { expect, test } from '@playwright/test';
import { encodeFunctionData, parseAbi } from 'viem';

const IMPORT_PATHS = {
  nearBuilder: '/_test-sdk/esm/core/signingEngine/chains/near/display.js',
  evmBuilder: '/_test-sdk/esm/core/signingEngine/chains/evm/display/evmTx.js',
  tempoBuilder: '/_test-sdk/esm/core/signingEngine/chains/tempo/display.js',
  txTreeUtils: '/_test-sdk/esm/core/signingEngine/uiConfirm/ui/lit-components/TxTree/tx-tree-utils.js',
} as const;

const ERC20_ABI = parseAbi(['function transfer(address to, uint256 amount)']);
const FAUCET_ABI = parseAbi([
  'function setGreeting(string newGreeting)',
  'function drip(address[] tokenAddresses)',
]);

test.describe('touchConfirm display model fixtures', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('normalizes NEAR action payloads into display operations', async ({ page }) => {
    const model = await page.evaluate(
      async ({ paths }) => {
        const { buildNearDisplayModel } = await import(paths.nearBuilder);
        return buildNearDisplayModel({
          intentDigest: 'near-intent',
          signerAccount: 'alice.near',
          title: 'NEAR fixture',
          txSigningRequests: [
            {
              receiverId: 'contract.near',
              actions: [
                { action_type: 'Transfer', deposit: '10' },
                {
                  action_type: 'FunctionCall',
                  method_name: 'set_message',
                  args: '{"message":"hello"}',
                  gas: '30000000000000',
                  deposit: '1',
                },
              ],
            },
          ],
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(model.chain).toBe('near');
    expect(model.operations).toHaveLength(1);
    expect(model.operations[0].kind).toBe('generic.contractCall');
    expect(model.operations[0].children).toHaveLength(2);
    expect(model.operations[0].children[0].kind).toBe('near.action');
    expect(model.operations[0].children[1].kind).toBe('near.action');
  });

  test('adds known function signature for direct EIP-1559 contract calls', async ({ page }) => {
    const tokenContract = `0x${'99'.repeat(20)}` as const;
    const tokenRecipient = `0x${'77'.repeat(20)}` as const;
    const erc20TransferData = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [tokenRecipient, 123n],
    });

    const model = await page.evaluate(
      async ({ paths, tokenContractArg, erc20TransferDataArg }) => {
        const { buildEvmDisplayModel } = await import(paths.evmBuilder);
        return buildEvmDisplayModel({
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 10n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 300_000n,
              to: tokenContractArg,
              value: 0n,
              data: erc20TransferDataArg,
              accessList: [],
            },
          },
        });
      },
      {
        paths: IMPORT_PATHS,
        tokenContractArg: tokenContract,
        erc20TransferDataArg: erc20TransferData,
      },
    );

    expect(model.operations[0].kind).toBe('generic.contractCall');
    expect(model.operations[0].label).toContain('Transaction to contract');
    expect(model.operations[0].children).toHaveLength(1);
    expect(model.operations[0].selector).toBe('0xa9059cbb');
    const callChild = model.operations[0].children[0];
    expect(callChild.label).toContain('Calling transfer()');
    const fields = Array.isArray(callChild.fields) ? callChild.fields : [];
    expect(fields.some((field: { label?: string; value?: string }) => field.label === 'Function')).toBe(
      false,
    );
    expect(fields.some((field: { label?: string; value?: string }) => field.label === 'Selector')).toBe(
      false,
    );
  });

  test('keeps direct EIP-1559 ABI decode lazy with operation hints', async ({ page }) => {
    const greetingContract = `0x${'42'.repeat(20)}` as const;
    const greetingText = 'Hello ABI decode';
    const callData = encodeFunctionData({
      abi: FAUCET_ABI,
      functionName: 'setGreeting',
      args: [greetingText],
    });

    const model = await page.evaluate(
      async ({ paths, greetingContractArg, callDataArg, abiArg }) => {
        const { buildEvmDisplayModel } = await import(paths.evmBuilder);
        return buildEvmDisplayModel({
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              nonce: 10n,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 210_000n,
              to: greetingContractArg,
              value: 0n,
              data: callDataArg,
              abi: abiArg,
              accessList: [],
            },
          },
        });
      },
      {
        paths: IMPORT_PATHS,
        greetingContractArg: greetingContract,
        callDataArg: callData,
        abiArg: FAUCET_ABI,
      },
    );

    const callChild = model.operations[0].children?.[0];
    const fields = Array.isArray(callChild?.fields) ? callChild.fields : [];
    expect(fields.some((field: { label?: string }) => field.label === 'Function')).toBe(false);
    expect(callChild?.abiDecodeHint?.dataHex).toBe(callData);
    expect(Array.isArray(callChild?.abiDecodeHint?.abi)).toBe(true);
  });

  test('normalizes Tempo typed transaction payloads', async ({ page }) => {
    const model = await page.evaluate(
      async ({ paths }) => {
        const { buildTempoDisplayModel } = await import(paths.tempoBuilder);
        return buildTempoDisplayModel({
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 2n,
              nonceKey: 1n,
              maxPriorityFeePerGas: 10n,
              maxFeePerGas: 20n,
              gasLimit: 50_000n,
              calls: [
                {
                  to: `0x${'11'.repeat(20)}`,
                  value: 3n,
                  input: '0xabcdef12',
                },
              ],
              accessList: [],
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          },
          intentDigest: '0x22',
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(model.chain).toBe('tempo');
    expect(model.operations).toHaveLength(1);
    expect(model.operations[0].kind).toBe('tempo.eip2718');
    expect(model.operations[0].label).toContain('Transaction to contract');
    expect(model.operations[0].children?.length || 0).toBe(1);
    const fields = Array.isArray(model.operations[0].children?.[0]?.fields)
      ? model.operations[0].children[0].fields
      : [];
    expect(fields.some((field: { label?: string; value?: string }) => field.label === 'Function')).toBe(
      false,
    );
    expect(fields.some((field: { label?: string; value?: string }) => field.label === 'Selector')).toBe(
      false,
    );
  });

  test('recognizes Tempo fee-manager setUserToken calldata', async ({ page }) => {
    const feeToken = '20c0000000000000000000000000000000000001';
    const calldata = `0xe7897444${feeToken.padStart(64, '0')}`;
    const model = await page.evaluate(
      async ({ paths, calldataArg }) => {
        const { buildTempoDisplayModel } = await import(paths.tempoBuilder);
        return buildTempoDisplayModel({
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 2n,
              nonceKey: 1n,
              maxPriorityFeePerGas: 10n,
              maxFeePerGas: 20n,
              gasLimit: 50_000n,
              calls: [
                {
                  to: '0xfeec000000000000000000000000000000000000',
                  value: 0n,
                  input: calldataArg,
                },
              ],
              accessList: [],
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          },
        });
      },
      { paths: IMPORT_PATHS, calldataArg: calldata },
    );

    expect(model.operations).toHaveLength(1);
    const child = model.operations[0].children?.[0];
    expect(child?.kind).toBe('generic.contractCall');
    expect(child?.label).toContain('setUserToken()');
    expect(child?.selector).toBe('0xe7897444');
  });

  test('keeps Tempo ABI decode lazy with operation hints', async ({ page }) => {
    const tokenA = `0x${'11'.repeat(20)}` as const;
    const tokenB = `0x${'22'.repeat(20)}` as const;
    const calldata = encodeFunctionData({
      abi: FAUCET_ABI,
      functionName: 'drip',
      args: [[tokenA, tokenB]],
    });

    const model = await page.evaluate(
      async ({ paths, calldataArg, abiArg }) => {
        const { buildTempoDisplayModel } = await import(paths.tempoBuilder);
        return buildTempoDisplayModel({
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              nonce: 3n,
              nonceKey: 1n,
              maxPriorityFeePerGas: 10n,
              maxFeePerGas: 20n,
              gasLimit: 200_000n,
              calls: [
                {
                  to: `0x${'99'.repeat(20)}`,
                  value: 0n,
                  input: calldataArg,
                  abi: abiArg,
                },
              ],
              accessList: [],
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          },
        });
      },
      {
        paths: IMPORT_PATHS,
        calldataArg: calldata,
        abiArg: FAUCET_ABI,
      },
    );

    const child = model.operations[0].children?.[0];
    const fields = Array.isArray(child?.fields) ? child.fields : [];
    expect(fields.some((field: { label?: string }) => field.label === 'Function')).toBe(false);
    expect(child?.abiDecodeHint?.dataHex).toBe(calldata);
    expect(Array.isArray(child?.abiDecodeHint?.abi)).toBe(true);
  });

  test('builds review tree from model without txSigningRequests', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { buildDisplayTreeFromModel } = await import(paths.txTreeUtils);
        const model = {
          chain: 'evm',
          title: 'Model-only Render',
          operations: [
            {
              id: 'fixture-op',
              kind: 'generic.contractCall',
              label: 'Call',
              fields: [{ label: 'To', value: `0x${'77'.repeat(20)}` }],
            },
          ],
        };

        const treeNode = buildDisplayTreeFromModel(model as any);
        const hasTree =
          !!treeNode && Array.isArray(treeNode.children) && treeNode.children.length > 0;
        const treeLabel = String(treeNode?.label || '');
        return { hasTree, treeLabel };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.hasTree).toBe(true);
    expect(result.treeLabel).toBe('Model-only Render');
  });
});
