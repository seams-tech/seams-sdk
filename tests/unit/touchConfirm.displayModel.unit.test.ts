import { expect, test } from '@playwright/test';
import { encodeFunctionData, parseAbi } from 'viem';

const IMPORT_PATHS = {
  nearBuilder: '/sdk/esm/core/signingEngine/touchConfirm/displayFormat/nearTx.js',
  evmBuilder: '/sdk/esm/core/signingEngine/touchConfirm/displayFormat/evmTx.js',
  tempoBuilder: '/sdk/esm/core/signingEngine/touchConfirm/displayFormat/tempoTx.js',
  txTreeUtils: '/sdk/esm/core/signingEngine/touchConfirm/ui/lit-components/TxTree/tx-tree-utils.js',
} as const;

const SMART_ACCOUNT_ABI = parseAbi([
  'function execute(address to, uint256 value, bytes data)',
  'function executeBatch(address[] to, uint256[] value, bytes[] data)',
]);

const ENTRY_POINT_V06_ABI = parseAbi([
  'function handleOps((address sender,uint256 nonce,bytes initCode,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,bytes paymasterAndData,bytes signature)[] ops,address beneficiary)',
]);

const ERC20_ABI = parseAbi(['function transfer(address to, uint256 amount)']);

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

  test('decodes ERC-4337 handleOps + execute callData into child calls', async ({ page }) => {
    const entryPoint = `0x${'99'.repeat(20)}` as const;
    const beneficiary = `0x${'33'.repeat(20)}` as const;
    const smartAccount = `0x${'11'.repeat(20)}` as const;
    const target = `0x${'22'.repeat(20)}` as const;
    const tokenRecipient = `0x${'44'.repeat(20)}` as const;

    const erc20TransferData = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [tokenRecipient, 42n],
    });

    const executeCallData = encodeFunctionData({
      abi: SMART_ACCOUNT_ABI,
      functionName: 'execute',
      args: [target, 7n, erc20TransferData],
    });

    const handleOpsData = encodeFunctionData({
      abi: ENTRY_POINT_V06_ABI,
      functionName: 'handleOps',
      args: [
        [
          {
            sender: smartAccount,
            nonce: 5n,
            initCode: '0x',
            callData: executeCallData,
            callGasLimit: 120_000n,
            verificationGasLimit: 300_000n,
            preVerificationGas: 50_000n,
            maxFeePerGas: 1_000_000_000n,
            maxPriorityFeePerGas: 100_000_000n,
            paymasterAndData: '0x',
            signature: `0x${'aa'.repeat(65)}`,
          },
        ],
        beneficiary,
      ],
    });

    const model = await page.evaluate(
      async ({ paths, entryPointArg, handleOpsDataArg }) => {
        const { buildEvmDisplayModel } = await import(paths.evmBuilder);
        return buildEvmDisplayModel({
          intentDigest: '0x11',
          signerAccount: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 300_000n,
              to: entryPointArg,
              value: 0n,
              data: handleOpsDataArg,
              accessList: [],
            },
          },
        });
      },
      {
        paths: IMPORT_PATHS,
        entryPointArg: entryPoint,
        handleOpsDataArg: handleOpsData,
      },
    );

    expect(model.operations[0].kind).toBe('evm.erc4337');
    expect(model.operations[0].children).toHaveLength(1);
    expect(model.operations[0].children[0].kind).toBe('evm.erc4337');
    expect(model.operations[0].children[0].children).toHaveLength(1);
    expect(model.operations[0].children[0].children[0].kind).toBe('generic.contractCall');
    expect(model.operations[0].children[0].children[0].to?.toLowerCase()).toBe(
      target.toLowerCase(),
    );
    expect(model.operations[0].children[0].children[0].value).toBe('7');
    expect(model.operations[0].children[0].children[0].selector).toBe('0xa9059cbb');
    const nestedCallFields = Array.isArray(model.operations[0].children[0].children[0].fields)
      ? model.operations[0].children[0].children[0].fields
      : [];
    expect(
      nestedCallFields.some((field: { label?: string; value?: string }) => field.label === 'Function'),
    ).toBe(false);
    expect(
      nestedCallFields.some((field: { label?: string; value?: string }) => field.label === 'Selector'),
    ).toBe(false);
  });

  test('decodes executeBatch callData for direct smart-account calls', async ({ page }) => {
    const smartAccount = `0x${'ab'.repeat(20)}` as const;
    const firstTarget = `0x${'12'.repeat(20)}` as const;
    const secondTarget = `0x${'34'.repeat(20)}` as const;
    const tokenRecipient = `0x${'56'.repeat(20)}` as const;

    const erc20TransferA = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [tokenRecipient, 1n],
    });

    const erc20TransferB = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [tokenRecipient, 2n],
    });

    const executeBatchData = encodeFunctionData({
      abi: SMART_ACCOUNT_ABI,
      functionName: 'executeBatch',
      args: [
        [firstTarget, secondTarget],
        [5n, 9n],
        [erc20TransferA, erc20TransferB],
      ],
    });

    const model = await page.evaluate(
      async ({ paths, smartAccountArg, executeBatchDataArg }) => {
        const { buildEvmDisplayModel } = await import(paths.evmBuilder);
        return buildEvmDisplayModel({
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 8n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 300_000n,
              to: smartAccountArg,
              value: 0n,
              data: executeBatchDataArg,
              accessList: [],
            },
          },
        });
      },
      {
        paths: IMPORT_PATHS,
        smartAccountArg: smartAccount,
        executeBatchDataArg: executeBatchData,
      },
    );

    expect(model.operations[0].kind).toBe('evm.erc4337');
    expect(model.operations[0].callType).toBe('executeBatch');
    expect(model.operations[0].children).toHaveLength(2);
    expect(model.operations[0].children[0].to?.toLowerCase()).toBe(firstTarget.toLowerCase());
    expect(model.operations[0].children[1].to?.toLowerCase()).toBe(secondTarget.toLowerCase());
    expect(model.operations[0].children[0].value).toBe('5');
    expect(model.operations[0].children[1].value).toBe('9');
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

  test('falls back safely for partial ERC-4337 decode failures', async ({ page }) => {
    const malformedExecuteCallData = '0xb61d27f6';
    const model = await page.evaluate(
      async ({ paths, malformedData }) => {
        const { buildEvmDisplayModel } = await import(paths.evmBuilder);
        return buildEvmDisplayModel({
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 9n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 300_000n,
              to: `0x${'cd'.repeat(20)}`,
              value: 0n,
              data: malformedData,
              accessList: [],
            },
          },
        });
      },
      {
        paths: IMPORT_PATHS,
        malformedData: malformedExecuteCallData,
      },
    );

    expect(model.operations[0].kind).toBe('evm.erc4337');
    expect(model.warnings?.length || 0).toBeGreaterThan(0);
    expect(model.operations[0].children[0].kind).toBe('generic.contractCall');
    expect(model.operations[0].children[0].selector).toBe('0xb61d27f6');
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
