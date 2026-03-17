import { expect, test } from '@playwright/test';
import { getNearSpendCapChainId } from '@shared/console/gasSponsorshipSpendCapTargets';
import {
  evaluateConsolePolicyRules,
  isConsoleGasSponsorshipPolicyRules,
  parseConsolePolicyRulesInput,
  parseStoredConsolePolicyRules,
  validateGasSponsorshipPolicyRulesForPublish,
} from '../../server/src/console/policies/rules';
import {
  parseCreateConsolePolicyRequest,
  parseListConsolePoliciesRequest,
  parseSimulateConsolePolicyRequest,
  parseUpdateConsolePolicyRequest,
} from '../../server/src/console/policies/requests';
import { createInMemoryConsolePolicyService } from '../../server/src/console/policies/service';

async function expectPolicyError(
  fn: () => unknown | Promise<unknown>,
  expectedCode: string,
): Promise<void> {
  let caught: unknown;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String((caught as { code?: unknown } | null)?.code || '')).toBe(expectedCode);
}

test.describe('console policy rules parser and evaluator', () => {
  test('request parsers normalize known rules and reject unknown keys', async () => {
    expect(
      parseCreateConsolePolicyRequest({
        kind: 'TRANSACTION',
        name: 'Typed policy',
        rules: {
          blockedActions: [' transfer ', 'transfer'],
          allowedChains: [' Ethereum ', 'Ethereum'],
          maxAmountMinor: 5000,
        },
      }),
    ).toEqual({
      kind: 'TRANSACTION',
      name: 'Typed policy',
      rules: {
        schemaVersion: 1,
        blockedActions: ['transfer'],
        allowedChains: ['Ethereum'],
        allowedContractCalls: [],
        maxAmountMinor: 5000,
      },
    });

    await expectPolicyError(
      async () =>
        parseConsolePolicyRulesInput(
          {
            blockedActions: ['transfer'],
            maxTransactionsPerHour: 10,
          },
          'TRANSACTION',
        ),
      'invalid_body',
    );

    expect(
      parseCreateConsolePolicyRequest({
        kind: 'GAS_SPONSORSHIP',
        name: 'Gas policy draft',
        rules: {
          kind: 'evm_call',
          executionMode: 'evm_eoa',
          scopeType: 'POLICY',
          scopePolicyId: 'policy_tx_scope_1',
          enabled: true,
          networkClass: 'MAINNET',
          allowedCalls: [
            {
              chainId: 1,
              to: '0x1111111111111111111111111111111111111111',
              functionSignature: 'transfer(address,uint256)',
              maxGasLimit: '21000',
              maxValueWei: '0',
            },
          ],
          spendCap: {
            mode: 'CHAIN_TOTAL',
            period: 'MONTHLY',
            capsByChain: [{ chainId: 1, capMinor: 10_000 }],
          },
        },
      }),
    ).toEqual({
      kind: 'GAS_SPONSORSHIP',
      name: 'Gas policy draft',
      rules: {
        schemaVersion: 1,
        scopeType: 'POLICY',
        projectId: null,
        environmentId: null,
        scopePolicyId: 'policy_tx_scope_1',
        walletSegmentId: null,
        enabled: true,
        templateId: null,
        networkClass: 'MAINNET',
        kind: 'evm_call',
        executionMode: 'evm_eoa',
        allowedCalls: [
          {
            chainId: 1,
            to: '0x1111111111111111111111111111111111111111',
            functionSignature: 'transfer(address,uint256)',
            selector: '0xa9059cbb',
            maxGasLimit: '21000',
            maxValueWei: '0',
          },
        ],
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 1, capMinor: 10_000 }],
        },
      },
    });

    await expectPolicyError(
      async () =>
        parseCreateConsolePolicyRequest({
          kind: 'GAS_SPONSORSHIP',
          name: 'Invalid gas assignment',
          assignment: {
            scopeType: 'ORG',
            scopeId: 'org_1',
          },
        }),
      'invalid_body',
    );

    expect(parseListConsolePoliciesRequest({ kind: 'gas_sponsorship' })).toEqual({
      kind: 'GAS_SPONSORSHIP',
    });

    await expectPolicyError(
      async () =>
        parseListConsolePoliciesRequest({
          kind: 'signing',
        }),
      'invalid_query',
    );

    await expectPolicyError(
      async () =>
        parseCreateConsolePolicyRequest({
          id: 'policy_user_supplied',
          name: 'Should fail',
        }),
      'invalid_body',
    );
  });

  test('stored-rule parsing drops stale keys and shared evaluator returns specific reasons', async () => {
    const rules = parseStoredConsolePolicyRules({
      blockedActions: ['export_key'],
      allowedChains: ['Base'],
      maxTransactionsPerHour: 24,
    });
    expect(rules).toEqual({
      schemaVersion: 1,
      blockedActions: ['export_key'],
      allowedChains: ['Base'],
      allowedContractCalls: [],
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'transfer',
        chain: 'Ethereum',
        amountMinor: 1,
      }),
    ).toEqual({
      decision: 'DENY',
      denyReasons: [
        {
          code: 'CHAIN_NOT_ALLOWED',
          message: 'Chain ethereum is not allowed by policy',
        },
      ],
      normalizedRequest: {
        action: 'transfer',
        chain: 'ethereum',
        amountMinor: 1,
        contractAddress: null,
        functionSelector: null,
      },
    });
  });

  test('gas policy rules normalize and validate publish-time requirements', async () => {
    const gasRules = parseConsolePolicyRulesInput(
      {
        kind: 'evm_call',
        executionMode: 'evm_eoa',
        scopeType: 'ENVIRONMENT',
        environmentId: 'env_1',
        enabled: false,
        networkClass: 'testnet',
        allowedCalls: [
          {
            chainId: 84532,
            to: '0x1111111111111111111111111111111111111111',
            functionSignature: 'transfer(address,uint256)',
            maxGasLimit: '42000',
            maxValueWei: '0',
          },
        ],
        spendCap: {
          mode: 'NONE',
          period: 'WEEKLY',
          capsByChain: [{ chainId: 84532, capMinor: 100 }],
        },
      },
      'GAS_SPONSORSHIP',
    );
    expect(isConsoleGasSponsorshipPolicyRules(gasRules)).toBe(true);
    expect(gasRules).toEqual({
      schemaVersion: 1,
      scopeType: 'ENVIRONMENT',
      projectId: null,
      environmentId: 'env_1',
      scopePolicyId: null,
      walletSegmentId: null,
      enabled: false,
      templateId: null,
      networkClass: 'TESTNET',
      kind: 'evm_call',
      executionMode: 'evm_eoa',
      allowedCalls: [
        {
          chainId: 84532,
          to: '0x1111111111111111111111111111111111111111',
          functionSignature: 'transfer(address,uint256)',
          selector: '0xa9059cbb',
          maxGasLimit: '42000',
          maxValueWei: '0',
        },
      ],
      spendCap: {
        mode: 'NONE',
        period: 'WEEKLY',
        capsByChain: [],
      },
    });

    expect(() => validateGasSponsorshipPolicyRulesForPublish(gasRules)).not.toThrow();

    const invalidGasRules = parseConsolePolicyRulesInput(
      {
        kind: 'evm_call',
        scopeType: 'POLICY',
        allowedCalls: [],
      },
      'GAS_SPONSORSHIP',
    );
    expect(isConsoleGasSponsorshipPolicyRules(invalidGasRules)).toBe(true);
    await expectPolicyError(
      async () => validateGasSponsorshipPolicyRulesForPublish(invalidGasRules),
      'invalid_body',
    );
  });

  test('near gas sponsorship publish validation accepts concrete spend caps and rejects ambiguous ones', async () => {
    const nearTestnetChainId = getNearSpendCapChainId('TESTNET');
    const nearRules = parseConsolePolicyRulesInput(
      {
        kind: 'near_delegate',
        executionMode: 'near_delegate',
        scopeType: 'ENVIRONMENT',
        environmentId: 'env_1',
        enabled: true,
        networkClass: 'TESTNET',
        allowedDelegateActions: [
          {
            receiverId: 'guest-book.testnet',
            methods: ['add_message'],
            maxDepositYocto: '1000000000000000000000000',
            allowTransfers: false,
          },
        ],
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: nearTestnetChainId, capMinor: 25_000 }],
        },
      },
      'GAS_SPONSORSHIP',
    );
    expect(isConsoleGasSponsorshipPolicyRules(nearRules)).toBe(true);
    expect(() => validateGasSponsorshipPolicyRulesForPublish(nearRules)).not.toThrow();

    const ambiguousNearRules = parseConsolePolicyRulesInput(
      {
        kind: 'near_delegate',
        executionMode: 'near_delegate',
        scopeType: 'ENVIRONMENT',
        environmentId: 'env_1',
        enabled: true,
        networkClass: 'ANY',
        allowedDelegateActions: [
          {
            receiverId: 'guest-book.testnet',
            methods: ['add_message'],
            maxDepositYocto: '1000000000000000000000000',
            allowTransfers: false,
          },
        ],
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: nearTestnetChainId, capMinor: 25_000 }],
        },
      },
      'GAS_SPONSORSHIP',
    );
    await expectPolicyError(
      async () => validateGasSponsorshipPolicyRulesForPublish(ambiguousNearRules),
      'invalid_body',
    );

    const mismatchedNearRules = parseConsolePolicyRulesInput(
      {
        kind: 'near_delegate',
        executionMode: 'near_delegate',
        scopeType: 'ENVIRONMENT',
        environmentId: 'env_1',
        enabled: true,
        networkClass: 'TESTNET',
        allowedDelegateActions: [
          {
            receiverId: 'guest-book.testnet',
            methods: ['add_message'],
            maxDepositYocto: '1000000000000000000000000',
            allowTransfers: false,
          },
        ],
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 42_431, capMinor: 25_000 }],
        },
      },
      'GAS_SPONSORSHIP',
    );
    await expectPolicyError(
      async () => validateGasSponsorshipPolicyRulesForPublish(mismatchedNearRules),
      'invalid_body',
    );
  });

  test('in-memory service simulates policies through the shared evaluator', async () => {
    const service = createInMemoryConsolePolicyService();
    const ctx = {
      orgId: 'org-policy-rules-1',
      actorUserId: 'user-policy-rules-1',
      roles: ['admin'],
    };

    const policy = await service.createPolicy(ctx, {
      name: 'Policy Rules 1',
      rules: {
        blockedActions: ['export_key'],
        allowedChains: ['Ethereum'],
        maxAmountMinor: 100,
      },
    });
    expect(policy.id).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
    expect(policy.kind).toBe('TRANSACTION');

    const allowed = await service.simulatePolicy(ctx, policy.id, {
      action: 'transfer',
      chain: 'Ethereum',
      amountMinor: 100,
    });
    expect(allowed).toMatchObject({
      decision: 'ALLOW',
      denyReasons: [],
      normalizedRequest: {
        action: 'transfer',
        chain: 'ethereum',
        amountMinor: 100,
        contractAddress: null,
        functionSelector: null,
      },
    });

    const denied = await service.simulatePolicy(ctx, policy.id, {
      action: 'export_key',
      chain: 'Ethereum',
      amountMinor: 1,
    });
    expect(denied).toMatchObject({
      decision: 'DENY',
      denyReasons: [
        {
          code: 'ACTION_BLOCKED',
          message: 'Action export_key is blocked by policy',
        },
      ],
      normalizedRequest: {
        action: 'export_key',
        chain: 'ethereum',
        amountMinor: 1,
        contractAddress: null,
        functionSelector: null,
      },
    });
  });

  test('in-memory service supports gas policy drafts but rejects assignment and simulation flows', async () => {
    const service = createInMemoryConsolePolicyService();
    const ctx = {
      orgId: 'org-gas-policy-rules-1',
      actorUserId: 'user-gas-policy-rules-1',
      roles: ['admin'],
    };

    const gasPolicy = await service.createPolicy(ctx, {
      kind: 'GAS_SPONSORSHIP',
      name: 'Gas Policy 1',
      rules: {
        scopeType: 'ORG',
        kind: 'evm_call',
        allowedCalls: [
          {
            chainId: 1,
            to: '0x1111111111111111111111111111111111111111',
            functionSignature: 'transfer(address,uint256)',
            maxGasLimit: '21000',
            maxValueWei: '0',
          },
        ],
      },
    });
    expect(gasPolicy.kind).toBe('GAS_SPONSORSHIP');
    expect(gasPolicy.rules).toMatchObject({
      scopeType: 'ORG',
      kind: 'evm_call',
      scopePolicyId: null,
      allowedCalls: [
        {
          chainId: 1,
          selector: '0xa9059cbb',
        },
      ],
    });

    const published = await service.publishPolicy(ctx, gasPolicy.id);
    expect(published?.policy.kind).toBe('GAS_SPONSORSHIP');

    await expectPolicyError(
      async () =>
        service.simulatePolicy(ctx, gasPolicy.id, {
          action: 'transfer',
        }),
      'simulation_not_supported',
    );

    await expectPolicyError(
      async () =>
        service.upsertAssignment(ctx, {
          scopeType: 'ORG',
          scopeId: ctx.orgId,
          policyId: gasPolicy.id,
        }),
      'policy_assignment_unsupported',
    );
  });

  test('in-memory service bootstraps a protected default policy with a generated id', async () => {
    const service = createInMemoryConsolePolicyService();
    const ctx = {
      orgId: 'org-policy-default-1',
      actorUserId: 'user-policy-default-1',
      roles: ['admin'],
    };

    const policies = await service.listPolicies(ctx);
    const defaultPolicy = policies.find((entry) => entry.isSystemDefault) || null;
    expect(defaultPolicy).toBeTruthy();
    expect(defaultPolicy?.id).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
    expect(defaultPolicy?.kind).toBe('TRANSACTION');
    expect(defaultPolicy?.name).toBe('Default Policy');

    await expectPolicyError(
      async () => {
        await service.deletePolicy(ctx, String(defaultPolicy?.id || ''));
      },
      'default_policy_protected',
    );
  });

  test('contract_call allowlists enforce contract and function restrictions', async () => {
    const allowedContractAddress = '0x1111111111111111111111111111111111111111';
    const deniedContractAddress = '0x2222222222222222222222222222222222222222';
    const rules = parseStoredConsolePolicyRules({
      allowedContractCalls: [
        {
          contractAddress: allowedContractAddress,
          functions: ['0xa9059cbb'],
        },
      ],
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'contract_call',
        contractAddress: deniedContractAddress,
      }),
    ).toEqual({
      decision: 'DENY',
      denyReasons: [
        {
          code: 'CONTRACT_NOT_ALLOWED',
          message: `Contract ${deniedContractAddress} is not allowed by policy`,
        },
      ],
      normalizedRequest: {
        action: 'contract_call',
        chain: null,
        amountMinor: null,
        contractAddress: deniedContractAddress,
        functionSelector: null,
      },
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'contract_call',
        contractAddress: allowedContractAddress,
        functionSelector: '0x095ea7b3',
      }),
    ).toEqual({
      decision: 'DENY',
      denyReasons: [
        {
          code: 'FUNCTION_NOT_ALLOWED',
          message: `Function 0x095ea7b3 is not allowed for contract ${allowedContractAddress}`,
        },
      ],
      normalizedRequest: {
        action: 'contract_call',
        chain: null,
        amountMinor: null,
        contractAddress: allowedContractAddress,
        functionSelector: '0x095ea7b3',
      },
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'contract_call',
        contractAddress: allowedContractAddress,
        functionSelector: '0xa9059cbb',
      }),
    ).toEqual({
      decision: 'ALLOW',
      denyReasons: [],
      normalizedRequest: {
        action: 'contract_call',
        chain: null,
        amountMinor: null,
        contractAddress: allowedContractAddress,
        functionSelector: '0xa9059cbb',
      },
    });
  });

  test('contract_call rules reject invalid addresses, invalid selectors, and duplicates', async () => {
    await expectPolicyError(
      async () =>
        parseCreateConsolePolicyRequest({
          name: 'Invalid contract address policy',
          rules: {
            allowedContractCalls: [
              {
                contractAddress: '0xabc123',
              },
            ],
          },
        }),
      'invalid_body',
    );

    await expectPolicyError(
      async () =>
        parseUpdateConsolePolicyRequest({
          rules: {
            allowedContractCalls: [
              {
                contractAddress: '0x1111111111111111111111111111111111111111',
                functions: ['approve('],
              },
            ],
          },
        }),
      'invalid_body',
    );

    await expectPolicyError(
      async () =>
        parseUpdateConsolePolicyRequest({
          rules: {
            allowedContractCalls: [
              {
                contractAddress: '0x1111111111111111111111111111111111111111',
              },
              {
                contractAddress: '0x1111111111111111111111111111111111111111',
              },
            ],
          },
        }),
      'invalid_body',
    );

    await expectPolicyError(
      async () =>
        parseUpdateConsolePolicyRequest({
          rules: {
            allowedContractCalls: [
              {
                contractAddress: '0x1111111111111111111111111111111111111111',
                functions: ['0xA9059CBB', '0xa9059cbb'],
              },
            ],
          },
        }),
      'invalid_body',
    );
  });

  test('contract_call rules normalize stored addresses and function identifiers', async () => {
    expect(
      parseConsolePolicyRulesInput({
        allowedContractCalls: [
          {
            contractAddress: '0x1111111111111111111111111111111111111111',
            functions: ['0xA9059CBB', 'transfer( address , uint256 )'],
          },
        ],
      }),
    ).toEqual({
      schemaVersion: 1,
      blockedActions: [],
      allowedChains: [],
      maxAmountMinor: undefined,
      allowedContractCalls: [
        {
          contractAddress: '0x1111111111111111111111111111111111111111',
          functions: ['0xa9059cbb', 'transfer(address,uint256)'],
        },
      ],
    });

    expect(
      parseSimulateConsolePolicyRequest({
        action: 'contract_call',
        contractAddress: '0x1111111111111111111111111111111111111111',
        functionSelector: 'transfer( address , uint256 )',
      }),
    ).toEqual({
      action: 'contract_call',
      contractAddress: '0x1111111111111111111111111111111111111111',
      functionSelector: 'transfer(address,uint256)',
    });
  });
});
