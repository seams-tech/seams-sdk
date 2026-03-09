import { expect, test } from '@playwright/test';
import {
  evaluateConsolePolicyRules,
  parseStoredConsolePolicyRules,
} from '../../server/src/console/policies/rules.ts';
import { parseCreateConsolePolicyRequest, parseUpdateConsolePolicyRequest } from '../../server/src/console/policies/requests.ts';
import { createInMemoryConsolePolicyService } from '../../server/src/console/policies/service.ts';

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
        name: 'Typed policy',
        rules: {
          blockedActions: [' transfer ', 'transfer'],
          allowedChains: [' Ethereum ', 'Ethereum'],
          maxAmountMinor: 5000,
        },
      }),
    ).toEqual({
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
        parseUpdateConsolePolicyRequest({
          rules: {
            blockedActions: ['transfer'],
            maxTransactionsPerHour: 10,
          },
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

  test('in-memory service simulates policies through the shared evaluator', async () => {
    const service = createInMemoryConsolePolicyService();
    const ctx = {
      orgId: 'org-policy-rules-1',
      actorUserId: 'user-policy-rules-1',
      roles: ['admin'],
    };

    const policy = await service.createPolicy(ctx, {
      id: 'policy-rules-1',
      name: 'Policy Rules 1',
      rules: {
        blockedActions: ['export_key'],
        allowedChains: ['Ethereum'],
        maxAmountMinor: 100,
      },
    });

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

  test('contract_call allowlists enforce contract and function restrictions', async () => {
    const rules = parseStoredConsolePolicyRules({
      allowedContractCalls: [
        {
          contractAddress: '0xabc123',
          functions: ['0xa9059cbb'],
        },
      ],
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'contract_call',
        contractAddress: '0xdef456',
      }),
    ).toEqual({
      decision: 'DENY',
      denyReasons: [
        {
          code: 'CONTRACT_NOT_ALLOWED',
          message: 'Contract 0xdef456 is not allowed by policy',
        },
      ],
      normalizedRequest: {
        action: 'contract_call',
        chain: null,
        amountMinor: null,
        contractAddress: '0xdef456',
        functionSelector: null,
      },
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'contract_call',
        contractAddress: '0xabc123',
        functionSelector: '0x095ea7b3',
      }),
    ).toEqual({
      decision: 'DENY',
      denyReasons: [
        {
          code: 'FUNCTION_NOT_ALLOWED',
          message: 'Function 0x095ea7b3 is not allowed for contract 0xabc123',
        },
      ],
      normalizedRequest: {
        action: 'contract_call',
        chain: null,
        amountMinor: null,
        contractAddress: '0xabc123',
        functionSelector: '0x095ea7b3',
      },
    });

    expect(
      evaluateConsolePolicyRules(rules, {
        action: 'contract_call',
        contractAddress: '0xabc123',
        functionSelector: '0xa9059cbb',
      }),
    ).toEqual({
      decision: 'ALLOW',
      denyReasons: [],
      normalizedRequest: {
        action: 'contract_call',
        chain: null,
        amountMinor: null,
        contractAddress: '0xabc123',
        functionSelector: '0xa9059cbb',
      },
    });
  });
});
