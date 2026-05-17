import { expect, test } from '@playwright/test';
import { resolveSponsoredEvmCallConfigFromEnv } from '../../server/src/sponsorship/evmRelay';

test.describe('sponsored EVM executor registry parsing', () => {
  test('derives sponsorAddress from sponsorPrivateKeyHex', async () => {
    const sponsorPrivateKeyHex =
      '0x1111111111111111111111111111111111111111111111111111111111111111' as const;
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        42431: {
          rpcUrl: 'https://rpc.moderato.tempo.xyz',
          sponsorPrivateKeyHex,
          maxPriorityFeePerGasFloor: '2000000000',
          maxFeePerGasFloor: '40000000000',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).not.toBeNull();
    const executor = config?.executorsByChain.get(42_431);
    expect(executor).toBeTruthy();
    expect(executor?.sponsorAddress).toBe('0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a');
    expect(executor?.rpcUrl).toBe('https://rpc.moderato.tempo.xyz');
  });

  test('uses the default Tempo RPC when chain 42431 omits rpcUrl', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        42431: {
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config?.executorsByChain.get(42_431)?.rpcUrl).toBe('https://rpc.moderato.tempo.xyz');
  });

  test('returns null when all executor entries are invalid', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        11155111: {
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });

  test('returns null for invalid registry JSON', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: '{invalid-json',
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });

  test('ignores entries with unsupported executor kinds', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        42431: {
          kind: 'unsupported_executor',
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });

  test('returns null for duplicate normalized chain entries', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        tempo_primary: {
          chainId: 42431,
          rpcUrl: 'https://rpc.example-one.invalid',
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
        },
        tempo_secondary: {
          chainId: 42431,
          rpcUrl: 'https://rpc.moderato.tempo.xyz',
          sponsorPrivateKeyHex:
            '0x2222222222222222222222222222222222222222222222222222222222222222',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });

  test('returns null when executor entries are missing sponsorPrivateKeyHex', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        42431: {
          rpcUrl: 'https://rpc.moderato.tempo.xyz',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });

  test('returns null when a non-default chain omits rpcUrl', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        11155111: {
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });

  test('returns null when explicit fee floor values are malformed', async () => {
    const config = await resolveSponsoredEvmCallConfigFromEnv({
      SPONSORED_EVM_EXECUTORS_JSON: JSON.stringify({
        42431: {
          rpcUrl: 'https://rpc.moderato.tempo.xyz',
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
          maxPriorityFeePerGasFloor: 'abc',
          maxFeePerGasFloor: '-1',
        },
      }),
    } as NodeJS.ProcessEnv);
    expect(config).toBeNull();
  });
});
