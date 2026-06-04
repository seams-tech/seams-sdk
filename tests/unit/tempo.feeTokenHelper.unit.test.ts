import { expect, test } from '@playwright/test';
import { SDK_ESM_PATHS, setupBasicPasskeyTest } from '../setup';

test.describe('Tempo fee token helpers', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('encodes setUserToken(address) calldata and default fee-manager call', async ({ page }) => {
    const result = await page.evaluate(async (indexPath) => {
      const mod = await import(indexPath);
      const token = '0x20c0000000000000000000000000000000000001';
      const user = '0x8454d149beb26e3e3fc5ed1c87fb0b2a1b7b6c2c';
      const calldata = mod.encodeTempoSetUserTokenCalldata(token);
      const userTokensCallData = mod.encodeTempoUserTokensCalldata(user);
      const call = mod.buildTempoSetUserTokenCall({ token });
      const decodedToken = mod.decodeTempoUserTokenResult(
        `0x000000000000000000000000${token.slice(2)}`,
      );
      const decodedUnset = mod.decodeTempoUserTokenResult(
        '0x0000000000000000000000000000000000000000000000000000000000000000',
      );
      return {
        feeManager: mod.TEMPO_FEE_MANAGER_CONTRACT,
        alphaToken: mod.TEMPO_ALPHA_USD_FEE_TOKEN,
        selector: mod.TEMPO_SET_USER_TOKEN_SELECTOR,
        userTokensSelector: mod.TEMPO_USER_TOKENS_SELECTOR,
        calldata,
        userTokensCallData,
        callTo: call.to,
        callValue: String(call.value),
        callInput: call.input,
        callAbiName: Array.isArray(call.abi) ? call.abi[0]?.name : null,
        callAbiType: Array.isArray(call.abi) ? call.abi[0]?.type : null,
        callAbiInputType:
          Array.isArray(call.abi) && Array.isArray(call.abi[0]?.inputs)
            ? call.abi[0]?.inputs?.[0]?.type
            : null,
        decodedToken,
        decodedUnset,
      };
    }, SDK_ESM_PATHS.index);

    const expectedCalldata =
      '0xe789744400000000000000000000000020c0000000000000000000000000000000000001';
    const expectedUserTokensCallData =
      '0xed498fa80000000000000000000000008454d149beb26e3e3fc5ed1c87fb0b2a1b7b6c2c';

    expect(result.feeManager).toBe('0xfeec000000000000000000000000000000000000');
    expect(result.alphaToken).toBe('0x20c0000000000000000000000000000000000001');
    expect(result.selector).toBe('0xe7897444');
    expect(result.userTokensSelector).toBe('0xed498fa8');
    expect(result.calldata).toBe(expectedCalldata);
    expect(result.userTokensCallData).toBe(expectedUserTokensCallData);
    expect(result.callTo).toBe(result.feeManager);
    expect(result.callValue).toBe('0');
    expect(result.callInput).toBe(expectedCalldata);
    expect(result.callAbiName).toBe('setUserToken');
    expect(result.callAbiType).toBe('function');
    expect(result.callAbiInputType).toBe('address');
    expect(result.decodedToken).toBe('0x20c0000000000000000000000000000000000001');
    expect(result.decodedUnset).toBeNull();
  });
});
