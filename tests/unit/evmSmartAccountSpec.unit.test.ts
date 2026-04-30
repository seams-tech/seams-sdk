import { expect, test } from '@playwright/test';
import {
  getSeamsSmartAccountMethodSelector,
  getSeamsSmartAccountMethodSignature,
  SEAMS_SMART_ACCOUNT_ADD_OWNER_ABI,
} from '@shared/utils/evmSmartAccountSpec';

test.describe('evm smart-account spec helper', () => {
  test('reads canonical selectors and abi fragments from the in-repo spec artifacts', () => {
    expect(getSeamsSmartAccountMethodSignature('addOwner')).toBe('addOwner(address)');
    expect(getSeamsSmartAccountMethodSignature('removeOwner')).toBe('removeOwner(address)');
    expect(getSeamsSmartAccountMethodSignature('verifyAndRecover')).toBe(
      'verifyAndRecover(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)',
    );
    expect(getSeamsSmartAccountMethodSignature('recoverAddOwner')).toBe(
      'recoverAddOwner(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)',
    );

    expect(getSeamsSmartAccountMethodSelector('addOwner')).toBe('0x7065cb48');
    expect(getSeamsSmartAccountMethodSelector('removeOwner')).toBe('0x173825d9');
    expect(getSeamsSmartAccountMethodSelector('verifyAndRecover')).toBe('0xc3ec1673');
    expect(getSeamsSmartAccountMethodSelector('recoverAddOwner')).toBe('0x087af047');

    expect(SEAMS_SMART_ACCOUNT_ADD_OWNER_ABI).toEqual([
      {
        type: 'function',
        name: 'addOwner',
        inputs: [{ name: 'owner', type: 'address' }],
        outputs: [],
        stateMutability: 'nonpayable',
      },
    ]);
  });
});
