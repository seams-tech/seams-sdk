import { expect, test } from '@playwright/test';
import {
  getTatchiSmartAccountMethodSelector,
  getTatchiSmartAccountMethodSignature,
  TATCHI_SMART_ACCOUNT_ADD_OWNER_ABI,
} from '@shared/utils/evmSmartAccountSpec';

test.describe('evm smart-account spec helper', () => {
  test('reads canonical selectors and abi fragments from the in-repo spec artifacts', () => {
    expect(getTatchiSmartAccountMethodSignature('addOwner')).toBe('addOwner(address)');
    expect(getTatchiSmartAccountMethodSignature('removeOwner')).toBe('removeOwner(address)');
    expect(getTatchiSmartAccountMethodSignature('verifyAndRecover')).toBe(
      'verifyAndRecover(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)',
    );
    expect(getTatchiSmartAccountMethodSignature('recoverAddOwner')).toBe(
      'recoverAddOwner(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)',
    );

    expect(getTatchiSmartAccountMethodSelector('addOwner')).toBe('0x7065cb48');
    expect(getTatchiSmartAccountMethodSelector('removeOwner')).toBe('0x173825d9');
    expect(getTatchiSmartAccountMethodSelector('verifyAndRecover')).toBe('0xc3ec1673');
    expect(getTatchiSmartAccountMethodSelector('recoverAddOwner')).toBe('0x087af047');

    expect(TATCHI_SMART_ACCOUNT_ADD_OWNER_ABI).toEqual([
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
