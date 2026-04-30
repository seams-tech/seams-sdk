import smartAccountMetadata from '../../../contracts/evm-smart-account/abi/SeamsSmartAccount.metadata.json' with { type: 'json' };

export type SeamsSmartAccountMethod =
  | 'addOwner'
  | 'removeOwner'
  | 'verifyAndRecover'
  | 'recoverAddOwner';

export const SEAMS_SMART_ACCOUNT_ADD_OWNER_SIGNATURE = 'addOwner(address)' as const;
export const SEAMS_SMART_ACCOUNT_REMOVE_OWNER_SIGNATURE = 'removeOwner(address)' as const;
export const SEAMS_SMART_ACCOUNT_VERIFY_AND_RECOVER_SIGNATURE =
  'verifyAndRecover(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)' as const;
export const SEAMS_SMART_ACCOUNT_RECOVER_ADD_OWNER_SIGNATURE =
  'recoverAddOwner(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)' as const;

const METHOD_SIGNATURES = {
  addOwner: SEAMS_SMART_ACCOUNT_ADD_OWNER_SIGNATURE,
  removeOwner: SEAMS_SMART_ACCOUNT_REMOVE_OWNER_SIGNATURE,
  verifyAndRecover: SEAMS_SMART_ACCOUNT_VERIFY_AND_RECOVER_SIGNATURE,
  recoverAddOwner: SEAMS_SMART_ACCOUNT_RECOVER_ADD_OWNER_SIGNATURE,
} as const satisfies Record<SeamsSmartAccountMethod, string>;

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function normalizeMethodIdentifier(value: unknown, label: string): `0x${string}` {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{8}$/.test(normalized)) {
    throw new Error(`Invalid smart-account method selector metadata for ${label}`);
  }
  return normalized as `0x${string}`;
}

function readMethodSelector(method: SeamsSmartAccountMethod): `0x${string}` {
  const methodIdentifiers = asObject(asObject(smartAccountMetadata).methodIdentifiers);
  const signature = METHOD_SIGNATURES[method];
  return normalizeMethodIdentifier(methodIdentifiers[signature], signature);
}

export function getSeamsSmartAccountMethodSignature(method: SeamsSmartAccountMethod): string {
  return METHOD_SIGNATURES[method];
}

export function getSeamsSmartAccountMethodSelector(
  method: SeamsSmartAccountMethod,
): `0x${string}` {
  return readMethodSelector(method);
}

// The packaged `.metadata.json` is machine-readable for selectors; the sibling `abi/*.json`
// files are currently human-formatted tables, so keep the minimal tx-confirmation ABI local here.
export const SEAMS_SMART_ACCOUNT_ADD_OWNER_ABI = Object.freeze([
  Object.freeze({
    type: 'function',
    name: 'addOwner',
    inputs: Object.freeze([{ name: 'owner', type: 'address' }]),
    outputs: Object.freeze([]),
    stateMutability: 'nonpayable',
  }),
]);

export const SEAMS_SMART_ACCOUNT_REMOVE_OWNER_ABI = Object.freeze([
  Object.freeze({
    type: 'function',
    name: 'removeOwner',
    inputs: Object.freeze([{ name: 'owner', type: 'address' }]),
    outputs: Object.freeze([]),
    stateMutability: 'nonpayable',
  }),
]);
