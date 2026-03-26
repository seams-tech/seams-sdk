import { keccak256Bytes } from '@shared/utils/keccak';
import {
  getTatchiSmartAccountMethodSelector,
  TATCHI_SMART_ACCOUNT_RECOVER_ADD_OWNER_SIGNATURE,
  TATCHI_SMART_ACCOUNT_VERIFY_AND_RECOVER_SIGNATURE,
} from '@shared/utils/evmSmartAccountSpec';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { signSecp256k1Recoverable } from './ThresholdService/ethSignerWasm';

export const RECOVERY_AUTHORITY_DOMAIN_NAME = 'TatchiSmartAccountRecovery';
export const RECOVERY_AUTHORITY_DOMAIN_VERSION = '1';
export const VERIFY_AND_RECOVER_SIGNATURE = TATCHI_SMART_ACCOUNT_VERIFY_AND_RECOVER_SIGNATURE;
export const RECOVER_ADD_OWNER_SIGNATURE = TATCHI_SMART_ACCOUNT_RECOVER_ADD_OWNER_SIGNATURE;

export type RecoveryAuthorityContractMethod = 'verifyAndRecover' | 'recoverAddOwner';

export type RecoveryAuthorityAuthorization = {
  version: 'recovery_authority_authorization_v1';
  contractMethod: RecoveryAuthorityContractMethod;
  authorityAddress: `0x${string}`;
  domain: {
    name: typeof RECOVERY_AUTHORITY_DOMAIN_NAME;
    version: typeof RECOVERY_AUTHORITY_DOMAIN_VERSION;
    chainId: number;
    verifyingContract: `0x${string}`;
  };
  payload: {
    nearAccountIdHash: `0x${string}`;
    newNearKeyHash: `0x${string}`;
    newOwner: `0x${string}`;
    recoverySessionHash: `0x${string}`;
    nonce: `0x${string}`;
    deadline: `0x${string}`;
  };
  digest: `0x${string}`;
  signature: `0x${string}`;
};

const DOMAIN_TYPEHASH = keccak256Bytes(
  new TextEncoder().encode('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
);
const RECOVERY_TYPEHASH = keccak256Bytes(
  new TextEncoder().encode(
    'RecoverAddOwner(bytes32 nearAccountIdHash,bytes32 newNearKeyHash,address newOwner,bytes32 recoverySessionHash,uint256 nonce,uint256 deadline)',
  ),
);

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`;
}

function utf8KeccakHex(value: string): `0x${string}` {
  return bytesToHex(keccak256Bytes(new TextEncoder().encode(value)));
}

function assertAddress(value: string, label: string): `0x${string}` {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`Invalid ${label}`);
  }
  return normalized as `0x${string}`;
}

function assertHex32(value: string, label: string): `0x${string}` {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`Invalid ${label}`);
  }
  return normalized as `0x${string}`;
}

function parseHexBytes(value: `0x${string}`, label: string): Uint8Array {
  const normalized = strip0x(value).toLowerCase();
  if (!normalized || normalized.length % 2 !== 0 || /[^0-9a-f]/.test(normalized)) {
    throw new Error(`Invalid ${label}`);
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    out[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return out;
}

function privateKeyHexToBytes(value: `0x${string}`): Uint8Array {
  return parseHexBytes(value, 'authorityPrivateKeyHex');
}

function strip0x(value: `0x${string}`): string {
  return value.slice(2);
}

function hexToBytes(value: `0x${string}`): Uint8Array {
  return parseHexBytes(value, 'hex value');
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeUint256(value: bigint): `0x${string}` {
  if (value < 0n) throw new Error('uint256 cannot be negative');
  return `0x${value.toString(16).padStart(64, '0')}` as `0x${string}`;
}

function encodeAddressWord(address: `0x${string}`): `0x${string}` {
  return `0x${strip0x(address).padStart(64, '0')}` as `0x${string}`;
}

function encodeDynamicBytesWord(value: `0x${string}`): `0x${string}` {
  const bytes = hexToBytes(value);
  const paddedLength = Math.ceil(bytes.length / 32) * 32;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes, 0);
  return `0x${strip0x(encodeUint256(BigInt(bytes.length)))}${Array.from(padded)
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`;
}

function signatureForMethod(method: RecoveryAuthorityContractMethod): string {
  return method === 'recoverAddOwner' ? RECOVER_ADD_OWNER_SIGNATURE : VERIFY_AND_RECOVER_SIGNATURE;
}

function buildDomainSeparator(input: {
  chainId: number;
  verifyingContract: `0x${string}`;
}): `0x${string}` {
  const chainId = BigInt(Math.floor(Number(input.chainId)));
  if (chainId <= 0n) throw new Error('Invalid chainId for recovery authorization');
  const encoded = concatBytes([
    DOMAIN_TYPEHASH,
    keccak256Bytes(new TextEncoder().encode(RECOVERY_AUTHORITY_DOMAIN_NAME)),
    keccak256Bytes(new TextEncoder().encode(RECOVERY_AUTHORITY_DOMAIN_VERSION)),
    hexToBytes(encodeUint256(chainId)),
    hexToBytes(encodeAddressWord(input.verifyingContract)),
  ]);
  return bytesToHex(keccak256Bytes(encoded));
}

function buildStructHash(input: {
  nearAccountIdHash: `0x${string}`;
  newNearKeyHash: `0x${string}`;
  newOwner: `0x${string}`;
  recoverySessionHash: `0x${string}`;
  nonce: `0x${string}`;
  deadline: `0x${string}`;
}): `0x${string}` {
  const encoded = concatBytes([
    RECOVERY_TYPEHASH,
    hexToBytes(input.nearAccountIdHash),
    hexToBytes(input.newNearKeyHash),
    hexToBytes(encodeAddressWord(input.newOwner)),
    hexToBytes(input.recoverySessionHash),
    hexToBytes(input.nonce),
    hexToBytes(input.deadline),
  ]);
  return bytesToHex(keccak256Bytes(encoded));
}

export function deriveRecoveryAuthorityAuthorizationNonce(input: {
  chainId: number;
  verifyingContract: string;
  recoverySessionId: string;
}): `0x${string}` {
  const chainId = Math.floor(Number(input.chainId));
  if (!Number.isFinite(chainId) || chainId <= 0) {
    throw new Error('Invalid chainId for recovery authorization');
  }
  const verifyingContract = assertAddress(input.verifyingContract, 'verifyingContract');
  const recoverySessionId = toOptionalTrimmedString(input.recoverySessionId);
  if (!recoverySessionId) {
    throw new Error('Invalid recoverySessionId');
  }
  return utf8KeccakHex(
    [
      'recovery-authority',
      String(chainId),
      verifyingContract,
      recoverySessionId,
    ].join(':'),
  );
}

export function buildRecoveryAuthorityAuthorizationDigest(input: {
  contractMethod?: RecoveryAuthorityContractMethod;
  chainId: number;
  verifyingContract: string;
  nearAccountId: string;
  newNearPublicKey: string;
  newOwnerAddress: string;
  recoverySessionId: string;
  deadlineEpochSeconds: number;
}): Omit<RecoveryAuthorityAuthorization, 'authorityAddress' | 'signature'> {
  const contractMethod = input.contractMethod || 'verifyAndRecover';
  const verifyingContract = assertAddress(input.verifyingContract, 'verifyingContract');
  const newOwner = assertAddress(input.newOwnerAddress, 'newOwnerAddress');
  const recoverySessionId = toOptionalTrimmedString(input.recoverySessionId);
  const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
  const newNearPublicKey = toOptionalTrimmedString(input.newNearPublicKey);
  const deadlineEpochSeconds = Math.floor(Number(input.deadlineEpochSeconds));
  if (!recoverySessionId || !nearAccountId || !newNearPublicKey || deadlineEpochSeconds <= 0) {
    throw new Error('Invalid recovery authorization payload');
  }

  const nearAccountIdHash = utf8KeccakHex(nearAccountId);
  const newNearKeyHash = utf8KeccakHex(newNearPublicKey);
  const recoverySessionHash = utf8KeccakHex(recoverySessionId);
  const nonce = deriveRecoveryAuthorityAuthorizationNonce({
    chainId: input.chainId,
    verifyingContract,
    recoverySessionId,
  });
  const deadline = encodeUint256(BigInt(deadlineEpochSeconds));
  const domain = {
    name: RECOVERY_AUTHORITY_DOMAIN_NAME,
    version: RECOVERY_AUTHORITY_DOMAIN_VERSION,
    chainId: Math.floor(Number(input.chainId)),
    verifyingContract,
  } as const;
  const structHash = buildStructHash({
    nearAccountIdHash,
    newNearKeyHash,
    newOwner,
    recoverySessionHash,
    nonce,
    deadline,
  });
  const digest = bytesToHex(
    keccak256Bytes(
      concatBytes([
        Uint8Array.from([0x19, 0x01]),
        hexToBytes(buildDomainSeparator(domain)),
        hexToBytes(structHash),
      ]),
    ),
  );

  return {
    version: 'recovery_authority_authorization_v1',
    contractMethod,
    domain,
    payload: {
      nearAccountIdHash,
      newNearKeyHash,
      newOwner,
      recoverySessionHash,
      nonce: assertHex32(nonce, 'nonce'),
      deadline: assertHex32(deadline, 'deadline'),
    },
    digest,
  };
}

export async function signRecoveryAuthorityAuthorization(input: {
  authorityPrivateKeyHex: `0x${string}`;
  authorityAddress: string;
  authorization: Omit<RecoveryAuthorityAuthorization, 'authorityAddress' | 'signature'>;
}): Promise<RecoveryAuthorityAuthorization> {
  const authorityAddress = assertAddress(input.authorityAddress, 'authorityAddress');
  const digestBytes = hexToBytes(assertHex32(input.authorization.digest, 'digest'));
  const signature65 = await signSecp256k1Recoverable(
    digestBytes,
    privateKeyHexToBytes(input.authorityPrivateKeyHex),
  );
  return {
    ...input.authorization,
    authorityAddress,
    signature: bytesToHex(signature65),
  };
}

export function encodeRecoveryAuthorityCalldata(
  authorization: RecoveryAuthorityAuthorization,
): `0x${string}` {
  const selector = getRecoveryAuthorityFunctionSelector(authorization.contractMethod);
  const signatureWord = encodeDynamicBytesWord(authorization.signature);
  const head = [
    authorization.payload.nearAccountIdHash,
    authorization.payload.newNearKeyHash,
    encodeAddressWord(authorization.payload.newOwner),
    authorization.payload.recoverySessionHash,
    authorization.payload.nonce,
    authorization.payload.deadline,
    encodeUint256(224n),
  ];
  return `0x${strip0x(selector)}${head.map((entry) => strip0x(entry)).join('')}${strip0x(signatureWord)}` as `0x${string}`;
}

export function getRecoveryAuthorityFunctionSelector(
  method: RecoveryAuthorityContractMethod,
): `0x${string}` {
  return getTatchiSmartAccountMethodSelector(method);
}

export function getRecoveryAuthorityFunctionSignature(
  method: RecoveryAuthorityContractMethod,
): string {
  return signatureForMethod(method);
}
