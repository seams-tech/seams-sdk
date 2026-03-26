import { keccak256Bytes } from '@shared/utils/keccak';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import smartAccountMetadata from '../../../contracts/evm-smart-account/abi/TatchiSmartAccount.metadata.json' with { type: 'json' };
import smartAccountFactoryMetadata from '../../../contracts/evm-smart-account/abi/TatchiSmartAccountFactory.metadata.json' with { type: 'json' };
import type { CanonicalSmartAccountDeploymentManifest } from './smartAccountDeploymentManifest';
import { normalizeSmartAccountHexLike } from './smartAccountRegistrationRecords';

const ZERO_ADDRESS = `0x${'00'.repeat(20)}` as `0x${string}`;
const CREATE_ACCOUNT_SIGNATURE = 'createAccount(bytes32,bytes)' as const;

export type CanonicalEvmSmartAccountDeploymentPlan = {
  version: 'evm_smart_account_deployment_plan_v1';
  factory: `0x${string}`;
  salt: `0x${string}`;
  initData: `0x${string}`;
  initDataHash: `0x${string}`;
  deploymentSalt: `0x${string}`;
  accountCreationCodeHash: `0x${string}`;
  predictedAddress: `0x${string}`;
  matchesAccountAddress: boolean;
  createAccountCalldata: `0x${string}`;
};

function strip0x(value: `0x${string}`): string {
  return value.slice(2);
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`;
}

function hexToBytes(value: `0x${string}`): Uint8Array {
  const normalized = strip0x(value).toLowerCase();
  if (normalized.length % 2 !== 0 || /[^0-9a-f]/.test(normalized)) {
    throw new Error(`Invalid hex value: ${value}`);
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    out[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return out;
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

function concatHex(parts: `0x${string}`[]): `0x${string}` {
  return `0x${parts.map((part) => strip0x(part)).join('')}` as `0x${string}`;
}

function normalizeAddress(value: unknown): `0x${string}` | '' {
  const normalized = normalizeSmartAccountHexLike(value);
  return /^0x[0-9a-f]{40}$/.test(normalized) ? (normalized as `0x${string}`) : '';
}

function normalizeBytes32(value: unknown, options?: { allowShort?: boolean }): `0x${string}` | '' {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  if (!normalized.startsWith('0x')) return '';
  const raw = normalized.slice(2);
  if (!raw || raw.length > 64 || raw.length % 2 !== 0 || /[^0-9a-f]/.test(raw)) return '';
  if (!options?.allowShort && raw.length !== 64) return '';
  return `0x${raw.padStart(64, '0')}` as `0x${string}`;
}

function normalizeOwnerAddresses(values: unknown): `0x${string}`[] {
  if (!Array.isArray(values)) return [];
  return values.map((value) => normalizeAddress(value)).filter(Boolean) as `0x${string}`[];
}

function assertHex4(value: unknown): `0x${string}` {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  if (!/^0x[0-9a-f]{8}$/.test(normalized)) {
    throw new Error('Invalid factory selector metadata');
  }
  return normalized as `0x${string}`;
}

function assertHex32(value: unknown): `0x${string}` {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new Error('Invalid account creation code hash metadata');
  }
  return normalized as `0x${string}`;
}

function encodeSmartAccountInitData(input: {
  nearAccountIdHash: `0x${string}`;
  recoveryAuthority: `0x${string}`;
  entryPoint: `0x${string}`;
  owners: `0x${string}`[];
}): `0x${string}` {
  const ownersHeadOffset = encodeUint256(128n);
  const ownersTail = concatHex([
    encodeUint256(BigInt(input.owners.length)),
    ...input.owners.map((owner) => encodeAddressWord(owner)),
  ]);
  return concatHex([
    input.nearAccountIdHash,
    encodeAddressWord(input.recoveryAuthority),
    encodeAddressWord(input.entryPoint),
    ownersHeadOffset,
    ownersTail,
  ]);
}

function encodeCreateAccountCalldata(input: {
  selector: `0x${string}`;
  salt: `0x${string}`;
  initData: `0x${string}`;
}): `0x${string}` {
  const encodedArgs = concatHex([
    input.salt,
    encodeUint256(64n),
    encodeDynamicBytesWord(input.initData),
  ]);
  return `0x${strip0x(input.selector)}${strip0x(encodedArgs)}` as `0x${string}`;
}

const ACCOUNT_CREATION_CODE_HASH = assertHex32(
  (smartAccountMetadata as { bytecodeHash?: unknown }).bytecodeHash,
);
const CREATE_ACCOUNT_SELECTOR = assertHex4(
  (
    smartAccountFactoryMetadata as {
      methodIdentifiers?: Record<string, unknown>;
    }
  ).methodIdentifiers?.[CREATE_ACCOUNT_SIGNATURE],
);

export function buildCanonicalEvmSmartAccountDeploymentPlan(
  manifest: CanonicalSmartAccountDeploymentManifest,
): CanonicalEvmSmartAccountDeploymentPlan | null {
  if (manifest.chain !== 'evm' || manifest.accountModel !== 'erc4337') return null;

  const factory = normalizeAddress(manifest.factory);
  const salt = normalizeBytes32(manifest.salt, { allowShort: true });
  const nearAccountIdHash = normalizeBytes32(manifest.nearAccountIdHash);
  const recoveryAuthority = normalizeAddress(manifest.recoveryAuthority);
  const entryPoint = normalizeAddress(manifest.entryPoint) || ZERO_ADDRESS;
  const owners = normalizeOwnerAddresses(manifest.ownerAddresses);
  const accountAddress = normalizeAddress(manifest.accountAddress);

  if (!factory || !salt || !nearAccountIdHash || !recoveryAuthority || owners.length === 0) {
    return null;
  }

  const initData = encodeSmartAccountInitData({
    nearAccountIdHash,
    recoveryAuthority,
    entryPoint,
    owners,
  });
  const initDataHash = bytesToHex(keccak256Bytes(hexToBytes(initData)));
  const deploymentSalt = bytesToHex(
    keccak256Bytes(concatBytes([hexToBytes(salt), hexToBytes(initDataHash)])),
  );
  const predictedAddress = `0x${strip0x(
    bytesToHex(
      keccak256Bytes(
        concatBytes([
          Uint8Array.from([0xff]),
          hexToBytes(factory),
          hexToBytes(deploymentSalt),
          hexToBytes(ACCOUNT_CREATION_CODE_HASH),
        ]),
      ),
    ),
  ).slice(-40)}` as `0x${string}`;

  return {
    version: 'evm_smart_account_deployment_plan_v1',
    factory,
    salt,
    initData,
    initDataHash,
    deploymentSalt,
    accountCreationCodeHash: ACCOUNT_CREATION_CODE_HASH,
    predictedAddress,
    matchesAccountAddress: !!accountAddress && predictedAddress === accountAddress,
    createAccountCalldata: encodeCreateAccountCalldata({
      selector: CREATE_ACCOUNT_SELECTOR,
      salt,
      initData,
    }),
  };
}
