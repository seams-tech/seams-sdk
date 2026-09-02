import type {
  EvmAddress,
  EvmContractAbi,
  Eip1559UnsignedTx,
  EvmSigningRequest,
  Hex,
} from '../evm/evmSigning.types';
import type { TempoCall } from './tempoSigning.types';
import { createEvmClient } from '@/core/rpcClients/evm/EvmClient';
import type { TempoChainTarget } from '@/core/platform/types';

const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const ABI_WORD_HEX_LENGTH = 64;
const ABI_ADDRESS_WORD_OFFSET = 24;

/**
 * Tempo fee manager predeploy contract.
 * Ref: https://docs.tempo.xyz/evm/predeployed-contracts
 */
export const TEMPO_FEE_MANAGER_CONTRACT: EvmAddress = '0xfeec000000000000000000000000000000000000';

/**
 * setUserToken(address) selector
 */
export const TEMPO_SET_USER_TOKEN_SELECTOR: Hex = '0xe7897444';

/**
 * userTokens(address) selector
 */
export const TEMPO_USER_TOKENS_SELECTOR: Hex = '0xed498fa8';

export const TEMPO_TOKEN_CURRENCY_SELECTOR: Hex = '0xe5a6b10f';

export const TEMPO_TOKEN_PAUSED_SELECTOR: Hex = '0x5c975abb';

/**
 * AlphaUSD token on Tempo.
 */
export const TEMPO_ALPHA_USD_FEE_TOKEN: EvmAddress = '0x20c0000000000000000000000000000000000001';

export const TEMPO_FEE_MANAGER_ABI: EvmContractAbi = [
  {
    type: 'function',
    name: 'setUserToken',
    inputs: [{ name: 'token', type: 'address' }],
  },
];

export type TempoFeeTokenPreferenceSigningRequest = Omit<EvmSigningRequest, 'tx'> & {
  tx: Omit<Eip1559UnsignedTx, 'to' | 'value' | 'data'> & {
    to: typeof TEMPO_FEE_MANAGER_CONTRACT;
    value: 0n;
    data: Hex;
  };
};

export function parseTempoEvmAddress(label: string, value: unknown): EvmAddress {
  const normalized = String(value || '').trim();
  if (!EVM_ADDRESS_RE.test(normalized)) {
    throw new Error(`[tempo] invalid ${label}: expected 20-byte 0x-prefixed address`);
  }
  return normalized.toLowerCase() as EvmAddress;
}

export function encodeTempoSetUserTokenCalldata(token: EvmAddress): Hex {
  const normalizedToken = parseTempoEvmAddress('fee token address', token).slice(2).toLowerCase();
  const tokenWord = normalizedToken.padStart(ABI_WORD_HEX_LENGTH, '0');
  return `${TEMPO_SET_USER_TOKEN_SELECTOR}${tokenWord}` as Hex;
}

export function requireTempoFeeTokenPreferenceSigningRequest(args: {
  request: EvmSigningRequest;
  chainTarget: TempoChainTarget;
}): TempoFeeTokenPreferenceSigningRequest {
  const { request, chainTarget } = args;
  if (
    request.chain !== 'evm' ||
    request.kind !== 'eip1559' ||
    request.senderSignatureAlgorithm !== 'secp256k1'
  ) {
    throw new Error('[tempo] fee-token request must use the EIP-1559 secp256k1 envelope');
  }
  if (request.tx.chainId !== chainTarget.chainId) {
    throw new Error('[tempo] fee-token request chain id does not match the Tempo target');
  }
  if (request.tx.to?.toLowerCase() !== TEMPO_FEE_MANAGER_CONTRACT) {
    throw new Error('[tempo] fee-token request must call the Tempo FeeManager');
  }
  if (request.tx.value !== 0n) {
    throw new Error('[tempo] fee-token request must not transfer value');
  }
  const data = String(request.tx.data ?? '').toLowerCase();
  const encodedToken = data.slice(TEMPO_SET_USER_TOKEN_SELECTOR.length);
  if (
    !data.startsWith(TEMPO_SET_USER_TOKEN_SELECTOR) ||
    !/^0{24}[0-9a-f]{40}$/.test(encodedToken)
  ) {
    throw new Error('[tempo] fee-token request must call FeeManager.setUserToken(address)');
  }
  if (request.tx.accessList && request.tx.accessList.length !== 0) {
    throw new Error('[tempo] fee-token request must not carry an access list');
  }
  const feeToken = parseTempoEvmAddress('fee token address', `0x${encodedToken.slice(24)}`);
  return {
    ...request,
    tx: {
      ...request.tx,
      to: TEMPO_FEE_MANAGER_CONTRACT,
      value: 0n,
      data: encodeTempoSetUserTokenCalldata(feeToken),
    },
  };
}

export function encodeTempoUserTokensCalldata(user: EvmAddress): Hex {
  const normalizedUser = parseTempoEvmAddress('user address', user).slice(2).toLowerCase();
  const userWord = normalizedUser.padStart(ABI_WORD_HEX_LENGTH, '0');
  return `${TEMPO_USER_TOKENS_SELECTOR}${userWord}` as Hex;
}

export function decodeTempoUserTokenResult(resultHex: string): EvmAddress | null {
  const normalized = String(resultHex || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]*$/.test(normalized)) {
    throw new Error('[tempo] invalid userTokens(address) result: expected 0x-prefixed hex');
  }

  const hex = normalized.slice(2);
  if (hex.length < ABI_WORD_HEX_LENGTH) {
    throw new Error('[tempo] invalid userTokens(address) result: expected at least 32 bytes');
  }

  const firstWord = hex.slice(0, ABI_WORD_HEX_LENGTH);
  const addressHex = firstWord.slice(ABI_ADDRESS_WORD_OFFSET);
  if (!/^[0-9a-f]{40}$/.test(addressHex)) {
    throw new Error('[tempo] invalid userTokens(address) result: malformed address word');
  }
  if (/^0+$/.test(addressHex)) return null;
  return `0x${addressHex}` as EvmAddress;
}

export function buildTempoSetUserTokenCall(args: {
  token: EvmAddress;
  feeManager?: EvmAddress;
}): TempoCall {
  const token = parseTempoEvmAddress('fee token address', args.token);
  const feeManager = parseTempoEvmAddress(
    'fee manager contract address',
    args.feeManager ?? TEMPO_FEE_MANAGER_CONTRACT,
  );

  return {
    to: feeManager,
    value: 0n,
    input: encodeTempoSetUserTokenCalldata(token),
    abi: TEMPO_FEE_MANAGER_ABI,
  };
}

function decodeAbiString(resultHex: string, label: string): string {
  const normalized = String(resultHex || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(normalized)) {
    throw new Error(`[tempo] invalid ${label} result: expected 0x-prefixed hex`);
  }
  const hex = normalized.slice(2);
  if (hex.length < ABI_WORD_HEX_LENGTH * 2) {
    throw new Error(`[tempo] invalid ${label} result: missing ABI string header`);
  }
  const offset = Number(BigInt(`0x${hex.slice(0, ABI_WORD_HEX_LENGTH)}`));
  if (!Number.isSafeInteger(offset)) {
    throw new Error(`[tempo] invalid ${label} result: unsafe ABI offset`);
  }
  const lengthStart = offset * 2;
  const lengthEnd = lengthStart + ABI_WORD_HEX_LENGTH;
  if (lengthEnd > hex.length) {
    throw new Error(`[tempo] invalid ${label} result: ABI offset out of bounds`);
  }
  const byteLength = Number(BigInt(`0x${hex.slice(lengthStart, lengthEnd)}`));
  if (!Number.isSafeInteger(byteLength)) {
    throw new Error(`[tempo] invalid ${label} result: unsafe ABI string length`);
  }
  const dataStart = lengthEnd;
  const dataEnd = dataStart + byteLength * 2;
  if (dataEnd > hex.length) {
    throw new Error(`[tempo] invalid ${label} result: ABI string out of bounds`);
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(dataStart + index * 2, dataStart + index * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

function decodeAbiBool(resultHex: string, label: string): boolean {
  const normalized = String(resultHex || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`[tempo] invalid ${label} result: expected one ABI word`);
  }
  const value = BigInt(normalized);
  if (value !== 0n && value !== 1n) {
    throw new Error(`[tempo] invalid ${label} result: expected boolean`);
  }
  return value === 1n;
}

async function callTempoContract(args: {
  rpcUrl: string;
  to: EvmAddress;
  data: Hex;
  timeoutMs?: number;
}): Promise<string> {
  const client = createEvmClient({
    rpcUrl: args.rpcUrl,
    ...(args.timeoutMs !== undefined ? { requestTimeoutMs: args.timeoutMs } : {}),
  });
  const result = await client.request<unknown>({
    method: 'eth_call',
    params: [{ to: args.to, data: args.data }, 'latest'],
    ...(args.timeoutMs !== undefined ? { timeoutMs: args.timeoutMs } : {}),
  });
  if (typeof result !== 'string') {
    throw new Error('[tempo] invalid eth_call response: expected a hex string');
  }
  return result;
}

export async function readTempoFeeTokenPreference(args: {
  rpcUrl: string;
  account: EvmAddress;
  timeoutMs?: number;
}): Promise<EvmAddress | null> {
  const account = parseTempoEvmAddress('account address', args.account);
  const result = await callTempoContract({
    rpcUrl: args.rpcUrl,
    to: TEMPO_FEE_MANAGER_CONTRACT,
    data: encodeTempoUserTokensCalldata(account),
    ...(args.timeoutMs !== undefined ? { timeoutMs: args.timeoutMs } : {}),
  });
  return decodeTempoUserTokenResult(result);
}

export type TempoFeeTokenValidation =
  | { kind: 'valid'; feeToken: EvmAddress; currency: 'USD'; paused: false }
  | {
      kind: 'invalid';
      feeToken: EvmAddress;
      reason: 'unsupported_currency';
      currency: string;
    }
  | { kind: 'invalid'; feeToken: EvmAddress; reason: 'paused'; currency: 'USD' };

export async function validateTempoFeeToken(args: {
  rpcUrl: string;
  feeToken: EvmAddress;
  timeoutMs?: number;
}): Promise<TempoFeeTokenValidation> {
  const feeToken = parseTempoEvmAddress('fee token address', args.feeToken);
  const callArgs = {
    rpcUrl: args.rpcUrl,
    to: feeToken,
    ...(args.timeoutMs !== undefined ? { timeoutMs: args.timeoutMs } : {}),
  };
  const currency = decodeAbiString(
    await callTempoContract({ ...callArgs, data: TEMPO_TOKEN_CURRENCY_SELECTOR }),
    'currency()',
  );
  if (currency !== 'USD') {
    return { kind: 'invalid', feeToken, reason: 'unsupported_currency', currency };
  }
  const pausedResult = await callTempoContract({
    ...callArgs,
    data: TEMPO_TOKEN_PAUSED_SELECTOR,
  });
  if (decodeAbiBool(pausedResult, 'paused()')) {
    return { kind: 'invalid', feeToken, reason: 'paused', currency: 'USD' };
  }
  return { kind: 'valid', feeToken, currency: 'USD', paused: false };
}

export function buildTempoSetUserTokenRequest(args: {
  chainId: number;
  feeToken: EvmAddress;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
}): TempoFeeTokenPreferenceSigningRequest {
  if (!Number.isSafeInteger(args.chainId) || args.chainId <= 0) {
    throw new Error('[tempo] chainId must be a positive safe integer');
  }
  if (args.maxPriorityFeePerGas < 0n) {
    throw new Error('[tempo] maxPriorityFeePerGas must be non-negative');
  }
  if (args.maxFeePerGas < args.maxPriorityFeePerGas) {
    throw new Error('[tempo] maxFeePerGas must be at least maxPriorityFeePerGas');
  }
  if (args.gasLimit <= 0n) {
    throw new Error('[tempo] gasLimit must be positive');
  }
  const call = buildTempoSetUserTokenCall({ token: args.feeToken });
  return {
    chain: 'evm',
    kind: 'eip1559',
    senderSignatureAlgorithm: 'secp256k1',
    tx: {
      chainId: args.chainId,
      maxPriorityFeePerGas: args.maxPriorityFeePerGas,
      maxFeePerGas: args.maxFeePerGas,
      gasLimit: args.gasLimit,
      to: call.to,
      value: 0n,
      data: call.input ?? '0x',
      abi: call.abi,
      accessList: [],
    },
  };
}
