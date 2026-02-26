import type { EvmAddress, Hex } from '../evm/types';
import type { TempoCall } from './types';

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

/**
 * AlphaUSD token on Tempo.
 */
export const TEMPO_ALPHA_USD_FEE_TOKEN: EvmAddress = '0x20c0000000000000000000000000000000000001';

function assertEvmAddress(label: string, value: string): EvmAddress {
  const normalized = String(value || '').trim();
  if (!EVM_ADDRESS_RE.test(normalized)) {
    throw new Error(`[tempo] invalid ${label}: expected 20-byte 0x-prefixed address`);
  }
  return normalized as EvmAddress;
}

export function encodeTempoSetUserTokenCalldata(token: EvmAddress): Hex {
  const normalizedToken = assertEvmAddress('fee token address', token).slice(2).toLowerCase();
  const tokenWord = normalizedToken.padStart(ABI_WORD_HEX_LENGTH, '0');
  return `${TEMPO_SET_USER_TOKEN_SELECTOR}${tokenWord}` as Hex;
}

export function encodeTempoUserTokensCalldata(user: EvmAddress): Hex {
  const normalizedUser = assertEvmAddress('user address', user).slice(2).toLowerCase();
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
  const token = assertEvmAddress('fee token address', args.token);
  const feeManager = assertEvmAddress(
    'fee manager contract address',
    args.feeManager ?? TEMPO_FEE_MANAGER_CONTRACT,
  );

  return {
    to: feeManager,
    value: 0n,
    input: encodeTempoSetUserTokenCalldata(token),
  };
}
