export {
  type NearClient,
  MinimalNearClient,
  encodeSignedTransactionBase64,
} from './core/rpcClients/near/NearClient';
export {
  createEvmClient,
  parseRpcHexQuantity as parseEvmRpcHexQuantity,
  type EvmClient,
  type EvmTransactionReceipt,
  type EvmBlockHeader,
  type EvmJsonRpcError,
  type WaitForEvmTransactionReceiptArgs,
} from './core/rpcClients/evm/EvmClient';
export { base64UrlEncode, base64UrlDecode } from '@shared/utils/encoders';
export { keccak256Bytes } from '@shared/utils/keccak';
export { normalizeLowercaseString, normalizeTrimmedString } from '@shared/utils/normalize';
export {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
export { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
export { createIntentId } from './core/idempotency/createIntentId';
export {
  TEMPO_FEE_MANAGER_CONTRACT,
  TEMPO_FEE_MANAGER_ABI,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_SET_USER_TOKEN_SELECTOR,
  TEMPO_USER_TOKENS_SELECTOR,
  TEMPO_TOKEN_CURRENCY_SELECTOR,
  TEMPO_TOKEN_PAUSED_SELECTOR,
  encodeTempoSetUserTokenCalldata,
  encodeTempoUserTokensCalldata,
  decodeTempoUserTokenResult,
  buildTempoSetUserTokenCall,
  buildTempoSetUserTokenRequest,
  readTempoFeeTokenPreference,
  validateTempoFeeToken,
  type TempoFeeTokenValidation,
} from './core/signingEngine/chains/tempo/feeToken';
export {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromConfig,
  walletSessionRefFromSession,
  toWalletId,
  walletIdFromWalletProfile,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
export type {
  EcdsaCommandSubject,
  NearAccountRef,
  NearCommandSubject,
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
