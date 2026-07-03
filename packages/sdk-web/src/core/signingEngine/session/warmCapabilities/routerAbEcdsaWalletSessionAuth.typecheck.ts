import type {
  RouterAbEcdsaWalletSessionAuthReady,
  RouterAbEcdsaWalletSessionAuthResolution,
} from './routerAbEcdsaWalletSessionAuth';

const validRecordBackedAuth = {
  kind: 'ready',
  walletSessionJwt: 'wallet-session-jwt',
  source: 'record',
} satisfies RouterAbEcdsaWalletSessionAuthReady;
void validRecordBackedAuth;

const invalidWarmCapabilityAuthSource = {
  kind: 'ready',
  walletSessionJwt: 'wallet-session-jwt',
  // @ts-expect-error ECDSA wallet-session auth resolution is single-record only.
  source: 'warm_capability',
} satisfies RouterAbEcdsaWalletSessionAuthResolution;
void invalidWarmCapabilityAuthSource;
