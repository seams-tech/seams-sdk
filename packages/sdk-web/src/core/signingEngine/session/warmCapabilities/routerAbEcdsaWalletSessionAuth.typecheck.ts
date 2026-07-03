import type {
  RouterAbEcdsaWalletSessionAuthority,
  RouterAbEcdsaWalletSessionAuthResolution,
} from './routerAbEcdsaWalletSessionAuth';
import type { EcdsaSessionIdentity } from './ecdsaProvisionPlan';

declare const identity: EcdsaSessionIdentity;

const validRecordBackedAuth = {
  kind: 'ready',
  identity,
  walletSessionJwt: 'wallet-session-jwt',
  source: 'record',
} satisfies RouterAbEcdsaWalletSessionAuthority;
void validRecordBackedAuth;

// @ts-expect-error ready ECDSA wallet-session authority carries exact session identity.
const invalidRecordBackedAuthWithoutIdentity: RouterAbEcdsaWalletSessionAuthResolution = {
  kind: 'ready',
  walletSessionJwt: 'wallet-session-jwt',
  source: 'record',
};
void invalidRecordBackedAuthWithoutIdentity;

const invalidWarmCapabilityAuthSource = {
  kind: 'ready',
  identity,
  walletSessionJwt: 'wallet-session-jwt',
  // @ts-expect-error ECDSA wallet-session auth resolution is single-record only.
  source: 'warm_capability',
} satisfies RouterAbEcdsaWalletSessionAuthResolution;
void invalidWarmCapabilityAuthSource;
