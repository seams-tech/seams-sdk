import type {
  resolveActiveAuthorizedRouterAbEd25519WalletSessionState,
  ResolvedRouterAbEd25519WalletSessionState,
} from './routerAbEd25519WalletSessionState';
import type { ExactWalletSessionReadPorts } from '../identity/exactWalletSessionCredential';

type Assert<T extends true> = T;
type IsNever<T> = [T] extends [never] ? true : false;
type ForbiddenStateKey = Extract<
  keyof ResolvedRouterAbEd25519WalletSessionState,
  | 'activeClient'
  | 'signingMaterial'
  | 'persistSigningMaterial'
  | 'restoreSigningMaterial'
  | 'refreshSigningMaterial'
>;

type PublicStateExcludesRuntimeSecrets = Assert<IsNever<ForbiddenStateKey>>;
type ResolveActiveAuthorizationInput = Parameters<
  typeof resolveActiveAuthorizedRouterAbEd25519WalletSessionState
>[0];
type ResolveActiveAuthorizationRequiresReadPorts = Assert<
  ResolveActiveAuthorizationInput extends { ports: ExactWalletSessionReadPorts } ? true : false
>;

const publicStateExcludesRuntimeSecrets: PublicStateExcludesRuntimeSecrets = true;
const resolveActiveAuthorizationRequiresReadPorts: ResolveActiveAuthorizationRequiresReadPorts = true;
void publicStateExcludesRuntimeSecrets;
void resolveActiveAuthorizationRequiresReadPorts;
