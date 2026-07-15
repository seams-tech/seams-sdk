import type { ResolvedRouterAbEd25519WalletSessionState } from './routerAbEd25519WalletSessionState';

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

const publicStateExcludesRuntimeSecrets: PublicStateExcludesRuntimeSecrets = true;
void publicStateExcludesRuntimeSecrets;
