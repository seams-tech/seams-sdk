import {
  parseRouterAbEd25519WalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  type RouterAbEd25519WalletSessionClaims,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { RuntimePolicyScope } from '../../../packages/shared-ts/src/threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from '../../../packages/shared-ts/src/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '../../../packages/shared-ts/src/utils/sessionTokens';
import type { WalletAuthAuthority } from '../../../packages/shared-ts/src/utils/walletAuthAuthority';

export type RouterAbEd25519WalletSessionClaimsFixtureInput = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
  readonly thresholdExpiresAtMs: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly normalSigning: RouterAbEd25519NormalSigningState;
  readonly authority: WalletAuthAuthority;
  readonly authorizationId?: string;
  readonly walletSessionId?: string;
  readonly quotaId?: string;
  readonly thresholdSessionId?: string;
};

export function buildRouterAbEd25519WalletSessionClaimsFixture(
  input: RouterAbEd25519WalletSessionClaimsFixtureInput,
): RouterAbEd25519WalletSessionClaims {
  const claims = parseRouterAbEd25519WalletSessionClaims({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'owner_wallet_session',
    sub: input.walletId,
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    thresholdSessionId: input.thresholdSessionId ?? 'threshold-ed25519-session-fixture',
    authorizationId: input.authorizationId ?? 'authorization-grant-ed25519-fixture',
    walletSessionId: input.walletSessionId ?? 'wallet-session-fixture',
    quotaId: input.quotaId ?? 'wallet-quota-fixture',
    relayerKeyId: input.relayerKeyId,
    authority: input.authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(input.authority),
    runtimePolicyScope: input.runtimePolicyScope,
    thresholdExpiresAtMs: input.thresholdExpiresAtMs,
    participantIds: Array.from(input.participantIds),
    routerAbNormalSigning: input.normalSigning,
  });
  if (!claims) throw new Error('Ed25519 Wallet Session claims fixture is invalid');
  return claims;
}
