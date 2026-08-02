import {
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  type RouterAbEcdsaDerivationWalletSessionClaims,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { RuntimePolicyScope } from '../../../packages/shared-ts/src/threshold/signingRootScope';
import type { RouterAbEcdsaDerivationNormalSigningScopeV1 } from '../../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1 } from '../../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '../../../packages/shared-ts/src/utils/sessionTokens';

export type RouterAbEcdsaWalletSessionClaimsFixtureInput = {
  readonly walletId: string;
  readonly keyHandle: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
  readonly thresholdExpiresAtMs: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly normalSigningScope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  readonly walletSessionId?: string;
  readonly authorizationSessionId?: string;
  readonly quotaId?: string;
  readonly thresholdSessionId?: string;
};

export function buildRouterAbEcdsaWalletSessionClaimsFixture(
  input: RouterAbEcdsaWalletSessionClaimsFixtureInput,
): RouterAbEcdsaDerivationWalletSessionClaims {
  const claims = parseRouterAbEcdsaDerivationWalletSessionClaims({
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    sub: input.walletId,
    walletId: input.walletId,
    thresholdSessionId: input.thresholdSessionId ?? 'threshold-session-fixture',
    authorizationSessionId:
      input.authorizationSessionId ?? 'authorization-session-fixture',
    walletSessionId: input.walletSessionId ?? 'wallet-session-fixture',
    quotaId: input.quotaId ?? 'wallet-quota-fixture',
    keyScope: 'evm-family',
    keyHandle: input.keyHandle,
    relayerKeyId: input.relayerKeyId,
    runtimePolicyScope: input.runtimePolicyScope,
    thresholdExpiresAtMs: input.thresholdExpiresAtMs,
    participantIds: Array.from(input.participantIds),
    routerAbEcdsaDerivationNormalSigning: {
      kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
      scope: input.normalSigningScope,
    },
  });
  if (!claims) throw new Error('ECDSA Wallet Session claims fixture is invalid');
  return claims;
}
