import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

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
  readonly authorizationId: string;
  readonly walletSessionId: string;
  readonly quotaId: string;
  readonly thresholdSessionId: string;
};

export type RouterAbEd25519WalletSessionClaimsFixture = {
  readonly sub: string;
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly thresholdSessionId: string;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
  readonly thresholdExpiresAtMs: number;
  readonly authority: WalletAuthAuthority;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

export function buildRouterAbEd25519WalletSessionClaimsFixture(
  input: RouterAbEd25519WalletSessionClaimsFixtureInput,
): RouterAbEd25519WalletSessionClaimsFixture {
  const walletId = required(parseWalletId(input.walletId));
  const authorizationId = required(parseWalletSessionAuthorizationId(input.authorizationId));
  const walletSessionId = required(parseWalletSessionId(input.walletSessionId));
  const quotaId = required(parseMpcWalletSigningQuotaId(input.quotaId));
  return {
    sub: String(walletId),
    walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    thresholdSessionId: input.thresholdSessionId,
    authorizationId,
    walletSessionId,
    quotaId,
    relayerKeyId: input.relayerKeyId,
    participantIds: Array.from(input.participantIds),
    thresholdExpiresAtMs: input.thresholdExpiresAtMs,
    authority: input.authority,
    runtimePolicyScope: input.runtimePolicyScope,
    routerAbNormalSigning: input.normalSigning,
  };
}
