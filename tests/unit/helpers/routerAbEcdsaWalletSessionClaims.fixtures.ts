import {
  parseEcdsaAuthorizationSessionId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type EcdsaAuthorizationSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletId,
  type ProviderSubject,
  type WalletId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

type EcdsaWalletSessionAuthSource =
  | { readonly kind: 'passkey'; readonly credentialIdB64u: WebAuthnCredentialIdB64u }
  | {
      readonly kind: 'oidc_provider';
      readonly providerId: 'google_oidc' | 'oidc';
      readonly providerSubject: ProviderSubject;
    };

export type RouterAbEcdsaWalletSessionClaimsFixtureInput = {
  readonly walletId: string;
  readonly keyHandle: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
  readonly thresholdExpiresAtMs: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly normalSigningScope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  readonly authorizationId: string;
  readonly walletSessionId: string;
  readonly authorizationSessionId: string;
  readonly quotaId: string;
  readonly thresholdSessionId: string;
  readonly authSource: EcdsaWalletSessionAuthSource;
  readonly walletAuthAuthorityRef: WalletAuthAuthorityRef;
};

export type RouterAbEcdsaWalletSessionClaimsFixture = {
  readonly sub: string;
  readonly walletId: WalletId;
  readonly keyHandle: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
  readonly thresholdExpiresAtMs: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly authorizationSessionId: EcdsaAuthorizationSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly thresholdSessionId: string;
  readonly authSource: EcdsaWalletSessionAuthSource;
  readonly walletAuthAuthorityRef: WalletAuthAuthorityRef;
  readonly routerAbEcdsaDerivationNormalSigning: {
    readonly kind: typeof ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1;
    readonly scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  };
};

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

export function buildRouterAbEcdsaWalletSessionClaimsFixture(
  input: RouterAbEcdsaWalletSessionClaimsFixtureInput,
): RouterAbEcdsaWalletSessionClaimsFixture {
  const walletId = required(parseWalletId(input.walletId));
  const authorizationId = required(parseWalletSessionAuthorizationId(input.authorizationId));
  const walletSessionId = required(parseWalletSessionId(input.walletSessionId));
  const authorizationSessionId = required(
    parseEcdsaAuthorizationSessionId(input.authorizationSessionId),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId(input.quotaId));
  return {
    sub: String(walletId),
    walletId,
    keyHandle: input.keyHandle,
    relayerKeyId: input.relayerKeyId,
    participantIds: Array.from(input.participantIds),
    thresholdExpiresAtMs: input.thresholdExpiresAtMs,
    runtimePolicyScope: input.runtimePolicyScope,
    thresholdSessionId: input.thresholdSessionId,
    authorizationId,
    walletSessionId,
    authorizationSessionId,
    quotaId,
    authSource: input.authSource,
    walletAuthAuthorityRef: input.walletAuthAuthorityRef,
    routerAbEcdsaDerivationNormalSigning: {
      kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
      scope: input.normalSigningScope,
    },
  };
}
