import type { OpaqueOwnerWalletSessionBinding } from '../../../packages/wallet-server/src/authorization/service';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityBindingDigest,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  type WalletId,
} from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RouterAbEcdsaDerivationNormalSigningScopeV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

type EcdsaWalletSessionBinding = Extract<
  OpaqueOwnerWalletSessionBinding,
  { readonly curve: 'ecdsa' }
>;

export type RouterAbEcdsaWalletSessionClaimsFixtureInput = {
  readonly walletId: string;
  readonly keyHandle: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
  readonly thresholdExpiresAtMs: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly normalSigningScope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  readonly authorizationId?: string;
  readonly walletSessionId?: string;
  readonly authorizationSessionId?: string;
  readonly quotaId?: string;
  readonly thresholdSessionId?: string;
  readonly authSource?: EcdsaWalletSessionBinding['authSource'];
  readonly walletAuthAuthorityRef?: WalletAuthAuthorityRef;
};

export type RouterAbEcdsaWalletSessionClaimsFixture = EcdsaWalletSessionBinding & {
  readonly sub: string;
};

const FIXTURE_DIGEST: DigestB64u = parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE');

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function defaultAuthorityRef(walletId: WalletId): WalletAuthAuthorityRef {
  return {
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: required(parseWalletAuthorityBindingDigest('authority-digest-fixture')),
    walletAuthMethodId: required(parseWalletAuthMethodId(`passkey:${String(walletId)}:fixture`)),
  };
}

export function buildRouterAbEcdsaWalletSessionClaimsFixture(
  input: RouterAbEcdsaWalletSessionClaimsFixtureInput,
): RouterAbEcdsaWalletSessionClaimsFixture {
  const walletId = required(parseWalletId(input.walletId));
  const authorizationId = required(
    parseWalletSessionAuthorizationId(input.authorizationId ?? 'authorization-grant-ecdsa-fixture'),
  );
  const walletSessionId = required(
    parseWalletSessionId(input.walletSessionId ?? 'wallet-session-fixture'),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId(input.quotaId ?? 'wallet-quota-fixture'));
  const authorizationSessionId = input.authorizationSessionId ?? 'authorization-session-fixture';
  const authorityRef = input.walletAuthAuthorityRef ?? defaultAuthorityRef(walletId);
  const authSource = input.authSource ?? {
    kind: 'passkey' as const,
    credentialIdB64u: required(parseWebAuthnCredentialIdB64u('credential-fixture')),
  };
  const subjectId =
    authSource.kind === 'oidc_provider' ? String(authSource.providerSubject) : String(walletId);
  return {
    kind: 'opaque_owner_wallet_session_binding_v1',
    curve: 'ecdsa',
    walletId,
    thresholdSessionId: input.thresholdSessionId ?? 'threshold-session-fixture',
    authorizationId,
    authorizationSessionId,
    walletSessionId,
    quotaId,
    relayerKeyId: input.relayerKeyId,
    participantIds: Array.from(input.participantIds),
    thresholdExpiresAtMs: input.thresholdExpiresAtMs,
    subjectId,
    keyManifestDigestB64u: FIXTURE_DIGEST,
    keyHandle: input.keyHandle,
    walletAuthAuthorityRef: authorityRef,
    authSource,
    runtimePolicyScope: input.runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: {
      kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
      scope: input.normalSigningScope,
    },
    sub: subjectId,
  };
}
