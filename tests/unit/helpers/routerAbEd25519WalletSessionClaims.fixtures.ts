import type { OpaqueOwnerWalletSessionBinding } from '../../../packages/wallet-server/src/authorization/service';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletId } from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../../packages/wallet-server/src/core/ThresholdService/validation';

type Ed25519WalletSessionBinding = Extract<
  OpaqueOwnerWalletSessionBinding,
  { readonly curve: 'ed25519' }
>;

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

export type RouterAbEd25519WalletSessionClaimsFixture = Ed25519WalletSessionBinding & {
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

export function buildRouterAbEd25519WalletSessionClaimsFixture(
  input: RouterAbEd25519WalletSessionClaimsFixtureInput,
): RouterAbEd25519WalletSessionClaimsFixture {
  const walletId = required(parseWalletId(input.walletId));
  const authorizationId = required(
    parseWalletSessionAuthorizationId(
      input.authorizationId ?? 'authorization-grant-ed25519-fixture',
    ),
  );
  const walletSessionId = required(
    parseWalletSessionId(input.walletSessionId ?? 'wallet-session-fixture'),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId(input.quotaId ?? 'wallet-quota-fixture'));
  const subjectId =
    input.authority.factor.kind === 'email_otp'
      ? String(input.authority.factor.providerUserId)
      : String(walletId);
  return {
    kind: 'opaque_owner_wallet_session_binding_v1',
    curve: 'ed25519',
    walletId,
    thresholdSessionId: input.thresholdSessionId ?? 'threshold-ed25519-session-fixture',
    authorizationId,
    walletSessionId,
    quotaId,
    relayerKeyId: input.relayerKeyId,
    participantIds: Array.from(input.participantIds),
    thresholdExpiresAtMs: input.thresholdExpiresAtMs,
    subjectId,
    keyManifestDigestB64u: FIXTURE_DIGEST,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    authority: input.authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(input.authority),
    runtimePolicyScope: input.runtimePolicyScope,
    routerAbNormalSigning: input.normalSigning,
    sub: subjectId,
  };
}
