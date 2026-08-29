import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parseReusableWalletSessionMintId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type PrincipalId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  type IssuedWalletSessionAuthorizationV2,
} from '../../../packages/wallet-server/src/authorization/domain';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function buildExactWalletSessionAuthorizationFixture(input: {
  readonly label: string;
  readonly walletSessionLabel?: string;
  readonly authorizationLabel?: string;
  readonly quotaLabel?: string;
  readonly mintLabel?: string;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly authority: ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
}): IssuedWalletSessionAuthorizationV2 {
  const walletSessionId = required(
    parseWalletSessionId(`wallet-session:${input.walletSessionLabel ?? input.label}`),
  );
  const quotaId = required(
    parseMpcWalletSigningQuotaId(`quota:${input.quotaLabel ?? input.label}`),
  );
  const session = buildWalletSessionAuthorizationV2({
    tenantId: input.tenantId,
    principalId: input.principalId,
    walletId: input.authority.walletId,
    authorityId: input.authority.authorityId,
    walletAuthMethodId: input.walletAuthMethodId,
    authorityDigestB64u: input.authority.authorityDigestB64u,
    authorityRevocationEpoch: input.authority.revocationEpoch,
    mintId: required(parseReusableWalletSessionMintId(`mint:${input.mintLabel ?? input.label}`)),
    authorizationId: required(
      parseWalletSessionAuthorizationId(`authorization:${input.authorizationLabel ?? input.label}`),
    ),
    walletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
    createdAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  return {
    session,
    quota: buildActiveWalletSessionQuota({
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletSessionId,
      quotaId,
      remainingUses: input.remainingUses,
      expiresAtMs: input.expiresAtMs,
    }),
  };
}
