import type {
  RouterAbEd25519YaoWalletSessionCredentialV1,
  RouterAbEd25519YaoWalletSessionMintInputV1,
} from '../../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseThresholdEd25519SessionId,
  parseWalletAuthMethodId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/encoders';

export const ROUTER_AB_ED25519_YAO_WALLET_SESSION_FIXTURE_ID = 'wallet-session:projection';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function buildIssuedRouterAbEd25519YaoWalletSessionCredentialFixture(
  walletSessionId: string = ROUTER_AB_ED25519_YAO_WALLET_SESSION_FIXTURE_ID,
): Extract<
  RouterAbEd25519YaoWalletSessionCredentialV1,
  { readonly kind: 'issued_wallet_session_v1' }
> {
  return {
    kind: 'issued_wallet_session_v1',
    operationCredential: parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'A'.repeat(43)}`,
      walletSessionId,
    }),
  };
}

export function buildRouterAbEd25519YaoWalletSessionMintInputFixture(input: {
  readonly walletSessionCredential: RouterAbEd25519YaoWalletSessionCredentialV1;
  readonly walletSessionId?: string;
  readonly expiresAtMs?: number;
}): Extract<
  RouterAbEd25519YaoWalletSessionMintInputV1,
  { readonly kind: 'verified_wallet_unlock_v1' }
> {
  const walletId = walletIdFromString('projection-wallet.testnet');
  return {
    kind: 'verified_wallet_unlock_v1',
    walletSessionCredential: input.walletSessionCredential,
    walletId,
    nearAccountId: 'projection-wallet.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-projection',
    authority: {
      walletId,
      factor: {
        kind: 'passkey',
        credentialIdB64u: required(parseWebAuthnCredentialIdB64u('projection-credential')),
      },
      verifier: {
        kind: 'webauthn',
        rpId: required(parseWebAuthnRpId('example.com')),
      },
      bindingId: required(parseWalletAuthMethodId('wallet-auth-method:projection')),
    },
    thresholdSessionId: required(parseThresholdEd25519SessionId('threshold-session:projection')),
    authorizationId: required(parseWalletSessionAuthorizationId('wallet-authorization:projection')),
    walletSessionId: required(
      parseWalletSessionId(
        input.walletSessionId ?? ROUTER_AB_ED25519_YAO_WALLET_SESSION_FIXTURE_ID,
      ),
    ),
    quotaId: required(parseMpcWalletSigningQuotaId('wallet-quota:projection')),
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-projection',
      projectId: 'project-projection',
      envId: 'env-projection',
      signingRootVersion: 'root-v1',
    },
    keyManifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(5))),
    expiresAtMs: input.expiresAtMs ?? Date.now() + 60_000,
    remainingUses: 3,
  };
}
