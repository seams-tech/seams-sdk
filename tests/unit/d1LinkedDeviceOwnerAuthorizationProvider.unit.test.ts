import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceApprovalV1,
  buildWalletSessionLinkedDeviceOwnerAuthorizationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  parsePrincipalId,
  parseTenantId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildPasskeyWalletAuthAuthority,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import {
  createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthorizationProvider';
import type {
  ResolvedOpaqueWalletSessionToken,
} from '../../packages/wallet-server/src/authorization/service';
import {
  buildR103AwaitingTargetPasskeySessionRecordV1,
} from './helpers/deviceLinkingServer.fixtures';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  buildRouterAbEd25519WalletSessionClaimsFixture,
} from './helpers/routerAbEd25519WalletSessionClaims.fixtures';

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: { readonly message: string } }): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

test('rebuilds owner context from persisted lane hints and opaque session identity', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:owner-metadata' });
  const tenantId = required(parseTenantId('org-owner-metadata'));
  const ownerAuthority = buildPasskeyWalletAuthAuthority({
    walletId: fixture.approval.walletId,
    rpId: 'owner.example.test',
    credentialIdB64u: 'owner-metadata-credential',
  });
  const binding = buildRouterAbEd25519WalletSessionClaimsFixture({
    walletId: String(fixture.approval.walletId),
    nearAccountId: 'owner-metadata.near',
    nearEd25519SigningKeyId: 'ed25519:owner-metadata',
    relayerKeyId: 'owner-metadata-relayer',
    participantIds: [1, 2],
    thresholdExpiresAtMs: 9_000,
    runtimePolicyScope: {
      orgId: 'org-owner-metadata',
      projectId: 'project-owner-metadata',
      envId: 'env-owner-metadata',
      signingRootVersion: 'owner-metadata-root',
    },
    normalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'owner-metadata-worker',
    },
    authority: ownerAuthority,
    walletSessionId: 'wallet-session:owner-metadata',
    authorizationId: 'wallet-session-authorization:owner-metadata',
    quotaId: 'mpc-wallet-signing-quota:owner-metadata',
  });
  const ownerAuthorization = buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
    walletSessionId: binding.walletSessionId,
    authorizationId: binding.authorizationId,
  });
  const approval = buildLinkedDeviceApprovalV1({
    ...fixture.approval,
    ownerAuthorization,
  });
  const linkedFixture = {
    ...fixture,
    approval,
    packageSetDigestB64u: binding.keyManifestDigestB64u,
  };
  const session = await buildR103AwaitingTargetPasskeySessionRecordV1(linkedFixture);
  const lookupCurves: string[] = [];
  const resolved: ResolvedOpaqueWalletSessionToken = {
    kind: 'resolved_opaque_wallet_session_token',
    curve: 'ed25519',
    binding,
    authorization: {
      tenantId,
      principalId: required(parsePrincipalId('principal:owner-metadata')),
      walletId: binding.walletId,
      authorityDigest: binding.keyManifestDigestB64u,
      walletAuthMethodId: null,
      authorizationId: binding.authorizationId,
      walletSessionId: binding.walletSessionId,
      quotaId: binding.quotaId,
      expiresAtMs: binding.thresholdExpiresAtMs,
    },
  };
  const metadata = createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1({
    tenantId,
    sessionStore: {
      getSessionV1: async () => session,
    },
    authorizationStore: {
      readOpaqueWalletSessionTokenByIdentity: async (input) => {
        lookupCurves.push(input.curve);
        return input.curve === 'ed25519' ? resolved : null;
      },
    },
    readOwnerSourceChildV1: async () => null,
    nowV1: () => 4_000,
  });

  const owner = await metadata.readApprovedOwnerContextV1({
    walletId: approval.walletId,
    linkSessionId: String(approval.linkSessionId),
  });

  expect(lookupCurves).toEqual(['ed25519']);
  expect(owner).toEqual({
    walletId: approval.walletId,
    walletSessionId: binding.walletSessionId,
    authorizationId: binding.authorizationId,
    expiresAtMs: binding.thresholdExpiresAtMs,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    keyManifestDigestB64u: binding.keyManifestDigestB64u,
    curve: 'ed25519',
    authority: binding.authority,
    authorityScope: binding.authorityScope,
  });
});
