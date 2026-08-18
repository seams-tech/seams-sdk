import { expect, test } from '@playwright/test';
import {
  parseRouterAbEd25519WalletSessionClaims,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  type RouterAbEd25519LinkedDeviceWalletSessionClaims,
} from '../../packages/wallet-server/src/core/ThresholdService/validation';
import {
  signRouterAbEd25519LinkedDeviceWalletSessionJwt,
  signRouterAbEcdsaDerivationLinkedDeviceWalletSessionJwt,
} from '../../packages/wallet-server/src/router/auth/commonRouterUtils';
import type { SessionAdapter } from '../../packages/wallet-server/src/router/framework/routerApi';
import { buildVerifiedEd25519WalletSessionAuth } from '../../packages/wallet-server/src/router/auth/verifiedWalletSessionAuth';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

function digest(fill: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(fill));
}

function linkedClaims(): Record<string, unknown> {
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    sub: 'linked-device:device:2',
    walletId: 'wallet:1',
    tenantId: 'tenant:1',
    deviceId: 'device:2',
    enrollmentId: 'enrollment:2',
    walletKeyId: 'wallet-key:1',
    keyManifestDigestB64u: digest(1),
    revocationEpoch: 0,
    permission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    issuedAtMs: 100,
    expiresAtMs: 1_000,
    authorizationId: 'linked-device-wallet-session-authorization:1',
    walletSessionId: 'wallet-session:linked',
    quotaId: 'wallet-quota:linked',
    iat: 0,
    exp: 1,
  };
}

test.describe('R103 linked-device Wallet Session claims', () => {
  test('accepts exact linked claims and preserves the discriminant', () => {
    const claims = parseRouterAbEd25519WalletSessionClaims(linkedClaims());
    expect(claims?.authorizationKind).toBe('linked_device_wallet_session');
    expect(claims).toMatchObject({
      tenantId: 'tenant:1',
      deviceId: 'device:2',
      enrollmentId: 'enrollment:2',
      walletKeyId: 'wallet-key:1',
      revocationEpoch: 0,
      issuedAtMs: 100,
      permission: { localUserPresence: 'required' },
    });
    if (!claims || claims.authorizationKind !== 'linked_device_wallet_session') return;
    expect(buildVerifiedEd25519WalletSessionAuth(claims)).toMatchObject({
      authorizationKind: 'linked_device_wallet_session',
      walletId: 'wallet:1',
      tenantId: 'tenant:1',
      deviceId: 'device:2',
      enrollmentId: 'enrollment:2',
      walletKeyId: 'wallet-key:1',
      revocationEpoch: 0,
    });
  });

  test('rejects owner and linked fields mixed in one JWT', () => {
    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...linkedClaims(),
        authority: { kind: 'passkey' },
      }),
    ).toBeNull();

    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...linkedClaims(),
        thresholdSessionId: 'threshold-session:linked',
      }),
    ).toBeNull();

    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...linkedClaims(),
        routerAbNormalSigning: { kind: 'router_ab_ed25519_normal_signing_v1' },
      }),
    ).toBeNull();

    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...linkedClaims(),
        authorizationKind: 'owner_wallet_session',
      }),
    ).toBeNull();

    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...linkedClaims(),
        sub: 'linked-device:device:substituted',
      }),
    ).toBeNull();

    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...linkedClaims(),
        kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
        keyHandle: 'ecdsa-key-handle',
      }),
    ).toBeNull();
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...linkedClaims(),
        kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
        materialActivation: { kind: 'router_ab_mpc_material_activation_ref_v1' },
      }),
    ).toBeNull();
  });

  test('rejects missing authorization kind instead of defaulting to owner', () => {
    const raw = linkedClaims();
    delete raw.authorizationKind;
    expect(parseRouterAbEd25519WalletSessionClaims(raw)).toBeNull();
  });

  test('linked signing builders emit only authorization and binding claims', async () => {
    const signedPayloads: Record<string, unknown>[] = [];
    const session: SessionAdapter = {
      signJwt: async (sub, extra = {}) => {
        signedPayloads.push({ sub, ...extra });
        return `signed-${signedPayloads.length}`;
      },
      verifyJwt: async () => ({ valid: false as const }),
      parse: async () => ({ ok: false, reason: 'missing' as const }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    const linkedSessionInfo = {
      sessionKind: 'jwt' as const,
      authorizationKind: 'linked_device_wallet_session' as const,
      walletId: 'wallet:1',
      tenantId: 'tenant:1',
      deviceId: 'device:2',
      enrollmentId: 'enrollment:2',
      walletKeyId: 'wallet-key:1',
      keyManifestDigestB64u: digest(1),
      revocationEpoch: 0,
      permission: {
        kind: 'owner_equivalent_signing' as const,
        administrationScope: 'signing_only' as const,
        localUserPresence: 'required' as const,
      },
      issuedAtMs: 100,
      authorizationId: 'linked-device-wallet-session-authorization:1',
      walletSessionId: 'wallet-session:linked',
      quotaId: 'wallet-quota:linked',
      expiresAtMs: 1_000,
    };
    const ed25519 = await signRouterAbEd25519LinkedDeviceWalletSessionJwt({
      session,
      userId: 'wallet:1',
      requireJwtErrorMessage: 'jwt required',
      invalidPayloadErrorMessage: 'invalid payload',
      sessionInfo: linkedSessionInfo,
    });
    const ecdsa = await signRouterAbEcdsaDerivationLinkedDeviceWalletSessionJwt({
      session,
      userId: 'wallet:1',
      requireJwtErrorMessage: 'jwt required',
      invalidPayloadErrorMessage: 'invalid payload',
      sessionInfo: linkedSessionInfo,
    });
    expect(ed25519).toMatchObject({ ok: true, authorizationKind: 'linked_device_wallet_session' });
    expect(ecdsa).toMatchObject({ ok: true, authorizationKind: 'linked_device_wallet_session' });
    expect(signedPayloads).toHaveLength(2);
    expect(parseRouterAbEd25519WalletSessionClaims(signedPayloads[0])).toMatchObject({
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      authorizationKind: 'linked_device_wallet_session',
    });
    expect(parseRouterAbEcdsaDerivationWalletSessionClaims(signedPayloads[1])).toMatchObject({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      authorizationKind: 'linked_device_wallet_session',
    });
    for (const payload of signedPayloads) {
      expect(payload).not.toHaveProperty('thresholdSessionId');
      expect(payload).not.toHaveProperty('participantIds');
      expect(payload).not.toHaveProperty('relayerKeyId');
      expect(payload).not.toHaveProperty('routerAbNormalSigning');
      expect(payload).not.toHaveProperty('routerAbEcdsaDerivationNormalSigning');
      expect(payload).not.toHaveProperty('keyHandle');
    }
  });
});

const _linkedClaimTypeFixture: RouterAbEd25519LinkedDeviceWalletSessionClaims | null = null;
void _linkedClaimTypeFixture;
