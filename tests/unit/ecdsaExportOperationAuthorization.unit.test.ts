import { expect, test } from '@playwright/test';
import {
  ecdsaExportOperationAuthorizationForLane,
  type ExactEcdsaExportLane,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import {
  exactEcdsaSigningLaneIdentity,
  buildEvmFamilyEcdsaSignerBinding,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { WALLET_SESSION_AUTHORIZATION_RECORD_VERSION } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefFixture,
} from './helpers/ecdsaMaterialRef.fixtures';

// Export authorization is derived from the lane's own active reusable Wallet
// Session, never from a session or grant identifier carried on a durable
// record. Replaces the pre-3C export-material assertions, which encoded the
// retired record-backed committed-lane and durable signing-session branches.

const WALLET_ID = 'export-authorization.testnet';

function b64u(seed: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(seed)).toString('base64url');
}

function requireId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('export fixture id is invalid');
  return result.value;
}

function buildExportLane(walletSessionSuffix: string): ExactEcdsaExportLane {
  const walletId = toWalletId(WALLET_ID);
  const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
    chain: 'tempo',
    chainId: 42431,
    networkSlug: 'tempo-testnet',
  });
  const keyHandle = toEvmFamilyEcdsaKeyHandle('export-key-handle');
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId,
    ecdsaThresholdKeyId: 'export-threshold-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'33'.repeat(20)}`,
  });
  const publicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle,
    publicKeyB64u: b64u(2, 33),
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'33'.repeat(20)}`,
  });
  const walletSessionId = requireId(
    parseWalletSessionId(`export-wallet-session:${walletSessionSuffix}`),
  );
  const quotaId = requireId(parseMpcWalletSigningQuotaId(`export-quota:${walletSessionSuffix}`));
  return {
    curve: 'ecdsa',
    key,
    publicFacts,
    laneIdentity: exactEcdsaSigningLaneIdentity({
      signer: buildEvmFamilyEcdsaSignerBinding({
        walletId,
        chainTarget,
        keyHandle,
        key,
        materialActivation: buildMpcMaterialActivationRefFixture('export-lane', WALLET_ID),
      }),
      auth: {
        kind: 'passkey',
        rpId: toRpId('localhost'),
        credentialIdB64u: 'export-credential',
      },
      authorization: {
        kind: 'active_reusable_wallet_session_authorization',
        projection: {
          recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
          walletId,
          authorizationSessionId: requireId(
            parseSeamsSessionId(`export-authorization-session:${walletSessionSuffix}`),
          ),
          walletSessionId,
          quotaId,
          authMethod: 'passkey',
          authority: buildWalletAuthAuthorityRefFixture({ walletId: WALLET_ID }),
          expiresAtMs: Date.now() + 60 * 60_000,
          status: 'active',
          walletSessionJwt: 'export-wallet-session-jwt' as never,
        },
        status: {
          walletSessionId,
          quotaId,
          status: 'active',
          remainingUses: 5,
          expiresAtMs: Date.now() + 60 * 60_000,
        },
      },
    }),
    session: {
      chainTarget,
      authMethod: 'passkey',
      material: { kind: 'loaded_worker_material' },
      state: 'ready',
      source: 'canonical_capability',
    },
  };
}

test.describe('ECDSA export operation authorization', () => {
  test('derives the reusable Wallet Session authority from the lane', () => {
    const authorization = ecdsaExportOperationAuthorizationForLane(buildExportLane('a'));
    expect(authorization.kind).toBe('reusable_wallet_session');
    if (authorization.kind !== 'reusable_wallet_session') return;
    expect(authorization.walletSessionId).toBe('export-wallet-session:a');
    // The branch is exclusive: an export authorized by a reusable session
    // never also carries a single-operation grant id.
    expect(authorization.grantId).toBeUndefined();
  });

  test('tracks the lane it was derived from', () => {
    const first = ecdsaExportOperationAuthorizationForLane(buildExportLane('a'));
    const second = ecdsaExportOperationAuthorizationForLane(buildExportLane('b'));
    expect(first).not.toEqual(second);
  });

  test('export sessions carry no threshold-session or signing-grant identity', () => {
    const session = buildExportLane('a').session as Record<string, unknown>;
    expect(session.thresholdSessionId).toBeUndefined();
    expect(session.signingGrantId).toBeUndefined();
  });
});
