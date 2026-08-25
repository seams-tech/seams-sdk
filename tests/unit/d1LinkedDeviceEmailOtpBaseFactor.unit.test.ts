import { expect, test } from '@playwright/test';
import { D1LinkedDeviceEmailOtpTargetFactorV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceEmailOtpTargetFactor';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  type WalletAuthMethodId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { sha256HexUtf8 } from '../../packages/shared-ts/src/utils/digests';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

async function buildProviderFixture() {
  const walletId = required(parseWalletId('wallet:email-base-factor'));
  const first = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'email-base-first',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    identity: {
      walletId,
      authorityId: 'authority:email-base-first',
      walletAuthMethodId: 'passkey:email-base-first',
      rpId: 'email-base.example.test',
    },
  });
  const second = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'email-base-second',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    identity: {
      walletId,
      authorityId: 'authority:email-base-second',
      walletAuthMethodId: 'passkey:email-base-second',
      rpId: 'email-base.example.test',
    },
  });
  const email = 'owner@example.test';
  const emailHashHex = await sha256HexUtf8(email);
  const firstMethodId = required(parseWalletAuthMethodId('email-otp:email-base-first'));
  const secondMethodId = required(parseWalletAuthMethodId('email-otp:email-base-second'));
  const methods = [
    buildEmailMethod(firstMethodId, first.authority.authorityId, walletId, emailHashHex),
    buildEmailMethod(secondMethodId, second.authority.authorityId, walletId, emailHashHex),
  ];
  const authorities = new Map([
    [first.authority.authorityId, first.authority],
    [second.authority.authorityId, second.authority],
  ]);
  const provider = new D1LinkedDeviceEmailOtpTargetFactorV1({
    issuer: { create: async () => Promise.reject(new Error('unused issuer')) },
    verifier: { verifyExisting: async () => Promise.reject(new Error('unused verifier')) },
    enrollments: {
      readEnrollment: async () => ({
        version: 'email_otp_wallet_enrollment_v1',
        walletId,
        providerUserId: 'google:email-base-owner',
        orgId: 'org:email-base',
        verifiedEmail: email,
        enrollmentId: 'email-enrollment:email-base',
        enrollmentVersion: 'v1',
        enrollmentSealKeyVersion: 'v1',
        clientUnlockPublicKeyB64u: 'client-unlock-key',
        unlockKeyVersion: 'v1',
        serverSealedFactorCiphertextB64u: 'sealed-factor',
        createdAtMs: 1,
        updatedAtMs: 1,
      }),
    },
    walletAuthMethods: { listForWalletV2: async () => methods },
    walletAuthorities: {
      readById: async (authorityId) => authorities.get(authorityId) ?? null,
    },
    serverSeal: {
      removeEmailOtpServerSeal: async () => Promise.reject(new Error('unused server seal')),
    },
    grants: {
      issueV1: async () => Promise.reject(new Error('unused grant issue')),
      readByIdV1: async () => Promise.reject(new Error('unused grant read')),
      buildConsumeStatementsV1: () => Promise.reject(new Error('unused grant consumption')),
    },
  });
  return { provider, walletId, firstMethodId, secondMethodId, authorities };
}

function buildEmailMethod(
  walletAuthMethodId: WalletAuthMethodId,
  walletAuthorityId: Parameters<typeof buildWalletAuthMethodRecordV2>[0]['walletAuthorityId'],
  walletId: Parameters<typeof buildWalletAuthMethodRecordV2>[0]['walletId'],
  emailHashHex: string,
) {
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletAuthorityId,
    walletId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex,
    registrationAuthorityId: `registration:${walletAuthMethodId}`,
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
  });
}

test('requires selection for several eligible Email OTP methods and sorts them', async () => {
  const fixture = await buildProviderFixture();
  const result = await fixture.provider.resolveBaseFactorSelectionV1({
    walletId: fixture.walletId,
    request: { kind: 'resolve', expectedRevision: 2 },
  });
  expect(result).toEqual({
    kind: 'selection_required',
    choices: [
      {
        baseWalletAuthMethodId: fixture.firstMethodId,
        maskedEmailHint: 'owner@example.test',
      },
      {
        baseWalletAuthMethodId: fixture.secondMethodId,
        maskedEmailHint: 'owner@example.test',
      },
    ],
  });
});

test('selects only the exact eligible Email OTP method', async () => {
  const fixture = await buildProviderFixture();
  await expect(
    fixture.provider.resolveBaseFactorSelectionV1({
      walletId: fixture.walletId,
      request: {
        kind: 'select',
        expectedRevision: 2,
        baseWalletAuthMethodId: fixture.secondMethodId,
      },
    }),
  ).resolves.toEqual({
    kind: 'selected',
    choice: {
      baseWalletAuthMethodId: fixture.secondMethodId,
      maskedEmailHint: 'owner@example.test',
    },
  });
});

test('returns the same unavailable result for stale or inactive selections', async () => {
  const fixture = await buildProviderFixture();
  fixture.authorities.delete(
    [...fixture.authorities.keys()].find((id) => id === 'authority:email-base-second')!,
  );
  await expect(
    fixture.provider.resolveBaseFactorSelectionV1({
      walletId: fixture.walletId,
      request: {
        kind: 'select',
        expectedRevision: 2,
        baseWalletAuthMethodId: fixture.secondMethodId,
      },
    }),
  ).resolves.toEqual({
    kind: 'unavailable',
    reason: 'no_active_email_otp_base_factor',
  });
});
