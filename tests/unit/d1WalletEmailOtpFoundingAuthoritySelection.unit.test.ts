import { expect, test } from '@playwright/test';
import { CloudflareD1WalletAuthMethodService } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService';
import {
  parseWalletAuthMethodId,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
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

test('wallet-level Email OTP login selects the unique founding method among linked siblings', async () => {
  const walletId = required(parseWalletId('wallet:email-login-selection'));
  const foundingMethodId = required(parseWalletAuthMethodId('email-otp:founding'));
  const linkedMethodId = required(parseWalletAuthMethodId('email-otp:linked'));
  const founding = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'email-login-founding',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    identity: {
      walletId,
      authorityId: 'authority:email-login-founding',
      walletAuthMethodId: 'passkey:email-login-founding',
      rpId: 'email-login.example.test',
    },
  });
  const linked = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'email-login-linked',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'device_link',
    sourceAuthorityId: founding.authority.authorityId,
    identity: {
      walletId,
      authorityId: 'authority:email-login-linked',
      walletAuthMethodId: 'passkey:email-login-linked',
      rpId: 'email-login.example.test',
    },
  });
  const emailHashHex = 'a'.repeat(64);
  const methods = [
    buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: foundingMethodId,
      walletId,
      walletAuthorityId: founding.authority.authorityId,
      kind: 'email_otp',
      status: 'active',
      emailHashHex,
      registrationAuthorityId: 'registration:email-login-founding',
      createdAtMs: 1,
      updatedAtMs: 1,
      activatedAtMs: 1,
    }),
    buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: linkedMethodId,
      walletId,
      walletAuthorityId: linked.authority.authorityId,
      kind: 'email_otp',
      status: 'active',
      emailHashHex,
      registrationAuthorityId: 'registration:email-login-linked',
      createdAtMs: 2,
      updatedAtMs: 2,
      activatedAtMs: 2,
    }),
  ];
  const authorities = new Map([
    [founding.authority.authorityId, founding.authority],
    [linked.authority.authorityId, linked.authority],
  ]);
  const service = new CloudflareD1WalletAuthMethodService({
    getWalletAuthMethodStore: () => ({ listForWalletV2: async () => methods }),
    walletAuthorityStore: {
      readById: async (authorityId: string) => authorities.get(authorityId) ?? null,
    },
  } as never);

  await expect(
    service.resolveActiveEmailOtpAuthorityForVerifiedSubject({
      walletId,
      providerUserId: 'google:email-login-owner',
    }),
  ).resolves.toMatchObject({
    ok: true,
    authority: {
      walletId,
      bindingId: foundingMethodId,
      verifier: { emailHashHex },
    },
  });
});
