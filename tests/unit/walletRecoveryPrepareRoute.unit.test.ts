import { expect, test } from '@playwright/test';
import {
  createWalletRecoveryRegistrationOptions,
} from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import type { CloudflareD1WebAuthnStore } from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import { parseRecoveryCodeReservationId } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeReservation';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';

const WALLET_ID = parseWalletId('recovery-expiry.testnet');
const AUTH_METHOD_ID = parseWalletAuthMethodId('wallet-auth-method:source');
const AUTHORITY_ID = parseWalletAuthorityId('wallet-authority:recovery-test');
const RP_ID = parseWebAuthnRpId('example.localhost');
const CREDENTIAL_ID = parseWebAuthnCredentialIdB64u('source-credential');
const SOURCE_AUTHORITY_DIGEST = parseDigestB64u('A'.repeat(43));

if (
  !WALLET_ID.ok ||
  !AUTH_METHOD_ID.ok ||
  !AUTHORITY_ID.ok ||
  !RP_ID.ok ||
  !CREDENTIAL_ID.ok
) {
  throw new Error('recovery challenge expiry test ids are invalid');
}

function activeSourceMethod(): Extract<WalletAuthMethodRecordV2, { readonly kind: 'passkey'; readonly status: 'active' }> {
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: AUTH_METHOD_ID.value,
    walletId: WALLET_ID.value,
    walletAuthorityId: AUTHORITY_ID.value,
    kind: 'passkey',
    status: 'active',
    rpId: RP_ID.value,
    credentialIdB64u: CREDENTIAL_ID.value,
    credentialPublicKeyB64u: 'source-public-key',
    counter: 0,
    createdAtMs: 1_000,
    updatedAtMs: 1_000,
    activatedAtMs: 1_000,
  });
}

test('the admitted prepare route is registered without a consume-first route', () => {
  const routeDefinitions = createRouterApiRouteDefinitions();
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_prepare');
  expect(route?.path).toBe('/wallets/recovery/prepare');
  expect(findRouteDefinitionById(routeDefinitions, 'wallet_recovery_code_spend')).toBeNull();
});

test('persists the prepared reservation expiry on the registration challenge', async () => {
  const preparedReservationExpiresAtMs = 1_900_000_300_000;
  let persistedRecordExpiresAtMs: number | undefined;
  let persistedExpiresAtMs: number | undefined;
  const webAuthnStore: Pick<
    CloudflareD1WebAuthnStore,
    'writeChallenge' | 'readBindingRows'
  > = {
    writeChallenge: async (input) => {
      persistedRecordExpiresAtMs = input.record.expiresAtMs;
      persistedExpiresAtMs = input.expiresAtMs;
    },
    readBindingRows: async () => [],
  };

  const result = await createWalletRecoveryRegistrationOptions({
    webAuthnStore,
    walletId: WALLET_ID.value,
    reservationId: parseRecoveryCodeReservationId('recovery-operation-1'),
    origin: 'https://example.localhost',
    rpId: RP_ID.value,
    sourceMethod: activeSourceMethod(),
    sourceAuthorityDigestB64u: SOURCE_AUTHORITY_DIGEST,
    expiresAtMs: preparedReservationExpiresAtMs,
    nowMs: 1_900_000_000_000,
  });

  expect(result.kind).toBe('ready');
  expect(persistedRecordExpiresAtMs).toBe(preparedReservationExpiresAtMs);
  expect(persistedExpiresAtMs).toBe(preparedReservationExpiresAtMs);
});
