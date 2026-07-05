import { expect, test } from '@playwright/test';
import { buildD1ThresholdEd25519RegistrationSessionPolicy } from '../../packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  TEST_COMBINED_NEAR_ACCOUNT_ID,
  requireParsedDomainId,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

test('D1 Ed25519 registration session policy requires bound passkey authority', () => {
  const rpId = requireParsedDomainId(parseWebAuthnRpId('localhost'));
  const walletId = 'jade-orchid-2caqh9';
  const authority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: 'cred-d1-passkey',
  });
  const built = buildD1ThresholdEd25519RegistrationSessionPolicy({
    requestedSessionPolicy: {
      version: 'threshold_session_v1',
      authority,
      thresholdSessionId: 'tsess-d1-passkey',
      signingGrantId: 'wss-d1-passkey',
      participantIds: [1, 2],
      ttlMs: 600_000,
      remainingUses: 3,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'local-signing-worker',
      },
    },
    walletId,
    nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: 'near-ed25519-signing-key-id',
    relayerKeyId: 'ed25519:relayer',
    authority,
  });
  expect(built.ok).toBe(true);
  if (!built.ok) throw new Error(built.message);
  expect(built.value.authority).toEqual(authority);
  expect(Object.prototype.hasOwnProperty.call(built.value, 'rpId')).toBe(false);
  expect(Object.prototype.hasOwnProperty.call(built.value, 'authorityScope')).toBe(false);
});

test('D1 Ed25519 registration session policy rejects root passkey RP ID', () => {
  const rpId = requireParsedDomainId(parseWebAuthnRpId('localhost'));
  const walletId = 'jade-orchid-2caqh9';
  const authority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: 'cred-d1-passkey',
  });
  const built = buildD1ThresholdEd25519RegistrationSessionPolicy({
    requestedSessionPolicy: {
      version: 'threshold_session_v1',
      authority,
      rpId: 'localhost',
      thresholdSessionId: 'tsess-d1-passkey',
      signingGrantId: 'wss-d1-passkey',
      ttlMs: 600_000,
      remainingUses: 3,
    },
    walletId,
    nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: 'near-ed25519-signing-key-id',
    relayerKeyId: 'ed25519:relayer',
    authority,
  });
  expect(built).toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: 'threshold_ed25519.session_policy.rpId belongs in authority',
  });
});
