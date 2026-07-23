import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ClientWalletSessionExpiryInvalidator } from '@/core/signingEngine/session/availability/clientSessionExpiryInvalidator';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildEd25519PasskeySigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { seedExpiredWalletSessionAuthorizationState } from './helpers/sealedSigningSession.fixtures';

const WALLET_ID = toWalletId('refactor-92-invalidation-wallet');
const LANE = buildEd25519PasskeySigningLane({
  walletId: WALLET_ID,
  nearAccountId: toAccountId('refactor-92.testnet'),
  nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
    'refactor-92-invalidation-key',
  ),
  signerSlot: 1,
  auth: {
    kind: SIGNER_AUTH_METHODS.passkey,
    rpId: toRpId('localhost'),
    credentialIdB64u: 'refactor-92-invalidation-credential',
  },
  signingGrantId: SigningSessionIds.signingGrant(
    'refactor-92-invalidation-grant',
  ),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
    'refactor-92-invalidation-session',
  ),
  storageSource: 'login',
});

const EXPIRED_STATE = seedExpiredWalletSessionAuthorizationState({
  identity: LANE.identity,
  expiresAtMs: 1_000,
  detectedAtMs: 1_001,
});

async function clearVolatileWarmSessionMaterial(): Promise<void> {}

async function clearEmailOtpWarmSessionMaterial(): Promise<void> {}

function clearThresholdEcdsaSessionRecordForExactIdentity(): void {}

test('Refactor 92 invalidation emits once for concurrent observations of one session', async () => {
  const invalidator = new ClientWalletSessionExpiryInvalidator({
    readiness: {
      touchConfirm: { clearVolatileWarmSessionMaterial },
      clearEmailOtpWarmSessionMaterial,
      clearThresholdEcdsaSessionRecordForExactIdentity,
    },
    statusOverrides: new Map(),
  });

  const results = await Promise.all([
    invalidator.invalidate(EXPIRED_STATE),
    invalidator.invalidate(EXPIRED_STATE),
    invalidator.invalidate(EXPIRED_STATE),
  ]);

  expect(results.filter((result) => result.kind === 'invalidated')).toHaveLength(1);
  expect(results.filter((result) => result.kind === 'already_invalidated')).toHaveLength(2);
  expect(results.find((result) => result.kind === 'invalidated')).toEqual({
    kind: 'invalidated',
    event: {
      kind: 'wallet_session_expired',
      walletId: WALLET_ID,
      walletSessionId: LANE.signingGrantId,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      expiresAtMs: 1_000,
      detectedAtMs: 1_001,
    },
  });
});
