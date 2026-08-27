import { expect, test } from '@playwright/test';
import { handleWalletRecoveryGoogleEmailOtpFinalize } from '../../packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';

const routeDefinitions = createRouterApiRouteDefinitions();
const OPERATION_ID = 'wallet-recovery-operation:google-email-finalize-test';
const RESERVATION_ID = 'recovery-reservation-google-email-finalize';

function context(body: unknown, finalize: (request: unknown) => Promise<unknown>) {
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/google-email-otp/finalize',
    request: new Request('https://relay.localhost/wallets/recovery/google-email-otp/finalize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    service: { passkeyCustody: { finalizeGoogleEmailOtpRecovery: finalize } },
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function baseBody() {
  return {
    recoveryOperationId: OPERATION_ID,
    reservationId: RESERVATION_ID,
    replacementEnvelope: passkeyCustodyEnvelope(),
    ecdsaMaterialPossessionProofs: [],
  };
}

test('the Google/Email recovery finalization route is target-specific', () => {
  const route = findRouteDefinitionById(
    routeDefinitions,
    'wallet_recovery_google_email_otp_finalize',
  );
  expect(route?.path).toBe('/wallets/recovery/google-email-otp/finalize');
});

test('finalization rejects loose recovery identity fields before service admission', async () => {
  let called = false;
  const response = await handleWalletRecoveryGoogleEmailOtpFinalize(
    context(
      {
        ...baseBody(),
        recovery: { providerSubject: 'attacker', verifiedEmail: 'attacker@example.test' },
        walletId: 'alice.testnet',
        providerSubject: 'attacker',
        verifiedEmail: 'attacker@example.test',
        targetAuthorityId: 'wallet-authority:attacker',
        targetWalletAuthMethodId: 'wallet-auth-method:attacker',
        targetDeviceId: 'device:attacker',
        enrollmentId: 'enrollment:attacker',
      },
      async () => {
        called = true;
        return { kind: 'conflict', reason: 'should not be reached' };
      },
    ),
  );

  expect(response?.status).toBe(400);
  expect(called).toBe(false);
});

test('finalization forwards the operation, envelope, proofs, and create material only', async () => {
  let seen: unknown = null;
  const response = await handleWalletRecoveryGoogleEmailOtpFinalize(
    context(
      {
        ...baseBody(),
        emailOtpEnrollment: {
          kind: 'create',
          material: {
            enrollmentSealKeyVersion: 'email-otp-seal-v1',
            clientUnlockPublicKeyB64u: 'compressed-client-key',
            unlockKeyVersion: 'email-otp-unlock-v1',
            serverSealedFactorCiphertextB64u: 'sealed-factor',
          },
        },
      },
      async (request) => {
        seen = request;
        return { kind: 'conflict', reason: 'test conflict' };
      },
    ),
  );

  expect(response?.status).toBe(409);
  expect(Object.keys(seen as object).sort()).toEqual([
    'ecdsaMaterialPossessionProofs',
    'emailOtpEnrollment',
    'recoveryOperationId',
    'replacementEnvelope',
    'reservationId',
  ]);
  expect(seen).toMatchObject({
    recoveryOperationId: OPERATION_ID,
    reservationId: RESERVATION_ID,
    emailOtpEnrollment: {
      kind: 'create',
      material: {
        enrollmentSealKeyVersion: 'email-otp-seal-v1',
        clientUnlockPublicKeyB64u: 'compressed-client-key',
        unlockKeyVersion: 'email-otp-unlock-v1',
        serverSealedFactorCiphertextB64u: 'sealed-factor',
      },
    },
  });
});
