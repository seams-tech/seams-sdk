import { expect, test } from '@playwright/test';
import { handleWalletRecoveryGoogleEmailOtpFinalize } from '../../packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture } from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseEmailOtpProviderUserId } from '../../packages/shared-ts/src/utils/domainIds';
import { buildWalletRecoveryCommittedProjectionV1 } from '../../packages/shared-ts/src/wallet-recovery/walletRecoveryCommittedProjection';

const routeDefinitions = createRouterApiRouteDefinitions();
const OPERATION_ID = 'wallet-recovery-operation:google-email-finalize-test';
const RESERVATION_ID = 'recovery-reservation-google-email-finalize';

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false }): T {
  if (!result.ok) throw new Error('invalid route fixture identity');
  return result.value;
}

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

async function committedEmailProjection() {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'google-email-route',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: 'alice.testnet',
      authorityId: 'wallet-authority:google-email-route',
      walletAuthMethodId: 'wallet-auth-method:google-email-route',
      rpId: 'wallet.example.localhost',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('Google Email OTP route fixture lost recovery provenance');
  }
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    walletId: fixture.authority.walletId,
    walletAuthorityId: fixture.authority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: 'c'.repeat(64),
    registrationAuthorityId: 'challenge:google-email-route',
    createdAtMs: fixture.authMethod.createdAtMs,
    updatedAtMs: fixture.authMethod.updatedAtMs,
    activatedAtMs: fixture.authMethod.activatedAtMs,
  });
  if (authMethod.kind !== 'email_otp' || authMethod.status !== 'active') {
    throw new Error('Google Email OTP route fixture changed method branch');
  }
  return buildWalletRecoveryCommittedProjectionV1({
    kind: 'google_email_otp',
    storeVersion: 'route-store-version',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod,
    providerSubject: required(parseEmailOtpProviderUserId('google:google-email-route')),
    emailHashHex: authMethod.emailHashHex,
    registrationAuthorityId: authMethod.registrationAuthorityId,
    enrollment: {
      kind: 'email_otp_enrollment_reference_v1',
      enrollmentId: 'enrollment:google-email-route',
      enrollmentSealKeyVersion: 'email-otp-seal-v1',
    },
  });
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

test('successful finalization returns only the credential-free committed projection', async () => {
  const projection = await committedEmailProjection();
  const response = await handleWalletRecoveryGoogleEmailOtpFinalize(
    context(
      {
        ...baseBody(),
        replacementEnvelope: buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
          walletId: 'alice.testnet',
          envelopeId: 'passkey-envelope-1',
          enrollmentId: 'enrollment:google-email-route',
          enrollmentSealKeyVersion: 'email-otp-seal-v1',
          walletAuthMethodId: 'wallet-auth-method:google-email-route',
        }),
      },
      async () => ({ kind: 'promoted', projection }),
    ),
  );

  expect(response?.status).toBe(200);
  const body = await response?.json();
  expect(body).toMatchObject({ ok: true, projection: { kind: 'google_email_otp' } });
  expect(Object.keys(body).sort()).toEqual(['ok', 'projection']);
  expect(JSON.stringify(body)).not.toContain('serverSealedFactorCiphertextB64u');
});
