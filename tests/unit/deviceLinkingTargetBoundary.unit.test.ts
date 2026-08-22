import { expect, test } from '@playwright/test';
import {
  parseLinkedDeviceTargetCredentialRegistrationResultV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
} from '@shared/device-linking/parsers';
import {
  targetCredentialResultResponse,
} from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceLinking';
import {
  buildR103DeviceLinkFixture,
} from './helpers/deviceLinkContracts.fixtures';
import { buildR103UnclaimedLinkedDeviceSessionRecordV1 } from './helpers/deviceLinkingServer.fixtures';
import {
  buildOrdinaryEcdsaReservationPreparationFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';

test('serializes server preparations with the browser recipient request', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:target-boundary' });
  const digest = parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE');
  const activation = buildOrdinaryMaterialActivationFixture('target-boundary');
  const preparation = buildOrdinaryEcdsaReservationPreparationFixture(
    'target-boundary',
    activation,
  );
  const walletKeyId = fixture.approval.orderedKeyBindings[0]?.walletKeyId;
  if (!walletKeyId) throw new Error('fixture signer binding is missing');
  const walletAuthMethodId = 'email_otp:wallet:r103:' + 'ab'.repeat(32);
  const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1({
    kind: 'linked_device_target_credential_registration_result_v1',
    outcome: 'applied',
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    walletAuthMethodId,
    targetPreparationDigestB64u: digest,
    targetFactor: {
      kind: 'verified_email_otp_target_v1',
      authMethod: {
        walletAuthMethodId,
        walletId: fixture.approval.walletId,
        createdAtMs: 1_000,
        kind: 'email_otp',
        emailHashHex: 'ab'.repeat(32),
        registrationAuthorityId: 'authority:r103',
      },
      verificationDigestB64u: digest,
      verifiedAtMs: 2_000,
    },
    ordinarySignerMaterialPreparations: [preparation],
    ordinarySignerMaterialRecipientRequests: [
      {
        kind: 'ordinary_ecdsa_signer_material_recipient_request_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletKeyId,
        clientEphemeralPublicKey: preparation.registrationRequest.client_ephemeral_public_key,
      },
    ],
    keyManifestDigestB64u: digest,
  });

  const response = targetCredentialResultResponse(
    buildR103UnclaimedLinkedDeviceSessionRecordV1(fixture),
    'applied',
    targetCredential,
  );
  const body = await response.json();
  expect(body.targetCredential.ordinarySignerMaterialRecipientRequests).toEqual([
    expect.objectContaining({
      clientEphemeralPublicKey: preparation.registrationRequest.client_ephemeral_public_key,
    }),
  ]);
  expect(body.targetCredential).not.toHaveProperty('recipientPrivateKey');
});

test('registration rejects private recipient material and activation choices', () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:target-boundary-reject' });
  const walletKeyId = fixture.approval.orderedKeyBindings[0]?.walletKeyId;
  if (!walletKeyId) throw new Error('fixture signer binding is missing');
  const base = {
    kind: 'linked_device_target_credential_registration_v1',
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    walletAuthMethodId: 'passkey:wallet.example.test:target-credential',
    targetFactor: { kind: 'passkey_prf' },
    targetPreparationDigestB64u: 'Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE',
    ordinarySignerMaterialRecipientRequests: [
      {
        kind: 'ordinary_ed25519_signer_material_recipient_request_v1',
        keyFamily: 'ed25519',
        walletKeyId,
        recipientPublicKeyB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    ],
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u: 'AQ',
      authenticatorAttachment: 'platform',
      clientDataJsonB64u: 'AQ',
      attestationObjectB64u: 'Ag',
      transports: ['internal'],
    },
    registeredAtMs: 2_000,
  };

  expect(() =>
    parseLinkedDeviceTargetCredentialRegistrationV1({
      ...base,
      ordinarySignerMaterialPreparations: [],
    }),
  ).toThrow(/unknown or missing fields|ordinarySignerMaterialPreparations/);
  expect(() =>
    parseLinkedDeviceTargetCredentialRegistrationV1({
      ...base,
      ordinarySignerMaterialRecipientRequests: [
        {
          ...base.ordinarySignerMaterialRecipientRequests[0],
          recipientPrivateKey: 'private-key-must-stay-in-browser',
        },
      ],
    }),
  ).toThrow(/unknown or missing fields|recipientPrivateKey/);
});
