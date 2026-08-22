import type { AuthenticatorPort } from '@/core/platform';
import type { LinkedDeviceWebAuthnRegistrationV1 } from '@shared/device-linking';
import { base64UrlDecode } from '@shared/utils/base64';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { DeviceLinkingTargetCredentialPortV1 } from './deviceLinkingPorts';

function requiredCredentialId(
  value: unknown,
): LinkedDeviceWebAuthnRegistrationV1['credentialIdB64u'] {
  const parsed = parseWebAuthnCredentialIdB64u(value);
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}
function requiredTransport(
  value: string,
): LinkedDeviceWebAuthnRegistrationV1['transports'][number] {
  switch (value) {
    case 'ble':
    case 'cable':
    case 'hybrid':
    case 'internal':
    case 'nfc':
    case 'smart-card':
    case 'usb':
      return value;
    default:
      throw new Error(`linked-device WebAuthn transport ${value} is unsupported`);
  }
}

function linkedDevicePasskeyName(walletId: string): string {
  return `${walletId} (2)`;
}

function zeroizeLiveBytes(value: Uint8Array): void {
  if (value.byteLength > 0) value.fill(0);
}

function registrationProjection(
  credential: Extract<
    Awaited<ReturnType<AuthenticatorPort['run']>>,
    { readonly ok: true; readonly operation: 'create_passkey'; readonly requirePrfFirst: true }
  >,
): LinkedDeviceWebAuthnRegistrationV1 {
  const attachment = credential.credential.authenticatorAttachment;
  if (attachment !== undefined && attachment !== 'platform' && attachment !== 'cross-platform') {
    throw new Error('linked-device WebAuthn authenticator attachment is invalid');
  }
  return {
    kind: 'linked_device_webauthn_registration_v1',
    credentialIdB64u: requiredCredentialId(credential.credentialIdB64u),
    authenticatorAttachment: attachment ?? null,
    clientDataJsonB64u: credential.credential.response.clientDataJSON,
    attestationObjectB64u: credential.credential.response.attestationObject,
    transports: credential.credential.response.transports.map(requiredTransport),
  };
}

export function createDeviceLinkingTargetCredentialPortV1(args: {
  readonly authenticator: AuthenticatorPort;
}): DeviceLinkingTargetCredentialPortV1 {
  return {
    async createTargetCredentialV1(input) {
      // Every registration parameter comes from the owner ceremony this
      // credential will finalize. Device 2 creates its passkey against exactly
      // what the server will verify and finalize against, so there is no second
      // set of parameters to fall out of step.
      const registration = input.preparation.ownerEnrollment.registration;
      // The relying party, challenge, and user handle all come from the
      // ceremony this credential will finalize, so Device 2 creates against
      // exactly what the server verifies. The display strings do not: WebAuthn
      // never verifies them, and the linked device labels itself distinctly so
      // the two credentials are tellable apart in the authenticator.
      const passkeyName = linkedDevicePasskeyName(String(input.preparation.walletId));
      const credential = await args.authenticator.run({
        kind: 'create_passkey',
        rpId: toRpId(registration.rpId),
        userHandleB64u: registration.user.idB64u,
        userName: passkeyName,
        userDisplayName: passkeyName,
        challengeB64u: registration.challengeB64u,
        requirePrfFirst: true,
        authenticatorOptions: { userVerification: 'required' },
      });
      if (!credential.ok) {
        throw new Error(`linked-device passkey creation failed: ${credential.message}`);
      }
      if (credential.operation !== 'create_passkey' || !credential.requirePrfFirst) {
        throw new Error('linked-device passkey creation returned the wrong operation result');
      }
      const webauthnRegistration = registrationProjection(credential);
      const factorSecret = base64UrlDecode(credential.prf.prfFirstB64u);
      if (factorSecret.byteLength !== 32) {
        zeroizeLiveBytes(factorSecret);
        throw new Error('linked-device passkey PRF output must be 32 bytes');
      }
      return {
        webauthnRegistration,
        factorSecret,
      };
    },
  };
}
