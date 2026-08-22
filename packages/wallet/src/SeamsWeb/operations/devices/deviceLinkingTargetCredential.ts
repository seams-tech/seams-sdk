import type { AuthenticatorPort } from '@/core/platform';
import type { LinkedDeviceWebAuthnRegistrationV1 } from '@shared/device-linking';
import { base64UrlDecode } from '@shared/utils/base64';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
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
      const registration = input.preparation.passkeyCreationOptions;
      if (registration.walletAuthMethodId !== input.preparation.walletAuthMethodId) {
        throw new Error('linked-device passkey options are bound to a different auth method');
      }
      const credential = await args.authenticator.run({
        kind: 'create_passkey',
        registrationOptions: registration,
        requirePrfFirst: true,
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
        walletAuthMethodId: registration.walletAuthMethodId,
        webauthnRegistration,
        factorSecret,
      };
    },
  };
}
