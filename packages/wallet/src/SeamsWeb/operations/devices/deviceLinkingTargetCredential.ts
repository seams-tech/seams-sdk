import type { AuthenticatorPort } from '@/core/platform';
import type { DeviceLinkingTargetCredentialPortV1 } from './deviceLinkingPorts';

export function createDeviceLinkingTargetCredentialPortV1(_args: {
  readonly authenticator: AuthenticatorPort;
}): DeviceLinkingTargetCredentialPortV1 {
  return {
    async createTargetCredentialV1() {
      throw new Error(
        'linked-device passkey registration cannot start: target preparation has no WebAuthn RP id, challenge, or user handle',
      );
    },
  };
}
