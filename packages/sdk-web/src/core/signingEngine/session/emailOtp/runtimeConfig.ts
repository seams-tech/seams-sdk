import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';

export type EmailOtpRuntimeConfigPorts = {
  configs: SeamsConfigsReadonly;
  getRpId: () => string | null;
};

export class EmailOtpRuntimeConfig {
  constructor(private readonly ports: EmailOtpRuntimeConfigPorts) {}

  requireRelayUrl(): string {
    const relayUrl = String(this.ports.configs.network.relayer?.url || '').trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    return relayUrl;
  }

  requireSigningSessionSealGroupId(): string {
    return SIGNING_SESSION_SEAL_GROUP_ID;
  }

  requireRpId(operation: string): string {
    const rpId = String(this.ports.getRpId() || '').trim();
    if (!rpId) {
      throw new Error(`${operation} requires an RP ID for ECDSA bootstrap`);
    }
    return rpId;
  }
}
