import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';

export type HydrateEmailOtpEd25519RecoveryCodeSigningSessionInput = {
  sessionId: string;
  recoveryCodeSecret32B64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: WarmSessionSealTransportInput;
};

export type EmailOtpEd25519RecoveryCodeSigningSessionHydration = {
  hydrateRecoveryCodeSigningSession: (
    input: HydrateEmailOtpEd25519RecoveryCodeSigningSessionInput,
  ) => Promise<void>;
};

export type WarmSessionHydrationPort = {
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
};

class EmailOtpEd25519RecoveryCodeWarmSessionHydration
  implements EmailOtpEd25519RecoveryCodeSigningSessionHydration
{
  constructor(private readonly port: WarmSessionHydrationPort) {}

  async hydrateRecoveryCodeSigningSession(
    input: HydrateEmailOtpEd25519RecoveryCodeSigningSessionInput,
  ): Promise<void> {
    await this.port.hydrateSigningSession({
      sessionId: input.sessionId,
      prfFirstB64u: input.recoveryCodeSecret32B64u,
      expiresAtMs: input.expiresAtMs,
      remainingUses: input.remainingUses,
      ...(input.transport ? { transport: input.transport } : {}),
    });
  }
}

export function createEmailOtpEd25519RecoveryCodeWarmSessionHydration(
  port: WarmSessionHydrationPort,
): EmailOtpEd25519RecoveryCodeSigningSessionHydration {
  return new EmailOtpEd25519RecoveryCodeWarmSessionHydration(port);
}
