import React from 'react';
import type {
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFailure,
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthRequestedMode,
  GoogleEmailOtpWalletAuthResult,
} from '@/SeamsWeb';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { RegistrationFlowEvent, UnlockFlowEvent } from '@/core/types/sdkSentEvents';
import { useSeams } from '@/react/context';

export type UseGoogleEmailOtpWalletAuthOptions = {
  getGoogleIdToken(input: { mode: GoogleEmailOtpWalletAuthRequestedMode }): Promise<string>;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

export type UseGoogleEmailOtpWalletAuthResult = {
  start(input: {
    mode: GoogleEmailOtpWalletAuthRequestedMode;
  }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
  busy: boolean;
  error: GoogleEmailOtpWalletAuthFailure | null;
};

export function useGoogleEmailOtpWalletAuth(
  options: UseGoogleEmailOtpWalletAuthOptions,
): UseGoogleEmailOtpWalletAuthResult {
  const seamsContext = useSeams();
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<GoogleEmailOtpWalletAuthFailure | null>(null);

  const start = React.useCallback(
    async (input: {
      mode: GoogleEmailOtpWalletAuthRequestedMode;
    }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>> => {
      setBusy(true);
      setError(null);
      try {
        const idToken = await options.getGoogleIdToken({ mode: input.mode });
        const result = await seamsContext.seams.auth.beginGoogleEmailOtpWalletAuth({
          idToken,
          mode: input.mode,
          ...(options.relayUrl ? { relayUrl: options.relayUrl } : {}),
          ...(options.sessionKind ? { sessionKind: options.sessionKind } : {}),
          ...(options.ecdsaTargets ? { ecdsaTargets: options.ecdsaTargets } : {}),
          ...(options.emailOtpAuthPolicy
            ? { emailOtpAuthPolicy: options.emailOtpAuthPolicy }
            : {}),
          ...(options.onEvent ? { onEvent: options.onEvent } : {}),
        });
        if (!result.ok) setError(result.error);
        return result;
      } finally {
        setBusy(false);
      }
    },
    [options, seamsContext.seams.auth],
  );

  return { start, busy, error };
}
