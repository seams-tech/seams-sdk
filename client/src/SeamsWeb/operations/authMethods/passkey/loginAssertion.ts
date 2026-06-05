import type { ClientAuthenticatorData } from '@/core/accountData/near/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types';

export type PasskeyLoginAssertionSurface = {
  getAuthenticationCredentialsSerialized(args: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: Array<{
      id: string;
      type: 'public-key';
      transports: AuthenticatorTransport[];
    }>;
    includeSecondPrfOutput: boolean;
  }): Promise<WebAuthnAuthenticationCredential>;
};

export async function collectPasskeyLoginAssertion(args: {
  signingEngine: PasskeyLoginAssertionSurface;
  subjectId: string;
  challengeB64u: string;
  authenticators: readonly ClientAuthenticatorData[];
  onPromptStarted: () => void;
  onPromptSucceeded: () => void;
}): Promise<WebAuthnAuthenticationCredential> {
  const allowCredentials = args.authenticators
    .map((authenticator) => {
      const id = String(authenticator.credentialId || '').trim();
      if (!id) return null;
      return {
        id,
        type: 'public-key' as const,
        transports: Array.isArray(authenticator.transports)
          ? (authenticator.transports as AuthenticatorTransport[])
          : [],
      };
    })
    .filter(
      (
        credential,
      ): credential is {
        id: string;
        type: 'public-key';
        transports: AuthenticatorTransport[];
      } => Boolean(credential),
    );
  args.onPromptStarted();
  const credential = await args.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: args.subjectId,
    challengeB64u: args.challengeB64u,
    allowCredentials,
    includeSecondPrfOutput: false,
  });
  args.onPromptSucceeded();
  return credential;
}
