import type { AccountId } from '@/core/types/accountIds';

export type NearSigningKeyOps = {
  deriveThresholdEd25519ClientVerifyingShare(args: {
    sessionId: string;
    nearAccountId: AccountId;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }>;
  deriveThresholdEd25519HssClientInputs(args: {
    sessionId: string;
    applicationBindingDigestB64u: string;
    participantIds: number[];
    prfFirstB64u: string;
  }): Promise<{
    success: boolean;
    applicationBindingDigestB64u: string;
    participantIds: number[];
    contextBindingB64u: string;
    yClientB64u: string;
    tauClientB64u: string;
    error?: string;
  }>;
};
