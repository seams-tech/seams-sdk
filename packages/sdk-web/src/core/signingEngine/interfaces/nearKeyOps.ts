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
};
