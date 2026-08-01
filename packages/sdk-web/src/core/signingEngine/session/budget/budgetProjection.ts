import type { SigningSessionStatus } from '@/core/types/seams';
import type { SigningGrantId } from '../operationState/types';

export type WalletBudgetUnknownReason =
  | 'adapter_unavailable'
  | 'missing_trusted_status'
  | 'status_unavailable';

export function budgetUnknownSigningSessionStatus(args: {
  signingGrantId: SigningGrantId | string;
  reason: WalletBudgetUnknownReason;
}): SigningSessionStatus {
  return {
    sessionId: String(args.signingGrantId),
    status: 'budget_unknown',
    statusCode: args.reason,
  };
}
