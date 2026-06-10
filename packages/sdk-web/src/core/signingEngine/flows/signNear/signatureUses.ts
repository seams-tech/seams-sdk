import type { TransactionInputWasm } from '@/core/types/actions';

export function requiredNearTransactionSignatureUses(
  transactions: readonly TransactionInputWasm[],
): number {
  return Math.max(1, transactions.length);
}
