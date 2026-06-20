import type { TransactionInputWasm } from '@/core/types/actions';

export function requiredNearTransactionSignatureUses(
  transaction: TransactionInputWasm,
): number {
  if (!transaction || !Array.isArray(transaction.actions) || transaction.actions.length === 0) {
    throw new Error('[SigningEngine][near] one NEAR transaction with actions is required');
  }
  return 1;
}

export function rejectNearMultiTransactionSigning(
  transactions: readonly TransactionInputWasm[],
): never {
  throw new Error(
    `[SigningEngine][near] exactly one NEAR transaction is supported per signing operation; received ${transactions.length}`,
  );
}
