import type {
  WalletSigningBudgetEcdsaBindings,
  WalletSigningBudgetSessionRecord,
  WalletSigningBudgetSessionStatus,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import { parseWalletSigningBudgetSessionRecord } from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';

/** ECDSA-only wallet signing-budget session status, with the record part routed
 * through the production `parseWalletSigningBudgetSessionRecord` boundary and
 * the budget projection derived the way the production store status projection
 * derives it (available = committed - reserved; remaining = available).
 *
 * The browser status reader fixture cannot express this store-status type, so
 * the builder lives here. */
export function createEcdsaOnlyWalletSigningBudgetSessionStatus(args: {
  walletId: string;
  expiresAtMs: number;
  ecdsaBindings: WalletSigningBudgetEcdsaBindings;
  committedRemainingUses: number;
  reservedUses?: number;
}): WalletSigningBudgetSessionStatus {
  const parsedRecord = parseWalletSigningBudgetSessionRecord({
    kind: 'wallet_signing_budget_session',
    expiresAtMs: args.expiresAtMs,
    walletId: args.walletId,
    bindings: { kind: 'ecdsa_only', ecdsa: args.ecdsaBindings },
  });
  if (!parsedRecord) {
    throw new Error(
      'walletSigningBudgetStatus fixture no longer parses through the production budget-record boundary',
    );
  }
  const record: WalletSigningBudgetSessionRecord = parsedRecord;
  const reservedUses = args.reservedUses ?? 0;
  const availableUses = Math.max(0, args.committedRemainingUses - reservedUses);
  return {
    record,
    expiresAtMs: args.expiresAtMs,
    committedRemainingUses: args.committedRemainingUses,
    reservedUses,
    availableUses,
    remainingUses: availableUses,
  };
}
