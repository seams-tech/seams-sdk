import type { SeamsWeb } from '@/web/SeamsWeb';
import { nearAccountRefFromAccountId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SignAndSendTransactionHooksOptions } from '@/core/types/sdkSentEvents';
import {
  fromTransactionInputsWasm,
  type ActionResult,
  type TransactionInput,
  type TransactionInputWasm,
} from '@/core/types';
import { isObject, toTrimmedString } from '@shared/utils/validation';
import type { PmActionName } from './iframe-lit-element-registry';

export type StructuredPrimitive = string | number | boolean | null;
export type StructuredValue =
  | StructuredPrimitive
  | undefined
  | bigint
  | Uint8Array
  | StructuredValue[]
  | { [key: string]: StructuredValue };

export type UiActionArgs = Record<string, StructuredValue>;

type SignAndSendArgs = UiActionArgs & {
  nearAccountId?: string;
  transactions?: TransactionInput[] | TransactionInputWasm[];
  txSigningRequests?: TransactionInput[] | TransactionInputWasm[];
  options?: SignAndSendTransactionHooksOptions;
};

export type PmActionArgsMap = {
  signAndSendTransactions: SignAndSendArgs;
};

export type PmActionResultMap = {
  signAndSendTransactions: ActionResult[];
};

export type PmActionArgs = PmActionArgsMap[PmActionName];
export type PmActionResult = PmActionResultMap[PmActionName];

export type RunPmAction = <T extends PmActionName>(
  action: T,
  args: PmActionArgsMap[T],
) => Promise<PmActionResultMap[T]>;

const isWasmTransactionInput = (
  tx: TransactionInput | TransactionInputWasm,
): tx is TransactionInputWasm => {
  return (
    Array.isArray(tx.actions) &&
    tx.actions.some((action: unknown) => isObject(action) && 'action_type' in action)
  );
};

const normalizeTransactions = (
  candidate?: TransactionInput[] | TransactionInputWasm[],
): TransactionInput[] => {
  if (!Array.isArray(candidate) || candidate.length === 0) return [];
  if (candidate.every(isWasmTransactionInput)) {
    return fromTransactionInputsWasm(candidate as TransactionInputWasm[]);
  }
  return candidate as TransactionInput[];
};

export async function runWalletUiAction<T extends PmActionName>(
  pm: SeamsWeb,
  action: T,
  args: PmActionArgsMap[T],
): Promise<PmActionResultMap[T]> {
  switch (action) {
    case 'signAndSendTransactions': {
      const input = args as SignAndSendArgs;
      const nearAccountId = toTrimmedString(input.nearAccountId);
      const transactions = normalizeTransactions(input.transactions || input.txSigningRequests);
      const options = (input.options || {}) as SignAndSendTransactionHooksOptions;
      if (!nearAccountId || transactions.length === 0) {
        throw new Error('nearAccountId and transactions required');
      }
      return (await pm.near.signAndSendTransactions({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        transactions,
        options,
      })) as PmActionResultMap[T];
    }
  }
  throw new Error(`Unknown pm action: ${String(action)}`);
}
