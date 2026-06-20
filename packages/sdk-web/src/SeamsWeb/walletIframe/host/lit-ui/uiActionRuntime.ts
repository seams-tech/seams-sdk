import type { SeamsWeb } from '@/SeamsWeb';
import { nearAccountRefFromAccountId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SignAndSendTransactionHooksOptions } from '@/core/types/sdkSentEvents';
import {
  type ActionResult,
  type ActionArgs,
} from '@/core/types';
import { toTrimmedString } from '@shared/utils/validation';
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
  receiverId?: string;
  actions?: ActionArgs[];
  options?: SignAndSendTransactionHooksOptions;
};

export type PmActionArgsMap = {
  signAndSendTransaction: SignAndSendArgs;
};

export type PmActionResultMap = {
  signAndSendTransaction: ActionResult;
};

export type PmActionArgs = PmActionArgsMap[PmActionName];
export type PmActionResult = PmActionResultMap[PmActionName];

export type RunPmAction = <T extends PmActionName>(
  action: T,
  args: PmActionArgsMap[T],
) => Promise<PmActionResultMap[T]>;

export async function runWalletUiAction<T extends PmActionName>(
  pm: SeamsWeb,
  action: T,
  args: PmActionArgsMap[T],
): Promise<PmActionResultMap[T]> {
  switch (action) {
    case 'signAndSendTransaction': {
      const input = args as SignAndSendArgs;
      const nearAccountId = toTrimmedString(input.nearAccountId);
      const receiverId = toTrimmedString(input.receiverId);
      if (!nearAccountId || !receiverId || !Array.isArray(input.actions)) {
        throw new Error('nearAccountId, receiverId, and actions required');
      }
      return (await pm.near.signAndSendTransaction({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        receiverId,
        actions: input.actions,
        options: input.options || {},
      })) as PmActionResultMap[T];
    }
  }
  throw new Error(`Unknown pm action: ${String(action)}`);
}
