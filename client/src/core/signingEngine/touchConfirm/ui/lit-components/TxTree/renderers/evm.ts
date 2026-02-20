import type { TxDisplayOperation } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { renderFallbackDisplayOperation } from './fallback';
import type { RenderDisplayOperation } from './types';

export function isEvmDisplayOperation(operation: TxDisplayOperation): boolean {
  return operation.kind === 'evm.erc4337' || operation.kind === 'generic.contractCall';
}

export const renderEvmDisplayOperation: RenderDisplayOperation = (args) => {
  return renderFallbackDisplayOperation(args);
};
