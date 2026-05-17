import type { TxDisplayOperation } from '@/core/signingEngine/interfaces/display';
import { renderFallbackDisplayOperation } from './fallback';
import type { RenderDisplayOperation } from './types';

export function isEvmDisplayOperation(operation: TxDisplayOperation): boolean {
  return operation.kind === 'generic.contractCall';
}

export const renderEvmDisplayOperation: RenderDisplayOperation = (args) => {
  return renderFallbackDisplayOperation(args);
};
