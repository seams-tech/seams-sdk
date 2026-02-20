import type { TxDisplayOperation } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { renderFallbackDisplayOperation } from './fallback';
import type { RenderDisplayOperation } from './types';

export function isTempoDisplayOperation(operation: TxDisplayOperation): boolean {
  return operation.kind === 'tempo.eip2718';
}

export const renderTempoDisplayOperation: RenderDisplayOperation = (args) => {
  return renderFallbackDisplayOperation(args);
};
