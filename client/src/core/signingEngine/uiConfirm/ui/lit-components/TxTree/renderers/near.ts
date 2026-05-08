import type { TxDisplayOperation } from '@/core/signingEngine/interfaces/display';
import { renderFallbackDisplayOperation } from './fallback';
import type { RenderDisplayOperation } from './types';

export function isNearDisplayOperation(operation: TxDisplayOperation): boolean {
  return operation.kind === 'near.action';
}

export const renderNearDisplayOperation: RenderDisplayOperation = (args) => {
  return renderFallbackDisplayOperation(args);
};
