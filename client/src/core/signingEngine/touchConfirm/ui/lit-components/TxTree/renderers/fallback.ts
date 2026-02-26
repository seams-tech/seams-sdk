import type { TxDisplayOperation } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { buildFieldNodes, type RenderDisplayOperation, type RenderTreeNode } from './types';

export function isFallbackDisplayOperation(_operation: TxDisplayOperation): boolean {
  return true;
}

export const renderFallbackDisplayOperation: RenderDisplayOperation = ({
  operation,
  depth,
  path,
  renderChild,
}) => {
  const opId = String(operation.id || '').trim() || `op-${path}`;
  const contractAddress = (() => {
    const raw = String((operation as { to?: string }).to || '').trim();
    return /^0x[0-9a-fA-F]{40}$/.test(raw) ? raw : undefined;
  })();
  const description = String(operation.description || '').trim();
  const childOps = Array.isArray(operation.children)
    ? operation.children.map((child, childIndex) => renderChild(child, depth + 1, `${path}.${childIndex}`))
    : [];
  const fieldNodes = buildFieldNodes(opId, operation.fields);
  const metadataNodes: RenderTreeNode[] = description
    ? [{ id: `${opId}-description`, label: description, type: 'file', open: false }]
    : [];

  if (operation.kind === 'raw.fallback') {
    const rawValue = String((operation as { raw?: string }).raw || '').trim();
    if (rawValue) {
      metadataNodes.push({
        id: `${opId}-raw`,
        label: 'Raw payload',
        type: 'file',
        open: false,
        content: rawValue,
      });
    }
  }

  const children = [...metadataNodes, ...fieldNodes, ...childOps];
  if (children.length === 0) {
    return {
      id: opId,
      label: String(operation.label || operation.kind),
      type: 'file',
      open: false,
      contractAddress,
    };
  }
  return {
    id: opId,
    label: String(operation.label || operation.kind),
    type: 'folder',
    open: depth < 1,
    contractAddress,
    children,
  };
};
