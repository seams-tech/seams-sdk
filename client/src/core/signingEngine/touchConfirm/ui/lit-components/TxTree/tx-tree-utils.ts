import type {
  TxDisplayModel,
  TxDisplayOperation,
  TxDisplayWarning,
  DisplayChain,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { isNearDisplayOperation, renderNearDisplayOperation } from './renderers/near';
import { isEvmDisplayOperation, renderEvmDisplayOperation } from './renderers/evm';
import { isTempoDisplayOperation, renderTempoDisplayOperation } from './renderers/tempo';
import { renderFallbackDisplayOperation } from './renderers/fallback';
import type { RenderDisplayOperation, RenderTreeNode } from './renderers/types';

export type TreeNodeType = 'folder' | 'file';

export interface TreeNode {
  id: string;
  label: string;
  type: TreeNodeType;
  open?: boolean;
  content?: string;
  children?: TreeNode[];
  copyValue?: string;
  hideChevron?: boolean;
  hideLabel?: boolean;
}

function toChainLabel(chain: DisplayChain): string {
  switch (chain) {
    case 'near':
      return 'NEAR';
    case 'evm':
      return 'EVM';
    case 'tempo':
      return 'Tempo';
    default:
      return 'Unknown';
  }
}

function buildWarningNodes(warnings?: TxDisplayWarning[]): TreeNode[] {
  if (!Array.isArray(warnings) || warnings.length === 0) return [];
  const children: TreeNode[] = warnings.map((warning, warningIndex) => ({
    id: `warning-${warningIndex}`,
    label: `[${String(warning.severity || 'warning').toUpperCase()}] ${String(warning.message || '')}`,
    type: 'file',
    open: false,
  }));
  return [
    {
      id: 'warnings-root',
      label: 'Warnings',
      type: 'folder',
      open: true,
      children,
    },
  ];
}

function selectOperationRenderer(operation: TxDisplayOperation): RenderDisplayOperation {
  if (isNearDisplayOperation(operation)) return renderNearDisplayOperation;
  if (isEvmDisplayOperation(operation)) return renderEvmDisplayOperation;
  if (isTempoDisplayOperation(operation)) return renderTempoDisplayOperation;
  return renderFallbackDisplayOperation;
}

function renderOperationNode(operation: TxDisplayOperation, depth: number, path: string): TreeNode {
  const renderer = selectOperationRenderer(operation);
  const rendered = renderer({
    operation,
    depth,
    path,
    renderChild: (childOperation, childDepth, childPath) =>
      renderOperationNode(childOperation, childDepth, childPath) as RenderTreeNode,
  });
  return rendered as TreeNode;
}

export function buildDisplayTreeFromModel(model: TxDisplayModel): TreeNode {
  const operations = Array.isArray(model.operations) ? model.operations : [];
  const operationNodes = operations.map((operation, operationIndex) =>
    renderOperationNode(operation, 0, String(operationIndex))
  );
  const warningNodes = buildWarningNodes(model.warnings);
  const rootChildren = [...warningNodes, ...operationNodes];

  if (rootChildren.length === 0) {
    rootChildren.push({
      id: 'no-operations',
      label: 'No operations',
      type: 'file',
      open: false,
    });
  }

  const chainLabel = toChainLabel(model.chain);
  const title = String(model.title || '').trim();
  return {
    id: 'display-root',
    label: title || `${chainLabel} Transaction`,
    type: 'folder',
    open: true,
    children: rootChildren,
  };
}
