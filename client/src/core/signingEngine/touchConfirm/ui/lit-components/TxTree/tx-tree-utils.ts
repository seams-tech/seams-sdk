import type {
  TxDisplayModel,
  TxDisplayOperation,
  TxDisplayWarning,
  DisplayChain,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';
import type { ActionArgs, TransactionInput } from '@/core/types/actions';
import { formatArgs, formatCodeSize, shortenPubkey } from '../common/formatters';
import { isString } from '@shared/utils/validation';
import { isNearDisplayOperation, renderNearDisplayOperation } from './renderers/near';
import { isEvmDisplayOperation, renderEvmDisplayOperation } from './renderers/evm';
import { isTempoDisplayOperation, renderTempoDisplayOperation } from './renderers/tempo';
import { renderFallbackDisplayOperation } from './renderers/fallback';
import type { RenderDisplayOperation, RenderTreeNode } from './renderers/types';

export type TreeNodeType = 'folder' | 'file';

// Structured highlight specification for labels
export type HighlightSpec =
  | { transaction: 'receiverId' }
  | { actionType: 'FunctionCall' | 'Transfer' | string; highlightKeys: string[] };

export interface TreeNode {
  id: string;
  label: string;
  type: TreeNodeType;
  chain?: DisplayChain;
  open?: boolean;
  content?: string;
  children?: TreeNode[];
  copyValue?: string;
  contractAddress?: string;
  hideChevron?: boolean;
  hideLabel?: boolean;
  highlight?: {
    type: 'receiverId' | 'methodName';
    color: string;
  };
  highlightSpec?: HighlightSpec;
  action?: ActionArgs;
  actionIndex?: number;
  transaction?: TransactionInput;
  transactionIndex?: number;
  totalTransactions?: number;
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

function hideFolderChevrons(node: TreeNode): TreeNode {
  const children = Array.isArray(node.children)
    ? node.children.map((child) => hideFolderChevrons(child))
    : undefined;
  if (node.type !== 'folder') {
    return children ? { ...node, children } : node;
  }
  return {
    ...node,
    hideChevron: true,
    children,
  };
}

function attachChainToNode(node: TreeNode, chain: DisplayChain): TreeNode {
  const children = Array.isArray(node.children)
    ? node.children.map((child) => attachChainToNode(child, chain))
    : undefined;
  return {
    ...node,
    chain,
    ...(children ? { children } : {}),
  };
}

export function buildDisplayTreeFromModel(model: TxDisplayModel): TreeNode {
  const hideModelFolderChevrons = model.chain === 'evm' || model.chain === 'tempo';
  const operations = Array.isArray(model.operations) ? model.operations : [];
  const operationNodes = operations
    .map((operation, operationIndex) => renderOperationNode(operation, 0, String(operationIndex)))
    .map((node) => attachChainToNode(node, model.chain))
    .map((node) => (hideModelFolderChevrons ? hideFolderChevrons(node) : node));
  const warningNodes = buildWarningNodes(model.warnings)
    .map((node) => attachChainToNode(node, model.chain))
    .map((node) => (hideModelFolderChevrons ? hideFolderChevrons(node) : node));
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

function buildActionNode(action: ActionArgs, idx: number): TreeNode {
  let actionNodes: TreeNode[];

  switch (action.type) {
    case 'FunctionCall':
      actionNodes = [
        {
          id: `a${idx}-args`,
          label: 'using args:',
          type: 'file',
          open: false,
          hideChevron: true,
          hideLabel: true,
          content: formatArgs(action.args),
        },
      ];
      break;

    case 'Transfer':
      actionNodes = [];
      break;

    case 'CreateAccount':
      actionNodes = [];
      break;

    case 'DeployContract': {
      const codeSize = formatCodeSize(action.code as unknown as string);
      actionNodes = [
        {
          id: `a${idx}-code-size`,
          label: `WASM contract code size: ${codeSize}`,
          type: 'file',
          open: false,
        },
      ];
      break;
    }

    case 'DeployGlobalContract': {
      const code = (action as unknown as { code?: unknown }).code;
      const deployMode = (action as unknown as { deployMode?: unknown }).deployMode;
      const codeSize = formatCodeSize(code as string);
      actionNodes = [
        {
          id: `a${idx}-deploy-mode`,
          label: `mode: ${String(deployMode || '')}`,
          type: 'file',
          open: false,
        },
        {
          id: `a${idx}-code-size`,
          label: `WASM global contract code size: ${codeSize}`,
          type: 'file',
          open: false,
        },
      ];
      break;
    }

    case 'UseGlobalContract': {
      const accountId = (action as unknown as { accountId?: unknown }).accountId;
      const codeHash = (action as unknown as { codeHash?: unknown }).codeHash;
      let label: string;
      if (accountId) {
        label = `by account: ${String(accountId)}`;
      } else if (codeHash) {
        const short = shortenPubkey(String(codeHash), { prefix: 10, suffix: 6 });
        label = `by hash: ${short}`;
      } else {
        label = 'by global contract identifier';
      }
      actionNodes = [
        {
          id: `a${idx}-identifier`,
          label,
          type: 'file',
          open: false,
        },
      ];
      break;
    }

    case 'Stake':
      actionNodes = [
        {
          id: `a${idx}-publicKey`,
          label: `validator: ${shortenPubkey(action.publicKey)}`,
          type: 'file',
          open: true,
          copyValue: action.publicKey,
        },
      ];
      break;

    case 'AddKey': {
      const ak = action.accessKey;
      let permissions = '';
      try {
        const accessKeyObj = isString(ak) ? JSON.parse(ak) : ak;
        permissions = accessKeyObj.permission === 'FullAccess'
          ? 'Full Access'
          : 'Function Call';
      } catch {
        permissions = 'Unknown';
      }
      actionNodes = [
        {
          id: `a${idx}-publicKey`,
          label: `key: ${shortenPubkey(action.publicKey)}`,
          open: false,
          type: 'file',
          copyValue: action.publicKey,
        },
        {
          id: `a${idx}-permissions`,
          label: `permissions: ${permissions}`,
          open: false,
          type: 'file',
        },
      ];
      break;
    }

    case 'DeleteKey':
      actionNodes = [
        {
          id: `a${idx}-publicKey`,
          label: `key: ${shortenPubkey(action.publicKey)}`,
          open: false,
          type: 'file',
          copyValue: action.publicKey,
        },
      ];
      break;

    case 'DeleteAccount':
      actionNodes = [
        {
          id: `a${idx}-beneficiaryId`,
          label: `sending balance to: ${action.beneficiaryId}`,
          open: false,
          type: 'file',
        },
      ];
      break;

    default: {
      let raw = '';
      try { raw = JSON.stringify(action, null, 2); } catch { raw = String(action); }
      actionNodes = [
        {
          id: `a${idx}-action`,
          label: `Action: ${action.type || 'Unknown'}`,
          open: false,
          type: 'file',
        },
        {
          id: `a${idx}-raw`,
          label: 'Raw Data',
          type: 'file',
          open: false,
          content: raw,
        },
      ];
      break;
    }
  }

  return {
    id: `action-${idx}`,
    label: '',
    type: 'folder',
    open: false,
    hideChevron: true,
    action,
    actionIndex: idx,
    children: actionNodes,
  };
}

export function buildTransactionNode(
  tx: TransactionInput,
  tIdx: number,
  totalTransactions: number,
): TreeNode {
  const actionFolders: TreeNode[] = tx.actions.map((action: ActionArgs, idx: number) =>
    buildActionNode(action, idx)
  );

  return {
    id: `tx-${tIdx}`,
    label: '',
    type: 'folder',
    open: true,
    hideChevron: true,
    transaction: tx,
    transactionIndex: tIdx,
    totalTransactions,
    children: [...actionFolders],
  };
}

export function buildDisplayTreeFromTxPayloads(
  txSigningRequests: TransactionInput[],
): TreeNode {
  const totalTransactions = txSigningRequests.length;
  const txFolders: TreeNode[] = txSigningRequests.map((tx: TransactionInput, tIdx: number) =>
    buildTransactionNode(tx, tIdx, totalTransactions)
  );

  return {
    id: 'txs-root',
    label: totalTransactions > 1 ? 'Transactions' : 'Transaction',
    type: 'folder',
    open: true,
    children: txFolders,
  };
}
