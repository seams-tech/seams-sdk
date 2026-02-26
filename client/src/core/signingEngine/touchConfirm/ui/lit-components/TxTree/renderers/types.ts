import type {
  TxDisplayField,
  TxDisplayOperation,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';

export type RenderTreeNodeType = 'folder' | 'file';

export interface RenderTreeNode {
  id: string;
  label: string;
  type: RenderTreeNodeType;
  open?: boolean;
  content?: string;
  children?: RenderTreeNode[];
  copyValue?: string;
  contractAddress?: string;
  hideLabel?: boolean;
  hideChevron?: boolean;
}

export type RenderDisplayOperation = (args: {
  operation: TxDisplayOperation;
  depth: number;
  path: string;
  renderChild: (operation: TxDisplayOperation, depth: number, path: string) => RenderTreeNode;
}) => RenderTreeNode;

function isZeroWeiDisplayField(label: string, value: string): boolean {
  if (!/Value \(wei\)$/i.test(label.trim())) return false;
  const normalized = value.trim();
  if (!normalized) return false;
  if (normalized === '0') return true;
  if (/^0x0+$/i.test(normalized)) return true;
  try {
    return BigInt(normalized) === 0n;
  } catch {
    return false;
  }
}

export function buildFieldNodes(parentId: string, fields?: TxDisplayField[]): RenderTreeNode[] {
  if (!Array.isArray(fields) || fields.length === 0) return [];
  return fields.flatMap((field, fieldIndex) => {
    const label = String(field.label || '').trim();
    const value = String(field.value || '');
    const renderAs = field.renderAs || 'inline';
    if (isZeroWeiDisplayField(label, value)) return [];
    if (renderAs === 'file-content') {
      return [
        {
          id: `${parentId}-field-${fieldIndex}`,
          label: label ? `${label}:` : '',
          type: 'file',
          open: false,
          content: value,
          copyValue: typeof field.copyValue === 'string' ? field.copyValue : undefined,
          hideLabel: Boolean(field.hideLabel),
          hideChevron: typeof field.hideChevron === 'boolean' ? field.hideChevron : true,
        },
      ];
    }
    return [
      {
        id: `${parentId}-field-${fieldIndex}`,
        label: label ? `${label}: ${value}` : value,
        type: 'file',
        open: false,
        copyValue: typeof field.copyValue === 'string' ? field.copyValue : undefined,
      },
    ];
  });
}
