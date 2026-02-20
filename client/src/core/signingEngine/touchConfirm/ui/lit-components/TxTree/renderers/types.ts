import type { TxDisplayField, TxDisplayOperation } from '@/core/signingEngine/touchConfirm/shared/displayModel';

export type RenderTreeNodeType = 'folder' | 'file';

export interface RenderTreeNode {
  id: string;
  label: string;
  type: RenderTreeNodeType;
  open?: boolean;
  content?: string;
  children?: RenderTreeNode[];
  copyValue?: string;
}

export type RenderDisplayOperation = (args: {
  operation: TxDisplayOperation;
  depth: number;
  path: string;
  renderChild: (operation: TxDisplayOperation, depth: number, path: string) => RenderTreeNode;
}) => RenderTreeNode;

export function buildFieldNodes(parentId: string, fields?: TxDisplayField[]): RenderTreeNode[] {
  if (!Array.isArray(fields) || fields.length === 0) return [];
  return fields.map((field, fieldIndex) => {
    const label = String(field.label || '').trim();
    const value = String(field.value || '');
    return {
      id: `${parentId}-field-${fieldIndex}`,
      label: label ? `${label}: ${value}` : value,
      type: 'file',
      open: false,
      copyValue: typeof field.copyValue === 'string' ? field.copyValue : undefined,
    };
  });
}
