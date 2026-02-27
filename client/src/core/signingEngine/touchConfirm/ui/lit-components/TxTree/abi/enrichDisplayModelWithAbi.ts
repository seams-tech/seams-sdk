import type {
  GenericContractCallOperation,
  TxDisplayField,
  TxDisplayModel,
  TxDisplayOperation,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { decodeCallDataWithAbi } from './abiDecode';

function isGenericContractCallOperation(
  operation: TxDisplayOperation,
): operation is GenericContractCallOperation {
  return operation.kind === 'generic.contractCall';
}

function rewriteCallingLabel(label: string, functionLabel: string): string {
  const normalized = String(label || '').trim();
  const match = normalized.match(/^Calling\s+.+?\s+using\s+(.+)$/i);
  if (!match) return normalized;
  return `Calling ${functionLabel} using ${match[1]}`;
}

function upsertField(fields: TxDisplayField[] | undefined, field: TxDisplayField): TxDisplayField[] {
  const next = Array.isArray(fields) ? [...fields] : [];
  const existingIndex = next.findIndex((entry) => entry.label === field.label);
  if (existingIndex >= 0) {
    next[existingIndex] = {
      ...next[existingIndex],
      ...field,
    };
    return next;
  }
  next.push(field);
  return next;
}

function maybeDecodeOperationWithAbi(
  operation: GenericContractCallOperation,
): GenericContractCallOperation {
  const hint = operation.abiDecodeHint;
  if (!hint || !Array.isArray(hint.abi) || hint.abi.length === 0) {
    return operation;
  }

  const decoded = decodeCallDataWithAbi({
    dataHex: hint.dataHex,
    abi: hint.abi,
  });
  if (!decoded) return operation;

  let fields = upsertField(operation.fields, {
    label: 'Function',
    value: decoded.functionSignature,
  });

  if (decoded.decodedArgumentsText) {
    const decodedArgsField: TxDisplayField = {
      label: 'Decoded Args',
      value: decoded.decodedArgumentsText,
    };
    if (decoded.decodedArgumentsText.includes('\n')) {
      decodedArgsField.renderAs = 'file-content';
    }
    fields = upsertField(fields, decodedArgsField);
  }

  return {
    ...operation,
    label: rewriteCallingLabel(operation.label, decoded.functionLabel),
    fields,
  };
}

function enrichOperation(operation: TxDisplayOperation): TxDisplayOperation {
  const children = Array.isArray(operation.children)
    ? operation.children.map((child) => enrichOperation(child))
    : operation.children;
  const operationWithChildren =
    children === operation.children
      ? operation
      : ({
          ...operation,
          children,
        } as TxDisplayOperation);

  if (!isGenericContractCallOperation(operationWithChildren)) {
    return operationWithChildren;
  }
  return maybeDecodeOperationWithAbi(operationWithChildren);
}

export function enrichDisplayModelWithAbi(model: TxDisplayModel): TxDisplayModel {
  if (!Array.isArray(model.operations) || model.operations.length === 0) {
    return model;
  }
  const operations = model.operations.map((operation) => enrichOperation(operation));
  return {
    ...model,
    operations,
  };
}
