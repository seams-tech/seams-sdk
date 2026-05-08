import type {
  GenericContractCallOperation,
  TxDisplayField,
  TxDisplayModel,
  TxDisplayOperation,
} from '@/core/signingEngine/interfaces/display';
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

function isDataField(field: TxDisplayField): boolean {
  return String(field.label || '')
    .trim()
    .toLowerCase() === 'data';
}

function rewriteDataFieldWithDecodedArgs(args: {
  fields: TxDisplayField[] | undefined;
  decodedArgsJsonText: string;
  fallbackRawDataHex: string;
}): TxDisplayField[] {
  const next = Array.isArray(args.fields) ? [...args.fields] : [];
  const dataFieldIndex = next.findIndex((field) => isDataField(field));
  const existingDataField = dataFieldIndex >= 0 ? next[dataFieldIndex] : undefined;
  const rawFallbackValue =
    String(existingDataField?.value || '').trim() || String(args.fallbackRawDataHex || '').trim();
  const rewrittenDataField: TxDisplayField = {
    ...(existingDataField || { label: 'Data' }),
    value: args.decodedArgsJsonText,
    renderAs: 'file-content',
    hideChevron:
      typeof existingDataField?.hideChevron === 'boolean' ? existingDataField.hideChevron : true,
    contentVariants: {
      decoded: args.decodedArgsJsonText,
      raw: rawFallbackValue,
      defaultMode: 'decoded',
    },
  };

  if (dataFieldIndex >= 0) {
    next[dataFieldIndex] = rewrittenDataField;
    return next;
  }

  next.push(rewrittenDataField);
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

  const fields = decoded.decodedArgumentsJsonText
    ? rewriteDataFieldWithDecodedArgs({
        fields: operation.fields,
        decodedArgsJsonText: decoded.decodedArgumentsJsonText,
        fallbackRawDataHex: hint.dataHex,
      })
    : operation.fields;

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
