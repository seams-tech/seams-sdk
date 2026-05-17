import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/types';
import {
  resolveFunctionDisplayName,
  resolveFunctionSignature,
  selectorFromHexData,
} from './functionSelectors';
import { normalizeHexData } from './normalization';
import { formatCalldataForDisplay } from './calldata';
import { formatCompactGas } from './gas';
import type {
  TxDisplayField,
  TxDisplayModel,
  GenericContractCallOperation,
  TxDisplayOperation,
} from '@/core/signingEngine/interfaces/display';

export type BuildEvmDisplayModelArgs = {
  request: EvmSigningRequest;
  intentDigest?: string;
  signerAccount?: string;
  title?: string;
  subtitle?: string;
};

function toSafeJson(value: unknown): string {
  try {
    return JSON.stringify(
      value,
      (_key, fieldValue) => (typeof fieldValue === 'bigint' ? fieldValue.toString() : fieldValue),
      2,
    );
  } catch {
    return String(value);
  }
}

function makeField(
  label: string,
  value: string | undefined,
  copyValue?: string,
): TxDisplayField | undefined {
  const normalized = String(value ?? '').trim();
  if (!normalized) return undefined;
  return {
    label,
    value: normalized,
    ...(typeof copyValue === 'string' && copyValue.trim() ? { copyValue } : {}),
  };
}

function shortenHexAddress(address: string | undefined): string {
  const normalized = String(address || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(normalized)) return normalized;
  return `${normalized.slice(0, 8)}...${normalized.slice(-4)}`;
}

function buildAbiDecodeHint(args: {
  dataHex: string | undefined;
  abi: EvmSigningRequest['tx']['abi'];
}): GenericContractCallOperation['abiDecodeHint'] | undefined {
  const normalizedDataHex = normalizeHexData(args.dataHex);
  if (normalizedDataHex === '0x') return undefined;
  if (!Array.isArray(args.abi) || args.abi.length === 0) return undefined;
  return {
    dataHex: normalizedDataHex,
    abi: args.abi as readonly Record<string, unknown>[],
  };
}

function buildDefaultContractCallOperation(args: {
  to?: string;
  valueWei: string;
  tx: EvmSigningRequest['tx'];
  dataHex: string;
  selector?: string;
}): GenericContractCallOperation {
  const functionLabel = resolveFunctionDisplayName(args.selector, args.to);
  const hasCallData = !!args.to && args.dataHex !== '0x';
  const formattedGasLimit = formatCompactGas(args.tx.gasLimit);
  const rowLabel = args.to
    ? `Transaction to contract ${shortenHexAddress(args.to)}`
    : 'Contract Deployment';
  const dataField = makeField('Data', formatCalldataForDisplay(args.dataHex), args.dataHex);
  if (dataField) {
    dataField.renderAs = 'file-content';
    dataField.hideLabel = true;
    dataField.hideChevron = true;
  }

  const callFields: TxDisplayField[] = [dataField, makeField('Value (wei)', args.valueWei)].filter(
    Boolean,
  ) as TxDisplayField[];

  let children: TxDisplayOperation[] | undefined;
  if (hasCallData) {
    const childOperation: GenericContractCallOperation = {
      id: 'evm.eip1559.call',
      kind: 'generic.contractCall',
      label: `Calling ${functionLabel || 'contract function'} using ${formattedGasLimit} gas`,
      to: args.to,
      value: args.valueWei,
      selector: args.selector,
      fields: callFields,
    };
    const abiDecodeHint = buildAbiDecodeHint({
      dataHex: args.dataHex,
      abi: args.tx.abi,
    });
    if (abiDecodeHint) {
      childOperation.abiDecodeHint = abiDecodeHint;
    }
    children = [childOperation];
  }

  return {
    id: 'evm.eip1559',
    kind: 'generic.contractCall',
    label: rowLabel,
    to: args.to,
    value: args.valueWei,
    selector: args.selector,
    ...(children ? { children } : {}),
  };
}

export function buildEvmDisplayModel(args: BuildEvmDisplayModelArgs): TxDisplayModel {
  const request = args.request;
  if (request.kind !== 'eip1559') {
    return {
      chain: 'evm',
      intentDigest: args.intentDigest,
      signerAccount: args.signerAccount,
      title: args.title || 'EVM Transaction',
      subtitle: args.subtitle,
      operations: [
        {
          id: 'evm.raw',
          kind: 'raw.fallback',
          label: 'Unsupported EVM Payload',
          raw: toSafeJson(request),
        },
      ],
      raw: {
        format: 'json',
        value: toSafeJson(request),
      },
    };
  }

  const tx = request.tx;
  const to = tx.to == null ? undefined : String(tx.to).toLowerCase();
  const valueWei = tx.value.toString();
  const dataHex = normalizeHexData(String(tx.data || '0x'));
  const selector = selectorFromHexData(dataHex);

  const operation = buildDefaultContractCallOperation({
    to,
    valueWei,
    tx,
    dataHex,
    selector,
  });
  const totalValueWei = tx.value > 0n ? tx.value : undefined;

  return {
    chain: 'evm',
    chainId: tx.chainId,
    intentDigest: args.intentDigest,
    signerAccount: args.signerAccount,
    title: args.title || 'EVM Transaction',
    subtitle: args.subtitle,
    operations: [operation],
    ...(totalValueWei != null
      ? {
          totals: {
            nativeValue: totalValueWei.toString(),
            nativeSymbol: 'wei',
          },
        }
      : {}),
  };
}
