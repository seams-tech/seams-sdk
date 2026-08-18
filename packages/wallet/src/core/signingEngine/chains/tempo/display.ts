import type {
  TempoCall,
  TempoSigningRequest,
} from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import {
  resolveFunctionDisplayName,
  selectorFromHexData,
} from '../evm/display/functionSelectors';
import { normalizeHexData } from '../evm/display/normalization';
import { formatCalldataForDisplay } from '../evm/display/calldata';
import { formatCompactGas } from '../evm/display/gas';
import type {
  TxDisplayField,
  TxDisplayModel,
  GenericContractCallOperation,
  TempoTypedOperation,
  TxDisplayOperation,
} from '@/core/signingEngine/interfaces/display';

export type BuildTempoDisplayModelArgs = {
  request: TempoSigningRequest;
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

function buildAbiDecodeHint(args: {
  input: string | undefined;
  abi: TempoCall['abi'];
}): GenericContractCallOperation['abiDecodeHint'] | undefined {
  const dataHex = normalizeHexData(args.input);
  if (dataHex === '0x') return undefined;
  if (!Array.isArray(args.abi) || args.abi.length === 0) return undefined;
  return {
    dataHex,
    abi: args.abi as readonly Record<string, unknown>[],
  };
}

function shortenHexAddress(address: string): string {
  const normalized = String(address || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(normalized)) return normalized;
  return `${normalized.slice(0, 8)}...${normalized.slice(-4)}`;
}

function buildTempoCallDetailsOperation(args: {
  rootId: string;
  call: TempoCall;
  tx: Extract<TempoSigningRequest, { kind: 'tempoTransaction' }>['tx'];
}): GenericContractCallOperation | undefined {
  const { rootId, call, tx } = args;
  const to = String(call.to || '').trim();
  const input = normalizeHexData(String(call.input || '0x'));
  if (input === '0x') return undefined;

  const selector = selectorFromHexData(input);
  const functionLabel = resolveFunctionDisplayName(selector, to) || 'contract function';
  const formattedGasLimit = formatCompactGas(tx.gasLimit);
  const inputField = makeField('Data', formatCalldataForDisplay(input), input);
  if (inputField) {
    inputField.renderAs = 'file-content';
    inputField.hideLabel = true;
    inputField.hideChevron = true;
  }
  const fields: TxDisplayField[] = [
    inputField,
    makeField('Value (wei)', call.value.toString()),
    makeField('Valid Before', tx.validBefore == null ? undefined : tx.validBefore.toString()),
    makeField('Valid After', tx.validAfter == null ? undefined : tx.validAfter.toString()),
  ].filter(Boolean) as TxDisplayField[];

  const operation: GenericContractCallOperation = {
    id: `${rootId}.call`,
    kind: 'generic.contractCall',
    label: `Calling ${functionLabel} using ${formattedGasLimit} gas`,
    to,
    value: call.value.toString(),
    selector,
    fields,
  };
  const abiDecodeHint = buildAbiDecodeHint({
    input,
    abi: call.abi,
  });
  if (abiDecodeHint) {
    operation.abiDecodeHint = abiDecodeHint;
  }
  return operation;
}

function buildTempoCallOperation(args: {
  call: TempoCall;
  callIndex: number;
  callCount: number;
  tx: Extract<TempoSigningRequest, { kind: 'tempoTransaction' }>['tx'];
}): TempoTypedOperation {
  const { call, callIndex, callCount, tx } = args;
  const id = `tempo.tx.${callIndex}`;
  const to = String(call.to || '').trim();
  const prefix =
    callCount > 1 ? `Transaction ${callIndex + 1} to contract ` : 'Transaction to contract ';
  const rowLabel = `${prefix}${shortenHexAddress(to) || 'unknown contract'}`;
  const child = buildTempoCallDetailsOperation({ rootId: id, call, tx });
  return {
    id,
    kind: 'tempo.eip2718',
    label: rowLabel,
    txTypeHex: '0x76',
    txTypeName: 'TempoTransaction',
    to,
    selector: selectorFromHexData(normalizeHexData(String(call.input || '0x'))),
    ...(child ? { children: [child] } : {}),
  };
}

function buildTempoOperations(request: TempoSigningRequest): TxDisplayOperation[] {
  if (request.kind !== 'tempoTransaction') {
    return [
      {
        id: 'tempo.raw',
        kind: 'raw.fallback',
        label: 'Unsupported Tempo Payload',
        raw: toSafeJson(request),
      },
    ];
  }

  const calls = Array.isArray(request.tx.calls) ? request.tx.calls : [];
  if (!calls.length) {
    return [
      {
        id: 'tempo.raw',
        kind: 'raw.fallback',
        label: 'Tempo Payload Missing Calls',
        raw: toSafeJson(request),
      },
    ];
  }

  return calls.map((call, callIndex) =>
    buildTempoCallOperation({
      call,
      callIndex,
      callCount: calls.length,
      tx: request.tx,
    }),
  );
}

export function buildTempoDisplayModel(args: BuildTempoDisplayModelArgs): TxDisplayModel {
  const operations = buildTempoOperations(args.request);

  let totalValue = BigInt(0);
  if (args.request.kind === 'tempoTransaction') {
    for (const call of args.request.tx.calls || []) {
      totalValue += BigInt(call.value || 0);
    }
  }

  return {
    chain: 'tempo',
    chainId: args.request.kind === 'tempoTransaction' ? args.request.tx.chainId : undefined,
    intentDigest: args.intentDigest,
    signerAccount: args.signerAccount,
    title: args.title || 'Tempo Transaction',
    subtitle: args.subtitle,
    operations,
    ...(totalValue > 0n
      ? {
          totals: {
            nativeValue: totalValue.toString(),
            nativeSymbol: 'wei',
          },
        }
      : {}),
  };
}
