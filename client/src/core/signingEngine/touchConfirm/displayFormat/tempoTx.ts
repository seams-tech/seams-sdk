import type { TempoCall, TempoSigningRequest } from '@/core/signingEngine/chainAdaptors/tempo/types';
import type {
  TxDisplayField,
  TxDisplayModel,
  TempoTypedOperation,
  GenericContractCallOperation,
  TxDisplayOperation,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';

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

function makeField(label: string, value: string | undefined, copyValue?: string): TxDisplayField | undefined {
  const normalized = String(value ?? '').trim();
  if (!normalized) return undefined;
  return {
    label,
    value: normalized,
    ...(typeof copyValue === 'string' && copyValue.trim() ? { copyValue } : {}),
  };
}

function selectorFromHexData(data: string | undefined): string | undefined {
  const normalized = String(data || '').trim();
  if (!normalized.startsWith('0x') || normalized.length < 10) return undefined;
  return normalized.slice(0, 10);
}

function buildCallOperation(call: TempoCall, callIndex: number): GenericContractCallOperation {
  const to = String(call.to || '').trim();
  const input = String(call.input || '0x');
  const selector = selectorFromHexData(input);

  const fields: TxDisplayField[] = [
    makeField('To', to, to),
    makeField('Value (wei)', call.value.toString()),
    makeField('Input', input, input),
    makeField('Selector', selector, selector),
  ].filter(Boolean) as TxDisplayField[];

  return {
    id: `tempo.call.${callIndex}`,
    kind: 'generic.contractCall',
    label: `Call ${callIndex + 1}`,
    to,
    value: call.value.toString(),
    selector,
    fields,
  };
}

function buildTempoOperation(request: TempoSigningRequest): TxDisplayOperation {
  if (request.kind !== 'tempoTransaction') {
    return {
      id: 'tempo.raw',
      kind: 'raw.fallback',
      label: 'Unsupported Tempo Payload',
      raw: toSafeJson(request),
    };
  }

  const tx = request.tx;
  const calls = Array.isArray(tx.calls) ? tx.calls : [];
  if (!calls.length) {
    return {
      id: 'tempo.raw',
      kind: 'raw.fallback',
      label: 'Tempo Payload Missing Calls',
      raw: toSafeJson(request),
    };
  }

  const fields: TxDisplayField[] = [
    makeField('Kind', 'Tempo Transaction (0x76)'),
    makeField('Chain ID', tx.chainId.toString()),
    makeField('Nonce', tx.nonce.toString()),
    makeField('Nonce Key', tx.nonceKey.toString()),
    makeField('Gas Limit', tx.gasLimit.toString()),
    makeField('Max Fee Per Gas', tx.maxFeePerGas.toString()),
    makeField('Max Priority Fee Per Gas', tx.maxPriorityFeePerGas.toString()),
    makeField('Call Count', String(calls.length)),
    makeField('Valid Before', tx.validBefore == null ? undefined : tx.validBefore.toString()),
    makeField('Valid After', tx.validAfter == null ? undefined : tx.validAfter.toString()),
    makeField('Fee Token', tx.feeToken == null ? undefined : String(tx.feeToken), tx.feeToken == null ? undefined : String(tx.feeToken)),
  ].filter(Boolean) as TxDisplayField[];

  const operation: TempoTypedOperation = {
    id: 'tempo.tx',
    kind: 'tempo.eip2718',
    label: 'Tempo Transaction',
    txTypeHex: '0x76',
    txTypeName: 'TempoTransaction',
    fields,
    children: calls.map((call, index) => buildCallOperation(call, index)),
  };

  return operation;
}

export function buildTempoDisplayModel(args: BuildTempoDisplayModelArgs): TxDisplayModel {
  const operation = buildTempoOperation(args.request);

  let totalValue = BigInt(0);
  if (args.request.kind === 'tempoTransaction') {
    for (const call of args.request.tx.calls || []) {
      totalValue += BigInt(call.value || 0);
    }
  }

  return {
    chain: 'tempo',
    intentDigest: args.intentDigest,
    signerAccount: args.signerAccount,
    title: args.title || 'Tempo Transaction',
    subtitle: args.subtitle,
    operations: [operation],
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
