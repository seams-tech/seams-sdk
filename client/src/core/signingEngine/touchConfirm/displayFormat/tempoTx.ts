import type { TempoCall, TempoSigningRequest } from '@/core/signingEngine/chainAdaptors/tempo/types';
import { resolveFunctionSignature, selectorFromHexData } from './functionSelectors';
import type {
  TxDisplayField,
  TxDisplayModel,
  TempoTypedOperation,
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

function buildCallFields(call: TempoCall, callIndex: number, callCount: number): TxDisplayField[] {
  const to = String(call.to || '').trim();
  const input = String(call.input || '0x');
  const selector = selectorFromHexData(input);
  const functionSignature = resolveFunctionSignature(selector);
  const prefix = callCount > 1 ? `Call ${callIndex + 1} ` : '';

  return [
    makeField(`${prefix}To`, to, to),
    makeField(`${prefix}Value (wei)`, call.value.toString()),
    makeField(`${prefix}Input`, input, input),
    makeField(`${prefix}Function`, functionSignature),
    makeField(`${prefix}Selector`, selector, selector),
  ].filter(Boolean) as TxDisplayField[];
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
    makeField('Nonce', tx.nonce.toString()),
    makeField('Gas Limit', tx.gasLimit.toString()),
    makeField('Valid Before', tx.validBefore == null ? undefined : tx.validBefore.toString()),
    makeField('Valid After', tx.validAfter == null ? undefined : tx.validAfter.toString()),
    makeField('Fee Token', tx.feeToken == null ? undefined : String(tx.feeToken), tx.feeToken == null ? undefined : String(tx.feeToken)),
    ...calls.flatMap((call, index) => buildCallFields(call, index, calls.length)),
  ].filter(Boolean) as TxDisplayField[];

  const operation: TempoTypedOperation = {
    id: 'tempo.tx',
    kind: 'tempo.eip2718',
    label: 'Tempo Transaction',
    txTypeHex: '0x76',
    txTypeName: 'TempoTransaction',
    fields,
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
    chainId: args.request.kind === 'tempoTransaction' ? args.request.tx.chainId.toString() : undefined,
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
