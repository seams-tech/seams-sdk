import type { EvmSigningRequest } from '@/core/signingEngine/chainAdaptors/evm/types';
import { bytesToHex, hexToBytes } from '@/core/signingEngine/chainAdaptors/evm/bytes';
import {
  resolveFunctionDisplayName,
  resolveFunctionSignature,
  selectorFromHexData,
} from './functionSelectors';
import { formatCalldataForDisplay } from './calldata';
import { formatCompactGas } from './gas';
import type {
  TxDisplayField,
  TxDisplayModel,
  GenericContractCallOperation,
  Erc4337Operation,
  TxDisplayWarning,
  TxDisplayOperation,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';

const EXECUTE_SELECTOR = '0xb61d27f6';
const EXECUTE_BATCH_SELECTOR = '0x47e1da2a';

// Common EntryPoint v0.6/v0.7 selectors for handleOps variants.
const HANDLE_OPS_SELECTORS = new Set<string>([
  '0x1fad948c',
  '0x765e827f',
  '0x1ac9445f',
  '0xd5f160fe',
  '0x8270127c',
  '0xf0288949',
  '0x6a0d5b27',
  '0x7390d0f8',
  '0xf3cf6c3c',
  '0x3856e65b',
  '0x9511c1ce',
  '0xdb08f292',
  '0x95493689',
]);

export type BuildEvmDisplayModelArgs = {
  request: EvmSigningRequest;
  intentDigest?: string;
  signerAccount?: string;
  title?: string;
  subtitle?: string;
};

type DecodedContractCall = {
  to?: string;
  valueWei?: string;
  dataHex: string;
  selector?: string;
  decodedArgs?: string;
};

type DecodedSmartAccountCall = {
  callType: 'execute' | 'executeBatch' | 'custom';
  selector?: string;
  calls: DecodedContractCall[];
  warning?: string;
};

type DecodedUserOperation = {
  sender?: string;
  nonce?: string;
  callDataHex: string;
  decodedCall: DecodedSmartAccountCall;
};

type DecodedHandleOps = {
  selector: string;
  beneficiary?: string;
  userOperations: DecodedUserOperation[];
  warning?: string;
};

type BuiltErc4337Operation = {
  operation: Erc4337Operation;
  warnings: TxDisplayWarning[];
  callValueTotalWei?: bigint;
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

function normalizeHex(input: string | undefined): string {
  const raw = String(input || '').trim();
  if (!raw) return '0x';
  return raw.startsWith('0x') ? raw : `0x${raw}`;
}

function parseHexBytes(hex: string): Uint8Array | undefined {
  try {
    return hexToBytes(normalizeHex(hex));
  } catch {
    return undefined;
  }
}

function readWord(bytes: Uint8Array, byteOffset: number): Uint8Array | undefined {
  if (!Number.isInteger(byteOffset) || byteOffset < 0) return undefined;
  if (byteOffset + 32 > bytes.length) return undefined;
  return bytes.slice(byteOffset, byteOffset + 32);
}

function readWordBigInt(bytes: Uint8Array, byteOffset: number): bigint | undefined {
  const word = readWord(bytes, byteOffset);
  if (!word) return undefined;
  return BigInt(bytesToHex(word));
}

function readWordNumber(bytes: Uint8Array, byteOffset: number): number | undefined {
  const value = readWordBigInt(bytes, byteOffset);
  if (value == null) return undefined;
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  return Number(value);
}

function readWordAddress(bytes: Uint8Array, byteOffset: number): string | undefined {
  const word = readWord(bytes, byteOffset);
  if (!word) return undefined;
  return bytesToHex(word.slice(12)).toLowerCase();
}

function readDynamicBytes(
  bytes: Uint8Array,
  baseOffset: number,
  relativeOffset: number,
): Uint8Array | undefined {
  if (!Number.isInteger(baseOffset) || baseOffset < 0) return undefined;
  if (!Number.isInteger(relativeOffset) || relativeOffset < 0) return undefined;

  const dynamicHeadOffset = baseOffset + relativeOffset;
  const valueLength = readWordNumber(bytes, dynamicHeadOffset);
  if (valueLength == null) return undefined;

  const valueStart = dynamicHeadOffset + 32;
  const valueEnd = valueStart + valueLength;
  if (valueEnd > bytes.length) return undefined;
  return bytes.slice(valueStart, valueEnd);
}

function readAddressArray(
  bytes: Uint8Array,
  baseOffset: number,
  relativeOffset: number,
): string[] | undefined {
  const arrayHeadOffset = baseOffset + relativeOffset;
  const length = readWordNumber(bytes, arrayHeadOffset);
  if (length == null) return undefined;

  const itemHeadOffset = arrayHeadOffset + 32;
  const out: string[] = [];
  for (let i = 0; i < length; i += 1) {
    const itemAddress = readWordAddress(bytes, itemHeadOffset + i * 32);
    if (!itemAddress) return undefined;
    out.push(itemAddress);
  }
  return out;
}

function readBigIntArray(
  bytes: Uint8Array,
  baseOffset: number,
  relativeOffset: number,
): bigint[] | undefined {
  const arrayHeadOffset = baseOffset + relativeOffset;
  const length = readWordNumber(bytes, arrayHeadOffset);
  if (length == null) return undefined;

  const itemHeadOffset = arrayHeadOffset + 32;
  const out: bigint[] = [];
  for (let i = 0; i < length; i += 1) {
    const itemValue = readWordBigInt(bytes, itemHeadOffset + i * 32);
    if (itemValue == null) return undefined;
    out.push(itemValue);
  }
  return out;
}

function readBytesArray(
  bytes: Uint8Array,
  baseOffset: number,
  relativeOffset: number,
): Uint8Array[] | undefined {
  const arrayHeadOffset = baseOffset + relativeOffset;
  const length = readWordNumber(bytes, arrayHeadOffset);
  if (length == null) return undefined;

  const tupleHeadOffset = arrayHeadOffset + 32;
  const out: Uint8Array[] = [];
  for (let i = 0; i < length; i += 1) {
    const itemOffset = readWordNumber(bytes, tupleHeadOffset + i * 32);
    if (itemOffset == null) return undefined;
    const value = readDynamicBytes(bytes, tupleHeadOffset, itemOffset);
    if (!value) return undefined;
    out.push(value);
  }
  return out;
}

function decodeExecuteCallData(callDataHex: string): DecodedSmartAccountCall {
  const bytes = parseHexBytes(callDataHex);
  if (!bytes || bytes.length < 4 + 32 * 3) {
    return {
      callType: 'execute',
      selector: EXECUTE_SELECTOR,
      calls: [
        {
          dataHex: normalizeHex(callDataHex),
          selector: EXECUTE_SELECTOR,
        },
      ],
      warning: 'Failed to decode execute(address,uint256,bytes) calldata',
    };
  }

  const paramsOffset = 4;
  const to = readWordAddress(bytes, paramsOffset);
  const valueWei = readWordBigInt(bytes, paramsOffset + 32);
  const dataOffset = readWordNumber(bytes, paramsOffset + 64);
  const dataBytes =
    dataOffset == null ? undefined : readDynamicBytes(bytes, paramsOffset, dataOffset);

  if (!to || valueWei == null || !dataBytes) {
    return {
      callType: 'execute',
      selector: EXECUTE_SELECTOR,
      calls: [
        {
          dataHex: normalizeHex(callDataHex),
          selector: EXECUTE_SELECTOR,
        },
      ],
      warning: 'Failed to decode execute(address,uint256,bytes) arguments',
    };
  }

  const nestedCallDataHex = bytesToHex(dataBytes);
  return {
    callType: 'execute',
    selector: EXECUTE_SELECTOR,
    calls: [
      {
        to,
        valueWei: valueWei.toString(),
        dataHex: nestedCallDataHex,
        selector: selectorFromHexData(nestedCallDataHex),
        decodedArgs: 'execute(address to, uint256 value, bytes data)',
      },
    ],
  };
}

function decodeExecuteBatchCallData(callDataHex: string): DecodedSmartAccountCall {
  const bytes = parseHexBytes(callDataHex);
  if (!bytes || bytes.length < 4 + 32 * 3) {
    return {
      callType: 'executeBatch',
      selector: EXECUTE_BATCH_SELECTOR,
      calls: [
        {
          dataHex: normalizeHex(callDataHex),
          selector: EXECUTE_BATCH_SELECTOR,
        },
      ],
      warning: 'Failed to decode executeBatch(address[],uint256[],bytes[]) calldata',
    };
  }

  const paramsOffset = 4;
  const toOffset = readWordNumber(bytes, paramsOffset);
  const valueOffset = readWordNumber(bytes, paramsOffset + 32);
  const dataOffset = readWordNumber(bytes, paramsOffset + 64);

  if (toOffset == null || valueOffset == null || dataOffset == null) {
    return {
      callType: 'executeBatch',
      selector: EXECUTE_BATCH_SELECTOR,
      calls: [
        {
          dataHex: normalizeHex(callDataHex),
          selector: EXECUTE_BATCH_SELECTOR,
        },
      ],
      warning: 'Failed to decode executeBatch(address[],uint256[],bytes[]) offsets',
    };
  }

  const targets = readAddressArray(bytes, paramsOffset, toOffset);
  const values = readBigIntArray(bytes, paramsOffset, valueOffset);
  const payloads = readBytesArray(bytes, paramsOffset, dataOffset);

  if (
    !targets ||
    !values ||
    !payloads ||
    targets.length !== values.length ||
    values.length !== payloads.length
  ) {
    return {
      callType: 'executeBatch',
      selector: EXECUTE_BATCH_SELECTOR,
      calls: [
        {
          dataHex: normalizeHex(callDataHex),
          selector: EXECUTE_BATCH_SELECTOR,
        },
      ],
      warning: 'Failed to decode executeBatch(address[],uint256[],bytes[]) arguments',
    };
  }

  return {
    callType: 'executeBatch',
    selector: EXECUTE_BATCH_SELECTOR,
    calls: targets.map((to, index) => {
      const nestedCallDataHex = bytesToHex(payloads[index]!);
      return {
        to,
        valueWei: values[index]!.toString(),
        dataHex: nestedCallDataHex,
        selector: selectorFromHexData(nestedCallDataHex),
        decodedArgs: 'executeBatch(address[] to, uint256[] value, bytes[] data)',
      };
    }),
  };
}

function decodeSmartAccountCallData(callDataHex: string): DecodedSmartAccountCall {
  const normalizedCallDataHex = normalizeHex(callDataHex);
  const selector = selectorFromHexData(normalizedCallDataHex);
  if (selector === EXECUTE_SELECTOR) return decodeExecuteCallData(normalizedCallDataHex);
  if (selector === EXECUTE_BATCH_SELECTOR) return decodeExecuteBatchCallData(normalizedCallDataHex);
  return {
    callType: 'custom',
    selector,
    calls: [
      {
        dataHex: normalizedCallDataHex,
        selector,
      },
    ],
  };
}

function decodeHandleOpsCallData(callDataHex: string): DecodedHandleOps | undefined {
  const normalizedCallDataHex = normalizeHex(callDataHex);
  const selector = selectorFromHexData(normalizedCallDataHex);
  if (!selector || !HANDLE_OPS_SELECTORS.has(selector)) return undefined;

  const bytes = parseHexBytes(normalizedCallDataHex);
  if (!bytes || bytes.length < 4 + 32 * 2) {
    return {
      selector,
      userOperations: [],
      warning: 'Failed to parse handleOps calldata payload',
    };
  }

  const paramsOffset = 4;
  const opsOffset = readWordNumber(bytes, paramsOffset);
  const beneficiary = readWordAddress(bytes, paramsOffset + 32);

  if (opsOffset == null) {
    return {
      selector,
      beneficiary,
      userOperations: [],
      warning: 'Failed to decode handleOps user operation offset',
    };
  }

  const opsHeadOffset = paramsOffset + opsOffset;
  const userOpCount = readWordNumber(bytes, opsHeadOffset);
  if (userOpCount == null) {
    return {
      selector,
      beneficiary,
      userOperations: [],
      warning: 'Failed to decode handleOps user operation count',
    };
  }

  const userOpTupleHeadOffset = opsHeadOffset + 32;
  const userOperations: DecodedUserOperation[] = [];
  let decodeWarning: string | undefined;

  for (let userOpIndex = 0; userOpIndex < userOpCount; userOpIndex += 1) {
    const userOpOffset = readWordNumber(bytes, userOpTupleHeadOffset + userOpIndex * 32);
    if (userOpOffset == null) {
      decodeWarning = decodeWarning || 'Failed to decode one or more UserOperation entries';
      continue;
    }

    const userOpHeadOffset = userOpTupleHeadOffset + userOpOffset;
    const sender = readWordAddress(bytes, userOpHeadOffset);
    const nonce = readWordBigInt(bytes, userOpHeadOffset + 32);
    const callDataOffset = readWordNumber(bytes, userOpHeadOffset + 3 * 32);
    const callDataBytes =
      callDataOffset == null
        ? undefined
        : readDynamicBytes(bytes, userOpHeadOffset, callDataOffset);

    const callDataHex = callDataBytes ? bytesToHex(callDataBytes) : '0x';
    const decodedCall = decodeSmartAccountCallData(callDataHex);
    if (!callDataBytes) {
      decodedCall.warning = decodedCall.warning || 'UserOperation callData was unavailable';
    }

    userOperations.push({
      sender,
      nonce: nonce?.toString(),
      callDataHex,
      decodedCall,
    });
  }

  return {
    selector,
    beneficiary,
    userOperations,
    warning: decodeWarning,
  };
}

function callTypeLabel(callType: 'execute' | 'executeBatch' | 'custom'): string {
  switch (callType) {
    case 'execute':
      return 'execute';
    case 'executeBatch':
      return 'executeBatch';
    default:
      return 'custom';
  }
}

function buildCallOperation(args: {
  id: string;
  label: string;
  call: DecodedContractCall;
}): GenericContractCallOperation {
  const { call } = args;
  const functionSignature = resolveFunctionSignature(call.selector, call.to);
  const fields: TxDisplayField[] = [
    makeField('To', call.to, call.to),
    makeField('Value (wei)', call.valueWei),
    makeField('Data', call.dataHex, call.dataHex),
    makeField('Function', functionSignature),
    makeField('Selector', call.selector, call.selector),
    makeField('Decoded Args', call.decodedArgs),
  ].filter(Boolean) as TxDisplayField[];

  return {
    id: args.id,
    kind: 'generic.contractCall',
    label: args.label,
    to: call.to,
    value: call.valueWei,
    selector: call.selector,
    fields,
  };
}

function buildErc4337OperationFromHandleOps(args: {
  to?: string;
  dataHex: string;
}): BuiltErc4337Operation | undefined {
  const decoded = decodeHandleOpsCallData(args.dataHex);
  if (!decoded) return undefined;

  const warnings: TxDisplayWarning[] = [];
  if (decoded.warning) {
    warnings.push({
      code: 'ERC4337_HANDLE_OPS_DECODE',
      severity: 'warning',
      message: decoded.warning,
    });
  }

  const userOpChildren: TxDisplayOperation[] = [];
  let callValueTotalWei = 0n;

  for (let userOpIndex = 0; userOpIndex < decoded.userOperations.length; userOpIndex += 1) {
    const userOp = decoded.userOperations[userOpIndex]!;
    const calls = userOp.decodedCall.calls;
    const callChildren = calls.map((call, callIndex) =>
      buildCallOperation({
        id: `evm.erc4337.userop.${userOpIndex}.call.${callIndex}`,
        label: calls.length > 1 ? `Call ${callIndex + 1}` : 'Call',
        call,
      }),
    );

    for (const call of calls) {
      if (call.valueWei != null) {
        try {
          callValueTotalWei += BigInt(call.valueWei);
        } catch {}
      }
    }

    if (userOp.decodedCall.warning) {
      warnings.push({
        code: 'ERC4337_USER_OP_DECODE',
        severity: 'warning',
        message: `UserOperation ${userOpIndex + 1}: ${userOp.decodedCall.warning}`,
      });
    }

    const userOpFields: TxDisplayField[] = [
      makeField('Smart Account', userOp.sender, userOp.sender),
      makeField('Nonce', userOp.nonce),
      makeField('Call Type', callTypeLabel(userOp.decodedCall.callType)),
      makeField(
        'CallData Function',
        resolveFunctionSignature(userOp.decodedCall.selector, userOp.sender),
      ),
      makeField('CallData Selector', userOp.decodedCall.selector, userOp.decodedCall.selector),
      makeField('CallData', userOp.callDataHex, userOp.callDataHex),
      makeField('Decoded Call Count', String(callChildren.length)),
    ].filter(Boolean) as TxDisplayField[];

    const userOpNode: Erc4337Operation = {
      id: `evm.erc4337.userop.${userOpIndex}`,
      kind: 'evm.erc4337',
      label: `UserOperation ${userOpIndex + 1}`,
      smartAccount: userOp.sender,
      callType: userOp.decodedCall.callType,
      fields: userOpFields,
      children: callChildren,
    };

    userOpChildren.push(userOpNode);
  }

  const distinctCallTypes = new Set(decoded.userOperations.map((op) => op.decodedCall.callType));
  const callType =
    distinctCallTypes.size === 1
      ? decoded.userOperations[0]?.decodedCall.callType || 'custom'
      : 'custom';

  const rootFields: TxDisplayField[] = [
    makeField('Kind', 'ERC-4337 UserOperation'),
    makeField('EntryPoint', args.to, args.to),
    makeField('Beneficiary', decoded.beneficiary, decoded.beneficiary),
    makeField('UserOperation Count', String(decoded.userOperations.length)),
    makeField('Function', resolveFunctionSignature(decoded.selector, args.to)),
    makeField('Selector', decoded.selector, decoded.selector),
  ].filter(Boolean) as TxDisplayField[];

  return {
    operation: {
      id: 'evm.erc4337',
      kind: 'evm.erc4337',
      label: 'ERC-4337 UserOperation',
      entryPoint: args.to,
      callType,
      fields: rootFields,
      children: userOpChildren,
    },
    warnings,
    callValueTotalWei: callValueTotalWei > 0n ? callValueTotalWei : undefined,
  };
}

function buildErc4337OperationFromDirectSmartAccountCall(args: {
  to?: string;
  dataHex: string;
}): BuiltErc4337Operation | undefined {
  const selector = selectorFromHexData(args.dataHex);
  if (selector !== EXECUTE_SELECTOR && selector !== EXECUTE_BATCH_SELECTOR) return undefined;

  const decodedCall = decodeSmartAccountCallData(args.dataHex);
  const warnings: TxDisplayWarning[] = [];
  if (decodedCall.warning) {
    warnings.push({
      code: 'ERC4337_EXECUTE_DECODE',
      severity: 'warning',
      message: decodedCall.warning,
    });
  }

  const callChildren = decodedCall.calls.map((call, callIndex) =>
    buildCallOperation({
      id: `evm.erc4337.call.${callIndex}`,
      label: decodedCall.calls.length > 1 ? `Call ${callIndex + 1}` : 'Call',
      call,
    }),
  );

  let callValueTotalWei = 0n;
  for (const call of decodedCall.calls) {
    if (call.valueWei == null) continue;
    try {
      callValueTotalWei += BigInt(call.valueWei);
    } catch {}
  }

  const rootFields: TxDisplayField[] = [
    makeField('Kind', 'ERC-4337 Smart Account Call'),
    makeField('Smart Account', args.to, args.to),
    makeField('Call Type', callTypeLabel(decodedCall.callType)),
    makeField('Function', resolveFunctionSignature(decodedCall.selector, args.to)),
    makeField('Selector', decodedCall.selector, decodedCall.selector),
    makeField('Decoded Call Count', String(callChildren.length)),
  ].filter(Boolean) as TxDisplayField[];

  return {
    operation: {
      id: 'evm.erc4337',
      kind: 'evm.erc4337',
      label: 'ERC-4337 Smart Account Call',
      smartAccount: args.to,
      callType: decodedCall.callType,
      fields: rootFields,
      children: callChildren,
    },
    warnings,
    callValueTotalWei: callValueTotalWei > 0n ? callValueTotalWei : undefined,
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
  const functionSignature = resolveFunctionSignature(args.selector, args.to);

  const callFields: TxDisplayField[] = [
    dataField,
    makeField('Function', functionSignature),
    makeField('Selector', args.selector, args.selector),
    makeField('Value (wei)', args.valueWei),
  ].filter(Boolean) as TxDisplayField[];

  const children = hasCallData
    ? [
        {
          id: 'evm.eip1559.call',
          kind: 'generic.contractCall' as const,
          label: `Calling ${functionLabel || 'contract function'} using ${formattedGasLimit} gas`,
          to: args.to,
          value: args.valueWei,
          selector: args.selector,
          fields: callFields,
        },
      ]
    : undefined;

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
  const dataHex = normalizeHex(String(tx.data || '0x'));
  const selector = selectorFromHexData(dataHex);

  const erc4337Operation =
    buildErc4337OperationFromHandleOps({ to, dataHex }) ||
    buildErc4337OperationFromDirectSmartAccountCall({ to, dataHex });

  const operation =
    erc4337Operation?.operation ||
    buildDefaultContractCallOperation({
      to,
      valueWei,
      tx,
      dataHex,
      selector,
    });

  const warnings = erc4337Operation?.warnings || [];
  const totalValueWei =
    erc4337Operation?.callValueTotalWei ?? (tx.value > 0n ? tx.value : undefined);

  return {
    chain: 'evm',
    chainId: tx.chainId,
    intentDigest: args.intentDigest,
    signerAccount: args.signerAccount,
    title: args.title || 'EVM Transaction',
    subtitle: args.subtitle,
    operations: [operation],
    ...(warnings.length ? { warnings } : {}),
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
