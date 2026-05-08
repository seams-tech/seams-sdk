import type { EvmAbiParameter, EvmContractAbi } from '@/core/signingEngine/chains/evm/types';
import { bytesToHex, hexToBytes } from '@/core/signingEngine/chains/evm/bytes';
import { keccak256Bytes } from '@shared/utils/keccak';
import {
  deriveSelectorFromHexData,
  normalizeHexData,
  normalizeHexSelector,
} from '@/core/signingEngine/chains/evm/display/normalization';

type AbiDecodedValue =
  | string
  | boolean
  | AbiDecodedValue[]
  | { [key: string]: AbiDecodedValue };

type AbiTypeNode =
  | {
      kind: 'scalar';
      typeName: string;
      canonicalType: string;
      dynamic: boolean;
    }
  | {
      kind: 'tuple';
      canonicalType: string;
      dynamic: boolean;
      components: AbiComponentNode[];
    }
  | {
      kind: 'array';
      canonicalType: string;
      dynamic: boolean;
      item: AbiTypeNode;
      length: number | null;
    };

type AbiComponentNode = {
  name: string;
  typeName: string;
  typeNode: AbiTypeNode;
};

type AbiFunctionEntryNormalized = {
  name: string;
  selector: string;
  inputs: AbiComponentNode[];
};

type AbiFunctionLookup = {
  bySelector: Map<string, AbiFunctionEntryNormalized>;
};

type AbiDecodeResult = {
  functionLabel: string;
  selector: string;
  decodedArgumentsJsonText?: string;
};

const WORD_SIZE = 32;
const MAX_DECODE_ARRAY_LENGTH = 256;
const ABI_FUNCTION_LOOKUP_CACHE = new WeakMap<EvmContractAbi, AbiFunctionLookup>();

function selectorFromDataHex(dataHex: string | undefined): string | null {
  return deriveSelectorFromHexData(dataHex) || null;
}

function buildAbiFunctionEntries(abi: EvmContractAbi): AbiFunctionEntryNormalized[] {
  const out: AbiFunctionEntryNormalized[] = [];
  for (const entry of abi) {
    if (!entry || typeof entry !== 'object') continue;
    const type = String((entry as { type?: unknown }).type || 'function').trim();
    if (type !== '' && type !== 'function') continue;
    const name = String((entry as { name?: unknown }).name || '').trim();
    if (!name) continue;
    const rawInputs = (entry as { inputs?: unknown }).inputs;
    const inputs = Array.isArray(rawInputs) ? rawInputs : [];
    const signature = `${name}(${inputs.map((input) => canonicalAbiTypeFromParameter(input)).join(',')})`;
    const selector = selectorFromSignature(signature);
    if (!selector) continue;
    const normalizedInputs = normalizeAbiComponentNodes(inputs);
    out.push({
      name,
      selector,
      inputs: normalizedInputs,
    });
  }
  return out;
}

function resolveAbiFunctionLookup(abi: EvmContractAbi | undefined): AbiFunctionLookup | undefined {
  if (!Array.isArray(abi) || abi.length === 0) return undefined;
  const cached = ABI_FUNCTION_LOOKUP_CACHE.get(abi);
  if (cached) return cached;
  const entries = buildAbiFunctionEntries(abi);
  if (!entries.length) return undefined;
  const bySelector = new Map<string, AbiFunctionEntryNormalized>();
  for (const entry of entries) {
    if (!bySelector.has(entry.selector)) {
      bySelector.set(entry.selector, entry);
    }
  }
  const lookup: AbiFunctionLookup = { bySelector };
  ABI_FUNCTION_LOOKUP_CACHE.set(abi, lookup);
  return lookup;
}

function selectorFromSignature(signature: string): string | null {
  const normalized = String(signature || '').trim();
  if (!normalized) return null;
  const digest = keccak256Bytes(new TextEncoder().encode(normalized));
  return normalizeHexSelector(bytesToHex(digest.slice(0, 4))) || null;
}

function canonicalAbiTypeFromParameter(input: unknown): string {
  const type = String((input as { type?: unknown })?.type || '')
    .trim()
    .toLowerCase();
  if (!type) return '';

  const components = Array.isArray((input as { components?: unknown })?.components)
    ? ((input as { components: unknown[] }).components as unknown[])
    : [];
  if (type.startsWith('tuple')) {
    const suffix = type.slice('tuple'.length);
    const tupleCore = `(${components.map((component) => canonicalAbiTypeFromParameter(component)).join(',')})`;
    return `${tupleCore}${suffix}`;
  }

  return type;
}

function normalizeAbiComponentNodes(inputs: readonly unknown[]): AbiComponentNode[] {
  const out: AbiComponentNode[] = [];
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index] as {
      name?: unknown;
      type?: unknown;
      components?: readonly EvmAbiParameter[];
    };
    const typeName = String(input?.type || '')
      .trim()
      .toLowerCase();
    if (!typeName) continue;
    const typeNode = parseAbiTypeNode({
      type: typeName,
      components: input?.components,
    });
    if (!typeNode) continue;
    const name = String(input?.name || '').trim();
    out.push({
      name: name || `arg${index}`,
      typeName,
      typeNode,
    });
  }
  return out;
}

function parseAbiTypeNode(args: {
  type: string;
  components?: readonly EvmAbiParameter[];
}): AbiTypeNode | null {
  const baseTypeRaw = String(args.type || '')
    .trim()
    .toLowerCase();
  if (!baseTypeRaw) return null;

  let baseType = baseTypeRaw;
  const arrayDimensions: (number | null)[] = [];
  while (baseType.endsWith(']')) {
    const openBracket = baseType.lastIndexOf('[');
    if (openBracket < 0) return null;
    const rawLength = baseType.slice(openBracket + 1, -1).trim();
    if (!/^\d*$/.test(rawLength)) return null;
    const length = rawLength === '' ? null : Number.parseInt(rawLength, 10);
    if (length != null && (!Number.isFinite(length) || length < 0)) return null;
    arrayDimensions.push(length);
    baseType = baseType.slice(0, openBracket);
  }

  let node: AbiTypeNode | null = null;
  if (baseType === 'tuple') {
    const components = Array.isArray(args.components) ? args.components : [];
    const normalizedComponents = normalizeAbiComponentNodes(components);
    const canonicalTupleType = `(${normalizedComponents.map((component) => component.typeNode.canonicalType).join(',')})`;
    node = {
      kind: 'tuple',
      canonicalType: canonicalTupleType,
      dynamic: normalizedComponents.some((component) => component.typeNode.dynamic),
      components: normalizedComponents,
    };
  } else {
    node = {
      kind: 'scalar',
      typeName: baseType,
      canonicalType: baseType,
      dynamic: baseType === 'bytes' || baseType === 'string',
    };
  }

  for (let i = arrayDimensions.length - 1; i >= 0; i -= 1) {
    const length = arrayDimensions[i]!;
    node = {
      kind: 'array',
      canonicalType: `${node.canonicalType}[${length == null ? '' : String(length)}]`,
      dynamic: length == null || node.dynamic,
      item: node,
      length,
    };
  }

  return node;
}

function readWord(bytes: Uint8Array, offset: number): Uint8Array | null {
  if (!Number.isInteger(offset) || offset < 0) return null;
  if (offset + WORD_SIZE > bytes.length) return null;
  return bytes.slice(offset, offset + WORD_SIZE);
}

function readWordBigInt(bytes: Uint8Array, offset: number): bigint | null {
  const word = readWord(bytes, offset);
  if (!word) return null;
  let out = 0n;
  for (const byte of word) {
    out = (out << 8n) + BigInt(byte);
  }
  return out;
}

function readWordNumber(bytes: Uint8Array, offset: number): number | null {
  const value = readWordBigInt(bytes, offset);
  if (value == null) return null;
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < 0n) return null;
  return Number(value);
}

function staticWordLength(typeNode: AbiTypeNode): number {
  if (typeNode.dynamic) return 1;
  if (typeNode.kind === 'scalar') return 1;
  if (typeNode.kind === 'tuple') {
    return typeNode.components.reduce((sum, component) => sum + staticWordLength(component.typeNode), 0);
  }
  if (typeNode.length == null) return 1;
  return typeNode.length * staticWordLength(typeNode.item);
}

function decodeScalar(typeName: string, bytes: Uint8Array, offset: number): AbiDecodedValue | null {
  const normalizedType = String(typeName || '').trim().toLowerCase();
  if (!normalizedType) return null;

  if (normalizedType === 'bytes') {
    const length = readWordNumber(bytes, offset);
    if (length == null) return null;
    const start = offset + WORD_SIZE;
    const end = start + length;
    if (end > bytes.length) return null;
    return bytesToHex(bytes.slice(start, end)).toLowerCase();
  }

  if (normalizedType === 'string') {
    const length = readWordNumber(bytes, offset);
    if (length == null) return null;
    const start = offset + WORD_SIZE;
    const end = start + length;
    if (end > bytes.length) return null;
    const valueBytes = bytes.slice(start, end);
    try {
      return new TextDecoder().decode(valueBytes);
    } catch {
      return bytesToHex(valueBytes).toLowerCase();
    }
  }

  const word = readWord(bytes, offset);
  if (!word) return null;
  const wordValue = readWordBigInt(bytes, offset);
  if (wordValue == null) return null;

  if (normalizedType === 'bool') {
    return wordValue !== 0n;
  }
  if (normalizedType === 'address') {
    return bytesToHex(word.slice(12)).toLowerCase();
  }
  if (normalizedType === 'function') {
    return bytesToHex(word.slice(0, 24)).toLowerCase();
  }

  const fixedBytesMatch = normalizedType.match(/^bytes(\d{1,2})$/);
  if (fixedBytesMatch) {
    const byteLength = Number.parseInt(fixedBytesMatch[1]!, 10);
    if (!Number.isFinite(byteLength) || byteLength <= 0 || byteLength > 32) return null;
    return bytesToHex(word.slice(0, byteLength)).toLowerCase();
  }

  const uintMatch = normalizedType.match(/^uint(\d{0,3})$/);
  if (uintMatch) {
    return wordValue.toString(10);
  }

  const intMatch = normalizedType.match(/^int(\d{0,3})$/);
  if (intMatch) {
    const bitsRaw = intMatch[1];
    const bits = bitsRaw ? Number.parseInt(bitsRaw, 10) : 256;
    if (!Number.isFinite(bits) || bits <= 0 || bits > 256 || bits % 8 !== 0) {
      return wordValue.toString(10);
    }
    const bitWidth = BigInt(bits);
    const modulus = 1n << bitWidth;
    const signBit = 1n << (bitWidth - 1n);
    const signed = wordValue >= signBit ? wordValue - modulus : wordValue;
    return signed.toString(10);
  }

  return bytesToHex(word).toLowerCase();
}

function decodeTypeAt(
  typeNode: AbiTypeNode,
  bytes: Uint8Array,
  offset: number,
): AbiDecodedValue | null {
  if (typeNode.kind === 'scalar') {
    return decodeScalar(typeNode.typeName, bytes, offset);
  }

  if (typeNode.kind === 'tuple') {
    const decodedItems = decodeTupleComponents(typeNode.components, bytes, offset);
    if (!decodedItems) return null;
    const out: Record<string, AbiDecodedValue> = {};
    for (let i = 0; i < typeNode.components.length; i += 1) {
      const component = typeNode.components[i]!;
      const baseName = String(component.name || '').trim() || `item${i}`;
      let name = baseName;
      let counter = 1;
      while (Object.prototype.hasOwnProperty.call(out, name)) {
        counter += 1;
        name = `${baseName}_${counter}`;
      }
      out[name] = decodedItems[i]!;
    }
    return out;
  }

  const expectedLength = typeNode.length;
  const isDynamicArray = expectedLength == null;
  const arrayLength = isDynamicArray ? readWordNumber(bytes, offset) : expectedLength;
  if (arrayLength == null) return null;
  if (arrayLength < 0 || arrayLength > MAX_DECODE_ARRAY_LENGTH) return null;

  const baseOffset = isDynamicArray ? offset + WORD_SIZE : offset;
  const items: AbiDecodedValue[] = [];

  if (typeNode.item.dynamic) {
    for (let i = 0; i < arrayLength; i += 1) {
      const itemRelativeOffset = readWordNumber(bytes, baseOffset + i * WORD_SIZE);
      if (itemRelativeOffset == null) return null;
      const decoded = decodeTypeAt(typeNode.item, bytes, baseOffset + itemRelativeOffset);
      if (decoded == null) return null;
      items.push(decoded);
    }
    return items;
  }

  const itemWords = staticWordLength(typeNode.item);
  for (let i = 0; i < arrayLength; i += 1) {
    const itemOffset = baseOffset + i * itemWords * WORD_SIZE;
    const decoded = decodeTypeAt(typeNode.item, bytes, itemOffset);
    if (decoded == null) return null;
    items.push(decoded);
  }
  return items;
}

function decodeTupleComponents(
  components: AbiComponentNode[],
  bytes: Uint8Array,
  tupleOffset: number,
): AbiDecodedValue[] | null {
  let cursorWords = 0;
  const headOffsets: number[] = [];
  for (const component of components) {
    headOffsets.push(cursorWords * WORD_SIZE);
    cursorWords += component.typeNode.dynamic ? 1 : staticWordLength(component.typeNode);
  }

  const out: AbiDecodedValue[] = [];
  for (let i = 0; i < components.length; i += 1) {
    const component = components[i]!;
    const headOffset = tupleOffset + headOffsets[i]!;
    if (component.typeNode.dynamic) {
      const relativeOffset = readWordNumber(bytes, headOffset);
      if (relativeOffset == null) return null;
      const decoded = decodeTypeAt(component.typeNode, bytes, tupleOffset + relativeOffset);
      if (decoded == null) return null;
      out.push(decoded);
      continue;
    }

    const decoded = decodeTypeAt(component.typeNode, bytes, headOffset);
    if (decoded == null) return null;
    out.push(decoded);
  }
  return out;
}

function formatDecodedArgumentsJsonText(
  args: { key: string; value: AbiDecodedValue }[],
): string | undefined {
  if (!args.length) return undefined;
  const payload: Record<string, AbiDecodedValue> = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    const baseKey = String(arg.key || '').trim() || `arg${index}`;
    let nextKey = baseKey;
    let suffix = 2;
    while (Object.prototype.hasOwnProperty.call(payload, nextKey)) {
      nextKey = `${baseKey}_${suffix}`;
      suffix += 1;
    }
    payload[nextKey] = arg.value;
  }
  try {
    return JSON.stringify(payload, null, 2);
  } catch {
    return undefined;
  }
}

export function decodeCallDataWithAbi(args: {
  dataHex: string | undefined;
  abi: EvmContractAbi | undefined;
}): AbiDecodeResult | undefined {
  const selector = selectorFromDataHex(args.dataHex);
  if (!selector) return undefined;
  const abiLookup = resolveAbiFunctionLookup(args.abi);
  if (!abiLookup) return undefined;
  const matched = abiLookup.bySelector.get(selector);
  if (!matched) return undefined;

  const normalizedDataHex = normalizeHexData(args.dataHex, { lowercase: true });
  let argsBytes: Uint8Array;
  try {
    const bytes = hexToBytes(normalizedDataHex);
    if (bytes.length < 4) {
      return {
        functionLabel: `${matched.name}()`,
        selector: matched.selector,
      };
    }
    argsBytes = bytes.slice(4);
  } catch {
    return {
      functionLabel: `${matched.name}()`,
      selector: matched.selector,
    };
  }

  const decodedValues = decodeTupleComponents(matched.inputs, argsBytes, 0);
  if (!decodedValues) {
    return {
      functionLabel: `${matched.name}()`,
      selector: matched.selector,
    };
  }

  const decodedArguments = matched.inputs.map((input, index) => ({
    key: String(input.name || '').trim() || `arg${index}`,
    value: decodedValues[index]!,
  }));

  return {
    functionLabel: `${matched.name}()`,
    selector: matched.selector,
    decodedArgumentsJsonText: formatDecodedArgumentsJsonText(decodedArguments),
  };
}
