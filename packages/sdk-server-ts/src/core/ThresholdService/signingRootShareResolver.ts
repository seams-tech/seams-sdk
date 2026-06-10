import { base64UrlDecode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  deriveEcdsaHssYRelayerFromSigningRootSecretShares,
  deriveEd25519HssServerInputsFromSigningRootSecretShares,
  type EcdsaHssStableKeyPrfContext,
} from './thresholdPrfWasm';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssServerInputs,
} from '../types';
import type {
  SigningRootSecretDecryptAdapter as AdapterSigningRootSecretDecryptAdapter,
  SigningRootSecretResolverAdapters as AdapterSigningRootSecretResolverAdapters,
  SigningRootSecretShareSource as AdapterSigningRootSecretShareSource,
} from './signingRootSecretResolverAdapters';
import {
  parseSigningRootSecretShareWireV1,
  resolveSigningRootSecretShareWirePair,
  zeroizeBytes,
  zeroizeSigningRootSecretShareWireV1,
  type SigningRootSecretShareId as SigningRootSecretShareIdValue,
  type SigningRootSecretShareWirePair,
  type SigningRootSecretShareWireResult,
} from './signingRootSecretShareWires';

export type SigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly preferredShareIds?: readonly [
    SigningRootSecretShareIdValue,
    SigningRootSecretShareIdValue,
  ];
};

export type SigningRootSharePair = readonly [Uint8Array, Uint8Array];

export type FixedSigningRootScope = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
};

export type SigningRootShareResolver = {
  readonly fixedSigningRootScope?: FixedSigningRootScope;
  readonly resolveSigningRootSharePair: (
    input: SigningRootShareResolverInput,
  ) => Promise<SigningRootSharePair>;
};

export type SigningRootSecretResolver = SigningRootShareResolver;
export type SigningRootSecretShareId = SigningRootSecretShareIdValue;
export type SigningRootSecretResolverAdapters = AdapterSigningRootSecretResolverAdapters;
export type SigningRootSecretDecryptAdapter = AdapterSigningRootSecretDecryptAdapter;
export type SigningRootSecretShareSource = AdapterSigningRootSecretShareSource;

export type SigningRootSecretShareInput = {
  readonly shareId: SigningRootSecretShareIdValue;
  readonly shareWire?: Uint8Array;
  readonly shareWireB64u?: string;
  readonly shareWireHex?: string;
};

export type CreateHostedSigningRootShareResolverInput = SigningRootSecretResolverAdapters;

export type CreateSelfHostedSigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly shares: readonly SigningRootSecretShareInput[];
};

export type CreateSealedSelfHostedSigningRootShareResolverInput =
  CreateHostedSigningRootShareResolverInput & {
    readonly signingRootId: string;
    readonly signingRootVersion?: string;
  };

export type DeriveEcdsaHssYRelayerFromSigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly preferredShareIds?: readonly [
    SigningRootSecretShareIdValue,
    SigningRootSecretShareIdValue,
  ];
  readonly resolver: SigningRootShareResolver;
  readonly context: EcdsaHssStableKeyPrfContext;
};

export type DeriveEd25519HssServerInputsFromSigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly preferredShareIds?: readonly [
    SigningRootSecretShareIdValue,
    SigningRootSecretShareIdValue,
  ];
  readonly resolver: SigningRootShareResolver;
  readonly context: ThresholdEd25519HssCanonicalContext;
};

function err<T>(message: string): SigningRootSecretShareWireResult<T> {
  return { ok: false, code: 'resolver_failed', message };
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function requireSigningRootId(signingRootId: unknown): string {
  const normalized = toOptionalTrimmedString(signingRootId);
  if (!normalized) throw new Error('signingRootId is required');
  return normalized;
}

function maybeSigningRootVersion(signingRootVersion: unknown): string | undefined {
  return toOptionalTrimmedString(signingRootVersion) || undefined;
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim();
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error('shareWireHex must be an even-length hex string');
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function shareWireInputToBytes(input: SigningRootSecretShareInput): Uint8Array {
  if (input.shareWire instanceof Uint8Array) return new Uint8Array(input.shareWire);
  const b64u = toOptionalTrimmedString(input.shareWireB64u);
  if (b64u) return base64UrlDecode(b64u);
  const hex = toOptionalTrimmedString(input.shareWireHex);
  if (hex) return hexToBytes(hex);
  throw new Error('signing-root share must include shareWire, shareWireB64u, or shareWireHex');
}

function parseShareInput(input: SigningRootSecretShareInput): Uint8Array {
  const raw = shareWireInputToBytes(input);
  try {
    const parsed = parseSigningRootSecretShareWireV1(raw);
    if (!parsed.ok) throw new Error(parsed.message);
    if (parsed.value[0] !== input.shareId) {
      zeroizeSigningRootSecretShareWireV1(parsed.value);
      throw new Error('signing-root share id does not match share wire');
    }
    return parsed.value;
  } finally {
    zeroizeBytes(raw);
  }
}

function selectPair(
  shares: ReadonlyMap<SigningRootSecretShareIdValue, Uint8Array>,
  preferredShareIds?: readonly [SigningRootSecretShareIdValue, SigningRootSecretShareIdValue],
): SigningRootSharePair {
  const selectedIds =
    preferredShareIds ??
    ([...shares.keys()].sort((a, b) => a - b).slice(0, 2) as [
      SigningRootSecretShareId,
      SigningRootSecretShareId,
    ]);
  if (selectedIds.length !== 2 || selectedIds[0] === selectedIds[1]) {
    throw new Error('preferredShareIds must identify two distinct signing-root shares');
  }
  const first = shares.get(selectedIds[0]);
  const second = shares.get(selectedIds[1]);
  if (!first || !second) throw new Error('requested signing-root shares are not available');
  return [new Uint8Array(first), new Uint8Array(second)] as const;
}

function assertFixedScope(input: {
  readonly expectedSigningRootId: string;
  readonly expectedSigningRootVersion?: string;
  readonly actualSigningRootId: string;
  readonly actualSigningRootVersion?: string;
}): void {
  if (input.actualSigningRootId !== input.expectedSigningRootId) {
    throw new Error(
      `signing-root resolver signingRootId mismatch (expected ${input.expectedSigningRootId}, got ${input.actualSigningRootId})`,
    );
  }
  const expectedSigningRootVersion = input.expectedSigningRootVersion || '';
  const actualSigningRootVersion = input.actualSigningRootVersion || expectedSigningRootVersion;
  if (actualSigningRootVersion !== expectedSigningRootVersion) {
    throw new Error('signing-root resolver signingRootVersion mismatch');
  }
}

export function createHostedSigningRootShareResolver(
  input: CreateHostedSigningRootShareResolverInput,
): SigningRootShareResolver {
  return {
    resolveSigningRootSharePair: async (request) => {
      const signingRootId = requireSigningRootId(request.signingRootId);
      const signingRootVersion = maybeSigningRootVersion(request.signingRootVersion);
      const records = await input.storageAdapter.listSealedSigningRootSecretShares({
        signingRootId,
        ...(signingRootVersion ? { signingRootVersion } : {}),
      });
      const resolved = await resolveSigningRootSecretShareWirePair({
        signingRootId,
        records,
        decryptShare: input.decryptAdapter.decryptSigningRootSecretShare,
        preferredShareIds: request.preferredShareIds,
      });
      if (!resolved.ok) throw new Error(resolved.message);
      return resolved.value;
    },
  };
}

export function createSelfHostedSigningRootShareResolver(
  input: CreateSelfHostedSigningRootShareResolverInput,
): SigningRootShareResolver {
  const signingRootId = requireSigningRootId(input.signingRootId);
  const signingRootVersion = maybeSigningRootVersion(input.signingRootVersion);
  const shares = new Map<SigningRootSecretShareIdValue, Uint8Array>();
  try {
    for (const share of input.shares) {
      if (share.shareId !== 1 && share.shareId !== 2 && share.shareId !== 3) {
        throw new Error('signing-root shareId must be 1, 2, or 3');
      }
      if (shares.has(share.shareId)) throw new Error('duplicate signing-root share id');
      shares.set(share.shareId, parseShareInput(share));
    }
    if (shares.size < 2) throw new Error('at least two signing-root shares are required');
  } catch (error) {
    for (const wire of shares.values()) zeroizeBytes(wire);
    throw error;
  }

  return {
    fixedSigningRootScope: {
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
    },
    resolveSigningRootSharePair: async (request) => {
      assertFixedScope({
        expectedSigningRootId: signingRootId,
        expectedSigningRootVersion: signingRootVersion,
        actualSigningRootId: requireSigningRootId(request.signingRootId),
        actualSigningRootVersion: maybeSigningRootVersion(request.signingRootVersion),
      });
      return selectPair(shares, request.preferredShareIds);
    },
  };
}

export function createSealedSelfHostedSigningRootShareResolver(
  input: CreateSealedSelfHostedSigningRootShareResolverInput,
): SigningRootShareResolver {
  const signingRootId = requireSigningRootId(input.signingRootId);
  const signingRootVersion = maybeSigningRootVersion(input.signingRootVersion);
  const hosted = createHostedSigningRootShareResolver(input);
  return {
    fixedSigningRootScope: {
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
    },
    resolveSigningRootSharePair: async (request) => {
      assertFixedScope({
        expectedSigningRootId: signingRootId,
        expectedSigningRootVersion: signingRootVersion,
        actualSigningRootId: requireSigningRootId(request.signingRootId),
        actualSigningRootVersion: maybeSigningRootVersion(request.signingRootVersion),
      });
      return hosted.resolveSigningRootSharePair(request);
    },
  };
}

function zeroizeSigningRootSharePair(pair: SigningRootSharePair): void {
  zeroizeBytes(pair[0]);
  zeroizeBytes(pair[1]);
}

function parseSigningRootSharePair(pair: SigningRootSharePair): SigningRootSecretShareWirePair {
  const first = parseSigningRootSecretShareWireV1(pair[0]);
  if (!first.ok) throw new Error(first.message);
  const second = parseSigningRootSecretShareWireV1(pair[1]);
  if (!second.ok) {
    zeroizeSigningRootSecretShareWireV1(first.value);
    throw new Error(second.message);
  }
  return [first.value, second.value] as const;
}

export async function deriveEcdsaHssYRelayerFromSigningRootShareResolver(
  input: DeriveEcdsaHssYRelayerFromSigningRootShareResolverInput,
): Promise<SigningRootSecretShareWireResult<Uint8Array>> {
  let pair: SigningRootSharePair | null = null;
  let parsedPair: SigningRootSecretShareWirePair | null = null;
  try {
    pair = await input.resolver.resolveSigningRootSharePair({
      signingRootId: input.signingRootId,
      ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
      ...(input.preferredShareIds ? { preferredShareIds: input.preferredShareIds } : {}),
    });
    parsedPair = parseSigningRootSharePair(pair);
    const yRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretShares({
      shareWires: parsedPair,
      context: input.context,
    });
    return { ok: true, value: yRelayer };
  } catch (error) {
    return err(errorMessage(error, 'failed to derive ecdsa-hss y_relayer'));
  } finally {
    if (parsedPair) {
      zeroizeSigningRootSecretShareWireV1(parsedPair[0]);
      zeroizeSigningRootSecretShareWireV1(parsedPair[1]);
    }
    if (pair) zeroizeSigningRootSharePair(pair);
  }
}

export async function deriveEd25519HssServerInputsFromSigningRootShareResolver(
  input: DeriveEd25519HssServerInputsFromSigningRootShareResolverInput,
): Promise<
  SigningRootSecretShareWireResult<
    ThresholdEd25519HssCanonicalContext &
      ThresholdEd25519HssServerInputs & { contextBindingB64u: string }
  >
> {
  let pair: SigningRootSharePair | null = null;
  let parsedPair: SigningRootSecretShareWirePair | null = null;
  try {
    pair = await input.resolver.resolveSigningRootSharePair({
      signingRootId: input.signingRootId,
      ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
      ...(input.preferredShareIds ? { preferredShareIds: input.preferredShareIds } : {}),
    });
    parsedPair = parseSigningRootSharePair(pair);
    const serverInputs = await deriveEd25519HssServerInputsFromSigningRootSecretShares({
      shareWires: parsedPair,
      context: input.context,
    });
    return { ok: true, value: serverInputs };
  } catch (error) {
    return err(errorMessage(error, 'failed to derive ed25519-hss server inputs'));
  } finally {
    if (parsedPair) {
      zeroizeSigningRootSecretShareWireV1(parsedPair[0]);
      zeroizeSigningRootSecretShareWireV1(parsedPair[1]);
    }
    if (pair) zeroizeSigningRootSharePair(pair);
  }
}
