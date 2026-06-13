import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  deriveEcdsaHssYRelayerFromSigningRootShares,
  deriveEd25519HssServerInputsFromSigningRootShares,
  parseSigningRootShareWire,
  type EcdsaHssStableKeyPrfContext,
  type SigningRootShareWireSet,
  type SigningRootShareWire,
} from './thresholdPrfWasm';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssServerInputs,
} from '../types';
import {
  zeroizeBytes,
  type SigningRootSecretShareWireResult,
} from './signingRootSecretShareWires';

export const MAX_THRESHOLD_PRF_SHARE_COUNT = 255;

export type ThresholdPrfPolicy = {
  readonly protocol: 'threshold-prf';
  readonly threshold: number;
  readonly shareCount: number;
};

export type SigningRootShareSet = SigningRootShareWireSet;

export type FixedSigningRootScope = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
};

export type SigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly preferredShareIds?: readonly number[];
};

export type SigningRootShareResolver = {
  readonly fixedSigningRootScope?: FixedSigningRootScope;
  readonly policy: ThresholdPrfPolicy;
  readonly resolveSigningRootShareSet: (
    input: SigningRootShareResolverInput,
  ) => Promise<SigningRootShareSet>;
};

export type SigningRootShareInput = {
  readonly shareId: number;
  readonly shareWire?: Uint8Array;
  readonly shareWireB64u?: string;
  readonly shareWireHex?: string;
};

export type SealedSigningRootShare = {
  readonly signingRootId: string;
  readonly shareId: number;
  readonly sealedShare: Uint8Array;
  readonly signingRootVersion?: string;
  readonly storageId?: string;
  readonly kekId?: string;
};

export type SigningRootShareSource = {
  readonly listSealedSigningRootShares: (
    input: Pick<SigningRootShareResolverInput, 'signingRootId' | 'signingRootVersion'>,
  ) => Promise<readonly SealedSigningRootShare[]>;
};

export type SigningRootShareDecryptAdapter = {
  readonly decryptSigningRootShare: (record: SealedSigningRootShare) => Promise<Uint8Array>;
};

export type CreateHostedSigningRootShareResolverInput = {
  readonly policy: ThresholdPrfPolicy;
  readonly storageAdapter: SigningRootShareSource;
  readonly decryptAdapter: SigningRootShareDecryptAdapter;
};

export type CreateSelfHostedSigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly policy: ThresholdPrfPolicy;
  readonly shares: readonly SigningRootShareInput[];
};

export type DeriveEcdsaHssYRelayerFromSigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly preferredShareIds?: readonly number[];
  readonly resolver: SigningRootShareResolver;
  readonly context: EcdsaHssStableKeyPrfContext;
};

export type DeriveEd25519HssServerInputsFromSigningRootShareResolverInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly preferredShareIds?: readonly number[];
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

function shareWireInputToBytes(input: {
  readonly shareWire?: Uint8Array;
  readonly shareWireB64u?: string;
  readonly shareWireHex?: string;
}): Uint8Array {
  if (input.shareWire instanceof Uint8Array) return new Uint8Array(input.shareWire);
  const b64u = toOptionalTrimmedString(input.shareWireB64u);
  if (b64u) return base64UrlDecode(b64u);
  const hex = toOptionalTrimmedString(input.shareWireHex);
  if (hex) return hexToBytes(hex);
  throw new Error('signing-root share must include shareWire, shareWireB64u, or shareWireHex');
}

function normalizePolicy(policy: ThresholdPrfPolicy): ThresholdPrfPolicy {
  if (policy.protocol !== 'threshold-prf') {
    throw new Error('threshold-prf policy protocol must be threshold-prf');
  }
  if (
    !Number.isInteger(policy.threshold) ||
    policy.threshold < 1 ||
    policy.threshold > MAX_THRESHOLD_PRF_SHARE_COUNT
  ) {
    throw new Error(`threshold must be an integer between 1 and ${MAX_THRESHOLD_PRF_SHARE_COUNT}`);
  }
  if (
    !Number.isInteger(policy.shareCount) ||
    policy.shareCount < 1 ||
    policy.shareCount > MAX_THRESHOLD_PRF_SHARE_COUNT
  ) {
    throw new Error(`shareCount must be an integer between 1 and ${MAX_THRESHOLD_PRF_SHARE_COUNT}`);
  }
  if (policy.threshold > policy.shareCount) {
    throw new Error('threshold must be less than or equal to shareCount');
  }
  return {
    protocol: 'threshold-prf',
    threshold: policy.threshold,
    shareCount: policy.shareCount,
  };
}

function shareWireShareId(wire: SigningRootShareWire): number {
  return (wire[0] << 8) | wire[1];
}

function parseShareInput(input: SigningRootShareInput): SigningRootShareWire {
  const raw = shareWireInputToBytes(input);
  try {
    const parsed = parseSigningRootShareWire(raw);
    const shareId = shareWireShareId(parsed);
    if (shareId !== input.shareId) {
      parsed.fill(0);
      throw new Error('signing-root share id does not match share wire');
    }
    return parsed;
  } finally {
    zeroizeBytes(raw);
  }
}

function normalizePreferredShareIds(
  policy: ThresholdPrfPolicy,
  preferredShareIds: readonly number[] | undefined,
): readonly number[] | null {
  if (preferredShareIds === undefined) return null;
  if (preferredShareIds.length !== policy.threshold) {
    throw new Error(`preferredShareIds must contain exactly ${policy.threshold} share ids`);
  }
  const seen = new Set<number>();
  for (const shareId of preferredShareIds) {
    if (!Number.isInteger(shareId) || shareId < 1 || shareId > policy.shareCount) {
      throw new Error('preferredShareIds must be inside the threshold policy');
    }
    if (seen.has(shareId)) {
      throw new Error('preferredShareIds must identify distinct shares');
    }
    seen.add(shareId);
  }
  return [...preferredShareIds];
}

function selectShareSet(
  shares: ReadonlyMap<number, SigningRootShareWire>,
  policy: ThresholdPrfPolicy,
  preferredShareIds?: readonly number[],
): SigningRootShareSet {
  const selectedIds =
    normalizePreferredShareIds(policy, preferredShareIds) ??
    [...shares.keys()].sort((a, b) => a - b).slice(0, policy.threshold);
  if (selectedIds.length !== policy.threshold) {
    throw new Error(`at least ${policy.threshold} signing-root shares are required`);
  }
  return selectedIds.map((shareId) => {
    const share = shares.get(shareId);
    if (!share) throw new Error('requested signing-root shares are not available');
    return new Uint8Array(share) as SigningRootShareWire;
  });
}

function selectSealedShareRecords(input: {
  readonly policy: ThresholdPrfPolicy;
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
  readonly records: readonly SealedSigningRootShare[];
  readonly preferredShareIds?: readonly number[];
}): readonly SealedSigningRootShare[] {
  const selectedIds =
    normalizePreferredShareIds(input.policy, input.preferredShareIds) ??
    input.records
      .map((record) => record.shareId)
      .filter((shareId) => Number.isInteger(shareId))
      .sort((a, b) => a - b)
      .slice(0, input.policy.threshold);
  if (selectedIds.length !== input.policy.threshold) {
    throw new Error(`at least ${input.policy.threshold} signing-root shares are required`);
  }

  const byShareId = new Map<number, SealedSigningRootShare>();
  for (const record of input.records) {
    if (!record || typeof record !== 'object') {
      throw new Error('sealed signing-root share record is required');
    }
    if (record.signingRootId !== input.signingRootId) {
      throw new Error('sealed signing-root share record signingRootId mismatch');
    }
    if (
      input.signingRootVersion !== undefined &&
      (record.signingRootVersion || '') !== input.signingRootVersion
    ) {
      throw new Error('sealed signing-root share record signingRootVersion mismatch');
    }
    if (
      !Number.isInteger(record.shareId) ||
      record.shareId < 1 ||
      record.shareId > input.policy.shareCount
    ) {
      throw new Error('sealed signing-root share record has invalid shareId');
    }
    if (!(record.sealedShare instanceof Uint8Array)) {
      throw new Error('sealed signing-root share bytes must be a Uint8Array');
    }
    if (byShareId.has(record.shareId)) {
      throw new Error('sealed signing-root share records contain a duplicate shareId');
    }
    byShareId.set(record.shareId, record);
  }

  return selectedIds.map((shareId) => {
    const record = byShareId.get(shareId);
    if (!record) throw new Error('requested signing-root shares are not available');
    return record;
  });
}

async function decryptSigningRootShareSet(input: {
  readonly records: readonly SealedSigningRootShare[];
  readonly decryptShare: SigningRootShareDecryptAdapter['decryptSigningRootShare'];
}): Promise<SigningRootShareSet> {
  const shares: SigningRootShareWire[] = [];
  try {
    for (const record of input.records) {
      let decrypted: Uint8Array | null = null;
      try {
        decrypted = await input.decryptShare(record);
        const parsed = parseSigningRootShareWire(decrypted);
        if (shareWireShareId(parsed) !== record.shareId) {
          parsed.fill(0);
          throw new Error('decrypted signing-root share id does not match its record');
        }
        shares.push(parsed);
      } finally {
        if (decrypted) zeroizeBytes(decrypted);
      }
    }
    return shares;
  } catch (error) {
    for (const share of shares) zeroizeBytes(share);
    throw error;
  }
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
  const policy = normalizePolicy(input.policy);
  return {
    policy,
    resolveSigningRootShareSet: async (request) => {
      const signingRootId = requireSigningRootId(request.signingRootId);
      const signingRootVersion = maybeSigningRootVersion(request.signingRootVersion);
      const records = await input.storageAdapter.listSealedSigningRootShares({
        signingRootId,
        ...(signingRootVersion ? { signingRootVersion } : {}),
      });
      const selected = selectSealedShareRecords({
        policy,
        signingRootId,
        signingRootVersion,
        records,
        preferredShareIds: request.preferredShareIds,
      });
      return decryptSigningRootShareSet({
        records: selected,
        decryptShare: input.decryptAdapter.decryptSigningRootShare,
      });
    },
  };
}

export function createSelfHostedSigningRootShareResolver(
  input: CreateSelfHostedSigningRootShareResolverInput,
): SigningRootShareResolver {
  const signingRootId = requireSigningRootId(input.signingRootId);
  const signingRootVersion = maybeSigningRootVersion(input.signingRootVersion);
  const policy = normalizePolicy(input.policy);
  const shares = new Map<number, SigningRootShareWire>();
  try {
    for (const share of input.shares) {
      if (
        !Number.isInteger(share.shareId) ||
        share.shareId < 1 ||
        share.shareId > policy.shareCount
      ) {
        throw new Error('signing-root shareId must be inside the threshold policy');
      }
      if (shares.has(share.shareId)) throw new Error('duplicate signing-root share id');
      shares.set(share.shareId, parseShareInput(share));
    }
    if (shares.size < policy.threshold) {
      throw new Error(`at least ${policy.threshold} signing-root shares are required`);
    }
  } catch (error) {
    for (const wire of shares.values()) zeroizeBytes(wire);
    throw error;
  }

  return {
    policy,
    fixedSigningRootScope: {
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
    },
    resolveSigningRootShareSet: async (request) => {
      assertFixedScope({
        expectedSigningRootId: signingRootId,
        expectedSigningRootVersion: signingRootVersion,
        actualSigningRootId: requireSigningRootId(request.signingRootId),
        actualSigningRootVersion: maybeSigningRootVersion(request.signingRootVersion),
      });
      return selectShareSet(shares, policy, request.preferredShareIds);
    },
  };
}

function zeroizeSigningRootShareSet(shareSet: SigningRootShareSet): void {
  for (const share of shareSet) zeroizeBytes(share);
}

export async function deriveEcdsaHssYRelayerFromSigningRootShareResolver(
  input: DeriveEcdsaHssYRelayerFromSigningRootShareResolverInput,
): Promise<SigningRootSecretShareWireResult<Uint8Array>> {
  let shareSet: SigningRootShareSet | null = null;
  try {
    shareSet = await input.resolver.resolveSigningRootShareSet({
      signingRootId: input.signingRootId,
      ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
      ...(input.preferredShareIds ? { preferredShareIds: input.preferredShareIds } : {}),
    });
    const yRelayer = await deriveEcdsaHssYRelayerFromSigningRootShares({
      policy: input.resolver.policy,
      shareWires: shareSet,
      context: input.context,
    });
    return { ok: true, value: yRelayer };
  } catch (error) {
    return err(errorMessage(error, 'failed to derive ecdsa-hss y_relayer'));
  } finally {
    if (shareSet) zeroizeSigningRootShareSet(shareSet);
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
  let shareSet: SigningRootShareSet | null = null;
  try {
    shareSet = await input.resolver.resolveSigningRootShareSet({
      signingRootId: input.signingRootId,
      ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
      ...(input.preferredShareIds ? { preferredShareIds: input.preferredShareIds } : {}),
    });
    const serverInputBytes = await deriveEd25519HssServerInputsFromSigningRootShares({
      policy: input.resolver.policy,
      shareWires: shareSet,
      context: input.context,
    });
    try {
      return {
        ok: true,
        value: {
          signingRootId: serverInputBytes.signingRootId,
          nearAccountId: serverInputBytes.nearAccountId,
          keyPurpose: serverInputBytes.keyPurpose,
          keyVersion: serverInputBytes.keyVersion,
          participantIds: serverInputBytes.participantIds,
          derivationVersion: serverInputBytes.derivationVersion,
          contextBindingB64u: base64UrlEncode(serverInputBytes.contextBinding),
          yRelayerB64u: base64UrlEncode(serverInputBytes.yRelayer),
          tauRelayerB64u: base64UrlEncode(serverInputBytes.tauRelayer),
        },
      };
    } finally {
      zeroizeBytes(serverInputBytes.contextBinding);
      zeroizeBytes(serverInputBytes.yRelayer);
      zeroizeBytes(serverInputBytes.tauRelayer);
    }
  } catch (error) {
    return err(errorMessage(error, 'failed to derive ed25519-hss server inputs'));
  } finally {
    if (shareSet) zeroizeSigningRootShareSet(shareSet);
  }
}
