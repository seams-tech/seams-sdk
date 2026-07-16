import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  computeSdkEcdsaDerivationApplicationBindingDigest32,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
  type EcdsaDerivationRelayerPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  formatEcdsaDerivationKeyVersionForWire,
  parseEcdsaDerivationKeyVersion,
  type EcdsaDerivationKeyVersion,
} from '../keyMaterialBrands';
import type { ThresholdEcdsaIntegratedKeyStore } from '../ThresholdService/stores/KeyStore';
import type {
  EcdsaWalletSessionRecord,
  EcdsaWalletSessionStore,
} from '../ThresholdService/stores/WalletSessionStore';
import type {
  EcdsaDerivationClientBootstrapRequest,
  EcdsaDerivationExportShareRequest,
  EcdsaDerivationExportShareResponse,
  EcdsaDerivationRoleLocalKeyRecord,
  EcdsaDerivationRouteResult,
  EcdsaDerivationServerBootstrapResponse,
  ThresholdEcdsaSigningRootMetadata,
} from '../types';
import type { ParseResult } from '../ThresholdService/routerAbNormalSigningPolicy';
import {
  addSecp256k1PublicKeys33,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
  validateSecp256k1PublicKey33,
} from '../ThresholdService/evmCryptoWasm';
import { roleLocalThresholdEcdsaDerivationRelayerBootstrap } from '../ThresholdService/routerAbEcdsaSigningWorkerWasm';
import { verifyEcdsaClientRootProof } from '../ThresholdService/ecdsaClientRootProof';
import type { RouterAbEcdsaDerivationWalletSessionClaims } from '../ThresholdService/validation';
import {
  deriveEcdsaDerivationYRelayerFromSigningRootShareResolver,
  type SigningRootShareResolver,
} from '../ThresholdService/signingRootShareResolver';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import type { RouterAbNormalSigningRuntime } from './RouterAbNormalSigningRuntime';

export type RouterAbEcdsaKeyHandleSelector = {
  readonly kind: 'key_handle';
  readonly keyHandle: string;
  readonly ecdsaThresholdKeyId?: never;
};

export type RouterAbEcdsaClientBootstrapRequest = EcdsaDerivationClientBootstrapRequest & {
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
};

export type RouterAbEcdsaExportShareRequest = EcdsaDerivationExportShareRequest & {
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
};

export type RouterAbEcdsaSessionClaims = RouterAbEcdsaDerivationWalletSessionClaims & {
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
};

export type RouterAbEcdsaKeyIdentityMetadata = {
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  readonly keyScope: 'evm-family';
  readonly keyHandle: string;
  readonly ecdsaThresholdKeyId: string;
  readonly relayerKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly participantIds: readonly [number, number];
  readonly thresholdOwnerAddress: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
};

export type RouterAbEcdsaSigningRootWalletVerificationInput = {
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly walletId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly ecdsaThresholdKeyId: string;
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  readonly clientPublicKey33B64u: string;
  readonly expectedEthereumAddress?: string;
  readonly walletKeyVersion?: string;
};

export type RouterAbEcdsaBootstrapExportRuntimeState =
  | {
      readonly kind: 'configured';
      readonly runtime: RouterAbEcdsaBootstrapExportPort;
    }
  | {
      readonly kind: 'unconfigured';
      readonly runtime?: never;
    };

export type RouterAbEcdsaBootstrapExportPort = Pick<
  RouterAbEcdsaBootstrapExportRuntime,
  | 'getEcdsaKeyIdentityMetadata'
  | 'verifyEcdsaSigningRootWalletAddress'
  | 'ecdsaDerivationRoleLocalBootstrap'
  | 'verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey'
  | 'ecdsaDerivationRoleLocalExportShare'
>;

type RouterAbEcdsaBootstrapSessionResult =
  | {
      readonly ok: true;
      readonly sessionId: string;
      readonly signingGrantId: string;
      readonly expiresAtMs: number;
      readonly expiresAt: string;
      readonly participantIds: number[];
      readonly remainingUses: number;
    }
  | {
      readonly ok: false;
      readonly code?: string;
      readonly message?: string;
    };

const THRESHOLD_ECDSA_DERIVATION_KEY_VERSION_V1 = parseEcdsaDerivationKeyVersion('v1');
const THRESHOLD_ECDSA_DERIVATION_VERSION_V1 = 1;
const THRESHOLD_ECDSA_DERIVATION_EXPORT_CLOCK_SKEW_MS = 5 * 60_000;
const THRESHOLD_ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-confirmation:v2';
const THRESHOLD_ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-authorization:v2';

function requireSdkEcdsaDerivationWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

function isEcdsaDerivationPublicKeyValidationError(message: string): boolean {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('public key') &&
    (normalized.includes('invalid') ||
      normalized.includes('secp256k1') ||
      normalized.includes('point') ||
      normalized.includes('identity'))
  );
}

function bytesToLowerHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left[index]! ^ right[index]!;
  }
  return diff === 0;
}

function canonicalEcdsaDerivationSigningRootVersion(signingRootVersion: unknown): string {
  return toOptionalTrimmedString(signingRootVersion) || 'default';
}

function parseEcdsaDerivationKeyVersionOrDefault(value: unknown): EcdsaDerivationKeyVersion {
  const raw = toOptionalTrimmedString(value);
  return raw ? parseEcdsaDerivationKeyVersion(raw) : THRESHOLD_ECDSA_DERIVATION_KEY_VERSION_V1;
}

function ecdsaDerivationKeyVersionWire(value: EcdsaDerivationKeyVersion): string {
  return formatEcdsaDerivationKeyVersionForWire(value);
}

async function deriveThresholdEcdsaDerivationKeyHandle(input: {
  readonly ecdsaThresholdKeyId: unknown;
  readonly signingRootId: unknown;
  readonly signingRootVersion?: unknown;
}): Promise<string> {
  return String(
    await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
  );
}

function createEcdsaSigningRootMetadata(
  signingRootId: string,
  signingRootVersion?: string,
  ecdsaDerivationKeyVersion: EcdsaDerivationKeyVersion = THRESHOLD_ECDSA_DERIVATION_KEY_VERSION_V1,
): ThresholdEcdsaSigningRootMetadata {
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    walletKeyVersion: ecdsaDerivationKeyVersionWire(ecdsaDerivationKeyVersion),
    derivationVersion: THRESHOLD_ECDSA_DERIVATION_VERSION_V1,
  };
}

function haveSameEcdsaSigningRootMetadata(
  left: Partial<ThresholdEcdsaSigningRootMetadata> | null | undefined,
  right: Partial<ThresholdEcdsaSigningRootMetadata> | null | undefined,
): boolean {
  return Boolean(
    left &&
    right &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion &&
    left.walletKeyVersion === right.walletKeyVersion &&
    left.derivationVersion === right.derivationVersion,
  );
}

function isRouterAbEcdsaSigningWorkerRuntimeError(messageRaw: string): boolean {
  const message = String(messageRaw || '').toLowerCase();
  return (
    message.includes('router a/b signing worker wasm') ||
    message.includes('router_ab_ecdsa_signing_worker') ||
    message.includes('not initialized')
  );
}

function freezeParticipantIds(
  participantIds: readonly [number, number],
): readonly [number, number] {
  const [clientParticipantId, relayerParticipantId] = participantIds;
  if (
    !Number.isSafeInteger(clientParticipantId) ||
    clientParticipantId <= 0 ||
    !Number.isSafeInteger(relayerParticipantId) ||
    relayerParticipantId <= 0 ||
    clientParticipantId === relayerParticipantId
  ) {
    throw new Error('Router A/B ECDSA participant ids must be distinct positive integers');
  }
  return Object.freeze([clientParticipantId, relayerParticipantId] as const);
}

async function bootstrapRelayerAndZeroizeShare(
  input: Parameters<typeof roleLocalThresholdEcdsaDerivationRelayerBootstrap>[0],
): Promise<Awaited<ReturnType<typeof roleLocalThresholdEcdsaDerivationRelayerBootstrap>>> {
  try {
    return await roleLocalThresholdEcdsaDerivationRelayerBootstrap(input);
  } finally {
    input.yRelayer32Le.fill(0);
  }
}

export class RouterAbEcdsaBootstrapExportRuntime {
  private readonly ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
  private readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
  private readonly signingRootShareResolver: SigningRootShareResolver;
  private readonly routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
  private readonly participantIds: readonly [number, number];

  constructor(input: {
    readonly ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
    readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
    readonly signingRootShareResolver: SigningRootShareResolver;
    readonly routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
    readonly participantIds: readonly [number, number];
  }) {
    this.ecdsaKeyStore = input.ecdsaKeyStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.signingRootShareResolver = input.signingRootShareResolver;
    this.routerAbNormalSigningRuntime = input.routerAbNormalSigningRuntime;
    this.participantIds = freezeParticipantIds(input.participantIds);
  }

  private async deriveThresholdEcdsaDerivationYRelayerForContext(input: {
    readonly derivationContext: {
      readonly applicationBindingDigest: Uint8Array;
    };
    readonly signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
  }): Promise<ParseResult<Uint8Array>> {
    const derived = await deriveEcdsaDerivationYRelayerFromSigningRootShareResolver({
      signingRootId: input.signingRootMetadata.signingRootId,
      ...(input.signingRootMetadata.signingRootVersion
        ? { signingRootVersion: input.signingRootMetadata.signingRootVersion }
        : {}),
      resolver: this.signingRootShareResolver,
      context: input.derivationContext,
    });
    if (!derived.ok) {
      return {
        ok: false,
        code: derived.code,
        message: `threshold-prf signing-root derivation failed: ${derived.message}`,
      };
    }
    return { ok: true, value: derived.value };
  }

  private clampSessionPolicy(input: { readonly ttlMs: number; readonly remainingUses: number }): {
    readonly ttlMs: number;
    readonly remainingUses: number;
  } {
    const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
    const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
    return {
      ttlMs: Math.min(ttlMs, 30 * 24 * 60 * 60_000),
      remainingUses: Math.min(remainingUses, 1_000_000),
    };
  }

  private async getEcdsaWalletSession(sessionId: string): Promise<EcdsaWalletSessionRecord | null> {
    return await this.ecdsaWalletSessionStore.getSession(sessionId);
  }

  private async putEcdsaWalletSessionRecord(input: {
    readonly sessionId: string;
    readonly record: EcdsaWalletSessionRecord;
    readonly ttlMs: number;
    readonly remainingUses: number;
  }): Promise<void> {
    await this.ecdsaWalletSessionStore.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  async getEcdsaKeyIdentityMetadata(input: {
    walletId: string;
    keySelector: RouterAbEcdsaKeyHandleSelector;
  }): Promise<RouterAbEcdsaKeyIdentityMetadata | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(input.keySelector.keyHandle);
    if (!record) return null;
    const keyHandle = toOptionalTrimmedString(record.keyHandle);
    if (keyHandle !== input.keySelector.keyHandle) return null;
    if (record.walletId !== walletId) {
      return null;
    }
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const recordOwnerAddress = toOptionalTrimmedString(record.ethereumAddress);
    if (!relayerKeyId || !recordOwnerAddress) return null;
    const evmFamilySigningKeySlotId = parseEvmFamilySigningKeySlotId(
      record.evmFamilySigningKeySlotId,
    );
    if (!evmFamilySigningKeySlotId.ok) return null;
    const thresholdOwnerAddress = recordOwnerAddress.toLowerCase();
    return {
      walletId: record.walletId,
      evmFamilySigningKeySlotId: evmFamilySigningKeySlotId.value,
      keyScope: 'evm-family',
      keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      relayerKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      participantIds: this.participantIds,
      thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: record.groupPublicKey33B64u,
    };
  }

  async verifyEcdsaSigningRootWalletAddress(
    input: RouterAbEcdsaSigningRootWalletVerificationInput,
  ): Promise<
    | {
        ok: true;
        verified: boolean;
        signingRootId: string;
        signingRootVersion: string;
        walletId: string;
        evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
        walletKeyVersion: string;
        canonicalPublicKeyHex: string;
        canonicalEthereumAddress: string;
        expectedEthereumAddress?: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const signingRootId = toOptionalTrimmedString(input.signingRootId);
    const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
    const walletId = toOptionalTrimmedString(input.walletId);
    const chainTarget = input.chainTarget;
    const ecdsaThresholdKeyId = toOptionalTrimmedString(input.ecdsaThresholdKeyId);
    const parsedEvmFamilySigningKeySlotId = parseEvmFamilySigningKeySlotId(
      input.evmFamilySigningKeySlotId,
    );
    const evmFamilySigningKeySlotId = parsedEvmFamilySigningKeySlotId.ok
      ? parsedEvmFamilySigningKeySlotId.value
      : null;
    const ecdsaDerivationKeyVersion = parseEcdsaDerivationKeyVersionOrDefault(
      input.walletKeyVersion,
    );
    const walletKeyVersion = ecdsaDerivationKeyVersionWire(ecdsaDerivationKeyVersion);
    if (
      !signingRootId ||
      !signingRootVersion ||
      !walletId ||
      !ecdsaThresholdKeyId ||
      !evmFamilySigningKeySlotId
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'signingRootId, signingRootVersion, walletId, chainTarget, ecdsaThresholdKeyId, and evmFamilySigningKeySlotId are required',
      };
    }
    if (!this.signingRootShareResolver) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-ecdsa wallet verification requires a signing-root share resolver',
      };
    }

    const parsedClientPublicKey = await this.parseCompressedSecp256k1PublicKeyB64u({
      fieldName: 'clientPublicKey33B64u',
      value: input.clientPublicKey33B64u,
    });
    if (!parsedClientPublicKey.ok) return parsedClientPublicKey;
    const clientPublicKey33 = base64UrlDecode(parsedClientPublicKey.value);

    const expectedEthereumAddress = toOptionalTrimmedString(input.expectedEthereumAddress);
    let yRelayer32Le: Uint8Array | null = null;
    try {
      const signingRootMetadata = createEcdsaSigningRootMetadata(
        signingRootId,
        signingRootVersion,
        ecdsaDerivationKeyVersion,
      );
      const canonicalSigningRootVersion =
        canonicalEcdsaDerivationSigningRootVersion(signingRootVersion);
      const derivationContext = {
        applicationBindingDigest: await computeSdkEcdsaDerivationApplicationBindingDigest32({
          walletId: requireSdkEcdsaDerivationWalletId(walletId),
          ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(ecdsaThresholdKeyId),
          signingRootId: parseSdkEcdsaDerivationSigningRootId(signingRootId),
          signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
            canonicalSigningRootVersion,
          ),
        }),
      };
      const derived = await this.deriveThresholdEcdsaDerivationYRelayerForContext({
        derivationContext,
        signingRootMetadata,
      });
      if (!derived.ok) return derived;
      yRelayer32Le = derived.value;

      const relayerPublicKey33 = await secp256k1PrivateKey32ToPublicKey33(yRelayer32Le);
      const groupPublicKey33 = await addSecp256k1PublicKeys33({
        left33: clientPublicKey33,
        right33: relayerPublicKey33,
      });
      const canonicalEthereumAddress =
        await secp256k1PublicKey33ToEthereumAddress(groupPublicKey33);
      const normalizedExpected = expectedEthereumAddress?.toLowerCase();
      return {
        ok: true,
        verified: normalizedExpected ? canonicalEthereumAddress === normalizedExpected : true,
        signingRootId,
        signingRootVersion,
        walletId,
        evmFamilySigningKeySlotId,
        walletKeyVersion,
        canonicalPublicKeyHex: bytesToLowerHex(groupPublicKey33),
        canonicalEthereumAddress,
        ...(expectedEthereumAddress ? { expectedEthereumAddress } : {}),
      };
    } finally {
      yRelayer32Le?.fill(0);
    }
  }

  private async parseCompressedSecp256k1PublicKeyB64u(input: {
    value: string;
    fieldName: string;
  }): Promise<ParseResult<string>> {
    let publicKey33: Uint8Array;
    try {
      publicKey33 = base64UrlDecode(input.value);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} must be valid base64url`,
      };
    }
    if (publicKey33.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} must decode to 33 bytes (compressed secp256k1 pubkey)`,
      };
    }
    try {
      await validateSecp256k1PublicKey33(publicKey33);
    } catch (e: unknown) {
      const runtimeMessage = errorMessage(e);
      if (isRouterAbEcdsaSigningWorkerRuntimeError(runtimeMessage)) {
        return {
          ok: false,
          code: 'internal',
          message: runtimeMessage || 'Router A/B ECDSA signing worker WASM runtime error',
        };
      }
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} is not a valid secp256k1 public key`,
      };
    }
    return { ok: true, value: input.value };
  }

  private async ecdsaMintSessionWithoutWebAuthn(input: {
    relayerKeyId: string;
    clientVerifyingShareB64u: string;
    walletId: string;
    evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    sessionId: string;
    signingGrantId: string;
    ttlMsRaw: number;
    remainingUsesRaw: number;
    policyParticipantIds: number[] | null;
    signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
  }): Promise<RouterAbEcdsaBootstrapSessionResult> {
    const {
      relayerKeyId,
      clientVerifyingShareB64u,
      walletId,
      evmFamilySigningKeySlotId,
      sessionId,
      signingGrantId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds,
      signingRootMetadata,
    } = input;

    const parsedClientVerifyingShare = await this.parseCompressedSecp256k1PublicKeyB64u({
      value: clientVerifyingShareB64u,
      fieldName: 'clientVerifyingShareB64u',
    });
    if (!parsedClientVerifyingShare.ok) {
      return parsedClientVerifyingShare;
    }

    const { ttlMs, remainingUses } = this.clampSessionPolicy({
      ttlMs: ttlMsRaw,
      remainingUses: remainingUsesRaw,
    });
    const participantIds = policyParticipantIds || [...this.participantIds];

    const existingSession = await this.getEcdsaWalletSession(sessionId);
    if (existingSession) {
      if (existingSession.walletId !== walletId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different user',
        };
      }
      if (existingSession.relayerKeyId !== relayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different relayerKeyId',
        };
      }
      if (existingSession.evmFamilySigningKeySlotId !== evmFamilySigningKeySlotId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different evmFamilySigningKeySlotId',
        };
      }
      const sameParticipantIds =
        existingSession.participantIds.length === participantIds.length &&
        existingSession.participantIds.every((id, i) => id === participantIds[i]);
      if (!sameParticipantIds) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different participant set',
        };
      }
      if (!haveSameEcdsaSigningRootMetadata(existingSession, signingRootMetadata)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different signing root',
        };
      }
      const walletBudget = await this.routerAbNormalSigningRuntime.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ecdsa',
        thresholdSessionId: sessionId,
        userId: walletId,
        evmFamilySigningKeySlotId,
        participantIds: existingSession.participantIds,
        ttlMs,
        remainingUses,
        operation: 'provision_curve_binding',
      });
      if (!walletBudget.ok) return walletBudget;
      return {
        ok: true,
        sessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
      };
    }

    const expiresAtMs = Date.now() + ttlMs;
    const walletBudget = await this.routerAbNormalSigningRuntime.ensureSigningGrantBudget({
      signingGrantId,
      curve: 'ecdsa',
      thresholdSessionId: sessionId,
      userId: walletId,
      evmFamilySigningKeySlotId,
      participantIds,
      ttlMs,
      remainingUses,
      operation: 'provision_curve_binding',
    });
    if (!walletBudget.ok) return walletBudget;
    await this.putEcdsaWalletSessionRecord({
      sessionId,
      record: {
        expiresAtMs,
        relayerKeyId,
        walletId,
        evmFamilySigningKeySlotId,
        participantIds,
        ...signingRootMetadata,
      },
      ttlMs,
      remainingUses,
    });

    return {
      ok: true,
      sessionId,
      signingGrantId,
      expiresAtMs: walletBudget.expiresAtMs,
      expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
      participantIds: walletBudget.participantIds,
      remainingUses,
    };
  }

  async ecdsaDerivationRoleLocalBootstrap(
    request: RouterAbEcdsaClientBootstrapRequest,
  ): Promise<EcdsaDerivationRouteResult<EcdsaDerivationServerBootstrapResponse>> {
    try {
      const signingRootMetadata = createEcdsaSigningRootMetadata(
        request.signingRootId,
        request.signingRootVersion,
      );
      const ecdsaDerivationKeyVersion = THRESHOLD_ECDSA_DERIVATION_KEY_VERSION_V1;
      const canonicalSigningRootVersion = canonicalEcdsaDerivationSigningRootVersion(
        signingRootMetadata.signingRootVersion,
      );
      const derivationContext = {
        applicationBindingDigest: await computeSdkEcdsaDerivationApplicationBindingDigest32({
          walletId: requireSdkEcdsaDerivationWalletId(request.walletId),
          ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(request.ecdsaThresholdKeyId),
          signingRootId: parseSdkEcdsaDerivationSigningRootId(signingRootMetadata.signingRootId),
          signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
            canonicalSigningRootVersion,
          ),
        }),
      };
      const derivedRelayerShare = await this.deriveThresholdEcdsaDerivationYRelayerForContext({
        derivationContext,
        signingRootMetadata,
      });
      if (!derivedRelayerShare.ok) {
        return {
          ok: false,
          code: 'internal',
          message: derivedRelayerShare.message,
        };
      }
      const ecdsaDerivationClientSharePublicKey33 = base64UrlDecode(
        request.derivationClientSharePublicKey33B64u,
      );
      const relayerBootstrap = await bootstrapRelayerAndZeroizeShare({
        applicationBindingDigest: derivationContext.applicationBindingDigest,
        relayerKeyId: request.relayerKeyId,
        yRelayer32Le: derivedRelayerShare.value,
        clientPublicKey33: ecdsaDerivationClientSharePublicKey33,
        clientShareRetryCounter: request.clientShareRetryCounter,
      });
      const expectedContextBinding32 = base64UrlDecode(request.contextBinding32B64u);
      if (!bytesEqual(expectedContextBinding32, relayerBootstrap.contextBinding32)) {
        return {
          ok: false,
          code: 'context_mismatch',
          message: 'contextBinding32B64u does not match role-local DERIVATION context',
        };
      }
      const keyHandle = await deriveThresholdEcdsaDerivationKeyHandle({
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: signingRootMetadata.signingRootVersion,
      });
      const existing = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (existing) {
        const signingRootVersion = canonicalEcdsaDerivationSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        );
        if (existing.relayerKeyId !== request.relayerKeyId) {
          return {
            ok: false,
            code: 'relayer_key_mismatch',
            message: 'relayerKeyId mismatch requires ECDSA DERIVATION re-bootstrap',
          };
        }
        if (
          existing.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
          existing.keyHandle !== keyHandle ||
          existing.walletId !== request.walletId ||
          existing.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
          existing.signingRootId !== signingRootMetadata.signingRootId ||
          existing.signingRootVersion !== signingRootVersion ||
          existing.keyScope !== request.keyScope ||
          existing.contextBinding32B64u !== request.contextBinding32B64u ||
          existing.clientPublicKey33B64u !== request.derivationClientSharePublicKey33B64u
        ) {
          return {
            ok: false,
            code: 'identity_mismatch',
            message: 'ECDSA DERIVATION key identity mismatch',
          };
        }
      }
      const session = await this.ecdsaMintSessionWithoutWebAuthn({
        relayerKeyId: request.relayerKeyId,
        clientVerifyingShareB64u: request.derivationClientSharePublicKey33B64u,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        sessionId: request.sessionId,
        signingGrantId: request.signingGrantId,
        ttlMsRaw: request.ttlMs,
        remainingUsesRaw: request.remainingUses,
        policyParticipantIds: request.participantIds,
        signingRootMetadata,
      });
      if (!session.ok) {
        return {
          ok: false,
          code:
            session.code === 'invalid_body' || session.code === 'unauthorized'
              ? session.code
              : 'internal',
          message: session.message || 'threshold-ecdsa role-local session mint failed',
        };
      }
      const nowMs = Date.now();
      const relayerPublicKey33B64u = base64UrlEncode(relayerBootstrap.relayerPublicKey33);
      const groupPublicKey33B64u = base64UrlEncode(relayerBootstrap.groupPublicKey33);
      const ethereumAddress = bytesToLowerHex(relayerBootstrap.ethereumAddress20);
      const publicTranscriptDigest32B64u = base64UrlEncode(
        relayerBootstrap.publicTranscriptDigest32,
      );
      const record = {
        version: 'threshold_ecdsa_derivation_role_local_v2',
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        keyHandle,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: canonicalEcdsaDerivationSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        ),
        keyScope: 'evm-family',
        relayerKeyId: request.relayerKeyId,
        contextBinding32B64u: request.contextBinding32B64u,
        relayerShare32B64u: base64UrlEncode(relayerBootstrap.relayerShare32),
        relayerPublicKey33B64u,
        clientPublicKey33B64u: request.derivationClientSharePublicKey33B64u,
        groupPublicKey33B64u,
        ethereumAddress,
        relayerCaitSithInput: {
          participantId: 2,
          mappedPrivateShare32B64u: base64UrlEncode(relayerBootstrap.relayerMappedPrivateShare32),
          verifyingShare33B64u: relayerPublicKey33B64u,
        },
        publicTranscriptDigest32B64u,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        updatedAtMs: nowMs,
      } satisfies EcdsaDerivationRoleLocalKeyRecord;
      await this.ecdsaKeyStore.putRoleLocalByKeyHandle(record);
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-derivation-role-local',
          walletId: request.walletId,
          evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          relayerKeyId: request.relayerKeyId,
          applicationBindingDigestB64u: base64UrlEncode(derivationContext.applicationBindingDigest),
          contextBinding32B64u: request.contextBinding32B64u,
          publicIdentity: {
            derivationClientSharePublicKey33B64u: request.derivationClientSharePublicKey33B64u,
            relayerPublicKey33B64u: relayerPublicKey33B64u as EcdsaDerivationRelayerPublicKey33B64u,
            groupPublicKey33B64u,
            ethereumAddress,
          },
          clientShareRetryCounter: request.clientShareRetryCounter,
          relayerShareRetryCounter: relayerBootstrap.relayerShareRetryCounter,
          publicTranscriptDigest32B64u,
          keyHandle,
          signingRootId: signingRootMetadata.signingRootId,
          signingRootVersion: canonicalEcdsaDerivationSigningRootVersion(
            signingRootMetadata.signingRootVersion,
          ),
          thresholdEcdsaPublicKeyB64u: groupPublicKey33B64u,
          ethereumAddress,
          relayerVerifyingShareB64u: relayerPublicKey33B64u,
          participantIds: session.participantIds,
          thresholdSessionId: session.sessionId,
          signingGrantId: session.signingGrantId || request.signingGrantId,
          expiresAtMs: session.expiresAtMs,
          expiresAt: session.expiresAt,
          remainingUses: session.remainingUses ?? request.remainingUses,
        },
      };
    } catch (error) {
      const message = errorMessage(error);
      if (isEcdsaDerivationPublicKeyValidationError(message)) {
        return {
          ok: false,
          code: 'public_key_invalid',
          message,
        };
      }
      return {
        ok: false,
        code: 'internal',
        message: message || 'threshold-ecdsa role-local bootstrap failed',
      };
    }
  }

  async verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey(
    request: RouterAbEcdsaClientBootstrapRequest & {
      clientRootProof: NonNullable<RouterAbEcdsaClientBootstrapRequest['clientRootProof']>;
    },
  ): Promise<EcdsaDerivationRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaDerivationKeyHandle({
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: request.signingRootId,
        signingRootVersion: request.signingRootVersion,
      });
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'ECDSA role-local key is not active for bootstrap authorization',
        };
      }
      if (
        record.walletId !== request.walletId ||
        record.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
        record.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
        record.keyHandle !== keyHandle ||
        record.signingRootId !== request.signingRootId ||
        record.signingRootVersion !==
          canonicalEcdsaDerivationSigningRootVersion(request.signingRootVersion) ||
        record.relayerKeyId !== request.relayerKeyId ||
        record.keyScope !== request.keyScope ||
        record.contextBinding32B64u !== request.contextBinding32B64u ||
        record.clientPublicKey33B64u !== request.derivationClientSharePublicKey33B64u
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA role-local bootstrap proof does not match persisted key identity',
        };
      }
      const verifiedRootProof = await verifyEcdsaClientRootProof(request.clientRootProof);
      if (!verifiedRootProof.ok) return verifiedRootProof;
      return { ok: true, value: { keyHandle } };
    } catch {
      return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
    }
  }

  private async computeEcdsaDerivationExportConfirmationDigest32(input: {
    request: RouterAbEcdsaExportShareRequest;
  }): Promise<Uint8Array> {
    const { request } = input;
    return await sha256BytesUtf8(
      alphabetizeStringify({
        version: THRESHOLD_ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        relayerKeyId: request.relayerKeyId,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity: request.publicIdentity,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        issuedAtUnixMs: request.issuedAtUnixMs,
        expiresAtUnixMs: request.expiresAtUnixMs,
      }),
    );
  }

  private async computeEcdsaDerivationExportAuthorizationDigest32(input: {
    request: RouterAbEcdsaExportShareRequest;
    keyHandle: string;
    record: EcdsaDerivationRoleLocalKeyRecord;
    claims: RouterAbEcdsaSessionClaims;
  }): Promise<Uint8Array> {
    const { request, record, claims } = input;
    return await sha256BytesUtf8(
      alphabetizeStringify({
        version: THRESHOLD_ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION,
        operation: 'explicit_key_export',
        keyHandle: input.keyHandle,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        relayerKeyId: request.relayerKeyId,
        signingRootId: record.signingRootId,
        signingRootVersion: record.signingRootVersion,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity: request.publicIdentity,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        confirmationDigest32B64u: request.confirmationDigest32B64u,
        issuedAtUnixMs: request.issuedAtUnixMs,
        expiresAtUnixMs: request.expiresAtUnixMs,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        thresholdSessionId: claims.thresholdSessionId,
        signingGrantId: claims.signingGrantId,
        thresholdExpiresAtMs: claims.thresholdExpiresAtMs,
        participantIds: claims.participantIds,
      }),
    );
  }

  private ecdsaDerivationExportReplayScope(input: {
    request: RouterAbEcdsaExportShareRequest;
    keyHandle: string;
    claims: RouterAbEcdsaSessionClaims;
  }): string {
    return [
      'ecdsa-derivation-export',
      input.request.walletId,
      input.request.evmFamilySigningKeySlotId,
      input.request.ecdsaThresholdKeyId,
      input.request.relayerKeyId,
      input.keyHandle,
      input.claims.thresholdSessionId,
    ].join(':');
  }

  private ecdsaDerivationExportReplayKey(request: RouterAbEcdsaExportShareRequest): string {
    return request.exportRequestNonce32B64u;
  }

  async ecdsaDerivationRoleLocalExportShare(input: {
    request: RouterAbEcdsaExportShareRequest;
    keyHandle: string;
    claims: RouterAbEcdsaSessionClaims;
  }): Promise<EcdsaDerivationRouteResult<EcdsaDerivationExportShareResponse>> {
    try {
      const { request } = input;
      const nowMs = Date.now();
      const keyHandle = toOptionalTrimmedString(input.keyHandle);
      if (!keyHandle) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Missing ECDSA DERIVATION key handle',
        };
      }
      const { claims } = input;
      const replayGuard = await this.ecdsaWalletSessionStore.reserveReplayGuard(
        this.ecdsaDerivationExportReplayScope({ request, keyHandle, claims }),
        this.ecdsaDerivationExportReplayKey(request),
        request.expiresAtUnixMs,
      );
      if (!replayGuard.ok) {
        return {
          ok: false,
          code:
            replayGuard.code === 'export_nonce_replay'
              ? 'export_nonce_replay'
              : replayGuard.code === 'export_authorization_expired'
                ? 'export_authorization_expired'
                : 'export_authorization_invalid',
          message: replayGuard.message,
        };
      }
      if (request.expiresAtUnixMs <= nowMs) {
        return {
          ok: false,
          code: 'export_authorization_expired',
          message: 'ECDSA DERIVATION export authorization is expired',
        };
      }
      if (request.issuedAtUnixMs > nowMs + THRESHOLD_ECDSA_DERIVATION_EXPORT_CLOCK_SKEW_MS) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA DERIVATION export authorization issue time is invalid',
        };
      }
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA DERIVATION role-local key not found',
        };
      }
      if (
        record.walletId !== request.walletId ||
        record.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
        record.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
        record.relayerKeyId !== request.relayerKeyId ||
        claims.walletId !== request.walletId ||
        claims.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
        claims.relayerKeyId !== request.relayerKeyId ||
        claims.keyHandle !== keyHandle
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA DERIVATION export request does not match persisted key identity',
        };
      }
      if (record.contextBinding32B64u !== request.contextBinding32B64u) {
        return {
          ok: false,
          code: 'context_mismatch',
          message: 'ECDSA DERIVATION export request context does not match persisted key',
        };
      }
      if (
        record.clientPublicKey33B64u !==
          request.publicIdentity.derivationClientSharePublicKey33B64u ||
        record.relayerPublicKey33B64u !== request.publicIdentity.relayerPublicKey33B64u ||
        record.groupPublicKey33B64u !== request.publicIdentity.groupPublicKey33B64u ||
        record.ethereumAddress.toLowerCase() !==
          request.publicIdentity.ethereumAddress.toLowerCase()
      ) {
        return {
          ok: false,
          code: 'public_key_invalid',
          message: 'ECDSA DERIVATION export request public identity does not match persisted key',
        };
      }
      const expectedConfirmationDigest32 =
        await this.computeEcdsaDerivationExportConfirmationDigest32({
          request,
        });
      if (
        !bytesEqual(base64UrlDecode(request.confirmationDigest32B64u), expectedConfirmationDigest32)
      ) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA DERIVATION export confirmation digest is invalid',
        };
      }
      const expectedAuthorizationDigest32 =
        await this.computeEcdsaDerivationExportAuthorizationDigest32({
          request,
          keyHandle,
          record,
          claims,
        });
      if (
        !bytesEqual(
          base64UrlDecode(request.authorizationDigest32B64u),
          expectedAuthorizationDigest32,
        )
      ) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA DERIVATION export authorization digest is invalid',
        };
      }
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-derivation-role-local-export',
          walletId: request.walletId,
          evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          relayerKeyId: request.relayerKeyId,
          contextBinding32B64u: request.contextBinding32B64u,
          publicIdentity: request.publicIdentity,
          exportAuthorizationDigest32B64u: request.authorizationDigest32B64u,
          serverExportShare32B64u: record.relayerShare32B64u,
        },
      };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'threshold-ecdsa role-local export share failed',
      };
    }
  }
}
