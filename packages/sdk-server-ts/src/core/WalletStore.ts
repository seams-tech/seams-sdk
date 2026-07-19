import type { NormalizedLogger } from './logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdEcdsaChainTarget,
  ThresholdStoreConfigInput,
} from './types';
import type { WalletRegistrationEcdsaWalletKey, WalletId } from './registrationContracts';
import {
  derivationClientSharePublicKey33B64uFromString,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  RouterAbEd25519YaoActivationResultV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parseRouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationRecoveryRequestV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationRecoveryRequestV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { alphabetizeStringify } from '@shared/utils/digests';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT, THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { resolveD1DatabaseFromConfig } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
} from './thresholdEcdsaChainTarget';
import { D1WalletStore } from './d1WalletStore';
import type { D1WalletStoreOptions } from './d1WalletStore';

export {
  D1WalletStore,
  WALLET_STORE_D1_SCHEMA_SQL,
  buildWalletEcdsaSignerRecord,
  ensureWalletStoreD1Schema,
} from './d1WalletStore';
export type { D1WalletStoreOptions, D1WalletStoreSchemaOptions } from './d1WalletStore';

export type WalletRecord = {
  version: 'wallet_v1';
  walletId: WalletId;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletEd25519YaoActiveCapabilityRecord =
  | {
      readonly version: 'wallet_ed25519_yao_registration_capability_v1';
      readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
      readonly nearAccountId: string;
      readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
      readonly activationResult: RouterAbEd25519YaoActivationResultV1<'registration'>;
      readonly runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      readonly version: 'wallet_ed25519_yao_recovery_capability_v1';
      readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
      readonly nearAccountId: string;
      readonly admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
      readonly activationResult: RouterAbEd25519YaoActivationResultV1<'recovery'>;
      readonly runtimePolicyScope: RuntimePolicyScope;
    };

export type WalletEd25519SignerRecord = {
  version: 'wallet_signer_ed25519_v1';
  walletId: WalletId;
  signerId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  signerSlot: number;
  publicKey: string;
  signingWorkerId: string;
  keyVersion: string;
  recoveryExportCapable: boolean;
  participantIds: readonly [number, number];
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: RuntimePolicyScope;
  activeYaoCapability: WalletEd25519YaoActiveCapabilityRecord;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletEcdsaSignerRecord = {
  version: 'wallet_signer_ecdsa_v1';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  signerId: string;
  chainTargetKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: WalletRegistrationEcdsaWalletKey;
  createdAtMs: number;
  updatedAtMs: number;
};

export type WalletSignerRecord = WalletEd25519SignerRecord | WalletEcdsaSignerRecord;

type WalletEcdsaPostRegistrationProofRecordBase = {
  version: 'wallet_ecdsa_pending_session_activation_v1';
  walletId: WalletId;
  lifecycleId: string;
  requestId: string;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  createdAtMs: number;
  expiresAtMs: number;
};

export type WalletEcdsaPendingSessionActivationRecord =
  | (WalletEcdsaPostRegistrationProofRecordBase & {
      operation: 'recovery';
      request: RouterAbEcdsaDerivationRecoveryRequestV1;
      response: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
    })
  | (WalletEcdsaPostRegistrationProofRecordBase & {
      operation: 'refresh';
      request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
      response: RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1;
    });

export type WalletEcdsaPostRegistrationPublicRequest =
  | RouterAbEcdsaDerivationRecoveryRequestV1
  | RouterAbEcdsaDerivationActivationRefreshRequestV1;

export interface WalletStore {
  getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null>;
  getEcdsaSignerByKeyHandle(input: {
    walletId: WalletId;
    keyHandle: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<WalletEcdsaSignerRecord | null>;
  getEcdsaSignerByPublicCapability(input: {
    walletId: WalletId;
    publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  }): Promise<WalletEcdsaSignerRecord | null>;
  getEcdsaSignerByPostRegistrationRequest(input: {
    walletId: WalletId;
    request: WalletEcdsaPostRegistrationPublicRequest;
  }): Promise<WalletEcdsaSignerRecord | null>;
  putEcdsaPendingSessionActivation(
    record: WalletEcdsaPendingSessionActivationRecord,
  ): Promise<void>;
  takeEcdsaPendingSessionActivationPair(input: {
    walletId: WalletId;
    recovery: { readonly lifecycleId: string; readonly requestId: string };
    refresh: { readonly lifecycleId: string; readonly requestId: string };
  }): Promise<{
    readonly recovery: Extract<
      WalletEcdsaPendingSessionActivationRecord,
      { readonly operation: 'recovery' }
    >;
    readonly refresh: Extract<
      WalletEcdsaPendingSessionActivationRecord,
      { readonly operation: 'refresh' }
    >;
  } | null>;
  putSubject(record: WalletRecord): Promise<void>;
  putSigner(record: WalletSignerRecord): Promise<void>;
  putSigners(records: readonly WalletSignerRecord[]): Promise<void>;
}

export function parseWalletEcdsaPendingSessionActivationRecord(
  raw: unknown,
): WalletEcdsaPendingSessionActivationRecord | null {
  if (!isObject(raw) || raw.version !== 'wallet_ecdsa_pending_session_activation_v1') return null;
  const walletId = parseWalletId(raw.walletId);
  const lifecycleId = toOptionalTrimmedString(raw.lifecycleId);
  const requestId = toOptionalTrimmedString(raw.requestId);
  const createdAtMs = normalizeTimestampMs(raw.createdAtMs);
  const expiresAtMs = normalizeTimestampMs(raw.expiresAtMs);
  if (
    !walletId.ok ||
    !lifecycleId ||
    !requestId ||
    createdAtMs == null ||
    expiresAtMs == null ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  try {
    const base = {
      version: 'wallet_ecdsa_pending_session_activation_v1',
      walletId: walletId.value,
      lifecycleId,
      requestId,
      publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(raw.publicCapability),
      createdAtMs,
      expiresAtMs,
    } as const;
    switch (raw.operation) {
      case 'recovery':
        return {
          ...base,
          operation: 'recovery',
          request: parseRouterAbEcdsaDerivationRecoveryRequestV1(raw.request),
          response: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(raw.response),
        };
      case 'refresh':
        return {
          ...base,
          operation: 'refresh',
          request: parseRouterAbEcdsaDerivationActivationRefreshRequestV1(raw.request),
          response: parseRouterAbEcdsaDerivationActivationRefreshForwardedResponseV1(raw.response),
        };
      default:
        return null;
    }
  } catch {
    return null;
  }
}

function ecdsaPublicCapabilitiesEqual(
  left: RouterAbEcdsaDerivationPublicCapabilityV1,
  right: RouterAbEcdsaDerivationPublicCapabilityV1,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

export function ecdsaPostRegistrationRequestMatchesCapability(input: {
  request: WalletEcdsaPostRegistrationPublicRequest;
  capability: RouterAbEcdsaDerivationPublicCapabilityV1;
}): boolean {
  return (
    input.request.client_id === input.capability.client_id &&
    input.request.router_id === input.capability.router_id &&
    alphabetizeStringify(input.request.context) ===
      alphabetizeStringify(input.capability.context) &&
    alphabetizeStringify(input.request.public_identity) ===
      alphabetizeStringify(input.capability.public_identity) &&
    alphabetizeStringify(input.request.signer_set) ===
      alphabetizeStringify(input.capability.signer_set)
  );
}

function isObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v && typeof v === 'object' && !Array.isArray(v));
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

export function resolveWalletStoreNamespace(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.WALLET_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');
  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}wallet:`;
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const isNamespace = (value: unknown): value is CloudflareDurableObjectNamespaceLike =>
    isObject(value) && typeof value.idFromName === 'function' && typeof value.get === 'function';
  const direct = config.namespace;
  if (isNamespace(direct)) return direct;
  const durableObjectNamespace = config.durableObjectNamespace;
  if (isNamespace(durableObjectNamespace)) return durableObjectNamespace;
  const envStyle = config.THRESHOLD_DO_NAMESPACE;
  if (isNamespace(envStyle)) return envStyle;
  return null;
}

function signerFamily(record: WalletSignerRecord): 'ed25519' | 'ecdsa' {
  return record.version === 'wallet_signer_ed25519_v1' ? 'ed25519' : 'ecdsa';
}

function normalizeTimestampMs(value: unknown): number | null {
  const numberValue = Number(value);
  if (!Number.isFinite(numberValue) || numberValue < 0) return null;
  return Math.floor(numberValue);
}

function parseWalletRecord(raw: unknown): WalletRecord | null {
  if (!isObject(raw)) return null;
  if (raw.version !== 'wallet_v1') return null;
  const walletId = parseWalletId(raw.walletId);
  const createdAtMs = normalizeTimestampMs(raw.createdAtMs);
  const updatedAtMs = normalizeTimestampMs(raw.updatedAtMs);
  if (!walletId.ok || createdAtMs == null || updatedAtMs == null) return null;
  return {
    version: 'wallet_v1',
    walletId: walletId.value,
    createdAtMs,
    updatedAtMs,
  };
}

export function parseWalletEcdsaSignerRecord(raw: unknown): WalletEcdsaSignerRecord | null {
  if (!isObject(raw) || raw.version !== 'wallet_signer_ecdsa_v1') return null;
  const walletId = parseWalletId(raw.walletId);
  const evmFamilySigningKeySlotId = toOptionalTrimmedString(raw.evmFamilySigningKeySlotId);
  const signerId = toOptionalTrimmedString(raw.signerId);
  const chainTargetKey = toOptionalTrimmedString(raw.chainTargetKey);
  const chainTarget = thresholdEcdsaChainTargetFromValue(raw.chainTarget);
  const walletKeyRaw = isObject(raw.walletKey) ? raw.walletKey : null;
  const walletKey = walletKeyRaw ? parseWalletRegistrationEcdsaWalletKey(walletKeyRaw) : null;
  const createdAtMs = normalizeTimestampMs(raw.createdAtMs);
  const updatedAtMs = normalizeTimestampMs(raw.updatedAtMs);
  if (
    !walletId.ok ||
    !evmFamilySigningKeySlotId ||
    !signerId ||
    !chainTargetKey ||
    !chainTarget ||
    !walletKey ||
    createdAtMs === null ||
    updatedAtMs === null ||
    walletKey.walletId !== walletId.value ||
    walletKey.evmFamilySigningKeySlotId !== evmFamilySigningKeySlotId ||
    thresholdEcdsaChainTargetKey(chainTarget) !== chainTargetKey ||
    thresholdEcdsaChainTargetKey(walletKey.chainTarget) !== chainTargetKey
  ) {
    return null;
  }
  return {
    version: 'wallet_signer_ecdsa_v1',
    walletId: walletId.value,
    evmFamilySigningKeySlotId,
    signerId,
    chainTargetKey,
    chainTarget,
    walletKey,
    createdAtMs,
    updatedAtMs,
  };
}

function parseWalletRegistrationEcdsaWalletKey(
  raw: Record<string, unknown>,
): WalletRegistrationEcdsaWalletKey | null {
  const walletId = parseWalletId(raw.walletId);
  const chainTarget = thresholdEcdsaChainTargetFromValue(raw.chainTarget);
  const participantIds = raw.participantIds;
  const clientShareRetryCounter = normalizeNonNegativeInteger(raw.clientShareRetryCounter);
  const relayerShareRetryCounter = normalizeNonNegativeInteger(raw.relayerShareRetryCounter);
  let publicCapability;
  try {
    publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(raw.publicCapability);
  } catch {
    return null;
  }
  let derivationClientSharePublicKey33B64u;
  try {
    derivationClientSharePublicKey33B64u = derivationClientSharePublicKey33B64uFromString(
      toOptionalTrimmedString(raw.derivationClientSharePublicKey33B64u) || '',
    );
  } catch {
    return null;
  }
  if (
    raw.keyScope !== 'evm-family' ||
    !walletId.ok ||
    !chainTarget ||
    !Array.isArray(participantIds) ||
    participantIds.length !== 2 ||
    participantIds[0] !== 1 ||
    participantIds[1] !== 2 ||
    clientShareRetryCounter === null ||
    relayerShareRetryCounter === null
  ) {
    return null;
  }
  const evmFamilySigningKeySlotId = toOptionalTrimmedString(raw.evmFamilySigningKeySlotId);
  const keyHandle = toOptionalTrimmedString(raw.keyHandle);
  let ecdsaThresholdKeyId;
  try {
    ecdsaThresholdKeyId = parseSdkEcdsaDerivationThresholdKeyId(raw.ecdsaThresholdKeyId);
  } catch {
    return null;
  }
  const signingRootId = toOptionalTrimmedString(raw.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(raw.signingRootVersion);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(raw.thresholdEcdsaPublicKeyB64u);
  const thresholdOwnerAddress = toOptionalTrimmedString(raw.thresholdOwnerAddress);
  const relayerKeyId = toOptionalTrimmedString(raw.relayerKeyId);
  const relayerVerifyingShareB64u = toOptionalTrimmedString(raw.relayerVerifyingShareB64u);
  const contextBinding32B64u = toOptionalTrimmedString(raw.contextBinding32B64u);
  if (
    !evmFamilySigningKeySlotId ||
    !keyHandle ||
    !signingRootId ||
    !signingRootVersion ||
    !thresholdEcdsaPublicKeyB64u ||
    !thresholdOwnerAddress ||
    !relayerKeyId ||
    !relayerVerifyingShareB64u ||
    !contextBinding32B64u
  ) {
    return null;
  }
  return {
    keyScope: 'evm-family',
    chainTarget,
    walletId: walletId.value,
    evmFamilySigningKeySlotId,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress,
    relayerKeyId,
    relayerVerifyingShareB64u,
    contextBinding32B64u,
    derivationClientSharePublicKey33B64u,
    clientShareRetryCounter,
    relayerShareRetryCounter,
    participantIds: [1, 2],
    publicCapability,
  };
}

function normalizeNonNegativeInteger(value: unknown): number | null {
  const normalized = Number(value);
  return Number.isSafeInteger(normalized) && normalized >= 0 ? normalized : null;
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 wallet store`);
  return normalized;
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1WalletStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

export function buildWalletEd25519SignerId(input: {
  nearAccountId: string;
  signerSlot: number;
}): string {
  const nearAccountId = String(input.nearAccountId || '').trim();
  const signerSlot = Number(input.signerSlot);
  if (!nearAccountId) throw new Error('Ed25519 signer ID requires nearAccountId');
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('Ed25519 signer ID requires an exact signerSlot');
  }
  return `ed25519:${nearAccountId}:${signerSlot}`;
}

class InMemoryWalletStore implements WalletStore {
  private readonly subjects = new Map<string, WalletRecord>();
  private readonly signers = new Map<string, WalletSignerRecord>();

  constructor(private readonly prefix: string) {}

  async getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    return this.subjects.get(`${this.prefix}${walletId}`) ?? null;
  }

  async getEcdsaSignerByKeyHandle(input: {
    walletId: WalletId;
    keyHandle: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<WalletEcdsaSignerRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const keyHandle = toOptionalTrimmedString(input.keyHandle);
    if (!walletId || !keyHandle) return null;
    const chainTargetKey = thresholdEcdsaChainTargetKey(input.chainTarget);
    const matches = [...this.signers.values()].filter(
      (record): record is WalletEcdsaSignerRecord =>
        record.version === 'wallet_signer_ecdsa_v1' &&
        record.walletId === walletId &&
        record.walletKey.keyHandle === keyHandle &&
        record.chainTargetKey === chainTargetKey,
    );
    return matches.length === 1 ? matches[0] : null;
  }

  async getEcdsaSignerByPublicCapability(input: {
    walletId: WalletId;
    publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  }): Promise<WalletEcdsaSignerRecord | null> {
    const matches = [...this.signers.values()].filter(
      (record): record is WalletEcdsaSignerRecord =>
        record.version === 'wallet_signer_ecdsa_v1' &&
        record.walletId === input.walletId &&
        ecdsaPublicCapabilitiesEqual(record.walletKey.publicCapability, input.publicCapability),
    );
    if (matches.length === 0) return null;
    const keyHandle = matches[0]?.walletKey.keyHandle;
    if (!keyHandle || matches.some((record) => record.walletKey.keyHandle !== keyHandle)) {
      throw new Error('Wallet has conflicting ECDSA public capabilities');
    }
    return matches[0] ?? null;
  }

  async getEcdsaSignerByPostRegistrationRequest(input: {
    walletId: WalletId;
    request: WalletEcdsaPostRegistrationPublicRequest;
  }): Promise<WalletEcdsaSignerRecord | null> {
    const matches = [...this.signers.values()].filter(
      (record): record is WalletEcdsaSignerRecord =>
        record.version === 'wallet_signer_ecdsa_v1' &&
        record.walletId === input.walletId &&
        ecdsaPostRegistrationRequestMatchesCapability({
          request: input.request,
          capability: record.walletKey.publicCapability,
        }),
    );
    if (matches.length === 0) return null;
    const keyHandle = matches[0]?.walletKey.keyHandle;
    if (!keyHandle || matches.some((record) => record.walletKey.keyHandle !== keyHandle)) {
      throw new Error('Wallet has conflicting ECDSA post-registration identities');
    }
    return matches[0] ?? null;
  }

  private readonly pendingEcdsaActivations = new Map<
    string,
    WalletEcdsaPendingSessionActivationRecord
  >();

  async putEcdsaPendingSessionActivation(
    record: WalletEcdsaPendingSessionActivationRecord,
  ): Promise<void> {
    this.pendingEcdsaActivations.set(
      `${record.walletId}:${record.lifecycleId}:${record.requestId}`,
      record,
    );
  }

  async takeEcdsaPendingSessionActivationPair(input: {
    walletId: WalletId;
    recovery: { readonly lifecycleId: string; readonly requestId: string };
    refresh: { readonly lifecycleId: string; readonly requestId: string };
  }): Promise<{
    readonly recovery: Extract<
      WalletEcdsaPendingSessionActivationRecord,
      { readonly operation: 'recovery' }
    >;
    readonly refresh: Extract<
      WalletEcdsaPendingSessionActivationRecord,
      { readonly operation: 'refresh' }
    >;
  } | null> {
    const recoveryKey = `${input.walletId}:${input.recovery.lifecycleId}:${input.recovery.requestId}`;
    const refreshKey = `${input.walletId}:${input.refresh.lifecycleId}:${input.refresh.requestId}`;
    const recovery = this.pendingEcdsaActivations.get(recoveryKey);
    const refresh = this.pendingEcdsaActivations.get(refreshKey);
    const now = Date.now();
    if (
      recovery?.operation !== 'recovery' ||
      refresh?.operation !== 'refresh' ||
      recovery.expiresAtMs <= now ||
      refresh.expiresAtMs <= now
    ) {
      return null;
    }
    this.pendingEcdsaActivations.delete(recoveryKey);
    this.pendingEcdsaActivations.delete(refreshKey);
    return { recovery, refresh };
  }

  async putSubject(record: WalletRecord): Promise<void> {
    this.subjects.set(`${this.prefix}${record.walletId}`, record);
  }

  async putSigner(record: WalletSignerRecord): Promise<void> {
    this.signers.set(
      `${this.prefix}${record.walletId}:${signerFamily(record)}:${record.signerId}`,
      record,
    );
  }

  async putSigners(records: readonly WalletSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

class CloudflareDurableObjectWalletStore implements WalletStore {
  private readonly stub: DurableObjectStubLike;

  constructor(
    private readonly input: {
      namespace: CloudflareDurableObjectNamespaceLike;
      objectName: string;
      prefix: string;
    },
  ) {
    const id = input.namespace.idFromName(input.objectName);
    this.stub = input.namespace.get(id) as unknown as DurableObjectStubLike;
  }

  private key(scope: 'subject' | 'signer' | 'ecdsa-session-activation', id: string): string {
    return `${this.input.prefix}${scope}:${id}`;
  }

  private async put(key: string, value: unknown): Promise<void> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op: 'set', key, value }),
    });
    if (!response.ok) {
      throw new Error(`Wallet DO store HTTP ${response.status}: ${await response.text()}`);
    }
  }

  async putSubject(record: WalletRecord): Promise<void> {
    await this.put(this.key('subject', record.walletId), record);
  }

  async getWallet(input: { walletId: WalletId }): Promise<WalletRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op: 'get', key: this.key('subject', walletId) }),
    });
    if (!response.ok) return null;
    const current = (await response.json().catch(() => null)) as { value?: unknown } | null;
    return parseWalletRecord(current?.value);
  }

  async getEcdsaSignerByKeyHandle(input: {
    walletId: WalletId;
    keyHandle: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<WalletEcdsaSignerRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const keyHandle = toOptionalTrimmedString(input.keyHandle);
    if (!walletId || !keyHandle) return null;
    const chainTargetKey = thresholdEcdsaChainTargetKey(input.chainTarget);
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        op: 'get',
        key: this.key('signer', `${walletId}:ecdsa-key-handle:${keyHandle}:${chainTargetKey}`),
      }),
    });
    if (!response.ok) return null;
    const current = (await response.json().catch(() => null)) as { value?: unknown } | null;
    return parseWalletEcdsaSignerRecord(current?.value);
  }

  async getEcdsaSignerByPublicCapability(input: {
    walletId: WalletId;
    publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  }): Promise<WalletEcdsaSignerRecord | null> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        op: 'get',
        key: this.key(
          'signer',
          `${input.walletId}:ecdsa-public-capability:${input.publicCapability.registration_request_digest_b64u}`,
        ),
      }),
    });
    if (!response.ok) return null;
    const current = (await response.json().catch(() => null)) as { value?: unknown } | null;
    const signer = parseWalletEcdsaSignerRecord(current?.value);
    return signer &&
      ecdsaPublicCapabilitiesEqual(signer.walletKey.publicCapability, input.publicCapability)
      ? signer
      : null;
  }

  async getEcdsaSignerByPostRegistrationRequest(input: {
    walletId: WalletId;
    request: WalletEcdsaPostRegistrationPublicRequest;
  }): Promise<WalletEcdsaSignerRecord | null> {
    const capabilityDigest = input.request.public_identity.context_binding_b64u;
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        op: 'get',
        key: this.key('signer', `${input.walletId}:ecdsa-context-binding:${capabilityDigest}`),
      }),
    });
    if (!response.ok) return null;
    const current = (await response.json().catch(() => null)) as { value?: unknown } | null;
    const signer = parseWalletEcdsaSignerRecord(current?.value);
    return signer &&
      ecdsaPostRegistrationRequestMatchesCapability({
        request: input.request,
        capability: signer.walletKey.publicCapability,
      })
      ? signer
      : null;
  }

  async putEcdsaPendingSessionActivation(
    record: WalletEcdsaPendingSessionActivationRecord,
  ): Promise<void> {
    await this.put(
      this.key(
        'ecdsa-session-activation',
        `${record.walletId}:${record.lifecycleId}:${record.requestId}`,
      ),
      record,
    );
  }

  async takeEcdsaPendingSessionActivationPair(input: {
    walletId: WalletId;
    recovery: { readonly lifecycleId: string; readonly requestId: string };
    refresh: { readonly lifecycleId: string; readonly requestId: string };
  }): Promise<{
    readonly recovery: Extract<
      WalletEcdsaPendingSessionActivationRecord,
      { readonly operation: 'recovery' }
    >;
    readonly refresh: Extract<
      WalletEcdsaPendingSessionActivationRecord,
      { readonly operation: 'refresh' }
    >;
  } | null> {
    const response = await this.stub.fetch('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        op: 'walletTakeEcdsaPendingSessionActivationPair',
        recoveryKey: this.key(
          'ecdsa-session-activation',
          `${input.walletId}:${input.recovery.lifecycleId}:${input.recovery.requestId}`,
        ),
        refreshKey: this.key(
          'ecdsa-session-activation',
          `${input.walletId}:${input.refresh.lifecycleId}:${input.refresh.requestId}`,
        ),
      }),
    });
    if (!response.ok) return null;
    const current: unknown = await response.json().catch(() => null);
    if (!isObject(current) || current.ok !== true || !isObject(current.value)) {
      return null;
    }
    const recovery = parseWalletEcdsaPendingSessionActivationRecord(current.value.recovery);
    const refresh = parseWalletEcdsaPendingSessionActivationRecord(current.value.refresh);
    const now = Date.now();
    if (
      recovery?.operation !== 'recovery' ||
      refresh?.operation !== 'refresh' ||
      recovery.expiresAtMs <= now ||
      refresh.expiresAtMs <= now
    ) {
      return null;
    }
    return { recovery, refresh };
  }

  async putSigner(record: WalletSignerRecord): Promise<void> {
    await this.put(
      this.key('signer', `${record.walletId}:${signerFamily(record)}:${record.signerId}`),
      record,
    );
    if (record.version === 'wallet_signer_ecdsa_v1') {
      await this.put(
        this.key(
          'signer',
          `${record.walletId}:ecdsa-key-handle:${record.walletKey.keyHandle}:${record.chainTargetKey}`,
        ),
        record,
      );
      await this.put(
        this.key(
          'signer',
          `${record.walletId}:ecdsa-public-capability:${record.walletKey.publicCapability.registration_request_digest_b64u}`,
        ),
        record,
      );
      await this.put(
        this.key(
          'signer',
          `${record.walletId}:ecdsa-context-binding:${record.walletKey.publicCapability.public_identity.context_binding_b64u}`,
        ),
        record,
      );
    }
  }

  async putSigners(records: readonly WalletSignerRecord[]): Promise<void> {
    for (const record of records) {
      await this.putSigner(record);
    }
  }
}

export function createWalletStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WalletStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = resolveWalletStoreNamespace(config);
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'd1') {
    const database = resolveD1DatabaseFromConfig(config);
    if (!database) {
      throw new Error('[wallet] D1 store selected but no D1 database was provided');
    }
    input.logger.info('[wallet] Using D1 store');
    return new D1WalletStore({
      database,
      ...d1ScopeFromConfig({ config, namespace: prefix }),
    });
  }
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do wallet store selected but no Durable Object namespace was provided',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[wallet] Using Cloudflare Durable Object store');
    return new CloudflareDurableObjectWalletStore({ namespace, objectName, prefix });
  }
  if (kind) throw new Error(`[wallet] Unknown wallet store kind: ${kind}`);
  input.logger.info('[wallet] Using in-memory store (non-persistent)');
  return new InMemoryWalletStore(prefix);
}
