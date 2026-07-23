/**
 * UserConfirm Web Worker
 *
 * Hosts the UserConfirm handshake runtime (`awaitUserConfirmationV2`) and the
 * threshold warm-session material cache.
 */
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  RouterAbEd25519YaoExportWorkerPayloadV1,
  WarmSessionSealAndPersistDiagnostics,
} from '@/core/types/secure-confirm-worker';
import { ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1 } from '@/core/types/secure-confirm-worker';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseClearVolatileWarmMaterialCommand } from '@/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands';
import { bytesToHex } from '../../chains/evm/bytes';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseSigningGrantId,
  parseThresholdEd25519SessionId,
  parseWalletId,
  type SigningGrantId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { base58Encode } from '@shared/utils/base58';
import { WALLET_SESSION_SEAL_BASE_PATH } from '@shared/utils/signingSessionSeal';
import {
  joinNormalizedUrl,
  normalizeNonNegativeInteger,
  normalizeOptionalTrimmedString,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { awaitUserConfirmationV2 } from '../../uiConfirm/awaitUserConfirmation';
import { getShamir3PassRuntime } from './shamir3pass/runtime';
import {
  UserConfirmationType,
  UserConfirmMessageType,
  type ExportPrivateKeyDisplayEntry,
  type LocalOnlyExportSubject,
  type UserConfirmRequest,
  type UserConfirmDecision,
} from '../../stepUpConfirmation/channel/confirmTypes';
import initEvmCrypto, {
  derive_secp256k1_keypair_from_prf_second,
  init_evm_crypto,
} from '../../../../../../../wasm/evm_crypto/pkg/evm_crypto.js';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
} from '../../threshold/ed25519/yaoClient';
import {
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoExportAuthorizationIdentityV1,
} from '@shared/utils/routerAbEd25519Yao';
import { normalizeThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { normalizeAuthenticationCredential } from '../../webauthnAuth/credentials/helpers';

// Expose the confirmation bridge under the JS name expected by wasm-bindgen.
// awaitUserConfirmationV2 expects a UserConfirmRequest object.
type UserConfirmWorkerGlobal = typeof globalThis & {
  awaitUserConfirmationV2?: typeof awaitUserConfirmationV2;
};
(globalThis as UserConfirmWorkerGlobal).awaitUserConfirmationV2 = awaitUserConfirmationV2;

type WarmSessionMaterialEntry = {
  prfFirstHandle: string;
  expiresAtMs: number;
  remainingUses: number;
};

type PasskeyPrfFirstHandleEntry = {
  prfFirstB64u: string;
  expiresAtMs: number;
};

type PasskeyServerSealedSecretCacheEntry = {
  sealedSecretB64u: string;
  expiresAtMs: number;
};

type PasskeyServerSealedSecretCacheScope = {
  kind: 'passkey_registration';
  walletId: string;
  credentialIdB64u: string;
  signingGrantId: string;
};

type OkResult = { ok: true; remainingUses: number; expiresAtMs: number };
type OkSealResult = OkResult & {
  sealedSecretB64u: string;
  keyVersion?: string;
  diagnostics?: WarmSessionSealAndPersistDiagnostics;
};
type OkDispenseResult = OkResult & { prfFirstB64u: string };
type ErrResult = { ok: false; code: string; message: string };
type WarmSessionMaterialReadResult =
  | ({ ok: true; entry: WarmSessionMaterialEntry; secret: PasskeyPrfFirstHandleEntry } & OkResult)
  | ErrResult;

const PASSKEY_SERVER_SEALED_SECRET_CACHE_MAX_ENTRIES = 32;

type SigningSessionSealTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  serverSealedSecretCacheScope?: PasskeyServerSealedSecretCacheScope;
};

type SigningSessionSealRouteResult =
  | {
      ok: true;
      ciphertext: string;
      keyVersion?: string;
      expiresAtMs?: number;
      remainingUses?: number;
    }
  | ErrResult;

const warmSessionPrfHandleCache = new Map<string, WarmSessionMaterialEntry>();
const passkeyPrfFirstHandleStore = new Map<string, PasskeyPrfFirstHandleEntry>();
const passkeyServerSealedSecretCache = new Map<string, PasskeyServerSealedSecretCacheEntry>();
const signingSessionSealApplyInFlight = new Map<string, Promise<OkSealResult | ErrResult>>();
const signingSessionSealRemoveInFlight = new Map<string, Promise<OkResult | ErrResult>>();
const evmCryptoWasmUrl = resolveWasmUrl('evm_crypto.wasm', 'Eth Signer');
const SIGNING_SESSION_SEAL_BASE_PATH = WALLET_SESSION_SEAL_BASE_PATH;
type EcdsaDerivationThresholdExportWorkerPayload = Extract<
  ExportPrivateKeysWithUiWorkerPayload,
  { artifactKind: 'ecdsa-derivation-secp256k1-export' }
>;

type ExportWorkerTarget = {
  kind: 'ecdsa';
  scheme: 'secp256k1';
  chainTarget: ThresholdEcdsaChainTarget;
};

type Secp256k1ExportPrivateKeyDisplayEntry = ExportPrivateKeyDisplayEntry & {
  scheme: 'secp256k1';
};

type Ed25519ExportPrivateKeyDisplayEntry = ExportPrivateKeyDisplayEntry & {
  scheme: 'ed25519';
};

let evmCryptoWasmInitPromise: Promise<void> | null = null;

type UserConfirmWorkerIncomingMessage = {
  id?: unknown;
  type?: unknown;
  payload?: unknown;
};

function asIncomingMessage(value: unknown): UserConfirmWorkerIncomingMessage {
  const record = asRecord(value);
  if (!record) return {};
  return {
    id: record.id,
    type: record.type,
    payload: record.payload,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

function nowMs(): number {
  return Date.now();
}

function roundWorkerDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function createWarmSessionSealAndPersistDiagnostics(): WarmSessionSealAndPersistDiagnostics {
  return {
    runtimeSetupMs: 0,
    clientSealMs: 0,
    serverSealRouteMs: 0,
    clientUnsealMs: 0,
    policyUpdateMs: 0,
  };
}

function recordWarmSessionSealAndPersistDiagnosticDuration(args: {
  diagnostics: WarmSessionSealAndPersistDiagnostics;
  bucket: keyof WarmSessionSealAndPersistDiagnostics;
  startedAt: number;
}): void {
  args.diagnostics[args.bucket] += roundWorkerDurationMs(args.startedAt);
}

function overwriteBytes(bytes: Uint8Array | null | undefined): void {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
  bytes.fill(0);
}

function toSessionId(prefix: string): string {
  const value = String(prefix || '').trim() || 'session';
  return `${value}:${secureRandomBase64Url(32, 'passkey confirm worker session IDs')}`;
}

function createPasskeyPrfFirstHandle(args: { prfFirstB64u: string; expiresAtMs: number }): string {
  const prfFirstB64u = normalizeOptionalTrimmedString(args.prfFirstB64u);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (!prfFirstB64u || expiresAtMs <= nowMs()) {
    throw new Error('Invalid passkey PRF material handle input');
  }
  const prfFirstHandle = toSessionId('passkey-prf-first');
  passkeyPrfFirstHandleStore.set(prfFirstHandle, {
    prfFirstB64u,
    expiresAtMs,
  });
  return prfFirstHandle;
}

async function sha256HexUtf8(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
}

async function passkeyServerSealedSecretCacheKey(args: {
  prfFirstB64u: string;
  relayerUrl: string;
  keyVersion: string;
  shamirPrimeB64u: string;
  cacheScope: PasskeyServerSealedSecretCacheScope | undefined;
}): Promise<string | null> {
  const prfFirstB64u = normalizeOptionalTrimmedString(args.prfFirstB64u);
  const relayerUrl = normalizeOptionalTrimmedString(args.relayerUrl);
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.shamirPrimeB64u);
  const cacheScope = args.cacheScope;
  if (!prfFirstB64u || !relayerUrl || !keyVersion || !shamirPrimeB64u || !cacheScope) {
    return null;
  }
  const prfDigestHex = await sha256HexUtf8(prfFirstB64u);
  return [
    'passkey-server-sealed-secret-v1',
    relayerUrl,
    keyVersion,
    shamirPrimeB64u,
    cacheScope.walletId,
    cacheScope.credentialIdB64u,
    cacheScope.signingGrantId,
    prfDigestHex,
  ].join('|');
}

function prunePasskeyServerSealedSecretCache(): void {
  const now = nowMs();
  for (const [key, entry] of passkeyServerSealedSecretCache) {
    if (entry.expiresAtMs <= now) {
      passkeyServerSealedSecretCache.delete(key);
    }
  }
  while (passkeyServerSealedSecretCache.size > PASSKEY_SERVER_SEALED_SECRET_CACHE_MAX_ENTRIES) {
    const firstKey = passkeyServerSealedSecretCache.keys().next().value;
    if (typeof firstKey !== 'string') return;
    passkeyServerSealedSecretCache.delete(firstKey);
  }
}

function readPasskeyServerSealedSecretCache(
  cacheKey: string | null,
): PasskeyServerSealedSecretCacheEntry | null {
  if (!cacheKey) return null;
  prunePasskeyServerSealedSecretCache();
  const entry = passkeyServerSealedSecretCache.get(cacheKey);
  if (!entry || entry.expiresAtMs <= nowMs()) {
    if (entry) passkeyServerSealedSecretCache.delete(cacheKey);
    return null;
  }
  return entry;
}

function writePasskeyServerSealedSecretCache(args: {
  cacheKey: string | null;
  sealedSecretB64u: string;
  expiresAtMs: number;
}): void {
  if (!args.cacheKey) return;
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (!sealedSecretB64u || expiresAtMs <= nowMs()) return;
  passkeyServerSealedSecretCache.set(args.cacheKey, { sealedSecretB64u, expiresAtMs });
  prunePasskeyServerSealedSecretCache();
}

function deleteWarmSessionPrfHandle(sessionId: string): void {
  const entry = warmSessionPrfHandleCache.get(sessionId);
  if (entry) passkeyPrfFirstHandleStore.delete(entry.prfFirstHandle);
  warmSessionPrfHandleCache.delete(sessionId);
}

function clearWarmSessionPrfHandles(): void {
  warmSessionPrfHandleCache.clear();
  passkeyPrfFirstHandleStore.clear();
  passkeyServerSealedSecretCache.clear();
}

function storeWarmSessionPrfHandle(args: {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
}): WarmSessionMaterialEntry {
  const sessionId = normalizeOptionalTrimmedString(args.sessionId);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (!sessionId || remainingUses <= 0 || expiresAtMs <= nowMs()) {
    throw new Error('Invalid warm-session PRF handle input');
  }
  deleteWarmSessionPrfHandle(sessionId);
  const prfFirstHandle = createPasskeyPrfFirstHandle({
    prfFirstB64u: args.prfFirstB64u,
    expiresAtMs,
  });
  const entry = { prfFirstHandle, expiresAtMs, remainingUses };
  warmSessionPrfHandleCache.set(sessionId, entry);
  return entry;
}

function updateWarmSessionPrfHandlePolicy(
  sessionId: string,
  entry: WarmSessionMaterialEntry,
  policy: OkResult,
): WarmSessionMaterialEntry {
  const nextEntry = {
    prfFirstHandle: entry.prfFirstHandle,
    remainingUses: policy.remainingUses,
    expiresAtMs: policy.expiresAtMs,
  };
  const secret = passkeyPrfFirstHandleStore.get(entry.prfFirstHandle);
  if (secret) {
    passkeyPrfFirstHandleStore.set(entry.prfFirstHandle, {
      prfFirstB64u: secret.prfFirstB64u,
      expiresAtMs: policy.expiresAtMs,
    });
  }
  warmSessionPrfHandleCache.set(sessionId, nextEntry);
  return nextEntry;
}

function isCancellationLikeError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  const lowered = message.toLowerCase();
  return (
    lowered.includes('notallowederror') ||
    lowered.includes('aborterror') ||
    lowered.includes('user cancelled') ||
    lowered.includes('user canceled') ||
    lowered.includes('user aborted') ||
    lowered.includes('rejected')
  );
}

function messageFromError(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.trim() || fallback;
}

function coerceTheme(value: unknown): 'dark' | 'light' | undefined {
  return value === 'dark' || value === 'light' ? value : undefined;
}

function coerceVariant(value: unknown): 'drawer' | 'modal' | undefined {
  return value === 'drawer' || value === 'modal' ? value : undefined;
}

function parseExportWorkerTarget(payload: Record<string, unknown>): ExportWorkerTarget | null {
  const rawChainTarget = asRecord(payload.chainTarget);
  if (!rawChainTarget) return null;
  try {
    return {
      kind: 'ecdsa',
      scheme: 'secp256k1',
      chainTarget: thresholdEcdsaChainTargetFromRequest(rawChainTarget),
    };
  } catch {
    return null;
  }
}

function secp256k1LabelForExportTarget(chainTarget: ThresholdEcdsaChainTarget): string {
  return chainTarget.kind === 'tempo' ? 'Tempo secp256k1' : 'EVM secp256k1';
}

function labelForExportTarget(target: ExportWorkerTarget): string {
  return secp256k1LabelForExportTarget(target.chainTarget);
}

function parseWorkerBytes32(value: unknown): readonly number[] | null {
  if (!Array.isArray(value) || value.length !== 32) return null;
  const bytes: number[] = [];
  for (const entry of value) {
    if (!Number.isInteger(entry) || entry < 0 || entry > 255) return null;
    bytes.push(entry);
  }
  return bytes;
}

function parseEd25519YaoExportWorkerPayload(
  payload: Record<string, unknown>,
): RouterAbEd25519YaoExportWorkerPayloadV1 | null {
  if (payload.artifactKind !== ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1) return null;
  const parsedWalletId = parseWalletId(payload.walletId);
  if (!parsedWalletId.ok) return null;
  const nearAccountId = normalizeOptionalNonEmptyString(payload.nearAccountId);
  const relayerUrl = normalizeOptionalNonEmptyString(payload.relayerUrl);
  const walletSessionJwt = normalizeOptionalNonEmptyString(payload.walletSessionJwt);
  const flowId = normalizeOptionalNonEmptyString(payload.flowId);
  const viewerSessionId = normalizeOptionalNonEmptyString(payload.viewerSessionId);
  const exactLane = asRecord(payload.exactLane);
  const capability = asRecord(payload.capability);
  if (
    !nearAccountId ||
    !relayerUrl ||
    !walletSessionJwt ||
    !flowId ||
    !viewerSessionId ||
    !exactLane ||
    !capability
  ) {
    return null;
  }
  const nearEd25519SigningKeyId = normalizeOptionalNonEmptyString(
    exactLane.nearEd25519SigningKeyId,
  );
  const credentialIdB64u = normalizeOptionalNonEmptyString(exactLane.credentialIdB64u);
  const signingGrantId = normalizeOptionalNonEmptyString(exactLane.signingGrantId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(exactLane.thresholdSessionId);
  const activeStateSessionId = normalizeOptionalNonEmptyString(exactLane.activeStateSessionId);
  const signerSlot = normalizePositiveInteger(exactLane.signerSlot);
  const registeredPublicKey = parseWorkerBytes32(capability.registeredPublicKey);
  const activeCapabilityBinding = parseWorkerBytes32(capability.activeCapabilityBinding);
  const stateEpoch = normalizeNonNegativeInteger(capability.stateEpoch);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(capability.runtimePolicyScope);
  const activationIdentity = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: capability.scope,
    application_binding: capability.applicationBinding,
    participant_ids: capability.participantIds,
  });
  if (
    !nearEd25519SigningKeyId ||
    !credentialIdB64u ||
    !signingGrantId ||
    !thresholdSessionId ||
    !activeStateSessionId ||
    signerSlot == null ||
    !registeredPublicKey ||
    !activeCapabilityBinding ||
    stateEpoch == null ||
    !runtimePolicyScope ||
    !activationIdentity.ok
  ) {
    return null;
  }
  return {
    artifactKind: ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1,
    walletId: String(parsedWalletId.value),
    nearAccountId,
    relayerUrl,
    walletSessionJwt,
    flowId,
    viewerSessionId,
    exactLane: {
      nearEd25519SigningKeyId,
      signerSlot,
      credentialIdB64u,
      signingGrantId,
      thresholdSessionId,
      activeStateSessionId,
    },
    capability: {
      scope: activationIdentity.value.scope,
      applicationBinding: activationIdentity.value.application_binding,
      participantIds: activationIdentity.value.participant_ids,
      registeredPublicKey,
      stateEpoch,
      activeCapabilityBinding,
      runtimePolicyScope,
    },
    variant: coerceVariant(payload.variant),
    theme: coerceTheme(payload.theme),
  };
}

function parseExportRequestPayload(value: unknown): ExportPrivateKeysWithUiWorkerPayload | null {
  const payload = asRecord(value);
  if (!payload) return null;
  if (payload.artifactKind === ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1) {
    return parseEd25519YaoExportWorkerPayload(payload);
  }
  const target = parseExportWorkerTarget(payload);
  const artifactKind = normalizeOptionalNonEmptyString(payload.artifactKind);
  if (!target) return null;
  const variant = coerceVariant(payload.variant);
  const theme = coerceTheme(payload.theme);
  const parsedWalletId = parseWalletId(payload.walletId);
  if (!parsedWalletId.ok) return null;
  const walletId = String(parsedWalletId.value);
  if (artifactKind === 'ecdsa-derivation-secp256k1-export') {
    const publicKeyHex = normalizeOptionalNonEmptyString(payload.publicKeyHex);
    const privateKeyHex = normalizeOptionalNonEmptyString(payload.privateKeyHex);
    const ethereumAddress = normalizeOptionalNonEmptyString(payload.ethereumAddress);
    if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
      return null;
    }
    return {
      walletId,
      chainTarget: target.chainTarget,
      artifactKind,
      publicKeyHex,
      privateKeyHex,
      ethereumAddress,
      variant,
      theme,
    };
  }
  if (artifactKind) {
    return null;
  }
  return {
    walletId,
    chainTarget: target.chainTarget,
    variant,
    theme,
  };
}

function isRouterAbEd25519YaoExportWorkerPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): payload is RouterAbEd25519YaoExportWorkerPayloadV1 {
  return (
    'artifactKind' in payload &&
    payload.artifactKind === ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1
  );
}

function requireEcdsaDerivationThresholdExportPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): EcdsaDerivationThresholdExportWorkerPayload {
  if (
    !('artifactKind' in payload) ||
    payload.artifactKind !== 'ecdsa-derivation-secp256k1-export'
  ) {
    throw new Error('ecdsa-derivation secp256k1 export artifact metadata missing or invalid');
  }
  return payload;
}

function exportSubjectIdForPayload(payload: ExportPrivateKeysWithUiWorkerPayload): string {
  return payload.walletId;
}

function requireExportWalletId(raw: string): string {
  const parsed = parseWalletId(raw);
  if (!parsed.ok) {
    throw new Error('ECDSA export requires wallet identity');
  }
  return String(parsed.value);
}

function requireExportThresholdSessionId(raw: string): ThresholdEd25519SessionId {
  const parsed = parseThresholdEd25519SessionId(raw);
  if (!parsed.ok) {
    throw new Error('Ed25519 export requires a threshold session identity');
  }
  return parsed.value;
}

function requireExportSigningGrantId(raw: string): SigningGrantId {
  const parsed = parseSigningGrantId(raw);
  if (!parsed.ok) {
    throw new Error('Ed25519 export requires a signing grant identity');
  }
  return parsed.value;
}

function localOnlyExportSubjectForTarget(args: {
  exportTarget: ExportWorkerTarget;
  exportSubjectId: string;
}): LocalOnlyExportSubject {
  return {
    kind: 'evm_wallet',
    walletId: requireExportWalletId(args.exportSubjectId),
  };
}

function exportIntentDigestForPayload(args: {
  payload: ExportPrivateKeysWithUiWorkerPayload;
  exportSubjectId: string;
  exportTarget: ExportWorkerTarget;
}): string {
  return `export-keys:${args.exportSubjectId}:${thresholdEcdsaChainTargetKey(args.exportTarget.chainTarget)}:secp256k1`;
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = asRecord(value);
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  const walletSessionJwt = normalizeOptionalNonEmptyString(transport.walletSessionJwt);
  const keyVersion = normalizeOptionalNonEmptyString(transport.signingSessionSealKeyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(transport.shamirPrimeB64u);
  const serverSealedSecretCacheScope = parsePasskeyServerSealedSecretCacheScope(
    transport.serverSealedSecretCacheScope,
  );
  if (!relayerUrl) return null;
  return {
    relayerUrl,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    ...(serverSealedSecretCacheScope ? { serverSealedSecretCacheScope } : {}),
  };
}

function parsePasskeyServerSealedSecretCacheScope(
  value: unknown,
): PasskeyServerSealedSecretCacheScope | undefined {
  const scope = asRecord(value);
  if (!scope || scope.kind !== 'passkey_registration') return undefined;
  const walletId = normalizeOptionalNonEmptyString(scope.walletId);
  const credentialIdB64u = normalizeOptionalNonEmptyString(scope.credentialIdB64u);
  const signingGrantId = normalizeOptionalNonEmptyString(scope.signingGrantId);
  if (!walletId || !credentialIdB64u || !signingGrantId) return undefined;
  return {
    kind: 'passkey_registration',
    walletId,
    credentialIdB64u,
    signingGrantId,
  };
}

function parseSigningSessionSealRouteResult(value: unknown): SigningSessionSealRouteResult {
  const result = asRecord(value);
  if (!result || typeof result.ok !== 'boolean') {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Invalid signing-session seal response',
    };
  }
  if (!result.ok) {
    return {
      ok: false,
      code: typeof result.code === 'string' ? result.code : 'request_failed',
      message:
        typeof result.message === 'string' ? result.message : 'Signing-session seal request failed',
    };
  }
  const ciphertext = normalizeOptionalTrimmedString(result.ciphertext);
  const keyVersion = normalizeOptionalNonEmptyString(result.keyVersion);
  const expiresAtMs = normalizePositiveInteger(result.expiresAtMs);
  const remainingUses = normalizeNonNegativeInteger(result.remainingUses);
  if (!ciphertext) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Missing ciphertext in signing-session seal response',
    };
  }
  return {
    ok: true,
    ciphertext,
    ...(keyVersion ? { keyVersion } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
    ...(remainingUses != null ? { remainingUses } : {}),
  };
}

function makeSigningSessionSealSingleFlightKey(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  sessionId: string;
  relayerUrl: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  payloadKey?: string;
}): string {
  const operation =
    args.operation === 'apply-server-seal' ? 'apply-server-seal' : 'remove-server-seal';
  const sessionId = normalizeOptionalTrimmedString(args.sessionId) || '';
  const relayerUrl = normalizeOptionalTrimmedString(args.relayerUrl) || '';
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion) || '';
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.shamirPrimeB64u) || '';
  const payloadKey = normalizeOptionalNonEmptyString(args.payloadKey) || '';
  return `${operation}|${sessionId}|${relayerUrl}|${keyVersion}|${shamirPrimeB64u}|${payloadKey}`;
}

async function callSigningSessionSealRoute(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  transport: SigningSessionSealTransport;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
}): Promise<SigningSessionSealRouteResult> {
  const routePath =
    args.operation === 'apply-server-seal' ? 'apply-server-seal' : 'remove-server-seal';
  const url = joinNormalizedUrl(
    args.transport.relayerUrl,
    `${SIGNING_SESSION_SEAL_BASE_PATH}/${routePath}`,
  );

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const walletSessionJwt = normalizeOptionalNonEmptyString(args.transport.walletSessionJwt);
    const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
    if (walletSessionJwt) {
      headers.Authorization = `Bearer ${walletSessionJwt}`;
    }
    const response = await fetch(url, {
      method: 'POST',
      credentials: walletSessionJwt ? 'omit' : 'include',
      headers,
      body: JSON.stringify({
        thresholdSessionId: args.thresholdSessionId,
        ciphertext: args.ciphertext,
        ...(keyVersion ? { keyVersion } : {}),
      }),
    });
    const data = await response.json().catch(() => null);
    const parsed = parseSigningSessionSealRouteResult(data);
    if (!response.ok && parsed.ok) {
      return {
        ok: false,
        code: 'http_error',
        message: `Signing-session seal route returned HTTP ${response.status}`,
      };
    }
    if (!parsed.ok) return parsed;
    return parsed;
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'network_error',
      message:
        error instanceof Error
          ? error.message
          : String(error || 'Signing-session seal request failed'),
    };
  }
}

function resolvePolicyFromServerAndLocal(args: {
  localRemainingUses: number;
  localExpiresAtMs: number;
  serverRemainingUses?: number;
  serverExpiresAtMs?: number;
}): OkResult | ErrResult {
  const localRemainingUses = Math.max(0, Math.floor(Number(args.localRemainingUses) || 0));
  const localExpiresAtMs = Math.max(0, Math.floor(Number(args.localExpiresAtMs) || 0));
  const serverRemainingUses =
    normalizeNonNegativeInteger(args.serverRemainingUses) ?? localRemainingUses;
  const serverExpiresAtMs = normalizePositiveInteger(args.serverExpiresAtMs) || localExpiresAtMs;
  const remainingUses = Math.min(localRemainingUses, serverRemainingUses);
  const expiresAtMs = Math.min(localExpiresAtMs, serverExpiresAtMs);
  if (remainingUses <= 0) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  if (expiresAtMs <= nowMs()) {
    return {
      ok: false,
      code: 'expired',
      message: 'Warm-session material expired for threshold session',
    };
  }
  return { ok: true, remainingUses, expiresAtMs };
}

function requirePrfB64uFromCredential(
  credential: WebAuthnAuthenticationCredential,
  output: 'first' | 'second',
): string {
  const results = asRecord(credential.clientExtensionResults);
  const prf = asRecord(results?.prf);
  const prfResults = asRecord(prf?.results);
  const value = normalizeOptionalTrimmedString(prfResults?.[output]);
  if (!value) {
    throw new Error(
      `Missing PRF.${output} output from credential (requires a PRF-enabled passkey)`,
    );
  }
  return value;
}

async function ensureEvmCryptoWasmReady(): Promise<void> {
  if (evmCryptoWasmInitPromise) return evmCryptoWasmInitPromise;
  evmCryptoWasmInitPromise = (async () => {
    try {
      await initEvmCrypto({ module_or_path: evmCryptoWasmUrl });
      init_evm_crypto();
    } catch (error: unknown) {
      evmCryptoWasmInitPromise = null;
      throw error;
    }
  })();
  return evmCryptoWasmInitPromise;
}

async function deriveSecp256k1FromPrfSecondInWorker(args: {
  prfSecondB64u: string;
  derivationSubjectId: string;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  await ensureEvmCryptoWasmReady();
  const prfSecond = base64UrlDecode(args.prfSecondB64u);
  try {
    const out = derive_secp256k1_keypair_from_prf_second(prfSecond, args.derivationSubjectId);
    if (out.length !== 85) {
      throw new Error(
        `derive_secp256k1_keypair_from_prf_second must return 85 bytes (got ${out.length})`,
      );
    }
    const privateKey32 = out.slice(0, 32);
    const publicKey33 = out.slice(32, 65);
    const ethereumAddress20 = out.slice(65, 85);
    return {
      privateKeyHex: bytesToHex(privateKey32),
      publicKeyHex: bytesToHex(publicKey33),
      ethereumAddress: bytesToHex(ethereumAddress20),
    };
  } finally {
    prfSecond.fill(0);
  }
}

function freshExportNonce32(): Uint8Array {
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return nonce;
}

function ed25519ExportCredentialMatches(
  credential: WebAuthnAuthenticationCredential,
  credentialIdB64u: string,
): boolean {
  return credential.id === credentialIdB64u || credential.rawId === credentialIdB64u;
}

function clearEd25519ExportDisplayEntries(entries: Ed25519ExportPrivateKeyDisplayEntry[]): void {
  for (const entry of entries) entry.privateKey = '';
}

function ignoreExportViewerError(): undefined {
  return undefined;
}

function assertExactEd25519ExportWorkerBinding(
  payload: RouterAbEd25519YaoExportWorkerPayloadV1,
): void {
  const capability = payload.capability;
  const application = capability.applicationBinding;
  const scope = capability.scope;
  if (
    application.wallet_id !== payload.walletId ||
    application.near_ed25519_signing_key_id !== payload.exactLane.nearEd25519SigningKeyId ||
    application.key_creation_signer_slot !== payload.exactLane.signerSlot ||
    scope.account_id !== payload.walletId ||
    scope.wallet_session_id !== payload.exactLane.activeStateSessionId
  ) {
    throw new Error('Ed25519 Yao export capability does not match the exact requested lane');
  }
}

async function buildEd25519ExportAuthorizationIdentity(
  payload: RouterAbEd25519YaoExportWorkerPayloadV1,
): Promise<RouterAbEd25519YaoExportAuthorizationIdentityV1> {
  const runtimePolicyBinding = await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
    payload.capability.runtimePolicyScope,
  );
  return {
    scope: payload.capability.scope,
    application_binding: payload.capability.applicationBinding,
    participant_ids: payload.capability.participantIds,
    registered_public_key: payload.capability.registeredPublicKey,
    state_epoch: payload.capability.stateEpoch,
    runtime_policy_binding: runtimePolicyBinding,
  };
}

async function runEd25519YaoExportWithUi(
  payload: RouterAbEd25519YaoExportWorkerPayloadV1,
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  assertExactEd25519ExportWorkerBinding(payload);
  const publicKey = `ed25519:${base58Encode(Uint8Array.from(payload.capability.registeredPublicKey))}`;
  const subject = { kind: 'near_wallet' as const, nearAccountId: payload.nearAccountId };
  const requestId = toSessionId('export-ed25519-yao');
  const viewerSessionId = payload.viewerSessionId;
  const issuedAtMs = nowMs();
  const expiresAtMs = issuedAtMs + 60_000;
  const nonce = freshExportNonce32();
  const identity = await buildEd25519ExportAuthorizationIdentity(payload);
  const confirmationDigest = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
    identity,
    nonce: [...nonce],
    issuedAtMs,
    expiresAtMs,
  });
  const intentDigest = `export-keys:${payload.walletId}:near:${payload.nearAccountId}:ed25519:${base64UrlEncode(Uint8Array.from(confirmationDigest))}`;
  const loadingKeys: Ed25519ExportPrivateKeyDisplayEntry[] = [
    {
      scheme: 'ed25519',
      label: 'NEAR Ed25519 private key',
      publicKey,
      privateKey: '',
    },
  ];
  let prfFirst = new Uint8Array(0);
  let artifact: { publicKey: string; privateKey: string } | null = null;
  let exportKeys: Ed25519ExportPrivateKeyDisplayEntry[] = [];
  let loadingViewerOpened = false;
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: payload.nearAccountId,
        publicKey,
        warning: 'Confirm to reveal your NEAR Ed25519 private key export.',
      },
      payload: {
        subject,
        publicKey,
        challengeB64u: base64UrlEncode(Uint8Array.from(confirmationDigest)),
      },
      intentDigest,
    } satisfies UserConfirmRequest);
    if (!decision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: decision.error || 'User cancelled Ed25519 export request',
      };
    }
    if (!decision.credential) {
      throw new Error('Ed25519 export confirmation did not return a WebAuthn credential');
    }
    const credential = normalizeAuthenticationCredential(decision.credential);
    if (!ed25519ExportCredentialMatches(credential, payload.exactLane.credentialIdB64u)) {
      throw new Error('Ed25519 export confirmation used a different passkey credential');
    }
    prfFirst = base64UrlDecode(requirePrfB64uFromCredential(credential, 'first'));
    if (prfFirst.length !== 32) {
      throw new Error('Ed25519 export requires a 32-byte PRF.first output');
    }
    const authorizationDigest = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
      identity,
      confirmationDigest,
      nonce: [...nonce],
      issuedAtMs,
      expiresAtMs,
      thresholdSessionId: payload.exactLane.thresholdSessionId,
      signingGrantId: payload.exactLane.signingGrantId,
      authority: {
        kind: 'passkey',
        credentialIdB64u: payload.exactLane.credentialIdB64u,
      },
    });
    const request = parseRouterAbEd25519YaoExportAdmissionRequestV1({
      ...identity,
      authorization: {
        confirmation_digest: confirmationDigest,
        authorization_digest: authorizationDigest,
        nonce: [...nonce],
        issued_at_ms: issuedAtMs,
        expires_at_ms: expiresAtMs,
      },
    });
    if (!request.ok) {
      throw new Error(`Invalid Ed25519 export admission: ${request.message}`);
    }

    const loadingDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-loading`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: payload.nearAccountId,
        publicKey,
        warning: 'Preparing your NEAR Ed25519 private key export.',
      },
      payload: {
        subject,
        viewerSessionId,
        publicKey,
        keys: loadingKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: true,
      },
      intentDigest,
    } satisfies UserConfirmRequest);
    if (!loadingDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: loadingDecision.error || 'User cancelled Ed25519 export viewer',
      };
    }
    loadingViewerOpened = true;

    const client = await RouterAbEd25519YaoClientV1.initializeBundled();
    const result = await client.exportSeed({
      request: request.value,
      authorizationIdentity: {
        thresholdSessionId: requireExportThresholdSessionId(
          payload.exactLane.thresholdSessionId,
        ),
        signingGrantId: requireExportSigningGrantId(payload.exactLane.signingGrantId),
      },
      factor: { kind: 'passkey_prf_first', ownedSecret32: prfFirst },
      authorization: { kind: 'passkey', webauthnAuthentication: credential },
      transport: new RouterAbEd25519YaoHttpActivationTransportV1({
        routerOrigin: new URL(payload.relayerUrl).origin,
        authorization: `Bearer ${payload.walletSessionJwt}`,
        fetch: globalThis.fetch.bind(globalThis),
      }),
    });
    prfFirst = new Uint8Array(0);
    if (!result.ok) throw new Error(result.message);
    artifact = result.artifact;
    if (artifact.publicKey !== publicKey) {
      throw new Error('Exported Ed25519 seed does not match the active registered public key');
    }
    exportKeys = [
      {
        scheme: 'ed25519',
        label: 'NEAR Ed25519 private key',
        publicKey: artifact.publicKey,
        privateKey: artifact.privateKey,
      },
    ];
    const showDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-ready`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: payload.nearAccountId,
        publicKey: artifact.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        subject,
        viewerSessionId,
        publicKey: artifact.publicKey,
        privateKey: artifact.privateKey,
        keys: exportKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: false,
      },
      intentDigest,
    } satisfies UserConfirmRequest);
    clearEd25519ExportDisplayEntries(exportKeys);
    if (!showDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: showDecision.error || 'User cancelled Ed25519 export viewer',
      };
    }
    return { ok: true, accountId: payload.nearAccountId, exportedSchemes: ['ed25519'] };
  } catch (error: unknown) {
    if (loadingViewerOpened) {
      const message = messageFromError(error, 'Failed to prepare Ed25519 export');
      await awaitUserConfirmationV2({
        requestId: `${requestId}-show-error`,
        type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
        summary: {
          operation: 'Export Private Key',
          accountId: payload.nearAccountId,
          publicKey,
          warning: 'Private key export failed.',
        },
        payload: {
          subject,
          viewerSessionId,
          publicKey,
          keys: loadingKeys,
          variant: payload.variant,
          theme: payload.theme,
          loading: false,
          errorMessage: message,
        },
        intentDigest,
      } satisfies UserConfirmRequest).catch(ignoreExportViewerError);
    }
    if (isCancellationLikeError(error)) {
      return {
        ok: false,
        cancelled: true,
        accountId: payload.nearAccountId,
        exportedSchemes: [],
        error: messageFromError(error, 'User cancelled Ed25519 export request'),
      };
    }
    throw error;
  } finally {
    prfFirst.fill(0);
    nonce.fill(0);
    clearEd25519ExportDisplayEntries(exportKeys);
    if (artifact) {
      artifact.privateKey = '';
    }
  }
}

async function runExportPrivateKeysWithUi(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  if (isRouterAbEd25519YaoExportWorkerPayload(payload)) {
    return await runEd25519YaoExportWithUi(payload);
  }
  // Worker-owned export flow boundary:
  // only this runtime initiates export confirmations via awaitUserConfirmationV2.
  const exportTarget = {
    kind: 'ecdsa' as const,
    scheme: 'secp256k1' as const,
    chainTarget: payload.chainTarget,
  };
  const exportSubjectId = exportSubjectIdForPayload(payload);
  const exportScheme = exportTarget.scheme;
  const ecdsaDerivationExportPayload =
    'artifactKind' in payload && payload.artifactKind === 'ecdsa-derivation-secp256k1-export'
      ? requireEcdsaDerivationThresholdExportPayload(payload)
      : null;
  const exportOperation = 'Export Private Key';
  const exportPublicKey = ecdsaDerivationExportPayload?.publicKeyHex || '';
  const loadingKeys: Secp256k1ExportPrivateKeyDisplayEntry[] = exportPublicKey
    ? [
        {
          scheme: exportScheme,
          label: labelForExportTarget(exportTarget),
          publicKey: exportPublicKey,
          privateKey: '',
        },
      ]
    : [];
  const requestId = toSessionId('export-keys');
  const viewerSessionId = `${requestId}-viewer`;
  const intentDigest = exportIntentDigestForPayload({
    payload,
    exportSubjectId,
    exportTarget,
  });
  const localOnlySubject = localOnlyExportSubjectForTarget({
    exportTarget,
    exportSubjectId,
  });

  let prfSecondB64u = '';
  const exportKeys: Secp256k1ExportPrivateKeyDisplayEntry[] = [];
  let loadingViewerOpened = false;
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: exportPublicKey || '(threshold export key)',
        warning: ecdsaDerivationExportPayload
          ? 'Confirm to reveal your EVM private key export.'
          : 'Authenticate with your passkey to prepare export keys.',
      },
      payload: {
        subject: localOnlySubject,
        publicKey: exportPublicKey,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!decision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error: decision.error || 'User cancelled export request',
      };
    }
    const credential = decision.credential
      ? normalizeAuthenticationCredential(decision.credential)
      : undefined;
    if (!ecdsaDerivationExportPayload) {
      if (!credential) {
        throw new Error('Export confirmation did not return a WebAuthn authentication credential');
      }
      prfSecondB64u = requirePrfB64uFromCredential(credential, 'second');
    }

    const loadingDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-loading`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: exportPublicKey || '(threshold export key)',
        warning: 'Preparing your private key export.',
      },
      payload: {
        subject: localOnlySubject,
        viewerSessionId,
        publicKey: exportPublicKey,
        keys: loadingKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: true,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!loadingDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error: loadingDecision.error || 'User cancelled export viewer',
      };
    }
    loadingViewerOpened = true;

    if (ecdsaDerivationExportPayload) {
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportTarget(exportTarget.chainTarget),
        publicKey: ecdsaDerivationExportPayload.publicKeyHex,
        privateKey: ecdsaDerivationExportPayload.privateKeyHex,
        address: ecdsaDerivationExportPayload.ethereumAddress,
      });
    }

    if (!ecdsaDerivationExportPayload) {
      const derived = await deriveSecp256k1FromPrfSecondInWorker({
        prfSecondB64u,
        derivationSubjectId: exportSubjectId,
      });
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportTarget(exportTarget.chainTarget),
        publicKey: derived.publicKeyHex,
        privateKey: derived.privateKeyHex,
        address: derived.ethereumAddress,
      });
    }

    if (!exportKeys.length) {
      throw new Error('No exportable keys were produced');
    }

    const first = exportKeys[0]!;
    const showDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show-ready`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: first.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        subject: localOnlySubject,
        viewerSessionId,
        publicKey: first.publicKey,
        privateKey: first.privateKey,
        keys: exportKeys,
        variant: payload.variant,
        theme: payload.theme,
        loading: false,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!showDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error: showDecision.error || 'User cancelled export viewer',
      };
    }

    return {
      ok: true,
      accountId: exportSubjectId,
      exportedSchemes: exportKeys.map((entry) => entry.scheme),
    };
  } catch (error: unknown) {
    if (isCancellationLikeError(error)) {
      return {
        ok: false,
        cancelled: true,
        accountId: exportSubjectId,
        exportedSchemes: [],
        error:
          error instanceof Error ? error.message : String(error || 'User cancelled export request'),
      };
    }
    if (loadingViewerOpened) {
      const message = messageFromError(error, 'Failed to prepare export keys');
      await awaitUserConfirmationV2({
        requestId: `${requestId}-show-error`,
        type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
        summary: {
          operation: exportOperation,
          accountId: exportSubjectId,
          publicKey: exportPublicKey || '(threshold export key)',
          warning: 'Private key export failed.',
        },
        payload: {
          subject: localOnlySubject,
          viewerSessionId,
          publicKey: exportPublicKey,
          keys: loadingKeys,
          variant: payload.variant,
          theme: payload.theme,
          loading: false,
          errorMessage: message,
        },
        intentDigest,
      } satisfies UserConfirmRequest).catch(() => undefined);
    }
    throw error;
  } finally {
    prfSecondB64u = '';
    for (const key of exportKeys) {
      key.privateKey = '';
    }
    exportKeys.length = 0;
  }
}

function readWarmSessionMaterialEntry(sessionId: string): WarmSessionMaterialReadResult {
  if (!sessionId)
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  const entry = warmSessionPrfHandleCache.get(sessionId);
  if (!entry)
    return {
      ok: false,
      code: 'not_found',
      message: 'Warm-session material is not available for threshold session',
    };
  if (nowMs() >= entry.expiresAtMs) {
    deleteWarmSessionPrfHandle(sessionId);
    return {
      ok: false,
      code: 'expired',
      message: 'Warm-session material expired for threshold session',
    };
  }
  if (entry.remainingUses <= 0) {
    deleteWarmSessionPrfHandle(sessionId);
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  const secret = passkeyPrfFirstHandleStore.get(entry.prfFirstHandle);
  if (!secret || nowMs() >= secret.expiresAtMs) {
    deleteWarmSessionPrfHandle(sessionId);
    return {
      ok: false,
      code: 'not_found',
      message: 'Warm-session material handle is not available for threshold session',
    };
  }
  return {
    ok: true,
    entry,
    secret,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function readWarmSessionClaimEntry(sessionId: string): OkResult | ErrResult {
  const activeEntry = readWarmSessionMaterialEntry(sessionId);
  if (!activeEntry.ok) return activeEntry;
  return {
    ok: true,
    remainingUses: activeEntry.remainingUses,
    expiresAtMs: activeEntry.expiresAtMs,
  };
}

function claimWarmSessionMaterialEntry(
  sessionId: string,
  uses: number,
  consume: boolean,
): OkDispenseResult | ErrResult {
  const activeEntry = readWarmSessionMaterialEntry(sessionId);
  if (!activeEntry.ok) return activeEntry;
  const entry = activeEntry.entry;
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  if (consume) {
    entry.remainingUses -= usesNeeded;
    if (entry.remainingUses <= 0) {
      deleteWarmSessionPrfHandle(sessionId);
    } else {
      warmSessionPrfHandleCache.set(sessionId, entry);
    }
  }
  return {
    ok: true,
    prfFirstB64u: activeEntry.secret.prfFirstB64u,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function consumeWarmSessionMaterialEntry(sessionId: string, uses: number): OkResult | ErrResult {
  const activeEntry = readWarmSessionMaterialEntry(sessionId);
  if (!activeEntry.ok) return activeEntry;
  const entry = activeEntry.entry;
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  entry.remainingUses -= usesNeeded;
  if (entry.remainingUses <= 0) {
    deleteWarmSessionPrfHandle(sessionId);
  } else {
    warmSessionPrfHandleCache.set(sessionId, entry);
  }
  return {
    ok: true,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

async function runSigningSessionSealAndPersist(args: {
  sessionId: string;
  transport: SigningSessionSealTransport;
}): Promise<OkSealResult | ErrResult> {
  const sessionId = normalizeOptionalTrimmedString(args.sessionId);
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing shamirPrimeB64u for signing-session seal',
    };
  }
  const activeEntry = readWarmSessionMaterialEntry(sessionId);
  if (!activeEntry.ok) return activeEntry;
  const entry = activeEntry.entry;
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'apply-server-seal',
    sessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.transport.keyVersion,
    shamirPrimeB64u,
    payloadKey: entry.prfFirstHandle,
  });
  const inFlight = signingSessionSealApplyInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<OkSealResult | ErrResult> => {
    const diagnostics = createWarmSessionSealAndPersistDiagnostics();
    try {
      const runtimeSetupStartedAt = performance.now();
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      recordWarmSessionSealAndPersistDiagnosticDuration({
        diagnostics,
        bucket: 'runtimeSetupMs',
        startedAt: runtimeSetupStartedAt,
      });
      try {
        const clientSealStartedAt = performance.now();
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: activeEntry.secret.prfFirstB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });
        recordWarmSessionSealAndPersistDiagnosticDuration({
          diagnostics,
          bucket: 'clientSealMs',
          startedAt: clientSealStartedAt,
        });

        const serverSealRouteStartedAt = performance.now();
        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
          ciphertext: clientEncryptedCiphertext,
          keyVersion: args.transport.keyVersion,
        });
        recordWarmSessionSealAndPersistDiagnosticDuration({
          diagnostics,
          bucket: 'serverSealRouteMs',
          startedAt: serverSealRouteStartedAt,
        });
        if (!applied.ok) return applied;
        const policyUpdateStartedAt = performance.now();
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses: entry.remainingUses,
          localExpiresAtMs: entry.expiresAtMs,
          serverRemainingUses: applied.remainingUses,
          serverExpiresAtMs: applied.expiresAtMs,
        });
        if (!policy.ok) {
          deleteWarmSessionPrfHandle(sessionId);
          return policy;
        }
        updateWarmSessionPrfHandlePolicy(sessionId, entry, policy);
        recordWarmSessionSealAndPersistDiagnosticDuration({
          diagnostics,
          bucket: 'policyUpdateMs',
          startedAt: policyUpdateStartedAt,
        });
        const keyVersion =
          normalizeOptionalNonEmptyString(applied.keyVersion) ||
          normalizeOptionalNonEmptyString(args.transport.keyVersion);
        const sealedSecretCacheKey = keyVersion
          ? await passkeyServerSealedSecretCacheKey({
              prfFirstB64u: activeEntry.secret.prfFirstB64u,
              relayerUrl: args.transport.relayerUrl,
              keyVersion,
              shamirPrimeB64u,
              cacheScope: args.transport.serverSealedSecretCacheScope,
            })
          : null;
        const cachedSealedSecret = readPasskeyServerSealedSecretCache(sealedSecretCacheKey);
        let sealedSecretB64u = cachedSealedSecret?.sealedSecretB64u || '';
        if (!sealedSecretB64u) {
          const clientUnsealStartedAt = performance.now();
          sealedSecretB64u = await runtime.removeClientSealWithKeyHandle({
            ciphertextB64u: applied.ciphertext,
            keyHandle: clientKeyHandle.keyHandle,
          });
          recordWarmSessionSealAndPersistDiagnosticDuration({
            diagnostics,
            bucket: 'clientUnsealMs',
            startedAt: clientUnsealStartedAt,
          });
          writePasskeyServerSealedSecretCache({
            cacheKey: sealedSecretCacheKey,
            sealedSecretB64u,
            expiresAtMs: policy.expiresAtMs,
          });
        }
        return {
          ok: true,
          sealedSecretB64u,
          ...(keyVersion ? { keyVersion } : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
          diagnostics,
        };
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error ? error.message : String(error || 'Failed to apply server seal'),
      };
    }
  })().finally(() => {
    signingSessionSealApplyInFlight.delete(singleFlightKey);
  });

  signingSessionSealApplyInFlight.set(singleFlightKey, task);
  return await task;
}

async function runSigningSessionRehydrate(args: {
  sessionId: string;
  sealedSecretB64u: string;
  keyVersion?: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
}): Promise<OkResult | ErrResult> {
  const sessionId = normalizeOptionalTrimmedString(args.sessionId);
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  }
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  if (!sealedSecretB64u) {
    return { ok: false, code: 'invalid_args', message: 'Missing sealedSecretB64u' };
  }
  const localRemainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const localExpiresAtMs = Math.max(0, Math.floor(Number(args.expiresAtMs) || 0));
  if (localRemainingUses <= 0) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  if (localExpiresAtMs <= nowMs()) {
    return {
      ok: false,
      code: 'expired',
      message: 'Warm-session material expired for threshold session',
    };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing shamirPrimeB64u for signing-session rehydrate',
    };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'remove-server-seal',
    sessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.keyVersion || args.transport.keyVersion,
    shamirPrimeB64u,
    payloadKey: sealedSecretB64u,
  });
  const inFlight = signingSessionSealRemoveInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<OkResult | ErrResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: sealedSecretB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });

        const removed = await callSigningSessionSealRoute({
          operation: 'remove-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
          ciphertext: clientEncryptedCiphertext,
          keyVersion: normalizeOptionalNonEmptyString(args.keyVersion) || args.transport.keyVersion,
        });
        if (!removed.ok) return removed;

        const prfFirstB64u = await runtime.removeClientSealWithKeyHandle({
          ciphertextB64u: removed.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses,
          localExpiresAtMs,
          serverRemainingUses: removed.remainingUses,
          serverExpiresAtMs: removed.expiresAtMs,
        });
        if (!policy.ok) return policy;

        storeWarmSessionPrfHandle({
          sessionId,
          prfFirstB64u,
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        return policy;
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error ? error.message : String(error || 'Failed to remove server seal'),
      };
    }
  })().finally(() => {
    signingSessionSealRemoveInFlight.delete(singleFlightKey);
  });

  signingSessionSealRemoveInFlight.set(singleFlightKey, task);
  return await task;
}

function postUserConfirmWorkerResponse(
  id: unknown,
  payload: { success: boolean; data?: unknown; error?: string },
): void {
  const response = {
    ...(typeof id === 'string' && id.trim() ? { id: id.trim() } : {}),
    success: !!payload.success,
    ...(payload.data !== undefined ? { data: payload.data } : {}),
    ...(payload.error ? { error: payload.error } : {}),
  };
  try {
    self.postMessage(response);
  } catch {}
}

function toDecisionFromWorkerResponse(
  response: Awaited<ReturnType<typeof awaitUserConfirmationV2>>,
): UserConfirmDecision {
  const requestId = String(response.request_id || '').trim();
  if (!response.confirmed) {
    return {
      requestId,
      intentDigest: response.intent_digest,
      confirmed: false,
      registrationDiagnostics: response.registration_diagnostics,
      error: response.error,
    };
  }
  const decisionBase = {
    requestId,
    intentDigest: response.intent_digest,
    confirmed: true,
    credential: response.credential,
    otpCode: response.otp_code,
    emailOtpChallengeId: response.email_otp_challenge_id,
    registrationDiagnostics: response.registration_diagnostics,
  } as const;
  if (response.near_transaction_readiness) {
    return {
      ...decisionBase,
      nearTransactionReadiness: response.near_transaction_readiness,
    };
  }
  if (response.transaction_context) {
    return {
      ...decisionBase,
      transactionContext: response.transaction_context,
      nonceLeases: response.nonce_leases,
    };
  }
  return decisionBase;
}

function forwardUserConfirmProgressToHost(value: unknown): void {
  const envelope = asRecord(value);
  if (!envelope) return;
  self.postMessage(envelope);
}

// Confirmation responses are consumed by awaitUserConfirmationV2. Progress
// emitted by the main-thread prompt must cross back through this worker.
self.onmessage = (event: MessageEvent) => {
  const incoming = asIncomingMessage(event.data);
  const eventType = incoming.type;
  if (eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return;
  if (eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS) {
    forwardUserConfirmProgressToHost(event.data);
    return;
  }

  const id = incoming.id;

  // Health check / liveness
  if (eventType === 'PING') {
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'SECURE_CONFIRM_REQUEST') {
    void (async () => {
      try {
        const payload = asRecord(incoming.payload);
        const requestInput = payload?.request;
        if (!requestInput || typeof requestInput !== 'object') {
          postUserConfirmWorkerResponse(id, {
            success: false,
            error: 'Invalid SECURE_CONFIRM_REQUEST payload: missing request object',
          });
          return;
        }
        const workerResponse = await awaitUserConfirmationV2(requestInput as UserConfirmRequest);
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: toDecisionFromWorkerResponse(workerResponse),
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        postUserConfirmWorkerResponse(id, { success: false, error: msg });
      }
    })();
    return;
  }

  if (eventType === 'EXPORT_PRIVATE_KEYS_WITH_UI') {
    void (async () => {
      try {
        const payload = parseExportRequestPayload(incoming.payload);
        if (!payload) {
          postUserConfirmWorkerResponse(id, {
            success: false,
            error: 'Invalid EXPORT_PRIVATE_KEYS_WITH_UI payload',
          });
          return;
        }
        const result = await runExportPrivateKeysWithUi(payload);
        postUserConfirmWorkerResponse(id, { success: true, data: result });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        postUserConfirmWorkerResponse(id, { success: false, error: msg });
      }
    })();
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_PUT') {
    try {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
      const prfFirstB64u = normalizeOptionalTrimmedString(payload?.prfFirstB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      if (!sessionId || !prfFirstB64u) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Missing sessionId or prfFirstB64u',
          } satisfies ErrResult,
        });
        return;
      }
      if (expiresAtMs <= nowMs() || remainingUses <= 0) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid expiresAtMs or remainingUses',
          } satisfies ErrResult,
        });
        return;
      }
      storeWarmSessionPrfHandle({ sessionId, prfFirstB64u, expiresAtMs, remainingUses });
      postUserConfirmWorkerResponse(id, {
        success: true,
        data: { ok: true, remainingUses, expiresAtMs } satisfies OkResult,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      postUserConfirmWorkerResponse(id, { success: false, error: msg });
    }
    return;
  }

  if (eventType === 'WARM_SESSION_STATUS_READ') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: readWarmSessionClaimEntry(sessionId),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_STATUS_BATCH_READ') {
    const payload = asRecord(incoming.payload);
    const sessionIds = Array.isArray(payload?.sessionIds)
      ? Array.from(
          new Set(
            payload.sessionIds
              .map((value) => normalizeOptionalTrimmedString(value))
              .filter((value): value is string => !!value),
          ),
        )
      : [];
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: {
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: readWarmSessionClaimEntry(sessionId),
        })),
      },
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CLAIM') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    const consume = payload?.consume !== false;
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: claimWarmSessionMaterialEntry(sessionId, uses, consume),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CONSUME') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: consumeWarmSessionMaterialEntry(sessionId, uses),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR') {
    const command = parseClearVolatileWarmMaterialCommand(incoming.payload);
    if (command?.scope.kind === 'session') {
      deleteWarmSessionPrfHandle(command.scope.sessionId);
    }
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR_ALL') {
    clearWarmSessionPrfHandles();
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'WARM_SESSION_SEAL_AND_PERSIST') {
    void (async () => {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
      const transport = parseSigningSessionSealTransport(payload?.transport);
      if (!sessionId || !transport) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid WARM_SESSION_SEAL_AND_PERSIST payload',
          } satisfies ErrResult,
        });
        return;
      }
      const result = await runSigningSessionSealAndPersist({ sessionId, transport });
      postUserConfirmWorkerResponse(id, { success: true, data: result });
    })();
    return;
  }

  if (eventType === 'WARM_SESSION_REHYDRATE') {
    void (async () => {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
      const sealedSecretB64u = normalizeOptionalTrimmedString(payload?.sealedSecretB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      const keyVersion = normalizeOptionalNonEmptyString(payload?.signingSessionSealKeyVersion);
      const transport = parseSigningSessionSealTransport(payload?.transport);
      if (!sessionId || !sealedSecretB64u || !transport || expiresAtMs <= 0 || remainingUses <= 0) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid WARM_SESSION_REHYDRATE payload',
          } satisfies ErrResult,
        });
        return;
      }
      const result = await runSigningSessionRehydrate({
        sessionId,
        sealedSecretB64u,
        expiresAtMs,
        remainingUses,
        ...(keyVersion ? { keyVersion } : {}),
        transport,
      });
      postUserConfirmWorkerResponse(id, { success: true, data: result });
    })();
    return;
  }

  // Unknown message types: respond with an explicit error (prevents sendMessage timeouts).
  if (typeof id === 'string' && id.trim()) {
    postUserConfirmWorkerResponse(id, {
      success: false,
      error: `Unsupported UserConfirm worker message type: ${String(eventType)}`,
    });
  }
};

// === GLOBAL ERROR MONITORING ===

self.onerror = (error) => {
  console.error('[secure-confirm-worker] error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[secure-confirm-worker] Unhandled promise rejection:', event.reason);
  event.preventDefault();
};
