/**
 * UserConfirm Web Worker
 *
 * Hosts the UserConfirm handshake runtime (`awaitUserConfirmationV2`) and the
 * threshold warm-session material cache.
 */
import { toAccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  WarmSessionEd25519UnsealAuthorizationClaimPayload,
  WarmSessionEd25519UnsealAuthorizationClaimResult,
  WarmSessionEd25519UnsealAuthorizationPutPayload,
} from '@/core/types/secure-confirm-worker';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseClearVolatileWarmMaterialCommand } from '@/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands';
import { bytesToHex } from '../../chains/evm/bytes';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode } from '@shared/utils/base64';
import { parseWalletId } from '@shared/utils/domainIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
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
import initEthSigner, {
  derive_secp256k1_keypair_from_prf_second,
  init_eth_signer,
} from '../../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import initHssClientSigner, {
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';

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

type WarmSessionEd25519UnsealAuthorizationEntry = {
  signingGrantId: string;
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  materialBindingDigest: string;
  authorization: WarmSessionEd25519UnsealAuthorizationPutPayload['authorization'];
  expiresAtMs: number;
  remainingUses: 1;
};

type PasskeyPrfFirstHandleEntry = {
  prfFirstB64u: string;
  expiresAtMs: number;
};

type OkResult = { ok: true; remainingUses: number; expiresAtMs: number };
type OkSealResult = OkResult & { sealedSecretB64u: string; keyVersion?: string };
type OkDispenseResult = OkResult & { prfFirstB64u: string };
type ErrResult = { ok: false; code: string; message: string };
type WarmSessionMaterialReadResult =
  | ({ ok: true; entry: WarmSessionMaterialEntry; secret: PasskeyPrfFirstHandleEntry } & OkResult)
  | ErrResult;

const ED25519_UNSEAL_AUTHORIZATION_DEFAULT_TTL_MS = 60 * 1000;
const ED25519_UNSEAL_AUTHORIZATION_MAX_TTL_MS = 5 * 60 * 1000;

type SigningSessionSealTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
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
const warmSessionEd25519UnsealAuthorizationCache = new Map<
  string,
  WarmSessionEd25519UnsealAuthorizationEntry
>();
const signingSessionSealApplyInFlight = new Map<string, Promise<OkSealResult | ErrResult>>();
const signingSessionSealRemoveInFlight = new Map<string, Promise<OkResult | ErrResult>>();
const ethSignerWasmUrl = resolveWasmUrl('eth_signer.wasm', 'Eth Signer');
const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'HSS Client Signer');
const SIGNING_SESSION_SEAL_BASE_PATH = WALLET_SESSION_SEAL_BASE_PATH;
type NearSeedExportWorkerPayload = Extract<
  ExportPrivateKeysWithUiWorkerPayload,
  { chain: 'near'; artifactKind: 'near-ed25519-seed-v1' }
>;
type EcdsaHssThresholdExportWorkerPayload = Extract<
  ExportPrivateKeysWithUiWorkerPayload,
  { artifactKind: 'ecdsa-hss-secp256k1-export' }
>;

type ExportWorkerTarget =
  | { kind: 'near'; scheme: 'ed25519' }
  | { kind: 'ecdsa'; scheme: 'secp256k1'; chainTarget: ThresholdEcdsaChainTarget };

let ethSignerWasmInitPromise: Promise<void> | null = null;
let hssClientSignerInitPromise: Promise<void> | null = null;

type UserConfirmWorkerIncomingMessage = {
  id?: unknown;
  type?: unknown;
  payload?: unknown;
};

function asIncomingMessage(value: unknown): UserConfirmWorkerIncomingMessage {
  if (!value || typeof value !== 'object') return {};
  return value as UserConfirmWorkerIncomingMessage;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
}

function nowMs(): number {
  return Date.now();
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

function deleteWarmSessionPrfHandle(sessionId: string): void {
  const entry = warmSessionPrfHandleCache.get(sessionId);
  if (entry) passkeyPrfFirstHandleStore.delete(entry.prfFirstHandle);
  warmSessionPrfHandleCache.delete(sessionId);
}

function deleteWarmSessionEd25519UnsealAuthorization(sessionId: string): void {
  warmSessionEd25519UnsealAuthorizationCache.delete(sessionId);
}

function clearWarmSessionPrfHandles(): void {
  warmSessionPrfHandleCache.clear();
  passkeyPrfFirstHandleStore.clear();
  warmSessionEd25519UnsealAuthorizationCache.clear();
}

function authorizationPurpose(authorization: unknown): string {
  const record = asRecord(authorization);
  return normalizeOptionalTrimmedString(record?.purpose);
}

function authorizationMaterialBindingDigest(authorization: unknown): string {
  const record = asRecord(authorization);
  return normalizeOptionalTrimmedString(record?.materialBindingDigest);
}

function authorizationExpiryMs(authorization: unknown): number {
  const record = asRecord(authorization);
  return Math.floor(Number(record?.expiresAtMs) || 0);
}

function isValidEd25519UnsealAuthorization(args: {
  authorization: unknown;
  materialBindingDigest: string;
}): boolean {
  return (
    authorizationPurpose(args.authorization) === 'unseal' &&
    authorizationMaterialBindingDigest(args.authorization) === args.materialBindingDigest
  );
}

function invalidEd25519UnsealAuthorizationResult(
  message: string,
): WarmSessionEd25519UnsealAuthorizationClaimResult {
  return {
    ok: false,
    code: 'invalid_authorization',
    message,
  };
}

function resolveEd25519UnsealAuthorizationStoreExpiresAtMs(value: unknown): number {
  const now = nowMs();
  const requestedExpiresAtMs = Math.floor(Number(value) || 0);
  const expiresAtMs =
    requestedExpiresAtMs === 0
      ? now + ED25519_UNSEAL_AUTHORIZATION_DEFAULT_TTL_MS
      : requestedExpiresAtMs;
  if (expiresAtMs <= now) return 0;
  if (expiresAtMs - now > ED25519_UNSEAL_AUTHORIZATION_MAX_TTL_MS) return 0;
  return expiresAtMs;
}

function storeWarmSessionEd25519UnsealAuthorization(
  payload: WarmSessionEd25519UnsealAuthorizationPutPayload,
): OkResult | ErrResult {
  const sessionId = normalizeOptionalTrimmedString(payload.sessionId);
  const signingGrantId = normalizeOptionalTrimmedString(payload.signingGrantId);
  const walletId = normalizeOptionalTrimmedString(payload.walletId);
  const authMethod = payload.authMethod;
  const materialBindingDigest = normalizeOptionalTrimmedString(payload.materialBindingDigest);
  const expiresAtMs = resolveEd25519UnsealAuthorizationStoreExpiresAtMs(payload.expiresAtMs);
  const authorizationExpiresAtMs = authorizationExpiryMs(payload.authorization);
  if (
    !sessionId ||
    !signingGrantId ||
    !walletId ||
    (authMethod !== 'passkey' && authMethod !== 'email_otp') ||
    !materialBindingDigest ||
    payload.remainingUses !== 1 ||
    !expiresAtMs ||
    authorizationExpiresAtMs < expiresAtMs
  ) {
    return { ok: false, code: 'invalid_args', message: 'Invalid Ed25519 unseal authorization scope' };
  }
  if (
    !isValidEd25519UnsealAuthorization({
      authorization: payload.authorization,
      materialBindingDigest,
    })
  ) {
    return {
      ok: false,
      code: 'invalid_authorization',
      message: 'Invalid Ed25519 unseal authorization',
    };
  }
  warmSessionEd25519UnsealAuthorizationCache.set(sessionId, {
    signingGrantId,
    walletId,
    authMethod,
    materialBindingDigest,
    authorization: payload.authorization,
    expiresAtMs,
    remainingUses: 1,
  });
  return { ok: true, remainingUses: 1, expiresAtMs };
}

function ed25519UnsealAuthorizationScopeMatches(args: {
  entry: WarmSessionEd25519UnsealAuthorizationEntry;
  payload: WarmSessionEd25519UnsealAuthorizationClaimPayload;
}): boolean {
  return (
    args.entry.signingGrantId === normalizeOptionalTrimmedString(args.payload.signingGrantId) &&
    args.entry.walletId === normalizeOptionalTrimmedString(args.payload.walletId) &&
    args.entry.authMethod === args.payload.authMethod &&
    args.entry.materialBindingDigest ===
      normalizeOptionalTrimmedString(args.payload.materialBindingDigest)
  );
}

function claimWarmSessionEd25519UnsealAuthorization(
  payload: WarmSessionEd25519UnsealAuthorizationClaimPayload,
): WarmSessionEd25519UnsealAuthorizationClaimResult {
  const sessionId = normalizeOptionalTrimmedString(payload.sessionId);
  if (!sessionId) {
    return invalidEd25519UnsealAuthorizationResult('Missing Ed25519 unseal authorization session');
  }
  if (payload.consume !== true) {
    return invalidEd25519UnsealAuthorizationResult('Invalid Ed25519 unseal authorization claim mode');
  }
  const entry = warmSessionEd25519UnsealAuthorizationCache.get(sessionId);
  if (!entry) {
    return { ok: false, code: 'not_found', message: 'Ed25519 unseal authorization not found' };
  }
  if (entry.expiresAtMs <= nowMs()) {
    deleteWarmSessionEd25519UnsealAuthorization(sessionId);
    return { ok: false, code: 'expired', message: 'Ed25519 unseal authorization expired' };
  }
  if (entry.remainingUses !== 1) {
    deleteWarmSessionEd25519UnsealAuthorization(sessionId);
    return { ok: false, code: 'exhausted', message: 'Ed25519 unseal authorization exhausted' };
  }
  if (!ed25519UnsealAuthorizationScopeMatches({ entry, payload })) {
    deleteWarmSessionEd25519UnsealAuthorization(sessionId);
    return {
      ok: false,
      code: 'scope_mismatch',
      message: 'Ed25519 unseal authorization scope mismatch',
    };
  }
  if (
    !isValidEd25519UnsealAuthorization({
      authorization: entry.authorization,
      materialBindingDigest: entry.materialBindingDigest,
    })
  ) {
    deleteWarmSessionEd25519UnsealAuthorization(sessionId);
    return invalidEd25519UnsealAuthorizationResult('Invalid stored Ed25519 unseal authorization');
  }
  deleteWarmSessionEd25519UnsealAuthorization(sessionId);
  return {
    ok: true,
    authorization: entry.authorization,
    expiresAtMs: entry.expiresAtMs,
  };
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
  if (payload.chain === 'near') return { kind: 'near', scheme: 'ed25519' };
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
  return target.kind === 'near'
    ? 'NEAR private key'
    : secp256k1LabelForExportTarget(target.chainTarget);
}

function parseExportRequestPayload(value: unknown): ExportPrivateKeysWithUiWorkerPayload | null {
  const payload = asRecord(value);
  if (!payload) return null;
  const target = parseExportWorkerTarget(payload);
  const artifactKind = normalizeOptionalNonEmptyString(payload.artifactKind);
  if (!target) return null;
  const variant = coerceVariant(payload.variant);
  const theme = coerceTheme(payload.theme);
  if (target.kind === 'near') {
    const nearAccountId = normalizeOptionalTrimmedString(payload.nearAccountId);
    const signerSlot = Math.floor(Number(payload.signerSlot));
    const expectedPublicKey = normalizeOptionalNonEmptyString(payload.expectedPublicKey);
    const seedB64u = normalizeOptionalNonEmptyString(payload.seedB64u);
    if (!nearAccountId || !Number.isFinite(signerSlot) || signerSlot < 1) return null;
    if (artifactKind === 'near-ed25519-seed-v1') {
      if (!expectedPublicKey || !seedB64u) {
        return null;
      }
      return {
        nearAccountId,
        signerSlot,
        chain: 'near',
        artifactKind,
        expectedPublicKey,
        seedB64u,
        variant,
        theme,
      };
    }
    return null;
  }
  const parsedWalletId = parseWalletId(payload.walletId);
  if (!parsedWalletId.ok) return null;
  const walletId = String(parsedWalletId.value);
  if (artifactKind === 'ecdsa-hss-secp256k1-export') {
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

function requireNearSeedExportPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): NearSeedExportWorkerPayload {
  if (
    !('chain' in payload) ||
    payload.chain !== 'near' ||
    payload.artifactKind !== 'near-ed25519-seed-v1'
  ) {
    throw new Error('Threshold Ed25519 seed export metadata missing or invalid');
  }
  return payload;
}

function requireEcdsaHssThresholdExportPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): EcdsaHssThresholdExportWorkerPayload {
  const artifactKind = 'artifactKind' in payload ? payload.artifactKind : undefined;
  if (!('chainTarget' in payload) || artifactKind !== 'ecdsa-hss-secp256k1-export') {
    throw new Error('ecdsa-hss secp256k1 export artifact metadata missing or invalid');
  }
  return payload as EcdsaHssThresholdExportWorkerPayload;
}

function exportSubjectIdForPayload(payload: ExportPrivateKeysWithUiWorkerPayload): string {
  if ('chain' in payload && payload.chain === 'near') {
    return String(toAccountId(payload.nearAccountId));
  }
  if ('walletId' in payload) return payload.walletId;
  throw new Error('Invalid export subject');
}

function requireExportWalletId(raw: string): string {
  const parsed = parseWalletId(raw);
  if (!parsed.ok) {
    throw new Error('ECDSA export requires wallet identity');
  }
  return String(parsed.value);
}

function localOnlyExportSubjectForTarget(args: {
  exportTarget: ExportWorkerTarget;
  exportSubjectId: string;
}): LocalOnlyExportSubject {
  switch (args.exportTarget.kind) {
    case 'near':
      return {
        kind: 'near_wallet',
        nearAccountId: String(toAccountId(args.exportSubjectId)),
      };
    case 'ecdsa':
      return {
        kind: 'evm_wallet',
        walletId: requireExportWalletId(args.exportSubjectId),
      };
    default: {
      const exhaustive: never = args.exportTarget;
      throw new Error(`Unsupported export target: ${String(exhaustive)}`);
    }
  }
}

function exportIntentDigestForPayload(args: {
  payload: ExportPrivateKeysWithUiWorkerPayload;
  exportSubjectId: string;
  exportTarget: ExportWorkerTarget;
}): string {
  if ('chain' in args.payload && args.payload.chain === 'near') {
    return `export-keys:${args.exportSubjectId}:${args.payload.signerSlot}`;
  }
  if (args.exportTarget.kind !== 'ecdsa') {
    throw new Error('Invalid ECDSA export target');
  }
  return `export-keys:${args.exportSubjectId}:${thresholdEcdsaChainTargetKey(args.exportTarget.chainTarget)}:secp256k1`;
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = asRecord(value);
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  const walletSessionJwt = normalizeOptionalNonEmptyString(transport.walletSessionJwt);
  const keyVersion = normalizeOptionalNonEmptyString(transport.signingSessionSealKeyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(transport.shamirPrimeB64u);
  if (!relayerUrl) return null;
  return {
    relayerUrl,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
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
  const results = asRecord(
    (credential as unknown as { clientExtensionResults?: unknown }).clientExtensionResults,
  );
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

async function ensureEthSignerWasmReady(): Promise<void> {
  if (ethSignerWasmInitPromise) return ethSignerWasmInitPromise;
  ethSignerWasmInitPromise = (async () => {
    try {
      await initEthSigner({ module_or_path: ethSignerWasmUrl });
      init_eth_signer();
    } catch (error: unknown) {
      ethSignerWasmInitPromise = null;
      throw error;
    }
  })();
  return ethSignerWasmInitPromise;
}

async function ensureHssClientSignerWasmReady(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    try {
      await initHssClientSigner({ module_or_path: hssClientSignerWasmUrl });
    } catch (error: unknown) {
      hssClientSignerInitPromise = null;
      throw error;
    }
  })();
  return hssClientSignerInitPromise;
}

async function deriveSecp256k1FromPrfSecondInWorker(args: {
  prfSecondB64u: string;
  derivationSubjectId: string;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  await ensureEthSignerWasmReady();
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

async function buildNearEd25519SeedExportArtifactInWorker(args: {
  seedB64u: string;
  expectedPublicKey: string;
}): Promise<{ publicKey: string; privateKey: string }> {
  await ensureHssClientSignerWasmReady();
  const artifact = threshold_ed25519_seed_export_artifact_from_seed({
    seedB64u: args.seedB64u,
    expectedPublicKey: args.expectedPublicKey,
  }) as {
    artifactKind?: unknown;
    publicKey?: unknown;
    privateKey?: unknown;
  } | null;
  const publicKey = String(artifact?.publicKey || '').trim();
  const privateKey = String(artifact?.privateKey || '').trim();
  const artifactKind = String(artifact?.artifactKind || '').trim();
  if (artifactKind !== 'near-ed25519-seed-v1') {
    throw new Error('NEAR seed export artifact builder returned an unexpected artifactKind');
  }
  if (!publicKey || !privateKey) {
    throw new Error('NEAR seed export artifact builder returned an incomplete keypair');
  }
  if (publicKey !== args.expectedPublicKey) {
    throw new Error('NEAR seed export artifact builder returned an unexpected public key');
  }
  return { publicKey, privateKey };
}

async function runExportPrivateKeysWithUi(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  // Worker-owned export flow boundary:
  // only this runtime initiates export confirmations via awaitUserConfirmationV2.
  const exportTarget =
    'chain' in payload && payload.chain === 'near'
      ? ({ kind: 'near', scheme: 'ed25519' } as const)
      : 'chainTarget' in payload
        ? ({ kind: 'ecdsa', scheme: 'secp256k1', chainTarget: payload.chainTarget } as const)
        : null;
  if (!exportTarget) throw new Error('Invalid export target');
  const exportSubjectId = exportSubjectIdForPayload(payload);
  const exportScheme = exportTarget.scheme;
  const nearSeedPayload =
    exportScheme === 'ed25519' &&
    'chain' in payload &&
    payload.chain === 'near' &&
    payload.artifactKind === 'near-ed25519-seed-v1'
      ? requireNearSeedExportPayload(payload)
      : null;
  const ecdsaHssExportPayload =
    exportScheme === 'secp256k1' &&
    'chainTarget' in payload &&
    'artifactKind' in payload &&
    payload.artifactKind === 'ecdsa-hss-secp256k1-export'
      ? requireEcdsaHssThresholdExportPayload(payload)
      : null;
  const exportOperation = 'Export Private Key';
  const exportPublicKey =
    nearSeedPayload?.expectedPublicKey || ecdsaHssExportPayload?.publicKeyHex || '';
  const loadingKeys: ExportPrivateKeyDisplayEntry[] = exportPublicKey
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
  const exportKeys: ExportPrivateKeyDisplayEntry[] = [];
  let loadingViewerOpened = false;
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: exportOperation,
        accountId: exportSubjectId,
        publicKey: exportPublicKey || '(threshold export key)',
        warning:
          exportScheme === 'ed25519'
            ? 'Confirm to reveal your NEAR private key export.'
            : ecdsaHssExportPayload
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
    const credential = decision.credential as WebAuthnAuthenticationCredential | undefined;
    if (exportScheme === 'secp256k1' && !ecdsaHssExportPayload) {
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

    if (exportScheme === 'ed25519') {
      if (!nearSeedPayload) {
        throw new Error('NEAR Ed25519 export now requires a canonical seed export artifact');
      }
      const derived = await buildNearEd25519SeedExportArtifactInWorker({
        seedB64u: nearSeedPayload.seedB64u,
        expectedPublicKey: nearSeedPayload.expectedPublicKey,
      });
      exportKeys.push({
        scheme: 'ed25519',
        label: 'NEAR private key',
        publicKey: derived.publicKey,
        privateKey: derived.privateKey,
      });
    }

    if (exportScheme === 'secp256k1' && ecdsaHssExportPayload) {
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportTarget(exportTarget.chainTarget),
        publicKey: ecdsaHssExportPayload.publicKeyHex,
        privateKey: ecdsaHssExportPayload.privateKeyHex,
        address: ecdsaHssExportPayload.ethereumAddress,
      });
    }

    if (exportScheme === 'secp256k1' && !ecdsaHssExportPayload) {
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
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: activeEntry.secret.prfFirstB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });

        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
          ciphertext: clientEncryptedCiphertext,
          keyVersion: args.transport.keyVersion,
        });
        if (!applied.ok) return applied;

        const sealedSecretB64u = await runtime.removeClientSealWithKeyHandle({
          ciphertextB64u: applied.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
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
        const keyVersion = normalizeOptionalNonEmptyString(applied.keyVersion);
        return {
          ok: true,
          sealedSecretB64u,
          ...(keyVersion ? { keyVersion } : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
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
  return {
    requestId,
    intentDigest: response.intent_digest,
    confirmed: true,
    credential: response.credential,
    otpCode: response.otp_code,
    emailOtpChallengeId: response.email_otp_challenge_id,
    transactionContext: response.transaction_context,
    ...(response.nonce_leases ? { nonceLeases: response.nonce_leases } : {}),
    registrationDiagnostics: response.registration_diagnostics,
  };
}

// This worker intentionally ignores USER_PASSKEY_CONFIRM_RESPONSE at the
// `onmessage` level so awaitUserConfirmationV2's listener can consume it.
self.onmessage = (event: MessageEvent) => {
  const incoming = asIncomingMessage(event.data);
  const eventType = incoming.type;
  if (eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return;

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

  if (eventType === 'WARM_SESSION_ED25519_UNSEAL_AUTHORIZATION_PUT') {
    const payload = asRecord(incoming.payload);
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: payload
        ? storeWarmSessionEd25519UnsealAuthorization(
            payload as WarmSessionEd25519UnsealAuthorizationPutPayload,
          )
        : {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid Ed25519 unseal authorization payload',
          } satisfies ErrResult,
    });
    return;
  }

  if (eventType === 'WARM_SESSION_ED25519_UNSEAL_AUTHORIZATION_CLAIM') {
    const payload = asRecord(incoming.payload);
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: payload
        ? claimWarmSessionEd25519UnsealAuthorization(
            payload as WarmSessionEd25519UnsealAuthorizationClaimPayload,
          )
        : invalidEd25519UnsealAuthorizationResult(
            'Invalid Ed25519 unseal authorization claim payload',
          ),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR') {
    const command = parseClearVolatileWarmMaterialCommand(incoming.payload);
    if (command?.scope.kind === 'session') {
      deleteWarmSessionPrfHandle(command.scope.sessionId);
      deleteWarmSessionEd25519UnsealAuthorization(command.scope.sessionId);
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
