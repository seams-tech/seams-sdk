import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  EMAIL_OTP_CHANNEL,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
  type ThresholdEcdsaHssRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/orchestration/thresholdActivation';
import {
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  THRESHOLD_SESSION_POLICY_VERSION,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from '@/core/signingEngine/threshold/workflows/thresholdEcdsaHssTransport';
import initEthSigner, {
  init_eth_signer,
  secp256k1_private_key_32_to_public_key_33,
  sign_secp256k1_recoverable,
} from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import initHssClientSigner, {
  threshold_ecdsa_hss_finalize_client_request,
  threshold_ecdsa_hss_prepare_client_request,
  threshold_ecdsa_hss_prepare_session,
} from '../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import initEmailOtpRuntime, {
  derive_email_otp_ecdsa_client_root_share32_from_secret32,
  derive_email_otp_unlock_auth_seed_from_secret32,
  init_email_otp_runtime,
} from '../../../../../../wasm/email_otp_runtime/pkg/email_otp_runtime.js';
import { WorkerControlMessage } from '../workerTypes';
import { postEmailOtpJson } from './email-otp/fetch';
import { getShamir3PassRuntime } from './shamir3pass/runtime';

const EMAIL_OTP_UNLOCK_KEY_VERSION = 'email-otp-unlock-v1';

type EmailOtpWorkerRequest =
  | {
      id: string;
      type: 'requestEmailOtpChallenge';
      payload: {
        relayUrl: string;
        walletId: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        operation?: WalletEmailOtpLoginOperation;
      };
    }
  | {
      id: string;
      type: 'requestEmailOtpEnrollmentChallenge';
      payload: {
        relayUrl: string;
        walletId: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        operation?: WalletEmailOtpLoginOperation;
      };
    }
  | {
      id: string;
      type: 'enrollEmailOtpWallet';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId?: string;
        otpCode: string;
        shamirPrimeB64u: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        operation?: WalletEmailOtpLoginOperation;
        clientSecret32?: ArrayBuffer;
      };
    }
  | {
      id: string;
      type: 'verifyEmailOtpCode';
      payload: {
        relayUrl: string;
        walletId: string;
        challengeId: string;
        otpCode: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        operation?: WalletEmailOtpLoginOperation;
      };
    }
  | {
      id: string;
      type: 'loginWithEmailOtpWallet';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId?: string;
        otpCode: string;
        shamirPrimeB64u: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        operation?: WalletEmailOtpLoginOperation;
      };
    }
  | {
      id: string;
      type: 'loginWithEmailOtpAndBootstrapEcdsaSession';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId?: string;
        otpCode: string;
        shamirPrimeB64u: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        operation?: WalletEmailOtpLoginOperation;
        rpId: string;
        ecdsaThresholdKeyId?: string;
        participantIds?: number[];
        sessionKind?: 'jwt' | 'cookie';
        sessionId?: string;
        thresholdRouteAuth?: AppOrThresholdSessionAuth;
        ttlMs?: number;
        remainingUses?: number;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
      };
    }
  | {
      id: string;
      type: 'enrollEmailOtpWalletAndBootstrapEcdsaSession';
      payload: {
        relayUrl: string;
        walletId: string;
        userId?: string;
        challengeId?: string;
        otpCode: string;
        shamirPrimeB64u: string;
        appSessionJwt?: string;
        otpChannel?: WalletEmailOtpChannel;
        clientSecret32?: ArrayBuffer;
        rpId: string;
        ecdsaThresholdKeyId?: string;
        participantIds?: number[];
        sessionKind?: 'jwt' | 'cookie';
        sessionId?: string;
        thresholdRouteAuth?: AppOrThresholdSessionAuth;
        ttlMs?: number;
        remainingUses?: number;
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
      };
    }
  | {
      id: string;
      type: 'getEmailOtpWarmSessionStatus';
      payload: {
        sessionId: string;
      };
    }
  | {
      id: string;
      type: 'claimEmailOtpWarmSessionMaterial';
      payload: {
        sessionId: string;
        uses?: number;
      };
    }
  | {
      id: string;
      type: 'claimEmailOtpEcdsaSigningShare';
      payload: {
        sessionId: string;
      };
    }
  | {
      id: string;
      type: 'clearEmailOtpWarmSessionMaterial';
      payload: {
        sessionId: string;
      };
    }
  | {
      id: string;
      type: 'exportThresholdEcdsaHssKeyFromEmailOtpWarmSession';
      payload: {
        relayUrl: string;
        userId: string;
        rpId: string;
        sessionId: string;
        thresholdSessionJwt?: string;
        sessionKind?: 'jwt' | 'cookie';
        ecdsaThresholdKeyId: string;
        chain: 'evm' | 'tempo';
      };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

type EmailOtpWarmSessionEntry = {
  clientRootShare32: Uint8Array;
  clientAdditiveShare32?: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
};

type EmailOtpWarmSessionStatusResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionClaimResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaSigningShareClaimResult =
  | { ok: true; clientSigningShare32: ArrayBuffer; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpThresholdEcdsaBootstrapResult = ThresholdEcdsaSessionBootstrapResult & {
  emailOtpClientAdditiveShare32: Uint8Array;
};

const emailOtpWarmSessions = new Map<string, EmailOtpWarmSessionEntry>();

function asWorkerErrorPayload(err: unknown): WorkerErrorPayload {
  if (err && typeof err === 'object') {
    const message =
      typeof (err as { message?: unknown }).message === 'string'
        ? String((err as { message?: string }).message).trim()
        : '';
    const code =
      typeof (err as { code?: unknown }).code === 'string'
        ? String((err as { code?: string }).code).trim()
        : '';
    const coreCode =
      typeof (err as { coreCode?: unknown }).coreCode === 'string'
        ? String((err as { coreCode?: string }).coreCode).trim()
        : '';
    return {
      message: message || errorMessage(err),
      ...(code ? { code } : {}),
      ...(coreCode ? { coreCode } : {}),
    };
  }
  return { message: errorMessage(err) };
}

function readString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function readOptionalString(value: unknown): string | undefined {
  const parsed = typeof value === 'string' ? value.trim() : '';
  return parsed || undefined;
}

function readOptionalThresholdRouteAuth(
  value: AppOrThresholdSessionAuth | undefined,
): AppOrThresholdSessionAuth | undefined {
  if (!value) return undefined;
  const jwt = readOptionalString(value.jwt);
  if (!jwt) return undefined;
  if (value.kind === 'app_session') return { kind: 'app_session', jwt };
  if (value.kind === 'threshold_session') return { kind: 'threshold_session', jwt };
  return undefined;
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function encodeEmailOtpTuple(fields: readonly string[]): Uint8Array {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (const field of fields) {
    const bytes = encoder.encode(String(field || ''));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    chunks.push(len, bytes);
    total += len.length + bytes.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function deriveEmailOtpEd25519PrfFirstB64u(args: {
  clientSecret32: Uint8Array;
  walletId: string;
  userId: string;
}): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('crypto.subtle is unavailable for Email OTP Ed25519 derivation');
  }
  const salt = new TextEncoder().encode('tatchi/email-otp/threshold-ed25519-hss/v1');
  const info = encodeEmailOtpTuple([
    'threshold-ed25519-hss-client-seed',
    String(args.walletId || '').trim(),
    String(args.userId || '').trim(),
  ]);
  const key = await subtle.importKey('raw', args.clientSecret32, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256);
  const seed32 = new Uint8Array(bits);
  try {
    return base64UrlEncode(seed32);
  } finally {
    zeroizeBytes(seed32);
  }
}

function deleteEmailOtpWarmSession(sessionId: string): void {
  const entry = emailOtpWarmSessions.get(sessionId);
  if (entry) {
    zeroizeBytes(entry.clientRootShare32);
    zeroizeBytes(entry.clientAdditiveShare32);
    emailOtpWarmSessions.delete(sessionId);
  }
}

function readEmailOtpWarmSessionStatus(sessionIdRaw: unknown): EmailOtpWarmSessionStatusResult {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  if (Date.now() >= entry.expiresAtMs) {
    deleteEmailOtpWarmSession(sessionId);
    return {
      ok: false,
      code: 'expired',
      message: 'Email OTP warm-session material expired',
    };
  }
  if (entry.remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  return {
    ok: true,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function putEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  clientRootShare32: Uint8Array;
  clientAdditiveShare32?: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
}): void {
  const sessionId = readString(args.sessionId, 'sessionId');
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  if (!(args.clientRootShare32 instanceof Uint8Array) || args.clientRootShare32.length !== 32) {
    throw new Error('clientRootShare32 must contain 32 bytes');
  }
  if (
    args.clientAdditiveShare32 &&
    (!(args.clientAdditiveShare32 instanceof Uint8Array) ||
      args.clientAdditiveShare32.length !== 32)
  ) {
    throw new Error('clientAdditiveShare32 must contain 32 bytes');
  }
  if (expiresAtMs <= Date.now() || remainingUses <= 0) {
    throw new Error('Invalid Email OTP warm-session ttl or remainingUses');
  }
  deleteEmailOtpWarmSession(sessionId);
  emailOtpWarmSessions.set(sessionId, {
    clientRootShare32: Uint8Array.from(args.clientRootShare32),
    ...(args.clientAdditiveShare32
      ? { clientAdditiveShare32: Uint8Array.from(args.clientAdditiveShare32) }
      : {}),
    expiresAtMs,
    remainingUses,
  });
}

function claimEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  uses?: number;
}): EmailOtpWarmSessionClaimResult {
  const sessionId = String(args.sessionId || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  if (entry.remainingUses < uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  const prfFirstB64u = base64UrlEncode(entry.clientRootShare32);
  entry.remainingUses -= uses;
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
  } else {
    emailOtpWarmSessions.set(sessionId, entry);
  }
  return {
    ok: true,
    prfFirstB64u,
    remainingUses,
    expiresAtMs,
  };
}

function claimEmailOtpWarmSessionClientRootShare(args: { sessionId: string; uses?: number }):
  | { ok: true; clientRootShare32: Uint8Array; remainingUses: number; expiresAtMs: number }
  | {
      ok: false;
      code: string;
      message: string;
    } {
  const sessionId = String(args.sessionId || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  if (entry.remainingUses < uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  const clientRootShare32 = Uint8Array.from(entry.clientRootShare32);
  entry.remainingUses -= uses;
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
  } else {
    emailOtpWarmSessions.set(sessionId, entry);
  }
  return {
    ok: true,
    clientRootShare32,
    remainingUses,
    expiresAtMs,
  };
}

function claimEmailOtpEcdsaSigningShare(
  sessionIdRaw: unknown,
): EmailOtpEcdsaSigningShareClaimResult {
  const sessionId = String(sessionIdRaw || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry?.clientAdditiveShare32) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP ECDSA signing material is not available',
    };
  }
  const clientSigningShare32 = Uint8Array.from(entry.clientAdditiveShare32);
  entry.remainingUses -= 1;
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (remainingUses <= 0) {
    deleteEmailOtpWarmSession(sessionId);
  } else {
    emailOtpWarmSessions.set(sessionId, entry);
  }
  return {
    ok: true,
    clientSigningShare32: clientSigningShare32.buffer,
    remainingUses,
    expiresAtMs,
  };
}

function requireFixed32ArrayBuffer(value: unknown, label: string): Uint8Array {
  if (!(value instanceof ArrayBuffer)) {
    throw new Error(`${label} must be an ArrayBuffer`);
  }
  const bytes = new Uint8Array(value);
  if (bytes.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  return bytes;
}

function generateRandomSecret32(): Uint8Array {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  return cryptoApi.getRandomValues(new Uint8Array(32));
}

const ethSignerWasmUrl = resolveWasmUrl('eth_signer.wasm', 'Email OTP');
const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'Email OTP HSS');
const emailOtpRuntimeWasmUrl = resolveWasmUrl('email_otp_runtime_bg.wasm', 'Email OTP Runtime');
let ethSignerInitPromise: Promise<void> | null = null;
let hssClientSignerInitPromise: Promise<void> | null = null;
let emailOtpRuntimeInitPromise: Promise<void> | null = null;

async function ensureEthSignerWasm(): Promise<void> {
  if (ethSignerInitPromise) return ethSignerInitPromise;
  ethSignerInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP',
      wasmUrl: ethSignerWasmUrl,
      initFunction: initEthSigner as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_eth_signer(),
    });
  })();
  return ethSignerInitPromise;
}

async function ensureHssClientSignerWasm(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP HSS',
      wasmUrl: hssClientSignerWasmUrl,
      initFunction: initHssClientSigner as unknown as (wasmModule?: unknown) => Promise<void>,
    });
  })();
  return hssClientSignerInitPromise;
}

async function ensureEmailOtpRuntimeWasm(): Promise<void> {
  if (emailOtpRuntimeInitPromise) return emailOtpRuntimeInitPromise;
  emailOtpRuntimeInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP Runtime',
      wasmUrl: emailOtpRuntimeWasmUrl,
      initFunction: initEmailOtpRuntime as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_email_otp_runtime(),
    });
  })();
  return emailOtpRuntimeInitPromise;
}

async function deriveEmailOtpEcdsaClientRootShare32InWorker(args: {
  clientSecret32: Uint8Array;
  walletId: string;
  userId: string;
  derivationPath?: string;
}): Promise<Uint8Array> {
  await ensureEmailOtpRuntimeWasm();
  return derive_email_otp_ecdsa_client_root_share32_from_secret32(
    args.clientSecret32,
    String(args.walletId || '').trim(),
    String(args.userId || '').trim(),
    String(args.derivationPath || '').trim() || undefined,
  );
}

async function deriveEmailOtpUnlockAuthSeedInWorker(args: {
  clientSecret32: Uint8Array;
  walletId: string;
}): Promise<Uint8Array> {
  await ensureEmailOtpRuntimeWasm();
  return derive_email_otp_unlock_auth_seed_from_secret32(
    args.clientSecret32,
    String(args.walletId || '').trim(),
  );
}

function generateKeygenSessionId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tecdsa-keygen-${id}`;
}

async function removeClientSealToBytes(args: {
  runtime: Awaited<ReturnType<typeof getShamir3PassRuntime>>;
  keyHandle: string;
  ciphertextB64u: string;
}): Promise<Uint8Array> {
  return await args.runtime.removeClientSealWithKeyHandleToBytes({
    ciphertextB64u: args.ciphertextB64u,
    keyHandle: args.keyHandle,
  });
}

async function addClientSealFromBytes(args: {
  runtime: Awaited<ReturnType<typeof getShamir3PassRuntime>>;
  keyHandle: string;
  ciphertext: Uint8Array;
}): Promise<string> {
  return readString(
    await args.runtime.addClientSealBytesWithKeyHandle({
      ciphertext: args.ciphertext,
      keyHandle: args.keyHandle,
    }),
    'wrappedCiphertext',
  );
}

async function completeEmailOtpUnlockFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  clientSecret32: Uint8Array;
}): Promise<{
  clientRootShare32: Uint8Array;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
}> {
  await ensureEthSignerWasm();
  const walletId = readString(args.walletId, 'walletId');
  const userId = String(args.userId || walletId).trim() || walletId;
  const challenge = await postEmailOtpJson({
    relayUrl: readString(args.relayUrl, 'relayUrl'),
    route: '/wallet/unlock/challenge',
    body: {
      unlockBackend: 'email_otp',
      walletId,
    },
  });
  const unlockChallengeId = readString(challenge.challengeId, 'challengeId');
  const unlockChallengeB64u = readString(challenge.challengeB64u, 'challengeB64u');
  let challengeDigest32: Uint8Array | null = base64UrlDecode(unlockChallengeB64u);
  if (challengeDigest32.length !== 32) {
    zeroizeBytes(challengeDigest32);
    throw new Error('wallet/unlock/challenge challengeB64u must decode to 32 bytes');
  }

  let unlockPrivateKey32: Uint8Array | null = null;
  let clientRootShare32: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  let unlockSignature65: Uint8Array | null = null;
  try {
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedInWorker({
      clientSecret32: args.clientSecret32,
      walletId,
    });
    unlockPublicKey33 = secp256k1_private_key_32_to_public_key_33(unlockPrivateKey32) as Uint8Array;
    unlockSignature65 = sign_secp256k1_recoverable(
      challengeDigest32,
      unlockPrivateKey32,
    ) as Uint8Array;

    const unlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const unlockSignatureB64u = base64UrlEncode(unlockSignature65);

    await postEmailOtpJson({
      relayUrl: readString(args.relayUrl, 'relayUrl'),
      route: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: unlockPublicKeyB64u,
          signature: unlockSignatureB64u,
        },
      },
    });

    clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
      clientSecret32: args.clientSecret32,
      walletId,
      userId,
    });

    return {
      clientRootShare32,
      unlockChallengeId,
      unlockChallengeB64u,
      unlockPublicKeyB64u,
      unlockSignatureB64u,
    };
  } finally {
    zeroizeBytes(challengeDigest32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(unlockPublicKey33);
    zeroizeBytes(unlockSignature65);
  }
}

async function completeEmailOtpEnrollmentFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  appSessionJwt?: string;
  clientSecret32?: Uint8Array;
  returnClientRootShare32?: boolean;
}): Promise<{
  thresholdEcdsaClientVerifyingShareB64u: string;
  thresholdEd25519PrfFirstB64u: string;
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailOtpKeyVersion: string;
  unlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  clientRootShare32?: Uint8Array;
}> {
  await ensureEthSignerWasm();
  const runtime = await getShamir3PassRuntime();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const userId = String(args.userId || walletId).trim() || walletId;
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const otpCode = readString(args.otpCode, 'otpCode');
  const keyHandle = readString(
    (await runtime.createClientKeyHandle({ shamirPrimeB64u })).keyHandle,
    'keyHandle',
  );
  let clientSecret32: Uint8Array | null = args.clientSecret32
    ? Uint8Array.from(args.clientSecret32)
    : generateRandomSecret32();
  let thresholdClientRootShare32: Uint8Array | null = null;
  let unlockPrivateKey32: Uint8Array | null = null;
  let thresholdEcdsaClientVerifyingShare33: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  let thresholdEd25519PrfFirstB64u = '';
  try {
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId) {
      const challenge = await postEmailOtpJson({
        relayUrl,
        route: '/wallet/email-otp/registration/challenge',
        appSessionJwt: args.appSessionJwt,
        body: {
          walletId,
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      });
      challengeId = readString(
        (challenge.challenge as Record<string, unknown>)?.challengeId,
        'challengeId',
      );
    }
    const wrappedCiphertext = await addClientSealFromBytes({
      runtime,
      keyHandle,
      ciphertext: clientSecret32,
    });
    const applied = await postEmailOtpJson({
      relayUrl,
      route: '/wallet/email-otp/registration/seal',
      appSessionJwt: args.appSessionJwt,
      body: {
        walletId,
        wrappedCiphertext,
      },
    });
    const emailOtpKeyVersion = readString(applied.emailOtpKeyVersion, 'emailOtpKeyVersion');
    const clientCiphertext = readString(applied.ciphertext, 'ciphertext');
    const emailOtpEscrowBlob = readString(
      await runtime.removeClientSealWithKeyHandle({
        ciphertextB64u: clientCiphertext,
        keyHandle,
      }),
      'emailOtpEscrowBlob',
    );

    thresholdClientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
      clientSecret32,
      walletId,
      userId,
    });
    thresholdEd25519PrfFirstB64u = await deriveEmailOtpEd25519PrfFirstB64u({
      clientSecret32,
      walletId,
      userId,
    });
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedInWorker({
      clientSecret32,
      walletId,
    });
    unlockPublicKey33 = secp256k1_private_key_32_to_public_key_33(unlockPrivateKey32) as Uint8Array;
    thresholdEcdsaClientVerifyingShare33 = secp256k1_private_key_32_to_public_key_33(
      thresholdClientRootShare32,
    ) as Uint8Array;
    const unlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const thresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
      thresholdEcdsaClientVerifyingShare33,
    );

    await postEmailOtpJson({
      relayUrl,
      route: '/wallet/email-otp/registration/finalize',
      appSessionJwt: args.appSessionJwt,
      body: {
        walletId,
        challengeId,
        otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        emailOtpEscrowBlob,
        emailOtpKeyVersion,
        unlockPublicKey: unlockPublicKeyB64u,
        unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
        thresholdEcdsaClientVerifyingShareB64u,
      },
    });

    const returnedClientRootShare32 =
      args.returnClientRootShare32 && thresholdClientRootShare32
        ? thresholdClientRootShare32
        : null;
    if (returnedClientRootShare32) {
      thresholdClientRootShare32 = null;
    }

    return {
      thresholdEcdsaClientVerifyingShareB64u,
      thresholdEd25519PrfFirstB64u,
      challengeId,
      otpChannel: EMAIL_OTP_CHANNEL,
      emailOtpKeyVersion,
      unlockPublicKeyB64u,
      unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
      ...(returnedClientRootShare32 ? { clientRootShare32: returnedClientRootShare32 } : {}),
    };
  } finally {
    zeroizeBytes(clientSecret32);
    zeroizeBytes(thresholdClientRootShare32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(thresholdEcdsaClientVerifyingShare33);
    zeroizeBytes(unlockPublicKey33);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
    clientSecret32 = null;
  }
}

async function loginWithEmailOtpAndRecoverClientRootShare(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  appSessionJwt?: string;
  operation?: WalletEmailOtpLoginOperation;
}): Promise<{
  clientRootShare32: Uint8Array;
  thresholdEd25519PrfFirstB64u: string;
  loginGrant: string;
  challengeId: string;
  emailOtpKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
}> {
  const runtime = await getShamir3PassRuntime();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const keyHandle = readString(
    (await runtime.createClientKeyHandle({ shamirPrimeB64u })).keyHandle,
    'keyHandle',
  );
  let clientSecret32: Uint8Array | null = null;
  try {
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId) {
      const challenge = await postEmailOtpJson({
        relayUrl,
        route: '/wallet/email-otp/login/challenge',
        appSessionJwt: args.appSessionJwt,
        body: {
          walletId,
          otpChannel: EMAIL_OTP_CHANNEL,
          ...(args.operation ? { operation: args.operation } : {}),
        },
      });
      challengeId = readString(
        (challenge.challenge as Record<string, unknown>)?.challengeId,
        'challengeId',
      );
    }
    const verified = await postEmailOtpJson({
      relayUrl,
      route: '/wallet/email-otp/login/verify',
      appSessionJwt: args.appSessionJwt,
      body: {
        walletId,
        challengeId,
        otpCode: readString(args.otpCode, 'otpCode'),
        otpChannel: EMAIL_OTP_CHANNEL,
        ...(args.operation ? { operation: args.operation } : {}),
      },
    });
    const loginGrant = readString(verified.loginGrant, 'loginGrant');
    const emailOtpEscrowBlob = readString(verified.emailOtpEscrowBlob, 'emailOtpEscrowBlob');
    const wrappedCiphertext = readString(
      await runtime.addClientSealWithKeyHandle({
        ciphertextB64u: emailOtpEscrowBlob,
        keyHandle,
      }),
      'wrappedCiphertext',
    );
    const unsealed = await postEmailOtpJson({
      relayUrl,
      route: '/wallet/email-otp/unseal',
      appSessionJwt: args.appSessionJwt,
      body: {
        loginGrant,
        wrappedCiphertext,
      },
    });
    const clientCiphertext = readString(unsealed.ciphertext, 'ciphertext');
    clientSecret32 = await removeClientSealToBytes({
      runtime,
      ciphertextB64u: clientCiphertext,
      keyHandle,
    });
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      userId: args.userId,
      clientSecret32,
    });
    const thresholdEd25519PrfFirstB64u = await deriveEmailOtpEd25519PrfFirstB64u({
      clientSecret32,
      walletId,
      userId: String(args.userId || walletId).trim() || walletId,
    });
    return {
      clientRootShare32: unlocked.clientRootShare32,
      thresholdEd25519PrfFirstB64u,
      loginGrant,
      challengeId,
      emailOtpKeyVersion: readString(unsealed.emailOtpKeyVersion, 'emailOtpKeyVersion'),
      unlockChallengeId: unlocked.unlockChallengeId,
      unlockChallengeB64u: unlocked.unlockChallengeB64u,
      unlockPublicKeyB64u: unlocked.unlockPublicKeyB64u,
      unlockSignatureB64u: unlocked.unlockSignatureB64u,
    };
  } finally {
    zeroizeBytes(clientSecret32);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
  }
}

async function runThresholdEcdsaAuthorizationBootstrapFromClientRootShare(args: {
  relayUrl: string;
  userId: string;
  rpId: string;
  clientRootShare32: Uint8Array;
  operation?: 'email_otp_bootstrap' | 'session_bootstrap';
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<EmailOtpThresholdEcdsaBootstrapResult> {
  await ensureHssClientSignerWasm();
  const relayerUrl = readString(args.relayUrl, 'relayUrl');
  const userId = readString(args.userId, 'userId');
  const rpId = readString(args.rpId, 'rpId');
  const routeAuth: ThresholdEcdsaHssRouteAuth | undefined =
    args.thresholdRouteAuth || (args.sessionKind === 'cookie' ? { kind: 'cookie' } : undefined);
  const operation = args.operation || 'session_bootstrap';
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const sessionKind = args.sessionKind || 'jwt';
  if (!routeAuth && sessionKind !== 'cookie') {
    throw new Error('thresholdRouteAuth is required for JWT threshold bootstrap sessions');
  }
  const keygenSessionId = generateKeygenSessionId();
  const requestedSessionId = String(args.sessionId || '').trim();
  const sessionId = requestedSessionId || generateThresholdSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const runtimePolicyScope = args.runtimePolicyScope;

  const prepare = await thresholdEcdsaHssPrepare(relayerUrl, {
    userId,
    rpId,
    operation,
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    keygenSessionId,
    auth: routeAuth,
    sessionPolicy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      userId,
      rpId,
      sessionId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      participantIds: participantIds || undefined,
      ttlMs,
      remainingUses,
    },
    sessionKind,
  });
  if (!prepare.ok) {
    throw new Error(
      prepare.error || prepare.message || prepare.code || 'Threshold bootstrap prepare failed',
    );
  }
  const ceremonyId = readString(prepare.ceremonyId, 'ceremonyId');
  const preparedServerSessionB64u = readString(
    prepare.preparedServerSessionB64u,
    'preparedServerSessionB64u',
  );
  const serverAssistInitB64u = readString(prepare.serverAssistInitB64u, 'serverAssistInitB64u');

  const preparedClientSession = threshold_ecdsa_hss_prepare_session({
    nearAccountId: userId,
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
    clientRootShare32: args.clientRootShare32,
  }) as { evaluatorDriverStateB64u?: unknown };
  const evaluatorDriverStateB64u = readString(
    preparedClientSession.evaluatorDriverStateB64u,
    'evaluatorDriverStateB64u',
  );
  const clientRequest = threshold_ecdsa_hss_prepare_client_request({
    evaluatorDriverStateB64u,
    serverAssistInitMessageB64u: serverAssistInitB64u,
    clientRootShare32: args.clientRootShare32,
  }) as { clientEvalRequestB64u?: unknown };
  const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
    ceremonyId,
    preparedServerSessionB64u,
    serverAssistInitB64u,
    clientEvalRequestB64u: readString(clientRequest.clientEvalRequestB64u, 'clientEvalRequestB64u'),
  });

  const respond = await thresholdEcdsaHssRespond(relayerUrl, {
    ceremonyId,
    requestMessageB64u,
    auth: routeAuth,
    sessionKind,
  });
  if (!respond.ok) {
    throw new Error(
      respond.error || respond.message || respond.code || 'Threshold bootstrap respond failed',
    );
  }
  const responseMessageB64u = readString(respond.responseMessageB64u, 'responseMessageB64u');
  const parsedResponse = parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
  if (!parsedResponse) {
    throw new Error(
      'Threshold bootstrap respond response missing hidden-eval server response envelope',
    );
  }
  const clientFinalize = threshold_ecdsa_hss_finalize_client_request({
    evaluatorDriverStateB64u,
    serverEvalResponseB64u: parsedResponse.serverEvalResponseB64u,
  }) as { clientEvalFinalizeB64u?: unknown };
  const finalizeMessageB64u = await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
    ceremonyId,
    requestMessageB64u,
    responseMessageB64u,
    clientEvalFinalizeB64u: readString(
      clientFinalize.clientEvalFinalizeB64u,
      'clientEvalFinalizeB64u',
    ),
  });

  const bootstrap = await thresholdEcdsaHssFinalize(relayerUrl, {
    ceremonyId,
    clientFinalizeMessageB64u: finalizeMessageB64u,
    auth: routeAuth,
    sessionKind,
  });
  if (!bootstrap.ok) {
    throw new Error(
      bootstrap.error ||
        bootstrap.message ||
        bootstrap.code ||
        'Threshold bootstrap finalize failed',
    );
  }

  const resolvedEcdsaThresholdKeyId = readString(
    bootstrap.ecdsaThresholdKeyId,
    'ecdsaThresholdKeyId',
  );
  const relayerKeyId = readString(bootstrap.relayerKeyId, 'relayerKeyId');
  const clientVerifyingShareB64u = readString(
    bootstrap.clientVerifyingShareB64u,
    'clientVerifyingShareB64u',
  );
  const clientAdditiveShare32B64u = readString(
    bootstrap.clientAdditiveShare32B64u,
    'clientAdditiveShare32B64u',
  );
  let emailOtpClientAdditiveShare32: Uint8Array;
  try {
    emailOtpClientAdditiveShare32 = base64UrlDecode(clientAdditiveShare32B64u);
  } catch {
    throw new Error('clientAdditiveShare32B64u must be valid base64url');
  }
  if (emailOtpClientAdditiveShare32.length !== 32) {
    zeroizeBytes(emailOtpClientAdditiveShare32);
    throw new Error('clientAdditiveShare32B64u must decode to 32 bytes');
  }
  const resolvedParticipantIds =
    normalizeThresholdEd25519ParticipantIds(bootstrap.participantIds) ||
    participantIds ||
    undefined;
  if (!resolvedParticipantIds) {
    throw new Error('Threshold bootstrap response missing participantIds');
  }
  const resolvedSessionId = readString(bootstrap.sessionId || sessionId, 'sessionId');
  const resolvedRemainingUses = Number.isFinite(Number(bootstrap.remainingUses))
    ? Math.floor(Number(bootstrap.remainingUses))
    : remainingUses;
  const expiresAtMs = Number.isFinite(Number(bootstrap.expiresAtMs))
    ? Math.floor(Number(bootstrap.expiresAtMs))
    : Date.now() + ttlMs;
  const thresholdSessionJwt = readOptionalString(bootstrap.jwt);
  const clientAdditiveShareHandle = {
    kind: 'email_otp_worker_session' as const,
    sessionId: resolvedSessionId,
  };

  const keygen: ThresholdEcdsaSessionBootstrapResult['keygen'] = {
    ok: true,
    keygenSessionId,
    rpId,
    ecdsaThresholdKeyId: resolvedEcdsaThresholdKeyId,
    clientVerifyingShareB64u,
    relayerKeyId,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: resolvedParticipantIds,
    ...(typeof bootstrap.chainId === 'number' ? { chainId: bootstrap.chainId } : {}),
    ...(readOptionalString(bootstrap.factory)
      ? { factory: readOptionalString(bootstrap.factory) }
      : {}),
    ...(readOptionalString(bootstrap.entryPoint)
      ? { entryPoint: readOptionalString(bootstrap.entryPoint) }
      : {}),
    ...(readOptionalString(bootstrap.salt) ? { salt: readOptionalString(bootstrap.salt) } : {}),
    ...(readOptionalString(bootstrap.counterfactualAddress)
      ? { counterfactualAddress: readOptionalString(bootstrap.counterfactualAddress) }
      : {}),
    ...(readOptionalString(bootstrap.code) ? { code: readOptionalString(bootstrap.code) } : {}),
    ...(readOptionalString(bootstrap.message)
      ? { message: readOptionalString(bootstrap.message) }
      : {}),
  };
  const session: ThresholdEcdsaSessionBootstrapResult['session'] = {
    ok: true,
    sessionId: resolvedSessionId,
    expiresAtMs,
    remainingUses: resolvedRemainingUses,
    ...(thresholdSessionJwt ? { jwt: thresholdSessionJwt } : {}),
    clientVerifyingShareB64u,
    ...(readOptionalString(bootstrap.code) ? { code: readOptionalString(bootstrap.code) } : {}),
    ...(readOptionalString(bootstrap.message)
      ? { message: readOptionalString(bootstrap.message) }
      : {}),
  };

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId,
      relayerUrl,
      ecdsaThresholdKeyId: resolvedEcdsaThresholdKeyId,
      backendBinding: {
        relayerKeyId,
        clientVerifyingShareB64u,
        clientAdditiveShareHandle,
      },
      participantIds: resolvedParticipantIds,
      ...(readOptionalString(bootstrap.thresholdEcdsaPublicKeyB64u)
        ? { thresholdEcdsaPublicKeyB64u: readOptionalString(bootstrap.thresholdEcdsaPublicKeyB64u) }
        : {}),
      ...(readOptionalString(bootstrap.ethereumAddress)
        ? { ethereumAddress: readOptionalString(bootstrap.ethereumAddress) }
        : {}),
      ...(readOptionalString(bootstrap.relayerVerifyingShareB64u)
        ? { relayerVerifyingShareB64u: readOptionalString(bootstrap.relayerVerifyingShareB64u) }
        : {}),
      thresholdSessionKind: sessionKind,
      thresholdSessionId: resolvedSessionId,
      ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    },
    keygen,
    session,
    emailOtpClientAdditiveShare32,
  };
}

async function runThresholdEcdsaExplicitExportFromClientRootShare(args: {
  relayUrl: string;
  userId: string;
  rpId: string;
  clientRootShare32: Uint8Array;
  ecdsaThresholdKeyId: string;
  thresholdSessionJwt?: string;
  sessionKind?: 'jwt' | 'cookie';
}): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  await ensureHssClientSignerWasm();
  const relayerUrl = readString(args.relayUrl, 'relayUrl');
  const userId = readString(args.userId, 'userId');
  const rpId = readString(args.rpId, 'rpId');
  const ecdsaThresholdKeyId = readString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId');
  const thresholdSessionJwt = readOptionalString(args.thresholdSessionJwt);
  const sessionKind = args.sessionKind || 'jwt';
  if (!thresholdSessionJwt && sessionKind !== 'cookie') {
    throw new Error('thresholdSessionJwt is required for JWT threshold export sessions');
  }
  const routeAuth: ThresholdEcdsaHssRouteAuth | undefined =
    thresholdSessionJwt
      ? { kind: 'threshold_session', jwt: thresholdSessionJwt }
      : sessionKind === 'cookie'
        ? { kind: 'cookie' }
        : undefined;

  const prepare = await thresholdEcdsaHssPrepare(relayerUrl, {
    userId,
    rpId,
    operation: 'explicit_key_export',
    ecdsaThresholdKeyId,
    auth: routeAuth,
    sessionKind,
  });
  if (!prepare.ok) {
    throw new Error(
      prepare.error || prepare.message || prepare.code || 'Threshold export prepare failed',
    );
  }
  const ceremonyId = readString(prepare.ceremonyId, 'ceremonyId');
  const preparedServerSessionB64u = readString(
    prepare.preparedServerSessionB64u,
    'preparedServerSessionB64u',
  );
  const serverAssistInitB64u = readString(prepare.serverAssistInitB64u, 'serverAssistInitB64u');

  const preparedClientSession = threshold_ecdsa_hss_prepare_session({
    nearAccountId: userId,
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
    clientRootShare32: args.clientRootShare32,
  }) as { evaluatorDriverStateB64u?: unknown };
  const evaluatorDriverStateB64u = readString(
    preparedClientSession.evaluatorDriverStateB64u,
    'evaluatorDriverStateB64u',
  );
  const clientRequest = threshold_ecdsa_hss_prepare_client_request({
    evaluatorDriverStateB64u,
    serverAssistInitMessageB64u: serverAssistInitB64u,
    clientRootShare32: args.clientRootShare32,
  }) as { clientEvalRequestB64u?: unknown };
  const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
    ceremonyId,
    preparedServerSessionB64u,
    serverAssistInitB64u,
    clientEvalRequestB64u: readString(clientRequest.clientEvalRequestB64u, 'clientEvalRequestB64u'),
  });

  const respond = await thresholdEcdsaHssRespond(relayerUrl, {
    ceremonyId,
    requestMessageB64u,
    auth: routeAuth,
    sessionKind,
  });
  if (!respond.ok) {
    throw new Error(
      respond.error || respond.message || respond.code || 'Threshold export respond failed',
    );
  }
  const responseMessageB64u = readString(respond.responseMessageB64u, 'responseMessageB64u');
  const parsedResponse = parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
  if (!parsedResponse) {
    throw new Error(
      'Threshold export respond response missing hidden-eval server response envelope',
    );
  }
  const clientFinalize = threshold_ecdsa_hss_finalize_client_request({
    evaluatorDriverStateB64u,
    serverEvalResponseB64u: parsedResponse.serverEvalResponseB64u,
  }) as { clientEvalFinalizeB64u?: unknown };
  const finalizeMessageB64u = await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
    ceremonyId,
    requestMessageB64u,
    responseMessageB64u,
    clientEvalFinalizeB64u: readString(
      clientFinalize.clientEvalFinalizeB64u,
      'clientEvalFinalizeB64u',
    ),
  });

  const finalized = await thresholdEcdsaHssFinalize(relayerUrl, {
    ceremonyId,
    clientFinalizeMessageB64u: finalizeMessageB64u,
    auth: routeAuth,
    sessionKind,
  });
  if (!finalized.ok) {
    throw new Error(
      finalized.error || finalized.message || finalized.code || 'Threshold export finalize failed',
    );
  }
  return {
    publicKeyHex: readString(finalized.canonicalPublicKeyHex, 'canonicalPublicKeyHex'),
    privateKeyHex: readString(finalized.privateKeyHex, 'privateKeyHex'),
    ethereumAddress: readString(finalized.canonicalEthereumAddress, 'canonicalEthereumAddress'),
  };
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  (
    self as unknown as { postMessage: (message: unknown, transfer?: Transferable[]) => void }
  ).postMessage(message, transfer);
}

setTimeout(() => {
  postToMainThread({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as EmailOtpWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    switch (msg.type) {
      case 'requestEmailOtpChallenge': {
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: '/wallet/email-otp/login/challenge',
          appSessionJwt: msg.payload.appSessionJwt,
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(msg.payload.operation ? { operation: msg.payload.operation } : {}),
          },
        });
        const challenge = response.challenge as Record<string, unknown>;
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            challengeId: readString(challenge?.challengeId, 'challengeId'),
            otpChannel: EMAIL_OTP_CHANNEL,
          },
        });
        return;
      }
      case 'requestEmailOtpEnrollmentChallenge': {
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: '/wallet/email-otp/registration/challenge',
          appSessionJwt: msg.payload.appSessionJwt,
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: EMAIL_OTP_CHANNEL,
          },
        });
        const challenge = response.challenge as Record<string, unknown>;
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            challengeId: readString(challenge?.challengeId, 'challengeId'),
            otpChannel: EMAIL_OTP_CHANNEL,
          },
        });
        return;
      }
      case 'enrollEmailOtpWallet': {
        const result = await completeEmailOtpEnrollmentFromSecret32({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          appSessionJwt: msg.payload.appSessionJwt,
          ...(msg.payload.clientSecret32 instanceof ArrayBuffer
            ? {
                clientSecret32: requireFixed32ArrayBuffer(
                  msg.payload.clientSecret32,
                  'clientSecret32',
                ),
              }
            : {}),
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'enrollEmailOtpWalletAndBootstrapEcdsaSession': {
        const enrolled = await completeEmailOtpEnrollmentFromSecret32({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          appSessionJwt: msg.payload.appSessionJwt,
          returnClientRootShare32: true,
          ...(msg.payload.clientSecret32 instanceof ArrayBuffer
            ? {
                clientSecret32: requireFixed32ArrayBuffer(
                  msg.payload.clientSecret32,
                  'clientSecret32',
                ),
              }
            : {}),
        });
        const clientRootShare32 = enrolled.clientRootShare32;
        if (!(clientRootShare32 instanceof Uint8Array)) {
          throw new Error('Email OTP enrollment did not return client root share for bootstrap');
        }
        let emailOtpClientAdditiveShare32: Uint8Array | null = null;
        try {
          const runtimePolicyScope =
            normalizeThresholdRuntimePolicyScope(msg.payload.runtimePolicyScope) ||
            parseThresholdRuntimePolicyScopeFromJwt(msg.payload.thresholdRouteAuth?.jwt) ||
            parseThresholdRuntimePolicyScopeFromJwt(msg.payload.appSessionJwt);
          const workerBootstrap = await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
            relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
            userId:
              String(msg.payload.userId || msg.payload.walletId || '').trim() ||
              readString(msg.payload.walletId, 'walletId'),
            rpId: readString(msg.payload.rpId, 'rpId'),
            clientRootShare32,
            operation: 'email_otp_bootstrap',
            ecdsaThresholdKeyId: msg.payload.ecdsaThresholdKeyId,
            participantIds: msg.payload.participantIds,
            sessionKind: msg.payload.sessionKind,
            sessionId: msg.payload.sessionId,
            ...(readOptionalThresholdRouteAuth(msg.payload.thresholdRouteAuth)
              ? { thresholdRouteAuth: readOptionalThresholdRouteAuth(msg.payload.thresholdRouteAuth) }
              : {}),
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            ttlMs: msg.payload.ttlMs,
            remainingUses: msg.payload.remainingUses,
          });
          const { emailOtpClientAdditiveShare32: additiveShare32, ...bootstrap } = workerBootstrap;
          emailOtpClientAdditiveShare32 = additiveShare32;
          putEmailOtpWarmSessionMaterial({
            sessionId: readString(bootstrap.session?.sessionId, 'thresholdSessionId'),
            clientRootShare32,
            clientAdditiveShare32: emailOtpClientAdditiveShare32,
            expiresAtMs: Math.floor(Number(bootstrap.session?.expiresAtMs) || 0),
            remainingUses: Math.floor(Number(bootstrap.session?.remainingUses) || 0),
          });
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              enrollment: {
                thresholdEcdsaClientVerifyingShareB64u:
                  enrolled.thresholdEcdsaClientVerifyingShareB64u,
                thresholdEd25519PrfFirstB64u: enrolled.thresholdEd25519PrfFirstB64u,
                challengeId: enrolled.challengeId,
                otpChannel: enrolled.otpChannel,
                emailOtpKeyVersion: enrolled.emailOtpKeyVersion,
                unlockPublicKeyB64u: enrolled.unlockPublicKeyB64u,
                unlockKeyVersion: enrolled.unlockKeyVersion,
              },
              bootstrap,
            },
          });
        } finally {
          zeroizeBytes(clientRootShare32);
          zeroizeBytes(emailOtpClientAdditiveShare32);
        }
        return;
      }
      case 'verifyEmailOtpCode': {
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: '/wallet/email-otp/login/verify',
          appSessionJwt: msg.payload.appSessionJwt,
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            challengeId: readString(msg.payload.challengeId, 'challengeId'),
            otpCode: readString(msg.payload.otpCode, 'otpCode'),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(msg.payload.operation ? { operation: msg.payload.operation } : {}),
          },
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            loginGrant: readString(response.loginGrant, 'loginGrant'),
            otpChannel: EMAIL_OTP_CHANNEL,
            emailOtpEscrowBlob: readString(response.emailOtpEscrowBlob, 'emailOtpEscrowBlob'),
          },
        });
        return;
      }
      case 'loginWithEmailOtpWallet': {
        const result = await loginWithEmailOtpAndRecoverClientRootShare({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          appSessionJwt: msg.payload.appSessionJwt,
          operation: msg.payload.operation,
        });
        try {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              recovery: {
                loginGrant: result.loginGrant,
                challengeId: result.challengeId,
                emailOtpKeyVersion: result.emailOtpKeyVersion,
                unlockChallengeId: result.unlockChallengeId,
                unlockChallengeB64u: result.unlockChallengeB64u,
                unlockPublicKeyB64u: result.unlockPublicKeyB64u,
                unlockSignatureB64u: result.unlockSignatureB64u,
                thresholdEd25519PrfFirstB64u: result.thresholdEd25519PrfFirstB64u,
              },
            },
          });
        } finally {
          zeroizeBytes(result.clientRootShare32);
        }
        return;
      }
      case 'loginWithEmailOtpAndBootstrapEcdsaSession': {
        const result = await loginWithEmailOtpAndRecoverClientRootShare({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          appSessionJwt: msg.payload.appSessionJwt,
          operation: msg.payload.operation,
        });
        let emailOtpClientAdditiveShare32: Uint8Array | null = null;
        try {
          const runtimePolicyScope =
            normalizeThresholdRuntimePolicyScope(msg.payload.runtimePolicyScope) ||
            parseThresholdRuntimePolicyScopeFromJwt(msg.payload.thresholdRouteAuth?.jwt) ||
            parseThresholdRuntimePolicyScopeFromJwt(msg.payload.appSessionJwt);
          const workerBootstrap = await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
            relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
            userId:
              String(msg.payload.userId || msg.payload.walletId || '').trim() ||
              readString(msg.payload.walletId, 'walletId'),
            rpId: readString(msg.payload.rpId, 'rpId'),
            clientRootShare32: result.clientRootShare32,
            operation: 'email_otp_bootstrap',
            ecdsaThresholdKeyId: msg.payload.ecdsaThresholdKeyId,
            participantIds: msg.payload.participantIds,
            sessionKind: msg.payload.sessionKind,
            sessionId: msg.payload.sessionId,
            ...(readOptionalThresholdRouteAuth(msg.payload.thresholdRouteAuth)
              ? { thresholdRouteAuth: readOptionalThresholdRouteAuth(msg.payload.thresholdRouteAuth) }
              : {}),
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            ttlMs: msg.payload.ttlMs,
            remainingUses: msg.payload.remainingUses,
          });
          const { emailOtpClientAdditiveShare32: additiveShare32, ...bootstrap } = workerBootstrap;
          emailOtpClientAdditiveShare32 = additiveShare32;
          putEmailOtpWarmSessionMaterial({
            sessionId: readString(bootstrap.session?.sessionId, 'thresholdSessionId'),
            clientRootShare32: result.clientRootShare32,
            clientAdditiveShare32: emailOtpClientAdditiveShare32,
            expiresAtMs: Math.floor(Number(bootstrap.session?.expiresAtMs) || 0),
            remainingUses: Math.floor(Number(bootstrap.session?.remainingUses) || 0),
          });
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              recovery: {
                loginGrant: result.loginGrant,
                challengeId: result.challengeId,
                emailOtpKeyVersion: result.emailOtpKeyVersion,
                unlockChallengeId: result.unlockChallengeId,
                unlockChallengeB64u: result.unlockChallengeB64u,
                unlockPublicKeyB64u: result.unlockPublicKeyB64u,
                unlockSignatureB64u: result.unlockSignatureB64u,
                thresholdEd25519PrfFirstB64u: result.thresholdEd25519PrfFirstB64u,
              },
              bootstrap,
            },
          });
        } finally {
          zeroizeBytes(result.clientRootShare32);
          zeroizeBytes(emailOtpClientAdditiveShare32);
        }
        return;
      }
      case 'getEmailOtpWarmSessionStatus': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: readEmailOtpWarmSessionStatus(msg.payload.sessionId),
        });
        return;
      }
      case 'claimEmailOtpWarmSessionMaterial': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: claimEmailOtpWarmSessionMaterial({
            sessionId: readString(msg.payload.sessionId, 'sessionId'),
            uses: msg.payload.uses,
          }),
        });
        return;
      }
      case 'claimEmailOtpEcdsaSigningShare': {
        const result = claimEmailOtpEcdsaSigningShare(
          readString(msg.payload.sessionId, 'sessionId'),
        );
        postToMainThread(
          {
            id: msg.id,
            ok: true,
            result,
          },
          result.ok ? [result.clientSigningShare32] : undefined,
        );
        return;
      }
      case 'clearEmailOtpWarmSessionMaterial': {
        deleteEmailOtpWarmSession(readString(msg.payload.sessionId, 'sessionId'));
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            ok: true,
            cleared: true,
          },
        });
        return;
      }
      case 'exportThresholdEcdsaHssKeyFromEmailOtpWarmSession': {
        const claimed = claimEmailOtpWarmSessionClientRootShare({
          sessionId: readString(msg.payload.sessionId, 'sessionId'),
          uses: 1,
        });
        if (!claimed.ok) {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: claimed,
          });
          return;
        }
        try {
          const artifact = await runThresholdEcdsaExplicitExportFromClientRootShare({
            relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
            userId: readString(msg.payload.userId, 'userId'),
            rpId: readString(msg.payload.rpId, 'rpId'),
            clientRootShare32: claimed.clientRootShare32,
            ecdsaThresholdKeyId: readString(msg.payload.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
            thresholdSessionJwt: msg.payload.thresholdSessionJwt,
            sessionKind: msg.payload.sessionKind,
          });
          postToMainThread({
            id: msg.id,
            ok: true,
            result: artifact,
          });
        } finally {
          zeroizeBytes(claimed.clientRootShare32);
        }
        return;
      }
      default:
        throw new Error('Unsupported emailOtp worker operation type');
    }
  } catch (error) {
    const err = asWorkerErrorPayload(error);
    postToMainThread({
      id: msg.id,
      ok: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
      ...(err.coreCode ? { coreCode: err.coreCode } : {}),
    });
  }
});
