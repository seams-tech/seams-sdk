import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/orchestration/thresholdActivation';
import {
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  THRESHOLD_SESSION_POLICY_VERSION,
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
        otpChannel?: 'email_otp';
      };
    }
  | {
      id: string;
      type: 'requestEmailOtpEnrollmentChallenge';
      payload: {
        relayUrl: string;
        walletId: string;
        appSessionJwt?: string;
        otpChannel?: 'email_otp';
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
        otpChannel?: 'email_otp';
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
        otpChannel?: 'email_otp';
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
        otpChannel?: 'email_otp';
        rpId: string;
        ecdsaThresholdKeyId?: string;
        participantIds?: number[];
        sessionKind?: 'jwt' | 'cookie';
        sessionId?: string;
        authorizationJwt: string;
        ttlMs?: number;
        remainingUses?: number;
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
      type: 'clearEmailOtpWarmSessionMaterial';
      payload: {
        sessionId: string;
      };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

type EmailOtpWarmSessionEntry = {
  clientRootShare32: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
};

type EmailOtpWarmSessionStatusResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionClaimResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

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

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function deleteEmailOtpWarmSession(sessionId: string): void {
  const entry = emailOtpWarmSessions.get(sessionId);
  if (entry) {
    zeroizeBytes(entry.clientRootShare32);
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
  expiresAtMs: number;
  remainingUses: number;
}): void {
  const sessionId = readString(args.sessionId, 'sessionId');
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  if (!(args.clientRootShare32 instanceof Uint8Array) || args.clientRootShare32.length !== 32) {
    throw new Error('clientRootShare32 must contain 32 bytes');
  }
  if (expiresAtMs <= Date.now() || remainingUses <= 0) {
    throw new Error('Invalid Email OTP warm-session ttl or remainingUses');
  }
  deleteEmailOtpWarmSession(sessionId);
  emailOtpWarmSessions.set(sessionId, {
    clientRootShare32: Uint8Array.from(args.clientRootShare32),
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
}): Promise<{
  thresholdEcdsaClientVerifyingShareB64u: string;
  challengeId: string;
  otpChannel: 'email_otp';
  emailOtpKeyVersion: string;
  unlockPublicKeyB64u: string;
  unlockKeyVersion: string;
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
  try {
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId) {
      const challenge = await postEmailOtpJson({
        relayUrl,
        route: '/wallet/email-otp/enroll/challenge',
        appSessionJwt: args.appSessionJwt,
        body: {
          walletId,
          otpChannel: 'email_otp',
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
      route: '/wallet/email-otp/enroll/seal',
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
      route: '/wallet/email-otp/enroll/verify',
      appSessionJwt: args.appSessionJwt,
      body: {
        walletId,
        challengeId,
        otpCode,
        otpChannel: 'email_otp',
        emailOtpEscrowBlob,
        emailOtpKeyVersion,
        unlockPublicKey: unlockPublicKeyB64u,
        unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
        thresholdEcdsaClientVerifyingShareB64u,
      },
    });

    return {
      thresholdEcdsaClientVerifyingShareB64u,
      challengeId,
      otpChannel: 'email_otp',
      emailOtpKeyVersion,
      unlockPublicKeyB64u,
      unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
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
}): Promise<{
  clientRootShare32: Uint8Array;
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
        route: '/wallet/email-otp/challenge',
        appSessionJwt: args.appSessionJwt,
        body: {
          walletId,
          otpChannel: 'email_otp',
        },
      });
      challengeId = readString(
        (challenge.challenge as Record<string, unknown>)?.challengeId,
        'challengeId',
      );
    }
    const verified = await postEmailOtpJson({
      relayUrl,
      route: '/wallet/email-otp/verify',
      appSessionJwt: args.appSessionJwt,
      body: {
        walletId,
        challengeId,
        otpCode: readString(args.otpCode, 'otpCode'),
        otpChannel: 'email_otp',
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
    return {
      clientRootShare32: unlocked.clientRootShare32,
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
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  authorizationJwt: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<ThresholdEcdsaSessionBootstrapResult> {
  await ensureHssClientSignerWasm();
  const relayerUrl = readString(args.relayUrl, 'relayUrl');
  const userId = readString(args.userId, 'userId');
  const rpId = readString(args.rpId, 'rpId');
  const authorizationJwt = readString(args.authorizationJwt, 'authorizationJwt');
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const sessionKind = args.sessionKind || 'jwt';
  const keygenSessionId = generateKeygenSessionId();
  const requestedSessionId = String(args.sessionId || '').trim();
  const sessionId = requestedSessionId || generateThresholdSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: args.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);

  const prepare = await thresholdEcdsaHssPrepare(relayerUrl, {
    userId,
    rpId,
    operation: 'session_bootstrap',
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    keygenSessionId,
    authorizationJwt,
    sessionPolicy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      userId,
      rpId,
      sessionId,
      participantIds: participantIds || undefined,
      ttlMs,
      remainingUses,
    },
    sessionKind,
  });
  if (!prepare.ok) {
    throw new Error(prepare.error || prepare.message || prepare.code || 'Threshold bootstrap prepare failed');
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
    authorizationJwt,
    sessionKind,
  });
  if (!respond.ok) {
    throw new Error(respond.error || respond.message || respond.code || 'Threshold bootstrap respond failed');
  }
  const responseMessageB64u = readString(respond.responseMessageB64u, 'responseMessageB64u');
  const parsedResponse =
    parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
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
    authorizationJwt,
    sessionKind,
  });
  if (!bootstrap.ok) {
    throw new Error(bootstrap.error || bootstrap.message || bootstrap.code || 'Threshold bootstrap finalize failed');
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

  const keygen: ThresholdEcdsaSessionBootstrapResult['keygen'] = {
    ok: true,
    keygenSessionId,
    rpId,
    ecdsaThresholdKeyId: resolvedEcdsaThresholdKeyId,
    clientVerifyingShareB64u,
    clientAdditiveShare32B64u,
    relayerKeyId,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: resolvedParticipantIds,
    ...(typeof bootstrap.chainId === 'number' ? { chainId: bootstrap.chainId } : {}),
    ...(readOptionalString(bootstrap.factory) ? { factory: readOptionalString(bootstrap.factory) } : {}),
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
        clientAdditiveShare32B64u,
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
  };
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  (self as unknown as { postMessage: (message: unknown, transfer?: Transferable[]) => void }).postMessage(
    message,
    transfer,
  );
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
          route: '/wallet/email-otp/challenge',
          appSessionJwt: msg.payload.appSessionJwt,
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: 'email_otp',
          },
        });
        const challenge = response.challenge as Record<string, unknown>;
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            challengeId: readString(challenge?.challengeId, 'challengeId'),
            otpChannel: 'email_otp',
          },
        });
        return;
      }
      case 'requestEmailOtpEnrollmentChallenge': {
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: '/wallet/email-otp/enroll/challenge',
          appSessionJwt: msg.payload.appSessionJwt,
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: 'email_otp',
          },
        });
        const challenge = response.challenge as Record<string, unknown>;
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            challengeId: readString(challenge?.challengeId, 'challengeId'),
            otpChannel: 'email_otp',
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
      case 'verifyEmailOtpCode': {
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: '/wallet/email-otp/verify',
          appSessionJwt: msg.payload.appSessionJwt,
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            challengeId: readString(msg.payload.challengeId, 'challengeId'),
            otpCode: readString(msg.payload.otpCode, 'otpCode'),
            otpChannel: 'email_otp',
          },
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            loginGrant: readString(response.loginGrant, 'loginGrant'),
            otpChannel: 'email_otp',
            emailOtpEscrowBlob: readString(response.emailOtpEscrowBlob, 'emailOtpEscrowBlob'),
          },
        });
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
        });
        try {
          const bootstrap = await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
            relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
            userId:
              String(msg.payload.userId || msg.payload.walletId || '').trim() ||
              readString(msg.payload.walletId, 'walletId'),
            rpId: readString(msg.payload.rpId, 'rpId'),
            clientRootShare32: result.clientRootShare32,
            ecdsaThresholdKeyId: msg.payload.ecdsaThresholdKeyId,
            participantIds: msg.payload.participantIds,
            sessionKind: msg.payload.sessionKind,
            sessionId: msg.payload.sessionId,
            authorizationJwt: readString(msg.payload.authorizationJwt, 'authorizationJwt'),
            ttlMs: msg.payload.ttlMs,
            remainingUses: msg.payload.remainingUses,
          });
          putEmailOtpWarmSessionMaterial({
            sessionId: readString(bootstrap.session?.sessionId, 'thresholdSessionId'),
            clientRootShare32: result.clientRootShare32,
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
              },
              bootstrap,
            },
          });
        } finally {
          zeroizeBytes(result.clientRootShare32);
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
