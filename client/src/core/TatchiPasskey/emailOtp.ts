import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  decodeEmailOtpClientSecret32B64u,
  deriveEmailOtpEcdsaClientRootShare32FromSecret32,
  deriveEmailOtpUnlockAuthSeedFromSecret32,
} from '@shared/utils/emailOtpDerivation';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { WorkerOperationContext } from '../signingEngine/workerManager/executeWorkerOperation';
import type { Shamir3PassRuntime } from '../signingEngine/workerManager/workers/shamir3pass/runtime';
import { getShamir3PassRuntime } from '../signingEngine/workerManager/workers/shamir3pass/runtime';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  secp256k1PrivateKey32ToPublicKey33Wasm,
  signSecp256k1RecoverableWasm,
} from '../signingEngine/signers/wasm/ethSignerWasm';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../signingEngine/SigningEngine';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';

type FetchLike = typeof fetch;
type EmailOtpChannel = 'email_otp';
const EMAIL_OTP_UNLOCK_KEY_VERSION = 'email-otp-unlock-v1';
type EmailOtpShamirRuntime = Pick<
  Shamir3PassRuntime,
  | 'createClientKeyHandle'
  | 'destroyClientKeyHandle'
  | 'addClientSealWithKeyHandle'
  | 'addClientSealBytesWithKeyHandle'
  | 'removeClientSealWithKeyHandle'
  | 'removeClientSealWithKeyHandleToBytes'
>;
type EmailOtpClientSealAuth = {
  keyHandle: string;
};

type JsonObject = Record<string, unknown>;
type EmailOtpUnlockRecovery = {
  clientRootShare32B64u: string;
  loginGrant: string;
  challengeId: string;
  emailOtpKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
};

type EmailOtpBootstrapRecovery = Omit<EmailOtpUnlockRecovery, 'clientRootShare32B64u'>;

function requireFetchImpl(fetchImpl?: FetchLike): FetchLike {
  const resolved = fetchImpl || globalThis.fetch;
  if (typeof resolved !== 'function') {
    throw new Error('fetch is unavailable in this runtime');
  }
  return resolved;
}

function requireObjectJson(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} returned invalid JSON`);
  }
  return value as JsonObject;
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

function generateRandomSecret32(): Uint8Array {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  return crypto.getRandomValues(new Uint8Array(32));
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function omitClientRootShare(recovery: EmailOtpUnlockRecovery): EmailOtpBootstrapRecovery {
  return {
    loginGrant: recovery.loginGrant,
    challengeId: recovery.challengeId,
    emailOtpKeyVersion: recovery.emailOtpKeyVersion,
    unlockChallengeId: recovery.unlockChallengeId,
    unlockChallengeB64u: recovery.unlockChallengeB64u,
    unlockPublicKeyB64u: recovery.unlockPublicKeyB64u,
    unlockSignatureB64u: recovery.unlockSignatureB64u,
  };
}

function buildSessionHeaders(appSessionJwt?: string): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = String(appSessionJwt || '').trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function postJson(args: {
  url: string;
  body: JsonObject;
  appSessionJwt?: string;
  fetchImpl?: FetchLike;
}): Promise<JsonObject> {
  const fetchImpl = requireFetchImpl(args.fetchImpl);
  const response = await fetchImpl(args.url, {
    method: 'POST',
    headers: buildSessionHeaders(args.appSessionJwt),
    credentials: 'include',
    body: JSON.stringify(args.body),
  });
  const text = await response.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${args.url} returned non-JSON response (HTTP ${response.status})`);
  }
  const objectJson = requireObjectJson(json, args.url);
  if (!response.ok || objectJson.ok === false) {
    const message =
      (typeof objectJson.message === 'string' && objectJson.message.trim()) ||
      `${args.url} failed (HTTP ${response.status})`;
    throw new Error(message);
  }
  return objectJson;
}

async function createEmailOtpClientSealAuth(args: {
  shamirPrimeB64u: string;
  shamirRuntime: EmailOtpShamirRuntime;
}): Promise<EmailOtpClientSealAuth> {
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  if (typeof args.shamirRuntime.createClientKeyHandle !== 'function') {
    throw new Error('Shamir3Pass runtime missing createClientKeyHandle');
  }
  return {
    keyHandle: readString(
      (await args.shamirRuntime.createClientKeyHandle({ shamirPrimeB64u })).keyHandle,
      'createClientKeyHandle keyHandle',
    ),
  };
}

async function destroyEmailOtpClientSealAuth(
  runtime: EmailOtpShamirRuntime,
  auth: EmailOtpClientSealAuth | null,
): Promise<void> {
  if (!auth) return;
  if (typeof runtime.destroyClientKeyHandle !== 'function') {
    throw new Error('Shamir3Pass runtime missing destroyClientKeyHandle');
  }
  await runtime.destroyClientKeyHandle({ keyHandle: auth.keyHandle }).catch(() => undefined);
}

async function addClientSealFromString(args: {
  runtime: EmailOtpShamirRuntime;
  auth: EmailOtpClientSealAuth;
  ciphertextB64u: string;
}): Promise<string> {
  if (typeof args.runtime.addClientSealWithKeyHandle !== 'function') {
    throw new Error('Shamir3Pass runtime missing addClientSealWithKeyHandle');
  }
  return await args.runtime.addClientSealWithKeyHandle({
    ciphertextB64u: args.ciphertextB64u,
    keyHandle: args.auth.keyHandle,
  });
}

async function addClientSealFromBytes(args: {
  runtime: EmailOtpShamirRuntime;
  auth: EmailOtpClientSealAuth;
  ciphertext: Uint8Array;
}): Promise<string> {
  if (typeof args.runtime.addClientSealBytesWithKeyHandle === 'function') {
    return await args.runtime.addClientSealBytesWithKeyHandle({
      ciphertext: args.ciphertext,
      keyHandle: args.auth.keyHandle,
    });
  }
  let ciphertextB64u = '';
  try {
    ciphertextB64u = base64UrlEncode(args.ciphertext);
    return await addClientSealFromString({
      runtime: args.runtime,
      auth: args.auth,
      ciphertextB64u,
    });
  } finally {
    ciphertextB64u = '';
  }
}

async function removeClientSealToString(args: {
  runtime: EmailOtpShamirRuntime;
  auth: EmailOtpClientSealAuth;
  ciphertextB64u: string;
}): Promise<string> {
  if (typeof args.runtime.removeClientSealWithKeyHandle !== 'function') {
    throw new Error('Shamir3Pass runtime missing removeClientSealWithKeyHandle');
  }
  return await args.runtime.removeClientSealWithKeyHandle({
    ciphertextB64u: args.ciphertextB64u,
    keyHandle: args.auth.keyHandle,
  });
}

async function removeClientSealToBytes(args: {
  runtime: EmailOtpShamirRuntime;
  auth: EmailOtpClientSealAuth;
  ciphertextB64u: string;
}): Promise<Uint8Array> {
  if (typeof args.runtime.removeClientSealWithKeyHandleToBytes === 'function') {
    return await args.runtime.removeClientSealWithKeyHandleToBytes({
      ciphertextB64u: args.ciphertextB64u,
      keyHandle: args.auth.keyHandle,
    });
  }
  return decodeEmailOtpClientSecret32B64u(
    await removeClientSealToString({
      runtime: args.runtime,
      auth: args.auth,
      ciphertextB64u: args.ciphertextB64u,
    }),
  );
}

export async function requestEmailOtpChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
}): Promise<{
  challengeId: string;
  otpChannel: EmailOtpChannel;
}> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || 'email_otp',
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/challenge');
  return {
    challengeId: readString(challenge.challengeId, 'wallet/email-otp/challenge challengeId'),
    otpChannel: 'email_otp',
  };
}

export async function requestEmailOtpEnrollmentChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
}): Promise<{
  challengeId: string;
  otpChannel: EmailOtpChannel;
}> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/enroll/challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || 'email_otp',
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/enroll/challenge');
  return {
    challengeId: readString(
      challenge.challengeId,
      'wallet/email-otp/enroll/challenge challengeId',
    ),
    otpChannel: 'email_otp',
  };
}

export async function verifyEmailOtpCode(args: {
  relayUrl: string;
  walletId: string;
  challengeId: string;
  otpCode: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
}): Promise<{
  loginGrant: string;
  otpChannel: EmailOtpChannel;
  emailOtpEscrowBlob: string;
}> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/verify'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      challengeId: readString(args.challengeId, 'challengeId'),
      otpCode: readString(args.otpCode, 'otpCode'),
      otpChannel: args.otpChannel || 'email_otp',
    },
  });
  return {
    loginGrant: readString(response.loginGrant, 'wallet/email-otp/verify loginGrant'),
    otpChannel: 'email_otp',
    emailOtpEscrowBlob: readString(
      response.emailOtpEscrowBlob,
      'wallet/email-otp/verify emailOtpEscrowBlob',
    ),
  };
}

async function unsealEmailOtpClientSecret(args: {
  relayUrl: string;
  walletId: string;
  otpCode: string;
  shamirPrimeB64u: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  shamirRuntime?: EmailOtpShamirRuntime;
}): Promise<{
  clientSecret32: Uint8Array;
  loginGrant: string;
  challengeId: string;
  emailOtpKeyVersion: string;
}> {
  const walletId = readString(args.walletId, 'walletId');
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const runtime = args.shamirRuntime || (await getShamir3PassRuntime());
  const clientSealAuth = await createEmailOtpClientSealAuth({
    shamirPrimeB64u,
    shamirRuntime: runtime,
  });
  try {
    const challenge = await requestEmailOtpChallenge({
      relayUrl: args.relayUrl,
      walletId,
      appSessionJwt: args.appSessionJwt,
      otpChannel: args.otpChannel,
      fetchImpl: args.fetchImpl,
    });
    const verified = await verifyEmailOtpCode({
      relayUrl: args.relayUrl,
      walletId,
      challengeId: challenge.challengeId,
      otpCode: args.otpCode,
      appSessionJwt: args.appSessionJwt,
      otpChannel: challenge.otpChannel,
      fetchImpl: args.fetchImpl,
    });

    const wrappedCiphertext = await addClientSealFromString({
      runtime,
      auth: clientSealAuth,
      ciphertextB64u: verified.emailOtpEscrowBlob,
    });
    const unsealed = await postJson({
      url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/unseal'),
      appSessionJwt: args.appSessionJwt,
      fetchImpl: args.fetchImpl,
      body: {
        loginGrant: verified.loginGrant,
        wrappedCiphertext,
      },
    });
    const clientCiphertext = readString(unsealed.ciphertext, 'wallet/email-otp/unseal ciphertext');
    const clientSecret32 = await removeClientSealToBytes({
      runtime,
      auth: clientSealAuth,
      ciphertextB64u: clientCiphertext,
    });

    return {
      clientSecret32,
      loginGrant: verified.loginGrant,
      challengeId: challenge.challengeId,
      emailOtpKeyVersion: readString(
        unsealed.emailOtpKeyVersion,
        'wallet/email-otp/unseal emailOtpKeyVersion',
      ),
    };
  } finally {
    await destroyEmailOtpClientSealAuth(runtime, clientSealAuth);
  }
}

async function createEmailOtpEnrollmentEscrow(args: {
  relayUrl: string;
  walletId: string;
  shamirPrimeB64u: string;
  appSessionJwt?: string;
  fetchImpl?: FetchLike;
  clientSecretB64u?: string;
  shamirRuntime?: EmailOtpShamirRuntime;
}): Promise<{
  clientSecret32: Uint8Array;
  emailOtpEscrowBlob: string;
  emailOtpKeyVersion: string;
}> {
  const walletId = readString(args.walletId, 'walletId');
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const runtime = args.shamirRuntime || (await getShamir3PassRuntime());
  const clientSecret32 = args.clientSecretB64u
    ? decodeEmailOtpClientSecret32B64u(readString(args.clientSecretB64u, 'clientSecretB64u'))
    : generateRandomSecret32();
  try {
    const clientSealAuth = await createEmailOtpClientSealAuth({
      shamirPrimeB64u,
      shamirRuntime: runtime,
    });
    try {
      const wrappedCiphertext = await addClientSealFromBytes({
        runtime,
        auth: clientSealAuth,
        ciphertext: clientSecret32,
      });
      const applied = await postJson({
        url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/enroll/seal'),
        appSessionJwt: args.appSessionJwt,
        fetchImpl: args.fetchImpl,
        body: {
          walletId,
          wrappedCiphertext,
        },
      });
      const clientCiphertext = readString(
        applied.ciphertext,
        'wallet/email-otp/enroll/seal ciphertext',
      );
      const emailOtpEscrowBlob = await removeClientSealToString({
        runtime,
        auth: clientSealAuth,
        ciphertextB64u: clientCiphertext,
      });
      return {
        clientSecret32,
        emailOtpEscrowBlob,
        emailOtpKeyVersion: readString(
          applied.emailOtpKeyVersion,
          'wallet/email-otp/enroll/seal emailOtpKeyVersion',
        ),
      };
    } finally {
      await destroyEmailOtpClientSealAuth(runtime, clientSealAuth);
    }
  } catch (error) {
    zeroizeBytes(clientSecret32);
    throw error;
  }
}

async function completeEmailOtpUnlockFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  clientSecret32: Uint8Array;
  workerCtx: WorkerOperationContext;
  fetchImpl?: FetchLike;
}): Promise<{
  clientRootShare32B64u: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
}> {
  const walletId = readString(args.walletId, 'walletId');
  const userId = String(args.userId || walletId).trim() || walletId;
  const challenge = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/unlock/challenge'),
    fetchImpl: args.fetchImpl,
    body: {
      unlockBackend: 'email_otp',
      walletId,
    },
  });
  const unlockChallengeId = readString(
    challenge.challengeId,
    'wallet/unlock/challenge challengeId',
  );
  const unlockChallengeB64u = readString(
    challenge.challengeB64u,
    'wallet/unlock/challenge challengeB64u',
  );
  let challengeDigest32: Uint8Array | null = base64UrlDecode(unlockChallengeB64u);
  if (challengeDigest32.length !== 32) {
    zeroizeBytes(challengeDigest32);
    throw new Error('wallet/unlock/challenge challengeB64u must decode to 32 bytes');
  }

  let unlockPrivateKey32: Uint8Array | null = null;
  let clientRootShare32: Uint8Array | null = null;
  try {
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedFromSecret32({
      clientSecret32: args.clientSecret32,
      walletId,
    });
    const unlockPublicKey33 = await secp256k1PrivateKey32ToPublicKey33Wasm({
      privateKey32: unlockPrivateKey32,
      workerCtx: args.workerCtx,
    });
    const unlockSignature65 = await signSecp256k1RecoverableWasm({
      digest32: challengeDigest32,
      privateKey32: unlockPrivateKey32,
      workerCtx: args.workerCtx,
    });

    await postJson({
      url: joinNormalizedUrl(args.relayUrl, '/wallet/unlock/verify'),
      fetchImpl: args.fetchImpl,
      body: {
        unlockBackend: 'email_otp',
        walletId,
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: base64UrlEncode(unlockPublicKey33),
          signature: base64UrlEncode(unlockSignature65),
        },
      },
    });

    clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32FromSecret32({
      clientSecret32: args.clientSecret32,
      walletId,
      userId,
    });
    return {
      clientRootShare32B64u: base64UrlEncode(clientRootShare32),
      unlockChallengeId,
      unlockChallengeB64u,
      unlockPublicKeyB64u: base64UrlEncode(unlockPublicKey33),
      unlockSignatureB64u: base64UrlEncode(unlockSignature65),
    };
  } finally {
    zeroizeBytes(challengeDigest32);
    zeroizeBytes(clientRootShare32);
    zeroizeBytes(unlockPrivateKey32);
  }
}

export async function completeEmailOtpUnlock(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  clientSecretB64u: string;
  workerCtx: WorkerOperationContext;
  fetchImpl?: FetchLike;
}): Promise<{
  clientRootShare32B64u: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
}> {
  const clientSecret32 = decodeEmailOtpClientSecret32B64u(
    readString(args.clientSecretB64u, 'clientSecretB64u'),
  );
  try {
    return await completeEmailOtpUnlockFromSecret32({
      relayUrl: args.relayUrl,
      walletId: args.walletId,
      userId: args.userId,
      clientSecret32,
      workerCtx: args.workerCtx,
      fetchImpl: args.fetchImpl,
    });
  } finally {
    zeroizeBytes(clientSecret32);
  }
}

export async function loginWithEmailOtpAndUnlockWallet(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  shamirRuntime?: EmailOtpShamirRuntime;
}): Promise<EmailOtpUnlockRecovery> {
  const recovered = await unsealEmailOtpClientSecret(args);
  const { loginGrant, challengeId, emailOtpKeyVersion } = recovered;
  try {
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl: args.relayUrl,
      walletId: args.walletId,
      userId: args.userId,
      clientSecret32: recovered.clientSecret32,
      workerCtx: args.workerCtx,
      fetchImpl: args.fetchImpl,
    });
    return {
      clientRootShare32B64u: unlocked.clientRootShare32B64u,
      loginGrant,
      challengeId,
      emailOtpKeyVersion,
      unlockChallengeId: unlocked.unlockChallengeId,
      unlockChallengeB64u: unlocked.unlockChallengeB64u,
      unlockPublicKeyB64u: unlocked.unlockPublicKeyB64u,
      unlockSignatureB64u: unlocked.unlockSignatureB64u,
    };
  } finally {
    zeroizeBytes(recovered.clientSecret32);
  }
}

export async function enrollEmailOtpWallet(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  shamirRuntime?: EmailOtpShamirRuntime;
  clientSecretB64u?: string;
}): Promise<{
  clientRootShare32B64u: string;
  thresholdEcdsaClientVerifyingShareB64u: string;
  challengeId: string;
  otpChannel: EmailOtpChannel;
  emailOtpKeyVersion: string;
  unlockPublicKeyB64u: string;
  unlockKeyVersion: string;
}> {
  const walletId = readString(args.walletId, 'walletId');
  const userId = String(args.userId || walletId).trim() || walletId;
  const challenge = await requestEmailOtpEnrollmentChallenge({
    relayUrl: args.relayUrl,
    walletId,
    appSessionJwt: args.appSessionJwt,
    otpChannel: args.otpChannel,
    fetchImpl: args.fetchImpl,
  });
  const escrow = await createEmailOtpEnrollmentEscrow({
    relayUrl: args.relayUrl,
    walletId,
    shamirPrimeB64u: args.shamirPrimeB64u,
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    shamirRuntime: args.shamirRuntime,
    ...(readOptionalString(args.clientSecretB64u) ? { clientSecretB64u: args.clientSecretB64u } : {}),
  });
  let unlockPrivateKey32: Uint8Array | null = null;
  let thresholdClientRootShare32: Uint8Array | null = null;
  try {
    thresholdClientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32FromSecret32({
      clientSecret32: escrow.clientSecret32,
      walletId,
      userId,
    });
    const clientRootShare32B64u = base64UrlEncode(thresholdClientRootShare32);
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedFromSecret32({
      clientSecret32: escrow.clientSecret32,
      walletId,
    });
    const unlockPublicKeyB64u = base64UrlEncode(
      await secp256k1PrivateKey32ToPublicKey33Wasm({
        privateKey32: unlockPrivateKey32,
        workerCtx: args.workerCtx,
      }),
    );
    const thresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
      await secp256k1PrivateKey32ToPublicKey33Wasm({
        privateKey32: thresholdClientRootShare32,
        workerCtx: args.workerCtx,
      }),
    );

    await postJson({
      url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/enroll/verify'),
      appSessionJwt: args.appSessionJwt,
      fetchImpl: args.fetchImpl,
      body: {
        walletId,
        challengeId: challenge.challengeId,
        otpCode: readString(args.otpCode, 'otpCode'),
        otpChannel: challenge.otpChannel,
        emailOtpEscrowBlob: escrow.emailOtpEscrowBlob,
        emailOtpKeyVersion: escrow.emailOtpKeyVersion,
        unlockPublicKey: unlockPublicKeyB64u,
        unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
        thresholdEcdsaClientVerifyingShareB64u,
      },
    });

    return {
      clientRootShare32B64u,
      thresholdEcdsaClientVerifyingShareB64u,
      challengeId: challenge.challengeId,
      otpChannel: challenge.otpChannel,
      emailOtpKeyVersion: escrow.emailOtpKeyVersion,
      unlockPublicKeyB64u,
      unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
    };
  } finally {
    zeroizeBytes(escrow.clientSecret32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(thresholdClientRootShare32);
  }
}

export async function loginWithEmailOtpAndBootstrapEcdsaCapability(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  shamirRuntime?: EmailOtpShamirRuntime;
  bootstrapEcdsaSession: (args: {
    nearAccountId: string;
    chain?: ThresholdEcdsaActivationChain;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    relayerUrl?: string;
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    sessionId?: string;
    clientRootShare32B64u?: string;
    authorizationJwt?: string;
    ttlMs?: number;
    remainingUses?: number;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  chain?: ThresholdEcdsaActivationChain;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  authorizationJwt?: string;
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
}): Promise<{
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}> {
  const recovery = await loginWithEmailOtpAndUnlockWallet(args);
  try {
    const bootstrap = await args.bootstrapEcdsaSession({
      nearAccountId: readString(args.userId || args.walletId, 'nearAccountId'),
      chain: args.chain || 'evm',
      ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
      relayerUrl: args.relayUrl,
      ...(String(args.ecdsaThresholdKeyId || '').trim()
        ? { ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId || '').trim() }
        : {}),
      ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
        ? { participantIds: [...args.participantIds] }
        : {}),
      ...(args.sessionKind ? { sessionKind: args.sessionKind } : {}),
      ...(String(args.sessionId || '').trim()
        ? { sessionId: String(args.sessionId || '').trim() }
        : {}),
      ...(String(args.authorizationJwt || '').trim()
        ? { authorizationJwt: String(args.authorizationJwt || '').trim() }
        : {}),
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
      ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      clientRootShare32B64u: recovery.clientRootShare32B64u,
    });
    return {
      recovery: omitClientRootShare(recovery),
      bootstrap,
    };
  } finally {
    recovery.clientRootShare32B64u = '';
  }
}
