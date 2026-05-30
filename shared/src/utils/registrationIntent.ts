import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import { base64UrlEncode } from './encoders';

export type WalletId = string & {
  readonly __walletIdBrand: unique symbol;
};

export type RegistrationIntentGrant = string & {
  readonly __registrationIntentGrantBrand: unique symbol;
};

export type AddAuthMethodIntentGrant = string & {
  readonly __addAuthMethodIntentGrantBrand: unique symbol;
};

export type AddSignerIntentGrant = string & {
  readonly __addSignerIntentGrantBrand: unique symbol;
};

export type RegisterWalletInput =
  | {
      kind: 'server_generated';
      walletId?: never;
    }
  | {
      kind: 'provided';
      walletId: WalletId;
    };

export type PasskeyRegistrationAuthMethodInput = {
  kind: 'passkey';
  authenticatorOptions?: unknown;
  email?: never;
  otpCode?: never;
  challengeId?: never;
  appSessionJwt?: never;
};

export type EmailOtpRegistrationAuthMethodInput = {
  kind: 'email_otp';
  email: string;
  otpCode: string;
  appSessionJwt: string;
  challengeId?: string;
  authenticatorOptions?: never;
};

export type RegistrationAuthMethodInput =
  | PasskeyRegistrationAuthMethodInput
  | EmailOtpRegistrationAuthMethodInput;

export type AddAuthMethodInput =
  | {
      kind: 'passkey';
      email?: never;
      otpCode?: never;
      challengeId?: never;
      appSessionJwt?: never;
      authenticatorOptions?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      otpCode?: never;
      challengeId?: never;
      appSessionJwt?: never;
      authenticatorOptions?: never;
    };

export type WalletAuthMethodTarget =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      email?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      credentialIdB64u?: never;
    };

export type RegistrationAuthority =
  | {
      kind: 'passkey';
      walletId: WalletId;
      rpId: string;
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
      counter: number;
      registrationIntentDigestB64u: string;
      providerSubject?: never;
      email?: never;
      emailHashHex?: never;
      challengeId?: never;
    }
  | {
      kind: 'email_otp';
      walletId: WalletId;
      rpId: string;
      /** OIDC provider subject from the app-session JWT that requested the OTP. */
      providerSubject: string;
      /** Normalized email address that received and verified the OTP. */
      email: string;
      emailHashHex: string;
      challengeId: string;
      registrationIntentDigestB64u: string;
      credentialIdB64u?: never;
      credentialPublicKeyB64u?: never;
      counter?: never;
    };

export type EmailOtpRegistrationProof = {
  version: 'email_otp_registration_proof_v1';
  /** OIDC provider subject from the app-session JWT that requested the OTP. */
  providerSubject: string;
  /** Normalized email address that received the OTP. */
  email: string;
  challengeId: string;
  otpCode: string;
  otpChannel: 'email_otp';
  /** Registration intent digest that binds the OTP proof to the wallet-registration request. */
  registrationIntentDigestB64u: string;
  appSessionVersion: string;
};

export type WalletAuthMethodRecord =
  | {
      version: 'wallet_auth_method_v1';
      kind: 'passkey';
      status: 'active' | 'revoked';
      walletId: WalletId;
      rpId: string;
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
      counter: number;
      createdAtMs: number;
      updatedAtMs: number;
      emailHashHex?: never;
      challengeId?: never;
    }
  | {
      version: 'wallet_auth_method_v1';
      kind: 'email_otp';
      status: 'active' | 'revoked';
      walletId: WalletId;
      rpId: string;
      emailHashHex: string;
      challengeId: string;
      createdAtMs: number;
      updatedAtMs: number;
      credentialIdB64u?: never;
      credentialPublicKeyB64u?: never;
      counter?: never;
    };

export type ThresholdEd25519RegistrationSpec = {
  nearAccountId: string;
  signerSlot: number;
  participantIds: number[];
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
  createNearAccount: boolean;
};

export type ThresholdEcdsaRegistrationSpec = {
  chainTargets: unknown[];
  participantIds: number[];
};

export type NearAccountOwnershipProofMessageV1 = {
  version: 'near_account_ownership_proof_message_v1';
  walletId: WalletId;
  rpId: string;
  nearAccountId: string;
  publicKey: string;
  nonceB64u: string;
  issuedAtMs: number;
  expiresAtMs: number;
};

export type NearAccountOwnershipProofV1 = {
  version: 'near_account_ownership_proof_v1';
  message: NearAccountOwnershipProofMessageV1;
  signatureB64u: string;
};

export type ThresholdEd25519AddSignerSpec =
  | {
      mode: 'create_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: number[];
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      accountOwnershipProof?: never;
    }
  | {
      mode: 'link_existing_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: number[];
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      accountOwnershipProof: NearAccountOwnershipProofV1;
    };

export type ThresholdEcdsaAddSignerSpec = {
  chainTargets: unknown[];
  participantIds: number[];
};

export type RegistrationSignerSelection =
  | {
      mode: 'ed25519_only';
      ed25519: ThresholdEd25519RegistrationSpec;
      ecdsa?: never;
    }
  | {
      mode: 'ecdsa_only';
      ecdsa: ThresholdEcdsaRegistrationSpec;
      ed25519?: never;
    }
  | {
      mode: 'ed25519_and_ecdsa';
      ed25519: ThresholdEd25519RegistrationSpec;
      ecdsa: ThresholdEcdsaRegistrationSpec;
    };

export type AddSignerSelection =
  | {
      mode: 'ed25519';
      ed25519: ThresholdEd25519AddSignerSpec;
      ecdsa?: never;
    }
  | {
      mode: 'ecdsa';
      ecdsa: ThresholdEcdsaAddSignerSpec;
      ed25519?: never;
    };

export type RuntimePolicyScopeLike = {
  orgId: string;
  projectId: string;
  envId: string;
  signingRootVersion?: string;
};

export type RegistrationIntentV1 = {
  version: 'registration_intent_v1';
  walletId: WalletId;
  rpId: string;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddSignerIntentV1 = {
  version: 'add_signer_intent_v1';
  walletId: WalletId;
  rpId: string;
  signerSelection: AddSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddAuthMethodIntentV1 = {
  version: 'add_auth_method_intent_v1';
  walletId: WalletId;
  rpId: string;
  authMethod: AddAuthMethodInput;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export function walletIdFromString(value: string): WalletId {
  return String(value || '').trim() as WalletId;
}

export function registrationIntentGrantFromString(value: string): RegistrationIntentGrant {
  return String(value || '').trim() as RegistrationIntentGrant;
}

export function addAuthMethodIntentGrantFromString(value: string): AddAuthMethodIntentGrant {
  return String(value || '').trim() as AddAuthMethodIntentGrant;
}

export function addSignerIntentGrantFromString(value: string): AddSignerIntentGrant {
  return String(value || '').trim() as AddSignerIntentGrant;
}

export function serializeRegistrationIntentV1(intent: RegistrationIntentV1): string {
  return alphabetizeStringify(intent);
}

export function serializeAddSignerIntentV1(intent: AddSignerIntentV1): string {
  return alphabetizeStringify(intent);
}

export function serializeAddAuthMethodIntentV1(intent: AddAuthMethodIntentV1): string {
  return alphabetizeStringify(intent);
}

export function serializeNearAccountOwnershipProofMessageV1(
  message: NearAccountOwnershipProofMessageV1,
): string {
  return alphabetizeStringify(message);
}

export async function computeRegistrationIntentDigestB64u(
  intent: RegistrationIntentV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(serializeRegistrationIntentV1(intent)));
}

export async function computeAddSignerIntentDigestB64u(
  intent: AddSignerIntentV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(serializeAddSignerIntentV1(intent)));
}

export async function computeAddAuthMethodIntentDigestB64u(
  intent: AddAuthMethodIntentV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(serializeAddAuthMethodIntentV1(intent)));
}

export async function computeNearAccountOwnershipProofDigestB64u(
  message: NearAccountOwnershipProofMessageV1,
): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(serializeNearAccountOwnershipProofMessageV1(message)),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function normalizeRegistrationAuthMethodInput(
  raw: unknown,
): RegistrationAuthMethodInput | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    if (
      Object.prototype.hasOwnProperty.call(raw, 'email') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId')
    ) {
      return null;
    }
    return {
      kind: 'passkey',
      ...(raw.authenticatorOptions !== undefined
        ? { authenticatorOptions: raw.authenticatorOptions }
        : {}),
    };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email);
    const otpCode = trimString(raw.otpCode);
    const appSessionJwt = trimString(raw.appSessionJwt);
    const challengeId = trimString(raw.challengeId);
    if (
      !email ||
      !otpCode ||
      !appSessionJwt ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    return {
      kind: 'email_otp',
      email,
      otpCode,
      appSessionJwt,
      ...(challengeId ? { challengeId } : {}),
    };
  }
  return null;
}

export function normalizeAddAuthMethodInput(raw: unknown): AddAuthMethodInput | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    if (
      Object.prototype.hasOwnProperty.call(raw, 'email') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId') ||
      Object.prototype.hasOwnProperty.call(raw, 'appSessionJwt') ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    return { kind: 'passkey' };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email);
    if (
      !email ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId') ||
      Object.prototype.hasOwnProperty.call(raw, 'appSessionJwt') ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    return {
      kind: 'email_otp',
      email,
    };
  }
  return null;
}

export function normalizeWalletAuthMethodTarget(raw: unknown): WalletAuthMethodTarget | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    const credentialIdB64u = trimString(raw.credentialIdB64u);
    if (!credentialIdB64u || Object.prototype.hasOwnProperty.call(raw, 'email')) {
      return null;
    }
    return {
      kind: 'passkey',
      credentialIdB64u,
    };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email).toLowerCase();
    if (!email || Object.prototype.hasOwnProperty.call(raw, 'credentialIdB64u')) {
      return null;
    }
    return {
      kind: 'email_otp',
      email,
    };
  }
  return null;
}

export function normalizeEmailOtpRegistrationProof(
  raw: unknown,
): EmailOtpRegistrationProof | null {
  if (!isRecord(raw)) return null;
  const version = trimString(raw.version);
  const providerSubject = trimString(raw.providerSubject);
  const email = trimString(raw.email).toLowerCase();
  const challengeId = trimString(raw.challengeId);
  const otpCode = trimString(raw.otpCode);
  const otpChannel = trimString(raw.otpChannel);
  const registrationIntentDigestB64u = trimString(raw.registrationIntentDigestB64u);
  const appSessionVersion = trimString(raw.appSessionVersion);
  if (
    version !== 'email_otp_registration_proof_v1' ||
    !providerSubject ||
    !email ||
    !challengeId ||
    !otpCode ||
    otpChannel !== 'email_otp' ||
    !registrationIntentDigestB64u ||
    !appSessionVersion
  ) {
    return null;
  }
  return {
    version: 'email_otp_registration_proof_v1',
    providerSubject,
    email,
    challengeId,
    otpCode,
    otpChannel: 'email_otp',
    registrationIntentDigestB64u,
    appSessionVersion,
  };
}

function normalizeTimestampMs(value: unknown): number | null {
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0) return null;
  return numeric;
}

export function normalizeNearAccountOwnershipProofV1(
  raw: unknown,
): NearAccountOwnershipProofV1 | null {
  if (!isRecord(raw)) return null;
  const message = isRecord(raw.message) ? raw.message : null;
  if (!message) return null;
  const proofVersion = trimString(raw.version);
  const messageVersion = trimString(message.version);
  const walletId = walletIdFromString(trimString(message.walletId));
  const rpId = trimString(message.rpId);
  const nearAccountId = trimString(message.nearAccountId);
  const publicKey = trimString(message.publicKey);
  const nonceB64u = trimString(message.nonceB64u);
  const issuedAtMs = normalizeTimestampMs(message.issuedAtMs);
  const expiresAtMs = normalizeTimestampMs(message.expiresAtMs);
  const signatureB64u = trimString(raw.signatureB64u);
  if (
    proofVersion !== 'near_account_ownership_proof_v1' ||
    messageVersion !== 'near_account_ownership_proof_message_v1' ||
    !walletId ||
    !rpId ||
    !nearAccountId ||
    !publicKey ||
    !nonceB64u ||
    issuedAtMs === null ||
    expiresAtMs === null ||
    !signatureB64u
  ) {
    return null;
  }
  return {
    version: 'near_account_ownership_proof_v1',
    signatureB64u,
    message: {
      version: 'near_account_ownership_proof_message_v1',
      walletId,
      rpId,
      nearAccountId,
      publicKey,
      nonceB64u,
      issuedAtMs,
      expiresAtMs,
    },
  };
}
