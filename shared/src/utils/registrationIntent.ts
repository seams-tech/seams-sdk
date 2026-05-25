import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import { base64UrlEncode } from './encoders';

export type WalletSubjectId = string & {
  readonly __walletSubjectIdBrand: unique symbol;
};

export type RegistrationIntentGrant = string & {
  readonly __registrationIntentGrantBrand: unique symbol;
};

export type AddSignerIntentGrant = string & {
  readonly __addSignerIntentGrantBrand: unique symbol;
};

export type RegisterWalletSubjectInput =
  | {
      kind: 'server_generated';
    }
  | {
      kind: 'provided';
      walletSubjectId: WalletSubjectId;
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
  walletSubjectId: WalletSubjectId;
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
  walletSubjectId: WalletSubjectId;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddSignerIntentV1 = {
  version: 'add_signer_intent_v1';
  walletSubjectId: WalletSubjectId;
  rpId: string;
  signerSelection: AddSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export function walletSubjectIdFromString(value: string): WalletSubjectId {
  return String(value || '').trim() as WalletSubjectId;
}

export function registrationIntentGrantFromString(value: string): RegistrationIntentGrant {
  return String(value || '').trim() as RegistrationIntentGrant;
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
  const walletSubjectId = walletSubjectIdFromString(trimString(message.walletSubjectId));
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
    !walletSubjectId ||
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
      walletSubjectId,
      rpId,
      nearAccountId,
      publicKey,
      nonceB64u,
      issuedAtMs,
      expiresAtMs,
    },
  };
}
