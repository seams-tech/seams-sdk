import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
} from './routerAbEcdsaDerivation';
import type { EmailOtpProvider } from './walletAuthAuthority';

export const SIGNING_SESSION_SEALED_RECORD_VERSION = 1 as const;
export const SIGNING_SESSION_SEAL_ALG = 'shamir3pass-v1' as const;
export const SIGNING_SESSION_SEAL_STORAGE_SCOPE = 'iframe_origin_indexeddb' as const;
export const SIGNING_SESSION_SECRET_KIND = 'signing_session_secret32' as const;
export const ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND =
  'router_ab_ed25519_normal_signing_v1' as const;
export const ROUTER_AB_ED25519_HEALTH_PATH = '/router-ab/ed25519/healthz' as const;
export const ROUTER_AB_ED25519_WALLET_SESSION_PATH = '/router-ab/wallet-session/ed25519' as const;
export const ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH =
  '/router-ab/ed25519/sign/prepare' as const;
export const ROUTER_AB_ED25519_NORMAL_SIGNING_PATH = '/router-ab/ed25519/sign' as const;
export const WALLET_SESSION_SEAL_BASE_PATH = '/wallet-session/seal' as const;

export const PASSKEY_PRF_FIRST_SALT_V1 = new Uint8Array([
  0x40, 0x0c, 0x31, 0x8b, 0x66, 0x95, 0x97, 0x36, 0x59, 0xa1, 0x69, 0x8a, 0xe5, 0x80, 0xdf, 0xd8,
  0x00, 0x1d, 0x99, 0x51, 0xba, 0x32, 0xc6, 0x95, 0xe6, 0x34, 0x99, 0x47, 0x50, 0x4f, 0x3f, 0x84,
]);

export const PASSKEY_PRF_SECOND_SALT_V1 = new Uint8Array([
  0x26, 0xda, 0x50, 0xe5, 0xac, 0x96, 0x4a, 0x7e, 0xa0, 0x84, 0x52, 0x7f, 0xb6, 0x47, 0xf6, 0x33,
  0x0b, 0x32, 0xde, 0x51, 0xa9, 0xaf, 0x46, 0x52, 0x4b, 0x00, 0x6d, 0x8f, 0x7f, 0xe7, 0xf4, 0xd1,
]);

export const EMAIL_OTP_HKDF_SALTS = {
  signingSessionSecret: 'seams/email-otp/signing-session-secret/v1',
  signingSessionRestoreRoot: 'seams/signing-session/restore-root/v1',
  thresholdEcdsaClientRoot: 'seams/signing-session/threshold-ecdsa-client-root/v1',
  thresholdEd25519RestoreSeed: 'seams/signing-session/threshold-ed25519-restore-seed/v1',
} as const;

export type SigningSessionSealAuthMethod = 'passkey' | 'email_otp';
export type SigningSessionSealCurve = 'ed25519' | 'ecdsa';
export type SealedSigningSessionEcdsaRestoreSource =
  | 'login'
  | 'registration'
  | 'manual-bootstrap'
  | 'email_otp';

export type SealedSigningSessionWalletSessionAuth =
  | {
      sessionKind: 'jwt';
      walletSessionJwt: string;
    }
  | {
      sessionKind: 'cookie';
      walletSessionJwt?: never;
    };

export type RouterAbEd25519NormalSigningState = {
  kind: typeof ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND;
  signingWorkerId: string;
};

function normalizeRouterAbNonEmptyString(value: unknown): string | null {
  const parsed = String(value || '').trim();
  return parsed || null;
}

export function parseRouterAbEd25519NormalSigningState(
  value: unknown,
): RouterAbEd25519NormalSigningState | null {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) return null;
  if (record.kind !== ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND) return null;
  const signingWorkerId = normalizeRouterAbNonEmptyString(record.signingWorkerId);
  if (!signingWorkerId) {
    throw new Error('Invalid Router A/B Ed25519 normal-signing state: missing signingWorkerId');
  }
  return {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId,
  };
}

export function requireRouterAbEd25519NormalSigningState(
  value: unknown,
): RouterAbEd25519NormalSigningState {
  const parsed = parseRouterAbEd25519NormalSigningState(value);
  if (!parsed) {
    throw new Error('Router A/B Ed25519 normal-signing state is required');
  }
  return parsed;
}

export type SealedSigningSessionEcdsaChainTarget =
  | {
      kind: 'tempo';
      chainId: number;
      networkSlug: string;
    }
  | {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug: string;
    };

type SealedSigningSessionEcdsaRestoreMetadataBase = SealedSigningSessionWalletSessionAuth & {
  chainTarget: SealedSigningSessionEcdsaChainTarget;
  signingRootId: string;
  signingRootVersion: string;
  keyHandle: string;
  ecdsaThresholdKeyId?: string;
  ethereumAddress: string;
  relayerKeyId: string;
  clientVerifyingShareB64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  participantIds: number[];
  runtimePolicyScope?: unknown;
  routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type SealedSigningSessionEcdsaRestoreMetadata =
  | (SealedSigningSessionEcdsaRestoreMetadataBase & {
      source: Exclude<SealedSigningSessionEcdsaRestoreSource, 'email_otp'>;
      evmFamilySigningKeySlotId: string;
      roleLocalDurableMaterialRef: string;
      rpId: string;
      credentialIdB64u: string;
      providerSubjectId?: never;
      authSubjectId?: never;
    })
  | (SealedSigningSessionEcdsaRestoreMetadataBase & {
      source: 'email_otp';
      evmFamilySigningKeySlotId: string;
      provider: EmailOtpProvider;
      providerSubjectId: string;
      emailHashHex: string;
      authSubjectId?: never;
      roleLocalDurableMaterialRef: string;
      rpId?: never;
      credentialIdB64u?: never;
    });

type SealedSigningSessionEd25519RestoreMetadataBase = SealedSigningSessionWalletSessionAuth & {
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: unknown;
  clientVerifyingShareB64u?: string;
  signerSlot: number;
  keyVersion?: string;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
};

export type SealedSigningSessionEd25519RestoreMetadata =
  | (SealedSigningSessionEd25519RestoreMetadataBase & {
      credentialIdB64u: string;
      providerSubjectId?: never;
      authSubjectId?: never;
    })
  | (SealedSigningSessionEd25519RestoreMetadataBase & {
      providerSubjectId: string;
      emailHashHex: string;
      credentialIdB64u?: never;
      authSubjectId?: never;
    });

type SealedSigningSessionRecordBase = {
  v: typeof SIGNING_SESSION_SEALED_RECORD_VERSION;
  alg: typeof SIGNING_SESSION_SEAL_ALG;
  storageScope: typeof SIGNING_SESSION_SEAL_STORAGE_SCOPE;
  authMethod: SigningSessionSealAuthMethod;
  secretKind: typeof SIGNING_SESSION_SECRET_KIND;
  storeKey: string;
  signingGrantId: string;
  sealedSecretB64u: string;
  walletId: string;
  relayerUrl: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
};

export type SealedSigningSessionRecord =
  | (SealedSigningSessionRecordBase & {
      curve: 'ed25519';
      thresholdSessionIds: {
        ed25519: string;
        ecdsa?: string;
      };
      signingRootId?: string;
      signingRootVersion?: string;
      ed25519Restore: SealedSigningSessionEd25519RestoreMetadata;
      ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
    })
  | (SealedSigningSessionRecordBase & {
      curve: 'ecdsa';
      thresholdSessionIds: {
        ed25519?: string;
        ecdsa: string;
      };
      signingRootId?: never;
      signingRootVersion?: never;
      ecdsaRestore: SealedSigningSessionEcdsaRestoreMetadata;
      ed25519Restore?: SealedSigningSessionEd25519RestoreMetadata;
    });

export type EmailOtpSigningSessionSecretInfoInput = {
  walletId: string;
  userId: string;
  signingRootId: string;
  signingRootVersion?: string;
  signingGrantId: string;
};

export type EmailOtpSigningSessionRestoreRootInfoInput = EmailOtpSigningSessionSecretInfoInput;

export type EmailOtpEcdsaRestoreInfoInput = {
  ecdsaThresholdSessionId: string;
  ecdsaThresholdKeyId: string;
  chainTarget: SealedSigningSessionEcdsaChainTarget;
  derivationPath?: string;
  participantIds: readonly number[] | string;
  relayerKeyId: string;
};

export type EmailOtpEd25519RestoreInfoInput = {
  ed25519ThresholdSessionId: string;
  relayerKeyId: string;
  participantIds: readonly number[] | string;
};

function trimString(value: unknown): string {
  return String(value || '').trim();
}

function participantIdsField(value: readonly number[] | string): string {
  if (typeof value === 'string') return trimString(value);
  return value.map((participantId) => Math.floor(Number(participantId))).join(',');
}

function ecdsaChainTargetInfoField(target: SealedSigningSessionEcdsaChainTarget): string {
  if (target.kind === 'tempo') return `tempo:${Math.floor(Number(target.chainId))}`;
  return `${target.kind}:${target.namespace}:${Math.floor(Number(target.chainId))}`;
}

export function encodeSigningSessionHkdfTuple(fields: readonly string[]): Uint8Array {
  const encoder = new TextEncoder();
  const chunks = fields.map((field) => {
    const bytes = encoder.encode(String(field || ''));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    return { len, bytes };
  });
  let total = 0;
  for (const chunk of chunks) total += chunk.len.length + chunk.bytes.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk.len, offset);
    offset += chunk.len.length;
    out.set(chunk.bytes, offset);
    offset += chunk.bytes.length;
  }
  return out;
}

export function emailOtpSigningSessionSecretInfoFields(
  args: EmailOtpSigningSessionSecretInfoInput,
): string[] {
  return [
    trimString(args.walletId),
    trimString(args.userId),
    trimString(args.signingRootId),
    trimString(args.signingRootVersion),
    trimString(args.signingGrantId),
    'email_otp',
  ];
}

export function emailOtpSigningSessionRestoreRootInfoFields(
  args: EmailOtpSigningSessionRestoreRootInfoInput,
): string[] {
  return [
    'email_otp',
    trimString(args.walletId),
    trimString(args.userId),
    trimString(args.signingRootId),
    trimString(args.signingRootVersion),
    trimString(args.signingGrantId),
  ];
}

export function emailOtpEcdsaRestoreInfoFields(args: EmailOtpEcdsaRestoreInfoInput): string[] {
  return [
    trimString(args.ecdsaThresholdSessionId),
    trimString(args.ecdsaThresholdKeyId),
    ecdsaChainTargetInfoField(args.chainTarget),
    trimString(args.derivationPath || 'evm-signing'),
    participantIdsField(args.participantIds),
    trimString(args.relayerKeyId),
  ];
}

export function emailOtpEd25519RestoreInfoFields(args: EmailOtpEd25519RestoreInfoInput): string[] {
  return [
    trimString(args.ed25519ThresholdSessionId),
    trimString(args.relayerKeyId),
    participantIdsField(args.participantIds),
  ];
}
