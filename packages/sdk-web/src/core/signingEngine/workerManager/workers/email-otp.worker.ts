import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { IndexedDBManager } from '@/core/indexedDB';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { base58Encode } from '@shared/utils/base58';
import { errorMessage } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import {
  joinNormalizedUrl,
  normalizeNonNegativeInteger,
  normalizeOptionalNonEmptyString,
  normalizeOptionalTrimmedString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1 } from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  isAttachEmailOtpToPresignPort,
  type EmailOtpEcdsaSigningShareRequest,
  type EmailOtpEcdsaSigningShareResponse,
} from '../ecdsaClientWorkerChannels';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpChannel,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import {
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  type DerivationClientSharePublicKey33B64u,
  type EcdsaDerivationRelayerPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  SIGNING_SESSION_SEAL_GROUP_ID,
  WALLET_SESSION_SEAL_BASE_PATH,
  parseRouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  parseRouterAbMpcMaterialActivationRef,
  parseRouterAbNormalSigningAuthorization,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { parseEmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/challengeDelivery';
import type { EmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  decodeEmailOtpEscrowSecret32,
  emailOtpCorruptLocalCustodyError,
  type EmailOtpEscrowSecret32DecodeResult,
} from '@/core/signingEngine/session/emailOtp/secretEscrow';
import { buildEmailOtpWorkerIssuedSessionHandle } from '@/core/platform/secretSources';
import type {
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpEcdsaClientRootHandleBinding,
  EmailOtpWalletRegistrationEcdsaPrepareHandleBinding,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayloads,
  EmailOtpWalletRegistrationEcdsaPrepareHandleRequest,
  EmailOtpWalletRegistrationEcdsaPrepareHandleResult,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerSessionHandleOperation,
  EmailOtpWorkerOperationRequestEnvelope,
  EmailOtpEd25519YaoFactorRequest,
  EmailOtpEd25519YaoFactorResult,
  EmailOtpEd25519YaoActiveCapabilityDescriptorV1,
  EmailOtpEd25519YaoRecoveryAugmentationV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEcdsaWalletUnlockAuthorization,
  EmailOtpWalletUnlockMaterialRequest,
  EmailOtpWarmMaterialTarget,
  EmailOtpWorkerOperationMap,
} from '@/core/signingEngine/workerManager/workerTypes';
import { materialActivationKey } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  EmailOtpEd25519YaoRootVault,
  type EmailOtpEd25519YaoPendingFactorHandle,
  type EmailOtpEd25519YaoRootHandle,
  type EmailOtpEd25519YaoRootScope,
} from '../../session/emailOtp/ed25519YaoRootVault';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../../session/keyMaterialBrands';
import {
  recoverEmailOtpEd25519YaoV1,
  registerEmailOtpEd25519YaoV1,
} from '../../session/emailOtp/ed25519YaoActivation';
import type {
  ProductEd25519YaoBrowserMaterialPersistencePortV1,
  ProductEd25519YaoPendingRegistrationPortV1,
} from '../../flows/registration/services/ed25519YaoRegistration';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
  WasmRouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoSealableActiveClientV1,
  type RouterAbEd25519YaoExportArtifactV1,
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '../../threshold/ed25519/yaoClient';
import { issueEd25519OperationStepUpAuthorization } from '../../threshold/ed25519/walletSession';
import type { NearResolvedEd25519SigningSessionState } from '../../interfaces/near';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../session/material/nearEd25519YaoMaterialActivation';
import {
  EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
  EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  encodeEmailOtpEd25519YaoStableCustodyBindingV1,
  persistEmailOtpEd25519YaoLocalMaterialV1,
  readEmailOtpEd25519YaoLocalMaterialByLocatorV1,
  readEmailOtpEd25519YaoLocalMaterialV1,
  type EmailOtpEd25519YaoLocalMaterialV1,
  type EmailOtpEd25519YaoStableCustodyBindingV1,
} from '../../session/emailOtp/ed25519YaoLocalMaterial';
import {
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
} from '@shared/utils/routerAbEd25519Yao';
import { type WalletRegistrationEd25519YaoBootstrapSession } from '@/core/rpcClients/relayer/walletRegistration';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  toEmailOtpAuthSubjectId,
} from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import initEvmCrypto, {
  init_evm_crypto,
  secp256k1_private_key_32_to_public_key_33,
  sign_secp256k1_recoverable,
} from '../../../../../../../wasm/evm_crypto/pkg/evm_crypto.js';
import initEmailOtpRuntime, {
  derive_email_otp_ecdsa_client_root_share32_from_secret32,
  derive_email_otp_unlock_auth_seed_from_secret32,
  init_email_otp_runtime,
} from '../../../../../../../wasm/email_otp_runtime/pkg/email_otp_runtime.js';
import initNearSignerRecoveryWasm, {
  email_recovery_chacha20poly1305_decrypt,
  email_recovery_chacha20poly1305_encrypt,
  init_worker as init_near_signer_recovery_worker,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { WorkerControlMessage, type EmailOtpWorkerProgressCode } from '../workerTypes';
import { postEmailOtpJson } from './email-otp/fetch';
import { getShamir3PassRuntime } from './shamir3pass/runtime';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  emailOtpRoutePath,
  normalizeEmailOtpRoutePlan,
  resolveEmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  deleteEmailOtpDeviceEnrollmentEscrowRecord,
  readEmailOtpDeviceEnrollmentEscrowRecord,
  writeEmailOtpDeviceEnrollmentEscrowRecord,
  type EmailOtpDeviceEnrollmentEscrowRecord,
} from './email-otp/deviceEnrollmentEscrowStore';
import {
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  deriveEmailOtpRecoveryKeyId,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
  generateEmailOtpRecoveryKeySet,
  unwrapEmailOtpDeviceEnrollmentEscrow,
  wrapEmailOtpDeviceEnrollmentEscrow,
  type EmailOtpRecoveryCodeSet,
  type EmailOtpRecoveryKeyIdBinding,
  type EmailOtpRecoveryWrapBinding,
} from '@shared/utils/emailOtpRecoveryKey';

const EMAIL_OTP_UNLOCK_KEY_VERSION = 'email-otp-unlock-v1';
const EMAIL_OTP_DEVICE_ENROLLMENT_VERSION = '1';
const EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_ID = 'email_otp_default_signing_root';
const EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_VERSION = 'default';
const EMAIL_OTP_ECDSA_CLIENT_ROOT_HANDLE_TTL_MS = 5 * 60_000;
const EMAIL_OTP_ED25519_YAO_HANDLE_TTL_MS = 5 * 60_000;
const MAX_EMAIL_OTP_ED25519_YAO_PENDING_REGISTRATIONS = 64;
const MAX_EMAIL_OTP_ED25519_YAO_ACTIVE_CLIENTS = 64;
const EMAIL_OTP_ED25519_YAO_EXPORT_AUTH_TTL_MS = 60_000;
const ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT = 'default';

function assertNeverEmailOtpWorker(value: never): never {
  throw new Error(`Unexpected Email OTP worker state: ${String(value)}`);
}

function emailOtpDeviceEnrollmentId(walletId: string, authSubjectId: string): string {
  return `email-otp-device-enrollment-v1:${walletId}:${authSubjectId}`;
}

function readJwtPayloadObject(jwtRaw: unknown): Record<string, unknown> | null {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) return null;
  const parts = jwt.split('.');
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1] || '')));
    return payload && typeof payload === 'object' && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function readAppSessionAuthSubjectIdFromRoutePlan(routePlan: EmailOtpRoutePlan): string {
  const lane = routePlan.authLane;
  if (lane.kind !== 'app_session') return '';
  const payload = readJwtPayloadObject(lane.jwt);
  return readOptionalString(payload?.providerSubject) || '';
}

function resolveEmailOtpAuthSubjectId(args: {
  walletId: string;
  userId?: unknown;
  routePlan: EmailOtpRoutePlan;
}): string {
  const appSessionAuthSubjectId = readAppSessionAuthSubjectIdFromRoutePlan(args.routePlan);
  if (appSessionAuthSubjectId) return appSessionAuthSubjectId;
  return readString(args.userId, 'userId');
}

type EmailOtpRecoveryWrappedEnrollmentEscrowPayload = {
  version: 'email_otp_recovery_wrapped_enrollment_escrow_v1';
  alg: typeof EMAIL_OTP_RECOVERY_WRAP_ALG;
  secretKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND;
  escrowKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND;
  walletId: string;
  userId: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeyId: string;
  recoveryKeyStatus: 'active';
  nonceB64u: string;
  wrappedDeviceEnrollmentEscrowB64u: string;
  aadHashB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};

type EmailOtpRecoveryChallengeEscrowPayload = Omit<
  EmailOtpRecoveryWrappedEnrollmentEscrowPayload,
  'recoveryKeyId' | 'recoveryKeyStatus' | 'issuedAtMs' | 'updatedAtMs'
> & {
  recoveryKeyId: string;
};

type ParsedEmailOtpRecoveryWrappedEnrollmentEscrowPayload = {
  payload: EmailOtpRecoveryChallengeEscrowPayload;
  binding: EmailOtpRecoveryWrapBinding;
  lifecycle: {
    status: 'active';
  };
};

type EmailOtpWorkerRequest = EmailOtpWorkerOperationRequestEnvelope;

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

type EmailOtpWarmSessionEntry = {
  clientRootShare32: Uint8Array;
  signingSessionSecret32: Uint8Array;
  clientAdditiveShare32?: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
};

type EmailOtpEd25519YaoWarmFactorEntry = {
  kind: 'ed25519_yao_factor';
  thresholdSessionId: string;
  factorSecret32: Uint8Array;
  materialActivation: MpcMaterialActivationRef;
  expiresAtMs: number;
  remainingUses: number;
};

type EmailOtpWarmMaterialEntry =
  | { kind: 'ecdsa'; entry: EmailOtpWarmSessionEntry }
  | { kind: 'ed25519_yao'; entry: EmailOtpEd25519YaoWarmFactorEntry };

type EmailOtpEcdsaClientRootHandleEntry = {
  handle: EmailOtpWorkerIssuedSessionHandlePayload;
  clientRootShare32: Uint8Array;
  expiresAtMs: number;
};

type EmailOtpWarmSessionStatusResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionConsumeResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionSealResult =
  | ({
      ok: true;
      sealedSecretB64u: string;
      keyVersion?: string;
      remainingUses: number;
      expiresAtMs: number;
    } & (
      | {
          materialKind: 'ecdsa';
          materialActivation?: never;
        }
      | {
          materialKind: 'ed25519_yao';
          materialActivation: MpcMaterialActivationRef;
        }
    ))
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaWarmSessionRehydrateResult =
  | {
      ok: true;
      clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

type EmailOtpEd25519YaoLocalMaterialRehydrateResult =
  EmailOtpWorkerOperationMap['rehydrateEmailOtpEd25519YaoLocalMaterial']['result'];

type ExactEmailOtpEcdsaWarmSessionRestore = {
  thresholdSessionId: string;
  walletId: string;
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
  authSubjectId: string;
};

type ExactEmailOtpEcdsaWarmSessionTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  keyVersion?: string;
  groupId: string;
};

type ExactEmailOtpEcdsaWarmSessionRehydrateArgs = {
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: ExactEmailOtpEcdsaWarmSessionTransport;
  restore: ExactEmailOtpEcdsaWarmSessionRestore;
};

type ParseEmailOtpEcdsaWarmSessionRehydrateArgsResult =
  | { kind: 'parsed'; value: ExactEmailOtpEcdsaWarmSessionRehydrateArgs }
  | { kind: 'error'; error: EmailOtpEcdsaWarmSessionRehydrateResult };

type SigningSessionSealTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  keyVersion?: string;
  groupId?: string;
};

type SigningSessionSealRouteResult =
  | {
      ok: true;
      ciphertext: string;
      keyVersion?: string;
      expiresAtMs?: number;
      remainingUses?: number;
    }
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaSigningShareClaimResult =
  | { ok: true; clientSigningShare32: ArrayBuffer; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpEd25519YaoPendingRegistrationEntry = {
  kind: 'pending_registration';
  pending: ProductEd25519YaoPendingRegistrationPortV1;
  factorSecret32: Uint8Array;
};

type EmailOtpEd25519YaoActiveClientEntry = {
  kind: 'active_client';
  activeClient: RouterAbEd25519YaoActiveClientV1;
};

type EmailOtpEd25519YaoWorkerActivationResult = {
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
};

function buildEmailOtpEd25519YaoStableCustodyBinding(args: {
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  walletIdentity: EmailOtpEd25519YaoLocalMaterialWalletIdentity;
  enrollment: EmailOtpDeviceEnrollmentEscrowRecord;
}): EmailOtpEd25519YaoStableCustodyBindingV1 {
  const walletId = args.walletIdentity.walletId;
  const nearAccountId = args.walletIdentity.nearAccountId;
  if (
    args.enrollment.walletId !== walletId ||
    args.enrollment.authSubjectId !== args.walletIdentity.providerSubjectId
  ) {
    throw new Error('Email OTP Ed25519 local custody enrollment changed wallet identity');
  }
  return {
    kind: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    walletId,
    nearAccountId,
    provider: 'google',
    providerSubjectId: args.walletIdentity.providerSubjectId,
    enrollmentId: args.enrollment.enrollmentId,
    enrollmentVersion: args.enrollment.enrollmentVersion,
    enrollmentSealKeyVersion: args.enrollment.enrollmentSealKeyVersion,
    signerSlot: args.metadata.applicationBinding.key_creation_signer_slot,
    nearEd25519SigningKeyId: args.metadata.applicationBinding.near_ed25519_signing_key_id,
    signingRootId: args.metadata.applicationBinding.signing_root_id,
    signingRootVersion: args.walletIdentity.signingRootVersion,
    lifecycleId: args.metadata.scope.lifecycle_id,
    rootShareEpoch: args.metadata.scope.root_share_epoch,
    signerSetId: args.metadata.scope.signer_set_id,
    participantIds: args.metadata.participantIds,
    signingWorkerId: args.metadata.scope.signing_worker_id,
    materialActivation: args.metadata.materialActivation,
    registeredPublicKeyB64u: base64UrlEncode(args.metadata.registeredPublicKey),
    signingWorkerVerifyingShareB64u: base64UrlEncode(args.metadata.signingWorkerVerifyingShare),
    stateEpoch: args.metadata.stateEpoch.toString(10),
    activationTranscriptB64u: base64UrlEncode(args.metadata.transcript),
    activeCapabilityBindingB64u: base64UrlEncode(
      Uint8Array.from(args.metadata.activeCapabilityBinding),
    ),
    applicationBinding: {
      walletId: args.metadata.applicationBinding.wallet_id,
      nearEd25519SigningKeyId: args.metadata.applicationBinding.near_ed25519_signing_key_id,
      signingRootId: args.metadata.applicationBinding.signing_root_id,
      keyCreationSignerSlot: args.metadata.applicationBinding.key_creation_signer_slot,
    },
  };
}

type EmailOtpEd25519YaoLocalMaterialWalletIdentity = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly providerSubjectId: string;
  readonly signingRootVersion: string;
};

async function persistEmailOtpEd25519YaoActiveClientLocalMaterial(args: {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  walletIdentity: EmailOtpEd25519YaoLocalMaterialWalletIdentity;
  enrollmentSecret32: Uint8Array;
}): Promise<void> {
  const enrollmentId = emailOtpDeviceEnrollmentId(
    args.walletIdentity.walletId,
    args.walletIdentity.providerSubjectId,
  );
  const enrollment = await readEmailOtpDeviceEnrollmentEscrowRecord({
    walletId: args.walletIdentity.walletId,
    authSubjectId: args.walletIdentity.providerSubjectId,
    enrollmentId,
  });
  if (
    !enrollment ||
    enrollment.walletId !== args.walletIdentity.walletId ||
    enrollment.authSubjectId !== args.walletIdentity.providerSubjectId ||
    enrollment.enrollmentId !== enrollmentId
  ) {
    throw new Error('Email OTP Ed25519 local custody requires its device enrollment');
  }
  const binding = buildEmailOtpEd25519YaoStableCustodyBinding({
    metadata: args.metadata,
    walletIdentity: args.walletIdentity,
    enrollment,
  });
  const nonce = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nonce);
  if (!(args.activeClient instanceof WasmRouterAbEd25519YaoActiveClientV1)) {
    throw new Error('Email OTP Ed25519 local custody requires a worker-owned WASM client');
  }
  const sealed = args.activeClient.sealEmailOtpLocalMaterial({
    ownedEnrollmentSecret32: args.enrollmentSecret32.slice(),
    binding: encodeEmailOtpEd25519YaoStableCustodyBindingV1(binding),
    nonce,
  });
  await persistEmailOtpEd25519YaoLocalMaterialV1({
    store: IndexedDBManager,
    binding,
    envelope: {
      algorithm: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
      nonceB64u: base64UrlEncode(sealed.nonce),
      ciphertextB64u: base64UrlEncode(sealed.ciphertext),
    },
  });
  const verified = await readEmailOtpEd25519YaoLocalMaterialV1({
    store: IndexedDBManager,
    expectedBinding: binding,
  });
  if (verified.kind !== 'exact_material_ready') {
    throw new Error('Email OTP Ed25519 local custody persistence verification failed');
  }
}

class EmailOtpEd25519YaoRegistrationMaterialPersistencePort implements ProductEd25519YaoBrowserMaterialPersistencePortV1 {
  constructor(
    private readonly walletIdentity: EmailOtpEd25519YaoLocalMaterialWalletIdentity,
    private readonly enrollmentSecret32: Uint8Array,
  ) {}

  async persist(
    activeClient: RouterAbEd25519YaoSealableActiveClientV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    const metadata = activeClient.metadata();
    await persistEmailOtpEd25519YaoActiveClientLocalMaterial({
      activeClient,
      metadata,
      walletIdentity: this.walletIdentity,
      enrollmentSecret32: this.enrollmentSecret32,
    });
    return metadata;
  }
}

const emailOtpWarmSessions = new Map<string, EmailOtpWarmSessionEntry>();
const emailOtpEd25519YaoWarmFactors = new Map<string, EmailOtpEd25519YaoWarmFactorEntry>();
const emailOtpEcdsaClientRootHandles = new Map<string, EmailOtpEcdsaClientRootHandleEntry>();
const emailOtpEd25519YaoRootVault = new EmailOtpEd25519YaoRootVault();
const emailOtpEd25519YaoPendingRegistrations = new Map<
  string,
  EmailOtpEd25519YaoPendingRegistrationEntry
>();
const emailOtpEd25519YaoActiveClients = new Map<string, EmailOtpEd25519YaoActiveClientEntry>();
const signingSessionSealApplyInFlight = new Map<string, Promise<EmailOtpWarmSessionSealResult>>();
const signingSessionSealRemoveInFlight = new Map<
  string,
  Promise<EmailOtpEcdsaWarmSessionRehydrateResult>
>();
const SIGNING_SESSION_SEAL_BASE_PATH = WALLET_SESSION_SEAL_BASE_PATH;

function cloneEmailOtpEd25519YaoMetadata(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): RouterAbEd25519YaoActiveClientMetadataV1 {
  return {
    kind: metadata.kind,
    scope: { ...metadata.scope },
    applicationBinding: { ...metadata.applicationBinding },
    participantIds: [metadata.participantIds[0], metadata.participantIds[1]],
    materialActivation: metadata.materialActivation,
    registeredPublicKey: metadata.registeredPublicKey.slice(),
    signingWorkerVerifyingShare: metadata.signingWorkerVerifyingShare.slice(),
    stateEpoch: metadata.stateEpoch,
    transcript: metadata.transcript.slice(),
    activeCapabilityBinding: [...metadata.activeCapabilityBinding],
  };
}

function removeEmailOtpEd25519YaoActiveClient(activeClientHandle: string): boolean {
  const entry = emailOtpEd25519YaoActiveClients.get(activeClientHandle);
  if (!entry) return false;
  emailOtpEd25519YaoActiveClients.delete(activeClientHandle);
  entry.activeClient.dispose();
  return true;
}

function storeEmailOtpEd25519YaoActiveClient(
  activeClient: RouterAbEd25519YaoActiveClientV1,
): EmailOtpEd25519YaoWorkerActivationResult {
  if (activeClient.status().kind !== 'active') {
    throw new Error('Email OTP Ed25519 Yao worker rejects disposed Client state');
  }
  if (emailOtpEd25519YaoActiveClients.size >= MAX_EMAIL_OTP_ED25519_YAO_ACTIVE_CLIENTS) {
    throw new Error('Email OTP Ed25519 Yao active Client capacity is exhausted');
  }
  const activeClientHandle = secureRandomId(
    'email-otp-ed25519-yao-active-client',
    32,
    'Email OTP Ed25519 Yao active Client handles',
  );
  const metadata = cloneEmailOtpEd25519YaoMetadata(activeClient.metadata());
  emailOtpEd25519YaoActiveClients.set(activeClientHandle, {
    kind: 'active_client',
    activeClient,
  });
  return { activeClientHandle, metadata };
}

function bytesToLowerHex(bytes: Uint8Array): string {
  let output = '';
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
  return output;
}

function safeEd25519YaoStateEpoch(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('Email OTP Ed25519 Yao export state epoch is invalid');
  }
  return value;
}

function sameEmailOtpEd25519YaoRuntimePolicyScope(
  left: ThresholdRuntimePolicyScope,
  right: ThresholdRuntimePolicyScope,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function assertEmailOtpEd25519YaoExportCapabilityContinuity(args: {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
}): void {
  if (!Number.isSafeInteger(args.signerSlot) || args.signerSlot < 1) {
    throw new Error('Email OTP Ed25519 Yao export signerSlot is invalid');
  }
  const capability = args.capability;
  const signingRoot = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  if (!signingRoot) {
    throw new Error('Email OTP Ed25519 Yao export runtime policy scope is invalid');
  }
  if (
    capability.nearAccountId !== args.nearAccountId ||
    capability.applicationBinding.wallet_id !== args.walletId ||
    capability.applicationBinding.near_ed25519_signing_key_id !== args.nearEd25519SigningKeyId ||
    capability.applicationBinding.key_creation_signer_slot !== args.signerSlot ||
    capability.applicationBinding.signing_root_id !== signingRoot.signingRootId ||
    capability.lifecycle.accountId !== args.walletId ||
    capability.lifecycle.rootShareEpoch !== args.runtimePolicyScope.signingRootVersion ||
    !sameEmailOtpEd25519YaoRuntimePolicyScope(
      capability.runtimePolicyScope,
      args.runtimePolicyScope,
    )
  ) {
    throw new Error('Email OTP Ed25519 Yao export capability changed the exact durable lane');
  }
  const nearAccountId = args.nearAccountId.trim().toLowerCase();
  if (
    /^[0-9a-f]{64}$/.test(nearAccountId) &&
    bytesToLowerHex(Uint8Array.from(capability.registeredPublicKey)) !== nearAccountId
  ) {
    throw new Error('Email OTP Ed25519 Yao export public key does not match the NEAR account');
  }
}

async function exportEmailOtpEd25519YaoSeed(args: {
  relayUrl: string;
  walletId: string;
  providerSubjectId: string;
  walletSessionJwt: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
  clientSecret32: Uint8Array;
}): Promise<RouterAbEd25519YaoExportArtifactV1> {
  assertEmailOtpEd25519YaoExportCapabilityContinuity(args);
  const capability = args.capability;
  const identity = {
    scope: {
      lifecycle_id: capability.lifecycle.lifecycleId,
      root_share_epoch: capability.lifecycle.rootShareEpoch,
      account_id: capability.lifecycle.accountId,
      threshold_session_id: capability.lifecycle.thresholdSessionId,
      signer_set_id: capability.lifecycle.signerSetId,
      signing_worker_id: capability.lifecycle.signingWorkerId,
      material_activation: routerAbMpcMaterialActivationRefToWire(
        capability.materialActivation,
      ),
    },
    application_binding: capability.applicationBinding,
    participant_ids: capability.participantIds,
    registered_public_key: [...capability.registeredPublicKey],
    state_epoch: safeEd25519YaoStateEpoch(capability.stateEpoch),
    runtime_policy_binding: await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
      args.runtimePolicyScope,
    ),
  };
  const issuedAtMs = Date.now();
  const expiresAtMs = issuedAtMs + EMAIL_OTP_ED25519_YAO_EXPORT_AUTH_TTL_MS;
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  try {
    const confirmationDigest = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
      identity,
      nonce: [...nonce],
      issuedAtMs,
      expiresAtMs,
    });
    const authorizationDigest = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
      identity,
      confirmationDigest,
      nonce: [...nonce],
      issuedAtMs,
      expiresAtMs,
      authority: {
        kind: 'email_otp',
        providerSubjectId: args.providerSubjectId,
      },
    });
    const request = parseRouterAbEd25519YaoExportAdmissionRequestV1({
      scope: identity.scope,
      application_binding: identity.application_binding,
      participant_ids: identity.participant_ids,
      registered_public_key: identity.registered_public_key,
      state_epoch: identity.state_epoch,
      runtime_policy_binding: identity.runtime_policy_binding,
      authorization: {
        confirmation_digest: confirmationDigest,
        authorization_digest: authorizationDigest,
        nonce: [...nonce],
        issued_at_ms: issuedAtMs,
        expires_at_ms: expiresAtMs,
      },
    });
    if (!request.ok) {
      throw new Error(`Invalid Email OTP Ed25519 Yao export admission: ${request.message}`);
    }
    const client = await getEmailOtpYaoClient();
    const result = await client.exportSeed({
      request: request.value,
      factor: { kind: 'email_otp_factor', ownedSecret32: args.clientSecret32 },
      authorization: {
        kind: 'email_otp_factor',
        providerSubjectId: args.providerSubjectId,
      },
      transport: new RouterAbEd25519YaoHttpActivationTransportV1({
        routerOrigin: new URL(args.relayUrl).origin,
        authorization: `Bearer ${args.walletSessionJwt}`,
        fetch: globalThis.fetch.bind(globalThis),
      }),
    });
    if (!result.ok) throw new Error(result.message);
    return result.artifact;
  } finally {
    nonce.fill(0);
  }
}

async function disposeEmailOtpEd25519YaoPendingRegistration(
  pendingHandle: string,
): Promise<boolean> {
  const entry = emailOtpEd25519YaoPendingRegistrations.get(pendingHandle);
  if (!entry) return false;
  emailOtpEd25519YaoPendingRegistrations.delete(pendingHandle);
  try {
    await entry.pending.dispose();
  } finally {
    zeroizeBytes(entry.factorSecret32);
  }
  return true;
}

async function storeEmailOtpEd25519YaoPendingRegistration(
  pending: ProductEd25519YaoPendingRegistrationPortV1,
  factorSecret32: Uint8Array,
): Promise<string> {
  if (factorSecret32.length !== 32) {
    zeroizeBytes(factorSecret32);
    await pending.dispose();
    throw new Error('Email OTP Ed25519 Yao factor must contain 32 bytes');
  }
  if (
    emailOtpEd25519YaoPendingRegistrations.size >= MAX_EMAIL_OTP_ED25519_YAO_PENDING_REGISTRATIONS
  ) {
    zeroizeBytes(factorSecret32);
    await pending.dispose();
    throw new Error('Email OTP Ed25519 Yao pending registration capacity is exhausted');
  }
  const pendingHandle = secureRandomId(
    'email-otp-ed25519-yao-pending-registration',
    32,
    'Email OTP Ed25519 Yao pending registration handles',
  );
  emailOtpEd25519YaoPendingRegistrations.set(pendingHandle, {
    kind: 'pending_registration',
    pending,
    factorSecret32,
  });
  return pendingHandle;
}

function issueEmailOtpEd25519YaoPendingFactor(args: {
  request: EmailOtpEd25519YaoFactorRequest;
  purpose: EmailOtpEd25519YaoRootScope['purpose'];
  walletId: string;
  ownedFactorSecret32?: Uint8Array;
}): EmailOtpEd25519YaoFactorResult {
  switch (args.request.kind) {
    case 'requested': {
      const ownedFactorSecret32 = args.ownedFactorSecret32;
      if (!(ownedFactorSecret32 instanceof Uint8Array)) {
        throw new Error('Email OTP enrollment did not return the requested Yao factor');
      }
      const nowMs = Date.now();
      return {
        kind: 'issued',
        pendingFactorHandle: emailOtpEd25519YaoRootVault.issuePendingOwned({
          purpose: args.purpose,
          walletId: args.walletId,
          providerSubject: args.request.providerSubject,
          ownedFactorSecret32,
          expiresAtMs: nowMs + EMAIL_OTP_ED25519_YAO_HANDLE_TTL_MS,
          nowMs,
        }),
      };
    }
    case 'not_requested':
      zeroizeBytes(args.ownedFactorSecret32);
      return { kind: 'not_requested' };
    default:
      return assertNeverEmailOtpWorker(args.request);
  }
}

function cloneEmailOtpEd25519YaoSigningShare(
  share: RouterAbEd25519YaoClientSigningShareV1,
): RouterAbEd25519YaoClientSigningShareV1 {
  return {
    clientCommitments: {
      hiding: share.clientCommitments.hiding,
      binding: share.clientCommitments.binding,
    },
    clientVerifyingShare: share.clientVerifyingShare.slice(),
    clientSignatureShareB64u: share.clientSignatureShareB64u,
  };
}

function rollbackEmailOtpEd25519YaoFactorResult(result: EmailOtpEd25519YaoFactorResult): void {
  switch (result.kind) {
    case 'issued':
      emailOtpEd25519YaoRootVault.removePending(result.pendingFactorHandle);
      return;
    case 'not_requested':
      return;
    default:
      return assertNeverEmailOtpWorker(result);
  }
}

function parseEmailOtpEcdsaWarmSessionRehydrateArgs(args: {
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    thresholdSessionId: string;
    walletId: string;
    keyHandle: string;
    chainTarget: ThresholdEcdsaChainTarget;
    authSubjectId: string;
  };
}): ParseEmailOtpEcdsaWarmSessionRehydrateArgsResult {
  const thresholdSessionId = normalizeOptionalTrimmedString(args.restore.thresholdSessionId);
  if (!thresholdSessionId) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing thresholdSessionId' },
    };
  }
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  if (!sealedSecretB64u) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing sealedSecretB64u' },
    };
  }
  const groupId = normalizeOptionalNonEmptyString(args.transport.groupId);
  if (!groupId) {
    return {
      kind: 'error',
      error: {
        ok: false,
        code: 'invalid_args',
        message: 'Missing groupId for signing-session restore',
      },
    };
  }
  const walletId = readString(args.restore.walletId, 'walletId');
  const keyHandle = readString(args.restore.keyHandle, 'keyHandle');
  return {
    kind: 'parsed',
    value: {
      sealedSecretB64u,
      remainingUses: Math.max(0, Math.floor(Number(args.remainingUses) || 0)),
      expiresAtMs: Math.max(0, Math.floor(Number(args.expiresAtMs) || 0)),
      transport: {
        relayerUrl: readString(args.transport.relayerUrl, 'relayerUrl'),
        ...(args.transport.walletSessionJwt
          ? { walletSessionJwt: args.transport.walletSessionJwt }
          : {}),
        ...(args.transport.keyVersion ? { keyVersion: args.transport.keyVersion } : {}),
        groupId,
      },
      restore: {
        thresholdSessionId,
        walletId,
        keyHandle,
        chainTarget: args.restore.chainTarget,
        authSubjectId: readString(args.restore.authSubjectId, 'authSubjectId'),
      },
    },
  };
}

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
  return requireTrimmedString(value, label);
}

function readSigningSessionSealGroupId(value: unknown): typeof SIGNING_SESSION_SEAL_GROUP_ID {
  if (readString(value, 'groupId') !== SIGNING_SESSION_SEAL_GROUP_ID) {
    throw new Error('Unsupported signing-session seal groupId');
  }
  return SIGNING_SESSION_SEAL_GROUP_ID;
}

function readThresholdEd25519SessionId(value: unknown, label: string): ThresholdEd25519SessionId {
  const parsed = parseThresholdEd25519SessionId(value);
  if (!parsed.ok) {
    throw new Error(`${label} is invalid`);
  }
  return parsed.value;
}

function requireNonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function readEvmFamilySigningKeySlotId(value: unknown, label: string) {
  return requireEvmFamilySigningKeySlotId(value, label);
}

function readNumber(value: unknown, label: string): number {
  const normalized = Number(value);
  if (!Number.isFinite(normalized)) {
    throw new Error(`${label} must be a finite number`);
  }
  return normalized;
}

function readOptionalString(value: unknown): string | undefined {
  return toOptionalTrimmedNonEmptyString(value);
}

function readRoutePlan(value: unknown, label: string): EmailOtpRoutePlan {
  const plan = normalizeEmailOtpRoutePlan(value);
  if (!plan) throw new Error(`${label} requires Email OTP routePlan`);
  return plan;
}

type EmailOtpEd25519SessionMaterialRequest = Extract<
  EmailOtpWalletUnlockMaterialRequest,
  {
    kind:
      | 'ed25519_yao_recovery'
      | 'wallet_unlock_capabilities';
  }
>;

function emailOtpEd25519SessionRequest(
  material: EmailOtpEd25519SessionMaterialRequest,
): EmailOtpEd25519YaoRecoveryAugmentationV1 {
  switch (material.kind) {
    case 'ed25519_yao_recovery':
      return material.ed25519YaoRecovery;
    case 'wallet_unlock_capabilities':
      return material.ed25519Yao.recovery;
    default:
      return assertNeverEmailOtpWorker(material);
  }
}

function emailOtpEd25519SessionIdentity(material: EmailOtpEd25519SessionMaterialRequest): {
  providerSubject: string;
  nearAccountId: string;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: string;
} {
  if (material.kind === 'wallet_unlock_capabilities') {
    return material.ed25519Yao;
  }
  return material;
}

function assertEmailOtpEd25519SessionMaterialIdentity(args: {
  walletId: string;
  material: EmailOtpEd25519SessionMaterialRequest;
}): void {
  const sessionRequest = emailOtpEd25519SessionRequest(args.material);
  const { providerSubject } = emailOtpEd25519SessionIdentity(args.material);
  if (!providerSubject.trim() || !sessionRequest.orgId.trim()) {
    throw new Error('Email OTP Ed25519 session requires its provider and organization identity');
  }
}

function assertEmailOtpUnlockMaterialRouteAuth(args: {
  walletId: string;
  routePlan: EmailOtpRoutePlan;
  material: EmailOtpWalletUnlockMaterialRequest;
}): void {
  const carriesEcdsaActivation =
    (args.material.kind === 'ecdsa' && Boolean(args.material.ecdsaSessionActivation)) ||
    args.material.kind === 'wallet_unlock_capabilities';
  if (carriesEcdsaActivation !== (args.routePlan.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION)) {
    throw new Error('Only Email OTP wallet unlock may carry first ECDSA session activation');
  }
  switch (args.material.kind) {
    case 'ecdsa':
      return;
    case 'wallet_unlock_capabilities':
      assertEmailOtpEd25519SessionMaterialIdentity({
        walletId: args.walletId,
        material: args.material,
      });
      if (
        args.material.ecdsa.clientRootHandleBinding.authSubjectId !==
          args.material.ed25519Yao.providerSubject ||
        args.material.ecdsa.runtimePolicyScope.orgId !== args.material.ed25519Yao.recovery.orgId
      ) {
        throw new Error('Email OTP capability unlock ECDSA and Ed25519 identities do not match');
      }
      return;
    case 'ed25519_yao_recovery': {
      assertEmailOtpEd25519SessionMaterialIdentity({
        walletId: args.walletId,
        material: args.material,
      });
      const routeAuth = authLaneToRouteAuth(args.routePlan.authLane);
      const usesAppSession =
        routeAuth?.kind === 'app_session' && args.routePlan.authLane.kind === 'app_session';
      const usesEd25519WalletSession =
        routeAuth?.kind === 'wallet_session' &&
        args.routePlan.authLane.kind === 'signing_session' &&
        args.routePlan.authLane.curve === 'ed25519';
      if (!usesAppSession && !usesEd25519WalletSession) {
        throw new Error('Email OTP Ed25519 session requires an authenticated route plan');
      }
      return;
    }
    default:
      return assertNeverEmailOtpWorker(args.material);
  }
}

function assertEmailOtpChallengeAction(args: {
  response: Record<string, unknown>;
  expectedAction: string;
  label: string;
}): void {
  const challenge =
    args.response.challenge &&
    typeof args.response.challenge === 'object' &&
    !Array.isArray(args.response.challenge)
      ? (args.response.challenge as Record<string, unknown>)
      : null;
  const action = normalizeOptionalTrimmedString(challenge?.action);
  if (action && action !== args.expectedAction) {
    throw new Error(`${args.label} returned ${action}; expected ${args.expectedAction}`);
  }
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  if (!relayerUrl) return null;
  const walletSessionJwt = normalizeOptionalNonEmptyString(transport.walletSessionJwt);
  const keyVersion = normalizeOptionalNonEmptyString(transport.signingSessionSealKeyVersion);
  const groupId = normalizeOptionalNonEmptyString(transport.groupId);
  return {
    relayerUrl,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(groupId ? { groupId } : {}),
  };
}

function parseSigningSessionSealRouteResult(value: unknown): SigningSessionSealRouteResult {
  const result = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
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
  if (!ciphertext) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Missing ciphertext in signing-session seal response',
    };
  }
  const keyVersion = normalizeOptionalNonEmptyString(result.keyVersion);
  const expiresAtMs = normalizePositiveInteger(result.expiresAtMs);
  const remainingUses = normalizeNonNegativeInteger(result.remainingUses);
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
  thresholdSessionId: string;
  materialIdentity: string;
  relayerUrl: string;
  keyVersion?: string;
  groupId?: string;
  payloadB64u?: string;
}): string {
  const operation =
    args.operation === 'remove-server-seal' ? 'remove-server-seal' : 'apply-server-seal';
  return [
    operation,
    normalizeOptionalTrimmedString(args.thresholdSessionId) || '',
    normalizeOptionalTrimmedString(args.materialIdentity) || '',
    normalizeOptionalTrimmedString(args.relayerUrl) || '',
    normalizeOptionalNonEmptyString(args.keyVersion) || '',
    normalizeOptionalNonEmptyString(args.groupId) || '',
    normalizeOptionalNonEmptyString(args.payloadB64u) || '',
  ].join('|');
}

async function callSigningSessionSealRoute(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  transport: SigningSessionSealTransport;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
}): Promise<SigningSessionSealRouteResult> {
  const operation =
    args.operation === 'remove-server-seal' ? 'remove-server-seal' : 'apply-server-seal';
  const url = joinNormalizedUrl(
    args.transport.relayerUrl,
    `${SIGNING_SESSION_SEAL_BASE_PATH}/${operation}`,
  );
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const walletSessionJwt = normalizeOptionalNonEmptyString(args.transport.walletSessionJwt);
    const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
    if (walletSessionJwt) headers.Authorization = `Bearer ${walletSessionJwt}`;
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
}):
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string } {
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
      message: 'Email OTP warm-session material exhausted',
    };
  }
  if (expiresAtMs <= Date.now()) {
    return {
      ok: false,
      code: 'expired',
      message: 'Email OTP warm-session material expired',
    };
  }
  return { ok: true, remainingUses, expiresAtMs };
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function deleteEmailOtpWarmSession(thresholdSessionId: string): void {
  const entry = emailOtpWarmSessions.get(thresholdSessionId);
  if (entry) {
    zeroizeBytes(entry.clientRootShare32);
    zeroizeBytes(entry.signingSessionSecret32);
    zeroizeBytes(entry.clientAdditiveShare32);
    emailOtpWarmSessions.delete(thresholdSessionId);
  }
}

function deleteEmailOtpEd25519YaoWarmFactor(
  materialActivation: MpcMaterialActivationRef,
): void {
  const activationKey = materialActivationKey(materialActivation);
  const entry = emailOtpEd25519YaoWarmFactors.get(activationKey);
  if (!entry) return;
  zeroizeBytes(entry.factorSecret32);
  emailOtpEd25519YaoWarmFactors.delete(activationKey);
}

function deleteEmailOtpWarmMaterial(target: EmailOtpWarmMaterialTarget): void {
  switch (target.kind) {
    case 'ecdsa':
      deleteEmailOtpWarmSession(target.thresholdSessionId);
      return;
    case 'ed25519_yao':
      deleteEmailOtpEd25519YaoWarmFactor(target.materialActivation);
      return;
  }
}

function putEmailOtpEd25519YaoWarmFactor(args: {
  target: Extract<EmailOtpWarmMaterialTarget, { kind: 'ed25519_yao' }>;
  factorSecret32: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
}): void {
  const thresholdSessionId = readString(
    args.target.thresholdSessionId,
    'target.thresholdSessionId',
  );
  const activationKey = materialActivationKey(args.target.materialActivation);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  if (args.factorSecret32.length !== 32) {
    throw new Error('Email OTP Ed25519 Yao factor must contain 32 bytes');
  }
  if (expiresAtMs <= Date.now() || remainingUses <= 0) {
    throw new Error('Invalid Email OTP Ed25519 Yao warm-factor policy');
  }
  deleteEmailOtpEd25519YaoWarmFactor(args.target.materialActivation);
  emailOtpEd25519YaoWarmFactors.set(activationKey, {
    kind: 'ed25519_yao_factor',
    thresholdSessionId,
    factorSecret32: Uint8Array.from(args.factorSecret32),
    materialActivation: args.target.materialActivation,
    expiresAtMs,
    remainingUses,
  });
}

function bindEmailOtpEd25519YaoCapabilityWarmFactor(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  factorSecret32: Uint8Array;
  materialActivation: MpcMaterialActivationRef;
}): void {
  putEmailOtpEd25519YaoWarmFactor({
    target: {
      kind: 'ed25519_yao',
      thresholdSessionId: args.bootstrap.session.thresholdSessionId,
      materialActivation: args.materialActivation,
    },
    factorSecret32: args.factorSecret32,
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
  });
}

function deleteEmailOtpEcdsaClientRootHandle(sessionId: string): void {
  const entry = emailOtpEcdsaClientRootHandles.get(sessionId);
  if (entry) {
    zeroizeBytes(entry.clientRootShare32);
    emailOtpEcdsaClientRootHandles.delete(sessionId);
  }
}

function expireEmailOtpEcdsaClientRootHandle(sessionId: string, expiresAtMs: number): void {
  const entry = emailOtpEcdsaClientRootHandles.get(sessionId);
  if (entry?.expiresAtMs === expiresAtMs && Date.now() >= entry.expiresAtMs) {
    deleteEmailOtpEcdsaClientRootHandle(sessionId);
  }
}

function scheduleEmailOtpEcdsaClientRootHandleExpiry(args: {
  sessionId: string;
  expiresAtMs: number;
}): void {
  const delayMs = Math.max(0, args.expiresAtMs - Date.now());
  setTimeout(expireEmailOtpEcdsaClientRootHandle, delayMs, args.sessionId, args.expiresAtMs);
}

function emailOtpEcdsaSessionHandleIdentityMatches(
  expected: EmailOtpEcdsaSessionBootstrapHandlePayload,
  actual: EmailOtpEcdsaSessionBootstrapHandlePayload,
): boolean {
  return expected.operation === actual.operation && expected.keyHandle === actual.keyHandle;
}

type EmailOtpEcdsaSessionHandleExpectedIdentity =
  {
    operation: Exclude<EmailOtpWorkerSessionHandleOperation, 'registration'>;
    keyHandle: string;
    evmFamilySigningKeySlotId?: never;
  };

function emailOtpEcdsaSessionHandleExpectedIdentity(
  handle: EmailOtpEcdsaSessionBootstrapHandlePayload,
): EmailOtpEcdsaSessionHandleExpectedIdentity {
  return {
    operation: handle.operation,
    keyHandle: handle.keyHandle,
  };
}

function disposeEmailOtpEcdsaClientRootHandle(
  handle: EmailOtpEcdsaSessionBootstrapHandlePayload,
): boolean {
  const sessionId = readString(handle.sessionId, 'clientRootShareHandle.sessionId');
  const entry = emailOtpEcdsaClientRootHandles.get(sessionId);
  if (!entry) return false;
  if (entry.handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP ECDSA client-root handle action mismatch');
  }
  if (
    !emailOtpEcdsaSessionHandleIdentityMatches(entry.handle, handle) ||
    entry.handle.walletId !== handle.walletId ||
    entry.handle.authSubjectId !== handle.authSubjectId ||
    !thresholdEcdsaChainTargetsEqual(entry.handle.chainTarget, handle.chainTarget)
  ) {
    throw new Error('Email OTP ECDSA client-root handle binding mismatch');
  }
  deleteEmailOtpEcdsaClientRootHandle(sessionId);
  return true;
}

function issueEmailOtpEcdsaClientRootHandle(args: {
  clientRootShare32: Uint8Array;
  walletId: string;
  binding: EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;
}): EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
function issueEmailOtpEcdsaClientRootHandle(args: {
  clientRootShare32: Uint8Array;
  walletId: string;
  binding: EmailOtpEcdsaSessionBootstrapHandleBinding;
}): EmailOtpEcdsaSessionBootstrapHandlePayload;
function issueEmailOtpEcdsaClientRootHandle(args: {
  clientRootShare32: Uint8Array;
  walletId: string;
  binding: EmailOtpEcdsaClientRootHandleBinding;
}): EmailOtpWorkerIssuedSessionHandlePayload {
  if (!(args.clientRootShare32 instanceof Uint8Array) || args.clientRootShare32.length !== 32) {
    throw new Error('Email OTP ECDSA client-root handle requires a 32-byte root share');
  }
  const sessionId = secureRandomId(
    'email-otp-ecdsa-root',
    32,
    'Email OTP ECDSA client-root handles',
  );
  const common = {
    kind: 'email_otp_worker_session_handle_v1' as const,
    sessionId,
    walletId: readString(args.walletId, 'walletId'),
    authSubjectId: readString(args.binding.authSubjectId, 'authSubjectId'),
  };
  let handle: EmailOtpWorkerIssuedSessionHandlePayload;
  if (args.binding.action === 'wallet_registration_ecdsa_prepare') {
    handle = {
      ...common,
      evmFamilySigningKeySlotId: String(
        readEvmFamilySigningKeySlotId(
          args.binding.evmFamilySigningKeySlotId,
          'evmFamilySigningKeySlotId',
        ),
      ),
      action: 'wallet_registration_ecdsa_prepare',
      operation: 'registration',
      keyScope: 'evm-family',
      chainTarget: args.binding.chainTarget,
    };
  } else {
    handle = {
      ...common,
      keyHandle: readString(args.binding.keyHandle, 'keyHandle'),
      action: 'threshold_ecdsa_bootstrap',
      operation: args.binding.operation,
      chainTarget: args.binding.chainTarget,
    };
  }
  const expiresAtMs = Date.now() + EMAIL_OTP_ECDSA_CLIENT_ROOT_HANDLE_TTL_MS;
  emailOtpEcdsaClientRootHandles.set(sessionId, {
    handle,
    clientRootShare32: Uint8Array.from(args.clientRootShare32),
    expiresAtMs,
  });
  scheduleEmailOtpEcdsaClientRootHandleExpiry({ sessionId, expiresAtMs });
  return handle;
}

function claimEmailOtpEcdsaClientRootShare(args: {
  handle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  walletId: string;
  expectedIdentity: EmailOtpEcdsaSessionHandleExpectedIdentity;
  authSubjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): Uint8Array {
  const handle = args.handle;
  if (handle.kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error('Email OTP ECDSA bootstrap received an unsupported worker handle');
  }
  if (handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP ECDSA bootstrap requires a threshold_ecdsa_bootstrap handle');
  }
  const sessionId = readString(handle.sessionId, 'clientRootShareHandle.sessionId');
  const entry = emailOtpEcdsaClientRootHandles.get(sessionId);
  if (!entry) {
    throw new Error('Email OTP ECDSA client-root handle expired or was already used');
  }
  try {
    if (Date.now() >= entry.expiresAtMs) {
      throw new Error('Email OTP ECDSA client-root handle expired');
    }
    if (entry.handle.walletId !== readString(args.walletId, 'walletId')) {
      throw new Error('Email OTP ECDSA client-root handle wallet mismatch');
    }
    if (entry.handle.action !== 'threshold_ecdsa_bootstrap') {
      throw new Error('Email OTP ECDSA client-root handle action mismatch');
    }
    if (entry.handle.keyHandle !== readString(args.expectedIdentity.keyHandle, 'keyHandle')) {
      throw new Error('Email OTP ECDSA client-root handle keyHandle mismatch');
    }
    if (entry.handle.authSubjectId !== readString(args.authSubjectId, 'authSubjectId')) {
      throw new Error('Email OTP ECDSA client-root handle subject mismatch');
    }
    if (
      entry.handle.operation !== handle.operation ||
      entry.handle.operation !== args.expectedIdentity.operation
    ) {
      throw new Error('Email OTP ECDSA client-root handle operation mismatch');
    }
    if (!thresholdEcdsaChainTargetsEqual(entry.handle.chainTarget, args.chainTarget)) {
      throw new Error('Email OTP ECDSA client-root handle chain target mismatch');
    }
    return Uint8Array.from(entry.clientRootShare32);
  } finally {
    deleteEmailOtpEcdsaClientRootHandle(sessionId);
  }
}

function claimEmailOtpWalletRegistrationEcdsaClientRootShare(args: {
  handle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  authSubjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): Uint8Array {
  const handle = args.handle;
  if (handle.kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare received an unsupported worker handle',
    );
  }
  if (handle.action !== 'wallet_registration_ecdsa_prepare') {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare requires a wallet_registration_ecdsa_prepare handle',
    );
  }
  const sessionId = readString(handle.sessionId, 'clientRootShareHandle.sessionId');
  const entry = emailOtpEcdsaClientRootHandles.get(sessionId);
  if (!entry) {
    throw new Error('Email OTP ECDSA client-root handle expired or was already used');
  }
  try {
    if (Date.now() >= entry.expiresAtMs) {
      throw new Error('Email OTP ECDSA client-root handle expired');
    }
    if (entry.handle.walletId !== readString(args.walletId, 'walletId')) {
      throw new Error('Email OTP ECDSA client-root handle wallet mismatch');
    }
    if (
      entry.handle.evmFamilySigningKeySlotId !==
      String(
        readEvmFamilySigningKeySlotId(args.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
      )
    ) {
      throw new Error('Email OTP ECDSA client-root handle evmFamilySigningKeySlotId mismatch');
    }
    if (entry.handle.authSubjectId !== readString(args.authSubjectId, 'authSubjectId')) {
      throw new Error('Email OTP ECDSA client-root handle subject mismatch');
    }
    if (entry.handle.action !== 'wallet_registration_ecdsa_prepare') {
      throw new Error('Email OTP ECDSA client-root handle action mismatch');
    }
    if (!thresholdEcdsaChainTargetsEqual(entry.handle.chainTarget, args.chainTarget)) {
      throw new Error('Email OTP ECDSA client-root handle chain target mismatch');
    }
    return Uint8Array.from(entry.clientRootShare32);
  } finally {
    deleteEmailOtpEcdsaClientRootHandle(sessionId);
  }
}

function requireEmailOtpEnrollmentClientRootShare32(args: {
  clientRootShare32: unknown;
  purpose: string;
}): Uint8Array {
  if (!(args.clientRootShare32 instanceof Uint8Array)) {
    throw new Error(`Email OTP enrollment did not return client root share for ${args.purpose}`);
  }
  return args.clientRootShare32;
}

function issueEmailOtpWalletRegistrationEcdsaHandleResult(args: {
  request: EmailOtpWalletRegistrationEcdsaPrepareHandleRequest;
  clientRootShare32: unknown;
  walletId: string;
}): EmailOtpWalletRegistrationEcdsaPrepareHandleResult {
  switch (args.request.kind) {
    case 'requested': {
      const clientRootShare32 = requireEmailOtpEnrollmentClientRootShare32({
        clientRootShare32: args.clientRootShare32,
        purpose: 'registration ECDSA bootstrap',
      });
      const handles: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload[] = [];
      for (const binding of args.request.bindings) {
        handles.push(
          issueEmailOtpEcdsaClientRootHandle({
            clientRootShare32,
            walletId: args.walletId,
            binding,
          }),
        );
      }
      const first = handles[0];
      if (!first) {
        throw new Error('Email OTP registration ECDSA handle request requires target bindings');
      }
      return {
        kind: 'available',
        handles: [
          first,
          ...handles.slice(1),
        ] satisfies EmailOtpWalletRegistrationEcdsaPrepareHandlePayloads,
      };
    }
    case 'not_requested':
      return { kind: 'not_requested' };
    default:
      return assertNeverEmailOtpWorker(args.request);
  }
}

function resolveEmailOtpWarmMaterialEntry(
  target: EmailOtpWarmMaterialTarget,
): EmailOtpWarmMaterialEntry | null {
  switch (target.kind) {
    case 'ecdsa': {
      const entry = emailOtpWarmSessions.get(target.thresholdSessionId);
      return entry ? { kind: 'ecdsa', entry } : null;
    }
    case 'ed25519_yao': {
      const entry = emailOtpEd25519YaoWarmFactors.get(
        materialActivationKey(target.materialActivation),
      );
      if (!entry || entry.thresholdSessionId !== target.thresholdSessionId) return null;
      if (!mpcMaterialActivationRefsEqual(entry.materialActivation, target.materialActivation)) {
        return null;
      }
      return { kind: 'ed25519_yao', entry };
    }
  }
}

function emailOtpWarmMaterialSecret32(entry: EmailOtpWarmMaterialEntry): Uint8Array {
  switch (entry.kind) {
    case 'ecdsa':
      return entry.entry.signingSessionSecret32;
    case 'ed25519_yao':
      return entry.entry.factorSecret32;
  }
}

function updateEmailOtpWarmMaterialPolicy(args: {
  target: EmailOtpWarmMaterialTarget;
  material: EmailOtpWarmMaterialEntry;
  remainingUses: number;
  expiresAtMs: number;
}): void {
  switch (args.material.kind) {
    case 'ecdsa':
      if (args.target.kind !== 'ecdsa') {
        throw new Error('Email OTP warm ECDSA material target mismatch');
      }
      emailOtpWarmSessions.set(args.target.thresholdSessionId, {
        clientRootShare32: args.material.entry.clientRootShare32,
        signingSessionSecret32: args.material.entry.signingSessionSecret32,
        ...(args.material.entry.clientAdditiveShare32
          ? { clientAdditiveShare32: args.material.entry.clientAdditiveShare32 }
          : {}),
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
      });
      return;
    case 'ed25519_yao':
      if (args.target.kind !== 'ed25519_yao') {
        throw new Error('Email OTP warm Ed25519 material target mismatch');
      }
      emailOtpEd25519YaoWarmFactors.set(materialActivationKey(args.target.materialActivation), {
        kind: 'ed25519_yao_factor',
        thresholdSessionId: args.material.entry.thresholdSessionId,
        factorSecret32: args.material.entry.factorSecret32,
        materialActivation: args.material.entry.materialActivation,
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
      });
      return;
  }
}

function readEmailOtpWarmSessionStatus(
  target: EmailOtpWarmMaterialTarget,
): EmailOtpWarmSessionStatusResult {
  const material = resolveEmailOtpWarmMaterialEntry(target);
  if (!material) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  if (Date.now() >= material.entry.expiresAtMs) {
    deleteEmailOtpWarmMaterial(target);
    return {
      ok: false,
      code: 'expired',
      message: 'Email OTP warm-session material expired',
    };
  }
  if (material.entry.remainingUses <= 0) {
    deleteEmailOtpWarmMaterial(target);
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  return {
    ok: true,
    remainingUses: material.entry.remainingUses,
    expiresAtMs: material.entry.expiresAtMs,
  };
}

function putEmailOtpWarmSessionMaterial(args: {
  thresholdSessionId: string;
  clientRootShare32: Uint8Array;
  signingSessionSecret32: Uint8Array;
  clientAdditiveShare32?: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
}): void {
  const thresholdSessionId = readString(args.thresholdSessionId, 'thresholdSessionId');
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  if (!(args.clientRootShare32 instanceof Uint8Array) || args.clientRootShare32.length !== 32) {
    throw new Error('clientRootShare32 must contain 32 bytes');
  }
  if (
    !(args.signingSessionSecret32 instanceof Uint8Array) ||
    args.signingSessionSecret32.length !== 32
  ) {
    throw new Error('signingSessionSecret32 must contain 32 bytes');
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
  deleteEmailOtpWarmSession(thresholdSessionId);
  emailOtpWarmSessions.set(thresholdSessionId, {
    clientRootShare32: Uint8Array.from(args.clientRootShare32),
    signingSessionSecret32: Uint8Array.from(args.signingSessionSecret32),
    ...(args.clientAdditiveShare32
      ? { clientAdditiveShare32: Uint8Array.from(args.clientAdditiveShare32) }
      : {}),
    expiresAtMs,
    remainingUses,
  });
}

function bindEmailOtpEcdsaWarmSessionFromWorkerHandle(args: {
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  thresholdSessionId: string;
  remainingUses: number;
  expiresAtMs: number;
}): EmailOtpWarmSessionStatusResult {
  const handle = args.clientRootShareHandle;
  let clientRootShare32: Uint8Array | null = null;
  try {
    clientRootShare32 = claimEmailOtpEcdsaClientRootShare({
      handle,
      walletId: handle.walletId,
      expectedIdentity: emailOtpEcdsaSessionHandleExpectedIdentity(handle),
      authSubjectId: handle.authSubjectId,
      chainTarget: handle.chainTarget,
    });
    putEmailOtpWarmSessionMaterial({
      thresholdSessionId: readString(args.thresholdSessionId, 'thresholdSessionId'),
      clientRootShare32,
      signingSessionSecret32: clientRootShare32,
      expiresAtMs: args.expiresAtMs,
      remainingUses: args.remainingUses,
    });
    return readEmailOtpWarmSessionStatus({
      kind: 'ecdsa',
      thresholdSessionId: args.thresholdSessionId,
    });
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'bind_failed',
      message:
        error instanceof Error
          ? error.message
          : String(error || 'Email OTP warm-session binding failed'),
    };
  } finally {
    zeroizeBytes(clientRootShare32);
  }
}

function consumeEmailOtpWarmSessionUses(args: {
  target: EmailOtpWarmMaterialTarget;
  uses?: number;
}): EmailOtpWarmSessionConsumeResult {
  const status = readEmailOtpWarmSessionStatus(args.target);
  if (!status.ok) return status;
  const material = resolveEmailOtpWarmMaterialEntry(args.target);
  if (!material) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  if (material.entry.remainingUses < uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Email OTP warm-session material exhausted',
    };
  }
  material.entry.remainingUses -= uses;
  const remainingUses = material.entry.remainingUses;
  const expiresAtMs = material.entry.expiresAtMs;
  if (remainingUses <= 0) {
    deleteEmailOtpWarmMaterial(args.target);
  } else {
    updateEmailOtpWarmMaterialPolicy({
      target: args.target,
      material,
      remainingUses,
      expiresAtMs,
    });
  }
  return {
    ok: true,
    remainingUses,
    expiresAtMs,
  };
}

async function sealEmailOtpWarmSessionMaterial(args: {
  target: EmailOtpWarmMaterialTarget;
  transport: SigningSessionSealTransport;
}): Promise<EmailOtpWarmSessionSealResult> {
  const thresholdSessionId = args.target.thresholdSessionId;
  const groupId = normalizeOptionalNonEmptyString(args.transport.groupId);
  if (!groupId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing groupId for signing-session seal',
    };
  }
  const status = readEmailOtpWarmSessionStatus(args.target);
  if (!status.ok) return status;
  const material = resolveEmailOtpWarmMaterialEntry(args.target);
  if (!material) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  const secret32 = emailOtpWarmMaterialSecret32(material);
  const payloadB64u = base64UrlEncode(secret32);
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'apply-server-seal',
    thresholdSessionId,
    materialIdentity:
      args.target.kind === 'ecdsa'
        ? args.target.thresholdSessionId
        : materialActivationKey(args.target.materialActivation),
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.transport.keyVersion,
    groupId,
    payloadB64u,
  });
  const inFlight = signingSessionSealApplyInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<EmailOtpWarmSessionSealResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealBytesWithKeyHandle({
          ciphertext: secret32,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId,
          ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
          keyVersion: args.transport.keyVersion,
        });
        if (!applied.ok) return applied;
        const sealedSecretB64u = await runtime.removeClientSealWithKeyHandle({
          ciphertextB64u: applied.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses: material.entry.remainingUses,
          localExpiresAtMs: material.entry.expiresAtMs,
          serverRemainingUses: applied.remainingUses,
          serverExpiresAtMs: applied.expiresAtMs,
        });
        if (!policy.ok) {
          deleteEmailOtpWarmMaterial(args.target);
          return policy;
        }
        updateEmailOtpWarmMaterialPolicy({
          target: args.target,
          material,
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        const keyVersion = normalizeOptionalNonEmptyString(applied.keyVersion);
        const common = {
          ok: true,
          sealedSecretB64u: readString(sealedSecretB64u, 'sealedSecretB64u'),
          ...(keyVersion ? { keyVersion } : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        } as const;
        switch (material.kind) {
          case 'ecdsa':
            return { ...common, materialKind: 'ecdsa' };
          case 'ed25519_yao':
            return {
              ...common,
              materialKind: 'ed25519_yao',
              materialActivation: material.entry.materialActivation,
            };
        }
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
          error instanceof Error
            ? error.message
            : String(error || 'Failed to apply signing-session seal'),
      };
    }
  })().finally(() => {
    signingSessionSealApplyInFlight.delete(singleFlightKey);
  });

  signingSessionSealApplyInFlight.set(singleFlightKey, task);
  return await task;
}

async function rehydrateEmailOtpEcdsaWarmSessionMaterial(args: {
  target: Extract<EmailOtpWarmMaterialTarget, { kind: 'ecdsa' }>;
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    thresholdSessionId: string;
    walletId: string;
    keyHandle: string;
    chainTarget: ThresholdEcdsaChainTarget;
    authSubjectId: string;
  };
}): Promise<EmailOtpEcdsaWarmSessionRehydrateResult> {
  if (args.target.thresholdSessionId !== args.restore.thresholdSessionId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Email OTP ECDSA restore target does not match the restored session',
    };
  }
  const parsed = parseEmailOtpEcdsaWarmSessionRehydrateArgs(args);
  if (parsed.kind === 'error') return parsed.error;
  const {
    sealedSecretB64u,
    remainingUses: localRemainingUses,
    expiresAtMs: localExpiresAtMs,
    transport,
    restore,
  } = parsed.value;
  const thresholdSessionId = restore.thresholdSessionId;
  if (localRemainingUses <= 0) {
    return { ok: false, code: 'exhausted', message: 'Email OTP signing-session seal exhausted' };
  }
  if (localExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'expired', message: 'Email OTP signing-session seal expired' };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'remove-server-seal',
    thresholdSessionId,
    materialIdentity: thresholdSessionId,
    relayerUrl: transport.relayerUrl,
    keyVersion: transport.keyVersion,
    groupId: transport.groupId,
    payloadB64u: sealedSecretB64u,
  });
  const inFlight = signingSessionSealRemoveInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<EmailOtpEcdsaWarmSessionRehydrateResult> => {
    let signingSessionSecret32: Uint8Array | null = null;
    let serverRemainingUses: number | undefined;
    let serverExpiresAtMs: number | undefined;
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: sealedSecretB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const removed = await callSigningSessionSealRoute({
          operation: 'remove-server-seal',
          transport,
          thresholdSessionId,
          ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
          keyVersion: transport.keyVersion,
        });
        if (!removed.ok) return removed;
        serverRemainingUses = removed.remainingUses;
        serverExpiresAtMs = removed.expiresAtMs;
        const unsealedSecret = await removeClientSealToSecret32({
          runtime,
          ciphertextB64u: removed.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
        if (unsealedSecret.kind === 'corrupt_local_custody') return unsealedSecret;
        signingSessionSecret32 = unsealedSecret.secret32;
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
      }

      const policy = resolvePolicyFromServerAndLocal({
        localRemainingUses,
        localExpiresAtMs,
        serverRemainingUses,
        serverExpiresAtMs,
      });
      if (!policy.ok) return policy;
      const clientRootShareHandle = issueEmailOtpEcdsaClientRootHandle({
        clientRootShare32: signingSessionSecret32,
        walletId: restore.walletId,
        binding: {
          action: 'threshold_ecdsa_bootstrap',
          operation: 'sign',
          keyHandle: restore.keyHandle,
          authSubjectId: restore.authSubjectId,
          chainTarget: restore.chainTarget,
        },
      });
      return {
        ok: true,
        clientRootShareHandle,
        remainingUses: policy.remainingUses,
        expiresAtMs: policy.expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error
            ? error.message
            : String(error || 'Failed to rehydrate Email OTP signing session'),
      };
    } finally {
      zeroizeBytes(signingSessionSecret32);
      signingSessionSealRemoveInFlight.delete(singleFlightKey);
    }
  })();

  signingSessionSealRemoveInFlight.set(singleFlightKey, task);
  return await task;
}

function buildEmailOtpEd25519YaoRecoveryBootstrap(args: {
  session: WalletRegistrationEd25519YaoBootstrapSession;
  material: EmailOtpEd25519YaoLocalMaterialV1;
  remainingUses: number;
  expiresAtMs: number;
}): EmailOtpEd25519YaoRecoveryBootstrapV1 {
  const binding = args.material.binding;
  const session = args.session;
  const capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1 = {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    activeCapabilityBinding: parseEmailOtpEd25519YaoJsonBytes32(
      Array.from(base64UrlDecode(binding.activeCapabilityBindingB64u)),
      'localMaterial.activeCapabilityBinding',
    ),
    registeredPublicKey: parseEmailOtpEd25519YaoJsonBytes32(
      Array.from(base64UrlDecode(binding.registeredPublicKeyB64u)),
      'localMaterial.registeredPublicKey',
    ),
    nearAccountId: binding.nearAccountId,
    applicationBinding: {
      wallet_id: binding.applicationBinding.walletId,
      near_ed25519_signing_key_id: binding.applicationBinding.nearEd25519SigningKeyId,
      signing_root_id: binding.applicationBinding.signingRootId,
      key_creation_signer_slot: binding.applicationBinding.keyCreationSignerSlot,
    },
    runtimePolicyScope: session.runtimePolicyScope,
    participantIds: binding.participantIds,
    materialActivation: binding.materialActivation,
    lifecycle: {
      lifecycleId: binding.lifecycleId,
      rootShareEpoch: binding.rootShareEpoch,
      accountId: binding.walletId,
      thresholdSessionId: readThresholdEd25519SessionId(
        session.thresholdSessionId,
        'session.thresholdSessionId',
      ),
      signerSetId: binding.signerSetId,
      signingWorkerId: binding.signingWorkerId,
    },
    stateEpoch: normalizePositiveInteger(Number(binding.stateEpoch)) ?? 0,
  };
  if (capability.stateEpoch < 1) {
    throw new Error('Email OTP Ed25519 local custody state epoch is invalid');
  }
  return {
    kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
    session: {
      sessionKind: 'jwt',
      walletSessionJwt: session.walletSessionJwt,
      walletId: session.walletId,
      nearAccountId: session.nearAccountId,
      nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
      authorityScope: session.authorityScope,
      thresholdSessionId: session.thresholdSessionId,
      walletSessionId: session.walletSessionId,
      quotaId: session.quotaId,
      expiresAtMs: args.expiresAtMs,
      participantIds: session.participantIds,
      remainingUses: args.remainingUses,
      signingRootId: session.signingRootId,
      signingRootVersion: session.signingRootVersion,
      runtimePolicyScope: session.runtimePolicyScope,
      routerAbNormalSigning: session.routerAbNormalSigning,
    },
    capability,
  };
}

async function rehydrateEmailOtpEd25519YaoLocalMaterial(args: {
  target: Extract<EmailOtpWarmMaterialTarget, { kind: 'ed25519_yao' }>;
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    session: WalletRegistrationEd25519YaoBootstrapSession;
    providerSubject: string;
    signerSlot: number;
    expectedOperationalPublicKey: string;
  };
}): Promise<EmailOtpEd25519YaoLocalMaterialRehydrateResult> {
  const session = args.restore.session;
  const thresholdSessionId = normalizeOptionalTrimmedString(session.thresholdSessionId);
  const walletId = normalizeOptionalTrimmedString(String(session.walletId));
  const providerSubject = normalizeOptionalTrimmedString(args.restore.providerSubject);
  const expectedOperationalPublicKey = normalizeOptionalTrimmedString(
    args.restore.expectedOperationalPublicKey,
  );
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  const groupId = normalizeOptionalNonEmptyString(args.transport.groupId);
  const walletSessionJwt = normalizeOptionalNonEmptyString(args.transport.walletSessionJwt);
  if (
    !thresholdSessionId ||
    !walletId ||
    !providerSubject ||
    !expectedOperationalPublicKey ||
    !sealedSecretB64u ||
    !groupId ||
    !walletSessionJwt ||
    session.authorityScope.kind !== 'email_otp' ||
    session.authorityScope.providerUserId !== providerSubject ||
    session.walletSessionJwt !== walletSessionJwt
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Email OTP Ed25519 exact-local restore requires exact session identity',
    };
  }
  if (args.target.thresholdSessionId !== thresholdSessionId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Email OTP Ed25519 restore target does not match the restored session',
    };
  }
  const localRemainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const localExpiresAtMs = Math.max(0, Math.floor(Number(args.expiresAtMs) || 0));
  if (localRemainingUses <= 0) {
    return { ok: false, code: 'exhausted', message: 'Email OTP signing-session seal exhausted' };
  }
  if (localExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'expired', message: 'Email OTP signing-session seal expired' };
  }

  const localMaterial = await readEmailOtpEd25519YaoLocalMaterialByLocatorV1({
    store: IndexedDBManager,
    walletId,
    nearAccountId: session.nearAccountId,
    signerSlot: args.restore.signerSlot,
    providerSubjectId: providerSubject,
    expectedOperationalPublicKey,
  });
  if (localMaterial.kind === 'material_absent') {
    return {
      ok: false,
      code: 'local_material_unavailable',
      message: 'Email OTP Ed25519 exact local material is unavailable',
    };
  }
  if (localMaterial.kind === 'material_invalid') {
    return {
      ok: false,
      code: 'local_material_invalid',
      message: `Email OTP Ed25519 local custody is invalid: ${localMaterial.code}`,
    };
  }

  let factorSecret32: Uint8Array | null = null;
  let importedClient: EmailOtpEd25519YaoWorkerActivationResult | null = null;
  try {
    const runtime = await getShamir3PassRuntime();
    const clientKeyHandle = await runtime.createClientKeyHandle({
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    });
    let serverRemainingUses: number | undefined;
    let serverExpiresAtMs: number | undefined;
    try {
      const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
        ciphertextB64u: sealedSecretB64u,
        keyHandle: clientKeyHandle.keyHandle,
      });
      const removed = await callSigningSessionSealRoute({
        operation: 'remove-server-seal',
        transport: args.transport,
        thresholdSessionId,
        ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
        keyVersion: args.transport.keyVersion,
      });
      if (!removed.ok) return removed;
      serverRemainingUses = removed.remainingUses;
      serverExpiresAtMs = removed.expiresAtMs;
      const unsealedSecret = await removeClientSealToSecret32({
        runtime,
        ciphertextB64u: removed.ciphertext,
        keyHandle: clientKeyHandle.keyHandle,
      });
      if (unsealedSecret.kind === 'corrupt_local_custody') return unsealedSecret;
      factorSecret32 = unsealedSecret.secret32;
    } finally {
      await runtime
        .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
        .catch(() => undefined);
    }
    const policy = resolvePolicyFromServerAndLocal({
      localRemainingUses,
      localExpiresAtMs,
      serverRemainingUses,
      serverExpiresAtMs,
    });
    if (!policy.ok) return policy;
    const bootstrap = buildEmailOtpEd25519YaoRecoveryBootstrap({
      session,
      material: localMaterial.material,
      remainingUses: policy.remainingUses,
      expiresAtMs: policy.expiresAtMs,
    });
    importedClient = await importEmailOtpEd25519YaoLocalMaterial({
      material: localMaterial.material,
      expectedThresholdSessionId: thresholdSessionId,
      enrollmentSecret32: factorSecret32,
    });
    assertEmailOtpEd25519YaoCapabilityContinuity({
      material: localMaterial.material,
      bootstrap,
      expectedThresholdSessionId: thresholdSessionId,
    });
    const restoredMaterialActivation = nearEd25519YaoMaterialActivationFromMetadata(
      importedClient.metadata,
    );
    if (
      !mpcMaterialActivationRefsEqual(
        restoredMaterialActivation,
        args.target.materialActivation,
      )
    ) {
      return {
        ok: false,
        code: 'material_activation_mismatch',
        message: 'Email OTP Ed25519 restored material activation does not match the target',
      };
    }
    bindEmailOtpEd25519YaoCapabilityWarmFactor({
      bootstrap,
      factorSecret32,
      materialActivation: restoredMaterialActivation,
    });
    const activated = importedClient;
    importedClient = null;
    return {
      ok: true,
      activeClientHandle: activated.activeClientHandle,
      metadata: activated.metadata,
      ed25519YaoCapability: bootstrap,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message:
        error instanceof Error
          ? error.message
          : String(error || 'Yao local material restore failed'),
    };
  } finally {
    if (importedClient) {
      removeEmailOtpEd25519YaoActiveClient(importedClient.activeClientHandle);
    }
    zeroizeBytes(factorSecret32);
  }
}

async function readEmailOtpEd25519YaoOperationMaterial(args: {
  walletId: string;
  nearAccountId: string;
  signerSlot: number;
  providerSubjectId: string;
  expectedOperationalPublicKey: string;
}): Promise<EmailOtpEd25519YaoLocalMaterialV1> {
  const resolved = await readEmailOtpEd25519YaoLocalMaterialByLocatorV1({
    store: IndexedDBManager,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    signerSlot: args.signerSlot,
    providerSubjectId: args.providerSubjectId,
    expectedOperationalPublicKey: args.expectedOperationalPublicKey,
  });
  switch (resolved.kind) {
    case 'exact_material_ready':
      return resolved.material;
    case 'material_absent':
      throw new Error('Email OTP Ed25519 operation material is unavailable on this device');
    case 'material_invalid':
      throw new Error(`Email OTP Ed25519 local custody is invalid: ${resolved.code}`);
    default:
      return assertNeverEmailOtpWorker(resolved);
  }
}

async function readEmailOtpEd25519YaoOperationEnrollment(args: {
  material: EmailOtpEd25519YaoLocalMaterialV1;
  walletId: string;
  providerSubjectId: string;
}): Promise<EmailOtpDeviceEnrollmentEscrowRecord> {
  const binding = args.material.binding;
  const enrollment = await readEmailOtpDeviceEnrollmentEscrowRecord({
    walletId: args.walletId,
    authSubjectId: args.providerSubjectId,
    enrollmentId: binding.enrollmentId,
  });
  if (
    !enrollment ||
    enrollment.walletId !== args.walletId ||
    enrollment.authSubjectId !== args.providerSubjectId ||
    enrollment.enrollmentId !== binding.enrollmentId ||
    enrollment.enrollmentVersion !== binding.enrollmentVersion ||
    enrollment.enrollmentSealKeyVersion !== binding.enrollmentSealKeyVersion ||
    enrollment.signingRootId !== binding.signingRootId ||
    enrollment.signingRootVersion !== binding.signingRootVersion ||
    enrollment.groupId !== SIGNING_SESSION_SEAL_GROUP_ID
  ) {
    throw new Error('Email OTP device enrollment escrow does not match operation material');
  }
  return enrollment;
}

function assertEmailOtpEd25519YaoOperationMaterialContinuity(args: {
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  walletId: string;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: ThresholdEd25519SessionId;
  expectedMaterialActivation: MpcMaterialActivationRef;
}): void {
  const activation = nearEd25519YaoMaterialActivationFromMetadata(args.metadata);
  if (
    args.metadata.scope.threshold_session_id !== String(args.expectedThresholdSessionId) ||
    args.metadata.applicationBinding.wallet_id !== args.walletId ||
    args.metadata.applicationBinding.key_creation_signer_slot !== args.signerSlot ||
    `ed25519:${base58Encode(args.metadata.registeredPublicKey)}` !==
      args.expectedOperationalPublicKey ||
    !mpcMaterialActivationRefsEqual(activation, args.expectedMaterialActivation)
  ) {
    throw new Error('Email OTP operation recovery activated different signing material');
  }
}

async function destroyEmailOtpOperationRecoveryKeyHandle(args: {
  runtime: Awaited<ReturnType<typeof getShamir3PassRuntime>>;
  keyHandle: string;
}): Promise<void> {
  try {
    await args.runtime.destroyClientKeyHandle({ keyHandle: args.keyHandle });
  } catch {
    return;
  }
}

async function rehydrateEmailOtpEd25519YaoOperationMaterial(
  args: EmailOtpWorkerOperationMap['rehydrateEmailOtpEd25519YaoOperationMaterial']['payload'],
): Promise<EmailOtpWorkerOperationMap['rehydrateEmailOtpEd25519YaoOperationMaterial']['result']> {
  const walletId = readString(args.walletId, 'walletId');
  const nearAccountId = readString(args.nearAccountId, 'nearAccountId');
  const providerSubjectId = readString(args.providerSubjectId, 'providerSubjectId');
  const expectedOperationalPublicKey = readString(
    args.expectedOperationalPublicKey,
    'expectedOperationalPublicKey',
  );
  const signerSlot = normalizePositiveInteger(args.signerSlot);
  if (signerSlot === null) {
    throw new Error('signerSlot must be a positive safe integer');
  }
  const material = await readEmailOtpEd25519YaoOperationMaterial({
    walletId,
    nearAccountId,
    signerSlot,
    providerSubjectId,
    expectedOperationalPublicKey,
  });
  const enrollment = await readEmailOtpEd25519YaoOperationEnrollment({
    material,
    walletId,
    providerSubjectId,
  });

  const runtime = await getShamir3PassRuntime();
  let keyHandle: string | null = null;
  let enrollmentSecret32: Uint8Array | null = null;
  let importedClient: EmailOtpEd25519YaoWorkerActivationResult | null = null;
  try {
    const clientKey = await runtime.createClientKeyHandle({
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    });
    keyHandle = clientKey.keyHandle;
    const wrappedCiphertext = await runtime.addClientSealWithKeyHandle({
      ciphertextB64u: readString(enrollment.encSB64u, 'enrollment.encSB64u'),
      keyHandle,
    });
    const issuedAuthorization = await issueEd25519OperationStepUpAuthorization({
      relayerUrl: readString(args.relayUrl, 'relayUrl'),
      normalSigningRequest: args.normalSigningRequest,
      displayDigest: readString(args.displayDigest, 'displayDigest'),
      proof: args.proof,
      credential: { kind: 'app_session_cookie' },
      materialRecovery: {
        kind: 'email_otp_local_material_v1',
        wrappedCiphertext: readString(wrappedCiphertext, 'wrappedCiphertext'),
        enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
      },
    });
    if (issuedAuthorization.materialRecovery.kind !== 'email_otp_local_material_v1') {
      throw new Error('Email OTP operation step-up did not return recovered material');
    }
    const unsealed = await removeClientSealToSecret32({
      runtime,
      keyHandle,
      ciphertextB64u: issuedAuthorization.materialRecovery.ciphertext,
    });
    if (unsealed.kind !== 'secret32') {
      throw emailOtpCorruptLocalCustodyError(unsealed);
    }
    enrollmentSecret32 = unsealed.secret32;
    importedClient = await importEmailOtpEd25519YaoLocalMaterial({
      material,
      expectedThresholdSessionId: String(args.expectedThresholdSessionId),
      enrollmentSecret32,
    });
    assertEmailOtpEd25519YaoOperationMaterialContinuity({
      metadata: importedClient.metadata,
      walletId,
      signerSlot,
      expectedOperationalPublicKey,
      expectedThresholdSessionId: args.expectedThresholdSessionId,
      expectedMaterialActivation: args.expectedMaterialActivation,
    });
    const activeClient = importedClient;
    importedClient = null;
    return {
      activeClientHandle: activeClient.activeClientHandle,
      metadata: activeClient.metadata,
      issuedAuthorization: {
        kind: issuedAuthorization.kind,
        authorization: issuedAuthorization.authorization,
        expiresAtMs: issuedAuthorization.expiresAtMs,
      },
    };
  } finally {
    if (importedClient) {
      removeEmailOtpEd25519YaoActiveClient(importedClient.activeClientHandle);
    }
    zeroizeBytes(enrollmentSecret32);
    if (keyHandle) {
      await destroyEmailOtpOperationRecoveryKeyHandle({ runtime, keyHandle });
    }
  }
}

function claimEmailOtpEcdsaSigningShare(
  thresholdSessionIdRaw: unknown,
): EmailOtpEcdsaSigningShareClaimResult {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  const status = readEmailOtpWarmSessionStatus({
    kind: 'ecdsa',
    thresholdSessionId,
  });
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(thresholdSessionId);
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
    deleteEmailOtpWarmSession(thresholdSessionId);
  } else {
    emailOtpWarmSessions.set(thresholdSessionId, entry);
  }
  return {
    ok: true,
    clientSigningShare32: clientSigningShare32.buffer,
    remainingUses,
    expiresAtMs,
  };
}

let ecdsaPresignPort: MessagePort | null = null;

function handleEmailOtpEcdsaSigningShareRequest(
  event: MessageEvent<EmailOtpEcdsaSigningShareRequest>,
): void {
  if (!ecdsaPresignPort) return;
  const request = event.data;
  if (request.kind !== 'email_otp_ecdsa_signing_share_request_v1') return;
  const result = claimEmailOtpEcdsaSigningShare(request.thresholdSessionId);
  if (!result.ok) {
    const failure: EmailOtpEcdsaSigningShareResponse = {
      kind: 'email_otp_ecdsa_signing_share_result_v1',
      requestId: request.requestId,
      ok: false,
      error: result.message || result.code,
    };
    ecdsaPresignPort.postMessage(failure);
    return;
  }
  const success: EmailOtpEcdsaSigningShareResponse = {
    kind: 'email_otp_ecdsa_signing_share_result_v1',
    requestId: request.requestId,
    ok: true,
    additiveShare32: result.clientSigningShare32,
    remainingUses: result.remainingUses,
    expiresAtMs: result.expiresAtMs,
  };
  ecdsaPresignPort.postMessage(success, [result.clientSigningShare32]);
}

function attachEcdsaPresignChannel(value: unknown): boolean {
  if (!isAttachEmailOtpToPresignPort(value)) return false;
  ecdsaPresignPort?.close();
  ecdsaPresignPort = value.port;
  ecdsaPresignPort.onmessage = handleEmailOtpEcdsaSigningShareRequest;
  ecdsaPresignPort.start();
  return true;
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

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', toArrayBufferCopy(input));
  return new Uint8Array(digest);
}

const evmCryptoWasmUrl = resolveWasmUrl('evm_crypto.wasm', 'Email OTP');
const emailOtpRuntimeWasmUrl = resolveWasmUrl('email_otp_runtime_bg.wasm', 'Email OTP Runtime');
const nearSignerRecoveryWasmUrl = resolveWasmUrl(
  'wasm_signer_worker_bg.wasm',
  'Email OTP Recovery Wrap',
);
let evmCryptoInitPromise: Promise<void> | null = null;
let emailOtpRuntimeInitPromise: Promise<void> | null = null;
let nearSignerRecoveryInitPromise: Promise<void> | null = null;
let emailOtpYaoClientInitPromise: Promise<RouterAbEd25519YaoClientV1> | null = null;

function resetEmailOtpYaoClientInitOnFailure(error: unknown): never {
  emailOtpYaoClientInitPromise = null;
  throw error;
}

function getEmailOtpYaoClient(): Promise<RouterAbEd25519YaoClientV1> {
  if (!emailOtpYaoClientInitPromise) {
    emailOtpYaoClientInitPromise = RouterAbEd25519YaoClientV1.initializeBundled().catch(
      resetEmailOtpYaoClientInitOnFailure,
    );
  }
  return emailOtpYaoClientInitPromise;
}

async function ensureEvmCryptoWasm(): Promise<void> {
  if (evmCryptoInitPromise) return evmCryptoInitPromise;
  evmCryptoInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP',
      wasmUrl: evmCryptoWasmUrl,
      initFunction: initEvmCrypto as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_evm_crypto(),
    });
  })();
  return evmCryptoInitPromise;
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

async function ensureNearSignerRecoveryWasm(): Promise<void> {
  if (nearSignerRecoveryInitPromise) return nearSignerRecoveryInitPromise;
  nearSignerRecoveryInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP Recovery Wrap',
      wasmUrl: nearSignerRecoveryWasmUrl,
      initFunction: initNearSignerRecoveryWasm as unknown as (
        wasmModule?: unknown,
      ) => Promise<void>,
      validateFunction: () => init_near_signer_recovery_worker(),
    });
  })();
  return nearSignerRecoveryInitPromise;
}

async function createEmailOtpRecoveryWrappedEnrollmentEscrows(args: {
  walletId: string;
  userId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  encSB64u: string;
}): Promise<{
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowPayload[];
}> {
  await ensureNearSignerRecoveryWasm();
  const recoveryKeys = generateEmailOtpRecoveryKeySet();
  const encS = base64UrlDecode(args.encSB64u);
  const issuedAtMs = Date.now();
  const recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowPayload[] = [];
  try {
    for (let index = 0; index < recoveryKeys.length; index += 1) {
      const keyIdBinding: EmailOtpRecoveryKeyIdBinding = {
        auth: {
          walletId: args.walletId,
          userId: args.userId,
          authSubjectId: args.userId,
          authMethod: 'google_sso_email_otp',
        },
        enrollment: {
          enrollmentId: args.enrollmentId,
          enrollmentVersion: args.enrollmentVersion,
          enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
        },
        signingRoot: {
          signingRootId: args.signingRootId,
          signingRootVersion: args.signingRootVersion,
        },
      };
      const recoveryKeyId = await deriveEmailOtpRecoveryKeyId({
        recoveryKey: recoveryKeys[index],
        binding: keyIdBinding,
      });
      const binding = buildEmailOtpRecoveryWrapBinding({
        walletId: args.walletId,
        userId: args.userId,
        authSubjectId: args.userId,
        authMethod: 'google_sso_email_otp',
        enrollmentId: args.enrollmentId,
        enrollmentVersion: args.enrollmentVersion,
        enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
        signingRootId: args.signingRootId,
        signingRootVersion: args.signingRootVersion,
        recoveryKeyId,
      });
      const wrapped = await wrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey: recoveryKeys[index],
        binding,
        encS,
        chacha20poly1305: {
          encrypt: async (input) =>
            email_recovery_chacha20poly1305_encrypt(
              input.key32,
              input.nonce12,
              input.aad,
              input.plaintext,
            ),
          decrypt: async () => {
            throw new Error('Email OTP enrollment recovery wrapping does not decrypt');
          },
        },
      });
      const aad = encodeEmailOtpRecoveryWrappedEnrollmentAad(binding);
      try {
        recoveryWrappedEnrollmentEscrows.push({
          version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
          alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
          secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
          escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
          walletId: args.walletId,
          userId: args.userId,
          authSubjectId: args.userId,
          authMethod: 'google_sso_email_otp',
          enrollmentId: args.enrollmentId,
          enrollmentVersion: args.enrollmentVersion,
          enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
          signingRootId: args.signingRootId,
          signingRootVersion: args.signingRootVersion,
          recoveryKeyId,
          recoveryKeyStatus: 'active',
          nonceB64u: base64UrlEncode(wrapped.nonce12),
          wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(wrapped.ciphertext),
          aadHashB64u: base64UrlEncode(await sha256Bytes(aad)),
          issuedAtMs,
          updatedAtMs: issuedAtMs,
        });
      } finally {
        zeroizeBytes(aad);
      }
    }
    return { recoveryKeys, recoveryCodesIssuedAtMs: issuedAtMs, recoveryWrappedEnrollmentEscrows };
  } finally {
    zeroizeBytes(encS);
  }
}

async function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload(
  value: unknown,
  recoveryKey: string,
): Promise<ParsedEmailOtpRecoveryWrappedEnrollmentEscrowPayload | null> {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  if (
    'recoveryKeyId' in obj ||
    'recoveryKeyStatus' in obj ||
    'issuedAtMs' in obj ||
    'updatedAtMs' in obj ||
    'consumedAtMs' in obj ||
    'revokedAtMs' in obj
  ) {
    return null;
  }
  const baseRecord = {
    version: readString(
      obj.version,
      'recoveryWrappedEnrollmentEscrow.version',
    ) as 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: readString(
      obj.alg,
      'recoveryWrappedEnrollmentEscrow.alg',
    ) as typeof EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: readString(
      obj.secretKind,
      'recoveryWrappedEnrollmentEscrow.secretKind',
    ) as typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: readString(
      obj.escrowKind,
      'recoveryWrappedEnrollmentEscrow.escrowKind',
    ) as typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId: readString(obj.walletId, 'recoveryWrappedEnrollmentEscrow.walletId'),
    userId: readString(obj.userId, 'recoveryWrappedEnrollmentEscrow.userId'),
    authSubjectId: readString(obj.authSubjectId, 'recoveryWrappedEnrollmentEscrow.authSubjectId'),
    authMethod: readString(
      obj.authMethod,
      'recoveryWrappedEnrollmentEscrow.authMethod',
    ) as 'google_sso_email_otp',
    enrollmentId: readString(obj.enrollmentId, 'recoveryWrappedEnrollmentEscrow.enrollmentId'),
    enrollmentVersion: readString(
      obj.enrollmentVersion,
      'recoveryWrappedEnrollmentEscrow.enrollmentVersion',
    ),
    enrollmentSealKeyVersion: readString(
      obj.enrollmentSealKeyVersion,
      'recoveryWrappedEnrollmentEscrow.enrollmentSealKeyVersion',
    ),
    signingRootId: readString(obj.signingRootId, 'recoveryWrappedEnrollmentEscrow.signingRootId'),
    signingRootVersion: readString(
      obj.signingRootVersion,
      'recoveryWrappedEnrollmentEscrow.signingRootVersion',
    ),
    nonceB64u: readString(obj.nonceB64u, 'recoveryWrappedEnrollmentEscrow.nonceB64u'),
    wrappedDeviceEnrollmentEscrowB64u: readString(
      obj.wrappedDeviceEnrollmentEscrowB64u,
      'recoveryWrappedEnrollmentEscrow.wrappedDeviceEnrollmentEscrowB64u',
    ),
    aadHashB64u: readString(obj.aadHashB64u, 'recoveryWrappedEnrollmentEscrow.aadHashB64u'),
  };
  if (baseRecord.version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1') return null;
  if (baseRecord.alg !== EMAIL_OTP_RECOVERY_WRAP_ALG) return null;
  if (baseRecord.secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND) return null;
  if (baseRecord.escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND) return null;
  if (baseRecord.authMethod !== 'google_sso_email_otp') return null;
  if ('acknowledgedAtMs' in obj || 'abandonedAtMs' in obj || 'cleanupReason' in obj) return null;
  const keyIdBinding: EmailOtpRecoveryKeyIdBinding = {
    auth: {
      walletId: baseRecord.walletId,
      userId: baseRecord.userId,
      authSubjectId: baseRecord.authSubjectId,
      authMethod: baseRecord.authMethod,
    },
    enrollment: {
      enrollmentId: baseRecord.enrollmentId,
      enrollmentVersion: baseRecord.enrollmentVersion,
      enrollmentSealKeyVersion: baseRecord.enrollmentSealKeyVersion,
    },
    signingRoot: {
      signingRootId: baseRecord.signingRootId,
      signingRootVersion: baseRecord.signingRootVersion,
    },
  };
  const recoveryKeyId = await deriveEmailOtpRecoveryKeyId({
    recoveryKey,
    binding: keyIdBinding,
  });
  const record: EmailOtpRecoveryChallengeEscrowPayload = {
    ...baseRecord,
    recoveryKeyId,
  };
  return {
    payload: record,
    binding: buildEmailOtpRecoveryWrapBinding({
      walletId: record.walletId,
      userId: record.userId,
      authSubjectId: record.authSubjectId,
      authMethod: record.authMethod,
      enrollmentId: record.enrollmentId,
      enrollmentVersion: record.enrollmentVersion,
      enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      recoveryKeyId: record.recoveryKeyId,
    }),
    lifecycle: {
      status: 'active',
    },
  };
}

async function writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord(
  record: Parameters<typeof writeEmailOtpDeviceEnrollmentEscrowRecord>[0],
  errorMessage: string,
): Promise<void> {
  await writeEmailOtpDeviceEnrollmentEscrowRecord(record);
  const persisted = await readEmailOtpDeviceEnrollmentEscrowRecord({
    walletId: record.walletId,
    authSubjectId: record.authSubjectId,
    enrollmentId: record.enrollmentId,
  });
  if (
    !persisted ||
    persisted.encSB64u !== record.encSB64u ||
    persisted.enrollmentSealKeyVersion !== record.enrollmentSealKeyVersion ||
    persisted.signingRootId !== record.signingRootId ||
    persisted.signingRootVersion !== record.signingRootVersion
  ) {
    throw new Error(errorMessage);
  }
}

async function reportEmailOtpRecoveryKeyAttemptFailure(args: {
  relayUrl: string;
  routeAuth: AppOrWalletSessionAuth | undefined;
  walletId: string;
  recoveryConsumeGrant: string;
}): Promise<void> {
  await postEmailOtpJson({
    relayUrl: args.relayUrl,
    route: '/wallet/email-otp/recovery-key/attempt-failed',
    ...(args.routeAuth ? { sessionAuth: args.routeAuth } : {}),
    body: {
      walletId: args.walletId,
      recoveryConsumeGrant: args.recoveryConsumeGrant,
    },
  });
}

async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey(args: {
  relayUrl: string;
  walletId: string;
  userId?: unknown;
  challengeId: string;
  otpCode: string;
  recoveryKey: string;
  groupId: string;
  routePlan: EmailOtpRoutePlan;
}): Promise<{
  walletId: string;
  userId: string;
  authSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  recoveryKeyId: string;
  activeRecoveryWrappedEnrollmentEscrowCount: number;
}> {
  await ensureNearSignerRecoveryWasm();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const requestedUserId = resolveEmailOtpAuthSubjectId({
    walletId,
    userId: args.userId,
    routePlan: args.routePlan,
  });
  const routeAuth = authLaneToRouteAuth(args.routePlan.authLane);
  const response = await postEmailOtpJson({
    relayUrl,
    route: '/wallet/email-otp/recovery-wrapped-escrows',
    ...(routeAuth ? { sessionAuth: routeAuth } : {}),
    body: {
      walletId,
      challengeId: readString(args.challengeId, 'challengeId'),
      otpCode: readString(args.otpCode, 'otpCode'),
      otpChannel: EMAIL_OTP_CHANNEL,
    },
  });
  const rawRecords = Array.isArray(response.recoveryWrappedEnrollmentEscrows)
    ? response.recoveryWrappedEnrollmentEscrows
    : [];
  const recoveryConsumeGrant = readString(response.recoveryConsumeGrant, 'recoveryConsumeGrant');
  const recoveryKey = readString(args.recoveryKey, 'recoveryKey');
  const records: ParsedEmailOtpRecoveryWrappedEnrollmentEscrowPayload[] = [];
  for (const rawRecord of rawRecords) {
    const parsed = await parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload(
      rawRecord,
      recoveryKey,
    );
    if (parsed) records.push(parsed);
  }
  if (records.length <= 0) {
    throw new Error('No active Email OTP recovery-wrapped enrollment escrows are available');
  }

  let sawRecoveryKeyUnwrapFailure = false;
  for (const parsed of records) {
    const { payload: record, binding } = parsed;
    if (record.walletId !== walletId) continue;
    if (requestedUserId && record.userId !== requestedUserId) continue;
    const aad = encodeEmailOtpRecoveryWrappedEnrollmentAad(binding);
    let encS: Uint8Array | null = null;
    try {
      const aadHashB64u = base64UrlEncode(await sha256Bytes(aad));
      if (aadHashB64u !== record.aadHashB64u) continue;
      encS = await unwrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey,
        binding,
        wrapped: {
          alg: record.alg,
          nonce12: base64UrlDecode(record.nonceB64u),
          ciphertext: base64UrlDecode(record.wrappedDeviceEnrollmentEscrowB64u),
        },
        chacha20poly1305: {
          encrypt: async () => {
            throw new Error('Email OTP enrollment recovery restore does not encrypt');
          },
          decrypt: async (input) =>
            email_recovery_chacha20poly1305_decrypt(
              input.key32,
              input.nonce12,
              input.aad,
              input.ciphertext,
            ),
        },
      });
      await writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord(
        {
          walletId: record.walletId,
          userId: record.userId,
          authSubjectId: record.authSubjectId,
          enrollmentId: record.enrollmentId,
          enrollmentVersion: record.enrollmentVersion,
          enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
          signingRootId: record.signingRootId,
          signingRootVersion: record.signingRootVersion,
          groupId: readSigningSessionSealGroupId(args.groupId),
          encSB64u: base64UrlEncode(encS),
          issuedAtMs: Date.now(),
          updatedAtMs: Date.now(),
        },
        'Email OTP recovery did not persist device-local enc_s(S)',
      );
      const consumeResponse = await postEmailOtpJson({
        relayUrl,
        route: '/wallet/email-otp/recovery-key/consume',
        ...(routeAuth ? { sessionAuth: routeAuth } : {}),
        body: {
          walletId,
          recoveryKeyId: record.recoveryKeyId,
          recoveryConsumeGrant,
        },
      });
      const activeRecoveryWrappedEnrollmentEscrowCount = Number(
        consumeResponse.activeRecoveryWrappedEnrollmentEscrowCount,
      );
      return {
        walletId: record.walletId,
        userId: record.userId,
        authSubjectId: record.authSubjectId,
        enrollmentId: record.enrollmentId,
        enrollmentVersion: record.enrollmentVersion,
        enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
        recoveryKeyId: record.recoveryKeyId,
        activeRecoveryWrappedEnrollmentEscrowCount: Number.isFinite(
          activeRecoveryWrappedEnrollmentEscrowCount,
        )
          ? activeRecoveryWrappedEnrollmentEscrowCount
          : records.length - 1,
      };
    } catch {
      if (encS) throw new Error('Email OTP recovery restore failed after successful unwrap');
      sawRecoveryKeyUnwrapFailure = true;
      continue;
    } finally {
      zeroizeBytes(aad);
      zeroizeBytes(encS);
    }
  }

  if (sawRecoveryKeyUnwrapFailure) {
    await reportEmailOtpRecoveryKeyAttemptFailure({
      relayUrl,
      routeAuth,
      walletId,
      recoveryConsumeGrant,
    });
  }
  throw new Error('Email OTP recovery unwrap failed');
}

async function rotateEmailOtpRecoveryCodesFromLocalDeviceEnrollment(args: {
  relayUrl: string;
  walletId: string;
  userId?: unknown;
  routePlan: EmailOtpRoutePlan;
}): Promise<{
  walletId: string;
  userId: string;
  authSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  activeRecoveryCodeCount: number;
  revokedRecoveryCodeCount: number;
  totalRecoveryCodeCount: number;
}> {
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const routePlan = readRoutePlan(args.routePlan, 'rotateEmailOtpRecoveryCodes');
  const routeAuth = authLaneToRouteAuth(routePlan.authLane);
  const authSubjectId = resolveEmailOtpAuthSubjectId({
    walletId,
    userId: args.userId,
    routePlan,
  });
  const record = await readEmailOtpDeviceEnrollmentEscrowRecord({
    walletId,
    authSubjectId,
    enrollmentId: emailOtpDeviceEnrollmentId(walletId, authSubjectId),
  });
  if (!record) {
    throw new Error('Email OTP device enrollment escrow is unavailable on this device');
  }
  const localUserId = readOptionalString(record.userId) || record.authSubjectId;
  if (record.authSubjectId !== authSubjectId) {
    throw new Error('Email OTP device enrollment escrow does not match the requested user');
  }

  const { recoveryKeys, recoveryWrappedEnrollmentEscrows } =
    await createEmailOtpRecoveryWrappedEnrollmentEscrows({
      walletId: record.walletId,
      userId: record.authSubjectId,
      enrollmentId: record.enrollmentId,
      enrollmentVersion: record.enrollmentVersion,
      enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      encSB64u: record.encSB64u,
    });
  const response = await postEmailOtpJson({
    relayUrl,
    route: '/wallet/email-otp/recovery-key/rotate',
    ...(routeAuth ? { sessionAuth: routeAuth } : {}),
    body: {
      walletId: record.walletId,
      enrollmentId: record.enrollmentId,
      enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
      recoveryWrappedEnrollmentEscrows: recoveryWrappedEnrollmentEscrows.map((escrow) => ({
        recoveryKeyId: escrow.recoveryKeyId,
        nonceB64u: escrow.nonceB64u,
        wrappedDeviceEnrollmentEscrowB64u: escrow.wrappedDeviceEnrollmentEscrowB64u,
        aadHashB64u: escrow.aadHashB64u,
      })),
    },
  });
  const recoveryCodesIssuedAtMs = Math.floor(Number(response.issuedAtMs));
  if (!Number.isFinite(recoveryCodesIssuedAtMs) || recoveryCodesIssuedAtMs <= 0) {
    throw new Error('Email OTP recovery-code rotation response did not include issuedAtMs');
  }
  return {
    walletId: record.walletId,
    userId: localUserId,
    authSubjectId,
    enrollmentId: record.enrollmentId,
    enrollmentVersion: record.enrollmentVersion,
    enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
    recoveryKeys,
    recoveryCodesIssuedAtMs,
    activeRecoveryCodeCount: Math.floor(Number(response.activeRecoveryCodeCount)),
    revokedRecoveryCodeCount: Math.floor(Number(response.revokedRecoveryCodeCount)),
    totalRecoveryCodeCount: Math.floor(Number(response.totalRecoveryCodeCount)),
  };
}

async function removeEmailOtpDeviceEnrollmentEscrowFromDevice(args: {
  walletId: string;
  userId: unknown;
  enrollmentId?: unknown;
}): Promise<{
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
  removed: true;
}> {
  const walletId = readString(args.walletId, 'walletId');
  const authSubjectId = readString(args.userId, 'userId');
  const enrollmentId =
    readOptionalString(args.enrollmentId) || emailOtpDeviceEnrollmentId(walletId, authSubjectId);
  await deleteEmailOtpDeviceEnrollmentEscrowRecord({
    walletId,
    authSubjectId,
    enrollmentId,
  });
  return {
    walletId,
    authSubjectId,
    enrollmentId,
    removed: true,
  };
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
  return secureRandomId('tecdsa-keygen', 32, 'Email OTP worker keygen session IDs');
}

async function removeClientSealToSecret32(args: {
  runtime: Awaited<ReturnType<typeof getShamir3PassRuntime>>;
  keyHandle: string;
  ciphertextB64u: string;
}): Promise<EmailOtpEscrowSecret32DecodeResult> {
  const plaintext = await args.runtime.removeClientSealWithKeyHandleToBytes({
    ciphertextB64u: args.ciphertextB64u,
    keyHandle: args.keyHandle,
  });
  try {
    return decodeEmailOtpEscrowSecret32(plaintext);
  } finally {
    zeroizeBytes(plaintext);
  }
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

type EmailOtpUnlockCompletionMaterial =
  | {
      kind: 'ecdsa';
      clientRootShare32: Uint8Array;
      ecdsaSession?: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
    }
  | { kind: 'ed25519_yao_export' }
  | {
      kind: 'ed25519_yao_recovery';
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'ed25519_yao_capability';
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      ed25519YaoCapability: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'wallet_unlock_capabilities';
      ecdsa: {
        clientRootShare32: Uint8Array;
        session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
      };
      ed25519Yao:
        | {
            kind: 'recovery';
            bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
          }
        | {
            kind: 'capability';
            activeClientHandle: string;
            metadata: RouterAbEd25519YaoActiveClientMetadataV1;
            bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
          };
    };

type EmailOtpUnlockSecretMaterialRequest =
  | Extract<EmailOtpWalletUnlockMaterialRequest, { kind: 'ecdsa' }>
  | { kind: 'ed25519_yao_export' }
  | Extract<
      EmailOtpWalletUnlockMaterialRequest,
      {
        kind:
          | 'ed25519_yao_recovery'
          | 'wallet_unlock_capabilities';
      }
    >;

function requireEmailOtpWorkerEcdsaSessionResponse(
  value: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | undefined,
): RouterAbEcdsaPostRegistrationSessionActivationResponseV1 {
  if (!value) throw new Error('Email OTP unlock did not return its first ECDSA Wallet Session');
  return value;
}

type EmailOtpEd25519YaoLocalMaterialSelection =
  | { kind: 'not_requested' }
  | { kind: 'exact_local_material'; material: EmailOtpEd25519YaoLocalMaterialV1 }
  | { kind: 'material_absent' };

async function resolveEmailOtpEd25519YaoLocalMaterial(args: {
  walletId: string;
  material: EmailOtpUnlockSecretMaterialRequest;
}): Promise<EmailOtpEd25519YaoLocalMaterialSelection> {
  const material = args.material;
  switch (material.kind) {
    case 'ecdsa':
    case 'ed25519_yao_export':
      return { kind: 'not_requested' };
    case 'ed25519_yao_recovery':
    case 'wallet_unlock_capabilities': {
      const sessionRequest = emailOtpEd25519SessionRequest(material);
      const identity = emailOtpEd25519SessionIdentity(material);
      const resolved = await readEmailOtpEd25519YaoLocalMaterialByLocatorV1({
        store: IndexedDBManager,
        walletId: args.walletId,
        nearAccountId: identity.nearAccountId,
        signerSlot: sessionRequest.signerSlot,
        providerSubjectId: identity.providerSubject,
        expectedOperationalPublicKey: identity.expectedOperationalPublicKey,
      });
      if (resolved.kind === 'material_invalid') {
        throw new Error(`Email OTP Ed25519 local custody is invalid: ${resolved.code}`);
      }
      if (resolved.kind === 'material_absent') {
        return resolved;
      }
      return { kind: 'exact_local_material', material: resolved.material };
    }
    default:
      return assertNeverEmailOtpWorker(material);
  }
}

type EmailOtpRequestedCapabilities =
  | {
      kind: 'none';
    }
  | {
      kind: 'ed25519_yao';
      signerSlot: number;
      remainingUses: number;
    };

function buildEmailOtpRequestedCapabilities(args: {
  material: EmailOtpUnlockSecretMaterialRequest;
  localMaterial: EmailOtpEd25519YaoLocalMaterialSelection;
}): EmailOtpRequestedCapabilities {
  switch (args.localMaterial.kind) {
    case 'not_requested':
      return { kind: 'none' };
    case 'exact_local_material': {
      const material = args.material;
      if (material.kind !== 'ed25519_yao_recovery' && material.kind !== 'wallet_unlock_capabilities') {
        throw new Error('Email OTP Ed25519 local material selection changed request branch');
      }
      const request = emailOtpEd25519SessionRequest(material);
      return {
        kind: 'ed25519_yao',
        signerSlot: request.signerSlot,
        remainingUses: request.remainingUses,
      };
    }
    case 'material_absent': {
      const material = args.material;
      if (material.kind !== 'ed25519_yao_recovery' && material.kind !== 'wallet_unlock_capabilities') {
        throw new Error('Email OTP Ed25519 recovery requires its requested capability');
      }
      return {
        kind: 'ed25519_yao',
        signerSlot: emailOtpEd25519SessionRequest(material).signerSlot,
        remainingUses: emailOtpEd25519SessionRequest(material).remainingUses,
      };
    }
    default:
      return assertNeverEmailOtpWorker(args.localMaterial);
  }
}

function emailOtpEd25519WalletSessionJwtForUnlockMaterial(
  material: EmailOtpUnlockSecretMaterialRequest,
): string | undefined {
  if (material.kind !== 'ecdsa' || material.ecdsaSessionActivation === undefined) {
    return undefined;
  }
  const authorization = material.walletSessionAuthorization;
  if (authorization.kind === 'reuse_ed25519_wallet_session') {
    return authorization.walletSessionJwt;
  }
  return undefined;
}

function metadataFromEmailOtpEd25519YaoLocalMaterial(args: {
  material: EmailOtpEd25519YaoLocalMaterialV1;
  expectedThresholdSessionId: string;
}): RouterAbEd25519YaoActiveClientMetadataV1 {
  const binding = args.material.binding;
  return {
    kind: 'router_ab_ed25519_yao_active_client_v1',
    scope: {
      lifecycle_id: binding.lifecycleId,
      root_share_epoch: binding.rootShareEpoch,
      account_id: binding.walletId,
      threshold_session_id: readString(args.expectedThresholdSessionId, 'expectedThresholdSessionId'),
      signer_set_id: binding.signerSetId,
      signing_worker_id: binding.signingWorkerId,
      material_activation: {
        kind: binding.materialActivation.kind,
        activation_id: binding.materialActivation.activationId,
        capability: binding.materialActivation.capability,
        material_owner: binding.materialActivation.materialOwner,
        key_binding: binding.materialActivation.keyBinding,
        lifecycle_binding: binding.materialActivation.lifecycleBinding,
        signing_worker: binding.materialActivation.signingWorker,
      },
    },
    applicationBinding: {
      wallet_id: binding.applicationBinding.walletId,
      near_ed25519_signing_key_id: binding.applicationBinding.nearEd25519SigningKeyId,
      signing_root_id: binding.applicationBinding.signingRootId,
      key_creation_signer_slot: binding.applicationBinding.keyCreationSignerSlot,
    },
    participantIds: binding.participantIds,
    materialActivation: binding.materialActivation,
    registeredPublicKey: base64UrlDecode(binding.registeredPublicKeyB64u),
    signingWorkerVerifyingShare: base64UrlDecode(binding.signingWorkerVerifyingShareB64u),
    stateEpoch: BigInt(binding.stateEpoch),
    transcript: base64UrlDecode(binding.activationTranscriptB64u),
    activeCapabilityBinding: parseEmailOtpEd25519YaoJsonBytes32(
      Array.from(base64UrlDecode(binding.activeCapabilityBindingB64u)),
      'localMaterial.activeCapabilityBinding',
    ),
  };
}

function assertEmailOtpEd25519YaoCapabilityContinuity(args: {
  material: EmailOtpEd25519YaoLocalMaterialV1;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  expectedThresholdSessionId: string;
}): void {
  const binding = args.material.binding;
  const session = args.bootstrap.session;
  const capability = args.bootstrap.capability;
  if (
    String(session.walletId) !== binding.walletId ||
    session.nearAccountId !== binding.nearAccountId ||
    session.nearEd25519SigningKeyId !== binding.nearEd25519SigningKeyId ||
    session.signingRootId !== binding.signingRootId ||
    session.signingRootVersion !== binding.signingRootVersion ||
    session.thresholdSessionId !== args.expectedThresholdSessionId ||
    session.authorityScope.kind !== 'email_otp' ||
    session.authorityScope.providerUserId !== binding.providerSubjectId ||
    session.routerAbNormalSigning.signingWorkerId !== binding.signingWorkerId ||
    capability.lifecycle.lifecycleId !== binding.lifecycleId ||
    capability.lifecycle.rootShareEpoch !== binding.rootShareEpoch ||
    capability.lifecycle.thresholdSessionId !== session.thresholdSessionId ||
    capability.lifecycle.signerSetId !== binding.signerSetId ||
    capability.lifecycle.signingWorkerId !== binding.signingWorkerId ||
    capability.stateEpoch.toString(10) !== binding.stateEpoch ||
    base64UrlEncode(Uint8Array.from(capability.registeredPublicKey)) !==
      binding.registeredPublicKeyB64u ||
    base64UrlEncode(Uint8Array.from(capability.activeCapabilityBinding)) !==
      binding.activeCapabilityBindingB64u
  ) {
    throw new Error('Email OTP Ed25519 local custody does not match the registered capability');
  }
}

async function importEmailOtpEd25519YaoLocalMaterial(args: {
  material: EmailOtpEd25519YaoLocalMaterialV1;
  expectedThresholdSessionId: string;
  enrollmentSecret32: Uint8Array;
}): Promise<EmailOtpEd25519YaoWorkerActivationResult> {
  const metadata = metadataFromEmailOtpEd25519YaoLocalMaterial(args);
  const client = await getEmailOtpYaoClient();
  const activeClient = client.importEmailOtpLocalMaterial({
    ownedEnrollmentSecret32: args.enrollmentSecret32.slice(),
    binding: encodeEmailOtpEd25519YaoStableCustodyBindingV1(args.material.binding),
    sealed: {
      kind: 'router_ab_ed25519_yao_email_otp_sealed_local_material_v1',
      nonce: base64UrlDecode(args.material.envelope.nonceB64u),
      ciphertext: base64UrlDecode(args.material.envelope.ciphertextB64u),
    },
    metadata,
  });
  try {
    return storeEmailOtpEd25519YaoActiveClient(activeClient);
  } catch (error) {
    activeClient.dispose();
    throw error;
  }
}

async function completeEmailOtpUnlockFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  orgId?: string;
  userId: string;
  clientSecret32: Uint8Array;
  material: EmailOtpUnlockSecretMaterialRequest;
  sessionAuth: AppOrWalletSessionAuth;
}): Promise<
  {
    unlockChallengeId: string;
    unlockChallengeB64u: string;
    clientUnlockPublicKeyB64u: string;
    unlockSignatureB64u: string;
  } & EmailOtpUnlockCompletionMaterial
> {
  await ensureEvmCryptoWasm();
  const walletId = readString(args.walletId, 'walletId');
  const userId = readString(args.userId, 'userId');
  const localEd25519Material = await resolveEmailOtpEd25519YaoLocalMaterial({
    walletId,
    material: args.material,
  });
  const challenge = await postEmailOtpJson({
    relayUrl: readString(args.relayUrl, 'relayUrl'),
    route: '/wallet/unlock/challenge',
    body: {
      unlockBackend: 'email_otp',
      walletId,
      ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
    },
  });
  const unlockChallengeId = readString(challenge.challengeId, 'challengeId');
  const unlockChallengeB64u = readString(challenge.challengeB64u, 'challengeB64u');
  const challengeDigest32: Uint8Array | null = base64UrlDecode(unlockChallengeB64u);
  if (challengeDigest32.length !== 32) {
    zeroizeBytes(challengeDigest32);
    throw new Error('wallet/unlock/challenge challengeB64u must decode to 32 bytes');
  }

  let unlockPrivateKey32: Uint8Array | null = null;
  let clientRootShare32: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  let unlockSignature65: Uint8Array | null = null;
  let importedEd25519Client: EmailOtpEd25519YaoWorkerActivationResult | null = null;
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

    const clientUnlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const unlockSignatureB64u = base64UrlEncode(unlockSignature65);

    if (localEd25519Material.kind === 'exact_local_material') {
      if (
        args.material.kind !== 'ed25519_yao_recovery' &&
        args.material.kind !== 'wallet_unlock_capabilities'
      ) {
        throw new Error('Email OTP Ed25519 local material selection changed request branch');
      }
      importedEd25519Client = await importEmailOtpEd25519YaoLocalMaterial({
        material: localEd25519Material.material,
        expectedThresholdSessionId:
          emailOtpEd25519SessionIdentity(args.material).expectedThresholdSessionId,
        enrollmentSecret32: args.clientSecret32,
      });
    }

    if (args.material.kind === 'ecdsa' || args.material.kind === 'wallet_unlock_capabilities') {
      clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
        clientSecret32: args.clientSecret32,
        walletId,
        userId,
      });
      if (clientRootShare32.length !== 32) {
        throw new Error('Email OTP ECDSA client-root share must contain exactly 32 bytes');
      }
    }

    const requestedCapabilities = buildEmailOtpRequestedCapabilities({
      material: args.material,
      localMaterial: localEd25519Material,
    });
    const verified = await postEmailOtpJson({
      relayUrl: readString(args.relayUrl, 'relayUrl'),
      route: '/wallet/unlock/verify',
      sessionAuth: args.sessionAuth,
      body: {
        unlockBackend: 'email_otp',
        walletId,
        ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: clientUnlockPublicKeyB64u,
          signature: unlockSignatureB64u,
        },
        ...(args.material.kind === 'ecdsa' && args.material.ecdsaSessionActivation
          ? { ecdsaSessionActivation: args.material.ecdsaSessionActivation }
          : args.material.kind === 'wallet_unlock_capabilities'
            ? { ecdsaSessionActivation: args.material.ecdsa.sessionActivation }
            : {}),
        ...(emailOtpEd25519WalletSessionJwtForUnlockMaterial(args.material)
          ? {
              ed25519WalletSessionJwt: emailOtpEd25519WalletSessionJwtForUnlockMaterial(
                args.material,
              ),
            }
          : {}),
        requestedCapabilities,
      },
    });
    const ecdsaSession =
      args.material.kind === 'ecdsa' && !args.material.ecdsaSessionActivation
        ? undefined
        : args.material.kind === 'ecdsa' || args.material.kind === 'wallet_unlock_capabilities'
          ? parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(verified.ecdsaSession)
          : undefined;
    const commonResult = {
      unlockChallengeId,
      unlockChallengeB64u,
      clientUnlockPublicKeyB64u,
      unlockSignatureB64u,
    };
    switch (args.material.kind) {
      case 'ecdsa': {
        if (!clientRootShare32) {
          throw new Error('Email OTP ECDSA client-root share was not prepared');
        }
        const ownedClientRootShare32 = clientRootShare32;
        clientRootShare32 = null;
        return {
          kind: 'ecdsa',
          ...commonResult,
          clientRootShare32: ownedClientRootShare32,
          ...(ecdsaSession ? { ecdsaSession } : {}),
        };
      }
      case 'ed25519_yao_export':
        return { kind: 'ed25519_yao_export', ...commonResult };
      case 'wallet_unlock_capabilities': {
        if (!clientRootShare32) {
          throw new Error('Email OTP capability unlock ECDSA client-root share was not prepared');
        }
        const ownedClientRootShare32 = clientRootShare32;
        if (localEd25519Material.kind === 'exact_local_material') {
          const ed25519YaoCapability = parseEmailOtpEd25519YaoRecoveryBootstrap(
            verified.ed25519YaoCapability,
          );
          assertEmailOtpEd25519YaoCapabilityContinuity({
            material: localEd25519Material.material,
            bootstrap: ed25519YaoCapability,
            expectedThresholdSessionId: args.material.ed25519Yao.expectedThresholdSessionId,
          });
          if (!importedEd25519Client) {
            throw new Error('Email OTP Ed25519 local client was not imported');
          }
          bindEmailOtpEd25519YaoCapabilityWarmFactor({
            bootstrap: ed25519YaoCapability,
            factorSecret32: args.clientSecret32,
            materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
              importedEd25519Client.metadata,
            ),
          });
          const imported = importedEd25519Client;
          importedEd25519Client = null;
          clientRootShare32 = null;
          return {
            kind: 'wallet_unlock_capabilities',
            ...commonResult,
            ecdsa: {
              clientRootShare32: ownedClientRootShare32,
              session: requireEmailOtpWorkerEcdsaSessionResponse(ecdsaSession),
            },
            ed25519Yao: {
              kind: 'capability',
              activeClientHandle: imported.activeClientHandle,
              metadata: imported.metadata,
              bootstrap: ed25519YaoCapability,
            },
          };
        }
        if (localEd25519Material.kind !== 'material_absent') {
          throw new Error('Email OTP Ed25519 local material selection changed request branch');
        }
        clientRootShare32 = null;
        return {
          kind: 'wallet_unlock_capabilities',
          ...commonResult,
          ecdsa: {
            clientRootShare32: ownedClientRootShare32,
            session: requireEmailOtpWorkerEcdsaSessionResponse(ecdsaSession),
          },
          ed25519Yao: {
            kind: 'recovery',
            bootstrap: parseEmailOtpEd25519YaoRecoveryBootstrap(verified.ed25519YaoCapability),
          },
        };
      }
      case 'ed25519_yao_recovery':
        if (localEd25519Material.kind === 'exact_local_material') {
          const ed25519YaoCapability = parseEmailOtpEd25519YaoRecoveryBootstrap(
            verified.ed25519YaoCapability,
          );
          assertEmailOtpEd25519YaoCapabilityContinuity({
            material: localEd25519Material.material,
            bootstrap: ed25519YaoCapability,
            expectedThresholdSessionId: args.material.expectedThresholdSessionId,
          });
          if (!importedEd25519Client) {
            throw new Error('Email OTP Ed25519 local client was not imported');
          }
          bindEmailOtpEd25519YaoCapabilityWarmFactor({
            bootstrap: ed25519YaoCapability,
            factorSecret32: args.clientSecret32,
            materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
              importedEd25519Client.metadata,
            ),
          });
          const imported = importedEd25519Client;
          importedEd25519Client = null;
          return {
            kind: 'ed25519_yao_capability',
            ...commonResult,
            activeClientHandle: imported.activeClientHandle,
            metadata: imported.metadata,
            ed25519YaoCapability,
          };
        }
        if (localEd25519Material.kind !== 'material_absent') {
          throw new Error('Email OTP Ed25519 local material selection changed request branch');
        }
        return {
          kind: 'ed25519_yao_recovery',
          ...commonResult,
          ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryBootstrap(verified.ed25519YaoCapability),
        };
      default:
        return assertNeverEmailOtpWorker(args.material);
    }
  } finally {
    if (importedEd25519Client) {
      removeEmailOtpEd25519YaoActiveClient(importedEd25519Client.activeClientHandle);
    }
    zeroizeBytes(challengeDigest32);
    zeroizeBytes(clientRootShare32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(unlockPublicKey33);
    zeroizeBytes(unlockSignature65);
  }
}

async function completeEmailOtpEnrollmentFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
  challengeId?: string;
  otpCode?: string;
  groupId: string;
  routePlan: EmailOtpRoutePlan;
  clientSecret32?: Uint8Array;
  returnClientRootShare32?: boolean;
  returnClientSecret32?: boolean;
  skipServerFinalize?: boolean;
  googleEmailOtpRegistrationAttemptId?: string;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<{
  thresholdEcdsaClientVerifyingShareB64u: string;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  emailOtpEnrollment: {
    recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowPayload[];
    enrollmentSealKeyVersion: string;
    clientUnlockPublicKeyB64u: string;
    unlockKeyVersion: string;
    thresholdEcdsaClientVerifyingShareB64u: string;
  };
  clientRootShare32?: Uint8Array;
  clientSecret32?: Uint8Array;
}> {
  await ensureEvmCryptoWasm();
  const runtime = await getShamir3PassRuntime();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const userId = resolveEmailOtpAuthSubjectId({
    walletId,
    userId: args.userId,
    routePlan: args.routePlan,
  });
  const groupId = readSigningSessionSealGroupId(args.groupId);
  const otpCode = args.skipServerFinalize ? '' : readString(args.otpCode, 'otpCode');
  const keyHandle = readString(
    (await runtime.createClientKeyHandle({ groupId: SIGNING_SESSION_SEAL_GROUP_ID })).keyHandle,
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
    const sessionAuth = authLaneToRouteAuth(args.routePlan.authLane);
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId && !args.skipServerFinalize) {
      const challenge = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'challenge'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      });
      assertEmailOtpChallengeAction({
        response: challenge,
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        label: 'Email OTP registration challenge',
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
      route: emailOtpRoutePath(args.routePlan, 'seal'),
      ...(sessionAuth ? { sessionAuth } : {}),
      body: {
        walletId,
        wrappedCiphertext,
      },
    });
    const enrollmentSealKeyVersion = readString(
      applied.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    );
    const clientCiphertext = readString(applied.ciphertext, 'ciphertext');
    const enrollmentEscrowCiphertextB64u = readString(
      await runtime.removeClientSealWithKeyHandle({
        ciphertextB64u: clientCiphertext,
        keyHandle,
      }),
      'enrollmentEscrowCiphertextB64u',
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
    const clientUnlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const thresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
      thresholdEcdsaClientVerifyingShare33,
    );
    const enrollmentId = emailOtpDeviceEnrollmentId(walletId, userId);
    const enrollmentVersion = EMAIL_OTP_DEVICE_ENROLLMENT_VERSION;
    const signingRootId = EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_ID;
    const signingRootVersion = EMAIL_OTP_DEVICE_ENROLLMENT_SIGNING_ROOT_VERSION;
    const { recoveryKeys, recoveryCodesIssuedAtMs, recoveryWrappedEnrollmentEscrows } =
      await createEmailOtpRecoveryWrappedEnrollmentEscrows({
        walletId,
        userId,
        enrollmentId,
        enrollmentVersion,
        enrollmentSealKeyVersion,
        signingRootId,
        signingRootVersion,
        encSB64u: enrollmentEscrowCiphertextB64u,
      });

    await writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord(
      {
        walletId,
        userId,
        authSubjectId: userId,
        enrollmentId,
        enrollmentVersion,
        enrollmentSealKeyVersion,
        signingRootId,
        signingRootVersion,
        encSB64u: enrollmentEscrowCiphertextB64u,
        groupId,
      },
      'Email OTP enrollment did not persist device-local enc_s(S)',
    );
    if (!args.skipServerFinalize) {
      const googleEmailOtpRegistrationAttemptId = readOptionalString(
        args.googleEmailOtpRegistrationAttemptId,
      );
      await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'finalize'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          challengeId,
          otpCode,
          otpChannel: EMAIL_OTP_CHANNEL,
          recoveryWrappedEnrollmentEscrows,
          enrollmentSealKeyVersion,
          clientUnlockPublicKeyB64u,
          unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
          thresholdEcdsaClientVerifyingShareB64u,
          ...(googleEmailOtpRegistrationAttemptId ? { googleEmailOtpRegistrationAttemptId } : {}),
        },
      });
      args.onProgress?.('otp.verify.succeeded');
    }
    args.onProgress?.('signer.email_otp.enroll.started');
    args.onProgress?.('signer.email_otp.enroll.succeeded');

    const returnedClientRootShare32 =
      args.returnClientRootShare32 && thresholdClientRootShare32
        ? thresholdClientRootShare32
        : null;
    if (returnedClientRootShare32) {
      thresholdClientRootShare32 = null;
    }
    const returnedClientSecret32 =
      args.returnClientSecret32 && clientSecret32 ? clientSecret32 : null;
    if (returnedClientSecret32) {
      clientSecret32 = null;
    }

    return {
      thresholdEcdsaClientVerifyingShareB64u,
      recoveryKeys,
      recoveryCodesIssuedAtMs,
      challengeId: challengeId || '',
      otpChannel: EMAIL_OTP_CHANNEL,
      enrollmentId,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u,
      unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u,
        unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
        thresholdEcdsaClientVerifyingShareB64u,
      },
      ...(returnedClientRootShare32 ? { clientRootShare32: returnedClientRootShare32 } : {}),
      ...(returnedClientSecret32 ? { clientSecret32: returnedClientSecret32 } : {}),
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

async function loginWithEmailOtpAndUnlockWallet(args: {
  relayUrl: string;
  walletId: string;
  orgId?: string;
  userId: string;
  verification:
    | {
        kind: 'otp';
        challengeId?: string;
        otpCode: string;
      }
    | {
        kind: 'email_otp_unseal_grant';
        grant: string;
        challengeId: string;
      };
  groupId: string;
  routePlan: EmailOtpRoutePlan;
  material: EmailOtpUnlockSecretMaterialRequest;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<
  {
    challengeId: string;
    enrollmentSealKeyVersion: string;
    unlockChallengeId: string;
    unlockChallengeB64u: string;
    clientUnlockPublicKeyB64u: string;
    unlockSignatureB64u: string;
  } & (
    | {
        kind: 'ecdsa';
        clientRootShare32: Uint8Array;
        ecdsaSession?: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        clientSecret32?: never;
        ed25519YaoRecovery?: never;
      }
    | {
        kind: 'ed25519_yao_export';
        clientSecret32: Uint8Array;
        clientRootShare32?: never;
        ed25519YaoRecovery?: never;
      }
    | {
        kind: 'ed25519_yao_recovery';
        clientSecret32: Uint8Array;
        ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
        clientRootShare32?: never;
      }
    | {
        kind: 'ed25519_yao_capability';
        activeClientHandle: string;
        metadata: RouterAbEd25519YaoActiveClientMetadataV1;
        ed25519YaoCapability: EmailOtpEd25519YaoRecoveryBootstrapV1;
        clientRootShare32?: never;
        clientSecret32?: never;
        ed25519YaoRecovery?: never;
      }
    | {
        kind: 'wallet_unlock_capabilities';
        ecdsa: {
          clientRootShare32: Uint8Array;
          session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        };
        ed25519Yao:
          | {
              kind: 'recovery';
              clientSecret32: Uint8Array;
              bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
            }
          | {
              kind: 'capability';
              activeClientHandle: string;
              metadata: RouterAbEd25519YaoActiveClientMetadataV1;
              bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
            };
      }
  )
> {
  const runtime = await getShamir3PassRuntime();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const groupId = readString(args.groupId, 'groupId');
  const keyHandle = readString(
    (await runtime.createClientKeyHandle({ groupId: SIGNING_SESSION_SEAL_GROUP_ID })).keyHandle,
    'keyHandle',
  );
  let clientSecret32: Uint8Array | null = null;
  try {
    const sessionAuth = authLaneToRouteAuth(args.routePlan.authLane);
    let challengeId: string;
    if (args.verification.kind === 'email_otp_unseal_grant') {
      challengeId = args.verification.challengeId;
    } else {
      const providedChallengeId = readOptionalString(args.verification.challengeId);
      if (providedChallengeId) {
        challengeId = providedChallengeId;
      } else {
        const challenge = await postEmailOtpJson({
          relayUrl,
          route: emailOtpRoutePath(args.routePlan, 'challenge'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId,
            otpChannel: EMAIL_OTP_CHANNEL,
            operation: args.routePlan.operation,
          },
        });
        assertEmailOtpChallengeAction({
          response: challenge,
          expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
          label: 'Email OTP login challenge',
        });
        challengeId = readString(
          (challenge.challenge as Record<string, unknown>)?.challengeId,
          'challengeId',
        );
      }
    }
    const userId = resolveEmailOtpAuthSubjectId({
      walletId,
      userId: args.userId,
      routePlan: args.routePlan,
    });
    const localEnrollmentEscrow = await readEmailOtpDeviceEnrollmentEscrowRecord({
      walletId,
      authSubjectId: userId,
      enrollmentId: emailOtpDeviceEnrollmentId(walletId, userId),
    });
    if (!localEnrollmentEscrow) {
      throw new Error('Email OTP device-local enc_s(S) is missing; recovery is required');
    }
    const wrappedCiphertext = readString(
      await runtime.addClientSealWithKeyHandle({
        ciphertextB64u: localEnrollmentEscrow.encSB64u,
        keyHandle,
      }),
      'wrappedCiphertext',
    );
    let unsealed: Record<string, unknown>;
    if (args.verification.kind === 'email_otp_unseal_grant') {
      unsealed = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'unseal'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          loginGrant: args.verification.grant,
          wrappedCiphertext,
        },
      });
    } else if (args.routePlan.routeFamily === 'login') {
      unsealed = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'verifyAndUnseal'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          challengeId: readString(challengeId, 'challengeId'),
          otpCode: readString(
            args.verification.kind === 'otp' ? args.verification.otpCode : undefined,
            'otpCode',
          ),
          otpChannel: EMAIL_OTP_CHANNEL,
          operation: args.routePlan.operation,
          wrappedCiphertext,
        },
      });
      args.onProgress?.('otp.verify.succeeded');
    } else {
      const verified = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'verify'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          challengeId: readString(challengeId, 'challengeId'),
          otpCode: readString(
            args.verification.kind === 'otp' ? args.verification.otpCode : undefined,
            'otpCode',
          ),
          otpChannel: EMAIL_OTP_CHANNEL,
          operation: args.routePlan.operation,
        },
      });
      const verifiedEnrollmentSealKeyVersion = readOptionalString(
        verified.enrollmentSealKeyVersion,
      );
      if (
        verifiedEnrollmentSealKeyVersion &&
        localEnrollmentEscrow.enrollmentSealKeyVersion !== verifiedEnrollmentSealKeyVersion
      ) {
        throw new Error('Email OTP device-local enc_s(S) metadata mismatch; recovery is required');
      }
      const loginGrant = readString(verified.loginGrant, 'loginGrant');
      args.onProgress?.('otp.verify.succeeded');
      unsealed = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'unseal'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          loginGrant,
          wrappedCiphertext,
        },
      });
    }
    const enrollmentSealKeyVersion = readString(
      unsealed.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    );
    if (localEnrollmentEscrow.enrollmentSealKeyVersion !== enrollmentSealKeyVersion) {
      throw new Error('Email OTP device-local enc_s(S) metadata mismatch; recovery is required');
    }
    const clientCiphertext = readString(unsealed.ciphertext, 'ciphertext');
    const unsealedSecret = await removeClientSealToSecret32({
      runtime,
      ciphertextB64u: clientCiphertext,
      keyHandle,
    });
    if (unsealedSecret.kind === 'corrupt_local_custody') {
      throw emailOtpCorruptLocalCustodyError(unsealedSecret);
    }
    clientSecret32 = unsealedSecret.secret32;
    if (!sessionAuth) {
      throw new Error('Email OTP wallet unlock requires app-session authorization');
    }
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
      userId,
      clientSecret32,
      material: args.material,
      sessionAuth,
    });
    const commonResult = {
      challengeId,
      enrollmentSealKeyVersion,
      unlockChallengeId: unlocked.unlockChallengeId,
      unlockChallengeB64u: unlocked.unlockChallengeB64u,
      clientUnlockPublicKeyB64u: unlocked.clientUnlockPublicKeyB64u,
      unlockSignatureB64u: unlocked.unlockSignatureB64u,
    };
    switch (unlocked.kind) {
      case 'ecdsa':
        return {
          kind: 'ecdsa',
          ...commonResult,
          clientRootShare32: unlocked.clientRootShare32,
          ...(unlocked.ecdsaSession ? { ecdsaSession: unlocked.ecdsaSession } : {}),
        };
      case 'ed25519_yao_export': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        return {
          kind: 'ed25519_yao_export',
          ...commonResult,
          clientSecret32: ownedClientSecret32,
        };
      }
      case 'ed25519_yao_recovery': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        return {
          kind: 'ed25519_yao_recovery',
          ...commonResult,
          clientSecret32: ownedClientSecret32,
          ed25519YaoRecovery: unlocked.ed25519YaoRecovery,
        };
      }
      case 'ed25519_yao_capability':
        return {
          kind: 'ed25519_yao_capability',
          ...commonResult,
          activeClientHandle: unlocked.activeClientHandle,
          metadata: unlocked.metadata,
          ed25519YaoCapability: unlocked.ed25519YaoCapability,
        };
      case 'wallet_unlock_capabilities':
        if (unlocked.ed25519Yao.kind === 'recovery') {
          const ownedClientSecret32 = clientSecret32;
          clientSecret32 = null;
          return {
            kind: 'wallet_unlock_capabilities',
            ...commonResult,
            ecdsa: unlocked.ecdsa,
            ed25519Yao: {
              kind: 'recovery',
              clientSecret32: ownedClientSecret32,
              bootstrap: unlocked.ed25519Yao.bootstrap,
            },
          };
        }
        return {
          kind: 'wallet_unlock_capabilities',
          ...commonResult,
          ecdsa: unlocked.ecdsa,
          ed25519Yao: unlocked.ed25519Yao,
        };
      default:
        return assertNeverEmailOtpWorker(unlocked);
    }
  } finally {
    zeroizeBytes(clientSecret32);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
  }
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  (
    self as unknown as { postMessage: (message: unknown, transfer?: Transferable[]) => void }
  ).postMessage(message, transfer);
}

function postEmailOtpWorkerProgress(id: string, code: EmailOtpWorkerProgressCode): void {
  postToMainThread({ id, progress: true, payload: { code } });
}

function emailOtpUnlockMaterialOrgId(material: EmailOtpWalletUnlockMaterialRequest): string {
  switch (material.kind) {
    case 'ecdsa':
      return material.runtimePolicyScope.orgId;
    case 'ed25519_yao_recovery':
      return material.ed25519YaoRecovery.orgId;
    case 'wallet_unlock_capabilities':
      return material.ed25519Yao.recovery.orgId;
    default:
      return assertNeverEmailOtpWorker(material);
  }
}

function workerPayloadObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function rejectUnknownEmailOtpYaoFields(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw new Error(`${label} contains unsupported field: ${key}`);
    }
  }
}

function parseEmailOtpWarmMaterialTarget(value: unknown): EmailOtpWarmMaterialTarget {
  const target = workerPayloadObject(value);
  if (!target) throw new Error('Email OTP warm material target is required');
  const kind = readString(target.kind, 'target.kind');
  switch (kind) {
    case 'ecdsa':
      rejectUnknownEmailOtpYaoFields(target, ['kind', 'thresholdSessionId'], 'target');
      return {
        kind: 'ecdsa',
        thresholdSessionId: readString(
          target.thresholdSessionId,
          'target.thresholdSessionId',
        ),
      };
    case 'ed25519_yao': {
      rejectUnknownEmailOtpYaoFields(
        target,
        ['kind', 'thresholdSessionId', 'materialActivation'],
        'target',
      );
      const materialActivation = parseMpcMaterialActivationRef(target.materialActivation);
      if (!materialActivation.ok) {
        throw new Error(`Email OTP warm material activation is invalid: ${materialActivation.error.message}`);
      }
      return {
        kind: 'ed25519_yao',
        thresholdSessionId: readString(
          target.thresholdSessionId,
          'target.thresholdSessionId',
        ),
        materialActivation: materialActivation.value,
      };
    }
    default:
      throw new Error(`Unsupported Email OTP warm material target kind: ${kind}`);
  }
}

function parseEmailOtpEd25519YaoFactorRequest(value: unknown): EmailOtpEd25519YaoFactorRequest {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao factor request is required');
  rejectUnknownEmailOtpYaoFields(obj, ['kind', 'providerSubject'], 'ed25519YaoFactor');
  const kind = readString(obj.kind, 'ed25519YaoFactor.kind');
  switch (kind) {
    case 'requested':
      return {
        kind: 'requested',
        providerSubject: readString(obj.providerSubject, 'ed25519YaoFactor.providerSubject'),
      };
    case 'not_requested':
      if (obj.providerSubject != null) {
        throw new Error('Email OTP Ed25519 Yao omitted factor rejects providerSubject');
      }
      return { kind: 'not_requested' };
    default:
      throw new Error(`Unsupported Email OTP Ed25519 Yao factor request: ${kind}`);
  }
}

function parseEmailOtpEd25519YaoParticipantIds(
  value: unknown,
  label: string,
): readonly [number, number] {
  const participantIds = normalizeThresholdEd25519ParticipantIds(value);
  if (!participantIds || participantIds.length !== 2) {
    throw new Error(`${label} requires exactly two participant IDs`);
  }
  return [participantIds[0], participantIds[1]];
}

function parseEmailOtpEd25519YaoRecoveryAugmentation(
  value: unknown,
): EmailOtpEd25519YaoRecoveryAugmentationV1 {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao recovery augmentation is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    ['kind', 'signerSlot', 'remainingUses', 'orgId'],
    'ed25519YaoRecovery',
  );
  if (obj.kind !== ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1) {
    throw new Error('Email OTP Ed25519 Yao recovery augmentation kind is invalid');
  }
  const signerSlot = normalizePositiveInteger(obj.signerSlot);
  if (!signerSlot) throw new Error('Email OTP Ed25519 Yao recovery signerSlot is invalid');
  const remainingUses = normalizePositiveInteger(obj.remainingUses);
  if (!remainingUses) throw new Error('Email OTP Ed25519 Yao recovery budget is invalid');
  return {
    kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
    signerSlot,
    remainingUses,
    orgId: readString(obj.orgId, 'ed25519YaoRecovery.orgId'),
  };
}

function emailOtpNonUnlockEcdsaHandleBindingFromParsedBinding(
  binding: EmailOtpEcdsaSessionBootstrapHandleBinding,
): Exclude<EmailOtpEcdsaSessionBootstrapHandleBinding, { operation: 'wallet_unlock' }> {
  switch (binding.operation) {
    case 'sign':
      return { ...binding, operation: 'sign' };
    case 'export':
      return { ...binding, operation: 'export' };
    case 'wallet_unlock':
      throw new Error('Email OTP wallet-unlock binding requires first-session activation');
  }
}

function parseEmailOtpEcdsaWalletUnlockAuthorization(
  value: unknown,
): EmailOtpEcdsaWalletUnlockAuthorization {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP ECDSA wallet unlock authorization is required');
  const kind = readString(obj.kind, 'walletSessionAuthorization.kind');
  switch (kind) {
    case 'verified_wallet_unlock':
      rejectUnknownEmailOtpYaoFields(obj, ['kind'], 'walletSessionAuthorization');
      return { kind };
    case 'reuse_ed25519_wallet_session': {
      rejectUnknownEmailOtpYaoFields(
        obj,
        ['kind', 'walletSessionJwt'],
        'walletSessionAuthorization',
      );
      const walletSessionJwt = readString(
        obj.walletSessionJwt,
        'walletSessionAuthorization.walletSessionJwt',
      );
      return { kind, walletSessionJwt };
    }
    default:
      throw new Error(`Unsupported Email OTP ECDSA wallet unlock authorization: ${kind}`);
  }
}

function parseEmailOtpWalletUnlockMaterialRequest(
  value: unknown,
): EmailOtpWalletUnlockMaterialRequest {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP wallet unlock material request is required');
  const kind = readString(obj.kind, 'material.kind');
  switch (kind) {
    case 'ecdsa': {
      rejectUnknownEmailOtpYaoFields(
        obj,
        [
          'kind',
          'ecdsaClientRootHandleBinding',
          'runtimePolicyScope',
          'ecdsaSessionActivation',
          'walletSessionAuthorization',
        ],
        'material',
      );
      const binding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        obj.ecdsaClientRootHandleBinding,
      );
      if (!binding) throw new Error('Email OTP ECDSA wallet unlock requires its root binding');
      const runtimePolicyScope = parseWorkerRuntimePolicyScope(
        obj.runtimePolicyScope,
        'Email OTP ECDSA wallet unlock',
      );
      if (binding.operation === 'wallet_unlock') {
        return {
          kind: 'ecdsa',
          ecdsaClientRootHandleBinding: { ...binding, operation: 'wallet_unlock' },
          runtimePolicyScope,
          ecdsaSessionActivation: parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1(
            obj.ecdsaSessionActivation,
          ),
          walletSessionAuthorization: parseEmailOtpEcdsaWalletUnlockAuthorization(
            obj.walletSessionAuthorization,
          ),
        };
      }
      if (obj.ecdsaSessionActivation !== undefined) {
        throw new Error('Email OTP first ECDSA activation requires wallet-unlock binding');
      }
      if (obj.walletSessionAuthorization !== undefined) {
        throw new Error('Email OTP Wallet Session authorization requires wallet-unlock binding');
      }
      return {
        kind: 'ecdsa',
        ecdsaClientRootHandleBinding: emailOtpNonUnlockEcdsaHandleBindingFromParsedBinding(binding),
        runtimePolicyScope,
      };
    }
    case 'ed25519_yao_recovery':
      rejectUnknownEmailOtpYaoFields(
        obj,
        [
          'kind',
          'ed25519YaoRecovery',
          'providerSubject',
          'nearAccountId',
          'expectedOperationalPublicKey',
          'expectedThresholdSessionId',
        ],
        'material',
      );
      return {
        kind: 'ed25519_yao_recovery',
        ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryAugmentation(obj.ed25519YaoRecovery),
        providerSubject: readString(obj.providerSubject, 'material.providerSubject'),
        nearAccountId: readString(obj.nearAccountId, 'material.nearAccountId'),
        expectedOperationalPublicKey: readString(
          obj.expectedOperationalPublicKey,
          'material.expectedOperationalPublicKey',
        ),
        expectedThresholdSessionId: readString(
          obj.expectedThresholdSessionId,
          'material.expectedThresholdSessionId',
        ),
      };
    case 'wallet_unlock_capabilities': {
      rejectUnknownEmailOtpYaoFields(obj, ['kind', 'ecdsa', 'ed25519Yao'], 'material');
      const ecdsa = workerPayloadObject(obj.ecdsa);
      const ed25519Yao = workerPayloadObject(obj.ed25519Yao);
      if (!ecdsa || !ed25519Yao) {
        throw new Error('Wallet unlock capabilities require exact ECDSA and Ed25519 inputs');
      }
      rejectUnknownEmailOtpYaoFields(
        ecdsa,
        ['clientRootHandleBinding', 'runtimePolicyScope', 'sessionActivation'],
        'material.ecdsa',
      );
      rejectUnknownEmailOtpYaoFields(
        ed25519Yao,
        [
          'recovery',
          'providerSubject',
          'nearAccountId',
          'expectedOperationalPublicKey',
          'expectedThresholdSessionId',
        ],
        'material.ed25519Yao',
      );
      const binding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        ecdsa.clientRootHandleBinding,
      );
      if (!binding) {
        throw new Error('Email OTP capability unlock requires its ECDSA root binding');
      }
      if (binding.operation !== 'wallet_unlock') {
        throw new Error('Email OTP capability unlock requires wallet-unlock ECDSA binding');
      }
      return {
        kind: 'wallet_unlock_capabilities',
        ecdsa: {
          clientRootHandleBinding: { ...binding, operation: 'wallet_unlock' },
          runtimePolicyScope: parseWorkerRuntimePolicyScope(
            ecdsa.runtimePolicyScope,
            'Email OTP capability wallet unlock',
          ),
          sessionActivation: parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1(
            ecdsa.sessionActivation,
          ),
        },
        ed25519Yao: {
          recovery: parseEmailOtpEd25519YaoRecoveryAugmentation(ed25519Yao.recovery),
          providerSubject: readString(
            ed25519Yao.providerSubject,
            'material.ed25519Yao.providerSubject',
          ),
          nearAccountId: readString(
            ed25519Yao.nearAccountId,
            'material.ed25519Yao.nearAccountId',
          ),
          expectedOperationalPublicKey: readString(
            ed25519Yao.expectedOperationalPublicKey,
            'material.ed25519Yao.expectedOperationalPublicKey',
          ),
          expectedThresholdSessionId: readString(
            ed25519Yao.expectedThresholdSessionId,
            'material.ed25519Yao.expectedThresholdSessionId',
          ),
        },
      };
    }
    default:
      throw new Error(`Unsupported Email OTP wallet unlock material request: ${kind}`);
  }
}

function parseEmailOtpEd25519YaoJsonBytes32(value: unknown, label: string): readonly number[] {
  if (!Array.isArray(value) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  const output: number[] = [];
  for (const byte of value) {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label} must contain exactly 32 bytes`);
    }
    output.push(byte);
  }
  return output;
}

function parseEmailOtpEd25519YaoMaterialActivation(value: unknown): MpcMaterialActivationRef {
  const wire = parseRouterAbMpcMaterialActivationRef(value);
  const parsed = parseMpcMaterialActivationRef({
    kind: wire.kind,
    activationId: wire.activation_id,
    capability: wire.capability,
    materialOwner: wire.material_owner,
    keyBinding: wire.key_binding,
    lifecycleBinding: wire.lifecycle_binding,
    signingWorker: wire.signing_worker,
  });
  if (!parsed.ok) {
    throw new Error(
      `Email OTP Ed25519 Yao active capability material activation is invalid: ${parsed.error.message}`,
    );
  }
  return parsed.value;
}

function parseEmailOtpEd25519YaoWorkerMaterialActivation(
  value: unknown,
): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(value);
  if (!parsed.ok) {
    throw new Error(
      `Email OTP Ed25519 Yao worker active capability material activation is invalid: ${parsed.error.message}`,
    );
  }
  return parsed.value;
}

function parseEmailOtpEd25519YaoBootstrapSession(
  value: unknown,
): WalletRegistrationEd25519YaoBootstrapSession {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao recovery session is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    [
      'sessionKind',
      'walletSessionJwt',
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'authorityScope',
      'thresholdSessionId',
      'walletSessionId',
      'quotaId',
      'expiresAtMs',
      'participantIds',
      'remainingUses',
      'signingRootId',
      'signingRootVersion',
      'runtimePolicyScope',
      'routerAbNormalSigning',
    ],
    'ed25519YaoRecovery.session',
  );
  if (obj.sessionKind !== 'jwt') {
    throw new Error('Email OTP Ed25519 Yao recovery session must use JWT');
  }
  const authorityScope = workerPayloadObject(obj.authorityScope);
  if (!authorityScope) {
    throw new Error('Email OTP Ed25519 Yao recovery authority scope is required');
  }
  rejectUnknownEmailOtpYaoFields(
    authorityScope,
    ['kind', 'provider', 'providerUserId'],
    'ed25519YaoRecovery.session.authorityScope',
  );
  if (
    authorityScope.kind !== 'email_otp' ||
    (authorityScope.provider !== 'google' && authorityScope.provider !== 'email')
  ) {
    throw new Error('Email OTP Ed25519 Yao recovery authority scope is invalid');
  }
  const expiresAtMs = normalizePositiveInteger(obj.expiresAtMs);
  const remainingUses = normalizePositiveInteger(obj.remainingUses);
  if (!expiresAtMs || !remainingUses) {
    throw new Error('Email OTP Ed25519 Yao recovery session budget is invalid');
  }
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(obj.routerAbNormalSigning);
  if (!routerAbNormalSigning) {
    throw new Error('Email OTP Ed25519 Yao recovery session signing state is invalid');
  }
  const walletSessionId = parseWalletSessionId(obj.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(obj.quotaId);
  if (!walletSessionId.ok || !quotaId.ok) {
    throw new Error('Email OTP Ed25519 Yao recovery Wallet Session identity is invalid');
  }
  return {
    sessionKind: 'jwt',
    walletSessionJwt: readString(obj.walletSessionJwt, 'session.walletSessionJwt'),
    walletId: toWalletId(readString(obj.walletId, 'session.walletId')),
    nearAccountId: readString(obj.nearAccountId, 'session.nearAccountId'),
    nearEd25519SigningKeyId: readString(
      obj.nearEd25519SigningKeyId,
      'session.nearEd25519SigningKeyId',
    ),
    authorityScope: {
      kind: 'email_otp',
      provider: authorityScope.provider,
      providerUserId: readString(
        authorityScope.providerUserId,
        'session.authorityScope.providerUserId',
      ),
    },
    thresholdSessionId: readString(obj.thresholdSessionId, 'session.thresholdSessionId'),
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs,
    participantIds: parseEmailOtpEd25519YaoParticipantIds(
      obj.participantIds,
      'Email OTP Ed25519 Yao recovery session',
    ),
    remainingUses,
    signingRootId: readString(obj.signingRootId, 'session.signingRootId'),
    signingRootVersion: readString(obj.signingRootVersion, 'session.signingRootVersion'),
    runtimePolicyScope: parseWorkerRuntimePolicyScope(
      obj.runtimePolicyScope,
      'Email OTP Ed25519 Yao recovery session',
    ),
    routerAbNormalSigning,
  };
}

type EmailOtpEd25519YaoMaterialActivationParser = (
  value: unknown,
) => MpcMaterialActivationRef;

function parseEmailOtpEd25519YaoActiveCapability(
  value: unknown,
): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  return parseEmailOtpEd25519YaoActiveCapabilityWithMaterialParser(
    value,
    parseEmailOtpEd25519YaoMaterialActivation,
    'ed25519YaoRecovery.capability',
  );
}

function parseEmailOtpEd25519YaoWorkerActiveCapability(
  value: unknown,
): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  return parseEmailOtpEd25519YaoActiveCapabilityWithMaterialParser(
    value,
    parseEmailOtpEd25519YaoWorkerMaterialActivation,
    'exportEmailOtpEd25519YaoSeedWithAuthorization.material.capability',
  );
}

function parseEmailOtpEd25519YaoActiveCapabilityWithMaterialParser(
  value: unknown,
  parseMaterialActivation: EmailOtpEd25519YaoMaterialActivationParser,
  capabilityLabel: string,
): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao active capability is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    [
      'kind',
      'activeCapabilityBinding',
      'materialActivation',
      'registeredPublicKey',
      'nearAccountId',
      'applicationBinding',
      'runtimePolicyScope',
      'participantIds',
      'lifecycle',
      'stateEpoch',
    ],
    capabilityLabel,
  );
  if (obj.kind !== 'router_ab_ed25519_yao_active_capability_v1') {
    throw new Error('Email OTP Ed25519 Yao active capability kind is invalid');
  }
  const application = workerPayloadObject(obj.applicationBinding);
  const lifecycle = workerPayloadObject(obj.lifecycle);
  if (!application || !lifecycle) {
    throw new Error('Email OTP Ed25519 Yao active capability identity is invalid');
  }
  rejectUnknownEmailOtpYaoFields(
    application,
    ['wallet_id', 'near_ed25519_signing_key_id', 'signing_root_id', 'key_creation_signer_slot'],
    'ed25519YaoRecovery.capability.applicationBinding',
  );
  rejectUnknownEmailOtpYaoFields(
    lifecycle,
    [
      'lifecycleId',
      'rootShareEpoch',
      'accountId',
      'thresholdSessionId',
      'signerSetId',
      'signingWorkerId',
    ],
    'ed25519YaoRecovery.capability.lifecycle',
  );
  const signerSlot = normalizePositiveInteger(application.key_creation_signer_slot);
  const stateEpoch = normalizePositiveInteger(obj.stateEpoch);
  const materialActivation = parseMaterialActivation(obj.materialActivation);
  if (!signerSlot || !stateEpoch) {
    throw new Error('Email OTP Ed25519 Yao active capability epoch or signer slot is invalid');
  }
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation,
    activeCapabilityBinding: parseEmailOtpEd25519YaoJsonBytes32(
      obj.activeCapabilityBinding,
      'capability.activeCapabilityBinding',
    ),
    registeredPublicKey: parseEmailOtpEd25519YaoJsonBytes32(
      obj.registeredPublicKey,
      'capability.registeredPublicKey',
    ),
    nearAccountId: readString(obj.nearAccountId, 'capability.nearAccountId'),
    applicationBinding: {
      wallet_id: readString(application.wallet_id, 'applicationBinding.wallet_id'),
      near_ed25519_signing_key_id: readString(
        application.near_ed25519_signing_key_id,
        'applicationBinding.near_ed25519_signing_key_id',
      ),
      signing_root_id: readString(
        application.signing_root_id,
        'applicationBinding.signing_root_id',
      ),
      key_creation_signer_slot: signerSlot,
    },
    runtimePolicyScope: parseWorkerRuntimePolicyScope(
      obj.runtimePolicyScope,
      'Email OTP Ed25519 Yao active capability',
    ),
    participantIds: parseEmailOtpEd25519YaoParticipantIds(
      obj.participantIds,
      'Email OTP Ed25519 Yao active capability',
    ),
    lifecycle: {
      lifecycleId: readString(lifecycle.lifecycleId, 'lifecycle.lifecycleId'),
      rootShareEpoch: readString(lifecycle.rootShareEpoch, 'lifecycle.rootShareEpoch'),
      accountId: readString(lifecycle.accountId, 'lifecycle.accountId'),
      thresholdSessionId: readThresholdEd25519SessionId(
        readString(lifecycle.thresholdSessionId, 'lifecycle.thresholdSessionId'),
        'lifecycle.thresholdSessionId',
      ),
      signerSetId: readString(lifecycle.signerSetId, 'lifecycle.signerSetId'),
      signingWorkerId: readString(lifecycle.signingWorkerId, 'lifecycle.signingWorkerId'),
    },
    stateEpoch,
  };
}

function parseEmailOtpEd25519YaoRecoveryBootstrap(
  value: unknown,
): EmailOtpEd25519YaoRecoveryBootstrapV1 {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao recovery bootstrap is required');
  rejectUnknownEmailOtpYaoFields(obj, ['kind', 'session', 'capability'], 'ed25519YaoRecovery');
  if (obj.kind !== ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1) {
    throw new Error('Email OTP Ed25519 Yao recovery bootstrap kind is invalid');
  }
  return {
    kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
    session: parseEmailOtpEd25519YaoBootstrapSession(obj.session),
    capability: parseEmailOtpEd25519YaoActiveCapability(obj.capability),
  };
}

function parseEmailOtpEd25519YaoPurpose(value: unknown): EmailOtpEd25519YaoRootScope['purpose'] {
  const purpose = readString(value, 'Email OTP Ed25519 Yao purpose');
  switch (purpose) {
    case 'registration':
    case 'recovery':
      return purpose;
    default:
      throw new Error(`Unsupported Email OTP Ed25519 Yao purpose: ${purpose}`);
  }
}

function parseEmailOtpEd25519YaoPendingFactorHandle(
  value: unknown,
): EmailOtpEd25519YaoPendingFactorHandle {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao pending factor handle is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    ['kind', 'handleId', 'purpose', 'expiresAtMs'],
    'pendingFactorHandle',
  );
  if (obj.kind !== 'email_otp_ed25519_yao_pending_factor_handle_v1') {
    throw new Error('Invalid Email OTP Ed25519 Yao pending factor handle kind');
  }
  const expiresAtMs = normalizePositiveInteger(obj.expiresAtMs);
  if (!expiresAtMs) {
    throw new Error('Email OTP Ed25519 Yao pending factor handle expiry is invalid');
  }
  return {
    kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
    handleId: readString(obj.handleId, 'pendingFactorHandle.handleId'),
    purpose: parseEmailOtpEd25519YaoPurpose(obj.purpose),
    expiresAtMs,
  };
}

function parseEmailOtpEd25519YaoRootHandle(value: unknown): EmailOtpEd25519YaoRootHandle {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao root handle is required');
  rejectUnknownEmailOtpYaoFields(obj, ['kind', 'handleId', 'purpose', 'expiresAtMs'], 'rootHandle');
  if (obj.kind !== 'email_otp_ed25519_yao_root_handle_v1') {
    throw new Error('Invalid Email OTP Ed25519 Yao root handle kind');
  }
  const expiresAtMs = normalizePositiveInteger(obj.expiresAtMs);
  if (!expiresAtMs) throw new Error('Email OTP Ed25519 Yao root handle expiry is invalid');
  return {
    kind: 'email_otp_ed25519_yao_root_handle_v1',
    handleId: readString(obj.handleId, 'rootHandle.handleId'),
    purpose: parseEmailOtpEd25519YaoPurpose(obj.purpose),
    expiresAtMs,
  };
}

function parseEmailOtpEd25519YaoRootScope(value: unknown): EmailOtpEd25519YaoRootScope {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao root scope is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    [
      'kind',
      'purpose',
      'walletId',
      'providerSubject',
      'nearEd25519SigningKeyId',
      'signingRootId',
      'signerSlot',
      'participantIds',
    ],
    'scope',
  );
  if (obj.kind !== 'email_otp_ed25519_yao_root_scope_v1') {
    throw new Error('Invalid Email OTP Ed25519 Yao root scope kind');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  if (!participantIds || participantIds.length !== 2) {
    throw new Error('Email OTP Ed25519 Yao root scope requires two participants');
  }
  const signerSlot = normalizePositiveInteger(obj.signerSlot);
  if (!signerSlot) throw new Error('Email OTP Ed25519 Yao root scope requires signerSlot');
  return {
    kind: 'email_otp_ed25519_yao_root_scope_v1',
    purpose: parseEmailOtpEd25519YaoPurpose(obj.purpose),
    walletId: readString(obj.walletId, 'scope.walletId'),
    providerSubject: readString(obj.providerSubject, 'scope.providerSubject'),
    nearEd25519SigningKeyId: readString(
      obj.nearEd25519SigningKeyId,
      'scope.nearEd25519SigningKeyId',
    ),
    signingRootId: readString(obj.signingRootId, 'scope.signingRootId'),
    signerSlot,
    participantIds: [participantIds[0], participantIds[1]],
  };
}

function parseEmailOtpEd25519YaoRegistrationAdmission(value: unknown) {
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(value);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function parseEmailOtpEd25519YaoRegistrationAdmissionReceipt(value: unknown) {
  const parsed = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(value);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function parseEmailOtpEd25519YaoRecoveryAdmission(value: unknown) {
  const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(value);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function parseEmailOtpEd25519YaoSessionPolicy(value: unknown): {
  thresholdSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
} {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao session policy is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    ['thresholdSessionId', 'expiresAtMs', 'remainingUses'],
    'sessionPolicy',
  );
  const expiresAtMs = normalizePositiveInteger(obj.expiresAtMs);
  const remainingUses = normalizePositiveInteger(obj.remainingUses);
  if (!expiresAtMs || !remainingUses) {
    throw new Error('Email OTP Ed25519 Yao session policy is invalid');
  }
  return {
    thresholdSessionId: readString(obj.thresholdSessionId, 'sessionPolicy.thresholdSessionId'),
    expiresAtMs,
    remainingUses,
  };
}

function parseEmailOtpEd25519YaoBytes32(value: unknown, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  return value.slice();
}

function parseEmailOtpEd25519YaoSigningInput(
  value: unknown,
): RouterAbEd25519YaoClientSigningInputV1 {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao signing input is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    ['admittedDigest', 'signingWorkerCommitments', 'signingWorkerVerifyingShare'],
    'signing input',
  );
  const commitments = workerPayloadObject(obj.signingWorkerCommitments);
  if (!commitments) {
    throw new Error('Email OTP Ed25519 Yao signing input requires worker commitments');
  }
  rejectUnknownEmailOtpYaoFields(commitments, ['hiding', 'binding'], 'signingWorkerCommitments');
  return {
    admittedDigest: parseEmailOtpEd25519YaoBytes32(
      obj.admittedDigest,
      'signing input admittedDigest',
    ),
    signingWorkerCommitments: {
      hiding: readString(commitments.hiding, 'signingWorkerCommitments.hiding'),
      binding: readString(commitments.binding, 'signingWorkerCommitments.binding'),
    },
    signingWorkerVerifyingShare: parseEmailOtpEd25519YaoBytes32(
      obj.signingWorkerVerifyingShare,
      'signing input worker verifying share',
    ),
  };
}

function isEmailOtpEd25519YaoWalletSessionState(
  value: unknown,
): value is NearResolvedEd25519SigningSessionState {
  const obj = workerPayloadObject(value);
  const walletSessionAuth = workerPayloadObject(obj?.walletSessionAuth);
  const signingLane = workerPayloadObject(obj?.signingLane);
  const laneAuth = workerPayloadObject(signingLane?.auth);
  const laneIdentity = workerPayloadObject(signingLane?.identity);
  const laneSigner = workerPayloadObject(laneIdentity?.signer);
  const laneAccount = workerPayloadObject(laneSigner?.account);
  const laneWallet = workerPayloadObject(laneAccount?.wallet);
  const routerAbNormalSigning = workerPayloadObject(obj?.routerAbNormalSigning);
  const signingWalletSession = workerPayloadObject(obj?.signingWalletSession);
  const signingWalletAuth = workerPayloadObject(signingWalletSession?.auth);
  const signingWalletCredential = workerPayloadObject(signingWalletAuth?.credential);
  if (
    !obj ||
    !walletSessionAuth ||
    !signingLane ||
    !laneAuth ||
    !laneIdentity ||
    !laneSigner ||
    !laneAccount ||
    !laneWallet ||
    !routerAbNormalSigning ||
    !signingWalletSession ||
    !signingWalletAuth ||
    !signingWalletCredential
  ) {
    return false;
  }
  const thresholdSessionId = optionalWorkerString(obj.thresholdSessionId);
  const walletSessionId = optionalWorkerString(obj.walletSessionId);
  const quotaId = optionalWorkerString(obj.quotaId);
  const signingRootId = optionalWorkerString(obj.signingRootId);
  const signingRootVersion = optionalWorkerString(obj.signingRootVersion);
  const relayerUrl = optionalWorkerString(obj.relayerUrl);
  const walletSessionJwt = optionalWorkerString(walletSessionAuth.walletSessionJwt);
  const walletId = optionalWorkerString(laneWallet.walletId);
  const nearAccountId = optionalWorkerString(laneAccount.nearAccountId);
  const nearEd25519SigningKeyId = optionalWorkerString(laneSigner.nearEd25519SigningKeyId);
  const providerSubjectId = optionalWorkerString(laneAuth.providerSubjectId);
  const signerSlot = normalizePositiveInteger(laneSigner.signerSlot);
  const remainingUses = normalizeNonNegativeInteger(obj.remainingUses);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(obj.runtimePolicyScope);
  const signingWalletRuntimePolicyScope = normalizeThresholdRuntimePolicyScope(
    signingWalletSession.runtimePolicyScope,
  );
  if (
    !thresholdSessionId ||
    !walletSessionId ||
    !quotaId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerUrl ||
    !walletSessionJwt ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !providerSubjectId ||
    !signerSlot ||
    remainingUses == null ||
    !runtimePolicyScope ||
    !signingWalletRuntimePolicyScope
  ) {
    return false;
  }
  return (
    walletSessionAuth.kind === 'wallet_session_jwt' &&
    signingLane.kind === 'selected_lane' &&
    signingLane.curve === 'ed25519' &&
    signingLane.chain === 'near' &&
    signingLane.keyKind === 'threshold_ed25519' &&
    signingLane.chainFamily === 'near' &&
    signingLane.storageSource === 'email_otp' &&
    laneAuth.kind === 'email_otp' &&
    laneIdentity.kind === 'exact_signing_lane' &&
    signingLane.thresholdSessionId === thresholdSessionId &&
    laneIdentity.thresholdSessionId === thresholdSessionId &&
    signingLane.walletSessionId === walletSessionId &&
    signingLane.quotaId === quotaId &&
    laneIdentity.walletSessionId === walletSessionId &&
    laneIdentity.quotaId === quotaId &&
    routerAbNormalSigning.kind === 'router_ab_ed25519_normal_signing_v1' &&
    optionalWorkerString(routerAbNormalSigning.signingWorkerId) != null &&
    signingWalletSession.curve === 'ed25519' &&
    signingWalletSession.thresholdSessionId === thresholdSessionId &&
    signingWalletSession.walletSessionId === walletSessionId &&
    signingWalletSession.quotaId === quotaId &&
    signingWalletSession.remainingUses === remainingUses &&
    signingWalletSession.signingRootId === signingRootId &&
    signingWalletSession.signingRootVersion === signingRootVersion &&
    signingWalletSession.routerAbNormalSigning != null &&
    signingWalletAuth.kind === 'wallet_session_jwt' &&
    signingWalletAuth.walletSessionJwt === walletSessionJwt &&
    signingWalletCredential.kind === 'jwt' &&
    signingWalletCredential.walletSessionJwt === walletSessionJwt
  );
}

function parseEmailOtpEd25519YaoWalletSessionState(
  value: unknown,
): NearResolvedEd25519SigningSessionState {
  if (!isEmailOtpEd25519YaoWalletSessionState(value)) {
    throw new Error('Email OTP Ed25519 Yao commit requires a valid Wallet Session state');
  }
  return value;
}

function optionalWorkerString(value: unknown): string | undefined {
  return normalizeOptionalTrimmedString(value) || undefined;
}

function optionalWorkerPositiveInteger(value: unknown): number | undefined {
  const normalized = normalizePositiveInteger(value);
  return normalized == null ? undefined : normalized;
}

function optionalWorkerNonNegativeInteger(value: unknown): number | undefined {
  const normalized = normalizeNonNegativeInteger(value);
  return normalized == null ? undefined : normalized;
}

function optionalWorkerBooleanTrue(value: unknown): true | undefined {
  return value === true ? true : undefined;
}

function parseWorkerRouteAuth(value: unknown, label: string): AppOrWalletSessionAuth {
  const obj = workerPayloadObject(value);
  const kind = normalizeOptionalTrimmedString(obj?.kind);
  const jwt = normalizeOptionalTrimmedString(obj?.jwt);
  if (!jwt) {
    throw new Error(`${label} requires routeAuth`);
  }
  if (kind === 'app_session') {
    return { kind: 'app_session', jwt };
  }
  if (kind === 'wallet_session') {
    return { kind: 'wallet_session', jwt };
  }
  throw new Error(`${label} requires routeAuth`);
}

function parseOptionalWorkerRouteAuth(value: unknown): AppOrWalletSessionAuth | undefined {
  if (value == null) return undefined;
  return parseWorkerRouteAuth(value, 'Email OTP worker request');
}

function parseWorkerRuntimePolicyScope(value: unknown, label: string): ThresholdRuntimePolicyScope {
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(value);
  if (!runtimePolicyScope) {
    throw new Error(`${label} requires runtimePolicyScope`);
  }
  return runtimePolicyScope;
}

function parseOptionalWorkerRuntimePolicyScope(
  value: unknown,
): ThresholdRuntimePolicyScope | undefined {
  return normalizeThresholdRuntimePolicyScope(value) || undefined;
}

function parseWorkerChainTarget(value: unknown): ThresholdEcdsaChainTarget {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP worker request requires chainTarget');
  return thresholdEcdsaChainTargetFromRequest(obj);
}

function parseEmailOtpWorkerHandleOperation(value: unknown): EmailOtpWorkerSessionHandleOperation {
  const operation = readString(value, 'Email OTP worker handle operation');
  switch (operation) {
    case 'registration':
    case 'wallet_unlock':
    case 'sign':
    case 'export':
      return operation;
    default:
      throw new Error(`Unsupported Email OTP worker handle operation: ${operation}`);
  }
}

function parseOptionalWorkerEcdsaClientRootHandleBinding(
  value: unknown,
): EmailOtpEcdsaClientRootHandleBinding | undefined {
  if (value == null) return undefined;
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP ECDSA client-root handle binding must be an object');
  }
  const action = readString(
    obj.action ?? 'threshold_ecdsa_bootstrap',
    'ecdsaClientRootHandleBinding.action',
  );
  if (action === 'wallet_registration_ecdsa_prepare') {
    const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
    if (operation !== 'registration') {
      throw new Error(
        'Email OTP wallet-registration ECDSA handle binding requires registration operation',
      );
    }
    const keyScope = readString(obj.keyScope, 'ecdsaClientRootHandleBinding.keyScope');
    if (keyScope !== 'evm-family') {
      throw new Error(
        'Email OTP wallet-registration ECDSA handle binding requires evm-family keyScope',
      );
    }
    return {
      evmFamilySigningKeySlotId: String(
        readEvmFamilySigningKeySlotId(
          obj.evmFamilySigningKeySlotId,
          'ecdsaClientRootHandleBinding.evmFamilySigningKeySlotId',
        ),
      ),
      authSubjectId: readString(obj.authSubjectId, 'ecdsaClientRootHandleBinding.authSubjectId'),
      action: 'wallet_registration_ecdsa_prepare',
      operation: 'registration',
      keyScope: 'evm-family',
      chainTarget: parseWorkerChainTarget(obj.chainTarget),
    };
  }
  if (action !== 'threshold_ecdsa_bootstrap') {
    throw new Error(`Unsupported Email OTP ECDSA client-root handle binding action: ${action}`);
  }
  const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
  const common = {
    authSubjectId: readString(obj.authSubjectId, 'ecdsaClientRootHandleBinding.authSubjectId'),
    action: 'threshold_ecdsa_bootstrap' as const,
    chainTarget: parseWorkerChainTarget(obj.chainTarget),
  };
  if (operation === 'registration') {
    throw new Error(
      'Email OTP registration ECDSA handle binding is retired; use wallet-registration prepare',
    );
  }
  if ('evmFamilySigningKeySlotId' in obj) {
    throw new Error('Email OTP runtime ECDSA handle binding forbids evmFamilySigningKeySlotId');
  }
  return {
    ...common,
    operation,
    keyHandle: readString(obj.keyHandle, 'ecdsaClientRootHandleBinding.keyHandle'),
  };
}

function parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
  value: unknown,
): EmailOtpEcdsaSessionBootstrapHandleBinding | undefined {
  const binding = parseOptionalWorkerEcdsaClientRootHandleBinding(value);
  if (!binding) return undefined;
  if (binding.action === 'wallet_registration_ecdsa_prepare') {
    throw new Error(
      'Email OTP session bootstrap handle binding rejects wallet-registration action',
    );
  }
  return binding;
}

function parseWorkerWalletRegistrationEcdsaPrepareHandleRequest(
  value: unknown,
): EmailOtpWalletRegistrationEcdsaPrepareHandleRequest {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP registration enrollment material requires ECDSA handle request');
  }
  const kind = readString(obj.kind, 'ecdsaClientRootHandle.kind');
  switch (kind) {
    case 'requested': {
      if (!Array.isArray(obj.bindings) || obj.bindings.length === 0) {
        throw new Error(
          'Email OTP registration enrollment material requires wallet-registration ECDSA handle bindings',
        );
      }
      const bindings: EmailOtpWalletRegistrationEcdsaPrepareHandleBinding[] = [];
      for (const value of obj.bindings) {
        const binding = parseOptionalWorkerEcdsaClientRootHandleBinding(value);
        if (!binding || binding.action !== 'wallet_registration_ecdsa_prepare') {
          throw new Error(
            'Email OTP registration enrollment material requires wallet-registration ECDSA handle bindings',
          );
        }
        bindings.push(binding);
      }
      const first = bindings[0];
      if (!first) {
        throw new Error(
          'Email OTP registration enrollment material requires wallet-registration ECDSA handle bindings',
        );
      }
      return { kind: 'requested', bindings: [first, ...bindings.slice(1)] };
    }
    case 'not_requested':
      if ('bindings' in obj) {
        throw new Error('Email OTP unrequested ECDSA handle request forbids bindings');
      }
      return { kind: 'not_requested' };
    default:
      throw new Error(`Unsupported Email OTP registration ECDSA handle request kind: ${kind}`);
  }
}

function parseWorkerWalletRegistrationEcdsaPrepareHandleResult(
  value: unknown,
): EmailOtpWalletRegistrationEcdsaPrepareHandleResult {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP registration enrollment material requires ECDSA handle result');
  }
  const kind = readString(obj.kind, 'clientRootShareHandle.kind');
  switch (kind) {
    case 'available':
      if (!Array.isArray(obj.handles) || obj.handles.length === 0) {
        throw new Error('Email OTP registration ECDSA handle result requires handles');
      }
      {
        const handles: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload[] = [];
        for (const value of obj.handles) {
          handles.push(parseWorkerIssuedWalletRegistrationEcdsaPrepareClientRootHandle(value));
        }
        const first = handles[0];
        if (!first) {
          throw new Error('Email OTP registration ECDSA handle result requires handles');
        }
        return {
          kind: 'available',
          handles: [first, ...handles.slice(1)],
        };
      }
    case 'not_requested':
      if ('handles' in obj) {
        throw new Error('Email OTP unrequested ECDSA handle result forbids handles');
      }
      return { kind: 'not_requested' };
    default:
      throw new Error(`Unsupported Email OTP registration ECDSA handle result kind: ${kind}`);
  }
}

function parseWorkerIssuedEcdsaSessionBootstrapClientRootHandle(
  value: unknown,
): EmailOtpEcdsaSessionBootstrapHandlePayload {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP ECDSA bootstrap requires clientRootShareHandle');
  }
  const kind = readString(obj.kind, 'clientRootShareHandle.kind');
  const action = readString(obj.action, 'clientRootShareHandle.action');
  if (kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(`Unsupported Email OTP worker handle kind: ${kind}`);
  }
  if (action !== 'threshold_ecdsa_bootstrap') {
    throw new Error(`Unsupported Email OTP worker handle action: ${action}`);
  }
  const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
  const common = {
    kind: 'email_otp_worker_session_handle_v1' as const,
    sessionId: readString(obj.sessionId, 'clientRootShareHandle.sessionId'),
    walletId: readString(obj.walletId, 'clientRootShareHandle.walletId'),
    authSubjectId: readString(obj.authSubjectId, 'clientRootShareHandle.authSubjectId'),
    action: 'threshold_ecdsa_bootstrap' as const,
    chainTarget: parseWorkerChainTarget(obj.chainTarget),
  };
  if (operation === 'registration') {
    throw new Error(
      'Email OTP registration ECDSA worker-issued handles are retired; use wallet-registration prepare',
    );
  }
  if ('evmFamilySigningKeySlotId' in obj) {
    throw new Error('Email OTP runtime ECDSA handle forbids evmFamilySigningKeySlotId');
  }
  return {
    ...common,
    operation,
    keyHandle: readString(obj.keyHandle, 'clientRootShareHandle.keyHandle'),
  };
}

function parseWorkerIssuedWalletRegistrationEcdsaPrepareClientRootHandle(
  value: unknown,
): EmailOtpWalletRegistrationEcdsaPrepareHandlePayload {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP wallet-registration ECDSA prepare requires clientRootShareHandle');
  }
  const kind = readString(obj.kind, 'clientRootShareHandle.kind');
  const action = readString(obj.action, 'clientRootShareHandle.action');
  if (kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(`Unsupported Email OTP worker handle kind: ${kind}`);
  }
  if (action !== 'wallet_registration_ecdsa_prepare') {
    throw new Error(`Unsupported Email OTP worker handle action: ${action}`);
  }
  const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
  if (operation !== 'registration') {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare handle requires registration operation',
    );
  }
  const keyScope = readString(obj.keyScope, 'clientRootShareHandle.keyScope');
  if (keyScope !== 'evm-family') {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare handle requires evm-family keyScope',
    );
  }
  return {
    kind: 'email_otp_worker_session_handle_v1',
    sessionId: readString(obj.sessionId, 'clientRootShareHandle.sessionId'),
    walletId: readString(obj.walletId, 'clientRootShareHandle.walletId'),
    evmFamilySigningKeySlotId: String(
      readEvmFamilySigningKeySlotId(
        obj.evmFamilySigningKeySlotId,
        'clientRootShareHandle.evmFamilySigningKeySlotId',
      ),
    ),
    authSubjectId: readString(obj.authSubjectId, 'clientRootShareHandle.authSubjectId'),
    action: 'wallet_registration_ecdsa_prepare',
    operation: 'registration',
    keyScope: 'evm-family',
    chainTarget: parseWorkerChainTarget(obj.chainTarget),
  };
}

function parseWorkerParticipantIds(value: unknown): number[] | undefined {
  const participantIds = normalizeThresholdEd25519ParticipantIds(value);
  return participantIds || undefined;
}

function parseWorkerSealTransport(value: unknown): {
  relayerUrl: string;
  walletSessionJwt?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
} {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP worker request requires transport');
  return {
    relayerUrl: readString(obj.relayerUrl, 'transport.relayerUrl'),
    ...(optionalWorkerString(obj.walletSessionJwt)
      ? { walletSessionJwt: optionalWorkerString(obj.walletSessionJwt)! }
      : {}),
    ...(optionalWorkerString(obj.signingSessionSealKeyVersion)
      ? {
          signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
            obj.signingSessionSealKeyVersion,
          ),
        }
      : {}),
    ...(optionalWorkerString(obj.groupId) ? { groupId: optionalWorkerString(obj.groupId)! } : {}),
  };
}

function parseRequiredWorkerSealTransport(value: unknown): {
  relayerUrl: string;
  walletSessionJwt: string;
  signingSessionSealKeyVersion: SigningSessionSealKeyVersion;
  groupId: string;
} {
  const transport = parseWorkerSealTransport(value);
  if (
    !transport.walletSessionJwt ||
    !transport.signingSessionSealKeyVersion ||
    !transport.groupId
  ) {
    throw new Error('Email OTP Ed25519 Yao rehydrate requires exact seal transport');
  }
  return {
    relayerUrl: transport.relayerUrl,
    walletSessionJwt: transport.walletSessionJwt,
    signingSessionSealKeyVersion: transport.signingSessionSealKeyVersion,
    groupId: transport.groupId,
  };
}

function readRegistrationRoutePlan(value: unknown, label: string): EmailOtpRoutePlan {
  const routePlan = readRoutePlan(value, label);
  if (routePlan.routeFamily !== 'registration') {
    throw new Error(`${label} requires an Email OTP registration route plan`);
  }
  return routePlan;
}

function parseEmailOtpOperationStepUpDigest(
  value: unknown,
  label: string,
): { bytes: readonly number[] } {
  const digest = workerPayloadObject(value);
  if (!digest) throw new Error(`${label} is required`);
  rejectUnknownEmailOtpYaoFields(digest, ['bytes'], label);
  if (
    !Array.isArray(digest.bytes) ||
    digest.bytes.length !== 32 ||
    digest.bytes.some(
      (byte) => !Number.isSafeInteger(byte) || Number(byte) < 0 || Number(byte) > 255,
    )
  ) {
    throw new Error(`${label}.bytes must contain exactly 32 bytes`);
  }
  return { bytes: digest.bytes.map((byte) => Number(byte)) };
}

function parseEmailOtpOperationStepUpNormalSigningScope(
  value: unknown,
): RouterAbNormalSigningPrepareRequestV2Wire['scope'] {
  const scope = workerPayloadObject(value);
  if (!scope) throw new Error('normalSigningRequest.scope is required');
  rejectUnknownEmailOtpYaoFields(
    scope,
    [
      'request_id',
      'account_id',
      'authorization',
      'material_activation',
      'signing_worker_id',
    ],
    'normalSigningRequest.scope',
  );
  const authorization = parseRouterAbNormalSigningAuthorization(scope.authorization);
  if (authorization.kind !== 'operation_step_up') {
    throw new Error('Email OTP material recovery requires operation-step-up authorization');
  }
  return {
    request_id: readString(scope.request_id, 'normalSigningRequest.scope.request_id'),
    account_id: readString(scope.account_id, 'normalSigningRequest.scope.account_id'),
    authorization,
    material_activation: parseRouterAbMpcMaterialActivationRef(scope.material_activation),
    signing_worker_id: readString(
      scope.signing_worker_id,
      'normalSigningRequest.scope.signing_worker_id',
    ),
  };
}

function parseEmailOtpOperationStepUpNearNetworkId(
  value: unknown,
): 'testnet' | 'mainnet' {
  if (value === 'testnet' || value === 'mainnet') return value;
  throw new Error('normalSigningRequest.intent.near_network_id is invalid');
}

function parseEmailOtpOperationStepUpNormalSigningIntent(
  value: unknown,
): RouterAbNormalSigningPrepareRequestV2Wire['intent'] {
  const intent = workerPayloadObject(value);
  if (!intent) throw new Error('normalSigningRequest.intent is required');
  switch (intent.kind) {
    case 'near_transaction_v1': {
      rejectUnknownEmailOtpYaoFields(
        intent,
        [
          'kind',
          'operation_id',
          'operation_fingerprint',
          'near_account_id',
          'near_network_id',
          'transactions',
          'unsigned_transaction_borsh_b64u',
        ],
        'normalSigningRequest.intent',
      );
      if (!Array.isArray(intent.transactions) || intent.transactions.length < 1) {
        throw new Error('normalSigningRequest.intent.transactions is required');
      }
      const transactions = intent.transactions.map((value, index) => {
        const transaction = workerPayloadObject(value);
        if (!transaction) {
          throw new Error(`normalSigningRequest.intent.transactions[${index}] is invalid`);
        }
        rejectUnknownEmailOtpYaoFields(
          transaction,
          ['receiver_id', 'action_fingerprint'],
          `normalSigningRequest.intent.transactions[${index}]`,
        );
        return {
          receiver_id: readString(
            transaction.receiver_id,
            `normalSigningRequest.intent.transactions[${index}].receiver_id`,
          ),
          action_fingerprint: readString(
            transaction.action_fingerprint,
            `normalSigningRequest.intent.transactions[${index}].action_fingerprint`,
          ),
        };
      });
      return {
        kind: 'near_transaction_v1',
        operation_id: readString(
          intent.operation_id,
          'normalSigningRequest.intent.operation_id',
        ),
        operation_fingerprint: readString(
          intent.operation_fingerprint,
          'normalSigningRequest.intent.operation_fingerprint',
        ),
        near_account_id: readString(
          intent.near_account_id,
          'normalSigningRequest.intent.near_account_id',
        ),
        near_network_id: parseEmailOtpOperationStepUpNearNetworkId(intent.near_network_id),
        transactions,
        unsigned_transaction_borsh_b64u: readString(
          intent.unsigned_transaction_borsh_b64u,
          'normalSigningRequest.intent.unsigned_transaction_borsh_b64u',
        ),
      };
    }
    case 'nep413_v1': {
      rejectUnknownEmailOtpYaoFields(
        intent,
        [
          'kind',
          'operation_id',
          'operation_fingerprint',
          'near_account_id',
          'near_network_id',
          'recipient',
          'message',
          'nonce_b64u',
          'callback_url',
        ],
        'normalSigningRequest.intent',
      );
      const callbackUrl = optionalWorkerString(intent.callback_url);
      return {
        kind: 'nep413_v1',
        operation_id: readString(
          intent.operation_id,
          'normalSigningRequest.intent.operation_id',
        ),
        operation_fingerprint: readString(
          intent.operation_fingerprint,
          'normalSigningRequest.intent.operation_fingerprint',
        ),
        near_account_id: readString(
          intent.near_account_id,
          'normalSigningRequest.intent.near_account_id',
        ),
        near_network_id: parseEmailOtpOperationStepUpNearNetworkId(intent.near_network_id),
        recipient: readString(intent.recipient, 'normalSigningRequest.intent.recipient'),
        message: readString(intent.message, 'normalSigningRequest.intent.message'),
        nonce_b64u: readString(intent.nonce_b64u, 'normalSigningRequest.intent.nonce_b64u'),
        ...(callbackUrl ? { callback_url: callbackUrl } : {}),
      };
    }
    case 'near_delegate_action_v1': {
      rejectUnknownEmailOtpYaoFields(
        intent,
        [
          'kind',
          'operation_id',
          'operation_fingerprint',
          'near_account_id',
          'near_network_id',
          'delegate',
        ],
        'normalSigningRequest.intent',
      );
      const delegate = workerPayloadObject(intent.delegate);
      if (!delegate) throw new Error('normalSigningRequest.intent.delegate is required');
      rejectUnknownEmailOtpYaoFields(
        delegate,
        [
          'sender_id',
          'receiver_id',
          'public_key',
          'nonce',
          'max_block_height',
          'action_fingerprint',
          'canonical_delegate_borsh_b64u',
        ],
        'normalSigningRequest.intent.delegate',
      );
      return {
        kind: 'near_delegate_action_v1',
        operation_id: readString(
          intent.operation_id,
          'normalSigningRequest.intent.operation_id',
        ),
        operation_fingerprint: readString(
          intent.operation_fingerprint,
          'normalSigningRequest.intent.operation_fingerprint',
        ),
        near_account_id: readString(
          intent.near_account_id,
          'normalSigningRequest.intent.near_account_id',
        ),
        near_network_id: parseEmailOtpOperationStepUpNearNetworkId(intent.near_network_id),
        delegate: {
          sender_id: readString(
            delegate.sender_id,
            'normalSigningRequest.intent.delegate.sender_id',
          ),
          receiver_id: readString(
            delegate.receiver_id,
            'normalSigningRequest.intent.delegate.receiver_id',
          ),
          public_key: readString(
            delegate.public_key,
            'normalSigningRequest.intent.delegate.public_key',
          ),
          nonce: readString(delegate.nonce, 'normalSigningRequest.intent.delegate.nonce'),
          max_block_height: readString(
            delegate.max_block_height,
            'normalSigningRequest.intent.delegate.max_block_height',
          ),
          action_fingerprint: readString(
            delegate.action_fingerprint,
            'normalSigningRequest.intent.delegate.action_fingerprint',
          ),
          canonical_delegate_borsh_b64u: readString(
            delegate.canonical_delegate_borsh_b64u,
            'normalSigningRequest.intent.delegate.canonical_delegate_borsh_b64u',
          ),
        },
      };
    }
    default:
      throw new Error('normalSigningRequest.intent.kind is invalid');
  }
}

function parseEmailOtpOperationStepUpNormalSigningPayload(
  value: unknown,
): RouterAbNormalSigningPrepareRequestV2Wire['signing_payload'] {
  const payload = workerPayloadObject(value);
  if (!payload) throw new Error('normalSigningRequest.signing_payload is required');
  switch (payload.kind) {
    case 'near_unsigned_transaction_borsh_v1':
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['kind', 'unsigned_transaction_borsh_b64u', 'expected_signing_digest_b64u'],
        'normalSigningRequest.signing_payload',
      );
      return {
        kind: 'near_unsigned_transaction_borsh_v1',
        unsigned_transaction_borsh_b64u: readString(
          payload.unsigned_transaction_borsh_b64u,
          'normalSigningRequest.signing_payload.unsigned_transaction_borsh_b64u',
        ),
        expected_signing_digest_b64u: readString(
          payload.expected_signing_digest_b64u,
          'normalSigningRequest.signing_payload.expected_signing_digest_b64u',
        ),
      };
    case 'nep413_message_v1':
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['kind', 'canonical_message_b64u', 'expected_signing_digest_b64u'],
        'normalSigningRequest.signing_payload',
      );
      return {
        kind: 'nep413_message_v1',
        canonical_message_b64u: readString(
          payload.canonical_message_b64u,
          'normalSigningRequest.signing_payload.canonical_message_b64u',
        ),
        expected_signing_digest_b64u: readString(
          payload.expected_signing_digest_b64u,
          'normalSigningRequest.signing_payload.expected_signing_digest_b64u',
        ),
      };
    case 'near_delegate_action_v1':
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['kind', 'canonical_delegate_borsh_b64u', 'expected_signing_digest_b64u'],
        'normalSigningRequest.signing_payload',
      );
      return {
        kind: 'near_delegate_action_v1',
        canonical_delegate_borsh_b64u: readString(
          payload.canonical_delegate_borsh_b64u,
          'normalSigningRequest.signing_payload.canonical_delegate_borsh_b64u',
        ),
        expected_signing_digest_b64u: readString(
          payload.expected_signing_digest_b64u,
          'normalSigningRequest.signing_payload.expected_signing_digest_b64u',
        ),
      };
    default:
      throw new Error('normalSigningRequest.signing_payload.kind is invalid');
  }
}

function parseEmailOtpOperationStepUpNormalSigningRequest(
  value: unknown,
): RouterAbNormalSigningPrepareRequestV2Wire {
  const request = workerPayloadObject(value);
  if (!request) throw new Error('normalSigningRequest is required');
  rejectUnknownEmailOtpYaoFields(
    request,
    ['scope', 'expires_at_ms', 'display_digest', 'intent', 'signing_payload'],
    'normalSigningRequest',
  );
  const expiresAtMs = normalizePositiveInteger(request.expires_at_ms);
  if (expiresAtMs === null) {
    throw new Error('normalSigningRequest.expires_at_ms must be a positive safe integer');
  }
  return {
    scope: parseEmailOtpOperationStepUpNormalSigningScope(request.scope),
    expires_at_ms: expiresAtMs,
    display_digest: parseEmailOtpOperationStepUpDigest(
      request.display_digest,
      'normalSigningRequest.display_digest',
    ),
    intent: parseEmailOtpOperationStepUpNormalSigningIntent(request.intent),
    signing_payload: parseEmailOtpOperationStepUpNormalSigningPayload(request.signing_payload),
  };
}

function parseEmailOtpWalletUnlockVerification(
  value: unknown,
):
  | { kind: 'otp'; challengeId?: string; otpCode: string }
  | { kind: 'email_otp_unseal_grant'; grant: string; challengeId: string } {
  const verification = workerPayloadObject(value);
  if (!verification) throw new Error('loginWithEmailOtpWallet.verification is required');
  const kind = readString(verification.kind, 'verification.kind');
  switch (kind) {
    case 'otp': {
      rejectUnknownEmailOtpYaoFields(
        verification,
        ['kind', 'challengeId', 'otpCode'],
        'loginWithEmailOtpWallet.verification',
      );
      const challengeId = optionalWorkerString(verification.challengeId);
      const otpCode = readString(verification.otpCode, 'verification.otpCode');
      if (challengeId) {
        return { kind: 'otp', challengeId, otpCode };
      }
      return {
        kind: 'otp',
        otpCode,
      };
    }
    case 'email_otp_unseal_grant': {
      rejectUnknownEmailOtpYaoFields(
        verification,
        ['kind', 'grant', 'challengeId'],
        'loginWithEmailOtpWallet.verification',
      );
      return {
        kind: 'email_otp_unseal_grant',
        grant: readString(verification.grant, 'verification.grant'),
        challengeId: readString(verification.challengeId, 'verification.challengeId'),
      };
    }
    default:
      throw new Error('loginWithEmailOtpWallet.verification.kind is invalid');
  }
}

function parseEmailOtpWorkerRequest(raw: unknown): EmailOtpWorkerRequest | null {
  const obj = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
  if (!obj) return null;
  const id = normalizeOptionalTrimmedString(obj.id);
  const type = normalizeOptionalTrimmedString(obj.type);
  const payload = workerPayloadObject(obj.payload);
  if (!id || !type || !payload) return null;

  switch (type) {
    case 'prewarmEmailOtpRegistrationCrypto':
      rejectUnknownEmailOtpYaoFields(payload, [], type);
      return { id, type, payload: {} };
    case 'requestEmailOtpChallenge':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          routePlan: readRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
        },
      };
    case 'requestEmailOtpEnrollmentChallenge':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          routePlan: readRegistrationRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
        },
      };
    case 'enrollEmailOtpWallet':
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'relayUrl',
          'walletId',
          'userId',
          'challengeId',
          'otpCode',
          'groupId',
          'routePlan',
          'googleEmailOtpRegistrationAttemptId',
          'otpChannel',
          'clientSecret32',
        ],
        type,
      );
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          ...(optionalWorkerString(payload.challengeId)
            ? { challengeId: optionalWorkerString(payload.challengeId)! }
            : {}),
          otpCode: readString(payload.otpCode, 'otpCode'),
          groupId: readString(payload.groupId, 'groupId'),
          routePlan: readRegistrationRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.googleEmailOtpRegistrationAttemptId)
            ? {
                googleEmailOtpRegistrationAttemptId: optionalWorkerString(
                  payload.googleEmailOtpRegistrationAttemptId,
                )!,
              }
            : {}),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
          ...(payload.clientSecret32 instanceof ArrayBuffer
            ? { clientSecret32: payload.clientSecret32 }
            : {}),
        },
      };
    case 'prepareEmailOtpRegistrationEnrollmentMaterial': {
      const handleRequest = parseWorkerWalletRegistrationEcdsaPrepareHandleRequest(
        payload.ecdsaClientRootHandle,
      );
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          groupId: readString(payload.groupId, 'groupId'),
          routePlan: readRegistrationRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
          ...(payload.clientSecret32 instanceof ArrayBuffer
            ? { clientSecret32: payload.clientSecret32 }
            : {}),
          ecdsaClientRootHandle: handleRequest,
          ed25519YaoFactor: parseEmailOtpEd25519YaoFactorRequest(payload.ed25519YaoFactor),
        },
      };
    }
    case 'bindEmailOtpEd25519YaoRoot':
      rejectUnknownEmailOtpYaoFields(payload, ['pendingFactorHandle', 'scope'], type);
      return {
        id,
        type,
        payload: {
          pendingFactorHandle: parseEmailOtpEd25519YaoPendingFactorHandle(
            payload.pendingFactorHandle,
          ),
          scope: parseEmailOtpEd25519YaoRootScope(payload.scope),
        },
      };
    case 'disposeEmailOtpEd25519YaoPendingFactor':
      rejectUnknownEmailOtpYaoFields(payload, ['pendingFactorHandle'], type);
      return {
        id,
        type,
        payload: {
          pendingFactorHandle: parseEmailOtpEd25519YaoPendingFactorHandle(
            payload.pendingFactorHandle,
          ),
        },
      };
    case 'disposeEmailOtpEd25519YaoRoot':
      rejectUnknownEmailOtpYaoFields(payload, ['rootHandle'], type);
      return {
        id,
        type,
        payload: {
          rootHandle: parseEmailOtpEd25519YaoRootHandle(payload.rootHandle),
        },
      };
    case 'disposeEmailOtpEcdsaClientRootHandle':
      rejectUnknownEmailOtpYaoFields(payload, ['clientRootShareHandle'], type);
      return {
        id,
        type,
        payload: {
          clientRootShareHandle: parseWorkerIssuedEcdsaSessionBootstrapClientRootHandle(
            payload.clientRootShareHandle,
          ),
        },
      };
    case 'startEmailOtpEd25519YaoRegistration':
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'rootHandle',
          'admissionRequest',
          'admissionReceipt',
          'walletId',
          'providerSubject',
          'registrationAuthorityId',
          'bearerToken',
          'routerOrigin',
        ],
        type,
      );
      return {
        id,
        type,
        payload: {
          rootHandle: parseEmailOtpEd25519YaoRootHandle(payload.rootHandle),
          admissionRequest: parseEmailOtpEd25519YaoRegistrationAdmission(payload.admissionRequest),
          admissionReceipt: parseEmailOtpEd25519YaoRegistrationAdmissionReceipt(
            payload.admissionReceipt,
          ),
          walletId: readString(payload.walletId, 'walletId'),
          providerSubject: readString(payload.providerSubject, 'providerSubject'),
          registrationAuthorityId: readString(
            payload.registrationAuthorityId,
            'registrationAuthorityId',
          ),
          bearerToken: readString(payload.bearerToken, 'bearerToken'),
          routerOrigin: readString(payload.routerOrigin, 'routerOrigin'),
        },
      };
    case 'persistEmailOtpEd25519YaoRegistrationMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'pendingHandle',
          'walletId',
          'providerSubject',
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'signerSlot',
          'signingRootVersion',
          'expectedOperationalPublicKey',
          'sessionPolicy',
        ],
        type,
      );
      const signerSlot = normalizePositiveInteger(payload.signerSlot);
      if (signerSlot === null) {
        throw new Error('signerSlot must be a positive safe integer');
      }
      return {
        id,
        type,
        payload: {
          pendingHandle: readString(payload.pendingHandle, 'pendingHandle'),
          walletId: readString(payload.walletId, 'walletId'),
          providerSubject: readString(payload.providerSubject, 'providerSubject'),
          nearAccountId: readString(payload.nearAccountId, 'nearAccountId'),
          nearEd25519SigningKeyId: readString(
            payload.nearEd25519SigningKeyId,
            'nearEd25519SigningKeyId',
          ),
          signerSlot,
          signingRootVersion: readString(payload.signingRootVersion, 'signingRootVersion'),
          expectedOperationalPublicKey: readString(
            payload.expectedOperationalPublicKey,
            'expectedOperationalPublicKey',
          ),
          sessionPolicy: parseEmailOtpEd25519YaoSessionPolicy(payload.sessionPolicy),
        },
      };
    }
    case 'disposeEmailOtpEd25519YaoRegistration':
      rejectUnknownEmailOtpYaoFields(payload, ['pendingHandle'], type);
      return {
        id,
        type,
        payload: { pendingHandle: readString(payload.pendingHandle, 'pendingHandle') },
      };
    case 'recoverEmailOtpEd25519Yao':
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'rootHandle',
          'admissionRequest',
          'walletId',
          'nearAccountId',
          'signingRootVersion',
          'providerSubject',
          'registrationAuthorityId',
          'bearerToken',
          'routerOrigin',
          'sessionPolicy',
        ],
        type,
      );
      return {
        id,
        type,
        payload: {
          rootHandle: parseEmailOtpEd25519YaoRootHandle(payload.rootHandle),
          admissionRequest: parseEmailOtpEd25519YaoRecoveryAdmission(payload.admissionRequest),
          walletId: readString(payload.walletId, 'walletId'),
          nearAccountId: readString(payload.nearAccountId, 'nearAccountId'),
          signingRootVersion: readString(payload.signingRootVersion, 'signingRootVersion'),
          providerSubject: readString(payload.providerSubject, 'providerSubject'),
          registrationAuthorityId: readString(
            payload.registrationAuthorityId,
            'registrationAuthorityId',
          ),
          bearerToken: readString(payload.bearerToken, 'bearerToken'),
          routerOrigin: readString(payload.routerOrigin, 'routerOrigin'),
          sessionPolicy: parseEmailOtpEd25519YaoSessionPolicy(payload.sessionPolicy),
        },
      };
    case 'rehydrateEmailOtpEd25519YaoOperationMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'relayUrl',
          'walletId',
          'nearAccountId',
          'signerSlot',
          'providerSubjectId',
          'expectedOperationalPublicKey',
          'expectedThresholdSessionId',
          'expectedMaterialActivation',
          'normalSigningRequest',
          'displayDigest',
          'proof',
        ],
        type,
      );
      const signerSlot = normalizePositiveInteger(payload.signerSlot);
      if (signerSlot === null) {
        throw new Error('signerSlot must be a positive safe integer');
      }
      const expectedMaterialActivation = parseMpcMaterialActivationRef(
        payload.expectedMaterialActivation,
      );
      if (!expectedMaterialActivation.ok) {
        throw new Error(expectedMaterialActivation.error.message);
      }
      const proof = workerPayloadObject(payload.proof);
      if (!proof) {
        throw new Error('Email OTP Ed25519 operation proof is required');
      }
      rejectUnknownEmailOtpYaoFields(
        proof,
        ['kind', 'authorityRef', 'providerSubjectId', 'challengeId', 'otpCode'],
        'proof',
      );
      if (proof.kind !== 'email_otp') {
        throw new Error('Email OTP Ed25519 operation proof kind is invalid');
      }
      const authorityRef = parseWalletAuthAuthorityRef(proof.authorityRef);
      if (!authorityRef) {
        throw new Error('Email OTP Ed25519 operation proof authority is invalid');
      }
      const walletId = readString(payload.walletId, 'walletId');
      const providerSubjectId = readString(payload.providerSubjectId, 'providerSubjectId');
      const proofProviderSubjectId = readString(
        proof.providerSubjectId,
        'proof.providerSubjectId',
      );
      if (
        String(authorityRef.walletId) !== walletId ||
        proofProviderSubjectId !== providerSubjectId
      ) {
        throw new Error('Email OTP Ed25519 operation proof changed material authority');
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId,
          nearAccountId: readString(payload.nearAccountId, 'nearAccountId'),
          signerSlot,
          providerSubjectId,
          expectedOperationalPublicKey: readString(
            payload.expectedOperationalPublicKey,
            'expectedOperationalPublicKey',
          ),
          expectedThresholdSessionId: readThresholdEd25519SessionId(
            payload.expectedThresholdSessionId,
            'expectedThresholdSessionId',
          ),
          expectedMaterialActivation: expectedMaterialActivation.value,
          normalSigningRequest: parseEmailOtpOperationStepUpNormalSigningRequest(
            payload.normalSigningRequest,
          ),
          displayDigest: readString(payload.displayDigest, 'displayDigest'),
          proof: {
            kind: 'email_otp',
            authorityRef,
            providerSubjectId: proofProviderSubjectId,
            challengeId: readString(proof.challengeId, 'proof.challengeId'),
            otpCode: readString(proof.otpCode, 'proof.otpCode'),
          },
        },
      };
    }
    case 'createEmailOtpEd25519YaoSigningShare':
      rejectUnknownEmailOtpYaoFields(payload, ['activeClientHandle', 'input'], type);
      return {
        id,
        type,
        payload: {
          activeClientHandle: readString(payload.activeClientHandle, 'activeClientHandle'),
          input: parseEmailOtpEd25519YaoSigningInput(payload.input),
        },
      };
    case 'disposeEmailOtpEd25519YaoActiveClient':
      rejectUnknownEmailOtpYaoFields(payload, ['activeClientHandle'], type);
      return {
        id,
        type,
        payload: {
          activeClientHandle: readString(payload.activeClientHandle, 'activeClientHandle'),
        },
      };
    case 'verifyEmailOtpCode':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          challengeId: readString(payload.challengeId, 'challengeId'),
          otpCode: readString(payload.otpCode, 'otpCode'),
          routePlan: readRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
        },
      };
    case 'restoreEmailOtpDeviceEnrollmentEscrow':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          challengeId: readString(payload.challengeId, 'challengeId'),
          otpCode: readString(payload.otpCode, 'otpCode'),
          recoveryKey: readString(payload.recoveryKey, 'recoveryKey'),
          groupId: readString(payload.groupId, 'groupId'),
          routePlan: readRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
        },
      };
    case 'rotateEmailOtpRecoveryCodes':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          routePlan: readRoutePlan(payload.routePlan, type),
        },
      };
    case 'removeEmailOtpDeviceEnrollmentEscrowFromDevice':
      return {
        id,
        type,
        payload: {
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          ...(optionalWorkerString(payload.enrollmentId)
            ? { enrollmentId: optionalWorkerString(payload.enrollmentId)! }
            : {}),
        },
      };
    case 'loginWithEmailOtpWallet':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          groupId: readString(payload.groupId, 'groupId'),
          routePlan: readRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
          verification: parseEmailOtpWalletUnlockVerification(payload.verification),
          material: parseEmailOtpWalletUnlockMaterialRequest(payload.material),
        },
      };
    case 'bindEmailOtpEcdsaWarmSessionFromWorkerHandle':
      return {
        id,
        type,
        payload: {
          clientRootShareHandle: parseWorkerIssuedEcdsaSessionBootstrapClientRootHandle(
            payload.clientRootShareHandle,
          ),
          thresholdSessionId: readString(payload.thresholdSessionId, 'thresholdSessionId'),
          remainingUses: normalizeNonNegativeInteger(payload.remainingUses) ?? 0,
          expiresAtMs: readNumber(payload.expiresAtMs, 'expiresAtMs'),
        },
      };
    case 'getEmailOtpWarmSessionStatus':
    case 'clearEmailOtpWarmSessionMaterial':
      return {
        id,
        type,
        payload: { target: parseEmailOtpWarmMaterialTarget(payload.target) },
      };
    case 'consumeEmailOtpWarmSessionUses':
      return {
        id,
        type,
        payload: {
          target: parseEmailOtpWarmMaterialTarget(payload.target),
          ...(optionalWorkerPositiveInteger(payload.uses)
            ? { uses: optionalWorkerPositiveInteger(payload.uses)! }
            : {}),
        },
      };
    case 'sealEmailOtpWarmSessionMaterial':
      return {
        id,
        type,
        payload: {
          target: parseEmailOtpWarmMaterialTarget(payload.target),
          transport: parseWorkerSealTransport(payload.transport),
        },
      };
    case 'rehydrateEmailOtpEcdsaWarmSessionMaterial': {
      const restore = workerPayloadObject(payload.restore);
      if (!restore) throw new Error('Email OTP ECDSA rehydrate requires restore payload');
      const target = parseEmailOtpWarmMaterialTarget(payload.target);
      if (target.kind !== 'ecdsa') {
        throw new Error('Email OTP ECDSA rehydrate requires an ECDSA target');
      }
      return {
        id,
        type,
        payload: {
          target,
          sealedSecretB64u: readString(payload.sealedSecretB64u, 'sealedSecretB64u'),
          remainingUses: normalizeNonNegativeInteger(payload.remainingUses) ?? 0,
          expiresAtMs: readNumber(payload.expiresAtMs, 'expiresAtMs'),
          transport: parseWorkerSealTransport(payload.transport),
          restore: {
            thresholdSessionId: readString(
              restore.thresholdSessionId,
              'restore.thresholdSessionId',
            ),
            walletId: readString(restore.walletId, 'restore.walletId'),
            keyHandle: readString(restore.keyHandle, 'restore.keyHandle'),
            chainTarget: parseWorkerChainTarget(restore.chainTarget),
            authSubjectId: readString(restore.authSubjectId, 'restore.authSubjectId'),
          },
        },
      };
    }
    case 'rehydrateEmailOtpEd25519YaoLocalMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['target', 'sealedSecretB64u', 'remainingUses', 'expiresAtMs', 'transport', 'restore'],
        type,
      );
      const restore = workerPayloadObject(payload.restore);
      if (!restore) throw new Error('Email OTP Ed25519 Yao rehydrate requires restore payload');
      const target = parseEmailOtpWarmMaterialTarget(payload.target);
      if (target.kind !== 'ed25519_yao') {
        throw new Error('Email OTP Ed25519 Yao rehydrate requires an Ed25519 Yao target');
      }
      rejectUnknownEmailOtpYaoFields(
        restore,
        ['session', 'providerSubject', 'signerSlot', 'expectedOperationalPublicKey'],
        'restore',
      );
      return {
        id,
        type,
        payload: {
          target,
          sealedSecretB64u: readString(payload.sealedSecretB64u, 'sealedSecretB64u'),
          remainingUses: normalizeNonNegativeInteger(payload.remainingUses) ?? 0,
          expiresAtMs: readNumber(payload.expiresAtMs, 'expiresAtMs'),
          transport: parseRequiredWorkerSealTransport(payload.transport),
          restore: {
            session: parseEmailOtpEd25519YaoBootstrapSession(restore.session),
            providerSubject: readString(restore.providerSubject, 'restore.providerSubject'),
            signerSlot: normalizePositiveInteger(restore.signerSlot) || 0,
            expectedOperationalPublicKey: readString(
              restore.expectedOperationalPublicKey,
              'restore.expectedOperationalPublicKey',
            ),
          },
        },
      };
    }
    case 'exportEmailOtpEd25519YaoSeedWithAuthorization': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'relayUrl',
          'challengeId',
          'otpCode',
          'groupId',
          'lane',
          'authorization',
          'material',
        ],
        type,
      );
      const lane = workerPayloadObject(payload.lane);
      const authorization = workerPayloadObject(payload.authorization);
      const material = workerPayloadObject(payload.material);
      if (!lane || !authorization || !material) {
        throw new Error(`${type} requires canonical lane, authorization, and material`);
      }
      rejectUnknownEmailOtpYaoFields(
        lane,
        [
          'walletId',
          'providerSubjectId',
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'signerSlot',
        ],
        `${type}.lane`,
      );
      rejectUnknownEmailOtpYaoFields(authorization, ['walletSessionJwt'], `${type}.authorization`);
      rejectUnknownEmailOtpYaoFields(material, ['materialActivation', 'capability'], `${type}.material`);
      const materialActivation = parseMpcMaterialActivationRef(material.materialActivation);
      if (!materialActivation.ok) {
        throw new Error(materialActivation.error.message);
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          challengeId: readString(payload.challengeId, 'challengeId'),
          otpCode: readString(payload.otpCode, 'otpCode'),
          groupId: readString(payload.groupId, 'groupId'),
          lane: {
            walletId: readString(lane.walletId, `${type}.lane.walletId`),
            providerSubjectId: readString(
              lane.providerSubjectId,
              `${type}.lane.providerSubjectId`,
            ),
            nearAccountId: readString(lane.nearAccountId, `${type}.lane.nearAccountId`),
            nearEd25519SigningKeyId: readString(
              lane.nearEd25519SigningKeyId,
              `${type}.lane.nearEd25519SigningKeyId`,
            ),
            signerSlot: normalizePositiveInteger(lane.signerSlot) || 0,
          },
          authorization: {
            walletSessionJwt: readString(
              authorization.walletSessionJwt,
              `${type}.authorization.walletSessionJwt`,
            ),
          },
          material: {
            materialActivation: materialActivation.value,
            capability: parseEmailOtpEd25519YaoWorkerActiveCapability(material.capability),
          },
        },
      };
    }
    default:
      return null;
  }
}

setTimeout(() => {
  postToMainThread({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  if (attachEcdsaPresignChannel(event.data)) return;
  const msg = parseEmailOtpWorkerRequest(event.data);
  if (!msg) return;

  try {
    switch (msg.type) {
      case 'prewarmEmailOtpRegistrationCrypto': {
        const startedAt = performance.now();
        try {
          await getEmailOtpYaoClient();
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              kind: 'succeeded',
              elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
            },
          });
        } catch {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              kind: 'failed',
              elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
              failureStage: 'yao_wasm_init',
            },
          });
        }
        return;
      }
      case 'requestEmailOtpChallenge': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'requestEmailOtpChallenge');
        const sessionAuth = authLaneToRouteAuth(routePlan.authLane);
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'challenge'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: EMAIL_OTP_CHANNEL,
            operation: routePlan.operation,
          },
        });
        assertEmailOtpChallengeAction({
          response,
          expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
          label: 'Email OTP login challenge',
        });
        const challenge = response.challenge as Record<string, unknown>;
        const delivery = parseEmailOtpChallengeDelivery(
          response.delivery,
          'Email OTP login challenge delivery',
        );
        const expiresAtMs = Number(challenge?.expiresAtMs);
        const appSessionVersion = String(challenge?.appSessionVersion || '').trim();
        const result: {
          challengeId: string;
          otpChannel: typeof EMAIL_OTP_CHANNEL;
          delivery: EmailOtpChallengeDelivery;
          emailHint?: string;
          expiresAtMs?: number;
          appSessionVersion?: string;
        } = {
          challengeId: readString(challenge?.challengeId, 'challengeId'),
          otpChannel: EMAIL_OTP_CHANNEL,
          delivery,
          emailHint: delivery.emailHint,
        };
        if (Number.isFinite(expiresAtMs)) {
          result.expiresAtMs = expiresAtMs;
        }
        if (appSessionVersion) {
          result.appSessionVersion = appSessionVersion;
        }
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'requestEmailOtpEnrollmentChallenge': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'requestEmailOtpEnrollmentChallenge',
        );
        const sessionAuth = authLaneToRouteAuth(routePlan.authLane);
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'challenge'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            otpChannel: EMAIL_OTP_CHANNEL,
          },
        });
        assertEmailOtpChallengeAction({
          response,
          expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
          label: 'Email OTP registration challenge',
        });
        const challenge = response.challenge as Record<string, unknown>;
        const delivery = parseEmailOtpChallengeDelivery(
          response.delivery,
          'Email OTP registration challenge delivery',
        );
        const expiresAtMs = Number(challenge?.expiresAtMs);
        const appSessionVersion = String(challenge?.appSessionVersion || '').trim();
        const result: {
          challengeId: string;
          otpChannel: typeof EMAIL_OTP_CHANNEL;
          delivery: EmailOtpChallengeDelivery;
          emailHint?: string;
          expiresAtMs?: number;
          appSessionVersion?: string;
        } = {
          challengeId: readString(challenge?.challengeId, 'challengeId'),
          otpChannel: EMAIL_OTP_CHANNEL,
          delivery,
          emailHint: delivery.emailHint,
        };
        if (Number.isFinite(expiresAtMs)) {
          result.expiresAtMs = expiresAtMs;
        }
        if (appSessionVersion) {
          result.appSessionVersion = appSessionVersion;
        }
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'enrollEmailOtpWallet': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'enrollEmailOtpWallet');
        const result = await completeEmailOtpEnrollmentFromSecret32({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          groupId: readString(msg.payload.groupId, 'groupId'),
          routePlan,
          googleEmailOtpRegistrationAttemptId: msg.payload.googleEmailOtpRegistrationAttemptId,
          onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
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
          result: {
            thresholdEcdsaClientVerifyingShareB64u: result.thresholdEcdsaClientVerifyingShareB64u,
            recoveryKeys: result.recoveryKeys,
            recoveryCodesIssuedAtMs: result.recoveryCodesIssuedAtMs,
            challengeId: result.challengeId,
            otpChannel: result.otpChannel,
            enrollmentId: result.enrollmentId,
            enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
            clientUnlockPublicKeyB64u: result.clientUnlockPublicKeyB64u,
            unlockKeyVersion: result.unlockKeyVersion,
          },
        });
        return;
      }
      case 'prepareEmailOtpRegistrationEnrollmentMaterial': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'prepareEmailOtpRegistrationEnrollmentMaterial',
        );
        const result = await completeEmailOtpEnrollmentFromSecret32({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          groupId: readString(msg.payload.groupId, 'groupId'),
          routePlan,
          returnClientRootShare32: true,
          returnClientSecret32: msg.payload.ed25519YaoFactor.kind === 'requested',
          skipServerFinalize: true,
          onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
          ...(msg.payload.clientSecret32 instanceof ArrayBuffer
            ? {
                clientSecret32: requireFixed32ArrayBuffer(
                  msg.payload.clientSecret32,
                  'clientSecret32',
                ),
              }
            : {}),
        });
        try {
          const walletId = readString(msg.payload.walletId, 'walletId');
          const clientRootShareHandle = issueEmailOtpWalletRegistrationEcdsaHandleResult({
            request: msg.payload.ecdsaClientRootHandle,
            clientRootShare32: result.clientRootShare32,
            walletId,
          });
          const ed25519YaoFactor = issueEmailOtpEd25519YaoPendingFactor({
            request: msg.payload.ed25519YaoFactor,
            purpose: 'registration',
            walletId,
            ownedFactorSecret32: result.clientSecret32,
          });
          try {
            postToMainThread({
              id: msg.id,
              ok: true,
              result: {
                thresholdEcdsaClientVerifyingShareB64u:
                  result.thresholdEcdsaClientVerifyingShareB64u,
                recoveryKeys: result.recoveryKeys,
                recoveryCodesIssuedAtMs: result.recoveryCodesIssuedAtMs,
                otpChannel: result.otpChannel,
                enrollmentId: result.enrollmentId,
                enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
                clientUnlockPublicKeyB64u: result.clientUnlockPublicKeyB64u,
                unlockKeyVersion: result.unlockKeyVersion,
                clientRootShareHandle,
                ed25519YaoFactor,
                emailOtpEnrollment: result.emailOtpEnrollment,
              },
            });
          } catch (error) {
            rollbackEmailOtpEd25519YaoFactorResult(ed25519YaoFactor);
            throw error;
          }
        } finally {
          zeroizeBytes(result.clientRootShare32);
          zeroizeBytes(result.clientSecret32);
        }
        return;
      }
      case 'bindEmailOtpEd25519YaoRoot': {
        const rootHandle = emailOtpEd25519YaoRootVault.bindPending({
          handle: msg.payload.pendingFactorHandle,
          scope: msg.payload.scope,
          expiresAtMs: msg.payload.pendingFactorHandle.expiresAtMs,
          nowMs: Date.now(),
        });
        postToMainThread({ id: msg.id, ok: true, result: { rootHandle } });
        return;
      }
      case 'disposeEmailOtpEd25519YaoPendingFactor': {
        const removed = emailOtpEd25519YaoRootVault.removePending(msg.payload.pendingFactorHandle);
        postToMainThread({ id: msg.id, ok: true, result: { removed } });
        return;
      }
      case 'disposeEmailOtpEd25519YaoRoot': {
        const removed = emailOtpEd25519YaoRootVault.remove(msg.payload.rootHandle);
        postToMainThread({ id: msg.id, ok: true, result: { removed } });
        return;
      }
      case 'disposeEmailOtpEcdsaClientRootHandle': {
        const removed = disposeEmailOtpEcdsaClientRootHandle(msg.payload.clientRootShareHandle);
        postToMainThread({ id: msg.id, ok: true, result: { removed } });
        return;
      }
      case 'startEmailOtpEd25519YaoRegistration': {
        const result = await registerEmailOtpEd25519YaoV1({
          vault: emailOtpEd25519YaoRootVault,
          input: {
            kind: 'email_otp_ed25519_yao_registration_input_v1',
            rootHandle: msg.payload.rootHandle,
            admissionRequest: msg.payload.admissionRequest,
            admissionReceipt: msg.payload.admissionReceipt,
            authority: {
              kind: 'verified_email_otp_ed25519_yao_authority_v1',
              walletId: msg.payload.walletId,
              providerSubject: msg.payload.providerSubject,
              registrationAuthorityId: msg.payload.registrationAuthorityId,
              bearerToken: msg.payload.bearerToken,
            },
            transport: {
              kind: 'email_otp_ed25519_yao_http_transport_v1',
              routerOrigin: msg.payload.routerOrigin,
              fetch: globalThis.fetch.bind(globalThis),
            },
            nowMs: Date.now(),
          },
        });
        if (!result.ok) throw new Error(result.message);
        const pending = result.value.registration;
        const factorSecret32 = result.value.retainedFactorSecret32;
        const operationalPublicKey = pending.publicKey();
        const activationReference = pending.activationReference();
        const pendingHandle = await storeEmailOtpEd25519YaoPendingRegistration(
          pending,
          factorSecret32,
        );
        try {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              pendingHandle,
              operationalPublicKey,
              activationReference,
              // Email OTP runs Yao in this worker, so the Router breakdown
              // only reaches the main thread by riding this response.
              ...(result.value.routerServerTiming
                ? { routerServerTiming: result.value.routerServerTiming }
                : {}),
              ...(result.value.clientTimings ? { clientTimings: result.value.clientTimings } : {}),
            },
          });
        } catch (error) {
          await disposeEmailOtpEd25519YaoPendingRegistration(pendingHandle);
          throw error;
        }
        return;
      }
      case 'persistEmailOtpEd25519YaoRegistrationMaterial': {
        const entry = emailOtpEd25519YaoPendingRegistrations.get(msg.payload.pendingHandle);
        if (!entry) {
          throw new Error('Email OTP Ed25519 Yao pending registration is unavailable');
        }
        emailOtpEd25519YaoPendingRegistrations.delete(msg.payload.pendingHandle);
        let persistedMetadata: RouterAbEd25519YaoActiveClientMetadataV1 | null = null;
        let activationResult: EmailOtpEd25519YaoWorkerActivationResult | null = null;
        try {
          const metadata = await entry.pending.persistRegistrationMaterial({
            kind: 'browser_owned',
            persistence: new EmailOtpEd25519YaoRegistrationMaterialPersistencePort(
              {
                walletId: msg.payload.walletId,
                nearAccountId: msg.payload.nearAccountId,
                providerSubjectId: msg.payload.providerSubject,
                signingRootVersion: msg.payload.signingRootVersion,
              },
              entry.factorSecret32,
            ),
          });
          if (
            `ed25519:${base58Encode(metadata.registeredPublicKey)}` !==
              msg.payload.expectedOperationalPublicKey ||
            metadata.applicationBinding.wallet_id !== msg.payload.walletId ||
            metadata.applicationBinding.near_ed25519_signing_key_id !==
              msg.payload.nearEd25519SigningKeyId ||
            metadata.applicationBinding.key_creation_signer_slot !== msg.payload.signerSlot ||
            metadata.scope.root_share_epoch !== msg.payload.signingRootVersion
          ) {
            throw new Error('Email OTP Ed25519 registration material changed signer identity');
          }
          persistedMetadata = metadata;
          const localMaterial = await readEmailOtpEd25519YaoLocalMaterialByLocatorV1({
            store: IndexedDBManager,
            walletId: msg.payload.walletId,
            nearAccountId: msg.payload.nearAccountId,
            signerSlot: msg.payload.signerSlot,
            providerSubjectId: msg.payload.providerSubject,
            expectedOperationalPublicKey: msg.payload.expectedOperationalPublicKey,
          });
          if (localMaterial.kind !== 'exact_material_ready') {
            throw new Error(
              `Email OTP Ed25519 registration local material is unavailable (${localMaterial.kind})`,
            );
          }
          activationResult = await importEmailOtpEd25519YaoLocalMaterial({
            material: localMaterial.material,
            expectedThresholdSessionId: msg.payload.sessionPolicy.thresholdSessionId,
            enrollmentSecret32: entry.factorSecret32,
          });
          if (
            !mpcMaterialActivationRefsEqual(
              activationResult.metadata.materialActivation,
              metadata.materialActivation,
            ) ||
            activationResult.metadata.scope.threshold_session_id !==
              msg.payload.sessionPolicy.thresholdSessionId
          ) {
            throw new Error('Email OTP Ed25519 registration active material changed identity');
          }
          putEmailOtpEd25519YaoWarmFactor({
            target: {
              kind: 'ed25519_yao',
              thresholdSessionId: msg.payload.sessionPolicy.thresholdSessionId,
              materialActivation: metadata.materialActivation,
            },
            factorSecret32: entry.factorSecret32,
            expiresAtMs: msg.payload.sessionPolicy.expiresAtMs,
            remainingUses: msg.payload.sessionPolicy.remainingUses,
          });
        } catch (error) {
          if (activationResult) {
            removeEmailOtpEd25519YaoActiveClient(activationResult.activeClientHandle);
            if (persistedMetadata) {
              deleteEmailOtpEd25519YaoWarmFactor(persistedMetadata.materialActivation);
            }
          }
          throw error;
        } finally {
          zeroizeBytes(entry.factorSecret32);
          await entry.pending.dispose();
        }
        if (!persistedMetadata || !activationResult) {
          throw new Error('Email OTP Ed25519 registration material was not persisted');
        }
        try {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              metadata: persistedMetadata,
              activeClientHandle: activationResult.activeClientHandle,
            },
          });
        } catch (error) {
          removeEmailOtpEd25519YaoActiveClient(activationResult.activeClientHandle);
          throw error;
        }
        return;
      }
      case 'disposeEmailOtpEd25519YaoRegistration': {
        const removed = await disposeEmailOtpEd25519YaoPendingRegistration(
          msg.payload.pendingHandle,
        );
        postToMainThread({ id: msg.id, ok: true, result: { removed } });
        return;
      }
      case 'recoverEmailOtpEd25519Yao': {
        const result = await recoverEmailOtpEd25519YaoV1({
          vault: emailOtpEd25519YaoRootVault,
          input: {
            kind: 'email_otp_ed25519_yao_recovery_input_v1',
            rootHandle: msg.payload.rootHandle,
            admissionRequest: msg.payload.admissionRequest,
            authority: {
              kind: 'verified_email_otp_ed25519_yao_authority_v1',
              walletId: msg.payload.walletId,
              providerSubject: msg.payload.providerSubject,
              registrationAuthorityId: msg.payload.registrationAuthorityId,
              bearerToken: msg.payload.bearerToken,
            },
            transport: {
              kind: 'email_otp_ed25519_yao_http_transport_v1',
              routerOrigin: msg.payload.routerOrigin,
              fetch: globalThis.fetch.bind(globalThis),
            },
            nowMs: Date.now(),
          },
        });
        if (!result.ok) throw new Error(result.message);
        if (!result.value.recovery.ok) {
          zeroizeBytes(result.value.retainedFactorSecret32);
          throw new Error(result.value.recovery.message);
        }
        const activeClient = result.value.recovery.activeClient;
        let activationResult: EmailOtpEd25519YaoWorkerActivationResult;
        try {
          activationResult = storeEmailOtpEd25519YaoActiveClient(activeClient);
          await persistEmailOtpEd25519YaoActiveClientLocalMaterial({
            activeClient,
            metadata: activationResult.metadata,
            walletIdentity: {
              walletId: msg.payload.walletId,
              nearAccountId: msg.payload.nearAccountId,
              providerSubjectId: msg.payload.providerSubject,
              signingRootVersion: msg.payload.signingRootVersion,
            },
            enrollmentSecret32: result.value.retainedFactorSecret32,
          });
          putEmailOtpEd25519YaoWarmFactor({
            target: {
              kind: 'ed25519_yao',
              thresholdSessionId: msg.payload.sessionPolicy.thresholdSessionId,
              materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
                activationResult.metadata,
              ),
            },
            factorSecret32: result.value.retainedFactorSecret32,
            expiresAtMs: msg.payload.sessionPolicy.expiresAtMs,
            remainingUses: msg.payload.sessionPolicy.remainingUses,
          });
          zeroizeBytes(result.value.retainedFactorSecret32);
        } catch (error) {
          zeroizeBytes(result.value.retainedFactorSecret32);
          activeClient.dispose();
          throw error;
        }
        const activation: RouterAbEd25519YaoRecoveryActivationReceiptV1 =
          result.value.recovery.activation;
        try {
          postToMainThread({
            id: msg.id,
            ok: true,
            result: { ...activationResult, activation },
          });
        } catch (error) {
          removeEmailOtpEd25519YaoActiveClient(activationResult.activeClientHandle);
          throw error;
        }
        return;
      }
      case 'createEmailOtpEd25519YaoSigningShare': {
        const entry = emailOtpEd25519YaoActiveClients.get(msg.payload.activeClientHandle);
        if (!entry || entry.activeClient.status().kind !== 'active') {
          if (entry) {
            emailOtpEd25519YaoActiveClients.delete(msg.payload.activeClientHandle);
          }
          throw new Error('Email OTP Ed25519 Yao active Client is unavailable');
        }
        const share = await entry.activeClient.createSigningShare(msg.payload.input);
        postToMainThread({
          id: msg.id,
          ok: true,
          result: cloneEmailOtpEd25519YaoSigningShare(share),
        });
        return;
      }
      case 'disposeEmailOtpEd25519YaoActiveClient': {
        const removed = removeEmailOtpEd25519YaoActiveClient(msg.payload.activeClientHandle);
        postToMainThread({ id: msg.id, ok: true, result: { removed } });
        return;
      }
      case 'verifyEmailOtpCode': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'verifyEmailOtpCode');
        const sessionAuth = authLaneToRouteAuth(routePlan.authLane);
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'verify'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            challengeId: readString(msg.payload.challengeId, 'challengeId'),
            otpCode: readString(msg.payload.otpCode, 'otpCode'),
            otpChannel: EMAIL_OTP_CHANNEL,
            operation: routePlan.operation,
          },
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result: {
            loginGrant: readString(response.loginGrant, 'loginGrant'),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(readOptionalString(response.enrollmentSealKeyVersion)
              ? { enrollmentSealKeyVersion: readOptionalString(response.enrollmentSealKeyVersion) }
              : {}),
          },
        });
        return;
      }
      case 'restoreEmailOtpDeviceEnrollmentEscrow': {
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'restoreEmailOtpDeviceEnrollmentEscrow',
        );
        const result = await restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          challengeId: readString(msg.payload.challengeId, 'challengeId'),
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          recoveryKey: readString(msg.payload.recoveryKey, 'recoveryKey'),
          groupId: readString(msg.payload.groupId, 'groupId'),
          routePlan,
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'rotateEmailOtpRecoveryCodes': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'rotateEmailOtpRecoveryCodes');
        const result = await rotateEmailOtpRecoveryCodesFromLocalDeviceEnrollment({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          routePlan,
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'removeEmailOtpDeviceEnrollmentEscrowFromDevice': {
        const result = await removeEmailOtpDeviceEnrollmentEscrowFromDevice({
          walletId: readString(msg.payload.walletId, 'walletId'),
          userId: msg.payload.userId,
          enrollmentId: msg.payload.enrollmentId,
        });
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'loginWithEmailOtpWallet': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'loginWithEmailOtpWallet');
        const material = msg.payload.material;
        const walletId = readString(msg.payload.walletId, 'walletId');
        assertEmailOtpUnlockMaterialRouteAuth({ walletId, routePlan, material });
        const orgId = emailOtpUnlockMaterialOrgId(material);
        const result = await loginWithEmailOtpAndUnlockWallet({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId,
          ...(orgId ? { orgId } : {}),
          userId: msg.payload.userId,
          verification: msg.payload.verification,
          groupId: readString(msg.payload.groupId, 'groupId'),
          routePlan,
          material,
          onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
        });
        const recovery = {
          challengeId: result.challengeId,
          enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
          unlockChallengeId: result.unlockChallengeId,
          unlockChallengeB64u: result.unlockChallengeB64u,
          clientUnlockPublicKeyB64u: result.clientUnlockPublicKeyB64u,
          unlockSignatureB64u: result.unlockSignatureB64u,
        };
        switch (result.kind) {
          case 'ecdsa':
            if (material.kind !== 'ecdsa') {
              zeroizeBytes(result.clientRootShare32);
              throw new Error('Email OTP wallet unlock material branch changed');
            }
            try {
              postToMainThread({
                id: msg.id,
                ok: true,
                result: {
                  kind: 'ecdsa',
                  operation: material.ecdsaClientRootHandleBinding.operation,
                  recovery,
                  clientRootShareHandle: issueEmailOtpEcdsaClientRootHandle({
                    clientRootShare32: result.clientRootShare32,
                    walletId,
                    binding: material.ecdsaClientRootHandleBinding,
                  }),
                  ...(result.ecdsaSession ? { ecdsaSession: result.ecdsaSession } : {}),
                },
              });
            } finally {
              zeroizeBytes(result.clientRootShare32);
            }
            return;
          case 'wallet_unlock_capabilities': {
            if (material.kind !== 'wallet_unlock_capabilities') {
              zeroizeBytes(result.ecdsa.clientRootShare32);
              if (result.ed25519Yao.kind === 'recovery') {
                zeroizeBytes(result.ed25519Yao.clientSecret32);
              } else {
                removeEmailOtpEd25519YaoActiveClient(result.ed25519Yao.activeClientHandle);
              }
              throw new Error('Email OTP capability wallet unlock material branch changed');
            }
            let clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload | null = null;
            let ed25519YaoFactor: ReturnType<typeof issueEmailOtpEd25519YaoPendingFactor> | null =
              null;
            try {
              clientRootShareHandle = issueEmailOtpEcdsaClientRootHandle({
                clientRootShare32: result.ecdsa.clientRootShare32,
                walletId,
                binding: material.ecdsa.clientRootHandleBinding,
              });
              const ecdsa = {
                clientRootShareHandle,
                session: result.ecdsa.session,
              };
              if (result.ed25519Yao.kind === 'recovery') {
                ed25519YaoFactor = issueEmailOtpEd25519YaoPendingFactor({
                  request: {
                    kind: 'requested',
                    providerSubject: material.ed25519Yao.providerSubject,
                  },
                  purpose: 'recovery',
                  walletId,
                  ownedFactorSecret32: result.ed25519Yao.clientSecret32,
                });
                if (ed25519YaoFactor.kind !== 'issued') {
                  throw new Error(
                    'Email OTP capability unlock did not issue its Ed25519 Yao factor',
                  );
                }
                postToMainThread({
                  id: msg.id,
                  ok: true,
                  result: {
                    kind: 'wallet_unlock_capabilities',
                    operation: 'wallet_unlock',
                    recovery,
                    ecdsa,
                    ed25519Yao: {
                      kind: 'recovery',
                      pendingFactorHandle: ed25519YaoFactor.pendingFactorHandle,
                      bootstrap: result.ed25519Yao.bootstrap,
                    },
                  },
                });
                return;
              }
              postToMainThread({
                id: msg.id,
                ok: true,
                result: {
                  kind: 'wallet_unlock_capabilities',
                  operation: 'wallet_unlock',
                  recovery,
                  ecdsa,
                  ed25519Yao: result.ed25519Yao,
                },
              });
            } catch (error) {
              if (clientRootShareHandle) {
                deleteEmailOtpEcdsaClientRootHandle(clientRootShareHandle.sessionId);
              }
              if (ed25519YaoFactor?.kind === 'issued') {
                rollbackEmailOtpEd25519YaoFactorResult(ed25519YaoFactor);
              }
              if (result.ed25519Yao.kind === 'capability') {
                removeEmailOtpEd25519YaoActiveClient(result.ed25519Yao.activeClientHandle);
                deleteEmailOtpEd25519YaoWarmFactor(
                  result.ed25519Yao.bootstrap.capability.materialActivation,
                );
              }
              throw error;
            } finally {
              zeroizeBytes(result.ecdsa.clientRootShare32);
              if (result.ed25519Yao.kind === 'recovery') {
                zeroizeBytes(result.ed25519Yao.clientSecret32);
              }
            }
            return;
          }
          case 'ed25519_yao_recovery': {
            if (material.kind !== 'ed25519_yao_recovery') {
              zeroizeBytes(result.clientSecret32);
              throw new Error('Email OTP wallet unlock material branch changed');
            }
            const ed25519YaoFactor = issueEmailOtpEd25519YaoPendingFactor({
              request: {
                kind: 'requested',
                providerSubject: material.providerSubject,
              },
              purpose: 'recovery',
              walletId,
              ownedFactorSecret32: result.clientSecret32,
            });
            if (ed25519YaoFactor.kind !== 'issued') {
              throw new Error('Email OTP Ed25519 Yao recovery factor was not issued');
            }
            try {
              postToMainThread({
                id: msg.id,
                ok: true,
                result: {
                  kind: 'ed25519_yao_recovery',
                  recovery,
                  pendingFactorHandle: ed25519YaoFactor.pendingFactorHandle,
                  ed25519YaoRecovery: result.ed25519YaoRecovery,
                },
              });
            } catch (error) {
              rollbackEmailOtpEd25519YaoFactorResult(ed25519YaoFactor);
              throw error;
            } finally {
              zeroizeBytes(result.clientSecret32);
            }
            return;
          }
          case 'ed25519_yao_capability':
            if (material.kind !== 'ed25519_yao_recovery') {
              removeEmailOtpEd25519YaoActiveClient(result.activeClientHandle);
              throw new Error('Email OTP wallet unlock material branch changed');
            }
            try {
              postToMainThread({
                id: msg.id,
                ok: true,
                result: {
                  kind: 'ed25519_yao_capability',
                  recovery,
                  activeClientHandle: result.activeClientHandle,
                  metadata: result.metadata,
                  ed25519YaoCapability: result.ed25519YaoCapability,
                },
              });
            } catch (error) {
              removeEmailOtpEd25519YaoActiveClient(result.activeClientHandle);
              deleteEmailOtpEd25519YaoWarmFactor(
                result.ed25519YaoCapability.capability.materialActivation,
              );
              throw error;
            }
            return;
          case 'ed25519_yao_export':
            zeroizeBytes(result.clientSecret32);
            throw new Error('Email OTP wallet unlock returned export-only material');
          default:
            return assertNeverEmailOtpWorker(result);
        }
      }
      case 'bindEmailOtpEcdsaWarmSessionFromWorkerHandle': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: bindEmailOtpEcdsaWarmSessionFromWorkerHandle(msg.payload),
        });
        return;
      }
      case 'getEmailOtpWarmSessionStatus': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: readEmailOtpWarmSessionStatus(msg.payload.target),
        });
        return;
      }
      case 'consumeEmailOtpWarmSessionUses': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: consumeEmailOtpWarmSessionUses({
            target: msg.payload.target,
            uses: msg.payload.uses,
          }),
        });
        return;
      }
      case 'sealEmailOtpWarmSessionMaterial': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await sealEmailOtpWarmSessionMaterial({
              target: msg.payload.target,
              transport,
            })
          : {
              ok: false,
              code: 'invalid_args',
              message: 'Invalid signing-session seal transport',
            };
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'rehydrateEmailOtpEcdsaWarmSessionMaterial': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await rehydrateEmailOtpEcdsaWarmSessionMaterial({
              target: msg.payload.target,
              sealedSecretB64u: readString(msg.payload.sealedSecretB64u, 'sealedSecretB64u'),
              remainingUses: Math.floor(Number(msg.payload.remainingUses) || 0),
              expiresAtMs: Math.floor(Number(msg.payload.expiresAtMs) || 0),
              transport,
              restore: msg.payload.restore,
            })
          : {
              ok: false,
              code: 'invalid_args',
              message: 'Invalid signing-session seal transport',
            };
        postToMainThread({
          id: msg.id,
          ok: true,
          result,
        });
        return;
      }
      case 'rehydrateEmailOtpEd25519YaoLocalMaterial': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await rehydrateEmailOtpEd25519YaoLocalMaterial({
              target: msg.payload.target,
              sealedSecretB64u: readString(msg.payload.sealedSecretB64u, 'sealedSecretB64u'),
              remainingUses: msg.payload.remainingUses,
              expiresAtMs: msg.payload.expiresAtMs,
              transport,
              restore: msg.payload.restore,
            })
          : {
              ok: false as const,
              code: 'invalid_args',
              message: 'Invalid signing-session seal transport',
            };
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'rehydrateEmailOtpEd25519YaoOperationMaterial': {
        const result = await rehydrateEmailOtpEd25519YaoOperationMaterial(msg.payload);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'clearEmailOtpWarmSessionMaterial': {
        deleteEmailOtpWarmMaterial(msg.payload.target);
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
      case 'exportEmailOtpEd25519YaoSeedWithAuthorization': {
        const authLane = resolveEmailOtpAuthLane({
          routeAuth: {
            kind: 'wallet_session',
            jwt: msg.payload.authorization.walletSessionJwt,
          },
          curve: 'ed25519',
        });
        if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') {
          throw new Error('Email OTP Ed25519 Yao export requires canonical signing-session auth');
        }
        const routePlan = buildEmailOtpRoutePlan({
          routeFamily: 'signing_session',
          authLane,
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        });
        const recovered = await loginWithEmailOtpAndUnlockWallet({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.lane.walletId, 'lane.walletId'),
          orgId: msg.payload.material.capability.runtimePolicyScope.orgId,
          userId: readString(msg.payload.lane.providerSubjectId, 'lane.providerSubjectId'),
          verification: {
            kind: 'otp',
            challengeId: readString(msg.payload.challengeId, 'challengeId'),
            otpCode: readString(msg.payload.otpCode, 'otpCode'),
          },
          groupId: readString(msg.payload.groupId, 'groupId'),
          routePlan,
          material: { kind: 'ed25519_yao_export' },
        });
        if (recovered.kind !== 'ed25519_yao_export') {
          throw new Error('Email OTP Ed25519 Yao export returned the wrong unlock material');
        }
        try {
          const artifact = await exportEmailOtpEd25519YaoSeed({
            relayUrl: msg.payload.relayUrl,
            walletId: msg.payload.lane.walletId,
            providerSubjectId: msg.payload.lane.providerSubjectId,
            walletSessionJwt: msg.payload.authorization.walletSessionJwt,
            nearAccountId: msg.payload.lane.nearAccountId,
            nearEd25519SigningKeyId: msg.payload.lane.nearEd25519SigningKeyId,
            signerSlot: msg.payload.lane.signerSlot,
            runtimePolicyScope: msg.payload.material.capability.runtimePolicyScope,
            capability: msg.payload.material.capability,
            clientSecret32: recovered.clientSecret32,
          });
          postToMainThread({ id: msg.id, ok: true, result: artifact });
        } finally {
          zeroizeBytes(recovered.clientSecret32);
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
