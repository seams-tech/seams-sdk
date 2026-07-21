import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { parseSigningGrantId, type SigningGrantId } from '@shared/utils/domainIds';
import {
  assertEvmFamilySigningKeySlotIdMatchesPlan,
  requireEvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import {
  joinNormalizedUrl,
  normalizeNonNegativeInteger,
  normalizeOptionalNonEmptyString,
  normalizeOptionalTrimmedString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  isAttachEmailOtpToPresignPort,
  type EmailOtpEcdsaSigningShareRequest,
  type EmailOtpEcdsaSigningShareResponse,
} from '../ecdsaClientWorkerChannels';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpChannel,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import {
  ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
  computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32B64u,
  computeEcdsaDerivationRoleLocalRelayerKeyId,
  computeEcdsaDerivationRoleLocalThresholdKeyId,
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  type EcdsaClientRootPublicKey33B64u,
  type EcdsaDerivationRoleLocalBootstrapIdentity,
  type DerivationClientSharePublicKey33B64u,
  type EcdsaDerivationRelayerPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  WALLET_SESSION_SEAL_BASE_PATH,
  parseRouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  thresholdEcdsaDerivationRoleLocalBootstrap,
  type ThresholdEcdsaDerivationRoleLocalBootstrapRequest,
  type ThresholdEcdsaDerivationRoleLocalClientRootProof,
  type ThresholdEcdsaDerivationRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import { decodeJwtPayloadRecord, type AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  buildEmailOtpWorkerIssuedSessionHandle,
  buildEmailOtpWorkerSessionSecretSource,
} from '@/core/platform/secretSources';
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
  EmailOtpWalletUnlockMaterialRequest,
  EmailOtpPrepareEcdsaClientBootstrapInput,
  EmailOtpEcdsaPublicationTargetPlan,
} from '@/core/signingEngine/workerManager/workerTypes';
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
  ProductEd25519YaoCapabilityActivationPortV1,
  ProductEd25519YaoPendingRegistrationPortV1,
} from '../../flows/registration/services/ed25519YaoRegistration';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
  type RouterAbEd25519YaoExportArtifactV1,
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '../../threshold/ed25519/yaoClient';
import type {
  NearEd25519YaoSigningCapability,
  NearResolvedEd25519SigningSessionState,
} from '../../interfaces/near';
import type { Ed25519YaoActiveClientIdentityV1 } from '../../threshold/ed25519/yaoActiveClientRegistry';
import {
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  registrationPreparationIdFromString,
  type WalletRegistrationEd25519YaoBootstrapSession,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaPrepareContext,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaDerivationSessionPolicy,
  generateThresholdSessionId,
  generateSigningGrantId,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../session/persistence/ecdsaRoleLocalRecords';
import {
  type GeneratedFinalizeEcdsaClientBootstrapOutput,
  type GeneratedPrepareEcdsaClientBootstrapOutput,
} from '@/core/platform/signerCoreCommandAdapters';
import {
  type EcdsaThresholdKeyId,
  type SigningRootId,
  type SigningRootVersion,
  type EmailOtpExistingKeyBootstrap,
  type EmailOtpRegistrationBootstrap,
  type SessionBootstrap,
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEcdsaDerivationThresholdKeyId,
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
  type WalletSessionUserId,
} from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import {
  buildSessionBootstrapKeyContext,
  deriveEvmFamilyEcdsaKeyHandle,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toRpId,
  type EvmFamilyEcdsaSessionLanePolicy,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import initEvmCrypto, {
  init_evm_crypto,
  secp256k1_private_key_32_to_public_key_33,
  sign_secp256k1_recoverable,
} from '../../../../../../../wasm/evm_crypto/pkg/evm_crypto.js';
import initEcdsaDerivationClient from '../../../../../../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.js';
import initEcdsaRegistrationClient, {
  finalize_ecdsa_client_bootstrap_v1,
  open_ecdsa_role_local_signing_share_v1,
  prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1,
} from '../../../../../../../wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.js';
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
  emailOtpRoutePath,
  normalizeEmailOtpRoutePlan,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  deleteEmailOtpDeviceEnrollmentEscrowRecord,
  readEmailOtpDeviceEnrollmentEscrowRecord,
  readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet,
  writeEmailOtpDeviceEnrollmentEscrowRecord,
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
  factorSecret32: Uint8Array;
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

type EmailOtpWarmSessionClaimResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionConsumeResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpWarmSessionSealResult =
  | {
      ok: true;
      sealedSecretB64u: string;
      keyVersion?: string;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaWarmSessionRehydrateResult =
  | {
      ok: true;
      clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

type EmailOtpEd25519YaoFactorRehydrateResult =
  | {
      ok: true;
      pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

type ExactEmailOtpEcdsaWarmSessionRestore = {
  sessionId: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  authSubjectId: string;
};

type ExactEmailOtpEcdsaWarmSessionTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  keyVersion?: string;
  shamirPrimeB64u: string;
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
  | { ok: false; code: string; message: string };

type EmailOtpEcdsaSigningShareClaimResult =
  | { ok: true; clientSigningShare32: ArrayBuffer; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

type EmailOtpThresholdEcdsaBootstrapResult = ThresholdEcdsaSessionBootstrapResult & {
  emailOtpClientAdditiveShare32: Uint8Array;
};

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
    registeredPublicKey: metadata.registeredPublicKey.slice(),
    signingWorkerVerifyingShare: metadata.signingWorkerVerifyingShare.slice(),
    stateEpoch: metadata.stateEpoch,
    transcript: metadata.transcript.slice(),
    activeCapabilityBinding: [...metadata.activeCapabilityBinding],
  };
}

function emailOtpEd25519YaoCapabilityIdentity(
  capability: NearEd25519YaoSigningCapability,
): Ed25519YaoActiveClientIdentityV1 {
  const lane = capability.walletSessionState.signingLane;
  return {
    walletId: lane.identity.signer.account.wallet.walletId,
    nearAccountId: lane.identity.signer.account.nearAccountId,
    thresholdSessionId: capability.walletSessionState.thresholdSessionId,
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
  thresholdSessionId: string;
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
    capability.lifecycle.walletSessionId !== args.thresholdSessionId ||
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
  thresholdSessionId: string;
  signingGrantId: string;
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
      wallet_session_id: capability.lifecycle.walletSessionId,
      signer_set_id: capability.lifecycle.signerSetId,
      signing_worker_id: capability.lifecycle.signingWorkerId,
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
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
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
    const client = await RouterAbEd25519YaoClientV1.initializeBundled();
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

class EmailOtpEd25519YaoWorkerActivationPort implements ProductEd25519YaoCapabilityActivationPortV1 {
  private activationResult: EmailOtpEd25519YaoWorkerActivationResult | null = null;

  async activateVerifiedNearEd25519YaoSigningCapability(
    capability: NearEd25519YaoSigningCapability,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    if (this.activationResult) {
      throw new Error('Email OTP Ed25519 Yao worker activation already completed');
    }
    const identity = emailOtpEd25519YaoCapabilityIdentity(capability);
    this.activationResult = storeEmailOtpEd25519YaoActiveClient(capability.activeClient);
    return identity;
  }

  takeActivationResult(): EmailOtpEd25519YaoWorkerActivationResult {
    const result = this.activationResult;
    if (!result) throw new Error('Email OTP Ed25519 Yao worker activation did not complete');
    this.activationResult = null;
    return result;
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
    sessionId: string;
    walletId: string;
    evmFamilySigningKeySlotId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    authSubjectId: string;
  };
}): ParseEmailOtpEcdsaWarmSessionRehydrateArgsResult {
  const sessionId = normalizeOptionalTrimmedString(args.restore.sessionId);
  if (!sessionId) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' },
    };
  }
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  if (!sealedSecretB64u) {
    return {
      kind: 'error',
      error: { ok: false, code: 'invalid_args', message: 'Missing sealedSecretB64u' },
    };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      kind: 'error',
      error: {
        ok: false,
        code: 'invalid_args',
        message: 'Missing shamirPrimeB64u for signing-session restore',
      },
    };
  }
  const walletId = readString(args.restore.walletId, 'walletId');
  const evmFamilySigningKeySlotId = String(
    readEvmFamilySigningKeySlotId(
      args.restore.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
  );
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
        shamirPrimeB64u,
      },
      restore: {
        sessionId,
        walletId,
        evmFamilySigningKeySlotId,
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

function readSigningGrantId(value: unknown, label: string): SigningGrantId {
  const parsed = parseSigningGrantId(value);
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

function readEcdsaPublicationTargetPlans(args: {
  walletId: string;
  primaryChainTarget: ThresholdEcdsaChainTarget;
  primaryEvmFamilySigningKeySlotId: string;
  publicationTargetPlans: unknown;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
}): EmailOtpEcdsaPublicationTargetPlan[] {
  if (!Array.isArray(args.publicationTargetPlans) || !args.publicationTargetPlans.length) {
    throw new Error('Email OTP ECDSA bootstrap requires publicationTargetPlans');
  }
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  const plans = args.publicationTargetPlans.map(
    (rawPlan, index): EmailOtpEcdsaPublicationTargetPlan => {
      const plan = workerPayloadObject(rawPlan);
      if (!plan) {
        throw new Error(`Email OTP ECDSA publication target plan ${index} must be an object`);
      }
      const kind = readString(plan.kind, `publicationTargetPlans[${index}].kind`);
      const chainTarget = parseWorkerChainTarget(plan.chainTarget);
      const evmFamilySigningKeySlotId = String(
        assertEvmFamilySigningKeySlotIdMatchesPlan({
          evmFamilySigningKeySlotId: plan.evmFamilySigningKeySlotId,
          walletId: args.walletId,
          signingRootId: signingRootScope.signingRootId,
          signingRootVersion: signingRootScope.signingRootVersion,
          message: 'Email OTP ECDSA publication target plan evmFamilySigningKeySlotId mismatch',
        }),
      );
      if (kind !== 'new_key_publication_target') {
        throw new Error(`Unsupported Email OTP ECDSA publication target plan kind: ${kind}`);
      }
      if (Object.prototype.hasOwnProperty.call(plan, 'keyHandle')) {
        throw new Error('Email OTP new-key publication target forbids keyHandle');
      }
      return {
        kind: 'new_key_publication_target',
        chainTarget,
        evmFamilySigningKeySlotId,
      };
    },
  );
  const primaryPlan = plans[0];
  if (
    !primaryPlan ||
    !thresholdEcdsaChainTargetsEqual(primaryPlan.chainTarget, args.primaryChainTarget)
  ) {
    throw new Error('Email OTP ECDSA primary target must be first publication target');
  }
  if (
    String(primaryPlan.evmFamilySigningKeySlotId) !== String(args.primaryEvmFamilySigningKeySlotId)
  ) {
    throw new Error('Email OTP ECDSA primary publication target must match client-root handle');
  }
  const seen = new Set<string>();
  for (const plan of plans) {
    const key = thresholdEcdsaChainTargetKey(plan.chainTarget);
    if (seen.has(key)) {
      throw new Error(`Email OTP ECDSA duplicate publication target: ${key}`);
    }
    seen.add(key);
  }
  return plans;
}

function routePlanSessionAuth(plan: EmailOtpRoutePlan): AppOrWalletSessionAuth | undefined {
  return authLaneToRouteAuth(plan.authLane);
}

function assertEmailOtpYaoRecoveryMaterialIdentity(args: {
  walletId: string;
  material: Extract<
    EmailOtpWalletUnlockMaterialRequest,
    { kind: 'ed25519_yao_recovery' | 'ecdsa_and_ed25519_yao_recovery' }
  >;
}): void {
  if (!args.material.providerSubject.trim() || !args.material.ed25519YaoRecovery.orgId.trim()) {
    throw new Error('Email OTP Yao recovery requires its provider and organization identity');
  }
}

function assertEmailOtpUnlockMaterialRouteAuth(args: {
  walletId: string;
  routePlan: EmailOtpRoutePlan;
  material: EmailOtpWalletUnlockMaterialRequest;
}): void {
  switch (args.material.kind) {
    case 'ecdsa':
      return;
    case 'ecdsa_and_ed25519_yao_recovery':
      assertEmailOtpYaoRecoveryMaterialIdentity({
        walletId: args.walletId,
        material: args.material,
      });
      if (
        args.material.ecdsaClientRootHandleBinding.authSubjectId !==
          args.material.providerSubject ||
        args.material.runtimePolicyScope.orgId !== args.material.ed25519YaoRecovery.orgId
      ) {
        throw new Error('Mixed Email OTP unlock ECDSA and Ed25519 identities do not match');
      }
      return;
    case 'ed25519_yao_recovery': {
      assertEmailOtpYaoRecoveryMaterialIdentity({
        walletId: args.walletId,
        material: args.material,
      });
      const routeAuth = routePlanSessionAuth(args.routePlan);
      const usesAppSession =
        routeAuth?.kind === 'app_session' && args.routePlan.authLane.kind === 'app_session';
      const usesEd25519WalletSession =
        routeAuth?.kind === 'wallet_session' &&
        args.routePlan.authLane.kind === 'signing_session' &&
        args.routePlan.authLane.curve === 'ed25519';
      if (!usesAppSession && !usesEd25519WalletSession) {
        throw new Error('Email OTP Ed25519 Yao recovery requires an authenticated route plan');
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

function googleEmailOtpRegistrationAttemptIdFromRoutePlan(plan: EmailOtpRoutePlan): string {
  if (plan.routeFamily !== 'registration') return '';
  const auth = routePlanSessionAuth(plan);
  if (auth?.kind !== 'app_session') return '';
  const payload = decodeJwtPayloadRecord(auth.jwt);
  return normalizeOptionalTrimmedString(payload?.googleEmailOtpRegistrationAttemptId);
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  if (!relayerUrl) return null;
  const walletSessionJwt = normalizeOptionalNonEmptyString(transport.walletSessionJwt);
  const keyVersion = normalizeOptionalNonEmptyString(transport.signingSessionSealKeyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(transport.shamirPrimeB64u);
  return {
    relayerUrl,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
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
  sessionId: string;
  relayerUrl: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  payloadB64u?: string;
}): string {
  const operation =
    args.operation === 'remove-server-seal' ? 'remove-server-seal' : 'apply-server-seal';
  return [
    operation,
    normalizeOptionalTrimmedString(args.sessionId) || '',
    normalizeOptionalTrimmedString(args.relayerUrl) || '',
    normalizeOptionalNonEmptyString(args.keyVersion) || '',
    normalizeOptionalNonEmptyString(args.shamirPrimeB64u) || '',
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

function deleteEmailOtpWarmSession(sessionId: string): void {
  const entry = emailOtpWarmSessions.get(sessionId);
  if (entry) {
    zeroizeBytes(entry.clientRootShare32);
    zeroizeBytes(entry.signingSessionSecret32);
    zeroizeBytes(entry.clientAdditiveShare32);
    emailOtpWarmSessions.delete(sessionId);
  }
}

function deleteEmailOtpEd25519YaoWarmFactor(sessionId: string): void {
  const entry = emailOtpEd25519YaoWarmFactors.get(sessionId);
  if (!entry) return;
  zeroizeBytes(entry.factorSecret32);
  emailOtpEd25519YaoWarmFactors.delete(sessionId);
}

function deleteEmailOtpWarmMaterial(sessionId: string): void {
  deleteEmailOtpWarmSession(sessionId);
  deleteEmailOtpEd25519YaoWarmFactor(sessionId);
}

function putEmailOtpEd25519YaoWarmFactor(args: {
  sessionId: string;
  factorSecret32: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
}): void {
  const sessionId = readString(args.sessionId, 'sessionId');
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  if (args.factorSecret32.length !== 32) {
    throw new Error('Email OTP Ed25519 Yao factor must contain 32 bytes');
  }
  if (expiresAtMs <= Date.now() || remainingUses <= 0) {
    throw new Error('Invalid Email OTP Ed25519 Yao warm-factor policy');
  }
  if (emailOtpWarmSessions.has(sessionId)) {
    throw new Error('Email OTP warm-session identity is ambiguous across curves');
  }
  deleteEmailOtpEd25519YaoWarmFactor(sessionId);
  emailOtpEd25519YaoWarmFactors.set(sessionId, {
    kind: 'ed25519_yao_factor',
    factorSecret32: Uint8Array.from(args.factorSecret32),
    expiresAtMs,
    remainingUses,
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

function disposeEmailOtpEcdsaClientRootHandle(
  handle: EmailOtpEcdsaSessionBootstrapHandlePayload,
): boolean {
  const sessionId = readString(handle.sessionId, 'clientRootShareHandle.sessionId');
  const entry = emailOtpEcdsaClientRootHandles.get(sessionId);
  if (!entry) return false;
  if (
    entry.handle.action !== handle.action ||
    entry.handle.operation !== handle.operation ||
    entry.handle.walletId !== handle.walletId ||
    entry.handle.evmFamilySigningKeySlotId !== handle.evmFamilySigningKeySlotId ||
    entry.handle.authSubjectId !== handle.authSubjectId ||
    !thresholdEcdsaChainTargetsEqual(entry.handle.chainTarget, handle.chainTarget)
  ) {
    throw new Error('Email OTP ECDSA client-root handle binding mismatch');
  }
  deleteEmailOtpEcdsaClientRootHandle(sessionId);
  return true;
}

function emailOtpWorkerHandleOperationFromOtpOperation(
  operation: WalletEmailOtpOperation,
): EmailOtpWorkerSessionHandleOperation {
  switch (operation) {
    case WALLET_EMAIL_OTP_REGISTRATION_OPERATION:
      return 'registration';
    case WALLET_EMAIL_OTP_UNLOCK_OPERATION:
      return 'wallet_unlock';
    case WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION:
      return 'sign';
    case WALLET_EMAIL_OTP_EXPORT_OPERATION:
      return 'export';
  }
  operation satisfies never;
  throw new Error('Unsupported Email OTP operation for worker handle');
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
    evmFamilySigningKeySlotId: String(
      readEvmFamilySigningKeySlotId(
        args.binding.evmFamilySigningKeySlotId,
        'evmFamilySigningKeySlotId',
      ),
    ),
    authSubjectId: readString(args.binding.authSubjectId, 'authSubjectId'),
  };
  const handle: EmailOtpWorkerIssuedSessionHandlePayload =
    args.binding.action === 'wallet_registration_ecdsa_prepare'
      ? {
          ...common,
          action: 'wallet_registration_ecdsa_prepare',
          operation: 'registration',
          keyScope: 'evm-family',
          chainTarget: args.binding.chainTarget,
        }
      : {
          ...common,
          action: 'threshold_ecdsa_bootstrap',
          operation: args.binding.operation,
          chainTarget: args.binding.chainTarget,
        };
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
  evmFamilySigningKeySlotId: string;
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
    if (entry.handle.action !== 'threshold_ecdsa_bootstrap') {
      throw new Error('Email OTP ECDSA client-root handle action mismatch');
    }
    if (entry.handle.operation !== handle.operation) {
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

function prepareEcdsaClientBootstrapFromResolvedEmailOtpRoot(args: {
  context: EmailOtpPrepareEcdsaClientBootstrapInput['context'];
  clientRootShare32: Uint8Array;
}): GeneratedPrepareEcdsaClientBootstrapOutput {
  const context = args.context;
  return JSON.parse(
    prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
      JSON.stringify({
        kind: 'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
        algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
        context: {
          applicationBindingDigestB64u: readString(
            context.applicationBindingDigestB64u,
            'context.applicationBindingDigestB64u',
          ),
        },
        participants: {
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
        },
        resolvedEmailOtpRootShare32B64u: base64UrlEncode(args.clientRootShare32),
      }),
    ),
  ) as GeneratedPrepareEcdsaClientBootstrapOutput;
}

function finalizeEcdsaClientBootstrapWithGeneratedCommand(args: {
  pendingStateBlobB64u: string;
  relayerKeyId: string;
  relayerPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
  relayerShareRetryCounter: number;
}): GeneratedFinalizeEcdsaClientBootstrapOutput {
  return JSON.parse(
    finalize_ecdsa_client_bootstrap_v1(
      JSON.stringify({
        kind: 'finalize_ecdsa_client_bootstrap_v1',
        pendingStateBlob: {
          kind: 'ecdsa_role_local_pending_state_blob_v1',
          curve: 'secp256k1',
          encoding: 'base64url',
          producer: 'signer_core',
          stateBlobB64u: readString(args.pendingStateBlobB64u, 'pendingStateBlobB64u'),
        },
        relayerPublicIdentity: {
          relayerKeyId: readString(args.relayerKeyId, 'relayerKeyId'),
          relayerPublicKey33B64u: readString(args.relayerPublicKey33B64u, 'relayerPublicKey33B64u'),
          groupPublicKey33B64u: readString(args.groupPublicKey33B64u, 'groupPublicKey33B64u'),
          ethereumAddress: readString(args.ethereumAddress, 'ethereumAddress'),
          relayerShareRetryCounter: requireNonNegativeInteger(
            args.relayerShareRetryCounter,
            'relayerShareRetryCounter',
          ),
        },
      }),
    ),
  ) as GeneratedFinalizeEcdsaClientBootstrapOutput;
}

function prepareEcdsaClientBootstrapFromEmailOtpWorkerHandle(
  input: EmailOtpPrepareEcdsaClientBootstrapInput,
): GeneratedPrepareEcdsaClientBootstrapOutput {
  if (input.secretSource.kind !== 'email_otp_worker_session') {
    throw new Error('Email OTP ECDSA prepare requires an email_otp_worker_session secret source');
  }
  const handle = input.secretSource.handle;
  if (handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP ECDSA prepare requires a threshold_ecdsa_bootstrap handle');
  }
  let clientRootShare32: Uint8Array | null = null;
  try {
    clientRootShare32 = claimEmailOtpEcdsaClientRootShare({
      handle,
      walletId: handle.walletId,
      evmFamilySigningKeySlotId: handle.evmFamilySigningKeySlotId,
      authSubjectId: handle.authSubjectId,
      chainTarget: handle.chainTarget,
    });
    return prepareEcdsaClientBootstrapFromResolvedEmailOtpRoot({
      context: input.context,
      clientRootShare32,
    });
  } finally {
    zeroizeBytes(clientRootShare32);
  }
}

function resolveEmailOtpWarmMaterialEntry(sessionId: string): EmailOtpWarmMaterialEntry | null {
  const ecdsa = emailOtpWarmSessions.get(sessionId);
  const ed25519Yao = emailOtpEd25519YaoWarmFactors.get(sessionId);
  if (ecdsa && ed25519Yao) {
    throw new Error('Email OTP warm-session identity is ambiguous across curves');
  }
  if (ecdsa) return { kind: 'ecdsa', entry: ecdsa };
  if (ed25519Yao) return { kind: 'ed25519_yao', entry: ed25519Yao };
  return null;
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
  sessionId: string;
  material: EmailOtpWarmMaterialEntry;
  remainingUses: number;
  expiresAtMs: number;
}): void {
  switch (args.material.kind) {
    case 'ecdsa':
      emailOtpWarmSessions.set(args.sessionId, {
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
      emailOtpEd25519YaoWarmFactors.set(args.sessionId, {
        kind: 'ed25519_yao_factor',
        factorSecret32: args.material.entry.factorSecret32,
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
      });
      return;
  }
}

function readEmailOtpWarmSessionStatus(sessionIdRaw: unknown): EmailOtpWarmSessionStatusResult {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  let material: EmailOtpWarmMaterialEntry | null;
  try {
    material = resolveEmailOtpWarmMaterialEntry(sessionId);
  } catch (error) {
    return {
      ok: false,
      code: 'ambiguous_material',
      message: error instanceof Error ? error.message : String(error),
    };
  }
  if (!material) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session material is not available',
    };
  }
  if (Date.now() >= material.entry.expiresAtMs) {
    deleteEmailOtpWarmMaterial(sessionId);
    return {
      ok: false,
      code: 'expired',
      message: 'Email OTP warm-session material expired',
    };
  }
  if (material.entry.remainingUses <= 0) {
    deleteEmailOtpWarmMaterial(sessionId);
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
  sessionId: string;
  clientRootShare32: Uint8Array;
  signingSessionSecret32: Uint8Array;
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
  deleteEmailOtpWarmSession(sessionId);
  emailOtpWarmSessions.set(sessionId, {
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
      evmFamilySigningKeySlotId: handle.evmFamilySigningKeySlotId,
      authSubjectId: handle.authSubjectId,
      chainTarget: handle.chainTarget,
    });
    putEmailOtpWarmSessionMaterial({
      sessionId: readString(args.thresholdSessionId, 'thresholdSessionId'),
      clientRootShare32,
      signingSessionSecret32: clientRootShare32,
      expiresAtMs: args.expiresAtMs,
      remainingUses: args.remainingUses,
    });
    return readEmailOtpWarmSessionStatus(args.thresholdSessionId);
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

function claimEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  uses?: number;
  consume?: boolean;
}): EmailOtpWarmSessionClaimResult {
  const sessionId = String(args.sessionId || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const entry = emailOtpWarmSessions.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP ECDSA warm-session material is not available',
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
  const consume = args.consume !== false;
  if (consume) {
    entry.remainingUses -= uses;
  }
  const remainingUses = entry.remainingUses;
  const expiresAtMs = entry.expiresAtMs;
  if (consume) {
    if (remainingUses <= 0) {
      deleteEmailOtpWarmMaterial(sessionId);
    } else {
      emailOtpWarmSessions.set(sessionId, entry);
    }
  }
  return {
    ok: true,
    prfFirstB64u,
    remainingUses,
    expiresAtMs,
  };
}

function consumeEmailOtpWarmSessionUses(args: {
  sessionId: string;
  uses?: number;
}): EmailOtpWarmSessionConsumeResult {
  const sessionId = String(args.sessionId || '').trim();
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const material = resolveEmailOtpWarmMaterialEntry(sessionId);
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
    deleteEmailOtpWarmMaterial(sessionId);
  } else {
    updateEmailOtpWarmMaterialPolicy({ sessionId, material, remainingUses, expiresAtMs });
  }
  return {
    ok: true,
    remainingUses,
    expiresAtMs,
  };
}

async function sealEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  transport: SigningSessionSealTransport;
}): Promise<EmailOtpWarmSessionSealResult> {
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing shamirPrimeB64u for signing-session seal',
    };
  }
  const status = readEmailOtpWarmSessionStatus(sessionId);
  if (!status.ok) return status;
  const material = resolveEmailOtpWarmMaterialEntry(sessionId);
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
    sessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.transport.keyVersion,
    shamirPrimeB64u,
    payloadB64u,
  });
  const inFlight = signingSessionSealApplyInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<EmailOtpWarmSessionSealResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealBytesWithKeyHandle({
          ciphertext: secret32,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
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
          deleteEmailOtpWarmMaterial(sessionId);
          return policy;
        }
        updateEmailOtpWarmMaterialPolicy({
          sessionId,
          material,
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        const keyVersion = normalizeOptionalNonEmptyString(applied.keyVersion);
        return {
          ok: true,
          sealedSecretB64u: readString(sealedSecretB64u, 'sealedSecretB64u'),
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
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    sessionId: string;
    walletId: string;
    evmFamilySigningKeySlotId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    authSubjectId: string;
  };
}): Promise<EmailOtpEcdsaWarmSessionRehydrateResult> {
  const parsed = parseEmailOtpEcdsaWarmSessionRehydrateArgs(args);
  if (parsed.kind === 'error') return parsed.error;
  const {
    sealedSecretB64u,
    remainingUses: localRemainingUses,
    expiresAtMs: localExpiresAtMs,
    transport,
    restore,
  } = parsed.value;
  const sessionId = restore.sessionId;
  if (localRemainingUses <= 0) {
    return { ok: false, code: 'exhausted', message: 'Email OTP signing-session seal exhausted' };
  }
  if (localExpiresAtMs <= Date.now()) {
    return { ok: false, code: 'expired', message: 'Email OTP signing-session seal expired' };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'remove-server-seal',
    sessionId,
    relayerUrl: transport.relayerUrl,
    keyVersion: transport.keyVersion,
    shamirPrimeB64u: transport.shamirPrimeB64u,
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
        shamirPrimeB64u: transport.shamirPrimeB64u,
      });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: sealedSecretB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const removed = await callSigningSessionSealRoute({
          operation: 'remove-server-seal',
          transport,
          thresholdSessionId: sessionId,
          ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
          keyVersion: transport.keyVersion,
        });
        if (!removed.ok) return removed;
        serverRemainingUses = removed.remainingUses;
        serverExpiresAtMs = removed.expiresAtMs;
        signingSessionSecret32 = await runtime.removeClientSealWithKeyHandleToBytes({
          ciphertextB64u: removed.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
      }

      if (signingSessionSecret32.length !== 32) {
        return {
          ok: false,
          code: 'invalid_response',
          message: 'Signing-session secret must decode to 32 bytes',
        };
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
          evmFamilySigningKeySlotId: restore.evmFamilySigningKeySlotId,
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

async function rehydrateEmailOtpEd25519YaoFactor(args: {
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
  restore: {
    sessionId: string;
    walletId: string;
    providerSubject: string;
  };
}): Promise<EmailOtpEd25519YaoFactorRehydrateResult> {
  const sessionId = normalizeOptionalTrimmedString(args.restore.sessionId);
  const walletId = normalizeOptionalTrimmedString(args.restore.walletId);
  const providerSubject = normalizeOptionalTrimmedString(args.restore.providerSubject);
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  const walletSessionJwt = normalizeOptionalNonEmptyString(args.transport.walletSessionJwt);
  if (
    !sessionId ||
    !walletId ||
    !providerSubject ||
    !sealedSecretB64u ||
    !shamirPrimeB64u ||
    !walletSessionJwt
  ) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Email OTP Ed25519 Yao sealed recovery requires exact restore identity',
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

  let factorSecret32: Uint8Array | null = null;
  try {
    const runtime = await getShamir3PassRuntime();
    const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
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
        thresholdSessionId: sessionId,
        ciphertext: readString(clientEncryptedCiphertext, 'clientEncryptedCiphertext'),
        keyVersion: args.transport.keyVersion,
      });
      if (!removed.ok) return removed;
      serverRemainingUses = removed.remainingUses;
      serverExpiresAtMs = removed.expiresAtMs;
      factorSecret32 = await runtime.removeClientSealWithKeyHandleToBytes({
        ciphertextB64u: removed.ciphertext,
        keyHandle: clientKeyHandle.keyHandle,
      });
    } finally {
      await runtime
        .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
        .catch(() => undefined);
    }
    if (factorSecret32.length !== 32) {
      return {
        ok: false,
        code: 'invalid_response',
        message: 'Email OTP Ed25519 Yao factor must decode to 32 bytes',
      };
    }
    const policy = resolvePolicyFromServerAndLocal({
      localRemainingUses,
      localExpiresAtMs,
      serverRemainingUses,
      serverExpiresAtMs,
    });
    if (!policy.ok) return policy;
    const nowMs = Date.now();
    const pendingFactorHandle = emailOtpEd25519YaoRootVault.issuePendingOwned({
      purpose: 'recovery',
      walletId,
      providerSubject,
      ownedFactorSecret32: factorSecret32,
      expiresAtMs: Math.min(policy.expiresAtMs, nowMs + EMAIL_OTP_ED25519_YAO_HANDLE_TTL_MS),
      nowMs,
    });
    factorSecret32 = null;
    return {
      ok: true,
      pendingFactorHandle,
      remainingUses: policy.remainingUses,
      expiresAtMs: policy.expiresAtMs,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message:
        error instanceof Error ? error.message : String(error || 'Yao factor restore failed'),
    };
  } finally {
    zeroizeBytes(factorSecret32);
  }
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

let ecdsaPresignPort: MessagePort | null = null;

function handleEmailOtpEcdsaSigningShareRequest(
  event: MessageEvent<EmailOtpEcdsaSigningShareRequest>,
): void {
  if (!ecdsaPresignPort) return;
  const request = event.data;
  if (request.kind !== 'email_otp_ecdsa_signing_share_request_v1') return;
  const result = claimEmailOtpEcdsaSigningShare(request.sessionId);
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
const ecdsaDerivationClientWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_derivation_client_bg.wasm',
  'Email OTP ECDSA DERIVATION',
);
const ecdsaRegistrationClientWasmUrl = resolveWasmUrl(
  'ecdsa_registration_client_bg.wasm',
  'Email OTP ECDSA REGISTRATION',
);
const emailOtpRuntimeWasmUrl = resolveWasmUrl('email_otp_runtime_bg.wasm', 'Email OTP Runtime');
const nearSignerRecoveryWasmUrl = resolveWasmUrl(
  'wasm_signer_worker_bg.wasm',
  'Email OTP Recovery Wrap',
);
let evmCryptoInitPromise: Promise<void> | null = null;
let ecdsaDerivationClientInitPromise: Promise<void> | null = null;
let ecdsaRegistrationClientInitPromise: Promise<void> | null = null;
let emailOtpRuntimeInitPromise: Promise<void> | null = null;
let nearSignerRecoveryInitPromise: Promise<void> | null = null;

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

async function ensureEcdsaDerivationClientWasm(): Promise<void> {
  if (ecdsaDerivationClientInitPromise) return ecdsaDerivationClientInitPromise;
  ecdsaDerivationClientInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP ECDSA DERIVATION',
      wasmUrl: ecdsaDerivationClientWasmUrl,
      initFunction: initEcdsaDerivationClient as unknown as (wasmModule?: unknown) => Promise<void>,
    });
  })();
  return ecdsaDerivationClientInitPromise;
}

async function initializeEcdsaRegistrationClientWasm(): Promise<void> {
  await initializeWasm({
    workerName: 'Email OTP ECDSA REGISTRATION',
    wasmUrl: ecdsaRegistrationClientWasmUrl,
    initFunction: initEcdsaRegistrationClient as unknown as (wasmModule?: unknown) => Promise<void>,
  });
}

async function ensureEcdsaRegistrationClientWasm(): Promise<void> {
  if (!ecdsaRegistrationClientInitPromise) {
    ecdsaRegistrationClientInitPromise = initializeEcdsaRegistrationClientWasm();
  }
  return ecdsaRegistrationClientInitPromise;
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
  routeAuth: ReturnType<typeof routePlanSessionAuth>;
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
  shamirPrimeB64u: string;
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
  const routeAuth = routePlanSessionAuth(args.routePlan);
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
          shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
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
  const requestedUserId = readOptionalString(args.userId);
  const routePlan = readRoutePlan(args.routePlan, 'rotateEmailOtpRecoveryCodes');
  const routeAuth = routePlanSessionAuth(routePlan);
  const record = await readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet({ walletId });
  if (!record) {
    throw new Error('Email OTP device enrollment escrow is unavailable on this device');
  }
  const localUserId = readOptionalString(record.userId) || record.authSubjectId;
  if (
    requestedUserId &&
    record.authSubjectId !== requestedUserId &&
    localUserId !== requestedUserId
  ) {
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
    authSubjectId: record.authSubjectId,
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

type EmailOtpUnlockCompletionMaterial =
  | { kind: 'ecdsa'; clientRootShare32: Uint8Array }
  | { kind: 'ed25519_yao_export' }
  | {
      kind: 'ed25519_yao_recovery';
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'ecdsa_and_ed25519_yao_recovery';
      clientRootShare32: Uint8Array;
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    };

type EmailOtpUnlockSecretMaterialRequest =
  | { kind: 'ecdsa' }
  | { kind: 'ed25519_yao_export' }
  | Extract<
      EmailOtpWalletUnlockMaterialRequest,
      { kind: 'ed25519_yao_recovery' | 'ecdsa_and_ed25519_yao_recovery' }
    >;

type EmailOtpUnlockVerifyRecoverySelectorV1 = Pick<
  EmailOtpEd25519YaoRecoveryAugmentationV1,
  'kind' | 'signerSlot' | 'remainingUses'
>;

function emailOtpUnlockVerifyRecoveryBody(
  material: EmailOtpUnlockSecretMaterialRequest,
): { ed25519YaoRecovery: EmailOtpUnlockVerifyRecoverySelectorV1 } | undefined {
  switch (material.kind) {
    case 'ecdsa':
    case 'ed25519_yao_export':
      return undefined;
    case 'ecdsa_and_ed25519_yao_recovery':
    case 'ed25519_yao_recovery':
      return {
        ed25519YaoRecovery: {
          kind: material.ed25519YaoRecovery.kind,
          signerSlot: material.ed25519YaoRecovery.signerSlot,
          remainingUses: material.ed25519YaoRecovery.remainingUses,
        },
      };
    default:
      return assertNeverEmailOtpWorker(material);
  }
}

async function completeEmailOtpUnlockFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  orgId?: string;
  userId: string;
  clientSecret32: Uint8Array;
  material: EmailOtpUnlockSecretMaterialRequest;
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

    const recoveryBody = emailOtpUnlockVerifyRecoveryBody(args.material);
    const verified = await postEmailOtpJson({
      relayUrl: readString(args.relayUrl, 'relayUrl'),
      route: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: clientUnlockPublicKeyB64u,
          signature: unlockSignatureB64u,
        },
        ...(recoveryBody || {}),
      },
    });
    const commonResult = {
      unlockChallengeId,
      unlockChallengeB64u,
      clientUnlockPublicKeyB64u,
      unlockSignatureB64u,
    };
    switch (args.material.kind) {
      case 'ecdsa':
        clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
          clientSecret32: args.clientSecret32,
          walletId,
          userId,
        });
        {
          const ownedClientRootShare32 = clientRootShare32;
          clientRootShare32 = null;
          return { kind: 'ecdsa', ...commonResult, clientRootShare32: ownedClientRootShare32 };
        }
      case 'ed25519_yao_export':
        return { kind: 'ed25519_yao_export', ...commonResult };
      case 'ecdsa_and_ed25519_yao_recovery':
        clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32InWorker({
          clientSecret32: args.clientSecret32,
          walletId,
          userId,
        });
        {
          const ownedClientRootShare32 = clientRootShare32;
          clientRootShare32 = null;
          return {
            kind: 'ecdsa_and_ed25519_yao_recovery',
            ...commonResult,
            clientRootShare32: ownedClientRootShare32,
            ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryBootstrap(
              verified.ed25519YaoRecovery,
            ),
          };
        }
      case 'ed25519_yao_recovery':
        return {
          kind: 'ed25519_yao_recovery',
          ...commonResult,
          ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryBootstrap(verified.ed25519YaoRecovery),
        };
      default:
        return assertNeverEmailOtpWorker(args.material);
    }
  } finally {
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
  shamirPrimeB64u: string;
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
  const shamirPrimeB64u = readString(args.shamirPrimeB64u, 'shamirPrimeB64u');
  const otpCode = args.skipServerFinalize ? '' : readString(args.otpCode, 'otpCode');
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
    const sessionAuth = routePlanSessionAuth(args.routePlan);
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
        shamirPrimeB64u,
      },
      'Email OTP enrollment did not persist device-local enc_s(S)',
    );
    if (!args.skipServerFinalize) {
      const googleEmailOtpRegistrationAttemptId =
        readOptionalString(args.googleEmailOtpRegistrationAttemptId) ||
        googleEmailOtpRegistrationAttemptIdFromRoutePlan(args.routePlan);
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
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
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
        kind: 'ecdsa_and_ed25519_yao_recovery';
        clientRootShare32: Uint8Array;
        clientSecret32: Uint8Array;
        ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
      }
  )
> {
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
    const sessionAuth = routePlanSessionAuth(args.routePlan);
    let challengeId = readOptionalString(args.challengeId);
    if (!challengeId) {
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
    let userId = resolveEmailOtpAuthSubjectId({
      walletId,
      userId: args.userId,
      routePlan: args.routePlan,
    });
    let localEnrollmentEscrow = await readEmailOtpDeviceEnrollmentEscrowRecord({
      walletId,
      authSubjectId: userId,
      enrollmentId: emailOtpDeviceEnrollmentId(walletId, userId),
    });
    if (!localEnrollmentEscrow) {
      localEnrollmentEscrow = await readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet({
        walletId,
      });
      if (localEnrollmentEscrow) {
        userId = localEnrollmentEscrow.authSubjectId;
      }
    }
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
    if (args.routePlan.routeFamily === 'login') {
      unsealed = await postEmailOtpJson({
        relayUrl,
        route: emailOtpRoutePath(args.routePlan, 'verifyAndUnseal'),
        ...(sessionAuth ? { sessionAuth } : {}),
        body: {
          walletId,
          challengeId,
          otpCode: readString(args.otpCode, 'otpCode'),
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
          challengeId,
          otpCode: readString(args.otpCode, 'otpCode'),
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
    clientSecret32 = await removeClientSealToBytes({
      runtime,
      ciphertextB64u: clientCiphertext,
      keyHandle,
    });
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
      userId,
      clientSecret32,
      material: args.material,
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
        return { kind: 'ecdsa', ...commonResult, clientRootShare32: unlocked.clientRootShare32 };
      case 'ed25519_yao_export': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        return {
          kind: 'ed25519_yao_export',
          ...commonResult,
          clientSecret32: ownedClientSecret32,
        };
      }
      case 'ecdsa_and_ed25519_yao_recovery': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        return {
          kind: 'ecdsa_and_ed25519_yao_recovery',
          ...commonResult,
          clientRootShare32: unlocked.clientRootShare32,
          clientSecret32: ownedClientSecret32,
          ed25519YaoRecovery: unlocked.ed25519YaoRecovery,
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
      default:
        return assertNeverEmailOtpWorker(unlocked);
    }
  } finally {
    zeroizeBytes(clientSecret32);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
  }
}

type ThresholdEcdsaEmailOtpBootstrapFromClientRootShareArgs = {
  relayUrl: string;
  clientRootShare32: Uint8Array;
  routeAuth?: AppOrWalletSessionAuth;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
} & (
  | (EmailOtpRegistrationBootstrap & {
      walletSessionUserId: WalletSessionUserId;
      authSubjectId: string;
      evmFamilySigningKeySlotId: string;
      participantIds?: number[];
      sessionKind?: 'jwt';
      chainTarget: ThresholdEcdsaChainTarget;
      sessionId?: string;
      signingGrantId?: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      ttlMs?: number;
      remainingUses?: number;
    })
  | (EmailOtpExistingKeyBootstrap & {
      walletSessionUserId: WalletSessionUserId;
      authSubjectId: string;
      evmFamilySigningKeySlotId: string;
      participantIds?: number[];
      sessionKind?: 'jwt';
      chainTarget: ThresholdEcdsaChainTarget;
      sessionId?: string;
      signingGrantId?: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      ttlMs?: number;
      remainingUses?: number;
    })
  | SessionBootstrap
);

function requireThresholdEcdsaDerivationKeyHandle(keyHandle: string, operation: string): string {
  const normalized = readOptionalString(keyHandle);
  if (!normalized) {
    throw new Error(`Threshold ECDSA ${operation} requires keyHandle`);
  }
  return normalized;
}

function relayerKeyIdFromRouteAuth(auth: ThresholdEcdsaDerivationRouteAuth | undefined): string {
  if (!auth || (auth.kind !== 'wallet_session' && auth.kind !== 'app_session')) return '';
  const payload = decodeJwtPayloadRecord(auth.jwt);
  return readOptionalString(payload?.relayerKeyId) || '';
}

async function buildEmailOtpEcdsaClientRootProof(args: {
  bootstrapIdentity: EcdsaDerivationRoleLocalBootstrapIdentity;
  clientRootShare32: Uint8Array;
}): Promise<ThresholdEcdsaDerivationRoleLocalClientRootProof> {
  await ensureEvmCryptoWasm();
  const digest32B64u = await computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32B64u(
    args.bootstrapIdentity,
  );
  const digest32: Uint8Array | null = base64UrlDecode(digest32B64u);
  let clientRootPublicKey33: Uint8Array | null = null;
  let signature65: Uint8Array | null = null;
  try {
    if (digest32.length !== 32) {
      throw new Error('Email OTP ECDSA client root proof digest must be 32 bytes');
    }
    clientRootPublicKey33 = secp256k1_private_key_32_to_public_key_33(
      args.clientRootShare32,
    ) as Uint8Array;
    signature65 = sign_secp256k1_recoverable(digest32, args.clientRootShare32) as Uint8Array;
    return {
      version: ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
      clientRootPublicKey33B64u: base64UrlEncode(
        clientRootPublicKey33,
      ) as EcdsaClientRootPublicKey33B64u,
      digest32B64u,
      signature65B64u: base64UrlEncode(signature65),
    };
  } finally {
    zeroizeBytes(digest32);
    zeroizeBytes(clientRootPublicKey33);
    zeroizeBytes(signature65);
  }
}

async function runThresholdEcdsaAuthorizationBootstrapFromClientRootShare(
  args: ThresholdEcdsaEmailOtpBootstrapFromClientRootShareArgs,
): Promise<EmailOtpThresholdEcdsaBootstrapResult> {
  await ensureEcdsaRegistrationClientWasm();
  const relayerUrl = readString(args.relayUrl, 'relayUrl');
  const exactSessionBootstrap = args.operation === 'session_bootstrap';
  const walletId = toWalletId(
    exactSessionBootstrap ? args.keyContext.walletId : args.walletSessionUserId,
  );
  const evmFamilySigningKeySlotId = exactSessionBootstrap
    ? String(
        readEvmFamilySigningKeySlotId(
          args.keyContext.evmFamilySigningKeySlotId,
          'keyContext.evmFamilySigningKeySlotId',
        ),
      )
    : String(
        readEvmFamilySigningKeySlotId(args.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
      );
  const chainTarget = exactSessionBootstrap ? args.lanePolicy.chainTarget : args.chainTarget;
  const chainId = Math.floor(Number(chainTarget.chainId));
  if (!Number.isSafeInteger(chainId) || chainId < 0) {
    throw new Error('chainTarget.chainId must be a non-negative safe integer');
  }
  const operation = args.operation;
  const keyHandle = exactSessionBootstrap
    ? String(args.keyHandle || '').trim()
    : String('keyHandle' in args ? args.keyHandle || '' : '').trim();
  const sessionKind = exactSessionBootstrap
    ? args.lanePolicy.thresholdSessionKind
    : args.sessionKind || 'jwt';
  if (sessionKind !== 'jwt') {
    throw new Error('Email OTP ECDSA bootstrap requires JWT signing sessions');
  }
  const routeAuth: ThresholdEcdsaDerivationRouteAuth | undefined = args.routeAuth;
  if (!routeAuth) {
    throw new Error('routeAuth is required for JWT threshold bootstrap sessions');
  }
  const keygenSessionId = generateKeygenSessionId();
  const requestedSessionId = exactSessionBootstrap
    ? String(args.lanePolicy.thresholdSessionId).trim()
    : String(args.sessionId || '').trim();
  const requestedSigningGrantIdRaw = exactSessionBootstrap
    ? String(args.lanePolicy.signingGrantId).trim()
    : String(args.signingGrantId || '').trim();
  const requestedSigningGrantId = requestedSigningGrantIdRaw
    ? readSigningGrantId(requestedSigningGrantIdRaw, 'signingGrantId')
    : null;
  const sessionId = requestedSessionId || generateThresholdSessionId();
  const signingGrantId = requestedSigningGrantId || generateSigningGrantId();
  if (
    operation === 'session_bootstrap' &&
    (!keyHandle || !requestedSessionId || !requestedSigningGrantId)
  ) {
    throw new Error(
      'Threshold ECDSA session bootstrap requires keyHandle, sessionId, and signingGrantId',
    );
  }
  const participantIds = exactSessionBootstrap
    ? args.keyContext.participantIds.map((participantId) => Number(participantId))
    : normalizeThresholdEd25519ParticipantIds(args.participantIds);
  const runtimePolicyScope = exactSessionBootstrap
    ? args.lanePolicy.runtimePolicyScope
    : args.runtimePolicyScope;

  args.onProgress?.('signer.ecdsa.bootstrap.started');
  const sessionPolicy = buildEcdsaDerivationSessionPolicy({
    walletId,
    evmFamilySigningKeySlotId,
    chainTarget,
    ...(keyHandle ? { keyHandle } : {}),
    sessionId,
    signingGrantId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(participantIds ? { participantIds } : {}),
    ttlMs: exactSessionBootstrap ? args.lanePolicy.ttlMs : args.ttlMs,
    remainingUses: exactSessionBootstrap ? args.lanePolicy.remainingUses : args.remainingUses,
  });
  const ttlMs = sessionPolicy.ttlMs;
  const remainingUses = sessionPolicy.remainingUses;
  const runRoleLocalBootstrap = async (roleLocalArgs: {
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: SigningRootId;
    signingRootVersion: SigningRootVersion;
    relayerKeyId: string;
  }): Promise<EmailOtpThresholdEcdsaBootstrapResult> => {
    args.onProgress?.('signer.ecdsa.bootstrap.started');
    const applicationBindingDigestB64u =
      await computeSdkEcdsaDerivationApplicationBindingDigestB64u({
        walletId,
        ecdsaThresholdKeyId: roleLocalArgs.ecdsaThresholdKeyId,
        signingRootId: roleLocalArgs.signingRootId,
        signingRootVersion: roleLocalArgs.signingRootVersion,
      });
    const prepared = prepareEcdsaClientBootstrapFromResolvedEmailOtpRoot({
      context: {
        applicationBindingDigestB64u,
      },
      clientRootShare32: args.clientRootShare32,
    });
    const pendingStateBlobB64u = readString(
      prepared.pendingStateBlob.stateBlobB64u,
      'pendingStateBlob.stateBlobB64u',
    );
    const contextBinding32B64u = readString(
      prepared.clientBootstrap.contextBinding32B64u,
      'clientBootstrap.contextBinding32B64u',
    );
    const derivationClientSharePublicKey33B64u = readString(
      prepared.clientBootstrap.derivationClientSharePublicKey33B64u,
      'clientBootstrap.derivationClientSharePublicKey33B64u',
    ) as DerivationClientSharePublicKey33B64u;
    const preparedClientVerifyingShareB64u = readString(
      prepared.publicFacts.clientVerifyingShareB64u,
      'publicFacts.clientVerifyingShareB64u',
    );
    const clientShareRetryCounter = Math.floor(
      Number(prepared.clientBootstrap.clientShareRetryCounter),
    );
    if (!Number.isSafeInteger(clientShareRetryCounter) || clientShareRetryCounter < 0) {
      throw new Error('clientShareRetryCounter must be a non-negative safe integer');
    }

    const bootstrapParticipantIds = participantIds || [1, 2];
    const bootstrapIdentity = {
      walletId,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: roleLocalArgs.ecdsaThresholdKeyId,
      signingRootId: roleLocalArgs.signingRootId,
      signingRootVersion: roleLocalArgs.signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId: roleLocalArgs.relayerKeyId,
      derivationClientSharePublicKey33B64u,
      clientShareRetryCounter,
      contextBinding32B64u,
      requestId: keygenSessionId,
      sessionId,
      signingGrantId,
      ttlMs,
      remainingUses,
      participantIds: bootstrapParticipantIds,
    } satisfies EcdsaDerivationRoleLocalBootstrapIdentity;
    const clientRootProof = await buildEmailOtpEcdsaClientRootProof({
      bootstrapIdentity,
      clientRootShare32: args.clientRootShare32,
    });
    const bootstrapRequest = {
      formatVersion: 'ecdsa-derivation-role-local',
      ...bootstrapIdentity,
      auth: routeAuth,
      clientRootProof,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    } satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest;
    const bootstrap = await thresholdEcdsaDerivationRoleLocalBootstrap(
      relayerUrl,
      bootstrapRequest,
    );
    if (!bootstrap.ok) {
      throw new Error(
        bootstrap.error ||
          bootstrap.message ||
          bootstrap.code ||
          'Threshold role-local bootstrap failed',
      );
    }
    args.onProgress?.('signer.ecdsa.bootstrap.succeeded');

    const value = bootstrap.value;
    const resolvedParticipantIds =
      normalizeThresholdEd25519ParticipantIds(value.participantIds) || participantIds;
    if (!resolvedParticipantIds) {
      throw new Error('Threshold role-local bootstrap response missing participantIds');
    }
    if (
      value.publicIdentity.derivationClientSharePublicKey33B64u !==
      derivationClientSharePublicKey33B64u
    ) {
      throw new Error('Threshold role-local bootstrap returned mismatched client public identity');
    }
    const finalized = finalizeEcdsaClientBootstrapWithGeneratedCommand({
      pendingStateBlobB64u,
      relayerKeyId: value.relayerKeyId,
      relayerPublicKey33B64u: value.publicIdentity.relayerPublicKey33B64u,
      groupPublicKey33B64u: value.publicIdentity.groupPublicKey33B64u,
      ethereumAddress: value.publicIdentity.ethereumAddress,
      relayerShareRetryCounter: value.relayerShareRetryCounter,
    });
    const readyStateBlobB64u = readString(
      finalized.stateBlob.stateBlobB64u,
      'stateBlob.stateBlobB64u',
    );
    const clientVerifyingShareB64u = readString(
      finalized.publicFacts.clientVerifyingShareB64u,
      'publicFacts.clientVerifyingShareB64u',
    );
    if (clientVerifyingShareB64u !== preparedClientVerifyingShareB64u) {
      throw new Error('Threshold role-local finalize returned mismatched client public facts');
    }
    const openedShare = open_ecdsa_role_local_signing_share_v1({
      stateBlobB64u: readyStateBlobB64u,
    }) as { signingShare32B64u?: unknown };
    const emailOtpClientAdditiveShare32 = base64UrlDecode(
      readString(openedShare.signingShare32B64u, 'signingShare32B64u'),
    );
    if (emailOtpClientAdditiveShare32.length !== 32) {
      zeroizeBytes(emailOtpClientAdditiveShare32);
      throw new Error('signingShare32B64u must decode to 32 bytes');
    }
    const readyStateBlob = {
      kind: 'ecdsa_role_local_state_blob_v1' as const,
      curve: 'secp256k1' as const,
      encoding: 'base64url' as const,
      producer: 'signer_core' as const,
      stateBlobB64u: readyStateBlobB64u,
    };
    const publicFacts = buildEcdsaRoleLocalPublicFacts({
      walletId,
      evmFamilySigningKeySlotId,
      chainTarget,
      keyHandle: value.keyHandle,
      ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
      signingRootId: value.signingRootId,
      signingRootVersion: value.signingRootVersion,
      applicationBindingDigestB64u,
      participantIds: resolvedParticipantIds,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      contextBinding32B64u,
      derivationClientSharePublicKey33B64u,
      relayerPublicKey33B64u: readString(
        finalized.publicFacts.relayerPublicKey33B64u,
        'publicFacts.relayerPublicKey33B64u',
      ),
      groupPublicKey33B64u: readString(
        finalized.publicFacts.groupPublicKey33B64u,
        'publicFacts.groupPublicKey33B64u',
      ),
      ethereumAddress: readString(
        finalized.publicFacts.ethereumAddress,
        'publicFacts.ethereumAddress',
      ),
    });
    const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
      stateBlob: readyStateBlob,
      publicFacts,
      authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
        authSubjectId: exactSessionBootstrap ? walletId : args.authSubjectId,
      }),
    });
    const clientAdditiveShareHandle = {
      kind: 'email_otp_worker_session' as const,
      sessionId: value.thresholdSessionId,
    };
    const walletSessionJwt =
      readOptionalString(value.jwt) ||
      (routeAuth.kind === 'wallet_session' ? readOptionalString(routeAuth.jwt) : undefined);
    return {
      thresholdEcdsaKeyRef: {
        type: 'threshold-ecdsa-secp256k1',
        userId: walletId,
        evmFamilySigningKeySlotId,
        chainTarget,
        relayerUrl,
        keyHandle: value.keyHandle,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        backendBinding: {
          materialKind: 'email_otp_worker_handle',
          relayerKeyId: value.relayerKeyId,
          clientVerifyingShareB64u,
          clientAdditiveShareHandle,
          ecdsaRoleLocalReadyRecord,
        },
        participantIds: resolvedParticipantIds,
        thresholdEcdsaPublicKeyB64u: value.thresholdEcdsaPublicKeyB64u,
        ethereumAddress: value.ethereumAddress,
        relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
        thresholdSessionKind: sessionKind,
        ...(walletSessionJwt ? { walletSessionJwt } : {}),
        thresholdSessionId: value.thresholdSessionId,
        signingGrantId: value.signingGrantId,
        routerAbEcdsaDerivationNormalSigning: value.routerAbEcdsaDerivationNormalSigning,
      },
      keygen: {
        ok: true,
        keygenSessionId,
        evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: value.ecdsaThresholdKeyId,
        clientVerifyingShareB64u,
        relayerKeyId: value.relayerKeyId,
        thresholdEcdsaPublicKeyB64u: value.thresholdEcdsaPublicKeyB64u,
        ethereumAddress: value.ethereumAddress,
        relayerVerifyingShareB64u: value.relayerVerifyingShareB64u,
        participantIds: resolvedParticipantIds,
        chainId,
      },
      session: {
        ok: true,
        thresholdSessionId: value.thresholdSessionId,
        signingGrantId: value.signingGrantId,
        expiresAtMs: value.expiresAtMs,
        remainingUses: value.remainingUses,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(walletSessionJwt ? { jwt: walletSessionJwt } : {}),
        clientVerifyingShareB64u,
      },
      emailOtpClientAdditiveShare32,
    };
  };

  const roleLocalRelayerKeyId = relayerKeyIdFromRouteAuth(routeAuth);
  if (exactSessionBootstrap && roleLocalRelayerKeyId) {
    if (!runtimePolicyScope) {
      throw new Error('Email OTP ECDSA session bootstrap requires runtime policy scope');
    }
    const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    const signingRootId = toEcdsaDerivationSigningRootId(signingRootScope.signingRootId);
    const signingRootVersion = toEcdsaDerivationSigningRootVersion(
      signingRootScope.signingRootVersion,
    );
    const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId(
      await computeEcdsaDerivationRoleLocalThresholdKeyId({
        walletId,
        evmFamilySigningKeySlotId,
        signingRootId,
        signingRootVersion,
      }),
    );
    const expectedKeyHandle = await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
    });
    if (String(expectedKeyHandle) !== keyHandle) {
      throw new Error('Email OTP ECDSA keyHandle does not match runtime policy key identity');
    }
    return await runRoleLocalBootstrap({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      relayerKeyId: roleLocalRelayerKeyId,
    });
  }

  if (!exactSessionBootstrap && operation === 'email_otp_bootstrap' && runtimePolicyScope) {
    const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    const signingRootId = toEcdsaDerivationSigningRootId(signingRootScope.signingRootId);
    const signingRootVersion = toEcdsaDerivationSigningRootVersion(
      signingRootScope.signingRootVersion,
    );
    const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId(
      await computeEcdsaDerivationRoleLocalThresholdKeyId({
        walletId,
        evmFamilySigningKeySlotId,
        signingRootId,
        signingRootVersion,
      }),
    );
    if (keyHandle) {
      const expectedKeyHandle = await deriveEvmFamilyEcdsaKeyHandle({
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
      });
      if (String(expectedKeyHandle) !== keyHandle) {
        throw new Error('Email OTP ECDSA keyHandle does not match runtime policy key identity');
      }
    }
    return await runRoleLocalBootstrap({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      relayerKeyId: await computeEcdsaDerivationRoleLocalRelayerKeyId({
        walletId,
        evmFamilySigningKeySlotId,
      }),
    });
  }

  throw new Error('Threshold ECDSA Email OTP bootstrap requires runtimePolicyScope');
}

async function runEmailOtpEcdsaPublicationBootstrapsFromClientRootShare(args: {
  relayUrl: string;
  walletSessionUserId: string;
  authSubjectId: string;
  clientRootShare32: Uint8Array;
  publicationTargetPlans: EmailOtpEcdsaPublicationTargetPlan[];
  participantIds?: number[];
  sessionKind?: 'jwt';
  sessionId?: string;
  signingGrantId?: string;
  routeAuth?: AppOrWalletSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<ThresholdEcdsaSessionBootstrapResult[]> {
  const publicationTargetPlans = args.publicationTargetPlans;
  if (!publicationTargetPlans.length) {
    throw new Error('Email OTP ECDSA bootstrap requires at least one publication target');
  }
  if (publicationTargetPlans.length > 1 && String(args.sessionId || '').trim()) {
    throw new Error('Email OTP multi-target ECDSA bootstrap requires per-target session ids');
  }
  const signingGrantId = String(args.signingGrantId || '').trim() || generateSigningGrantId();
  const bootstraps: ThresholdEcdsaSessionBootstrapResult[] = [];

  for (const plan of publicationTargetPlans) {
    const { chainTarget, evmFamilySigningKeySlotId } = plan;
    const walletSessionUserId = toWalletSessionUserId(args.walletSessionUserId);
    const authSubjectId = toEmailOtpAuthSubjectId(args.authSubjectId);
    const workerBootstrap = await runThresholdEcdsaAuthorizationBootstrapFromClientRootShare({
      relayUrl: args.relayUrl,
      walletSessionUserId,
      authSubjectId,
      evmFamilySigningKeySlotId,
      clientRootShare32: args.clientRootShare32,
      operation: 'email_otp_bootstrap',
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: publicationTargetPlans.length === 1 && args.sessionId ? args.sessionId : undefined,
      signingGrantId,
      chainTarget,
      routeAuth: args.routeAuth,
      runtimePolicyScope: args.runtimePolicyScope,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      onProgress: args.onProgress,
    });
    const { emailOtpClientAdditiveShare32, ...bootstrap }: EmailOtpThresholdEcdsaBootstrapResult =
      workerBootstrap;
    let signingSessionSecret32: Uint8Array | null = Uint8Array.from(args.clientRootShare32);
    try {
      putEmailOtpWarmSessionMaterial({
        sessionId: readString(bootstrap.session?.thresholdSessionId, 'thresholdSessionId'),
        clientRootShare32: args.clientRootShare32,
        signingSessionSecret32,
        clientAdditiveShare32: emailOtpClientAdditiveShare32,
        expiresAtMs: Math.floor(Number(bootstrap.session?.expiresAtMs) || 0),
        remainingUses: Math.floor(Number(bootstrap.session?.remainingUses) || 0),
      });
      bootstraps.push(bootstrap);
      const ecdsaRoleLocalReadyRecord =
        bootstrap.thresholdEcdsaKeyRef.backendBinding?.ecdsaRoleLocalReadyRecord;
      if (!ecdsaRoleLocalReadyRecord) {
        throw new Error('Email OTP ECDSA publication returned missing role-local identity');
      }
    } finally {
      zeroizeBytes(signingSessionSecret32);
      zeroizeBytes(emailOtpClientAdditiveShare32);
      signingSessionSecret32 = null;
    }
  }
  return bootstraps;
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  (
    self as unknown as { postMessage: (message: unknown, transfer?: Transferable[]) => void }
  ).postMessage(message, transfer);
}

function postEmailOtpWorkerProgress(id: string, code: EmailOtpWorkerProgressCode): void {
  postToMainThread({ id, progress: true, payload: { code } });
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
  if (obj.kind !== 'router_ab_ed25519_yao_email_otp_recovery_v1') {
    throw new Error('Email OTP Ed25519 Yao recovery augmentation kind is invalid');
  }
  const signerSlot = normalizePositiveInteger(obj.signerSlot);
  if (!signerSlot) throw new Error('Email OTP Ed25519 Yao recovery signerSlot is invalid');
  const remainingUses = normalizePositiveInteger(obj.remainingUses);
  if (!remainingUses) throw new Error('Email OTP Ed25519 Yao recovery budget is invalid');
  return {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
    signerSlot,
    remainingUses,
    orgId: readString(obj.orgId, 'ed25519YaoRecovery.orgId'),
  };
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
        ['kind', 'ecdsaClientRootHandleBinding', 'runtimePolicyScope'],
        'material',
      );
      const binding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        obj.ecdsaClientRootHandleBinding,
      );
      if (!binding) throw new Error('Email OTP ECDSA wallet unlock requires its root binding');
      return {
        kind: 'ecdsa',
        ecdsaClientRootHandleBinding: binding,
        runtimePolicyScope: parseWorkerRuntimePolicyScope(
          obj.runtimePolicyScope,
          'Email OTP ECDSA wallet unlock',
        ),
      };
    }
    case 'ed25519_yao_recovery':
      rejectUnknownEmailOtpYaoFields(
        obj,
        ['kind', 'ed25519YaoRecovery', 'providerSubject'],
        'material',
      );
      return {
        kind: 'ed25519_yao_recovery',
        ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryAugmentation(obj.ed25519YaoRecovery),
        providerSubject: readString(obj.providerSubject, 'material.providerSubject'),
      };
    case 'ecdsa_and_ed25519_yao_recovery': {
      rejectUnknownEmailOtpYaoFields(
        obj,
        [
          'kind',
          'ecdsaClientRootHandleBinding',
          'runtimePolicyScope',
          'ed25519YaoRecovery',
          'providerSubject',
        ],
        'material',
      );
      const binding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        obj.ecdsaClientRootHandleBinding,
      );
      if (!binding) throw new Error('Mixed Email OTP unlock requires its ECDSA root binding');
      return {
        kind: 'ecdsa_and_ed25519_yao_recovery',
        ecdsaClientRootHandleBinding: binding,
        runtimePolicyScope: parseWorkerRuntimePolicyScope(
          obj.runtimePolicyScope,
          'Mixed Email OTP wallet unlock',
        ),
        ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryAugmentation(obj.ed25519YaoRecovery),
        providerSubject: readString(obj.providerSubject, 'material.providerSubject'),
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
      'signingGrantId',
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
    signingGrantId: readString(obj.signingGrantId, 'session.signingGrantId'),
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

function parseEmailOtpEd25519YaoActiveCapability(
  value: unknown,
): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao active capability is required');
  rejectUnknownEmailOtpYaoFields(
    obj,
    [
      'kind',
      'activeCapabilityBinding',
      'registeredPublicKey',
      'nearAccountId',
      'applicationBinding',
      'runtimePolicyScope',
      'participantIds',
      'lifecycle',
      'stateEpoch',
    ],
    'ed25519YaoRecovery.capability',
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
      'walletSessionId',
      'signerSetId',
      'signingWorkerId',
    ],
    'ed25519YaoRecovery.capability.lifecycle',
  );
  const signerSlot = normalizePositiveInteger(application.key_creation_signer_slot);
  const stateEpoch = normalizePositiveInteger(obj.stateEpoch);
  if (!signerSlot || !stateEpoch) {
    throw new Error('Email OTP Ed25519 Yao active capability epoch or signer slot is invalid');
  }
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
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
      walletSessionId: readString(lifecycle.walletSessionId, 'lifecycle.walletSessionId'),
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
  if (obj.kind !== 'router_ab_ed25519_yao_email_otp_recovery_v1') {
    throw new Error('Email OTP Ed25519 Yao recovery bootstrap kind is invalid');
  }
  return {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
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
  const signingGrantId = optionalWorkerString(obj.signingGrantId);
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
    !signingGrantId ||
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
    signingLane.signingGrantId === signingGrantId &&
    routerAbNormalSigning.kind === 'router_ab_ed25519_normal_signing_v1' &&
    optionalWorkerString(routerAbNormalSigning.signingWorkerId) != null &&
    signingWalletSession.curve === 'ed25519' &&
    signingWalletSession.thresholdSessionId === thresholdSessionId &&
    signingWalletSession.signingGrantId === signingGrantId &&
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
  return {
    evmFamilySigningKeySlotId: String(
      readEvmFamilySigningKeySlotId(
        obj.evmFamilySigningKeySlotId,
        'ecdsaClientRootHandleBinding.evmFamilySigningKeySlotId',
      ),
    ),
    authSubjectId: readString(obj.authSubjectId, 'ecdsaClientRootHandleBinding.authSubjectId'),
    action: 'threshold_ecdsa_bootstrap',
    operation: parseEmailOtpWorkerHandleOperation(obj.operation),
    chainTarget: parseWorkerChainTarget(obj.chainTarget),
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
    action: 'threshold_ecdsa_bootstrap',
    operation: parseEmailOtpWorkerHandleOperation(obj.operation),
    chainTarget: parseWorkerChainTarget(obj.chainTarget),
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

function parseEmailOtpPrepareEcdsaClientBootstrapInput(
  value: unknown,
): EmailOtpPrepareEcdsaClientBootstrapInput {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP ECDSA prepare requires input');
  }
  const kind = readString(obj.kind, 'input.kind');
  const algorithm = readString(obj.algorithm, 'input.algorithm');
  if (kind !== 'prepare_ecdsa_client_bootstrap_v1') {
    throw new Error(`Unsupported Email OTP ECDSA prepare command kind: ${kind}`);
  }
  if (algorithm !== 'router_ab_ecdsa_derivation_secp256k1_role_local_v1') {
    throw new Error(`Unsupported Email OTP ECDSA prepare algorithm: ${algorithm}`);
  }
  const context = workerPayloadObject(obj.context);
  if (!context) {
    throw new Error('Email OTP ECDSA prepare requires context');
  }
  const participants = workerPayloadObject(obj.participants);
  if (!participants) {
    throw new Error('Email OTP ECDSA prepare requires participants');
  }
  const clientParticipantId = readNumber(
    participants.clientParticipantId,
    'participants.clientParticipantId',
  );
  const relayerParticipantId = readNumber(
    participants.relayerParticipantId,
    'participants.relayerParticipantId',
  );
  const participantIds = normalizeThresholdEd25519ParticipantIds(participants.participantIds);
  if (
    clientParticipantId !== 1 ||
    relayerParticipantId !== 2 ||
    !participantIds ||
    participantIds.length !== 2 ||
    participantIds[0] !== 1 ||
    participantIds[1] !== 2
  ) {
    throw new Error('Email OTP ECDSA prepare requires participant ids [1, 2]');
  }
  const secretSource = workerPayloadObject(obj.secretSource);
  if (!secretSource) {
    throw new Error('Email OTP ECDSA prepare requires secretSource');
  }
  const secretSourceKind = readString(secretSource.kind, 'secretSource.kind');
  if (secretSourceKind !== 'email_otp_worker_session') {
    throw new Error(`Unsupported Email OTP ECDSA prepare secretSource: ${secretSourceKind}`);
  }
  const handle = parseWorkerIssuedEcdsaSessionBootstrapClientRootHandle(secretSource.handle);
  const brandedHandle = buildEmailOtpWorkerIssuedSessionHandle({
    sessionId: handle.sessionId,
    walletId: toWalletId(handle.walletId),
    evmFamilySigningKeySlotId: readEvmFamilySigningKeySlotId(
      handle.evmFamilySigningKeySlotId,
      'clientRootShareHandle.evmFamilySigningKeySlotId',
    ),
    authSubjectId: toEmailOtpAuthSubjectId(handle.authSubjectId),
    action: 'threshold_ecdsa_bootstrap',
    operation: handle.operation,
    chainTarget: handle.chainTarget,
  });
  return {
    kind: 'prepare_ecdsa_client_bootstrap_v1',
    algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
    context: {
      applicationBindingDigestB64u: readString(
        context.applicationBindingDigestB64u,
        'context.applicationBindingDigestB64u',
      ),
    },
    participants: {
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
    },
    secretSource: buildEmailOtpWorkerSessionSecretSource(brandedHandle),
  };
}

function parseWorkerParticipantIds(value: unknown): number[] | undefined {
  const participantIds = normalizeThresholdEd25519ParticipantIds(value);
  return participantIds || undefined;
}

function parseWalletRegistrationEcdsaPrepareContext(
  value: unknown,
): WalletRegistrationEcdsaPrepareContext {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP wallet-registration ECDSA prepare requires prepare context');
  }
  const formatVersion = readString(obj.formatVersion, 'prepare.formatVersion');
  if (formatVersion !== 'ecdsa-derivation-role-local') {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare requires ecdsa-derivation-role-local format',
    );
  }
  const keyScope = readString(obj.keyScope, 'prepare.keyScope');
  if (keyScope !== 'evm-family') {
    throw new Error('Email OTP wallet-registration ECDSA prepare requires evm-family keyScope');
  }
  const ttlMs = optionalWorkerPositiveInteger(obj.ttlMs);
  const remainingUses = optionalWorkerPositiveInteger(obj.remainingUses);
  const participantIds = parseWorkerParticipantIds(obj.participantIds);
  if (
    !ttlMs ||
    !remainingUses ||
    !participantIds ||
    participantIds.length !== 2 ||
    participantIds[0] !== 1 ||
    participantIds[1] !== 2
  ) {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare requires ttl, uses, and participants',
    );
  }
  const registrationPreparationId = registrationPreparationIdFromString(
    readString(obj.registrationPreparationId, 'prepare.registrationPreparationId'),
  );
  const runtimePolicyScope = parseOptionalWorkerRuntimePolicyScope(obj.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error('Email OTP wallet-registration ECDSA prepare requires runtimePolicyScope');
  }
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: readString(obj.walletId, 'prepare.walletId'),
    evmFamilySigningKeySlotId: String(
      readEvmFamilySigningKeySlotId(
        obj.evmFamilySigningKeySlotId,
        'prepare.evmFamilySigningKeySlotId',
      ),
    ),
    ecdsaThresholdKeyId: readString(obj.ecdsaThresholdKeyId, 'prepare.ecdsaThresholdKeyId'),
    signingRootId: readString(obj.signingRootId, 'prepare.signingRootId'),
    signingRootVersion: readString(obj.signingRootVersion, 'prepare.signingRootVersion'),
    keyScope: 'evm-family',
    relayerKeyId: readString(obj.relayerKeyId, 'prepare.relayerKeyId'),
    registrationPreparationId,
    requestId: readString(obj.requestId, 'prepare.requestId'),
    thresholdSessionId: readString(obj.thresholdSessionId, 'prepare.thresholdSessionId'),
    signingGrantId: readSigningGrantId(obj.signingGrantId, 'prepare.signingGrantId'),
    ttlMs,
    remainingUses,
    participantIds: [1, 2],
    runtimePolicyScope,
  };
}

function parseWorkerSealTransport(value: unknown): {
  relayerUrl: string;
  walletSessionJwt?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  shamirPrimeB64u?: string;
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
    ...(optionalWorkerString(obj.shamirPrimeB64u)
      ? { shamirPrimeB64u: optionalWorkerString(obj.shamirPrimeB64u)! }
      : {}),
  };
}

function parseRequiredWorkerSealTransport(value: unknown): {
  relayerUrl: string;
  walletSessionJwt: string;
  signingSessionSealKeyVersion: SigningSessionSealKeyVersion;
  shamirPrimeB64u: string;
} {
  const transport = parseWorkerSealTransport(value);
  if (
    !transport.walletSessionJwt ||
    !transport.signingSessionSealKeyVersion ||
    !transport.shamirPrimeB64u
  ) {
    throw new Error('Email OTP Ed25519 Yao rehydrate requires exact seal transport');
  }
  return {
    relayerUrl: transport.relayerUrl,
    walletSessionJwt: transport.walletSessionJwt,
    signingSessionSealKeyVersion: transport.signingSessionSealKeyVersion,
    shamirPrimeB64u: transport.shamirPrimeB64u,
  };
}

function readRegistrationRoutePlan(value: unknown, label: string): EmailOtpRoutePlan {
  const routePlan = readRoutePlan(value, label);
  if (routePlan.routeFamily !== 'registration') {
    throw new Error(`${label} requires an Email OTP registration route plan`);
  }
  return routePlan;
}

function parseEmailOtpWorkerRequest(raw: unknown): EmailOtpWorkerRequest | null {
  const obj = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
  if (!obj) return null;
  const id = normalizeOptionalTrimmedString(obj.id);
  const type = normalizeOptionalTrimmedString(obj.type);
  const payload = workerPayloadObject(obj.payload);
  if (!id || !type || !payload) return null;

  switch (type) {
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
          shamirPrimeB64u: readString(payload.shamirPrimeB64u, 'shamirPrimeB64u'),
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
          ...(parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
            payload.ecdsaClientRootHandleBinding,
          )
            ? {
                ecdsaClientRootHandleBinding: parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
                  payload.ecdsaClientRootHandleBinding,
                )!,
              }
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
          shamirPrimeB64u: readString(payload.shamirPrimeB64u, 'shamirPrimeB64u'),
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
    case 'commitEmailOtpEd25519YaoRegistration':
      rejectUnknownEmailOtpYaoFields(payload, ['pendingHandle', 'walletSessionState'], type);
      return {
        id,
        type,
        payload: {
          pendingHandle: readString(payload.pendingHandle, 'pendingHandle'),
          walletSessionState: parseEmailOtpEd25519YaoWalletSessionState(payload.walletSessionState),
        },
      };
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
    case 'prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle':
      return {
        id,
        type,
        payload: {
          prepare: parseWalletRegistrationEcdsaPrepareContext(payload.prepare),
          clientRootShareHandle: parseWorkerIssuedWalletRegistrationEcdsaPrepareClientRootHandle(
            payload.clientRootShareHandle,
          ),
          chainTarget: parseWorkerChainTarget(payload.chainTarget),
        },
      };
    case 'commitEmailOtpEcdsaRegistrationWarmMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'walletId',
          'chainTarget',
          'retainedClientRootShareHandle',
          'thresholdSessionId',
          'expiresAtMs',
          'remainingUses',
        ],
        type,
      );
      const expiresAtMs = normalizePositiveInteger(payload.expiresAtMs);
      const remainingUses = normalizePositiveInteger(payload.remainingUses);
      if (!expiresAtMs || !remainingUses) {
        throw new Error('Email OTP ECDSA registration warm-material policy is invalid');
      }
      return {
        id,
        type,
        payload: {
          walletId: readString(payload.walletId, 'walletId'),
          chainTarget: parseWorkerChainTarget(payload.chainTarget),
          retainedClientRootShareHandle:
            parseWorkerIssuedWalletRegistrationEcdsaPrepareClientRootHandle(
              payload.retainedClientRootShareHandle,
            ),
          thresholdSessionId: readString(payload.thresholdSessionId, 'thresholdSessionId'),
          expiresAtMs,
          remainingUses,
        },
      };
    }
    case 'prepareEcdsaClientBootstrapFromEmailOtpHandle':
      return {
        id,
        type,
        payload: {
          input: parseEmailOtpPrepareEcdsaClientBootstrapInput(payload.input),
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
          shamirPrimeB64u: readString(payload.shamirPrimeB64u, 'shamirPrimeB64u'),
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
          ...(optionalWorkerString(payload.challengeId)
            ? { challengeId: optionalWorkerString(payload.challengeId)! }
            : {}),
          otpCode: readString(payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan: readRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
          material: parseEmailOtpWalletUnlockMaterialRequest(payload.material),
        },
      };
    case 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle': {
      const chainTarget = parseWorkerChainTarget(payload.chainTarget);
      if (payload.sessionKind !== 'jwt') {
        throw new Error('Email OTP ECDSA bootstrap requires JWT signing sessions');
      }
      const walletId = readString(payload.walletId, 'walletId');
      const runtimePolicyScope = parseWorkerRuntimePolicyScope(
        payload.runtimePolicyScope,
        'Email OTP ECDSA bootstrap',
      );
      const clientRootShareHandle = parseWorkerIssuedEcdsaSessionBootstrapClientRootHandle(
        payload.clientRootShareHandle,
      );
      const basePayload = {
        relayUrl: readString(payload.relayUrl, 'relayUrl'),
        walletId,
        walletSessionUserId: readString(payload.walletSessionUserId, 'walletSessionUserId'),
        userId: readString(payload.userId, 'userId'),
        clientRootShareHandle,
        chainTarget,
        publicationTargetPlans: readEcdsaPublicationTargetPlans({
          walletId,
          primaryChainTarget: chainTarget,
          primaryEvmFamilySigningKeySlotId: clientRootShareHandle.evmFamilySigningKeySlotId,
          publicationTargetPlans: payload.publicationTargetPlans,
          runtimePolicyScope,
        }),
        runtimePolicyScope,
        ...(parseWorkerParticipantIds(payload.participantIds)
          ? { participantIds: parseWorkerParticipantIds(payload.participantIds)! }
          : {}),
        ...(optionalWorkerString(payload.sessionId)
          ? { sessionId: optionalWorkerString(payload.sessionId)! }
          : {}),
        ...(optionalWorkerString(payload.signingGrantId)
          ? { signingGrantId: optionalWorkerString(payload.signingGrantId)! }
          : {}),
        ...(optionalWorkerPositiveInteger(payload.ttlMs)
          ? { ttlMs: optionalWorkerPositiveInteger(payload.ttlMs)! }
          : {}),
        ...(optionalWorkerNonNegativeInteger(payload.remainingUses) != null
          ? { remainingUses: optionalWorkerNonNegativeInteger(payload.remainingUses)! }
          : {}),
      };
      return {
        id,
        type,
        payload: {
          ...basePayload,
          sessionKind: 'jwt',
          routeAuth: parseWorkerRouteAuth(payload.routeAuth, 'Email OTP ECDSA bootstrap'),
        },
      };
    }
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
        payload: { sessionId: readString(payload.sessionId, 'sessionId') },
      };
    case 'claimEmailOtpWarmSessionMaterial':
      return {
        id,
        type,
        payload: {
          sessionId: readString(payload.sessionId, 'sessionId'),
          ...(optionalWorkerPositiveInteger(payload.uses)
            ? { uses: optionalWorkerPositiveInteger(payload.uses)! }
            : {}),
          ...(typeof payload.consume === 'boolean' ? { consume: payload.consume } : {}),
        },
      };
    case 'consumeEmailOtpWarmSessionUses':
      return {
        id,
        type,
        payload: {
          sessionId: readString(payload.sessionId, 'sessionId'),
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
          sessionId: readString(payload.sessionId, 'sessionId'),
          transport: parseWorkerSealTransport(payload.transport),
        },
      };
    case 'rehydrateEmailOtpEcdsaWarmSessionMaterial': {
      const restore = workerPayloadObject(payload.restore);
      if (!restore) throw new Error('Email OTP ECDSA rehydrate requires restore payload');
      return {
        id,
        type,
        payload: {
          sealedSecretB64u: readString(payload.sealedSecretB64u, 'sealedSecretB64u'),
          remainingUses: normalizeNonNegativeInteger(payload.remainingUses) ?? 0,
          expiresAtMs: readNumber(payload.expiresAtMs, 'expiresAtMs'),
          transport: parseWorkerSealTransport(payload.transport),
          restore: {
            sessionId: readString(restore.sessionId, 'restore.sessionId'),
            walletId: readString(restore.walletId, 'restore.walletId'),
            evmFamilySigningKeySlotId: String(
              readEvmFamilySigningKeySlotId(
                restore.evmFamilySigningKeySlotId,
                'restore.evmFamilySigningKeySlotId',
              ),
            ),
            chainTarget: parseWorkerChainTarget(restore.chainTarget),
            authSubjectId: readString(restore.authSubjectId, 'restore.authSubjectId'),
          },
        },
      };
    }
    case 'rehydrateEmailOtpEd25519YaoFactor': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['sealedSecretB64u', 'remainingUses', 'expiresAtMs', 'transport', 'restore'],
        type,
      );
      const restore = workerPayloadObject(payload.restore);
      if (!restore) throw new Error('Email OTP Ed25519 Yao rehydrate requires restore payload');
      rejectUnknownEmailOtpYaoFields(
        restore,
        ['sessionId', 'walletId', 'providerSubject'],
        'restore',
      );
      return {
        id,
        type,
        payload: {
          sealedSecretB64u: readString(payload.sealedSecretB64u, 'sealedSecretB64u'),
          remainingUses: normalizeNonNegativeInteger(payload.remainingUses) ?? 0,
          expiresAtMs: readNumber(payload.expiresAtMs, 'expiresAtMs'),
          transport: parseRequiredWorkerSealTransport(payload.transport),
          restore: {
            sessionId: readString(restore.sessionId, 'restore.sessionId'),
            walletId: readString(restore.walletId, 'restore.walletId'),
            providerSubject: readString(restore.providerSubject, 'restore.providerSubject'),
          },
        },
      };
    }
    case 'exportEmailOtpEd25519YaoSeedWithAuthorization':
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'relayUrl',
          'walletId',
          'userId',
          'challengeId',
          'otpCode',
          'shamirPrimeB64u',
          'routePlan',
          'walletSessionJwt',
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'signerSlot',
          'thresholdSessionId',
          'signingGrantId',
          'runtimePolicyScope',
          'capability',
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
          challengeId: readString(payload.challengeId, 'challengeId'),
          otpCode: readString(payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan: readRoutePlan(payload.routePlan, type),
          walletSessionJwt: readString(payload.walletSessionJwt, 'walletSessionJwt'),
          nearAccountId: readString(payload.nearAccountId, 'nearAccountId'),
          nearEd25519SigningKeyId: readString(
            payload.nearEd25519SigningKeyId,
            'nearEd25519SigningKeyId',
          ),
          signerSlot: normalizePositiveInteger(payload.signerSlot) || 0,
          thresholdSessionId: readString(payload.thresholdSessionId, 'thresholdSessionId'),
          signingGrantId: readString(payload.signingGrantId, 'signingGrantId'),
          runtimePolicyScope: parseWorkerRuntimePolicyScope(
            payload.runtimePolicyScope,
            'Email OTP Ed25519 Yao export',
          ),
          capability: parseEmailOtpEd25519YaoActiveCapability(payload.capability),
        },
      };
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
      case 'requestEmailOtpChallenge': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'requestEmailOtpChallenge');
        const sessionAuth = routePlanSessionAuth(routePlan);
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
        const delivery = response.delivery as Record<string, unknown> | undefined;
        const expiresAtMs = Number(challenge?.expiresAtMs);
        const emailHint = String(delivery?.emailHint || '').trim();
        const appSessionVersion = String(challenge?.appSessionVersion || '').trim();
        const result: {
          challengeId: string;
          otpChannel: typeof EMAIL_OTP_CHANNEL;
          emailHint?: string;
          expiresAtMs?: number;
          appSessionVersion?: string;
        } = {
          challengeId: readString(challenge?.challengeId, 'challengeId'),
          otpChannel: EMAIL_OTP_CHANNEL,
        };
        if (emailHint) {
          result.emailHint = emailHint;
        }
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
        const sessionAuth = routePlanSessionAuth(routePlan);
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
        const delivery = response.delivery as Record<string, unknown> | undefined;
        const expiresAtMs = Number(challenge?.expiresAtMs);
        const emailHint = String(delivery?.emailHint || '').trim();
        const appSessionVersion = String(challenge?.appSessionVersion || '').trim();
        const result: {
          challengeId: string;
          otpChannel: typeof EMAIL_OTP_CHANNEL;
          emailHint?: string;
          expiresAtMs?: number;
          appSessionVersion?: string;
        } = {
          challengeId: readString(challenge?.challengeId, 'challengeId'),
          otpChannel: EMAIL_OTP_CHANNEL,
        };
        if (emailHint) {
          result.emailHint = emailHint;
        }
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
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
          googleEmailOtpRegistrationAttemptId: msg.payload.googleEmailOtpRegistrationAttemptId,
          returnClientRootShare32: true,
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
        const clientRootShare32 = (() => {
          if (!(result.clientRootShare32 instanceof Uint8Array)) {
            throw new Error('Email OTP enrollment did not return client root share for bootstrap');
          }
          return result.clientRootShare32;
        })();
        const clientRootShareHandle = msg.payload.ecdsaClientRootHandleBinding
          ? issueEmailOtpEcdsaClientRootHandle({
              clientRootShare32,
              walletId: readString(msg.payload.walletId, 'walletId'),
              binding: msg.payload.ecdsaClientRootHandleBinding,
            })
          : undefined;
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
            ...(clientRootShareHandle ? { clientRootShareHandle } : {}),
          },
        });
        zeroizeBytes(result.clientRootShare32);
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
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
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
            },
          });
        } catch (error) {
          await disposeEmailOtpEd25519YaoPendingRegistration(pendingHandle);
          throw error;
        }
        return;
      }
      case 'commitEmailOtpEd25519YaoRegistration': {
        const entry = emailOtpEd25519YaoPendingRegistrations.get(msg.payload.pendingHandle);
        if (!entry) {
          throw new Error('Email OTP Ed25519 Yao pending registration is unavailable');
        }
        emailOtpEd25519YaoPendingRegistrations.delete(msg.payload.pendingHandle);
        const activation = new EmailOtpEd25519YaoWorkerActivationPort();
        let activationResult: EmailOtpEd25519YaoWorkerActivationResult | null = null;
        try {
          await entry.pending.commit({
            activation,
            walletSessionState: msg.payload.walletSessionState,
          });
          activationResult = activation.takeActivationResult();
          putEmailOtpEd25519YaoWarmFactor({
            sessionId: msg.payload.walletSessionState.thresholdSessionId,
            factorSecret32: entry.factorSecret32,
            expiresAtMs: msg.payload.walletSessionState.signingWalletSession.expiresAtMs,
            remainingUses: msg.payload.walletSessionState.remainingUses,
          });
          zeroizeBytes(entry.factorSecret32);
          postToMainThread({
            id: msg.id,
            ok: true,
            result: activationResult,
          });
        } catch (error) {
          zeroizeBytes(entry.factorSecret32);
          if (activationResult) {
            removeEmailOtpEd25519YaoActiveClient(activationResult.activeClientHandle);
          }
          await entry.pending.dispose();
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
          putEmailOtpEd25519YaoWarmFactor({
            sessionId: msg.payload.sessionPolicy.thresholdSessionId,
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
      case 'prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle': {
        let clientRootShare32: Uint8Array | null = null;
        try {
          await ensureEcdsaRegistrationClientWasm();
          const prepare = msg.payload.prepare;
          clientRootShare32 = claimEmailOtpWalletRegistrationEcdsaClientRootShare({
            handle: msg.payload.clientRootShareHandle,
            walletId: prepare.walletId,
            evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
            authSubjectId: msg.payload.clientRootShareHandle.authSubjectId,
            chainTarget: msg.payload.chainTarget,
          });
          const applicationBindingDigestB64u =
            await computeSdkEcdsaDerivationApplicationBindingDigestB64u({
              walletId: toWalletId(readString(prepare.walletId, 'prepare.walletId')),
              ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId(prepare.ecdsaThresholdKeyId),
              signingRootId: toEcdsaDerivationSigningRootId(prepare.signingRootId),
              signingRootVersion: toEcdsaDerivationSigningRootVersion(prepare.signingRootVersion),
            });
          const prepared = prepareEcdsaClientBootstrapFromResolvedEmailOtpRoot({
            context: {
              applicationBindingDigestB64u,
            },
            clientRootShare32,
          });
          const retainedClientRootShareHandle = issueEmailOtpEcdsaClientRootHandle({
            clientRootShare32,
            walletId: prepare.walletId,
            binding: msg.payload.clientRootShareHandle,
          });
          const clientBootstrap: WalletRegistrationEcdsaClientBootstrap = {
            ...prepare,
            derivationClientSharePublicKey33B64u:
              prepared.clientBootstrap.derivationClientSharePublicKey33B64u,
            clientShareRetryCounter: prepared.clientBootstrap.clientShareRetryCounter,
            contextBinding32B64u: prepared.clientBootstrap.contextBinding32B64u,
          };
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              clientBootstrap,
              pendingStateBlob: prepared.pendingStateBlob,
              preparePublicFacts: prepared.publicFacts,
              retainedClientRootShareHandle,
            },
          });
        } finally {
          zeroizeBytes(clientRootShare32);
        }
        return;
      }
      case 'commitEmailOtpEcdsaRegistrationWarmMaterial': {
        let clientRootShare32: Uint8Array | null = null;
        try {
          clientRootShare32 = claimEmailOtpWalletRegistrationEcdsaClientRootShare({
            handle: msg.payload.retainedClientRootShareHandle,
            walletId: msg.payload.walletId,
            evmFamilySigningKeySlotId:
              msg.payload.retainedClientRootShareHandle.evmFamilySigningKeySlotId,
            authSubjectId: msg.payload.retainedClientRootShareHandle.authSubjectId,
            chainTarget: msg.payload.chainTarget,
          });
          putEmailOtpWarmSessionMaterial({
            sessionId: msg.payload.thresholdSessionId,
            clientRootShare32,
            signingSessionSecret32: clientRootShare32,
            expiresAtMs: msg.payload.expiresAtMs,
            remainingUses: msg.payload.remainingUses,
          });
          postToMainThread({ id: msg.id, ok: true, result: { committed: true } });
        } finally {
          zeroizeBytes(clientRootShare32);
        }
        return;
      }
      case 'prepareEcdsaClientBootstrapFromEmailOtpHandle': {
        await ensureEcdsaRegistrationClientWasm();
        postToMainThread({
          id: msg.id,
          ok: true,
          result: prepareEcdsaClientBootstrapFromEmailOtpWorkerHandle(msg.payload.input),
        });
        return;
      }
      case 'verifyEmailOtpCode': {
        const routePlan = readRoutePlan(msg.payload.routePlan, 'verifyEmailOtpCode');
        const sessionAuth = routePlanSessionAuth(routePlan);
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
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
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
        const orgId =
          material.kind === 'ecdsa'
            ? material.runtimePolicyScope.orgId
            : material.ed25519YaoRecovery.orgId;
        const result = await loginWithEmailOtpAndUnlockWallet({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId,
          ...(orgId ? { orgId } : {}),
          userId: msg.payload.userId,
          challengeId: msg.payload.challengeId,
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
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
                  recovery,
                  clientRootShareHandle: issueEmailOtpEcdsaClientRootHandle({
                    clientRootShare32: result.clientRootShare32,
                    walletId,
                    binding: material.ecdsaClientRootHandleBinding,
                  }),
                },
              });
            } finally {
              zeroizeBytes(result.clientRootShare32);
            }
            return;
          case 'ecdsa_and_ed25519_yao_recovery': {
            if (material.kind !== 'ecdsa_and_ed25519_yao_recovery') {
              zeroizeBytes(result.clientRootShare32);
              zeroizeBytes(result.clientSecret32);
              throw new Error('Mixed Email OTP wallet unlock material branch changed');
            }
            let clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload | null = null;
            let ed25519YaoFactor: ReturnType<typeof issueEmailOtpEd25519YaoPendingFactor> | null =
              null;
            try {
              clientRootShareHandle = issueEmailOtpEcdsaClientRootHandle({
                clientRootShare32: result.clientRootShare32,
                walletId,
                binding: material.ecdsaClientRootHandleBinding,
              });
              ed25519YaoFactor = issueEmailOtpEd25519YaoPendingFactor({
                request: {
                  kind: 'requested',
                  providerSubject: material.providerSubject,
                },
                purpose: 'recovery',
                walletId,
                ownedFactorSecret32: result.clientSecret32,
              });
              if (ed25519YaoFactor.kind !== 'issued') {
                throw new Error('Mixed Email OTP unlock did not issue its Ed25519 Yao factor');
              }
              postToMainThread({
                id: msg.id,
                ok: true,
                result: {
                  kind: 'ecdsa_and_ed25519_yao_recovery',
                  recovery,
                  clientRootShareHandle,
                  pendingFactorHandle: ed25519YaoFactor.pendingFactorHandle,
                  ed25519YaoRecovery: result.ed25519YaoRecovery,
                },
              });
            } catch (error) {
              if (clientRootShareHandle) {
                deleteEmailOtpEcdsaClientRootHandle(clientRootShareHandle.sessionId);
              }
              if (ed25519YaoFactor?.kind === 'issued') {
                rollbackEmailOtpEd25519YaoFactorResult(ed25519YaoFactor);
              }
              throw error;
            } finally {
              zeroizeBytes(result.clientRootShare32);
              zeroizeBytes(result.clientSecret32);
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
          case 'ed25519_yao_export':
            zeroizeBytes(result.clientSecret32);
            throw new Error('Email OTP wallet unlock returned export-only material');
          default:
            return assertNeverEmailOtpWorker(result);
        }
      }
      case 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle': {
        let clientRootShare32: Uint8Array | null = null;
        try {
          const relayerUrl = readString(msg.payload.relayUrl, 'relayUrl');
          const walletId = readString(msg.payload.walletId, 'walletId');
          const walletSessionUserId = readString(
            msg.payload.walletSessionUserId,
            'walletSessionUserId',
          );
          const userId = readString(msg.payload.userId, 'userId');
          const primaryPlan = msg.payload.publicationTargetPlans[0];
          if (!primaryPlan) {
            throw new Error('Email OTP ECDSA bootstrap requires a primary publication target');
          }
          const evmFamilySigningKeySlotId = String(
            readEvmFamilySigningKeySlotId(
              primaryPlan.evmFamilySigningKeySlotId,
              'primaryPublicationTarget.evmFamilySigningKeySlotId',
            ),
          );
          clientRootShare32 = claimEmailOtpEcdsaClientRootShare({
            handle: msg.payload.clientRootShareHandle,
            walletId,
            evmFamilySigningKeySlotId,
            authSubjectId: userId,
            chainTarget: primaryPlan.chainTarget,
          });
          const bootstraps = await runEmailOtpEcdsaPublicationBootstrapsFromClientRootShare({
            relayUrl: relayerUrl,
            walletSessionUserId,
            authSubjectId: userId,
            clientRootShare32,
            publicationTargetPlans: msg.payload.publicationTargetPlans,
            participantIds: msg.payload.participantIds,
            sessionKind: msg.payload.sessionKind,
            sessionId: msg.payload.sessionId,
            signingGrantId: msg.payload.signingGrantId,
            routeAuth: msg.payload.routeAuth,
            runtimePolicyScope: msg.payload.runtimePolicyScope,
            ttlMs: msg.payload.ttlMs,
            remainingUses: msg.payload.remainingUses,
            onProgress: (code) => postEmailOtpWorkerProgress(msg.id, code),
          });
          const primaryBootstrap = bootstraps[0];
          if (!primaryBootstrap) {
            throw new Error('Email OTP ECDSA bootstrap returned no publication lanes');
          }
          postToMainThread({
            id: msg.id,
            ok: true,
            result: { bootstraps },
          });
        } finally {
          zeroizeBytes(clientRootShare32);
          clientRootShare32 = null;
        }
        return;
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
            consume: msg.payload.consume,
          }),
        });
        return;
      }
      case 'consumeEmailOtpWarmSessionUses': {
        postToMainThread({
          id: msg.id,
          ok: true,
          result: consumeEmailOtpWarmSessionUses({
            sessionId: readString(msg.payload.sessionId, 'sessionId'),
            uses: msg.payload.uses,
          }),
        });
        return;
      }
      case 'sealEmailOtpWarmSessionMaterial': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await sealEmailOtpWarmSessionMaterial({
              sessionId: readString(msg.payload.sessionId, 'sessionId'),
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
      case 'rehydrateEmailOtpEd25519YaoFactor': {
        const transport = parseSigningSessionSealTransport(msg.payload.transport);
        const result = transport
          ? await rehydrateEmailOtpEd25519YaoFactor({
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
      case 'clearEmailOtpWarmSessionMaterial': {
        deleteEmailOtpWarmMaterial(readString(msg.payload.sessionId, 'sessionId'));
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
        const routePlan = readRoutePlan(
          msg.payload.routePlan,
          'exportEmailOtpEd25519YaoSeedWithAuthorization',
        );
        if (routePlan.operation !== WALLET_EMAIL_OTP_EXPORT_OPERATION) {
          throw new Error('Email OTP Ed25519 Yao export requires export_key routePlan');
        }
        const recovered = await loginWithEmailOtpAndUnlockWallet({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.walletId, 'walletId'),
          orgId: msg.payload.runtimePolicyScope.orgId,
          userId: readString(msg.payload.userId, 'userId'),
          challengeId: readString(msg.payload.challengeId, 'challengeId'),
          otpCode: readString(msg.payload.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan,
          material: { kind: 'ed25519_yao_export' },
        });
        if (recovered.kind !== 'ed25519_yao_export') {
          throw new Error('Email OTP Ed25519 Yao export returned the wrong unlock material');
        }
        try {
          const artifact = await exportEmailOtpEd25519YaoSeed({
            relayUrl: msg.payload.relayUrl,
            walletId: msg.payload.walletId,
            providerSubjectId: msg.payload.userId,
            walletSessionJwt: msg.payload.walletSessionJwt,
            nearAccountId: msg.payload.nearAccountId,
            nearEd25519SigningKeyId: msg.payload.nearEd25519SigningKeyId,
            signerSlot: msg.payload.signerSlot,
            thresholdSessionId: msg.payload.thresholdSessionId,
            signingGrantId: msg.payload.signingGrantId,
            runtimePolicyScope: msg.payload.runtimePolicyScope,
            capability: parseEmailOtpEd25519YaoActiveCapability(msg.payload.capability),
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
