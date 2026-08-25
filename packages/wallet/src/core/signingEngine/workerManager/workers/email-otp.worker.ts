import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { base58Encode } from '@shared/utils/base58';
import { errorMessage } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parsePasskeyEnvelopeId,
  parseThresholdEd25519SessionId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
  parseWalletAuthMethodId,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  buildMethodBoundEnvelopeOwnership,
  buildPasskeyCustodyEnvelopeRecord,
  buildPasskeyEnvelopeFactor,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parsePasskeyCustodyEnvelopeRecord,
  isWalletCustodySeedBinding,
  type PasskeyCustodyEnvelopeRecord,
  type WalletCustodyEvmFamilyActivationCompletion,
  type WalletCustodyEvmFamilyPublicFacts,
  custodyEnvelopeBindingJsonV1,
} from '@shared/passkey-custody';
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
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
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
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  requireOpaqueWalletSessionToken,
  type WalletSessionRouteAuth,
} from '@shared/utils/sessionTokens';
import { parseEmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/challengeDelivery';
import type { EmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  decodeEmailOtpEscrowSecret32,
  type EmailOtpEscrowSecret32DecodeResult,
} from '@/core/signingEngine/session/emailOtp/secretEscrow';
import { buildEmailOtpWorkerIssuedSessionHandle } from '@/core/platform/secretSources';
import {
  parseWalletCustodyUnlockKeyManifest,
  type WalletCustodyUnlockKeyManifest,
  type WalletCustodyUnlockKeyManifestEntry,
} from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import {
  walletCustodyEd25519ActiveClientMetadataV1,
  walletRecoveryEd25519ActiveClientMetadataV1,
} from '@/core/signingEngine/walletCustody/ceremonyActiveClientMetadata';
import {
  activateWalletRecoveryEd25519V1,
  admitWalletRecoveryEd25519V1,
  buildWalletSessionEd25519RecoveryAdmissionRequestV1,
  executeWalletRecoveryEd25519RoundV1,
} from '@/core/signingEngine/walletCustody/walletRecoveryEd25519';
import {
  openWalletCustodyEd25519ActiveClientV1,
  walletCustodyActivationFactsFromActiveClientMetadataV1,
  walletCustodyCacheEnvelopeFromRecordV1,
  type WalletCustodyActivationFactsV1,
  type WalletCustodyCacheEnvelopeV1,
} from '@/core/signingEngine/walletCustody/openCustodyCache';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type LoadedWalletCustodyEd25519MaterialV1,
  type WalletCustodyEd25519MaterialBindingV1,
  type WalletCustodySealedEd25519MaterialV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import type {
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpEcdsaSessionHandleBinding,
  EmailOtpWalletRegistrationEcdsaPrepareHandleBinding,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayloads,
  EmailOtpWalletRegistrationEcdsaPrepareHandleRequest,
  EmailOtpWalletRegistrationEcdsaPrepareHandleResult,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerSessionHandleOperation,
  EmailOtpWorkerOperationRequestEnvelope,
  EmailOtpEd25519YaoActiveCapabilityDescriptorV1,
  EmailOtpEd25519YaoExportMaterialV1,
  EmailOtpEd25519YaoRecoveryAugmentationV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEcdsaWalletUnlockAuthorization,
  EmailOtpEcdsaCustodyContinuityV1,
  EmailOtpEcdsaCustodyRestoreV1,
  EmailOtpEcdsaCustodySignerV1,
  EmailOtpAuthoritySelector,
  EmailOtpWalletCustodyEd25519MaterialRequest,
  EmailOtpWalletUnlockMaterialRequest,
  EmailOtpWarmMaterialTarget,
  EmailOtpWorkerOperationMap,
} from '@/core/signingEngine/workerManager/workerTypes';
import { materialActivationKey } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../../session/keyMaterialBrands';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
  WasmRouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoExportArtifactV1,
  type RouterAbEd25519YaoExportEmailOtpFactorReleaseV1,
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
  type RouterAbEd25519YaoExportCustodyEnvelopeV1,
} from '../../threshold/ed25519/yaoClient';
import type { NearResolvedEd25519SigningSessionState } from '../../interfaces/near';
import {
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { type WalletRegistrationEd25519YaoBootstrapSession } from '@/core/rpcClients/relayer/walletRegistration';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  issueEd25519OperationStepUpAuthorization,
  type Ed25519OperationStepUpCredential,
  type Ed25519OperationStepUpProof,
  type IssuedEd25519OperationStepUpAuthorization,
} from '../../threshold/ed25519/walletSession';
import type {
  RouterAbEd25519NormalSigningIntentV2Wire,
  RouterAbEd25519SigningPayloadV2Wire,
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbNormalSigningScopeV2Wire,
  RouterAbNearDelegateActionIntentV1Wire,
  RouterAbNearTransactionIntentV1Wire,
  RouterAbNearNetworkIdV2Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
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
import { toEmailOtpAuthSubjectId } from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import initEvmCrypto, {
  init_evm_crypto,
  secp256k1_private_key_32_to_public_key_33,
  sign_secp256k1_recoverable,
} from '../../../../../../../wasm/evm_crypto/pkg/evm_crypto.js';
import initEmailOtpRuntime, {
  derive_email_otp_unlock_auth_seed_from_secret32,
  init_email_otp_runtime,
} from '../../../../../../../wasm/email_otp_runtime/pkg/email_otp_runtime.js';
import initWalletCustodyCeremony, {
  wallet_custody_ceremony_join_v1,
  type WasmCeremonyEvmActivationPendingV1,
  type WasmCeremonyManifestEstablishedV1,
  type WasmCeremonyProtocolCompletedV1,
  type WasmCeremonyProtocolPreparedV1,
  type WasmCeremonySeedHeldV1,
} from '../../../../../../../wasm/wallet_custody_ceremony/pkg/wallet_custody_ceremony.js';
import initNearSignerRecoveryWasm, {
  init_worker as init_near_signer_recovery_worker,
  passkey_custody_open_wallet_seed_v1,
  passkey_custody_reseal_wallet_seed_v1,
  type WasmPasskeyCustodyHandleV1,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import { normalizeRegistrationCredential } from '../../webauthnAuth/credentials/helpers';
import { WorkerControlMessage, type EmailOtpWorkerProgressCode } from '../workerTypes';
import { parseWalletRecoverySetRotationWorkerResultV1 } from '@shared/wallet-recovery/walletRecoveryRotation';
import { postEmailOtpJson } from './email-otp/fetch';
import { getShamir3PassRuntime } from './shamir3pass/runtime';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  emailOtpRoutePath,
  normalizeEmailOtpRoutePlan,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';

const EMAIL_OTP_UNLOCK_KEY_VERSION = 'email-otp-unlock-v1';
const EMAIL_OTP_ED25519_YAO_HANDLE_TTL_MS = 5 * 60_000;
const MAX_EMAIL_OTP_ED25519_YAO_PENDING_REGISTRATIONS = 64;
const MAX_EMAIL_OTP_ED25519_YAO_ACTIVE_CLIENTS = 64;
const EMAIL_OTP_ED25519_YAO_EXPORT_AUTH_TTL_MS = 60_000;
const EMAIL_OTP_PASSKEY_CUSTODY_LINK_TTL_MS = 2 * 60_000;
const MAX_EMAIL_OTP_PASSKEY_CUSTODY_LINKS = 8;
const ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT = 'default';

type EmailOtpWalletCustodyUnlockProjection = {
  readonly kind: 'wallet_custody_email_otp_unlock_v1';
  readonly walletId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly envelopeVersion: string;
  readonly envelopeRevision: number;
  readonly storeVersion: string;
  readonly activeKeySetIds: readonly string[];
  readonly keyManifest: WalletCustodyUnlockKeyManifest;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
};

function assertNeverEmailOtpWorker(value: never): never {
  throw new Error(`Unexpected Email OTP worker state: ${String(value)}`);
}

function emailOtpDeviceEnrollmentId(walletId: string, authSubjectId: string): string {
  return `email-otp-device-enrollment-v1:${walletId}:${authSubjectId}`;
}

function resolveEmailOtpAuthSubjectId(args: {
  walletId: string;
  userId?: unknown;
  routePlan: EmailOtpRoutePlan;
}): string {
  return readString(args.userId, 'userId');
}

type EmailOtpWorkerRequest = EmailOtpWorkerOperationRequestEnvelope;

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

type EmailOtpWarmSessionEntry = {
  signingSessionSecret32: Uint8Array;
  expiresAtMs: number;
  remainingUses: number;
};

type EmailOtpPasskeyCustodyLinkEntry = {
  readonly handle: WasmPasskeyCustodyHandleV1;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly expiresAtMs: number;
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
      emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

type ExactEmailOtpEcdsaWarmSessionRestore = {
  thresholdSessionId: string;
  walletId: string;
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
  authSubjectId: string;
};

type ExactEmailOtpEcdsaWarmSessionTransport = {
  relayerUrl: string;
  walletSessionToken: string;
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
  walletSessionToken: string;
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

type EmailOtpEd25519YaoActiveClientEntry = {
  kind: 'active_client';
  activeClient: RouterAbEd25519YaoActiveClientV1;
};

type EmailOtpEd25519YaoWorkerActivationHandle = {
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
};

const emailOtpWarmSessions = new Map<string, EmailOtpWarmSessionEntry>();
const emailOtpEd25519YaoWarmFactors = new Map<string, EmailOtpEd25519YaoWarmFactorEntry>();
const emailOtpEd25519YaoActiveClients = new Map<string, EmailOtpEd25519YaoActiveClientEntry>();
const emailOtpPasskeyCustodyLinks = new Map<string, EmailOtpPasskeyCustodyLinkEntry>();
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
): EmailOtpEd25519YaoWorkerActivationHandle {
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
  walletAuthMethodId: string;
  challengeId: string;
  otpCode: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
  resolveCustodyEnvelope: (
    release: RouterAbEd25519YaoExportEmailOtpFactorReleaseV1,
  ) => Promise<RouterAbEd25519YaoExportCustodyEnvelopeV1>;
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
      material_activation: routerAbMpcMaterialActivationRefToWire(capability.materialActivation),
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
      authorization: {
        kind: 'email_otp_factor',
        providerSubjectId: args.providerSubjectId,
        walletAuthMethodId: args.walletAuthMethodId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
      },
      resolveCustodyEnvelope: args.resolveCustodyEnvelope,
      transport: new RouterAbEd25519YaoHttpActivationTransportV1({
        routerOrigin: new URL(args.relayUrl).origin,
        authorization: { kind: 'cookies' },
        fetch: globalThis.fetch.bind(globalThis),
      }),
    });
    if (!result.ok) throw new Error(result.message);
    return result.artifact;
  } finally {
    nonce.fill(0);
  }
}

type EmailOtpEd25519ExportCustodyResolutionState = {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly providerSubjectId: string;
  readonly material: EmailOtpEd25519YaoExportMaterialV1;
  activeClientHandle: string | null;
  warmFactorBound: boolean;
  rehydrated: EmailOtpEd25519YaoWorkerActivationHandle | null;
};

function emailOtpEd25519YaoExportCapabilityV1(
  material: EmailOtpEd25519YaoExportMaterialV1,
): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  switch (material.kind) {
    case 'active_capability':
      return material.capability;
    case 'sealed_custody':
      return material.bootstrap.capability;
    case 'sealed_export_root':
      return material.capability;
    default:
      return assertNeverEmailOtpWorker(material);
  }
}

function emailOtpEd25519ExportRootEnvelopeWireV1(
  envelope: PasskeyCustodyEnvelopeRecord,
): Omit<RouterAbEd25519YaoExportCustodyEnvelopeV1, 'factorSecret'> {
  if (
    envelope.lifecycle.state !== 'active' ||
    envelope.binding.kind !== 'ed25519_yao_client_root_v1'
  ) {
    throw new Error('Email OTP Ed25519 export requires an active Client-root envelope');
  }
  return {
    kind: 'ed25519_yao_client_root_v1',
    bindingJson: custodyEnvelopeBindingJsonV1(envelope),
    nonce: base64UrlDecode(envelope.nonceB64u),
    ciphertext: base64UrlDecode(envelope.sealedCustodySecretB64u),
    aadHash: base64UrlDecode(envelope.aadHashB64u),
    ciphertextDigest: base64UrlDecode(envelope.ciphertextDigestB64u),
  };
}

async function resolveEmailOtpEd25519ExportCustodyEnvelope(
  state: EmailOtpEd25519ExportCustodyResolutionState,
  release: RouterAbEd25519YaoExportEmailOtpFactorReleaseV1,
): Promise<{
  readonly factorSecret: Uint8Array;
  readonly bindingJson: string;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly aadHash: Uint8Array;
  readonly ciphertextDigest: Uint8Array;
  readonly kind: 'wallet_custody_seed_v1' | 'ed25519_yao_client_root_v1';
}> {
  const released = await releaseEmailOtpFactorSecret({
    relayUrl: state.relayUrl,
    walletId: state.walletId,
    kind: 'verified_grant',
    loginGrant: release.loginGrant,
    challengeId: release.challengeId,
    sessionAuth: undefined,
  });
  let factorSecret32: Uint8Array | null = released.factorSecret32;
  try {
    if (state.material.kind === 'sealed_export_root') {
      const rootEnvelope = state.material.exportRootEnvelope;
      if (
        rootEnvelope.lifecycle.state !== 'active' ||
        rootEnvelope.walletId !== state.walletId ||
        rootEnvelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
        rootEnvelope.binding.targetFactor.kind !== 'email_otp' ||
        rootEnvelope.binding.registeredPublicKeyB64u !==
          base64UrlEncode(Uint8Array.from(state.material.capability.registeredPublicKey)) ||
        rootEnvelope.factor.kind !== 'email_otp' ||
        rootEnvelope.factor.enrollmentId !== released.enrollmentId ||
        rootEnvelope.factor.enrollmentSealKeyVersion !== released.enrollmentSealKeyVersion
      ) {
        throw new Error('Email OTP Ed25519 export root is bound to another factor or lane');
      }
      const envelope = emailOtpEd25519ExportRootEnvelopeWireV1(rootEnvelope);
      const ownedFactorSecret = factorSecret32;
      factorSecret32 = null;
      return {
        ...envelope,
        factorSecret: ownedFactorSecret,
      };
    }
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl: state.relayUrl,
      walletId: state.walletId,
      authoritySelector: { kind: 'wallet' },
      orgId: state.orgId,
      userId: state.providerSubjectId,
      enrollmentId: released.enrollmentId,
      enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
      clientSecret32: factorSecret32,
      material: { kind: 'ed25519_yao_export' },
      sessionAuth: undefined,
      ed25519WalletSessionToken: undefined,
    });
    if (unlocked.kind !== 'ed25519_yao_export') {
      throw new Error('Email OTP Ed25519 Yao export returned the wrong custody material');
    }
    if (state.material.kind === 'sealed_custody') {
      const bootstrap = state.material.bootstrap;
      const activeClient = await openWalletCustodyEd25519ActiveClientV1({
        material: state.material.walletCustodyEd25519Material,
        activation: walletCustodyActivationFactsFromEmailOtpBootstrap(bootstrap),
        envelope: walletCustodyCacheEnvelopeFromRecordV1(unlocked.walletCustodyEnvelope),
        ownedFactorSecret: factorSecret32.slice(),
      });
      try {
        const stored = storeEmailOtpEd25519YaoActiveClient(activeClient);
        state.activeClientHandle = stored.activeClientHandle;
        state.rehydrated = stored;
        bindEmailOtpEd25519YaoCapabilityWarmFactor({
          bootstrap,
          factorSecret32,
          materialActivation: state.material.materialActivation,
        });
        state.warmFactorBound = true;
      } catch (error) {
        activeClient.dispose();
        throw error;
      }
    }
    const envelope = walletCustodyCacheEnvelopeFromRecordV1(unlocked.walletCustodyEnvelope);
    const ownedFactorSecret = factorSecret32;
    factorSecret32 = null;
    return {
      kind: 'wallet_custody_seed_v1',
      factorSecret: ownedFactorSecret,
      bindingJson: envelope.bindingJson,
      nonce: base64UrlDecode(envelope.nonceB64u),
      ciphertext: base64UrlDecode(envelope.ciphertextB64u),
      aadHash: base64UrlDecode(envelope.aadHashB64u),
      ciphertextDigest: base64UrlDecode(envelope.ciphertextDigestB64u),
    };
  } finally {
    zeroizeBytes(factorSecret32);
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
        walletSessionToken: args.transport.walletSessionToken,
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

function readEmailOtpAuthoritySelector(value: unknown): EmailOtpAuthoritySelector {
  if (!value || typeof value !== 'object') {
    throw new Error('Email OTP authority selector is required');
  }
  const selector = value as { readonly kind?: unknown; readonly walletAuthMethodId?: unknown };
  if (selector.kind === 'wallet') return { kind: 'wallet' };
  if (selector.kind === 'wallet_auth_method') {
    return {
      kind: 'wallet_auth_method',
      walletAuthMethodId: readString(selector.walletAuthMethodId, 'walletAuthMethodId'),
    };
  }
  throw new Error('Email OTP authority selector kind is invalid');
}

function emailOtpAuthoritySelectorBody(selector: EmailOtpAuthoritySelector): {
  readonly walletAuthMethodId?: string;
} {
  return selector.kind === 'wallet_auth_method'
    ? { walletAuthMethodId: selector.walletAuthMethodId }
    : {};
}

function readRoutePlan(value: unknown, label: string): EmailOtpRoutePlan {
  const plan = normalizeEmailOtpRoutePlan(value);
  if (!plan) throw new Error(`${label} requires Email OTP routePlan`);
  return plan;
}

type EmailOtpEd25519SessionMaterialRequest = Extract<
  EmailOtpWalletUnlockMaterialRequest,
  {
    kind: 'ed25519_yao_recovery' | 'wallet_unlock_capabilities';
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
    (args.material.kind === 'ecdsa' && Boolean(args.material.ecdsaSessionPolicy)) ||
    args.material.kind === 'wallet_unlock_capabilities';
  /* One direction only: an Ed25519-only wallet unlocks without any ECDSA
     activation, so wallet_unlock does not imply ECDSA-bearing material. */
  if (carriesEcdsaActivation && args.routePlan.operation !== WALLET_EMAIL_OTP_UNLOCK_OPERATION) {
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
        args.material.ecdsa.sessionHandleBinding.authSubjectId !==
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
      /* Two legitimate carriers. A cold wallet unlock presents a fresh OTP as
         its proof and has no session to authenticate with — the same
         activation a combined wallet performs through
         `wallet_unlock_capabilities`. A signing-session rejoin has a session
         and must present its exact Ed25519 wallet session below. */
      if (
        args.routePlan.routeFamily === 'login' &&
        args.routePlan.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION
      ) {
        return;
      }
      if (args.routePlan.routeFamily !== 'signing_session') {
        throw new Error(
          'Email OTP Ed25519 session requires a wallet-unlock or signing-session route plan',
        );
      }
      const routeAuth = authLaneToRouteAuth(args.routePlan.authLane);
      const usesEd25519WalletSession =
        routeAuth?.kind === 'opaque_wallet_session' &&
        args.routePlan.authLane.kind === 'signing_session' &&
        args.routePlan.authLane.curve === 'ed25519';
      if (!usesEd25519WalletSession) {
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
  const walletSessionToken = normalizeOptionalNonEmptyString(transport.walletSessionToken);
  if (!walletSessionToken) return null;
  const keyVersion = normalizeOptionalNonEmptyString(transport.signingSessionSealKeyVersion);
  const groupId = normalizeOptionalNonEmptyString(transport.groupId);
  return {
    relayerUrl,
    walletSessionToken,
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
    const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
    headers.Authorization = `Bearer ${args.transport.walletSessionToken}`;
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'omit',
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
    zeroizeBytes(entry.signingSessionSecret32);
    emailOtpWarmSessions.delete(thresholdSessionId);
  }
}

function deleteEmailOtpEd25519YaoWarmFactor(materialActivation: MpcMaterialActivationRef): void {
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

function issueEmailOtpEcdsaSessionHandle(args: {
  walletId: string;
  binding: EmailOtpEcdsaSessionBootstrapHandleBinding;
}): EmailOtpEcdsaSessionBootstrapHandlePayload {
  const sessionId = secureRandomId(
    'email-otp-session',
    32,
    'Email OTP ECDSA authorization handles',
  );
  return {
    kind: 'email_otp_worker_session_handle_v1' as const,
    sessionId,
    walletId: readString(args.walletId, 'walletId'),
    authSubjectId: readString(args.binding.authSubjectId, 'authSubjectId'),
    keyHandle: readString(args.binding.keyHandle, 'keyHandle'),
    action: 'threshold_ecdsa_bootstrap',
    operation: args.binding.operation,
    chainTarget: args.binding.chainTarget,
  };
}

function bindEmailOtpEcdsaWarmSessionFactor(args: {
  session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1['session'];
  factorSecret32: Uint8Array;
}): void {
  const thresholdSessionId = readString(args.session.threshold_session_id, 'thresholdSessionId');
  if (args.factorSecret32.length !== 32) {
    throw new Error('Email OTP ECDSA warm factor must contain 32 bytes');
  }
  const remainingUses = normalizePositiveInteger(args.session.remaining_uses);
  const expiresAtMs = normalizePositiveInteger(args.session.expires_at_ms);
  if (!remainingUses || !expiresAtMs || expiresAtMs <= Date.now()) {
    throw new Error('Email OTP ECDSA warm factor requires an active session policy');
  }
  deleteEmailOtpWarmSession(thresholdSessionId);
  emailOtpWarmSessions.set(thresholdSessionId, {
    signingSessionSecret32: Uint8Array.from(args.factorSecret32),
    remainingUses,
    expiresAtMs,
  });
}

function emailOtpWalletRegistrationEcdsaHandleResult(
  request: EmailOtpWalletRegistrationEcdsaPrepareHandleRequest,
): EmailOtpWalletRegistrationEcdsaPrepareHandleResult {
  if (request.kind === 'requested') {
    throw new Error('Email OTP registration no longer derives an ECDSA root share');
  }
  return { kind: 'not_requested' };
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
        signingSessionSecret32: args.material.entry.signingSessionSecret32,
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
      const emailOtpSessionHandle = issueEmailOtpEcdsaSessionHandle({
        walletId: restore.walletId,
        binding: {
          action: 'threshold_ecdsa_bootstrap',
          operation: 'sign',
          keyHandle: restore.keyHandle,
          authSubjectId: restore.authSubjectId,
          chainTarget: restore.chainTarget,
        },
      });
      if (!signingSessionSecret32) {
        throw new Error('Email OTP signing-session seal returned no local material');
      }
      deleteEmailOtpWarmSession(thresholdSessionId);
      emailOtpWarmSessions.set(thresholdSessionId, {
        signingSessionSecret32,
        remainingUses: policy.remainingUses,
        expiresAtMs: policy.expiresAtMs,
      });
      signingSessionSecret32 = null;
      return {
        ok: true,
        emailOtpSessionHandle,
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
const walletCustodyCeremonyWasmUrl = resolveWasmUrl(
  'wallet_custody_ceremony_bg.wasm',
  'Email OTP Wallet Custody',
);
const nearSignerRecoveryWasmUrl = resolveWasmUrl(
  'wasm_signer_worker_bg.wasm',
  'Email OTP Recovery Wrap',
);
let evmCryptoInitPromise: Promise<void> | null = null;
let emailOtpRuntimeInitPromise: Promise<void> | null = null;
let nearSignerRecoveryInitPromise: Promise<void> | null = null;
let walletCustodyCeremonyInitPromise: Promise<void> | null = null;
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

async function ensureWalletCustodyCeremonyWasm(): Promise<void> {
  if (walletCustodyCeremonyInitPromise) return walletCustodyCeremonyInitPromise;
  walletCustodyCeremonyInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Email OTP Wallet Custody',
      wasmUrl: walletCustodyCeremonyWasmUrl,
      initFunction: initWalletCustodyCeremony as unknown as (wasmModule?: unknown) => Promise<void>,
    });
  })();
  return walletCustodyCeremonyInitPromise;
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

const EMAIL_OTP_FACTOR_RELEASE_AAD_PREFIX = 'seams/email-otp/factor-release/v1';

async function decryptEmailOtpFactorReleaseEnvelope(args: {
  walletId: string;
  challengeId: string;
  workerPrivateKey: CryptoKey;
  materialRecovery: Extract<
    IssuedEd25519OperationStepUpAuthorization['materialRecovery'],
    { kind: 'email_otp_factor_release_v1' }
  >;
}): Promise<{
  challengeId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  factorSecret32: Uint8Array;
}> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Email OTP factor release requires WebCrypto');
  const released = args.materialRecovery;
  if (released.challengeId !== args.challengeId) {
    throw new Error('Email OTP factor release challenge binding changed');
  }
  let serverPublicKey: Uint8Array | null = null;
  let nonce: Uint8Array | null = null;
  let ciphertext: Uint8Array | null = null;
  let sharedSecret: Uint8Array | null = null;
  let aad: Uint8Array | null = null;
  let factorSecret32: Uint8Array | null = null;
  try {
    serverPublicKey = base64UrlDecode(released.serverEphemeralPublicKey65B64u);
    if (serverPublicKey.length !== 65 || serverPublicKey[0] !== 4) {
      throw new Error('Email OTP factor release returned an invalid server public key');
    }
    nonce = base64UrlDecode(released.nonce12B64u);
    if (nonce.length !== 12) throw new Error('Email OTP factor release returned an invalid nonce');
    ciphertext = base64UrlDecode(released.ciphertextB64u);
    if (ciphertext.length < 16) {
      throw new Error('Email OTP factor release returned an invalid ciphertext');
    }
    const serverKey = await subtle.importKey(
      'raw',
      serverPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    sharedSecret = new Uint8Array(
      await subtle.deriveBits({ name: 'ECDH', public: serverKey }, args.workerPrivateKey, 256),
    );
    const aesKey = await subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, [
      'decrypt',
    ]);
    aad = new TextEncoder().encode(
      `${EMAIL_OTP_FACTOR_RELEASE_AAD_PREFIX}\0${args.walletId}\0${released.enrollmentId}\0${released.enrollmentSealKeyVersion}\0${released.challengeId}`,
    );
    factorSecret32 = new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext,
      ),
    );
    if (factorSecret32.length !== 32) {
      throw new Error('Email OTP factor release plaintext must contain exactly 32 bytes');
    }
    const ownedFactorSecret32 = factorSecret32;
    factorSecret32 = null;
    return {
      challengeId: released.challengeId,
      enrollmentId: released.enrollmentId,
      enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
      factorSecret32: ownedFactorSecret32,
    };
  } finally {
    zeroizeBytes(serverPublicKey);
    zeroizeBytes(nonce);
    zeroizeBytes(ciphertext);
    zeroizeBytes(sharedSecret);
    zeroizeBytes(aad);
    zeroizeBytes(factorSecret32);
  }
}

async function releaseEmailOtpFactorSecret(
  args: {
    relayUrl: string;
    walletId: string;
  } & (
    | {
        kind: 'verified_grant';
        challengeId: string;
        loginGrant: string;
        sessionAuth: WalletSessionRouteAuth | undefined;
        otpCode?: never;
        operation?: never;
      }
    | {
        kind: 'email_otp';
        authoritySelector: EmailOtpAuthoritySelector;
        challengeId: string;
        otpCode: string;
        operation: WalletEmailOtpOperation;
        sessionAuth: WalletSessionRouteAuth | undefined;
        loginGrant?: never;
      }
    | {
        kind: 'wallet_session';
        sessionAuth: WalletSessionRouteAuth;
        challengeId?: never;
        loginGrant?: never;
        otpCode?: never;
        operation?: never;
      }
  ),
): Promise<{
  challengeId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  factorSecret32: Uint8Array;
}> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Email OTP factor release requires WebCrypto');
  const generated = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);
  if (!('privateKey' in generated) || !('publicKey' in generated)) {
    throw new Error('Email OTP factor release generated an invalid ECDH key pair');
  }
  const workerPublicKey = new Uint8Array(await subtle.exportKey('raw', generated.publicKey));
  if (workerPublicKey.length !== 65) {
    throw new Error('Email OTP factor release generated an invalid public key');
  }
  let serverPublicKey: Uint8Array | null = null;
  let nonce: Uint8Array | null = null;
  let ciphertext: Uint8Array | null = null;
  let sharedSecret: Uint8Array | null = null;
  let aad: Uint8Array | null = null;
  let factorSecret32: Uint8Array | null = null;
  try {
    const released = await postEmailOtpJson({
      relayUrl: args.relayUrl,
      route: '/wallet/email-otp/factor-release',
      ...(args.sessionAuth ? { sessionAuth: args.sessionAuth } : {}),
      body: {
        walletId: args.walletId,
        ...(args.kind === 'verified_grant'
          ? { kind: 'verified_grant', loginGrant: args.loginGrant }
          : args.kind === 'email_otp'
            ? {
                kind: 'email_otp',
                ...emailOtpAuthoritySelectorBody(args.authoritySelector),
                challengeId: args.challengeId,
                otpCode: args.otpCode,
                operation: args.operation,
              }
            : { kind: 'wallet_session' }),
        workerEphemeralPublicKey65B64u: base64UrlEncode(workerPublicKey),
      },
    });
    if (readString(released.kind, 'factor-release.kind') !== 'email_otp_factor_release_v1') {
      throw new Error('Email OTP factor release returned an invalid response kind');
    }
    const releasedChallengeId = readString(released.challengeId, 'factor-release.challengeId');
    if (args.kind !== 'wallet_session' && releasedChallengeId !== args.challengeId) {
      throw new Error('Email OTP factor release challenge binding changed');
    }
    const enrollmentId = readString(released.enrollmentId, 'factor-release.enrollmentId');
    const enrollmentSealKeyVersion = readString(
      released.enrollmentSealKeyVersion,
      'factor-release.enrollmentSealKeyVersion',
    );
    serverPublicKey = base64UrlDecode(
      readString(
        released.serverEphemeralPublicKey65B64u,
        'factor-release.serverEphemeralPublicKey65B64u',
      ),
    );
    if (serverPublicKey.length !== 65) {
      throw new Error('Email OTP factor release returned an invalid server public key');
    }
    nonce = base64UrlDecode(readString(released.nonce12B64u, 'factor-release.nonce12B64u'));
    if (nonce.length !== 12) {
      throw new Error('Email OTP factor release returned an invalid nonce');
    }
    ciphertext = base64UrlDecode(
      readString(released.ciphertextB64u, 'factor-release.ciphertextB64u'),
    );
    if (ciphertext.length < 16) {
      throw new Error('Email OTP factor release returned an invalid ciphertext');
    }
    const serverKey = await subtle.importKey(
      'raw',
      serverPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    sharedSecret = new Uint8Array(
      await subtle.deriveBits({ name: 'ECDH', public: serverKey }, generated.privateKey, 256),
    );
    const aesKey = await subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, [
      'decrypt',
    ]);
    aad = new TextEncoder().encode(
      `${EMAIL_OTP_FACTOR_RELEASE_AAD_PREFIX}\0${args.walletId}\0${enrollmentId}\0${enrollmentSealKeyVersion}\0${releasedChallengeId}`,
    );
    factorSecret32 = new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext,
      ),
    );
    if (factorSecret32.length !== 32) {
      throw new Error('Email OTP factor release plaintext must contain exactly 32 bytes');
    }
    const ownedFactorSecret32 = factorSecret32;
    factorSecret32 = null;
    return {
      challengeId: releasedChallengeId,
      enrollmentId,
      enrollmentSealKeyVersion,
      factorSecret32: ownedFactorSecret32,
    };
  } finally {
    zeroizeBytes(workerPublicKey);
    zeroizeBytes(serverPublicKey);
    zeroizeBytes(nonce);
    zeroizeBytes(ciphertext);
    zeroizeBytes(sharedSecret);
    zeroizeBytes(aad);
    zeroizeBytes(factorSecret32);
  }
}

async function unlockEmailOtpAuthorityWallet(
  args: EmailOtpWorkerOperationMap['unlockEmailOtpAuthorityWallet']['payload'],
): Promise<EmailOtpWorkerOperationMap['unlockEmailOtpAuthorityWallet']['result']> {
  await ensureEvmCryptoWasm();
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const walletAuthMethodId = readString(args.walletAuthMethodId, 'walletAuthMethodId');
  const challengeId = readString(args.challengeId, 'challengeId');
  const otpCode = readString(args.otpCode, 'otpCode');
  const released = await releaseEmailOtpFactorSecret({
    relayUrl,
    walletId,
    authoritySelector: { kind: 'wallet_auth_method', walletAuthMethodId },
    challengeId,
    otpCode,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    kind: 'email_otp',
    sessionAuth: undefined,
  });
  let factorSecret32: Uint8Array | null = released.factorSecret32;
  let challengeDigest32: Uint8Array | null = null;
  let unlockPrivateKey32: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  let unlockSignature65: Uint8Array | null = null;
  try {
    const unlockChallenge = await postEmailOtpJson({
      relayUrl,
      route: '/wallet/unlock/challenge',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        walletAuthMethodId,
      },
    });
    const unlockChallengeId = readString(unlockChallenge.challengeId, 'challengeId');
    const unlockChallengeB64u = readString(unlockChallenge.challengeB64u, 'challengeB64u');
    challengeDigest32 = base64UrlDecode(unlockChallengeB64u);
    if (challengeDigest32.length !== 32) {
      throw new Error('wallet/unlock/challenge challengeB64u must decode to 32 bytes');
    }
    if (!factorSecret32) {
      throw new Error('Email OTP factor release did not return a factor secret');
    }
    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedInWorker({
      clientSecret32: factorSecret32,
      walletId,
    });
    unlockPublicKey33 = secp256k1_private_key_32_to_public_key_33(unlockPrivateKey32) as Uint8Array;
    unlockSignature65 = sign_secp256k1_recoverable(
      challengeDigest32,
      unlockPrivateKey32,
    ) as Uint8Array;
    const verified = await postEmailOtpJson({
      relayUrl,
      route: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        walletAuthMethodId,
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: base64UrlEncode(unlockPublicKey33),
          signature: base64UrlEncode(unlockSignature65),
        },
        requestedCapabilities:
          args.ed25519.kind === 'no_ed25519'
            ? { kind: 'wallet_session' }
            : {
                kind: 'ed25519_yao',
                signerSlot: args.ed25519.signerSlot,
                remainingUses: args.ed25519.remainingUses,
              },
      },
    });
    const walletSession = parseActiveWalletSessionV1(verified.walletSession);
    const operationCredential = parseWalletSessionOperationCredentialV1(
      verified.operationCredential,
    );
    if (
      String(walletSession.walletId) !== walletId ||
      String(walletSession.authMethodId) !== walletAuthMethodId
    ) {
      throw new Error('Email OTP authority Wallet Session identity changed');
    }
    let ed25519Activation: EmailOtpWorkerOperationMap['unlockEmailOtpAuthorityWallet']['result']['ed25519Activation'] =
      { kind: 'ed25519_activation_absent' };
    if (args.ed25519.kind !== 'no_ed25519') {
      const bootstrap = parseEmailOtpEd25519YaoRecoveryBootstrap(verified.ed25519YaoCapability);
      if (args.ed25519.kind === 'linked_device') {
        /* A linked device opens its own sealed material after this call, so the
           bootstrap is all it needs from here. */
        ed25519Activation = { kind: 'ed25519_bootstrap_only', bootstrap };
      } else {
        /* An owner authority has no sealed material of its own. The verify
           response above already carried the custody projection, so the runtime
           is built here from the seed this unlock already holds rather than by
           verifying the factor a second time somewhere else. */
        const walletCustody = parseEmailOtpWalletCustodyUnlockProjection({
          raw: verified.walletCustody,
          walletId,
          enrollmentId: released.enrollmentId,
          enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
        });
        if (!factorSecret32) {
          throw new Error('Email OTP authority unlock lost its factor secret');
        }
        const restored = await restoreEmailOtpEd25519FromCustodyCache({
          relayUrl,
          walletId,
          projection: walletCustody,
          material: {
            kind: 'ed25519_yao_recovery',
            ed25519YaoRecovery: args.ed25519.recovery.ed25519YaoRecovery,
            providerSubject: args.ed25519.recovery.providerSubject,
            nearAccountId: args.ed25519.recovery.nearAccountId,
            expectedOperationalPublicKey: args.ed25519.recovery.expectedOperationalPublicKey,
            expectedThresholdSessionId: args.ed25519.recovery.expectedThresholdSessionId,
            walletCustodyEd25519Material: args.ed25519.recovery.walletCustodyEd25519Material,
          },
          bootstrap,
          clientSecret32: factorSecret32,
        });
        if (restored.kind !== 'opened') {
          throw new Error(`Email OTP authority Ed25519 runtime is ${restored.kind}`);
        }
        ed25519Activation = {
          kind: 'ed25519_activation_ready',
          activeClientHandle: restored.activeClientHandle,
          metadata: restored.metadata,
          bootstrap,
        };
      }
    }
    const ownedFactorSecret32 = factorSecret32;
    factorSecret32 = null;
    return {
      kind: 'email_otp_authority_wallet_unlock_v1',
      factorSecret32: ownedFactorSecret32,
      walletSession,
      operationCredential,
      ed25519Activation,
    };
  } finally {
    zeroizeBytes(factorSecret32);
    zeroizeBytes(challengeDigest32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(unlockPublicKey33);
    zeroizeBytes(unlockSignature65);
  }
}

function assertEmailOtpEd25519OperationMaterialContinuity(args: {
  walletId: string;
  nearAccountId: string;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: ThresholdEd25519SessionId;
  expectedMaterialActivation: MpcMaterialActivationRef;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
}): void {
  const metadataActivation = args.metadata.materialActivation;
  const capability = args.bootstrap.capability;
  if (
    !mpcMaterialActivationRefsEqual(metadataActivation, args.expectedMaterialActivation) ||
    !mpcMaterialActivationRefsEqual(
      capability.materialActivation,
      args.expectedMaterialActivation,
    ) ||
    capability.nearAccountId !== args.nearAccountId ||
    capability.applicationBinding.wallet_id !== args.walletId ||
    capability.applicationBinding.key_creation_signer_slot !== args.signerSlot ||
    capability.lifecycle.thresholdSessionId !== args.expectedThresholdSessionId ||
    `ed25519:${base58Encode(args.metadata.registeredPublicKey)}` !==
      args.expectedOperationalPublicKey
  ) {
    throw new Error('Email OTP operation recovery activated different signing material');
  }
}

async function rehydrateEmailOtpEd25519YaoOperationMaterial(
  args: EmailOtpWorkerOperationMap['rehydrateEmailOtpEd25519YaoOperationMaterial']['payload'],
): Promise<EmailOtpWorkerOperationMap['rehydrateEmailOtpEd25519YaoOperationMaterial']['result']> {
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const providerSubjectId = readString(args.providerSubjectId, 'providerSubjectId');
  const nearAccountId = readString(args.nearAccountId, 'nearAccountId');
  const signerSlot = normalizePositiveInteger(args.signerSlot);
  if (signerSlot === null) throw new Error('signerSlot must be a positive safe integer');
  const expectedThresholdSessionId = readThresholdEd25519SessionId(
    args.expectedThresholdSessionId,
    'expectedThresholdSessionId',
  );
  const expectedOperationalPublicKey = readString(
    args.expectedOperationalPublicKey,
    'expectedOperationalPublicKey',
  );
  const expectedMaterialActivation = args.expectedMaterialActivation;
  if (String(expectedMaterialActivation.materialOwner) !== walletId) {
    throw new Error('Email OTP operation material activation belongs to another wallet');
  }
  if (args.ed25519YaoRecovery.orgId !== String(args.orgId).trim()) {
    throw new Error('Email OTP operation material organization binding changed');
  }
  if (args.ed25519YaoRecovery.signerSlot !== signerSlot) {
    throw new Error('Email OTP operation material signer slot binding changed');
  }
  if (args.proof.providerSubjectId !== providerSubjectId) {
    throw new Error('Email OTP operation material provider binding changed');
  }
  if (String(args.proof.authorityRef.walletId) !== walletId) {
    throw new Error('Email OTP operation material authority wallet binding changed');
  }
  const credential = args.credential;
  if (credential.kind !== 'wallet_session_opaque') {
    throw new Error('Email OTP operation material requires an opaque Wallet Session credential');
  }
  const material: Extract<EmailOtpWalletUnlockMaterialRequest, { kind: 'ed25519_yao_recovery' }> = {
    kind: 'ed25519_yao_recovery',
    ed25519YaoRecovery: args.ed25519YaoRecovery,
    providerSubject: providerSubjectId,
    nearAccountId,
    expectedOperationalPublicKey,
    expectedThresholdSessionId: String(expectedThresholdSessionId),
    walletCustodyEd25519Material: args.walletCustodyEd25519Material,
  };
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Email OTP operation material requires WebCrypto');
  const generated = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);
  if (!('privateKey' in generated) || !('publicKey' in generated)) {
    throw new Error('Email OTP operation material generated an invalid ECDH key pair');
  }
  const workerPublicKey = new Uint8Array(await subtle.exportKey('raw', generated.publicKey));
  let factorSecret32: Uint8Array | null = null;
  let activeClientHandle: string | null = null;
  try {
    if (workerPublicKey.length !== 65 || workerPublicKey[0] !== 4) {
      throw new Error('Email OTP operation material generated an invalid public key');
    }
    const issuedAuthorization = await issueEd25519OperationStepUpAuthorization({
      relayerUrl: relayUrl,
      normalSigningRequest: args.normalSigningRequest,
      displayDigest: readString(args.displayDigest, 'displayDigest'),
      proof: args.proof,
      credential,
      materialRecovery: {
        kind: 'email_otp_factor_release_v1',
        workerEphemeralPublicKey65B64u: base64UrlEncode(workerPublicKey),
      },
    });
    if (issuedAuthorization.materialRecovery.kind !== 'email_otp_factor_release_v1') {
      throw new Error('Email OTP operation step-up did not return factor-release material');
    }
    const released = await decryptEmailOtpFactorReleaseEnvelope({
      walletId,
      challengeId: args.proof.challengeId,
      workerPrivateKey: generated.privateKey,
      materialRecovery: issuedAuthorization.materialRecovery,
    });
    factorSecret32 = released.factorSecret32;
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      authoritySelector: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: String(args.proof.authorityRef.walletAuthMethodId),
      },
      orgId: args.orgId,
      userId: providerSubjectId,
      enrollmentId: released.enrollmentId,
      enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
      clientSecret32: factorSecret32,
      material,
      sessionAuth: {
        kind: 'opaque_wallet_session',
        walletSessionToken: requireOpaqueWalletSessionToken(credential.walletSessionToken),
      },
      ed25519WalletSessionToken: requireOpaqueWalletSessionToken(credential.walletSessionToken),
    });
    if (unlocked.kind !== 'ed25519_yao_capability') {
      throw new Error('Email OTP operation material did not activate an Ed25519 capability');
    }
    activeClientHandle = unlocked.activeClientHandle;
    assertEmailOtpEd25519OperationMaterialContinuity({
      walletId,
      nearAccountId,
      signerSlot,
      expectedOperationalPublicKey,
      expectedThresholdSessionId,
      expectedMaterialActivation,
      metadata: unlocked.metadata,
      bootstrap: unlocked.ed25519YaoCapability,
    });
    const ownedActiveClientHandle = activeClientHandle;
    activeClientHandle = null;
    return {
      activeClientHandle: ownedActiveClientHandle,
      metadata: unlocked.metadata,
      bootstrap: unlocked.ed25519YaoCapability,
      ...(unlocked.walletCustodyEd25519Material
        ? { walletCustodyEd25519Material: unlocked.walletCustodyEd25519Material }
        : {}),
      issuedAuthorization,
    };
  } catch (error) {
    if (activeClientHandle) removeEmailOtpEd25519YaoActiveClient(activeClientHandle);
    throw error;
  } finally {
    zeroizeBytes(workerPublicKey);
    zeroizeBytes(factorSecret32);
  }
}

async function rehydrateActiveEmailOtpEd25519YaoSessionMaterial(
  args: EmailOtpWorkerOperationMap['rehydrateActiveEmailOtpEd25519YaoSessionMaterial']['payload'],
): Promise<
  EmailOtpWorkerOperationMap['rehydrateActiveEmailOtpEd25519YaoSessionMaterial']['result']
> {
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const providerSubjectId = readString(args.providerSubjectId, 'providerSubjectId');
  const walletSessionToken = requireOpaqueWalletSessionToken(args.walletSessionToken);
  const sessionAuth: WalletSessionRouteAuth = {
    kind: 'opaque_wallet_session',
    walletSessionToken,
  };
  const released = await releaseEmailOtpFactorSecret({
    relayUrl,
    walletId,
    kind: 'wallet_session',
    sessionAuth,
  });
  let factorSecret32: Uint8Array | null = released.factorSecret32;
  try {
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      authoritySelector: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: readString(args.walletAuthMethodId, 'walletAuthMethodId'),
      },
      orgId: readString(args.orgId, 'orgId'),
      userId: providerSubjectId,
      enrollmentId: released.enrollmentId,
      enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
      clientSecret32: factorSecret32,
      material: {
        kind: 'wallet_unlock_capabilities',
        ecdsa: args.ecdsa,
        ed25519Yao: {
          providerSubject: providerSubjectId,
          nearAccountId: args.nearAccountId,
          expectedOperationalPublicKey: args.expectedOperationalPublicKey,
          expectedThresholdSessionId: args.expectedThresholdSessionId,
          walletCustodyEd25519Material: args.walletCustodyEd25519Material,
          recovery: {
            kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
            signerSlot: args.signerSlot,
            remainingUses: args.remainingUses,
            orgId: args.orgId,
          },
        },
      },
      sessionAuth,
      ed25519WalletSessionToken: walletSessionToken,
    });
    factorSecret32 = null;
    if (
      unlocked.kind !== 'wallet_unlock_capabilities' ||
      unlocked.ed25519Yao.kind !== 'capability'
    ) {
      throw new Error('Active Email OTP Wallet Session did not restore wallet capabilities');
    }
    return {
      activeClientHandle: unlocked.ed25519Yao.activeClientHandle,
      metadata: unlocked.ed25519Yao.metadata,
      bootstrap: unlocked.ed25519Yao.bootstrap,
      ecdsaSession: unlocked.ecdsa.session,
    };
  } finally {
    zeroizeBytes(factorSecret32);
  }
}

type EmailOtpUnlockCompletionMaterial =
  | {
      kind: 'ecdsa';
      ecdsaSession?: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
      ecdsaCustody?: EmailOtpEcdsaCustodyRestoreV1;
    }
  | {
      kind: 'ed25519_yao_export';
      walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
    }
  | {
      kind: 'wallet_custody_cache_absent';
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'ed25519_yao_capability';
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      ed25519YaoCapability: EmailOtpEd25519YaoRecoveryBootstrapV1;
      walletCustodyEd25519Material?: LoadedWalletCustodyEd25519MaterialV1;
      walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
    }
  | {
      kind: 'wallet_unlock_capabilities';
      walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
      ecdsa: {
        session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        custody: EmailOtpEcdsaCustodyRestoreV1;
      };
      ed25519Yao:
        | {
            kind: 'wallet_custody_cache_absent';
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
        kind: 'ed25519_yao_recovery' | 'wallet_unlock_capabilities';
      }
    >;

function requireEmailOtpWorkerEcdsaSessionResponse(
  value: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | undefined,
): RouterAbEcdsaPostRegistrationSessionActivationResponseV1 {
  if (!value) throw new Error('Email OTP unlock did not return its first ECDSA Wallet Session');
  return value;
}

function requireEmailOtpWorkerEcdsaCustodyRestore(
  value: EmailOtpEcdsaCustodyRestoreV1 | undefined,
): EmailOtpEcdsaCustodyRestoreV1 {
  if (!value) throw new Error('Email OTP unlock did not restore ECDSA custody');
  return value;
}

type EmailOtpRequestedCapabilities =
  | {
      kind: 'none';
    }
  | {
      kind: 'wallet_session';
    }
  | {
      kind: 'ed25519_yao';
      signerSlot: number;
      remainingUses: number;
    };

function buildEmailOtpRequestedCapabilities(args: {
  material: EmailOtpUnlockSecretMaterialRequest;
}): EmailOtpRequestedCapabilities {
  switch (args.material.kind) {
    case 'ecdsa':
      return args.material.ecdsaSessionPolicy
        ? { kind: 'wallet_session' }
        : { kind: 'none' };
    case 'ed25519_yao_export':
      return { kind: 'none' };
    case 'ed25519_yao_recovery': {
      const request = emailOtpEd25519SessionRequest(args.material);
      return {
        kind: 'ed25519_yao',
        signerSlot: request.signerSlot,
        remainingUses: request.remainingUses,
      };
    }
    case 'wallet_unlock_capabilities': {
      const request = emailOtpEd25519SessionRequest(args.material);
      return {
        kind: 'ed25519_yao',
        signerSlot: request.signerSlot,
        remainingUses: request.remainingUses,
      };
    }
    default:
      return assertNeverEmailOtpWorker(args.material);
  }
}

function emailOtpEd25519WalletSessionTokenForUnlockMaterial(
  material: EmailOtpUnlockSecretMaterialRequest,
): string | undefined {
  if (material.kind !== 'ecdsa' || material.ecdsaSessionPolicy === undefined) {
    return undefined;
  }
  const authorization = material.walletSessionAuthorization;
  if (authorization.kind === 'reuse_ed25519_wallet_session') {
    return authorization.walletSessionToken;
  }
  return undefined;
}

function parseEmailOtpWalletCustodyUnlockProjection(args: {
  raw: unknown;
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
}): EmailOtpWalletCustodyUnlockProjection {
  const projection = workerPayloadObject(args.raw);
  if (!projection || projection.kind !== 'wallet_custody_email_otp_unlock_v1') {
    throw new Error('Email OTP unlock omitted its wallet custody projection');
  }
  const walletId = readString(projection.walletId, 'walletCustody.walletId');
  const enrollmentId = readString(projection.enrollmentId, 'walletCustody.enrollmentId');
  const enrollmentSealKeyVersion = readString(
    projection.enrollmentSealKeyVersion,
    'walletCustody.enrollmentSealKeyVersion',
  );
  if (
    walletId !== args.walletId ||
    enrollmentId !== args.enrollmentId ||
    enrollmentSealKeyVersion !== args.enrollmentSealKeyVersion
  ) {
    throw new Error('Email OTP wallet custody projection changed its enrollment binding');
  }
  const envelope = parsePasskeyCustodyEnvelopeRecord(projection.envelope);
  if (
    envelope.walletId !== walletId ||
    envelope.lifecycle.state !== 'active' ||
    !isWalletCustodySeedBinding(envelope.binding) ||
    envelope.factor.kind !== 'email_otp' ||
    envelope.factor.enrollmentId !== enrollmentId ||
    envelope.factor.enrollmentSealKeyVersion !== enrollmentSealKeyVersion
  ) {
    throw new Error('Email OTP wallet custody envelope binding is invalid');
  }
  const envelopeVersion = readString(projection.envelopeVersion, 'walletCustody.envelopeVersion');
  if (String(envelope.envelopeVersion) !== envelopeVersion) {
    throw new Error('Email OTP wallet custody envelope version changed');
  }
  const envelopeRevision = Number(projection.envelopeRevision);
  if (!Number.isSafeInteger(envelopeRevision) || envelopeRevision < 1) {
    throw new Error('Email OTP wallet custody envelope revision is invalid');
  }
  if (envelopeRevision !== Number(envelope.envelopeRevision)) {
    throw new Error('Email OTP wallet custody envelope revision changed');
  }
  const storeVersion = readString(projection.storeVersion, 'walletCustody.storeVersion');
  const keyManifest = parseWalletCustodyUnlockKeyManifest(projection.keyManifest, walletId);
  if (!Array.isArray(projection.activeKeySetIds) || projection.activeKeySetIds.length === 0) {
    throw new Error('Email OTP wallet custody projection omitted active key sets');
  }
  const activeKeySetIds = projection.activeKeySetIds.map((value, index) =>
    readString(value, `walletCustody.activeKeySetIds[${index}]`),
  );
  if (
    new Set(activeKeySetIds).size !== activeKeySetIds.length ||
    activeKeySetIds.length !== keyManifest.entries.length ||
    activeKeySetIds.some(
      (keySetId) => !keyManifest.entries.some((entry) => entry.keySetId === keySetId),
    )
  ) {
    throw new Error('Email OTP wallet custody projection key sets are inconsistent');
  }
  return {
    kind: 'wallet_custody_email_otp_unlock_v1',
    walletId,
    enrollmentId,
    enrollmentSealKeyVersion,
    envelopeVersion,
    envelopeRevision,
    storeVersion,
    activeKeySetIds,
    keyManifest,
    envelope,
  };
}

function emailOtpEcdsaKeyManifestEntry(args: {
  material: EmailOtpUnlockSecretMaterialRequest;
  keyManifest: WalletCustodyUnlockKeyManifest;
}): Extract<WalletCustodyUnlockKeyManifestEntry, { kind: 'evm_family_ecdsa' }> {
  const keyHandle =
    args.material.kind === 'wallet_unlock_capabilities'
      ? args.material.ecdsa.sessionHandleBinding.keyHandle
      : args.material.kind === 'ecdsa'
        ? args.material.ecdsaSessionHandleBinding.keyHandle
        : '';
  const entry = args.keyManifest.entries.find(
    (
      candidate,
    ): candidate is Extract<WalletCustodyUnlockKeyManifestEntry, { kind: 'evm_family_ecdsa' }> =>
      candidate.kind === 'evm_family_ecdsa' && candidate.keyHandle === keyHandle,
  );
  if (!entry) {
    throw new Error('Email OTP wallet custody projection omitted the requested ECDSA key set');
  }
  return entry;
}

function parseEmailOtpEcdsaCustodyContinuity(raw: unknown): EmailOtpEcdsaCustodyContinuityV1 {
  const continuity = workerPayloadObject(raw);
  if (!continuity || continuity.kind !== 'wallet_custody_ecdsa_sync_continuity_v1') {
    throw new Error('Email OTP unlock returned invalid ECDSA custody continuity');
  }
  if (!Array.isArray(continuity.signers) || continuity.signers.length === 0) {
    throw new Error('Email OTP unlock returned no ECDSA custody signers');
  }
  const signers: EmailOtpEcdsaCustodySignerV1[] = continuity.signers.map((rawSigner, index) => {
    const signer = workerPayloadObject(rawSigner);
    const walletKey = signer && workerPayloadObject(signer.walletKey);
    if (!signer || !walletKey) {
      throw new Error(`Email OTP ECDSA custody signer ${index} is invalid`);
    }
    const participantIds = walletKey.participantIds;
    if (
      !Array.isArray(participantIds) ||
      participantIds.length !== 2 ||
      participantIds[0] !== 1 ||
      participantIds[1] !== 2
    ) {
      throw new Error('Email OTP ECDSA custody participants are invalid');
    }
    return {
      chainTarget: parseWorkerChainTarget(signer.chainTarget),
      walletKey: {
        walletId: readString(walletKey.walletId, 'ecdsaCustody.walletKey.walletId'),
        keyHandle: readString(walletKey.keyHandle, 'ecdsaCustody.walletKey.keyHandle'),
        ecdsaThresholdKeyId: readString(
          walletKey.ecdsaThresholdKeyId,
          'ecdsaCustody.walletKey.ecdsaThresholdKeyId',
        ),
        signingRootId: readString(walletKey.signingRootId, 'ecdsaCustody.walletKey.signingRootId'),
        signingRootVersion: readString(
          walletKey.signingRootVersion,
          'ecdsaCustody.walletKey.signingRootVersion',
        ),
        relayerKeyId: readString(walletKey.relayerKeyId, 'ecdsaCustody.walletKey.relayerKeyId'),
        contextBinding32B64u: readString(
          walletKey.contextBinding32B64u,
          'ecdsaCustody.walletKey.contextBinding32B64u',
        ),
        derivationClientSharePublicKey33B64u: readString(
          walletKey.derivationClientSharePublicKey33B64u,
          'ecdsaCustody.walletKey.derivationClientSharePublicKey33B64u',
        ),
        participantIds: [1, 2],
        publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(
          walletKey.publicCapability,
        ),
      },
      activationReceipt: parseRouterAbEcdsaRegistrationActivationReceiptV1(
        signer.activationReceipt,
      ),
      runtimePolicyScope: parseWorkerRuntimePolicyScope(
        signer.runtimePolicyScope,
        'ecdsaCustody.runtimePolicyScope',
      ),
    };
  });
  return { kind: 'wallet_custody_ecdsa_sync_continuity_v1', signers };
}

function ethereumAddressFromEcdsaIdentityB64u(value: string): string {
  const address = base64UrlDecode(value);
  if (address.length !== 20) {
    throw new Error('Email OTP ECDSA activation returned an invalid Ethereum address');
  }
  return `0x${Array.from(address, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function parseEmailOtpEcdsaPublicFacts(value: unknown): WalletCustodyEvmFamilyPublicFacts {
  const facts = workerPayloadObject(value);
  if (!facts) throw new Error('Email OTP ECDSA custody returned no public facts');
  const clientShareRetryCounter = Number(facts.clientShareRetryCounter);
  const relayerShareRetryCounter = Number(facts.relayerShareRetryCounter);
  if (
    !Number.isSafeInteger(clientShareRetryCounter) ||
    clientShareRetryCounter < 0 ||
    !Number.isSafeInteger(relayerShareRetryCounter) ||
    relayerShareRetryCounter < 0
  ) {
    throw new Error('Email OTP ECDSA custody public facts retry counters are invalid');
  }
  return {
    contextBinding32B64u: readString(
      facts.contextBinding32B64u,
      'ecdsaPublicFacts.contextBinding32B64u',
    ),
    derivationClientSharePublicKey33B64u: readString(
      facts.derivationClientSharePublicKey33B64u,
      'ecdsaPublicFacts.derivationClientSharePublicKey33B64u',
    ),
    clientVerifyingShare33B64u: readString(
      facts.clientVerifyingShare33B64u,
      'ecdsaPublicFacts.clientVerifyingShare33B64u',
    ),
    relayerPublicKey33B64u: readString(
      facts.relayerPublicKey33B64u,
      'ecdsaPublicFacts.relayerPublicKey33B64u',
    ),
    groupPublicKey33B64u: readString(
      facts.groupPublicKey33B64u,
      'ecdsaPublicFacts.groupPublicKey33B64u',
    ),
    ethereumAddress: readString(facts.ethereumAddress, 'ecdsaPublicFacts.ethereumAddress'),
    clientShareRetryCounter,
    relayerShareRetryCounter,
  };
}

async function restoreEmailOtpEcdsaMaterialFromCustody(args: {
  projection: EmailOtpWalletCustodyUnlockProjection;
  clientSecret32: Uint8Array;
  material: EmailOtpUnlockSecretMaterialRequest;
  continuity: EmailOtpEcdsaCustodyContinuityV1;
}): Promise<EmailOtpEcdsaCustodyRestoreV1> {
  const wire = joinCustodyWireFromEnvelopeRecord(args.projection.envelope);
  if (!wire.ok) throw new Error(`Email OTP wallet custody envelope is unusable: ${wire.reason}`);
  const keySet = emailOtpEcdsaKeyManifestEntry({
    material: args.material,
    keyManifest: args.projection.keyManifest,
  });
  await ensureWalletCustodyCeremonyWasm();
  const factorSecret32 = args.clientSecret32.slice();
  let seedHeld: WasmCeremonySeedHeldV1 | null = null;
  let prepared: WasmCeremonyProtocolPreparedV1 | null = null;
  let pending: WasmCeremonyEvmActivationPendingV1 | null = null;
  try {
    seedHeld = wallet_custody_ceremony_join_v1(factorSecret32, wire.custodyJson);
    prepared = seedHeld.prepare_evm_family(
      JSON.stringify({ applicationBindingDigestB64u: keySet.applicationBindingDigestB64u }),
    );
    seedHeld = null;
    const derivedPublicKey = prepared.ecdsa_client_share_public_key33_b64u();
    if (!derivedPublicKey || derivedPublicKey !== keySet.clientRootPublicKey33B64u) {
      throw new Error('Email OTP wallet custody ECDSA material does not match its key manifest');
    }
    const first = args.continuity.signers[0];
    if (!first || first.walletKey.keyHandle !== keySet.keyHandle) {
      throw new Error('Email OTP ECDSA custody continuity does not match the requested key set');
    }
    for (const signer of args.continuity.signers) {
      if (
        signer.walletKey.walletId !== args.projection.walletId ||
        signer.walletKey.keyHandle !== first.walletKey.keyHandle ||
        signer.walletKey.ecdsaThresholdKeyId !== first.walletKey.ecdsaThresholdKeyId ||
        signer.walletKey.signingRootId !== first.walletKey.signingRootId ||
        signer.walletKey.signingRootVersion !== first.walletKey.signingRootVersion ||
        signer.walletKey.relayerKeyId !== first.walletKey.relayerKeyId ||
        JSON.stringify(signer.walletKey.publicCapability) !==
          JSON.stringify(first.walletKey.publicCapability) ||
        JSON.stringify(signer.activationReceipt) !== JSON.stringify(first.activationReceipt) ||
        JSON.stringify(signer.runtimePolicyScope) !== JSON.stringify(first.runtimePolicyScope)
      ) {
        throw new Error('Email OTP ECDSA custody continuity conflicts across targets');
      }
    }
    const identity = first.activationReceipt.ecdsa_activation.public_identity;
    pending = prepared.prepare_evm_activation_joining_custody(
      keySet.evmFamilySigningKeySlotId,
      keySet.recordedKeyManifestDigestB64u,
    );
    prepared = null;
    const completed = pending.complete(
      JSON.stringify({
        relayerKeyId: first.walletKey.relayerKeyId,
        relayerPublicKey33B64u: identity.server_public_key33_b64u,
        groupPublicKey33B64u: identity.threshold_public_key33_b64u,
        ethereumAddress: ethereumAddressFromEcdsaIdentityB64u(identity.ethereum_address20_b64u),
        relayerShareRetryCounter: identity.server_share_retry_counter,
      }),
    ) as WalletCustodyEvmFamilyActivationCompletion;
    pending = null;
    if (
      completed.walletId !== args.projection.walletId ||
      completed.keyManifestDigestB64u !== keySet.recordedKeyManifestDigestB64u ||
      completed.clientRootPublicKey33B64u !== keySet.clientRootPublicKey33B64u
    ) {
      throw new Error('Email OTP ECDSA custody activation changed its registered identity');
    }
    return {
      continuity: args.continuity,
      readyStateBlobB64u: readString(
        completed.ecdsaReadyStateBlobB64u,
        'ecdsa custody ready state',
      ),
      publicFacts: parseEmailOtpEcdsaPublicFacts(completed.ecdsaPublicFacts),
    };
  } finally {
    factorSecret32.fill(0);
    prepared?.free();
    pending?.free();
    seedHeld?.free();
  }
}

function walletCustodyActivationFactsFromEmailOtpBootstrap(
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1,
): WalletCustodyActivationFactsV1 {
  const capability = bootstrap.capability;
  const continuity = capability.registrationContinuity;
  if (continuity.kind !== 'registration') {
    throw new Error('Email OTP wallet custody cache requires registration continuity');
  }
  return {
    materialActivation: capability.materialActivation,
    lifecycleId: capability.lifecycle.lifecycleId,
    signingRootVersion: capability.lifecycle.rootShareEpoch,
    signingRootId: capability.applicationBinding.signing_root_id,
    signerSetId: capability.lifecycle.signerSetId,
    thresholdSessionId: capability.lifecycle.thresholdSessionId,
    activationTranscriptB64u: base64UrlEncode(Uint8Array.from(continuity.activationTranscript)),
    activationCapabilityBindingB64u: base64UrlEncode(
      Uint8Array.from(capability.activeCapabilityBinding),
    ),
  };
}

function parseEmailOtpWalletCustodyRejoinCommitPayload(value: unknown): {
  walletId: string;
  keySet: string;
  ed25519LocalMaterialB64u: string;
  ed25519LocalMaterialNonceB64u: string;
  ed25519ApplicationBindingDigestB64u: string;
} {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('Email OTP wallet custody rejoin returned no commit payload');
  const walletId = readString(record.walletId, 'wallet custody rejoin walletId');
  const keySet = readString(record.keySet, 'wallet custody rejoin keySet');
  if (keySet !== 'near_ed25519_v1') {
    throw new Error('Email OTP wallet custody rejoin returned the wrong key set');
  }
  const ed25519LocalMaterialB64u = readString(
    record.ed25519LocalMaterialB64u,
    'wallet custody rejoin local material',
  );
  const ed25519LocalMaterialNonceB64u = readString(
    record.ed25519LocalMaterialNonceB64u,
    'wallet custody rejoin local material nonce',
  );
  const ed25519ApplicationBindingDigestB64u = readString(
    record.ed25519ApplicationBindingDigestB64u,
    'wallet custody rejoin application binding digest',
  );
  return {
    walletId,
    keySet,
    ed25519LocalMaterialB64u,
    ed25519LocalMaterialNonceB64u,
    ed25519ApplicationBindingDigestB64u,
  };
}

function walletCustodyEd25519RejoinMaterial(args: {
  payload: ReturnType<typeof parseEmailOtpWalletCustodyRejoinCommitPayload>;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
}): LoadedWalletCustodyEd25519MaterialV1 {
  const capability = args.bootstrap.capability;
  const nearAccountId = readString(
    args.bootstrap.session.nearAccountId,
    'wallet custody nearAccountId',
  );
  if (nearAccountId !== capability.nearAccountId) {
    throw new Error('Email OTP wallet custody rejoin near account changed');
  }
  if (args.payload.walletId !== capability.applicationBinding.wallet_id) {
    throw new Error('Email OTP wallet custody rejoin wallet changed');
  }
  const registeredPublicKeyB64u = base64UrlEncode(args.metadata.registeredPublicKey);
  const expectedRegisteredPublicKeyB64u = base64UrlEncode(
    Uint8Array.from(capability.registeredPublicKey),
  );
  if (registeredPublicKeyB64u !== expectedRegisteredPublicKeyB64u) {
    throw new Error('Email OTP wallet custody rejoin registered key changed');
  }
  const participantIds: readonly [number, number] = [
    args.metadata.participantIds[0],
    args.metadata.participantIds[1],
  ];
  const binding: WalletCustodyEd25519MaterialBindingV1 = {
    kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    applicationBindingDigestB64u: args.payload.ed25519ApplicationBindingDigestB64u,
    registeredPublicKeyB64u,
    participantIds,
    stateEpoch: String(args.metadata.stateEpoch),
    walletId: args.payload.walletId,
    nearAccountId,
    nearEd25519SigningKeyId: capability.applicationBinding.near_ed25519_signing_key_id,
    signerSlot: capability.applicationBinding.key_creation_signer_slot,
    signingWorkerId: args.metadata.scope.signing_worker_id,
    signingWorkerVerifyingShareB64u: base64UrlEncode(args.metadata.signingWorkerVerifyingShare),
  };
  const sealed: WalletCustodySealedEd25519MaterialV1 = {
    ciphertextB64u: args.payload.ed25519LocalMaterialB64u,
    nonceB64u: args.payload.ed25519LocalMaterialNonceB64u,
  };
  return { binding, sealed };
}

async function rejoinEmailOtpEd25519FromCustody(args: {
  relayUrl: string;
  walletId: string;
  projection: EmailOtpWalletCustodyUnlockProjection;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  clientSecret32: Uint8Array;
}): Promise<{
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  material: LoadedWalletCustodyEd25519MaterialV1;
}> {
  const capability = args.bootstrap.capability;
  const custodyWire = joinCustodyWireFromEnvelopeRecord(args.projection.envelope);
  if (!custodyWire.ok) {
    throw new Error(`Email OTP wallet custody envelope is unusable: ${custodyWire.reason}`);
  }
  const participantIds: readonly [number, number] = [
    capability.participantIds[0],
    capability.participantIds[1],
  ];
  const registeredPublicKeyB64u = base64UrlEncode(Uint8Array.from(capability.registeredPublicKey));
  const recoveryRequest = await buildWalletSessionEd25519RecoveryAdmissionRequestV1({
    basis: capability,
  });
  const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
    routerOrigin: new URL(args.relayUrl).origin,
    authorization: {
      kind: 'bearer',
      value: `Bearer ${capabilitySessionWalletToken(args.bootstrap)}`,
    },
    fetch: globalThis.fetch,
  });
  const admitted = await admitWalletRecoveryEd25519V1({ request: recoveryRequest, transport });
  const protocolInputsJson = JSON.stringify({
    yaoAdmission: admitted.receipt,
    yaoApplication: admitted.request.application_binding,
    clientParticipantId: participantIds[0],
    signingWorkerParticipantId: participantIds[1],
    continuityRegisteredPublicKeyB64u: registeredPublicKeyB64u,
  });
  await ensureWalletCustodyCeremonyWasm();
  const factorSecret32 = args.clientSecret32.slice();
  let seedHeld: WasmCeremonySeedHeldV1 | null = null;
  let prepared: WasmCeremonyProtocolPreparedV1 | null = null;
  let completed: WasmCeremonyProtocolCompletedV1 | null = null;
  let established: WasmCeremonyManifestEstablishedV1 | null = null;
  try {
    seedHeld = wallet_custody_ceremony_join_v1(factorSecret32, custodyWire.custodyJson);
    prepared = seedHeld.prepare_near_ed25519(protocolInputsJson);
    seedHeld = null;
    const yaoExecuteRequestJson = prepared.yao_execute_request_json();
    if (!yaoExecuteRequestJson) {
      throw new Error('Email OTP wallet custody rejoin produced no Router request');
    }
    const activationResultJson = await executeWalletRecoveryEd25519RoundV1({
      executeRequestJson: yaoExecuteRequestJson,
      transport,
    });
    completed = prepared.complete_near_ed25519(activationResultJson);
    prepared = null;
    const activationReceipt = await activateWalletRecoveryEd25519V1({
      request: recoveryRequest,
      protocolResultJson: activationResultJson,
      transport,
    });
    established = completed.establish_manifest(
      'near_ed25519_v1',
      capability.applicationBinding.near_ed25519_signing_key_id,
    );
    completed = null;
    const payload = parseEmailOtpWalletCustodyRejoinCommitPayload(
      established.finish_joining_custody(),
    );
    established = null;
    if (payload.walletId !== args.walletId) {
      throw new Error('Email OTP wallet custody rejoin returned another wallet');
    }
    const metadata = walletRecoveryEd25519ActiveClientMetadataV1({
      admissionRequest: recoveryRequest,
      activationResultJson,
      activationReceipt,
    });
    const material = walletCustodyEd25519RejoinMaterial({
      payload,
      metadata,
      bootstrap: args.bootstrap,
    });
    const activeClient = await openWalletCustodyEd25519ActiveClientV1({
      material,
      activation: walletCustodyActivationFactsFromActiveClientMetadataV1(metadata),
      envelope: walletCustodyCacheEnvelopeFromRecordV1(args.projection.envelope),
      ownedFactorSecret: args.clientSecret32.slice(),
    });
    try {
      const activated = storeEmailOtpEd25519YaoActiveClient(activeClient);
      return { ...activated, material };
    } catch (error) {
      activeClient.dispose();
      throw error;
    }
  } finally {
    factorSecret32.fill(0);
    prepared?.free();
    seedHeld?.free();
    completed?.free();
    established?.free();
  }
}

function capabilitySessionWalletToken(
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1,
): ReturnType<typeof requireOpaqueWalletSessionToken> {
  return requireOpaqueWalletSessionToken(
    readString(bootstrap.session.walletSessionToken, 'wallet custody Wallet Session token'),
  );
}

type EmailOtpEd25519WalletCustodyRestoreResult =
  | {
      kind: 'opened';
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      material?: LoadedWalletCustodyEd25519MaterialV1;
    }
  | { kind: 'cache_absent' };

async function restoreEmailOtpEd25519FromCustodyCache(args: {
  relayUrl: string;
  walletId: string;
  projection: EmailOtpWalletCustodyUnlockProjection;
  material:
    | Extract<EmailOtpUnlockSecretMaterialRequest, { kind: 'ed25519_yao_recovery' }>
    | Extract<EmailOtpUnlockSecretMaterialRequest, { kind: 'wallet_unlock_capabilities' }>;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  clientSecret32: Uint8Array;
}): Promise<EmailOtpEd25519WalletCustodyRestoreResult> {
  const cacheRequest =
    args.material.kind === 'wallet_unlock_capabilities'
      ? args.material.ed25519Yao.walletCustodyEd25519Material
      : args.material.walletCustodyEd25519Material;
  if (cacheRequest.kind === 'absent') {
    if (args.material.kind !== 'ed25519_yao_recovery') return { kind: 'cache_absent' };
    const rejoined = await rejoinEmailOtpEd25519FromCustody({
      relayUrl: args.relayUrl,
      walletId: args.walletId,
      projection: args.projection,
      bootstrap: args.bootstrap,
      clientSecret32: args.clientSecret32,
    });
    return {
      kind: 'opened',
      activeClientHandle: rejoined.activeClientHandle,
      metadata: rejoined.metadata,
      material: rejoined.material,
    };
  }
  const activeClient = await openWalletCustodyEd25519ActiveClientV1({
    material: cacheRequest.material,
    activation: walletCustodyActivationFactsFromEmailOtpBootstrap(args.bootstrap),
    envelope: walletCustodyCacheEnvelopeFromRecordV1(args.projection.envelope),
    ownedFactorSecret: args.clientSecret32.slice(),
  });
  try {
    const activated = storeEmailOtpEd25519YaoActiveClient(activeClient);
    return {
      kind: 'opened',
      activeClientHandle: activated.activeClientHandle,
      metadata: activated.metadata,
    };
  } catch (error) {
    activeClient.dispose();
    throw error;
  }
}

async function completeEmailOtpUnlockFromSecret32(args: {
  relayUrl: string;
  walletId: string;
  authoritySelector: EmailOtpAuthoritySelector;
  orgId?: string;
  userId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  clientSecret32: Uint8Array;
  material: EmailOtpUnlockSecretMaterialRequest;
  sessionAuth: WalletSessionRouteAuth | undefined;
  ed25519WalletSessionToken: string | undefined;
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
      ...emailOtpAuthoritySelectorBody(args.authoritySelector),
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
  let unlockPublicKey33: Uint8Array | null = null;
  let unlockSignature65: Uint8Array | null = null;
  let openedEd25519Client: EmailOtpEd25519YaoWorkerActivationHandle | null = null;
  let openedEd25519Material: LoadedWalletCustodyEd25519MaterialV1 | null = null;
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

    const requestedCapabilities = buildEmailOtpRequestedCapabilities({
      material: args.material,
    });
    const verified = await postEmailOtpJson({
      relayUrl: readString(args.relayUrl, 'relayUrl'),
      route: '/wallet/unlock/verify',
      ...(args.sessionAuth ? { sessionAuth: args.sessionAuth } : {}),
      body: {
        unlockBackend: 'email_otp',
        walletId,
        ...emailOtpAuthoritySelectorBody(args.authoritySelector),
        ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: clientUnlockPublicKeyB64u,
          signature: unlockSignatureB64u,
        },
        ...(args.material.kind === 'ecdsa' && args.material.ecdsaSessionPolicy
          ? { ecdsaSessionPolicy: args.material.ecdsaSessionPolicy }
          : args.material.kind === 'wallet_unlock_capabilities'
            ? { ecdsaSessionPolicy: args.material.ecdsa.sessionPolicy }
            : {}),
        ...(args.ed25519WalletSessionToken ||
        emailOtpEd25519WalletSessionTokenForUnlockMaterial(args.material)
          ? {
              ed25519WalletSessionToken:
                args.ed25519WalletSessionToken ||
                emailOtpEd25519WalletSessionTokenForUnlockMaterial(args.material),
            }
          : {}),
        requestedCapabilities,
      },
    });
    const walletCustody = parseEmailOtpWalletCustodyUnlockProjection({
      raw: verified.walletCustody,
      walletId,
      enrollmentId: args.enrollmentId,
      enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
    });
    const ecdsaCustody =
      args.material.kind === 'ecdsa' && args.material.ecdsaSessionPolicy
        ? parseEmailOtpEcdsaCustodyContinuity(verified.ecdsaCustody)
        : args.material.kind === 'wallet_unlock_capabilities'
          ? parseEmailOtpEcdsaCustodyContinuity(verified.ecdsaCustody)
          : undefined;
    const ecdsaCustodyRestore = ecdsaCustody
      ? await restoreEmailOtpEcdsaMaterialFromCustody({
          projection: walletCustody,
          clientSecret32: args.clientSecret32,
          material: args.material,
          continuity: ecdsaCustody,
        })
      : undefined;
    const ed25519YaoBootstrap =
      args.material.kind === 'ed25519_yao_recovery' ||
      args.material.kind === 'wallet_unlock_capabilities'
        ? parseEmailOtpEd25519YaoRecoveryBootstrap(verified.ed25519YaoCapability)
        : null;
    if (
      ed25519YaoBootstrap &&
      (args.material.kind === 'ed25519_yao_recovery' ||
        args.material.kind === 'wallet_unlock_capabilities')
    ) {
      const restored = await restoreEmailOtpEd25519FromCustodyCache({
        relayUrl: args.relayUrl,
        walletId,
        projection: walletCustody,
        material: args.material,
        bootstrap: ed25519YaoBootstrap,
        clientSecret32: args.clientSecret32,
      });
      if (restored.kind === 'opened') {
        openedEd25519Client = {
          activeClientHandle: restored.activeClientHandle,
          metadata: restored.metadata,
        };
        openedEd25519Material = restored.material || null;
      }
    }
    const ecdsaSession =
      args.material.kind === 'ecdsa' && !args.material.ecdsaSessionPolicy
        ? undefined
        : args.material.kind === 'ecdsa' || args.material.kind === 'wallet_unlock_capabilities'
          ? parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(verified.ecdsaSession)
          : undefined;
    if (ecdsaSession) {
      bindEmailOtpEcdsaWarmSessionFactor({
        session: ecdsaSession.session,
        factorSecret32: args.clientSecret32,
      });
    }
    const commonResult = {
      unlockChallengeId,
      unlockChallengeB64u,
      clientUnlockPublicKeyB64u,
      unlockSignatureB64u,
    };
    switch (args.material.kind) {
      case 'ecdsa': {
        return {
          kind: 'ecdsa',
          ...commonResult,
          ...(ecdsaSession ? { ecdsaSession } : {}),
          ...(ecdsaCustodyRestore ? { ecdsaCustody: ecdsaCustodyRestore } : {}),
        };
      }
      case 'ed25519_yao_export':
        return {
          kind: 'ed25519_yao_export',
          ...commonResult,
          walletCustodyEnvelope: walletCustody.envelope,
        };
      case 'wallet_unlock_capabilities': {
        if (openedEd25519Client) {
          const ed25519YaoCapability = ed25519YaoBootstrap;
          if (!ed25519YaoCapability) {
            throw new Error('Email OTP Ed25519 custody capability was not returned');
          }
          bindEmailOtpEd25519YaoCapabilityWarmFactor({
            bootstrap: ed25519YaoCapability,
            factorSecret32: args.clientSecret32,
            materialActivation: ed25519YaoCapability.capability.materialActivation,
          });
          const opened = openedEd25519Client;
          openedEd25519Client = null;
          return {
            kind: 'wallet_unlock_capabilities',
            ...commonResult,
            walletCustodyEnvelope: walletCustody.envelope,
            ecdsa: {
              session: requireEmailOtpWorkerEcdsaSessionResponse(ecdsaSession),
              custody: requireEmailOtpWorkerEcdsaCustodyRestore(ecdsaCustodyRestore),
            },
            ed25519Yao: {
              kind: 'capability',
              activeClientHandle: opened.activeClientHandle,
              metadata: opened.metadata,
              bootstrap: ed25519YaoCapability,
            },
          };
        }
        if (!ed25519YaoBootstrap) {
          throw new Error('Email OTP Ed25519 custody capability was not returned');
        }
        return {
          kind: 'wallet_unlock_capabilities',
          ...commonResult,
          walletCustodyEnvelope: walletCustody.envelope,
          ecdsa: {
            session: requireEmailOtpWorkerEcdsaSessionResponse(ecdsaSession),
            custody: requireEmailOtpWorkerEcdsaCustodyRestore(ecdsaCustodyRestore),
          },
          ed25519Yao: {
            kind: 'wallet_custody_cache_absent',
            bootstrap: ed25519YaoBootstrap,
          },
        };
      }
      case 'ed25519_yao_recovery':
        if (openedEd25519Client) {
          const ed25519YaoCapability = ed25519YaoBootstrap;
          if (!ed25519YaoCapability) {
            throw new Error('Email OTP Ed25519 custody capability was not returned');
          }
          bindEmailOtpEd25519YaoCapabilityWarmFactor({
            bootstrap: ed25519YaoCapability,
            factorSecret32: args.clientSecret32,
            materialActivation: ed25519YaoCapability.capability.materialActivation,
          });
          const opened = openedEd25519Client;
          openedEd25519Client = null;
          return {
            kind: 'ed25519_yao_capability',
            ...commonResult,
            activeClientHandle: opened.activeClientHandle,
            metadata: opened.metadata,
            ed25519YaoCapability,
            ...(openedEd25519Material
              ? { walletCustodyEd25519Material: openedEd25519Material }
              : {}),
            walletCustodyEnvelope: walletCustody.envelope,
          };
        }
        if (!ed25519YaoBootstrap) {
          throw new Error('Email OTP Ed25519 custody capability was not returned');
        }
        return {
          kind: 'wallet_custody_cache_absent',
          ...commonResult,
          ed25519YaoRecovery: ed25519YaoBootstrap,
        };
      default:
        return assertNeverEmailOtpWorker(args.material);
    }
  } finally {
    if (openedEd25519Client) {
      removeEmailOtpEd25519YaoActiveClient(openedEd25519Client.activeClientHandle);
    }
    zeroizeBytes(challengeDigest32);
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
  returnClientSecret32?: boolean;
  skipServerFinalize?: boolean;
  googleEmailOtpRegistrationAttemptId?: string;
  onProgress?: (code: EmailOtpWorkerProgressCode) => void;
}): Promise<{
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  serverSealedFactorCiphertextB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  emailOtpEnrollment: {
    enrollmentSealKeyVersion: string;
    serverSealedFactorCiphertextB64u: string;
    clientUnlockPublicKeyB64u: string;
    unlockKeyVersion: string;
  };
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
  let unlockPrivateKey32: Uint8Array | null = null;
  let unlockPublicKey33: Uint8Array | null = null;
  try {
    const sessionAuth =
      args.routePlan.routeFamily === 'signing_session'
        ? authLaneToRouteAuth(args.routePlan.authLane)
        : undefined;
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
    const serverSealedFactorCiphertextB64u = readString(
      await runtime.removeClientSealWithKeyHandle({
        ciphertextB64u: clientCiphertext,
        keyHandle,
      }),
      'serverSealedFactorCiphertextB64u',
    );

    unlockPrivateKey32 = await deriveEmailOtpUnlockAuthSeedInWorker({
      clientSecret32,
      walletId,
    });
    unlockPublicKey33 = secp256k1_private_key_32_to_public_key_33(unlockPrivateKey32) as Uint8Array;
    const clientUnlockPublicKeyB64u = base64UrlEncode(unlockPublicKey33);
    const enrollmentId = emailOtpDeviceEnrollmentId(walletId, userId);
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
          enrollmentSealKeyVersion,
          serverSealedFactorCiphertextB64u,
          clientUnlockPublicKeyB64u,
          unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
          ...(googleEmailOtpRegistrationAttemptId ? { googleEmailOtpRegistrationAttemptId } : {}),
        },
      });
      args.onProgress?.('otp.verify.succeeded');
    }
    args.onProgress?.('signer.email_otp.enroll.started');
    args.onProgress?.('signer.email_otp.enroll.succeeded');

    const returnedClientSecret32 =
      args.returnClientSecret32 && clientSecret32 ? clientSecret32 : null;
    if (returnedClientSecret32) {
      clientSecret32 = null;
    }

    return {
      challengeId: challengeId || '',
      otpChannel: EMAIL_OTP_CHANNEL,
      enrollmentId,
      enrollmentSealKeyVersion,
      serverSealedFactorCiphertextB64u,
      clientUnlockPublicKeyB64u,
      unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
      emailOtpEnrollment: {
        enrollmentSealKeyVersion,
        serverSealedFactorCiphertextB64u,
        clientUnlockPublicKeyB64u,
        unlockKeyVersion: EMAIL_OTP_UNLOCK_KEY_VERSION,
      },
      ...(returnedClientSecret32 ? { clientSecret32: returnedClientSecret32 } : {}),
    };
  } finally {
    zeroizeBytes(clientSecret32);
    zeroizeBytes(unlockPrivateKey32);
    zeroizeBytes(unlockPublicKey33);
    await runtime.destroyClientKeyHandle({ keyHandle }).catch(() => undefined);
    clientSecret32 = null;
  }
}

async function loginWithEmailOtpAndUnlockWallet(args: {
  relayUrl: string;
  walletId: string;
  authoritySelector: EmailOtpAuthoritySelector;
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
  factorReleaseSessionAuth?: WalletSessionRouteAuth;
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
        ecdsaSession?: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        ecdsaCustody?: EmailOtpEcdsaCustodyRestoreV1;
        clientSecret32?: never;
        ed25519YaoRecovery?: never;
      }
    | {
        kind: 'ed25519_yao_export';
        clientSecret32: Uint8Array;
        walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
        ed25519YaoRecovery?: never;
      }
    | {
        kind: 'wallet_custody_cache_absent';
        ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
      }
    | {
        kind: 'ed25519_yao_capability';
        activeClientHandle: string;
        metadata: RouterAbEd25519YaoActiveClientMetadataV1;
        ed25519YaoCapability: EmailOtpEd25519YaoRecoveryBootstrapV1;
        walletCustodyEd25519Material?: LoadedWalletCustodyEd25519MaterialV1;
        /* An Ed25519-only unlock carries the same export-root custody a
           combined unlock returns, so the main thread can establish the
           unlocked export-root capability. */
        clientSecret32: Uint8Array;
        walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
        ed25519YaoRecovery?: never;
      }
    | {
        kind: 'wallet_unlock_capabilities';
        clientSecret32: Uint8Array;
        walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
        ecdsa: {
          session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
          custody: EmailOtpEcdsaCustodyRestoreV1;
        };
        ed25519Yao:
          | {
              kind: 'wallet_custody_cache_absent';
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
  const relayUrl = readString(args.relayUrl, 'relayUrl');
  const walletId = readString(args.walletId, 'walletId');
  const groupId = readString(args.groupId, 'groupId');
  let clientSecret32: Uint8Array | null = null;
  try {
    const sessionAuth =
      args.routePlan.routeFamily === 'signing_session'
        ? authLaneToRouteAuth(args.routePlan.authLane)
        : undefined;
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
            ...emailOtpAuthoritySelectorBody(args.authoritySelector),
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
    const released = await releaseEmailOtpFactorSecret({
      relayUrl,
      walletId,
      challengeId,
      sessionAuth: args.factorReleaseSessionAuth || sessionAuth,
      ...(args.verification.kind === 'email_otp_unseal_grant'
        ? { kind: 'verified_grant', loginGrant: args.verification.grant }
        : {
            kind: 'email_otp',
            authoritySelector: args.authoritySelector,
            otpCode: readString(args.verification.otpCode, 'otpCode'),
            operation: args.routePlan.operation,
          }),
    });
    if (args.verification.kind === 'otp') args.onProgress?.('otp.verify.succeeded');
    const enrollmentSealKeyVersion = released.enrollmentSealKeyVersion;
    clientSecret32 = released.factorSecret32;
    const unlocked = await completeEmailOtpUnlockFromSecret32({
      relayUrl,
      walletId,
      authoritySelector: args.authoritySelector,
      ...(readOptionalString(args.orgId) ? { orgId: readOptionalString(args.orgId) } : {}),
      userId,
      enrollmentId: released.enrollmentId,
      enrollmentSealKeyVersion,
      clientSecret32,
      material: args.material,
      sessionAuth,
      ed25519WalletSessionToken: undefined,
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
          ...(unlocked.ecdsaSession ? { ecdsaSession: unlocked.ecdsaSession } : {}),
          ...(unlocked.ecdsaCustody ? { ecdsaCustody: unlocked.ecdsaCustody } : {}),
        };
      case 'ed25519_yao_export': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        return {
          kind: 'ed25519_yao_export',
          ...commonResult,
          clientSecret32: ownedClientSecret32,
          walletCustodyEnvelope: unlocked.walletCustodyEnvelope,
        };
      }
      case 'wallet_custody_cache_absent': {
        return {
          kind: 'wallet_custody_cache_absent',
          ...commonResult,
          ed25519YaoRecovery: unlocked.ed25519YaoRecovery,
        };
      }
      case 'ed25519_yao_capability': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        return {
          kind: 'ed25519_yao_capability',
          ...commonResult,
          activeClientHandle: unlocked.activeClientHandle,
          metadata: unlocked.metadata,
          ed25519YaoCapability: unlocked.ed25519YaoCapability,
          ...(unlocked.walletCustodyEd25519Material
            ? { walletCustodyEd25519Material: unlocked.walletCustodyEd25519Material }
            : {}),
          clientSecret32: ownedClientSecret32,
          walletCustodyEnvelope: unlocked.walletCustodyEnvelope,
        };
      }
      case 'wallet_unlock_capabilities': {
        const ownedClientSecret32 = clientSecret32;
        clientSecret32 = null;
        if (unlocked.ed25519Yao.kind === 'wallet_custody_cache_absent') {
          return {
            kind: 'wallet_unlock_capabilities',
            ...commonResult,
            clientSecret32: ownedClientSecret32,
            walletCustodyEnvelope: unlocked.walletCustodyEnvelope,
            ecdsa: unlocked.ecdsa,
            ed25519Yao: {
              kind: 'wallet_custody_cache_absent',
              bootstrap: unlocked.ed25519Yao.bootstrap,
            },
          };
        }
        return {
          kind: 'wallet_unlock_capabilities',
          ...commonResult,
          clientSecret32: ownedClientSecret32,
          walletCustodyEnvelope: unlocked.walletCustodyEnvelope,
          ecdsa: unlocked.ecdsa,
          ed25519Yao: unlocked.ed25519Yao,
        };
      }
      default:
        return assertNeverEmailOtpWorker(unlocked);
    }
  } finally {
    zeroizeBytes(clientSecret32);
  }
}

function walletCustodyEnvelopeBindingJson(envelope: PasskeyCustodyEnvelopeRecord): string {
  return JSON.stringify({
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    factor: envelope.factor,
    envelopeRevision: envelope.envelopeRevision,
    binding: envelope.binding,
  });
}

function disposeEmailOtpPasskeyCustodyLink(entry: EmailOtpPasskeyCustodyLinkEntry): void {
  entry.handle.free();
}

function discardExpiredEmailOtpPasskeyCustodyLinks(nowMs: number): void {
  for (const [pendingHandleId, entry] of emailOtpPasskeyCustodyLinks) {
    if (entry.expiresAtMs > nowMs) continue;
    emailOtpPasskeyCustodyLinks.delete(pendingHandleId);
    disposeEmailOtpPasskeyCustodyLink(entry);
  }
}

function storeEmailOtpPasskeyCustodyLink(entry: EmailOtpPasskeyCustodyLinkEntry): string {
  const nowMs = Date.now();
  discardExpiredEmailOtpPasskeyCustodyLinks(nowMs);
  if (emailOtpPasskeyCustodyLinks.size >= MAX_EMAIL_OTP_PASSKEY_CUSTODY_LINKS) {
    const oldest = emailOtpPasskeyCustodyLinks.entries().next().value as
      | [string, EmailOtpPasskeyCustodyLinkEntry]
      | undefined;
    if (oldest) {
      emailOtpPasskeyCustodyLinks.delete(oldest[0]);
      disposeEmailOtpPasskeyCustodyLink(oldest[1]);
    }
  }
  const pendingHandleId = secureRandomId(
    'email-otp-passkey-custody-link',
    24,
    'Email OTP passkey custody link handle',
  );
  emailOtpPasskeyCustodyLinks.set(pendingHandleId, entry);
  return pendingHandleId;
}

function takeEmailOtpPasskeyCustodyLink(
  pendingHandleIdRaw: unknown,
): EmailOtpPasskeyCustodyLinkEntry {
  const pendingHandleId = readString(pendingHandleIdRaw, 'pendingHandleId');
  const nowMs = Date.now();
  discardExpiredEmailOtpPasskeyCustodyLinks(nowMs);
  const entry = emailOtpPasskeyCustodyLinks.get(pendingHandleId);
  if (!entry) throw new Error('Email OTP passkey custody link is missing or expired');
  emailOtpPasskeyCustodyLinks.delete(pendingHandleId);
  return entry;
}

function emailOtpPasskeySourceEnvelopeMatches(
  expected: PasskeyCustodyEnvelopeRecord,
  received: PasskeyCustodyEnvelopeRecord,
): boolean {
  return (
    expected.walletId === received.walletId &&
    expected.envelopeId === received.envelopeId &&
    expected.envelopeVersion === received.envelopeVersion &&
    expected.envelopeRevision === received.envelopeRevision &&
    expected.nonceB64u === received.nonceB64u &&
    expected.sealedCustodySecretB64u === received.sealedCustodySecretB64u &&
    expected.aadHashB64u === received.aadHashB64u &&
    expected.ciphertextDigestB64u === received.ciphertextDigestB64u &&
    JSON.stringify(expected.binding) === JSON.stringify(received.binding) &&
    JSON.stringify(expected.factor) === JSON.stringify(received.factor) &&
    JSON.stringify(expected.lifecycle) === JSON.stringify(received.lifecycle)
  );
}

async function prepareEmailOtpPasskeyCustodyLink(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly userId: string;
  readonly groupId: string;
  readonly routePlan: EmailOtpRoutePlan;
  readonly verification: {
    readonly kind: 'otp';
    readonly challengeId: string;
    readonly otpCode: string;
  };
}): Promise<EmailOtpWorkerOperationMap['prepareEmailOtpPasskeyCustodyLink']['result']> {
  const orgId = readString(args.groupId, 'groupId');
  const recovered = await loginWithEmailOtpAndUnlockWallet({
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    authoritySelector: { kind: 'wallet' },
    userId: args.userId,
    groupId: args.groupId,
    routePlan: args.routePlan,
    orgId,
    verification: args.verification,
    material: { kind: 'ed25519_yao_export' },
  });
  if (recovered.kind !== 'ed25519_yao_export') {
    throw new Error('Email OTP passkey linking did not return wallet custody material');
  }
  const envelope = parsePasskeyCustodyEnvelopeRecord(recovered.walletCustodyEnvelope);
  if (
    envelope.walletId !== args.walletId ||
    envelope.factor.kind !== 'email_otp' ||
    envelope.lifecycle.state !== 'active'
  ) {
    zeroizeBytes(recovered.clientSecret32);
    throw new Error('Email OTP passkey linking returned a mismatched custody envelope');
  }
  await ensureNearSignerRecoveryWasm();
  let handle: WasmPasskeyCustodyHandleV1 | null = null;
  try {
    handle = passkey_custody_open_wallet_seed_v1(
      recovered.clientSecret32,
      walletCustodyEnvelopeBindingJson(envelope),
      base64UrlDecode(envelope.nonceB64u),
      envelope.sealedCustodySecretB64u,
      envelope.aadHashB64u,
      envelope.ciphertextDigestB64u,
    );
    const expiresAtMs = Date.now() + EMAIL_OTP_PASSKEY_CUSTODY_LINK_TTL_MS;
    const pendingHandleId = storeEmailOtpPasskeyCustodyLink({ handle, envelope, expiresAtMs });
    handle = null;
    return {
      pendingHandleId,
      walletId: envelope.walletId,
      envelopeId: envelope.envelopeId,
      envelopeRevision: envelope.envelopeRevision,
      enrollmentId: envelope.factor.enrollmentId,
      enrollmentSealKeyVersion: envelope.factor.enrollmentSealKeyVersion,
      expiresAtMs,
    };
  } finally {
    handle?.free();
    zeroizeBytes(recovered.clientSecret32);
  }
}

async function rotateEmailOtpWalletRecoverySet(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly userId: string;
  readonly groupId: string;
  readonly routePlan: EmailOtpRoutePlan;
  readonly verification: {
    readonly kind: 'otp';
    readonly challengeId: string;
    readonly otpCode: string;
  };
  readonly recoveryCodesJson: string;
}): Promise<EmailOtpWorkerOperationMap['rotateEmailOtpWalletRecoverySet']['result']> {
  const orgId = readString(args.groupId, 'groupId');
  const recovered = await loginWithEmailOtpAndUnlockWallet({
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    authoritySelector: { kind: 'wallet' },
    userId: args.userId,
    groupId: args.groupId,
    routePlan: args.routePlan,
    orgId,
    verification: args.verification,
    material: { kind: 'ed25519_yao_export' },
  });
  if (recovered.kind !== 'ed25519_yao_export') {
    throw new Error('Email OTP recovery rotation did not return wallet custody material');
  }
  await ensureWalletCustodyCeremonyWasm();
  let handle: WasmCeremonySeedHeldV1 | null = null;
  try {
    const custody = joinCustodyWireFromEnvelopeRecord(recovered.walletCustodyEnvelope);
    if (!custody.ok) throw new Error(custody.reason);
    handle = wallet_custody_ceremony_join_v1(recovered.clientSecret32, custody.custodyJson);
    const resultJson = handle.rotate_recovery_codes(args.recoveryCodesJson);
    handle = null;
    return parseWalletRecoverySetRotationWorkerResultV1(JSON.parse(resultJson));
  } finally {
    handle?.free();
    zeroizeBytes(recovered.clientSecret32);
  }
}

function requireWorkerWalletAuthMethodId(value: unknown): WalletAuthMethodId {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(`walletAuthMethodId ${parsed.error.message}`);
  return parsed.value;
}

function completeEmailOtpPasskeyCustodyLink(args: {
  readonly pendingHandleId: string;
  readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly registration: EmailOtpWorkerOperationMap['completeEmailOtpPasskeyCustodyLink']['payload']['registration'];
  readonly registrationCredential: EmailOtpWorkerOperationMap['completeEmailOtpPasskeyCustodyLink']['payload']['registrationCredential'];
}): EmailOtpWorkerOperationMap['completeEmailOtpPasskeyCustodyLink']['result'] {
  const entry = takeEmailOtpPasskeyCustodyLink(args.pendingHandleId);
  const existingEnvelope = parsePasskeyCustodyEnvelopeRecord(args.existingEnvelope);
  const credential = normalizeRegistrationCredential(args.registrationCredential);
  const replacementFactorSecret = base64UrlDecode(getPrfFirstB64uFromCredential(credential) || '');
  try {
    if (!emailOtpPasskeySourceEnvelopeMatches(entry.envelope, existingEnvelope)) {
      throw new Error('Email OTP passkey linking source envelope changed');
    }
    if (replacementFactorSecret.byteLength !== 32) {
      throw new Error('New passkey did not return a 32-byte PRF.first output');
    }
    const credentialId = parseWebAuthnCredentialIdB64u(credential.rawId || credential.id);
    if (!credentialId.ok) throw new Error(credentialId.error.message);
    const envelopeId = parsePasskeyEnvelopeId(
      secureRandomId('wallet-custody-envelope', 24, 'wallet custody envelope ids'),
    );
    if (!envelopeId.ok) throw new Error(envelopeId.error.message);
    const factor = buildPasskeyEnvelopeFactor({
      rpId: args.registration.rpId,
      credentialIdB64u: credentialId.value,
    });
    const replacementBindingJson = JSON.stringify({
      walletId: existingEnvelope.walletId,
      envelopeId: envelopeId.value,
      factor,
      envelopeRevision: 1,
      binding: existingEnvelope.binding,
    });
    const resealed = passkey_custody_reseal_wallet_seed_v1(
      entry.handle,
      replacementFactorSecret,
      replacementBindingJson,
    ) as Record<string, unknown>;
    const nowMs = Date.now();
    return {
      registrationCredential: credential,
      custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(
        buildPasskeyCustodyEnvelopeRecord({
          ownership: buildMethodBoundEnvelopeOwnership(args.walletAuthMethodId),
          envelopeId: envelopeId.value,
          walletId: existingEnvelope.walletId,
          binding: existingEnvelope.binding,
          factor,
          envelopeRevision: parseEnvelopeRevision(1),
          nonceB64u: parseEnvelopeNonceB64u(readString(resealed.nonceB64u, 'resealed.nonceB64u')),
          sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
            readString(resealed.sealedCustodySecretB64u, 'resealed.sealedCustodySecretB64u'),
          ),
          aadHashB64u: parseDigestB64u(readString(resealed.aadHashB64u, 'resealed.aadHashB64u')),
          ciphertextDigestB64u: parseDigestB64u(
            readString(resealed.ciphertextDigestB64u, 'resealed.ciphertextDigestB64u'),
          ),
          lifecycle: { state: 'active', activatedAtMs: nowMs },
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
        }),
      ),
    };
  } finally {
    replacementFactorSecret.fill(0);
    disposeEmailOtpPasskeyCustodyLink(entry);
  }
}

function discardEmailOtpPasskeyCustodyLink(pendingHandleIdRaw: unknown): boolean {
  const pendingHandleId = readString(pendingHandleIdRaw, 'pendingHandleId');
  const entry = emailOtpPasskeyCustodyLinks.get(pendingHandleId);
  if (!entry) return false;
  emailOtpPasskeyCustodyLinks.delete(pendingHandleId);
  disposeEmailOtpPasskeyCustodyLink(entry);
  return true;
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

function parseWalletCustodyEd25519MaterialRequest(
  value: unknown,
): EmailOtpWalletCustodyEd25519MaterialRequest {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP wallet custody Ed25519 material is required');
  const kind = readString(obj.kind, 'walletCustodyEd25519Material.kind');
  if (kind === 'absent') {
    rejectUnknownEmailOtpYaoFields(obj, ['kind'], 'walletCustodyEd25519Material');
    return { kind: 'absent' };
  }
  if (kind !== 'found') {
    throw new Error(`Unsupported wallet custody Ed25519 material kind: ${kind}`);
  }
  rejectUnknownEmailOtpYaoFields(obj, ['kind', 'material'], 'walletCustodyEd25519Material');
  const material = workerPayloadObject(obj.material);
  if (!material) throw new Error('walletCustodyEd25519Material.material is required');
  rejectUnknownEmailOtpYaoFields(
    material,
    ['binding', 'sealed'],
    'walletCustodyEd25519Material.material',
  );
  const bindingRecord = workerPayloadObject(material.binding);
  const sealedRecord = workerPayloadObject(material.sealed);
  if (!bindingRecord || !sealedRecord) {
    throw new Error('walletCustodyEd25519Material requires binding and sealed records');
  }
  rejectUnknownEmailOtpYaoFields(
    bindingRecord,
    [
      'kind',
      'applicationBindingDigestB64u',
      'registeredPublicKeyB64u',
      'participantIds',
      'stateEpoch',
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'signerSlot',
      'signingWorkerId',
      'signingWorkerVerifyingShareB64u',
    ],
    'walletCustodyEd25519Material.binding',
  );
  rejectUnknownEmailOtpYaoFields(
    sealedRecord,
    ['ciphertextB64u', 'nonceB64u'],
    'walletCustodyEd25519Material.sealed',
  );
  const participants = normalizeThresholdEd25519ParticipantIds(bindingRecord.participantIds);
  if (!participants || participants.length !== 2) {
    throw new Error('walletCustodyEd25519Material.binding.participantIds is invalid');
  }
  const signerSlot = normalizePositiveInteger(bindingRecord.signerSlot);
  if (!signerSlot) throw new Error('walletCustodyEd25519Material.binding.signerSlot is invalid');
  const binding: WalletCustodyEd25519MaterialBindingV1 = {
    kind: 'wallet_custody_ed25519_active_client_v1',
    applicationBindingDigestB64u: readString(
      bindingRecord.applicationBindingDigestB64u,
      'walletCustodyEd25519Material.binding.applicationBindingDigestB64u',
    ),
    registeredPublicKeyB64u: readString(
      bindingRecord.registeredPublicKeyB64u,
      'walletCustodyEd25519Material.binding.registeredPublicKeyB64u',
    ),
    participantIds: [participants[0], participants[1]],
    stateEpoch: readString(
      bindingRecord.stateEpoch,
      'walletCustodyEd25519Material.binding.stateEpoch',
    ),
    walletId: readString(bindingRecord.walletId, 'walletCustodyEd25519Material.binding.walletId'),
    nearAccountId: readString(
      bindingRecord.nearAccountId,
      'walletCustodyEd25519Material.binding.nearAccountId',
    ),
    nearEd25519SigningKeyId: readString(
      bindingRecord.nearEd25519SigningKeyId,
      'walletCustodyEd25519Material.binding.nearEd25519SigningKeyId',
    ),
    signerSlot,
    signingWorkerId: readString(
      bindingRecord.signingWorkerId,
      'walletCustodyEd25519Material.binding.signingWorkerId',
    ),
    signingWorkerVerifyingShareB64u: readString(
      bindingRecord.signingWorkerVerifyingShareB64u,
      'walletCustodyEd25519Material.binding.signingWorkerVerifyingShareB64u',
    ),
  };
  const sealed: WalletCustodySealedEd25519MaterialV1 = {
    ciphertextB64u: readString(
      sealedRecord.ciphertextB64u,
      'walletCustodyEd25519Material.sealed.ciphertextB64u',
    ),
    nonceB64u: readString(sealedRecord.nonceB64u, 'walletCustodyEd25519Material.sealed.nonceB64u'),
  };
  const parsed: LoadedWalletCustodyEd25519MaterialV1 = { binding, sealed };
  return { kind: 'found', material: parsed };
}

function parseWalletCustodyCacheEnvelope(value: unknown): WalletCustodyCacheEnvelopeV1 {
  const envelope = workerPayloadObject(value);
  if (!envelope) throw new Error('Wallet custody cache envelope is required');
  rejectUnknownEmailOtpYaoFields(
    envelope,
    ['bindingJson', 'nonceB64u', 'ciphertextB64u', 'aadHashB64u', 'ciphertextDigestB64u'],
    'walletCustodyCacheEnvelope',
  );
  return {
    bindingJson: readString(envelope.bindingJson, 'walletCustodyCacheEnvelope.bindingJson'),
    nonceB64u: readString(envelope.nonceB64u, 'walletCustodyCacheEnvelope.nonceB64u'),
    ciphertextB64u: readString(
      envelope.ciphertextB64u,
      'walletCustodyCacheEnvelope.ciphertextB64u',
    ),
    aadHashB64u: readString(envelope.aadHashB64u, 'walletCustodyCacheEnvelope.aadHashB64u'),
    ciphertextDigestB64u: readString(
      envelope.ciphertextDigestB64u,
      'walletCustodyCacheEnvelope.ciphertextDigestB64u',
    ),
  };
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
        thresholdSessionId: readString(target.thresholdSessionId, 'target.thresholdSessionId'),
      };
    case 'ed25519_yao': {
      rejectUnknownEmailOtpYaoFields(
        target,
        ['kind', 'thresholdSessionId', 'materialActivation'],
        'target',
      );
      const materialActivation = parseMpcMaterialActivationRef(target.materialActivation);
      if (!materialActivation.ok) {
        throw new Error(
          `Email OTP warm material activation is invalid: ${materialActivation.error.message}`,
        );
      }
      return {
        kind: 'ed25519_yao',
        thresholdSessionId: readString(target.thresholdSessionId, 'target.thresholdSessionId'),
        materialActivation: materialActivation.value,
      };
    }
    default:
      throw new Error(`Unsupported Email OTP warm material target kind: ${kind}`);
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
        ['kind', 'walletSessionToken'],
        'walletSessionAuthorization',
      );
      const walletSessionToken = readString(
        obj.walletSessionToken,
        'walletSessionAuthorization.walletSessionToken',
      );
      return { kind, walletSessionToken };
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
          'ecdsaSessionHandleBinding',
          'runtimePolicyScope',
          'ecdsaSessionPolicy',
          'walletSessionAuthorization',
        ],
        'material',
      );
      const binding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        obj.ecdsaSessionHandleBinding,
      );
      if (!binding) throw new Error('Email OTP ECDSA wallet unlock requires its session binding');
      const runtimePolicyScope = parseWorkerRuntimePolicyScope(
        obj.runtimePolicyScope,
        'Email OTP ECDSA wallet unlock',
      );
      if (binding.operation === 'wallet_unlock') {
        return {
          kind: 'ecdsa',
          ecdsaSessionHandleBinding: { ...binding, operation: 'wallet_unlock' },
          runtimePolicyScope,
          ecdsaSessionPolicy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
            obj.ecdsaSessionPolicy,
          ),
          walletSessionAuthorization: parseEmailOtpEcdsaWalletUnlockAuthorization(
            obj.walletSessionAuthorization,
          ),
        };
      }
      if (obj.ecdsaSessionPolicy !== undefined) {
        throw new Error('Email OTP first ECDSA activation requires wallet-unlock binding');
      }
      if (obj.walletSessionAuthorization !== undefined) {
        throw new Error('Email OTP Wallet Session authorization requires wallet-unlock binding');
      }
      return {
        kind: 'ecdsa',
        ecdsaSessionHandleBinding: emailOtpNonUnlockEcdsaHandleBindingFromParsedBinding(binding),
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
          'walletCustodyEd25519Material',
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
        walletCustodyEd25519Material: parseWalletCustodyEd25519MaterialRequest(
          obj.walletCustodyEd25519Material,
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
        ['sessionHandleBinding', 'runtimePolicyScope', 'sessionPolicy'],
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
          'walletCustodyEd25519Material',
        ],
        'material.ed25519Yao',
      );
      const binding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        ecdsa.sessionHandleBinding,
      );
      if (!binding) {
        throw new Error('Email OTP capability unlock requires its ECDSA session binding');
      }
      if (binding.operation !== 'wallet_unlock') {
        throw new Error('Email OTP capability unlock requires wallet-unlock ECDSA binding');
      }
      return {
        kind: 'wallet_unlock_capabilities',
        ecdsa: {
          sessionHandleBinding: { ...binding, operation: 'wallet_unlock' },
          runtimePolicyScope: parseWorkerRuntimePolicyScope(
            ecdsa.runtimePolicyScope,
            'Email OTP capability wallet unlock',
          ),
          sessionPolicy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
            ecdsa.sessionPolicy,
          ),
        },
        ed25519Yao: {
          recovery: parseEmailOtpEd25519YaoRecoveryAugmentation(ed25519Yao.recovery),
          providerSubject: readString(
            ed25519Yao.providerSubject,
            'material.ed25519Yao.providerSubject',
          ),
          nearAccountId: readString(ed25519Yao.nearAccountId, 'material.ed25519Yao.nearAccountId'),
          expectedOperationalPublicKey: readString(
            ed25519Yao.expectedOperationalPublicKey,
            'material.ed25519Yao.expectedOperationalPublicKey',
          ),
          expectedThresholdSessionId: readString(
            ed25519Yao.expectedThresholdSessionId,
            'material.ed25519Yao.expectedThresholdSessionId',
          ),
          walletCustodyEd25519Material: parseWalletCustodyEd25519MaterialRequest(
            ed25519Yao.walletCustodyEd25519Material,
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

function parseEmailOtpEd25519YaoWorkerMaterialActivation(value: unknown): MpcMaterialActivationRef {
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
      'walletSessionToken',
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'authorityScope',
      'thresholdSessionId',
      'authorizationId',
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
  if (obj.sessionKind !== 'opaque') {
    throw new Error('Email OTP Ed25519 Yao recovery session must use an opaque token');
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
  const authorizationId = parseWalletSessionAuthorizationId(obj.authorizationId);
  const quotaId = parseMpcWalletSigningQuotaId(obj.quotaId);
  if (!walletSessionId.ok || !authorizationId.ok || !quotaId.ok) {
    throw new Error('Email OTP Ed25519 Yao recovery Wallet Session identity is invalid');
  }
  return {
    sessionKind: 'opaque',
    walletSessionToken: readString(obj.walletSessionToken, 'session.walletSessionToken'),
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
    authorizationId: authorizationId.value,
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

type EmailOtpEd25519YaoMaterialActivationParser = (value: unknown) => MpcMaterialActivationRef;

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
    'exportEmailOtpEd25519YaoSeed.material.capability',
  );
}

function parseEmailOtpEd25519YaoExportMaterial(value: unknown): EmailOtpEd25519YaoExportMaterialV1 {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP Ed25519 Yao export material is required');
  const kind = readString(obj.kind, 'material.kind');
  const materialActivation = parseMpcMaterialActivationRef(obj.materialActivation);
  if (!materialActivation.ok) {
    throw new Error(
      `Email OTP export material activation is invalid: ${materialActivation.error.message}`,
    );
  }
  switch (kind) {
    case 'active_capability': {
      rejectUnknownEmailOtpYaoFields(
        obj,
        ['kind', 'materialActivation', 'capability'],
        'export material',
      );
      const capability = parseEmailOtpEd25519YaoWorkerActiveCapability(obj.capability);
      if (
        !mpcMaterialActivationRefsEqual(capability.materialActivation, materialActivation.value)
      ) {
        throw new Error('Email OTP export capability activation does not match its material');
      }
      return {
        kind,
        materialActivation: materialActivation.value,
        capability,
      };
    }
    case 'sealed_custody': {
      rejectUnknownEmailOtpYaoFields(
        obj,
        ['kind', 'materialActivation', 'walletCustodyEd25519Material', 'bootstrap'],
        'export material',
      );
      const custody = parseWalletCustodyEd25519MaterialRequest({
        kind: 'found',
        material: obj.walletCustodyEd25519Material,
      });
      if (custody.kind !== 'found') {
        throw new Error('Sealed Email OTP export material requires cached custody material');
      }
      const bootstrap = parseEmailOtpEd25519YaoWorkerRecoveryBootstrap(obj.bootstrap);
      if (
        !mpcMaterialActivationRefsEqual(
          bootstrap.capability.materialActivation,
          materialActivation.value,
        )
      ) {
        throw new Error('Email OTP export bootstrap activation does not match its material');
      }
      const capability = bootstrap.capability;
      if (
        custody.material.binding.walletId !== capability.applicationBinding.wallet_id ||
        custody.material.binding.nearAccountId !== capability.nearAccountId ||
        custody.material.binding.nearEd25519SigningKeyId !==
          capability.applicationBinding.near_ed25519_signing_key_id ||
        custody.material.binding.signerSlot !==
          capability.applicationBinding.key_creation_signer_slot ||
        custody.material.binding.signingWorkerId !== capability.lifecycle.signingWorkerId ||
        custody.material.binding.registeredPublicKeyB64u !==
          base64UrlEncode(Uint8Array.from(capability.registeredPublicKey))
      ) {
        throw new Error('Email OTP export custody material changed the exact lane');
      }
      return {
        kind,
        materialActivation: materialActivation.value,
        walletCustodyEd25519Material: custody.material,
        bootstrap,
      };
    }
    case 'sealed_export_root': {
      rejectUnknownEmailOtpYaoFields(
        obj,
        ['kind', 'materialActivation', 'capability', 'exportRootEnvelope'],
        'export material',
      );
      const capability = parseEmailOtpEd25519YaoWorkerActiveCapability(obj.capability);
      if (
        !mpcMaterialActivationRefsEqual(capability.materialActivation, materialActivation.value)
      ) {
        throw new Error('Email OTP export root capability activation does not match its material');
      }
      const exportRootEnvelope = parsePasskeyCustodyEnvelopeRecord(obj.exportRootEnvelope);
      if (
        exportRootEnvelope.lifecycle.state !== 'active' ||
        exportRootEnvelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
        exportRootEnvelope.binding.targetFactor.kind !== 'email_otp' ||
        exportRootEnvelope.factor.kind !== 'email_otp' ||
        exportRootEnvelope.binding.registeredPublicKeyB64u !==
          base64UrlEncode(Uint8Array.from(capability.registeredPublicKey)) ||
        exportRootEnvelope.walletId !== capability.applicationBinding.wallet_id
      ) {
        throw new Error('Email OTP export root envelope changed the exact lane');
      }
      return {
        kind,
        materialActivation: materialActivation.value,
        capability,
        exportRootEnvelope,
      };
    }
    default:
      throw new Error(`Unsupported Email OTP Ed25519 Yao export material kind: ${kind}`);
  }
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
      'registrationContinuity',
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
  const registrationContinuity = workerPayloadObject(obj.registrationContinuity);
  if (!registrationContinuity) {
    throw new Error('Email OTP Ed25519 Yao active capability continuity is required');
  }
  const continuityKind = readString(
    registrationContinuity.kind,
    'capability.registrationContinuity.kind',
  );
  let parsedRegistrationContinuity: EmailOtpEd25519YaoActiveCapabilityDescriptorV1['registrationContinuity'];
  if (continuityKind === 'recovery') {
    rejectUnknownEmailOtpYaoFields(
      registrationContinuity,
      ['kind', 'activationTranscript'],
      'capability.registrationContinuity',
    );
    const activationTranscript = parseEmailOtpEd25519YaoJsonBytes32(
      registrationContinuity.activationTranscript,
      'capability.registrationContinuity.activationTranscript',
    );
    parsedRegistrationContinuity = { kind: 'recovery', activationTranscript };
  } else if (continuityKind === 'registration') {
    rejectUnknownEmailOtpYaoFields(
      registrationContinuity,
      ['kind', 'admissionRequest', 'admissionReceipt', 'activationTranscript'],
      'capability.registrationContinuity',
    );
    if (!Array.isArray(registrationContinuity.activationTranscript)) {
      throw new Error('Email OTP registration continuity transcript is required');
    }
    const activationTranscript = registrationContinuity.activationTranscript.map((byte, index) => {
      const parsed = Number(byte);
      if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
        throw new Error(
          `capability.registrationContinuity.activationTranscript[${index}] is invalid`,
        );
      }
      return parsed;
    });
    if (activationTranscript.length === 0) {
      throw new Error('Email OTP registration continuity transcript is empty');
    }
    const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
      registrationContinuity.admissionRequest,
    );
    if (!admissionRequest.ok) throw new Error(admissionRequest.message);
    const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
      registrationContinuity.admissionReceipt,
    );
    if (!admissionReceipt.ok) throw new Error(admissionReceipt.message);
    parsedRegistrationContinuity = {
      kind: 'registration',
      admissionRequest: admissionRequest.value,
      admissionReceipt: admissionReceipt.value,
      activationTranscript,
    };
  } else {
    throw new Error(`Unsupported Email OTP registration continuity kind: ${continuityKind}`);
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
    registrationContinuity: parsedRegistrationContinuity,
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

function parseEmailOtpEd25519YaoWorkerRecoveryBootstrap(
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
    capability: parseEmailOtpEd25519YaoWorkerActiveCapability(obj.capability),
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
  const walletSessionToken = optionalWorkerString(walletSessionAuth.walletSessionToken);
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
    !walletSessionToken ||
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
    walletSessionAuth.kind === 'wallet_session_opaque' &&
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
    signingWalletAuth.kind === 'wallet_session_opaque' &&
    signingWalletAuth.walletSessionToken === walletSessionToken &&
    signingWalletCredential.kind === 'wallet_session_opaque' &&
    signingWalletCredential.walletSessionToken === walletSessionToken
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

function parseWorkerRouteAuth(value: unknown, label: string): WalletSessionRouteAuth {
  const obj = workerPayloadObject(value);
  const kind = normalizeOptionalTrimmedString(obj?.kind);
  const walletSessionToken = normalizeOptionalTrimmedString(obj?.walletSessionToken);
  if (kind === 'opaque_wallet_session' && walletSessionToken) {
    return {
      kind: 'opaque_wallet_session',
      walletSessionToken: requireOpaqueWalletSessionToken(walletSessionToken),
    };
  }
  throw new Error(`${label} requires opaque routeAuth`);
}

function parseOptionalWorkerRouteAuth(value: unknown): WalletSessionRouteAuth | undefined {
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

function parseOptionalWorkerEcdsaSessionHandleBinding(
  value: unknown,
): EmailOtpEcdsaSessionHandleBinding | undefined {
  if (value == null) return undefined;
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP ECDSA session handle binding must be an object');
  }
  const action = readString(
    obj.action ?? 'threshold_ecdsa_bootstrap',
    'ecdsaSessionHandleBinding.action',
  );
  if (action === 'wallet_registration_ecdsa_prepare') {
    const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
    if (operation !== 'registration') {
      throw new Error(
        'Email OTP wallet-registration ECDSA handle binding requires registration operation',
      );
    }
    const keyScope = readString(obj.keyScope, 'ecdsaSessionHandleBinding.keyScope');
    if (keyScope !== 'evm-family') {
      throw new Error(
        'Email OTP wallet-registration ECDSA handle binding requires evm-family keyScope',
      );
    }
    return {
      evmFamilySigningKeySlotId: String(
        readEvmFamilySigningKeySlotId(
          obj.evmFamilySigningKeySlotId,
          'ecdsaSessionHandleBinding.evmFamilySigningKeySlotId',
        ),
      ),
      authSubjectId: readString(obj.authSubjectId, 'ecdsaSessionHandleBinding.authSubjectId'),
      action: 'wallet_registration_ecdsa_prepare',
      operation: 'registration',
      keyScope: 'evm-family',
      chainTarget: parseWorkerChainTarget(obj.chainTarget),
    };
  }
  if (action !== 'threshold_ecdsa_bootstrap') {
    throw new Error(`Unsupported Email OTP ECDSA session handle binding action: ${action}`);
  }
  const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
  const common = {
    authSubjectId: readString(obj.authSubjectId, 'ecdsaSessionHandleBinding.authSubjectId'),
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
    keyHandle: readString(obj.keyHandle, 'ecdsaSessionHandleBinding.keyHandle'),
  };
}

function parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
  value: unknown,
): EmailOtpEcdsaSessionBootstrapHandleBinding | undefined {
  const binding = parseOptionalWorkerEcdsaSessionHandleBinding(value);
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
  const kind = readString(obj.kind, 'ecdsaSessionHandle.kind');
  switch (kind) {
    case 'requested': {
      if (!Array.isArray(obj.bindings) || obj.bindings.length === 0) {
        throw new Error(
          'Email OTP registration enrollment material requires wallet-registration ECDSA handle bindings',
        );
      }
      const bindings: EmailOtpWalletRegistrationEcdsaPrepareHandleBinding[] = [];
      for (const value of obj.bindings) {
        const binding = parseOptionalWorkerEcdsaSessionHandleBinding(value);
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
  const kind = readString(obj.kind, 'emailOtpSessionHandle.kind');
  switch (kind) {
    case 'available':
      if (!Array.isArray(obj.handles) || obj.handles.length === 0) {
        throw new Error('Email OTP registration ECDSA handle result requires handles');
      }
      {
        const handles: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload[] = [];
        for (const value of obj.handles) {
          handles.push(parseWorkerIssuedWalletRegistrationEcdsaPrepareSessionHandle(value));
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

function parseWorkerIssuedEmailOtpSessionHandle(
  value: unknown,
): EmailOtpEcdsaSessionBootstrapHandlePayload {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP ECDSA bootstrap requires emailOtpSessionHandle');
  }
  const kind = readString(obj.kind, 'emailOtpSessionHandle.kind');
  const action = readString(obj.action, 'emailOtpSessionHandle.action');
  if (kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(`Unsupported Email OTP worker handle kind: ${kind}`);
  }
  if (action !== 'threshold_ecdsa_bootstrap') {
    throw new Error(`Unsupported Email OTP worker handle action: ${action}`);
  }
  const operation = parseEmailOtpWorkerHandleOperation(obj.operation);
  const common = {
    kind: 'email_otp_worker_session_handle_v1' as const,
    sessionId: readString(obj.sessionId, 'emailOtpSessionHandle.sessionId'),
    walletId: readString(obj.walletId, 'emailOtpSessionHandle.walletId'),
    authSubjectId: readString(obj.authSubjectId, 'emailOtpSessionHandle.authSubjectId'),
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
    keyHandle: readString(obj.keyHandle, 'emailOtpSessionHandle.keyHandle'),
  };
}

function parseWorkerIssuedWalletRegistrationEcdsaPrepareSessionHandle(
  value: unknown,
): EmailOtpWalletRegistrationEcdsaPrepareHandlePayload {
  const obj = workerPayloadObject(value);
  if (!obj) {
    throw new Error('Email OTP wallet-registration ECDSA prepare requires emailOtpSessionHandle');
  }
  const kind = readString(obj.kind, 'emailOtpSessionHandle.kind');
  const action = readString(obj.action, 'emailOtpSessionHandle.action');
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
  const keyScope = readString(obj.keyScope, 'emailOtpSessionHandle.keyScope');
  if (keyScope !== 'evm-family') {
    throw new Error(
      'Email OTP wallet-registration ECDSA prepare handle requires evm-family keyScope',
    );
  }
  return {
    kind: 'email_otp_worker_session_handle_v1',
    sessionId: readString(obj.sessionId, 'emailOtpSessionHandle.sessionId'),
    walletId: readString(obj.walletId, 'emailOtpSessionHandle.walletId'),
    evmFamilySigningKeySlotId: String(
      readEvmFamilySigningKeySlotId(
        obj.evmFamilySigningKeySlotId,
        'emailOtpSessionHandle.evmFamilySigningKeySlotId',
      ),
    ),
    authSubjectId: readString(obj.authSubjectId, 'emailOtpSessionHandle.authSubjectId'),
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
  walletSessionToken: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
} {
  const obj = workerPayloadObject(value);
  if (!obj) throw new Error('Email OTP worker request requires transport');
  const walletSessionToken = optionalWorkerString(obj.walletSessionToken);
  if (!walletSessionToken) {
    throw new Error('Email OTP worker request requires an opaque Wallet Session token');
  }
  return {
    relayerUrl: readString(obj.relayerUrl, 'transport.relayerUrl'),
    walletSessionToken,
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

function parseEmailOtpOperationDigest(value: unknown, label: string): { bytes: readonly number[] } {
  const record = workerPayloadObject(value);
  if (!record) throw new Error(`${label} must be an object`);
  rejectUnknownEmailOtpYaoFields(record, ['bytes'], label);
  if (!Array.isArray(record.bytes) || record.bytes.length !== 32) {
    throw new Error(`${label}.bytes must contain exactly 32 bytes`);
  }
  const bytes = record.bytes.map((byte, index) => {
    if (!Number.isSafeInteger(byte) || Number(byte) < 0 || Number(byte) > 255) {
      throw new Error(`${label}.bytes[${index}] is invalid`);
    }
    return Number(byte);
  });
  return { bytes };
}

function parseEmailOtpOperationNetworkId(
  value: unknown,
  label: string,
): RouterAbNearNetworkIdV2Wire {
  const networkId = readString(value, label);
  if (networkId !== 'testnet' && networkId !== 'mainnet') {
    throw new Error(`${label} is invalid`);
  }
  return networkId;
}

function parseEmailOtpOperationTransactionIntent(
  value: unknown,
): RouterAbNearTransactionIntentV1Wire {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('normalSigningRequest.intent.transactions entry is invalid');
  rejectUnknownEmailOtpYaoFields(record, ['receiver_id', 'action_fingerprint'], 'transaction');
  return {
    receiver_id: readString(record.receiver_id, 'transaction.receiver_id'),
    action_fingerprint: readString(record.action_fingerprint, 'transaction.action_fingerprint'),
  };
}

function parseEmailOtpOperationDelegateIntent(
  value: unknown,
): RouterAbNearDelegateActionIntentV1Wire {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('normalSigningRequest.intent.delegate is invalid');
  rejectUnknownEmailOtpYaoFields(
    record,
    [
      'sender_id',
      'receiver_id',
      'public_key',
      'nonce',
      'max_block_height',
      'action_fingerprint',
      'canonical_delegate_borsh_b64u',
    ],
    'delegate',
  );
  return {
    sender_id: readString(record.sender_id, 'delegate.sender_id'),
    receiver_id: readString(record.receiver_id, 'delegate.receiver_id'),
    public_key: readString(record.public_key, 'delegate.public_key'),
    nonce: readString(record.nonce, 'delegate.nonce'),
    max_block_height: readString(record.max_block_height, 'delegate.max_block_height'),
    action_fingerprint: readString(record.action_fingerprint, 'delegate.action_fingerprint'),
    canonical_delegate_borsh_b64u: readString(
      record.canonical_delegate_borsh_b64u,
      'delegate.canonical_delegate_borsh_b64u',
    ),
  };
}

function parseEmailOtpOperationIntent(value: unknown): RouterAbEd25519NormalSigningIntentV2Wire {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('normalSigningRequest.intent is invalid');
  const kind = readString(record.kind, 'normalSigningRequest.intent.kind');
  switch (kind) {
    case 'near_transaction_v1': {
      rejectUnknownEmailOtpYaoFields(
        record,
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
      if (!Array.isArray(record.transactions) || record.transactions.length === 0) {
        throw new Error('normalSigningRequest.intent.transactions is invalid');
      }
      return {
        kind,
        operation_id: readString(record.operation_id, 'intent.operation_id'),
        operation_fingerprint: readString(
          record.operation_fingerprint,
          'intent.operation_fingerprint',
        ),
        near_account_id: readString(record.near_account_id, 'intent.near_account_id'),
        near_network_id: parseEmailOtpOperationNetworkId(
          record.near_network_id,
          'intent.near_network_id',
        ),
        transactions: record.transactions.map(parseEmailOtpOperationTransactionIntent),
        unsigned_transaction_borsh_b64u: readString(
          record.unsigned_transaction_borsh_b64u,
          'intent.unsigned_transaction_borsh_b64u',
        ),
      };
    }
    case 'nep413_v1': {
      rejectUnknownEmailOtpYaoFields(
        record,
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
      const callbackUrl = optionalWorkerString(record.callback_url);
      return {
        kind,
        operation_id: readString(record.operation_id, 'intent.operation_id'),
        operation_fingerprint: readString(
          record.operation_fingerprint,
          'intent.operation_fingerprint',
        ),
        near_account_id: readString(record.near_account_id, 'intent.near_account_id'),
        near_network_id: parseEmailOtpOperationNetworkId(
          record.near_network_id,
          'intent.near_network_id',
        ),
        recipient: readString(record.recipient, 'intent.recipient'),
        message: readString(record.message, 'intent.message'),
        nonce_b64u: readString(record.nonce_b64u, 'intent.nonce_b64u'),
        ...(callbackUrl ? { callback_url: callbackUrl } : {}),
      };
    }
    case 'near_delegate_action_v1': {
      rejectUnknownEmailOtpYaoFields(
        record,
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
      return {
        kind,
        operation_id: readString(record.operation_id, 'intent.operation_id'),
        operation_fingerprint: readString(
          record.operation_fingerprint,
          'intent.operation_fingerprint',
        ),
        near_account_id: readString(record.near_account_id, 'intent.near_account_id'),
        near_network_id: parseEmailOtpOperationNetworkId(
          record.near_network_id,
          'intent.near_network_id',
        ),
        delegate: parseEmailOtpOperationDelegateIntent(record.delegate),
      };
    }
    default:
      throw new Error(`Unsupported normalSigningRequest.intent.kind: ${kind}`);
  }
}

function parseEmailOtpOperationSigningPayload(value: unknown): RouterAbEd25519SigningPayloadV2Wire {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('normalSigningRequest.signing_payload is invalid');
  const kind = readString(record.kind, 'normalSigningRequest.signing_payload.kind');
  switch (kind) {
    case 'near_unsigned_transaction_borsh_v1':
    case 'nep413_message_v1':
    case 'near_delegate_action_v1':
      rejectUnknownEmailOtpYaoFields(
        record,
        [
          kind === 'near_unsigned_transaction_borsh_v1' ? 'kind' : 'kind',
          'canonical_message_b64u',
          'canonical_delegate_borsh_b64u',
          'unsigned_transaction_borsh_b64u',
          'expected_signing_digest_b64u',
        ],
        'normalSigningRequest.signing_payload',
      );
      if (kind === 'near_unsigned_transaction_borsh_v1') {
        return {
          kind,
          unsigned_transaction_borsh_b64u: readString(
            record.unsigned_transaction_borsh_b64u,
            'signing_payload.unsigned_transaction_borsh_b64u',
          ),
          expected_signing_digest_b64u: readString(
            record.expected_signing_digest_b64u,
            'signing_payload.expected_signing_digest_b64u',
          ),
        };
      }
      if (kind === 'nep413_message_v1') {
        return {
          kind,
          canonical_message_b64u: readString(
            record.canonical_message_b64u,
            'signing_payload.canonical_message_b64u',
          ),
          expected_signing_digest_b64u: readString(
            record.expected_signing_digest_b64u,
            'signing_payload.expected_signing_digest_b64u',
          ),
        };
      }
      return {
        kind,
        canonical_delegate_borsh_b64u: readString(
          record.canonical_delegate_borsh_b64u,
          'signing_payload.canonical_delegate_borsh_b64u',
        ),
        expected_signing_digest_b64u: readString(
          record.expected_signing_digest_b64u,
          'signing_payload.expected_signing_digest_b64u',
        ),
      };
    default:
      throw new Error(`Unsupported normalSigningRequest.signing_payload.kind: ${kind}`);
  }
}

function parseEmailOtpOperationNormalSigningRequest(
  value: unknown,
): RouterAbNormalSigningPrepareRequestV2Wire {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('normalSigningRequest is required');
  rejectUnknownEmailOtpYaoFields(
    record,
    ['scope', 'expires_at_ms', 'display_digest', 'intent', 'signing_payload'],
    'normalSigningRequest',
  );
  const scope = workerPayloadObject(record.scope);
  if (!scope) throw new Error('normalSigningRequest.scope is invalid');
  rejectUnknownEmailOtpYaoFields(
    scope,
    ['request_id', 'account_id', 'authorization', 'material_activation', 'signing_worker_id'],
    'normalSigningRequest.scope',
  );
  return {
    scope: {
      request_id: readString(scope.request_id, 'scope.request_id'),
      account_id: readString(scope.account_id, 'scope.account_id'),
      authorization: parseRouterAbNormalSigningAuthorization(scope.authorization),
      material_activation: parseRouterAbMpcMaterialActivationRef(scope.material_activation),
      signing_worker_id: readString(scope.signing_worker_id, 'scope.signing_worker_id'),
    } satisfies RouterAbNormalSigningScopeV2Wire,
    expires_at_ms: readNumber(record.expires_at_ms, 'normalSigningRequest.expires_at_ms'),
    display_digest: parseEmailOtpOperationDigest(
      record.display_digest,
      'normalSigningRequest.display_digest',
    ),
    intent: parseEmailOtpOperationIntent(record.intent),
    signing_payload: parseEmailOtpOperationSigningPayload(record.signing_payload),
  };
}

function parseEmailOtpOperationStepUpProof(
  value: unknown,
): Extract<Ed25519OperationStepUpProof, { kind: 'email_otp' }> {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('operation step-up proof is required');
  rejectUnknownEmailOtpYaoFields(
    record,
    ['kind', 'authorityRef', 'providerSubjectId', 'challengeId', 'otpCode'],
    'operation step-up proof',
  );
  const authorityRef = parseWalletAuthAuthorityRef(record.authorityRef);
  if (!authorityRef) throw new Error('operation step-up proof authorityRef is invalid');
  if (readString(record.kind, 'operation step-up proof.kind') !== 'email_otp') {
    throw new Error('operation step-up proof must use Email OTP');
  }
  return {
    kind: 'email_otp',
    authorityRef,
    providerSubjectId: readString(record.providerSubjectId, 'proof.providerSubjectId'),
    challengeId: readString(record.challengeId, 'proof.challengeId'),
    otpCode: readString(record.otpCode, 'proof.otpCode'),
  };
}

function parseEmailOtpOperationCredential(value: unknown): Ed25519OperationStepUpCredential {
  const record = workerPayloadObject(value);
  if (!record) throw new Error('operation step-up credential is required');
  rejectUnknownEmailOtpYaoFields(
    record,
    ['kind', 'walletSessionToken'],
    'operation step-up credential',
  );
  if (readString(record.kind, 'credential.kind') !== 'wallet_session_opaque') {
    throw new Error('Email OTP operation material requires an opaque Wallet Session credential');
  }
  return {
    kind: 'wallet_session_opaque',
    walletSessionToken: readString(record.walletSessionToken, 'credential.walletSessionToken'),
  };
}

function readRegistrationRoutePlan(value: unknown, label: string): EmailOtpRoutePlan {
  const routePlan = readRoutePlan(value, label);
  if (routePlan.routeFamily !== 'registration') {
    throw new Error(`${label} requires an Email OTP registration route plan`);
  }
  return routePlan;
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

function parseEmailOtpPasskeyRegistrationSummary(
  raw: unknown,
): EmailOtpWorkerOperationMap['completeEmailOtpPasskeyCustodyLink']['payload']['registration'] {
  const value = workerPayloadObject(raw);
  if (!value || value.kind !== 'webauthn_add_auth_method_registration_v1') {
    throw new Error('Email OTP passkey linking requires registration options');
  }
  const rpId = parseWebAuthnRpId(readString(value.rpId, 'registration.rpId'));
  if (!rpId.ok) throw new Error(rpId.error.message);
  return { kind: 'webauthn_add_auth_method_registration_v1', rpId: rpId.value };
}

/**
 * The request id alone, recovered from a message this worker refused to parse,
 * so a rejected request can be answered instead of leaving its caller to time
 * out with nothing to report.
 */
function workerRequestIdFromRawMessage(raw: unknown): string | null {
  const obj = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
  if (!obj) return null;
  return normalizeOptionalTrimmedString(obj.id) || null;
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
          ...(optionalWorkerString(payload.walletAuthMethodId)
            ? { walletAuthMethodId: optionalWorkerString(payload.walletAuthMethodId)! }
            : {}),
          routePlan: readRoutePlan(payload.routePlan, type),
          ...(optionalWorkerString(payload.otpChannel)
            ? { otpChannel: optionalWorkerString(payload.otpChannel)! as WalletEmailOtpChannel }
            : {}),
          ...(optionalWorkerString(payload.operationFingerprintDigest)
            ? {
                operationFingerprintDigest: parseDigestB64u(
                  optionalWorkerString(payload.operationFingerprintDigest)!,
                ),
              }
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
        payload.ecdsaSessionHandle,
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
          ecdsaSessionHandle: handleRequest,
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
    case 'prepareEmailOtpPasskeyCustodyLink': {
      const verification = workerPayloadObject(payload.verification);
      if (!verification || verification.kind !== 'otp') {
        throw new Error('Email OTP passkey linking requires OTP verification');
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          groupId: readString(payload.groupId, 'groupId'),
          routePlan: readRoutePlan(payload.routePlan, type),
          verification: {
            kind: 'otp',
            challengeId: readString(verification.challengeId, 'verification.challengeId'),
            otpCode: readString(verification.otpCode, 'verification.otpCode'),
          },
        },
      };
    }
    case 'completeEmailOtpPasskeyCustodyLink':
      return {
        id,
        type,
        payload: {
          pendingHandleId: readString(payload.pendingHandleId, 'pendingHandleId'),
          existingEnvelope: parsePasskeyCustodyEnvelopeRecord(payload.existingEnvelope),
          /* Part of the request allow-list, not an afterthought: a field the
             parser does not name is rejected, and a rejection here used to
             escape the responder and hang the caller for its full timeout. */
          walletAuthMethodId: requireWorkerWalletAuthMethodId(payload.walletAuthMethodId),
          registration: parseEmailOtpPasskeyRegistrationSummary(payload.registration),
          registrationCredential: normalizeRegistrationCredential(payload.registrationCredential),
        },
      };
    case 'discardEmailOtpPasskeyCustodyLink':
      return {
        id,
        type,
        payload: {
          pendingHandleId: readString(payload.pendingHandleId, 'pendingHandleId'),
        },
      };
    case 'rotateEmailOtpWalletRecoverySet': {
      const verification = workerPayloadObject(payload.verification);
      if (!verification || verification.kind !== 'otp') {
        throw new Error('Email OTP recovery rotation requires OTP verification');
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          userId: readString(payload.userId, 'userId'),
          groupId: readString(payload.groupId, 'groupId'),
          routePlan: readRoutePlan(payload.routePlan, type),
          verification: {
            kind: 'otp',
            challengeId: readString(verification.challengeId, 'verification.challengeId'),
            otpCode: readString(verification.otpCode, 'verification.otpCode'),
          },
          recoveryCodesJson: readString(payload.recoveryCodesJson, 'recoveryCodesJson'),
        },
      };
    }
    case 'loginWithEmailOtpWallet':
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          authoritySelector: readEmailOtpAuthoritySelector(payload.authoritySelector),
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
    case 'unlockEmailOtpAuthorityWallet': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['relayUrl', 'walletId', 'walletAuthMethodId', 'challengeId', 'otpCode', 'ed25519'],
        type,
      );
      const ed25519Payload = workerPayloadObject(payload.ed25519);
      if (!ed25519Payload) throw new Error(`${type}.ed25519 is required`);
      const branch = readString(ed25519Payload.kind, `${type}.ed25519.kind`);
      const parsedEd25519 = (() => {
        switch (branch) {
          case 'no_ed25519':
            rejectUnknownEmailOtpYaoFields(ed25519Payload, ['kind'], `${type}.ed25519`);
            return { kind: 'no_ed25519' as const };
          case 'linked_device': {
            rejectUnknownEmailOtpYaoFields(
              ed25519Payload,
              ['kind', 'signerSlot', 'remainingUses'],
              `${type}.ed25519`,
            );
            return {
              kind: 'linked_device' as const,
              signerSlot: normalizePositiveInteger(ed25519Payload.signerSlot) || 0,
              remainingUses: normalizePositiveInteger(ed25519Payload.remainingUses) || 0,
            };
          }
          case 'owner_authority': {
            rejectUnknownEmailOtpYaoFields(
              ed25519Payload,
              ['kind', 'signerSlot', 'remainingUses', 'recovery'],
              `${type}.ed25519`,
            );
            const recovery = workerPayloadObject(ed25519Payload.recovery);
            if (!recovery) throw new Error(`${type}.ed25519.recovery is required`);
            rejectUnknownEmailOtpYaoFields(
              recovery,
              [
                'ed25519YaoRecovery',
                'providerSubject',
                'nearAccountId',
                'expectedOperationalPublicKey',
                'expectedThresholdSessionId',
                'walletCustodyEd25519Material',
              ],
              `${type}.ed25519.recovery`,
            );
            return {
              kind: 'owner_authority' as const,
              signerSlot: normalizePositiveInteger(ed25519Payload.signerSlot) || 0,
              remainingUses: normalizePositiveInteger(ed25519Payload.remainingUses) || 0,
              recovery: {
                ed25519YaoRecovery: parseEmailOtpEd25519YaoRecoveryAugmentation(
                  recovery.ed25519YaoRecovery,
                ),
                providerSubject: readString(
                  recovery.providerSubject,
                  `${type}.ed25519.recovery.providerSubject`,
                ),
                nearAccountId: readString(
                  recovery.nearAccountId,
                  `${type}.ed25519.recovery.nearAccountId`,
                ),
                expectedOperationalPublicKey: readString(
                  recovery.expectedOperationalPublicKey,
                  `${type}.ed25519.recovery.expectedOperationalPublicKey`,
                ),
                expectedThresholdSessionId: readString(
                  recovery.expectedThresholdSessionId,
                  `${type}.ed25519.recovery.expectedThresholdSessionId`,
                ),
                walletCustodyEd25519Material: parseWalletCustodyEd25519MaterialRequest(
                  recovery.walletCustodyEd25519Material,
                ),
              },
            };
          }
          default:
            return null;
        }
      })();
      if (
        !parsedEd25519 ||
        (parsedEd25519.kind !== 'no_ed25519' &&
          (parsedEd25519.signerSlot <= 0 || parsedEd25519.remainingUses <= 0))
      ) {
        throw new Error(`${type}.ed25519 is invalid`);
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          walletAuthMethodId: readString(payload.walletAuthMethodId, 'walletAuthMethodId'),
          challengeId: readString(payload.challengeId, 'challengeId'),
          otpCode: readString(payload.otpCode, 'otpCode'),
          ed25519: parsedEd25519,
        },
      };
    }
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
    case 'rehydrateEmailOtpEd25519YaoOperationMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'relayUrl',
          'walletId',
          'walletAuthMethodId',
          'orgId',
          'providerSubjectId',
          'nearAccountId',
          'signerSlot',
          'expectedOperationalPublicKey',
          'expectedThresholdSessionId',
          'expectedMaterialActivation',
          'ed25519YaoRecovery',
          'walletCustodyEd25519Material',
          'normalSigningRequest',
          'displayDigest',
          'proof',
          'credential',
        ],
        type,
      );
      const activation = parseMpcMaterialActivationRef(payload.expectedMaterialActivation);
      if (!activation.ok) throw new Error(activation.error.message);
      const recovery = parseEmailOtpEd25519YaoRecoveryAugmentation(payload.ed25519YaoRecovery);
      const orgId = readString(payload.orgId, 'orgId');
      if (recovery.orgId !== orgId) {
        throw new Error('Email OTP operation material orgId does not match recovery facts');
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          orgId,
          providerSubjectId: readString(payload.providerSubjectId, 'providerSubjectId'),
          nearAccountId: readString(payload.nearAccountId, 'nearAccountId'),
          signerSlot: normalizePositiveInteger(payload.signerSlot) || 0,
          expectedOperationalPublicKey: readString(
            payload.expectedOperationalPublicKey,
            'expectedOperationalPublicKey',
          ),
          expectedThresholdSessionId: readThresholdEd25519SessionId(
            payload.expectedThresholdSessionId,
            'expectedThresholdSessionId',
          ),
          expectedMaterialActivation: activation.value,
          ed25519YaoRecovery: recovery,
          walletCustodyEd25519Material: parseWalletCustodyEd25519MaterialRequest(
            payload.walletCustodyEd25519Material,
          ),
          normalSigningRequest: parseEmailOtpOperationNormalSigningRequest(
            payload.normalSigningRequest,
          ),
          displayDigest: readString(payload.displayDigest, 'displayDigest'),
          proof: parseEmailOtpOperationStepUpProof(payload.proof),
          credential: parseEmailOtpOperationCredential(payload.credential),
        },
      };
    }
    case 'rehydrateActiveEmailOtpEd25519YaoSessionMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        [
          'relayUrl',
          'walletId',
          'walletAuthMethodId',
          'orgId',
          'providerSubjectId',
          'nearAccountId',
          'signerSlot',
          'remainingUses',
          'expectedOperationalPublicKey',
          'expectedThresholdSessionId',
          'walletSessionToken',
          'ecdsa',
          'walletCustodyEd25519Material',
        ],
        type,
      );
      const ecdsa = workerPayloadObject(payload.ecdsa);
      if (!ecdsa) {
        throw new Error('Active Email OTP restore requires exact ECDSA session input');
      }
      rejectUnknownEmailOtpYaoFields(
        ecdsa,
        ['sessionHandleBinding', 'runtimePolicyScope', 'sessionPolicy'],
        `${type}.ecdsa`,
      );
      const ecdsaBinding = parseOptionalWorkerEcdsaSessionBootstrapHandleBinding(
        ecdsa.sessionHandleBinding,
      );
      if (!ecdsaBinding || ecdsaBinding.operation !== 'wallet_unlock') {
        throw new Error('Active Email OTP restore requires wallet-unlock ECDSA binding');
      }
      const material = parseWalletCustodyEd25519MaterialRequest(
        payload.walletCustodyEd25519Material,
      );
      if (material.kind !== 'found') {
        throw new Error('Active Email OTP restore requires wallet custody Ed25519 material');
      }
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          walletId: readString(payload.walletId, 'walletId'),
          walletAuthMethodId: readString(payload.walletAuthMethodId, 'walletAuthMethodId'),
          orgId: readString(payload.orgId, 'orgId'),
          providerSubjectId: readString(payload.providerSubjectId, 'providerSubjectId'),
          nearAccountId: readString(payload.nearAccountId, 'nearAccountId'),
          signerSlot: normalizePositiveInteger(payload.signerSlot) || 0,
          remainingUses: normalizeNonNegativeInteger(payload.remainingUses) ?? 0,
          expectedOperationalPublicKey: readString(
            payload.expectedOperationalPublicKey,
            'expectedOperationalPublicKey',
          ),
          expectedThresholdSessionId: readThresholdEd25519SessionId(
            payload.expectedThresholdSessionId,
            'expectedThresholdSessionId',
          ),
          walletSessionToken: requireOpaqueWalletSessionToken(payload.walletSessionToken),
          ecdsa: {
            sessionHandleBinding: { ...ecdsaBinding, operation: 'wallet_unlock' },
            runtimePolicyScope: parseWorkerRuntimePolicyScope(
              ecdsa.runtimePolicyScope,
              'Active Email OTP restore',
            ),
            sessionPolicy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
              ecdsa.sessionPolicy,
            ),
          },
          walletCustodyEd25519Material: material,
        },
      };
    }
    case 'activateEmailOtpEd25519YaoRegistrationMaterial': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['material', 'bootstrap', 'envelope', 'factorSecret32'],
        type,
      );
      const material = parseWalletCustodyEd25519MaterialRequest({
        kind: 'found',
        material: payload.material,
      });
      if (material.kind !== 'found') {
        throw new Error('Registration activation requires wallet custody Ed25519 material');
      }
      return {
        id,
        type,
        payload: {
          material: material.material,
          bootstrap: parseEmailOtpEd25519YaoWorkerRecoveryBootstrap(payload.bootstrap),
          envelope: parseWalletCustodyCacheEnvelope(payload.envelope),
          factorSecret32: requireFixed32ArrayBuffer(payload.factorSecret32, 'factorSecret32'),
        },
      };
    }
    case 'exportEmailOtpEd25519YaoSeed': {
      rejectUnknownEmailOtpYaoFields(
        payload,
        ['relayUrl', 'challengeId', 'otpCode', 'lane', 'material'],
        type,
      );
      const lane = workerPayloadObject(payload.lane);
      const material = workerPayloadObject(payload.material);
      if (!lane || !material) {
        throw new Error(`${type} requires canonical lane and material`);
      }
      rejectUnknownEmailOtpYaoFields(
        lane,
        [
          'walletId',
          'providerSubjectId',
          'walletAuthMethodId',
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'signerSlot',
        ],
        `${type}.lane`,
      );
      rejectUnknownEmailOtpYaoFields(
        material,
        [
          'kind',
          'materialActivation',
          'capability',
          'walletCustodyEd25519Material',
          'bootstrap',
          'exportRootEnvelope',
        ],
        `${type}.material`,
      );
      return {
        id,
        type,
        payload: {
          relayUrl: readString(payload.relayUrl, 'relayUrl'),
          challengeId: readString(payload.challengeId, 'challengeId'),
          otpCode: readString(payload.otpCode, 'otpCode'),
          lane: {
            walletId: readString(lane.walletId, `${type}.lane.walletId`),
            providerSubjectId: readString(lane.providerSubjectId, `${type}.lane.providerSubjectId`),
            walletAuthMethodId: readString(
              lane.walletAuthMethodId,
              `${type}.lane.walletAuthMethodId`,
            ),
            nearAccountId: readString(lane.nearAccountId, `${type}.lane.nearAccountId`),
            nearEd25519SigningKeyId: readString(
              lane.nearEd25519SigningKeyId,
              `${type}.lane.nearEd25519SigningKeyId`,
            ),
            signerSlot: normalizePositiveInteger(lane.signerSlot) || 0,
          },
          material: parseEmailOtpEd25519YaoExportMaterial(material),
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
  /* Parsing sat outside the try below, so a rejected field threw past the
     responder and the caller waited out its whole timeout with no error
     anywhere. A request that cannot be parsed still has to answer. */
  let msg: ReturnType<typeof parseEmailOtpWorkerRequest>;
  try {
    msg = parseEmailOtpWorkerRequest(event.data);
  } catch (error) {
    const err = asWorkerErrorPayload(error);
    const requestId = workerRequestIdFromRawMessage(event.data);
    console.error('[EmailOtpWorker] rejected an unparsable request', err.message);
    if (requestId !== null) {
      postToMainThread({
        id: requestId,
        ok: false,
        error: err.message,
        ...(err.code ? { code: err.code } : {}),
        ...(err.coreCode ? { coreCode: err.coreCode } : {}),
      });
    }
    return;
  }
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
        const sessionAuth =
          routePlan.routeFamily === 'signing_session'
            ? authLaneToRouteAuth(routePlan.authLane)
            : undefined;
        const response = await postEmailOtpJson({
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          route: emailOtpRoutePath(routePlan, 'challenge'),
          ...(sessionAuth ? { sessionAuth } : {}),
          body: {
            walletId: readString(msg.payload.walletId, 'walletId'),
            ...(msg.payload.walletAuthMethodId
              ? {
                  walletAuthMethodId: readString(
                    msg.payload.walletAuthMethodId,
                    'walletAuthMethodId',
                  ),
                }
              : {}),
            otpChannel: EMAIL_OTP_CHANNEL,
            operation: routePlan.operation,
            ...(msg.payload.operationFingerprintDigest
              ? { operationFingerprintDigest: msg.payload.operationFingerprintDigest }
              : {}),
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
        const result: {
          challengeId: string;
          otpChannel: typeof EMAIL_OTP_CHANNEL;
          delivery: EmailOtpChallengeDelivery;
          emailHint?: string;
          expiresAtMs?: number;
          ownerProofBindingDigest: string;
        } = {
          challengeId: readString(challenge?.challengeId, 'challengeId'),
          otpChannel: EMAIL_OTP_CHANNEL,
          delivery,
          emailHint: delivery.emailHint,
          ownerProofBindingDigest: readString(
            challenge?.ownerProofBindingDigest,
            'ownerProofBindingDigest',
          ),
        };
        if (Number.isFinite(expiresAtMs)) {
          result.expiresAtMs = expiresAtMs;
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
        const sessionAuth =
          routePlan.routeFamily === 'signing_session'
            ? authLaneToRouteAuth(routePlan.authLane)
            : undefined;
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
        const result: {
          challengeId: string;
          otpChannel: typeof EMAIL_OTP_CHANNEL;
          delivery: EmailOtpChallengeDelivery;
          emailHint?: string;
          expiresAtMs?: number;
        } = {
          challengeId: readString(challenge?.challengeId, 'challengeId'),
          otpChannel: EMAIL_OTP_CHANNEL,
          delivery,
          emailHint: delivery.emailHint,
        };
        if (Number.isFinite(expiresAtMs)) {
          result.expiresAtMs = expiresAtMs;
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
            challengeId: result.challengeId,
            otpChannel: result.otpChannel,
            enrollmentId: result.enrollmentId,
            enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
            serverSealedFactorCiphertextB64u: result.serverSealedFactorCiphertextB64u,
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
          returnClientSecret32: false,
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
          readString(msg.payload.walletId, 'walletId');
          const emailOtpSessionHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleResult =
            emailOtpWalletRegistrationEcdsaHandleResult(msg.payload.ecdsaSessionHandle);
          postToMainThread({
            id: msg.id,
            ok: true,
            result: {
              otpChannel: result.otpChannel,
              enrollmentId: result.enrollmentId,
              enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
              serverSealedFactorCiphertextB64u: result.serverSealedFactorCiphertextB64u,
              clientUnlockPublicKeyB64u: result.clientUnlockPublicKeyB64u,
              unlockKeyVersion: result.unlockKeyVersion,
              emailOtpSessionHandle,
              emailOtpEnrollment: result.emailOtpEnrollment,
            },
          });
        } finally {
          zeroizeBytes(result.clientSecret32);
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
      case 'prepareEmailOtpPasskeyCustodyLink': {
        const result = await prepareEmailOtpPasskeyCustodyLink(msg.payload);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'completeEmailOtpPasskeyCustodyLink': {
        const result = completeEmailOtpPasskeyCustodyLink(msg.payload);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'discardEmailOtpPasskeyCustodyLink': {
        const discarded = discardEmailOtpPasskeyCustodyLink(msg.payload.pendingHandleId);
        postToMainThread({ id: msg.id, ok: true, result: { discarded } });
        return;
      }
      case 'rotateEmailOtpWalletRecoverySet': {
        const result = await rotateEmailOtpWalletRecoverySet(msg.payload);
        postToMainThread({ id: msg.id, ok: true, result });
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
          authoritySelector: readEmailOtpAuthoritySelector(msg.payload.authoritySelector),
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
              throw new Error('Email OTP wallet unlock material branch changed');
            }
            postToMainThread({
              id: msg.id,
              ok: true,
              result: {
                kind: 'ecdsa',
                operation: material.ecdsaSessionHandleBinding.operation,
                recovery,
                emailOtpSessionHandle: issueEmailOtpEcdsaSessionHandle({
                  walletId,
                  binding: material.ecdsaSessionHandleBinding,
                }),
                ...(result.ecdsaSession ? { ecdsaSession: result.ecdsaSession } : {}),
                ...(result.ecdsaCustody ? { ecdsaCustody: result.ecdsaCustody } : {}),
              },
            });
            return;
          case 'wallet_unlock_capabilities': {
            if (material.kind !== 'wallet_unlock_capabilities') {
              result.clientSecret32.fill(0);
              if (result.ed25519Yao.kind === 'capability') {
                removeEmailOtpEd25519YaoActiveClient(result.ed25519Yao.activeClientHandle);
              }
              throw new Error('Email OTP capability wallet unlock material branch changed');
            }
            const emailOtpSessionHandle = issueEmailOtpEcdsaSessionHandle({
              walletId,
              binding: material.ecdsa.sessionHandleBinding,
            });
            try {
              const ecdsa = {
                emailOtpSessionHandle,
                session: result.ecdsa.session,
                custody: result.ecdsa.custody,
              };
              postToMainThread(
                {
                  id: msg.id,
                  ok: true,
                  result: {
                    kind: 'wallet_unlock_capabilities',
                    operation: 'wallet_unlock',
                    recovery,
                    ed25519ExportRootCustody: {
                      existingEnvelope: result.walletCustodyEnvelope,
                      factorSecret32: result.clientSecret32,
                    },
                    ecdsa,
                    ed25519Yao: result.ed25519Yao,
                  },
                },
                [result.clientSecret32.buffer],
              );
            } catch (error) {
              if (result.clientSecret32.byteLength > 0) result.clientSecret32.fill(0);
              if (result.ed25519Yao.kind === 'capability') {
                removeEmailOtpEd25519YaoActiveClient(result.ed25519Yao.activeClientHandle);
                deleteEmailOtpEd25519YaoWarmFactor(
                  result.ed25519Yao.bootstrap.capability.materialActivation,
                );
              }
              throw error;
            }
            return;
          }
          case 'wallet_custody_cache_absent': {
            if (material.kind !== 'ed25519_yao_recovery') {
              throw new Error('Email OTP wallet unlock material branch changed');
            }
            postToMainThread({
              id: msg.id,
              ok: true,
              result: {
                kind: 'wallet_custody_cache_absent',
                recovery,
                ed25519YaoRecovery: result.ed25519YaoRecovery,
              },
            });
            return;
          }
          case 'ed25519_yao_capability':
            if (material.kind !== 'ed25519_yao_recovery') {
              removeEmailOtpEd25519YaoActiveClient(result.activeClientHandle);
              throw new Error('Email OTP wallet unlock material branch changed');
            }
            try {
              postToMainThread(
                {
                  id: msg.id,
                  ok: true,
                  result: {
                    kind: 'ed25519_yao_capability',
                    recovery,
                    activeClientHandle: result.activeClientHandle,
                    metadata: result.metadata,
                    ed25519YaoCapability: result.ed25519YaoCapability,
                    ...(result.walletCustodyEd25519Material
                      ? { walletCustodyEd25519Material: result.walletCustodyEd25519Material }
                      : {}),
                    ed25519ExportRootCustody: {
                      existingEnvelope: result.walletCustodyEnvelope,
                      factorSecret32: result.clientSecret32,
                    },
                  },
                },
                [result.clientSecret32.buffer],
              );
            } catch (error) {
              if (result.clientSecret32.byteLength > 0) result.clientSecret32.fill(0);
              removeEmailOtpEd25519YaoActiveClient(result.activeClientHandle);
              deleteEmailOtpEd25519YaoWarmFactor(
                result.ed25519YaoCapability.capability.materialActivation,
              );
              throw error;
            }
            return;
          case 'ed25519_yao_export':
            throw new Error('Email OTP wallet unlock returned export-only material');
          default:
            return assertNeverEmailOtpWorker(result);
        }
      }
      case 'unlockEmailOtpAuthorityWallet': {
        const result = await unlockEmailOtpAuthorityWallet(msg.payload);
        try {
          postToMainThread({ id: msg.id, ok: true, result }, [result.factorSecret32.buffer]);
        } catch (error: unknown) {
          result.factorSecret32.fill(0);
          throw error;
        }
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
      case 'rehydrateEmailOtpEd25519YaoOperationMaterial': {
        const result = await rehydrateEmailOtpEd25519YaoOperationMaterial(msg.payload);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'rehydrateActiveEmailOtpEd25519YaoSessionMaterial': {
        const result = await rehydrateActiveEmailOtpEd25519YaoSessionMaterial(msg.payload);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'activateEmailOtpEd25519YaoRegistrationMaterial': {
        const material = msg.payload.material;
        const bootstrap = msg.payload.bootstrap;
        const capability = bootstrap.capability;
        if (
          material.binding.walletId !== capability.applicationBinding.wallet_id ||
          material.binding.nearAccountId !== capability.nearAccountId ||
          material.binding.nearEd25519SigningKeyId !==
            capability.applicationBinding.near_ed25519_signing_key_id ||
          material.binding.signerSlot !== capability.applicationBinding.key_creation_signer_slot ||
          material.binding.signingWorkerId !== capability.lifecycle.signingWorkerId ||
          material.binding.registeredPublicKeyB64u !==
            base64UrlEncode(Uint8Array.from(capability.registeredPublicKey))
        ) {
          throw new Error('Registration custody material changed the exact Ed25519 lane');
        }
        const factorSecret32 = new Uint8Array(msg.payload.factorSecret32);
        let activeClientHandle: string | null = null;
        try {
          const activeClient = await openWalletCustodyEd25519ActiveClientV1({
            material,
            activation: walletCustodyActivationFactsFromEmailOtpBootstrap(bootstrap),
            envelope: msg.payload.envelope,
            ownedFactorSecret: factorSecret32.slice(),
          });
          let transferred = false;
          try {
            const stored = storeEmailOtpEd25519YaoActiveClient(activeClient);
            transferred = true;
            activeClientHandle = stored.activeClientHandle;
            bindEmailOtpEd25519YaoCapabilityWarmFactor({
              bootstrap,
              factorSecret32,
              materialActivation: capability.materialActivation,
            });
            postToMainThread({ id: msg.id, ok: true, result: stored });
            activeClientHandle = null;
          } finally {
            if (!transferred) activeClient.dispose();
          }
        } finally {
          if (activeClientHandle) removeEmailOtpEd25519YaoActiveClient(activeClientHandle);
          zeroizeBytes(factorSecret32);
        }
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
      case 'exportEmailOtpEd25519YaoSeed': {
        const capability = emailOtpEd25519YaoExportCapabilityV1(msg.payload.material);
        const exportOrgId = capability.runtimePolicyScope.orgId;
        const resolutionState: EmailOtpEd25519ExportCustodyResolutionState = {
          relayUrl: readString(msg.payload.relayUrl, 'relayUrl'),
          walletId: readString(msg.payload.lane.walletId, 'lane.walletId'),
          orgId: exportOrgId,
          providerSubjectId: readString(
            msg.payload.lane.providerSubjectId,
            'lane.providerSubjectId',
          ),
          material: msg.payload.material,
          activeClientHandle: null,
          warmFactorBound: false,
          rehydrated: null,
        };
        try {
          const artifact = await exportEmailOtpEd25519YaoSeed({
            relayUrl: resolutionState.relayUrl,
            walletId: resolutionState.walletId,
            providerSubjectId: resolutionState.providerSubjectId,
            walletAuthMethodId: msg.payload.lane.walletAuthMethodId,
            challengeId: msg.payload.challengeId,
            otpCode: msg.payload.otpCode,
            nearAccountId: msg.payload.lane.nearAccountId,
            nearEd25519SigningKeyId: msg.payload.lane.nearEd25519SigningKeyId,
            signerSlot: msg.payload.lane.signerSlot,
            runtimePolicyScope: capability.runtimePolicyScope,
            capability,
            resolveCustodyEnvelope: resolveEmailOtpEd25519ExportCustodyEnvelope.bind(
              undefined,
              resolutionState,
            ),
          });
          postToMainThread({
            id: msg.id,
            ok: true,
            result:
              msg.payload.material.kind === 'sealed_custody'
                ? {
                    kind: 'exported_and_rehydrated',
                    ...artifact,
                    activeClientHandle: resolutionState.rehydrated!.activeClientHandle,
                    metadata: resolutionState.rehydrated!.metadata,
                    bootstrap: msg.payload.material.bootstrap,
                  }
                : { kind: 'exported', ...artifact },
          });
          resolutionState.activeClientHandle = null;
          resolutionState.warmFactorBound = false;
        } finally {
          if (resolutionState.activeClientHandle) {
            removeEmailOtpEd25519YaoActiveClient(resolutionState.activeClientHandle);
            if (resolutionState.warmFactorBound) {
              deleteEmailOtpEd25519YaoWarmFactor(msg.payload.material.materialActivation);
            }
          }
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
