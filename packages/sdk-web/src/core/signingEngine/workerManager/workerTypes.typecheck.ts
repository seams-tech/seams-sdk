import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  EmailOtpEd25519YaoActiveCapabilityDescriptorV1,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWorkerIssuedSessionHandlePayload,
  EmailOtpWorkerOperationRequestEnvelope,
  EmailOtpWorkerOperationMap,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  EvmCryptoLocalSecp256k1OperationRequest,
  EvmCryptoTransactionOperationRequest,
  EcdsaDerivationRoleLocalMaterialOperationRequest,
  EcdsaPresignClientSessionInitRequest,
  NearWorkerOperationRequest,
  EcdsaPresignClientSessionStepRequest,
} from './workerTypes';
import type {
  CapabilityInstanceRef,
  MpcMaterialActivationRef,
  RootShareEpoch,
} from '@shared/utils/domainIds';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaPresignClientRequestType,
} from './workerTypes';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../session/keyMaterialBrands';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '@/core/rpcClients/relayer/walletRegistration';
import type {
  InitialEcdsaCapabilityActivationPlan,
  InitialEcdsaCapabilityActivationPlanInput,
} from '../session/material/initialEcdsaCapabilityActivation';
import type {
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  PersistInitialCanonicalEcdsaActivationRequestV1,
  ReconcileCanonicalEcdsaActivationRequestV1,
  ReconcileCanonicalEcdsaActivationResultV1,
} from '../routerAb/ecdsaDerivation/clientCeremony';
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletCustodyEvmFamilyPublicFacts } from '@shared/passkey-custody';
import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';

declare const rootShareEpoch: RootShareEpoch;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;
declare const materialActivation: MpcMaterialActivationRef;
declare const emailOtpEd25519YaoActiveCapability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
declare const incomingMessage: ArrayBuffer;
declare const emailOtpEd25519YaoSession: WalletRegistrationEd25519YaoBootstrapSession;
declare const initialEcdsaActivationPlanInput: InitialEcdsaCapabilityActivationPlanInput;
declare const initialEcdsaActivationPlan: InitialEcdsaCapabilityActivationPlan;
declare const activationJournalId: CorrelationId;
declare const activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
declare const clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
declare const normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
declare const walletCustodyPublicFacts: WalletCustodyEvmFamilyPublicFacts;
declare const activationCapability: CapabilityInstanceRef;
declare const activationAuthority: WalletAuthAuthorityRef;
declare const activationCommand: Extract<
  ReconcileCanonicalEcdsaActivationResultV1,
  { kind: 'canonical_ecdsa_activation_reconciliation_pending_v1' }
>['activationCommand'];
declare const finalizedRoleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
declare const finalizedMaterialActivation: FinalizeRouterAbEcdsaRegistrationActivationResultV1['materialActivation'];
declare const finalizedAuthority: FinalizeRouterAbEcdsaRegistrationActivationResultV1['authority'];
declare const finalizedPublicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
declare const finalizedPublicCapability: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicCapability'];
declare const roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
declare const ecdsaSessionPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;

const persistInitialCanonicalEcdsaActivationRequest: EcdsaDerivationRoleLocalMaterialOperationRequest<
  typeof EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation
> = {
  type: EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation,
  payload: {
    kind: 'persist_initial_canonical_ecdsa_activation_v1',
    bootstrapOwner: 'wallet_custody',
    ceremonyId: 'registration-ceremony',
    planInput: initialEcdsaActivationPlanInput,
    clientActivation,
  },
};
void persistInitialCanonicalEcdsaActivationRequest;

const persistInitialActivationWithPendingSecret = {
  kind: 'persist_initial_canonical_ecdsa_activation_v1',
  bootstrapOwner: 'wallet_custody',
  ceremonyId: 'registration-ceremony',
  planInput: initialEcdsaActivationPlanInput,
  clientActivation,
  // @ts-expect-error Pending registration secrets stay in live worker ceremony state.
  pendingStateBlob: 'caller-owned-pending-secret',
} satisfies PersistInitialCanonicalEcdsaActivationRequestV1;
void persistInitialActivationWithPendingSecret;

const persistInitialActivationWithConstructedPlan = {
  kind: 'persist_initial_canonical_ecdsa_activation_v1',
  bootstrapOwner: 'wallet_custody',
  ceremonyId: 'registration-ceremony',
  // @ts-expect-error The worker builds fresh proof objects from the narrow planner input.
  planInput: initialEcdsaActivationPlan,
  clientActivation,
} satisfies PersistInitialCanonicalEcdsaActivationRequestV1;
void persistInitialActivationWithConstructedPlan;

const finalizePersistedCanonicalEcdsaActivation = {
  kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
  bootstrapOwner: 'wallet_custody',
  journalId: activationJournalId,
  activationReceipt,
  routerAbEcdsaDerivationNormalSigning: normalSigning,
  readyStateBlobB64u: 'ready-state',
  walletCustodyPublicFacts,
} satisfies FinalizeRouterAbEcdsaRegistrationActivationRequestV1;
void finalizePersistedCanonicalEcdsaActivation;

const finalizedCanonicalEcdsaActivation = {
  kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
  journalId: activationJournalId,
  authority: finalizedAuthority,
  roleLocalMaterial: finalizedRoleLocalMaterial,
  materialActivation: finalizedMaterialActivation,
  publicFacts: finalizedPublicFacts,
  publicCapability: finalizedPublicCapability,
} satisfies FinalizeRouterAbEcdsaRegistrationActivationResultV1;
void finalizedCanonicalEcdsaActivation;

// @ts-expect-error Finalization must expose the exact canonical material activation.
const finalizedCanonicalEcdsaActivationWithoutIdentity: FinalizeRouterAbEcdsaRegistrationActivationResultV1 =
  {
    kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
    journalId: activationJournalId,
    authority: finalizedAuthority,
    roleLocalMaterial: finalizedRoleLocalMaterial,
    publicFacts: finalizedPublicFacts,
    publicCapability: finalizedPublicCapability,
  };
void finalizedCanonicalEcdsaActivationWithoutIdentity;

// @ts-expect-error Finalization must expose the authority bound by the committed manifest.
const finalizedCanonicalEcdsaActivationWithoutAuthority: FinalizeRouterAbEcdsaRegistrationActivationResultV1 =
  {
    kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
    journalId: activationJournalId,
    roleLocalMaterial: finalizedRoleLocalMaterial,
    materialActivation: finalizedMaterialActivation,
    publicFacts: finalizedPublicFacts,
    publicCapability: finalizedPublicCapability,
  };
void finalizedCanonicalEcdsaActivationWithoutAuthority;

const finalizeCanonicalEcdsaActivationWithCallerRelayer = {
  kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
  bootstrapOwner: 'wallet_custody',
  journalId: activationJournalId,
  activationReceipt,
  routerAbEcdsaDerivationNormalSigning: normalSigning,
  readyStateBlobB64u: 'ready-state',
  walletCustodyPublicFacts,
  // @ts-expect-error Finalization derives relayer identity from the committed journal.
  relayerKeyId: 'caller-selected-relayer',
} satisfies FinalizeRouterAbEcdsaRegistrationActivationRequestV1;
void finalizeCanonicalEcdsaActivationWithCallerRelayer;

const finalizeCanonicalEcdsaActivationWithCeremonyAlias = {
  kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
  bootstrapOwner: 'wallet_custody',
  journalId: activationJournalId,
  activationReceipt,
  routerAbEcdsaDerivationNormalSigning: normalSigning,
  readyStateBlobB64u: 'ready-state',
  walletCustodyPublicFacts,
  // @ts-expect-error Canonical finalization accepts only the persisted journal identity.
  ceremonyId: 'legacy-ceremony-alias',
} satisfies FinalizeRouterAbEcdsaRegistrationActivationRequestV1;
void finalizeCanonicalEcdsaActivationWithCeremonyAlias;

const reconcileCanonicalEcdsaActivation = {
  kind: 'reconcile_canonical_ecdsa_activation_v1',
  capability: activationCapability,
  authority: activationAuthority,
} satisfies ReconcileCanonicalEcdsaActivationRequestV1;
void reconcileCanonicalEcdsaActivation;

const reconcileCanonicalEcdsaActivationByJournalId = {
  kind: 'reconcile_canonical_ecdsa_activation_v1',
  // @ts-expect-error Reload reconciliation discovers the exact journal from capability authority.
  journalId: activationJournalId,
} satisfies ReconcileCanonicalEcdsaActivationRequestV1;
void reconcileCanonicalEcdsaActivationByJournalId;

const pendingCanonicalEcdsaActivation = {
  kind: 'canonical_ecdsa_activation_reconciliation_pending_v1',
  journalId: activationJournalId,
  reason: 'parent_confirmation_and_server_query_required',
  activationCommand,
} satisfies ReconcileCanonicalEcdsaActivationResultV1;
void pendingCanonicalEcdsaActivation;

const finalizedReconciledCanonicalEcdsaActivation = {
  kind: 'canonical_ecdsa_activation_reconciliation_finalized_v1',
  activation: finalizedCanonicalEcdsaActivation,
} satisfies ReconcileCanonicalEcdsaActivationResultV1;
void finalizedReconciledCanonicalEcdsaActivation;

const retiredEcdsaRegistrationHandle: EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-registration-root-session',
  walletId: 'wallet.testnet',
  authSubjectId: 'google:subject',
  action: 'threshold_ecdsa_bootstrap',
  // @ts-expect-error Generic ECDSA registration handles are retired; registration uses prepare handles.
  operation: 'registration',
  chainTarget,
};
void retiredEcdsaRegistrationHandle;

const walletRegistrationEcdsaPrepareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-registration-root-session',
  walletId: 'wallet.testnet',
  evmFamilySigningKeySlotId: 'wallet-key-localhost',
  authSubjectId: 'google:subject',
  action: 'wallet_registration_ecdsa_prepare',
  operation: 'registration',
  keyScope: 'evm-family',
  chainTarget,
};
void walletRegistrationEcdsaPrepareHandle;

// @ts-expect-error Registration-prep worker handles cannot be used for session bootstrap.
const bootstrapHandleFromRegistrationPrepare: EmailOtpEcdsaSessionBootstrapHandlePayload =
  walletRegistrationEcdsaPrepareHandle;
void bootstrapHandleFromRegistrationPrepare;

const issuedHandle: EmailOtpWorkerIssuedSessionHandlePayload = walletRegistrationEcdsaPrepareHandle;
void issuedHandle;

type PresignStepPayload = EcdsaPresignClientSessionStepRequest;
type EmailOtpEd25519YaoExportPayload =
  EmailOtpWorkerOperationMap['exportEmailOtpEd25519YaoSeed']['payload'];
type EmailOtpWalletUnlockPayload = EmailOtpWorkerOperationMap['loginWithEmailOtpWallet']['payload'];
type EmailOtpEcdsaWalletUnlockMaterial = Extract<
  EmailOtpWalletUnlockPayload['material'],
  { kind: 'ecdsa' }
>;
type EmailOtpCapabilityWalletUnlockMaterial = Extract<
  EmailOtpWalletUnlockPayload['material'],
  { kind: 'wallet_unlock_capabilities' }
>;

const emailOtpEcdsaExplicitUnlockMaterial: EmailOtpEcdsaWalletUnlockMaterial = {
  kind: 'ecdsa',
  ecdsaSessionHandleBinding: {
    keyHandle: 'ecdsa-key-handle',
    authSubjectId: 'provider-subject',
    operation: 'wallet_unlock',
    chainTarget,
  },
  runtimePolicyScope,
  ecdsaSessionPolicy,
  walletSessionAuthorization: { kind: 'verified_wallet_unlock' },
};
void emailOtpEcdsaExplicitUnlockMaterial;

const emailOtpSigningStepUpWithActivation: EmailOtpEcdsaWalletUnlockMaterial = {
  kind: 'ecdsa',
  ecdsaSessionHandleBinding: {
    keyHandle: 'ecdsa-key-handle',
    authSubjectId: 'provider-subject',
    operation: 'sign',
    chainTarget,
  },
  runtimePolicyScope,
};
void emailOtpSigningStepUpWithActivation;

// @ts-expect-error explicit unlock must carry its exact first-session activation.
const emailOtpUnlockWithoutActivation: EmailOtpEcdsaWalletUnlockMaterial = {
  kind: 'ecdsa',
  ecdsaSessionHandleBinding: {
    keyHandle: 'ecdsa-key-handle',
    authSubjectId: 'provider-subject',
    operation: 'wallet_unlock',
    chainTarget,
  },
  runtimePolicyScope,
};
void emailOtpUnlockWithoutActivation;
type EmailOtpEd25519YaoWalletUnlockMaterial = Extract<
  EmailOtpWalletUnlockPayload['material'],
  { kind: 'ed25519_yao_recovery' }
>;

const emailOtpEcdsaWarmMaterialTarget: EmailOtpWorkerOperationMap['getEmailOtpWarmSessionStatus']['payload'] =
  {
    target: { kind: 'ecdsa', thresholdSessionId: 'ecdsa-session' },
  };
void emailOtpEcdsaWarmMaterialTarget;

const emailOtpEd25519YaoWarmMaterialTarget: EmailOtpWorkerOperationMap['getEmailOtpWarmSessionStatus']['payload'] =
  {
    target: { kind: 'ed25519_yao', thresholdSessionId: 'ed-session', materialActivation },
  };
void emailOtpEd25519YaoWarmMaterialTarget;

const emailOtpEd25519YaoWarmMaterialTargetMissingActivation: EmailOtpWorkerOperationMap['getEmailOtpWarmSessionStatus']['payload'] =
  {
    // @ts-expect-error Ed25519 warm material always requires exact activation identity.
    target: { kind: 'ed25519_yao', thresholdSessionId: 'ed-session' },
  };
void emailOtpEd25519YaoWarmMaterialTargetMissingActivation;

const emailOtpEcdsaWarmMaterialTargetWithActivation: EmailOtpWorkerOperationMap['getEmailOtpWarmSessionStatus']['payload'] =
  {
    // @ts-expect-error ECDSA warm material remains session-addressed.
    target: { kind: 'ecdsa', thresholdSessionId: 'ecdsa-session', materialActivation },
  };
void emailOtpEcdsaWarmMaterialTargetWithActivation;

const emailOtpEd25519YaoWalletUnlockMaterial: EmailOtpEd25519YaoWalletUnlockMaterial = {
  kind: 'ed25519_yao_recovery',
  providerSubject: 'google:subject',
  nearAccountId: 'wallet.testnet',
  expectedOperationalPublicKey: 'ed25519:11111111111111111111111111111111',
  expectedThresholdSessionId: 'threshold-session',
  walletCustodyEd25519Material: { kind: 'absent' },
  ed25519YaoRecovery: {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
    signerSlot: 1,
    remainingUses: 3,
    orgId: 'org-test',
  },
};
void emailOtpEd25519YaoWalletUnlockMaterial;

const emailOtpCapabilityWalletUnlockMaterial: EmailOtpCapabilityWalletUnlockMaterial = {
  kind: 'wallet_unlock_capabilities',
  ecdsa: {
    sessionHandleBinding: emailOtpEcdsaExplicitUnlockMaterial.ecdsaSessionHandleBinding,
    runtimePolicyScope,
    sessionPolicy: ecdsaSessionPolicy,
  },
  ed25519Yao: {
    recovery: emailOtpEd25519YaoWalletUnlockMaterial.ed25519YaoRecovery,
    providerSubject: emailOtpEd25519YaoWalletUnlockMaterial.providerSubject,
    nearAccountId: emailOtpEd25519YaoWalletUnlockMaterial.nearAccountId,
    expectedOperationalPublicKey:
      emailOtpEd25519YaoWalletUnlockMaterial.expectedOperationalPublicKey,
    expectedThresholdSessionId: emailOtpEd25519YaoWalletUnlockMaterial.expectedThresholdSessionId,
    walletCustodyEd25519Material:
      emailOtpEd25519YaoWalletUnlockMaterial.walletCustodyEd25519Material,
  },
};
void emailOtpCapabilityWalletUnlockMaterial;

// @ts-expect-error Cross-curve combined material discriminants are retired.
const retiredCombinedWalletUnlockKind: EmailOtpWalletUnlockPayload['material']['kind'] =
  'ecdsa_and_ed25519_yao_recovery';
void retiredCombinedWalletUnlockKind;

const emailOtpEd25519YaoWalletUnlockWithoutThresholdIdentity = {
  kind: 'ed25519_yao_recovery',
  providerSubject: 'google:subject',
  nearAccountId: 'wallet.testnet',
  expectedOperationalPublicKey: 'ed25519:11111111111111111111111111111111',
  ed25519YaoRecovery: {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
    signerSlot: 1,
    remainingUses: 3,
    orgId: 'org-test',
  },
  walletCustodyEd25519Material: { kind: 'absent' },
  // @ts-expect-error Recovery requires its registered threshold lifecycle identity.
} satisfies EmailOtpEd25519YaoWalletUnlockMaterial;
void emailOtpEd25519YaoWalletUnlockWithoutThresholdIdentity;

const emailOtpEd25519YaoWalletUnlockWithPriorSession = {
  ...emailOtpEd25519YaoWalletUnlockMaterial,
  // @ts-expect-error Fresh OTP recovery rejects a prior Wallet Session credential.
  walletSessionAuth: { kind: 'wallet_session', jwt: 'prior.jwt' },
} satisfies EmailOtpEd25519YaoWalletUnlockMaterial;
void emailOtpEd25519YaoWalletUnlockWithPriorSession;

const emailOtpEd25519YaoWalletUnlockWithClientPolicy = {
  ...emailOtpEd25519YaoWalletUnlockMaterial,
  // @ts-expect-error Fresh OTP recovery rejects a client-authored session policy.
  sessionPolicy: { version: 'threshold_session_v1' },
} satisfies EmailOtpEd25519YaoWalletUnlockMaterial;
void emailOtpEd25519YaoWalletUnlockWithClientPolicy;

const presignStep: PresignStepPayload = {
  sessionId: 'presign-session',
  stage: 'triples',
  incomingMessages: [incomingMessage],
};
void presignStep;

const ethRecoverableSignatureVerifyRequest: EvmCryptoLocalSecp256k1OperationRequest<'verifySecp256k1RecoverableSignatureAgainstPublicKey33'> =
  {
    type: 'verifySecp256k1RecoverableSignatureAgainstPublicKey33',
    payload: {
      digest32: incomingMessage,
      signature65: incomingMessage,
      publicKey33: incomingMessage,
    },
  };
void ethRecoverableSignatureVerifyRequest;

type InvalidRecoverableSignatureVerifyAsEthTransaction =
  // @ts-expect-error Recoverable signature verification is not an ETH transaction encoding operation.
  EvmCryptoTransactionOperationRequest<'verifySecp256k1RecoverableSignatureAgainstPublicKey33'>;
declare const invalidRecoverableSignatureVerifyAsEthTransaction: InvalidRecoverableSignatureVerifyAsEthTransaction;
void invalidRecoverableSignatureVerifyAsEthTransaction;

const ecdsaPresignInitRequest: EcdsaPresignClientSessionInitRequest = {
  authority: {
    kind: 'role_local_derivation_handle',
    materialHandle: 'ecdsa-material-handle',
    material: {
      kind: 'persisted',
      materialRef: roleLocalMaterialRef,
    },
  },
  sessionId: 'presign-session',
  groupPublicKey33: incomingMessage,
  materialExpiresAtMs: 1_000,
  poolIdentity: {
    poolKey: 'pool-key',
    materialActivationId: 'activation-1',
    capability: 'evm-ecdsa-capability-1',
    keyBinding: 'ecdsa-threshold-key-1',
    walletId: 'wallet-id',
    signingScopeB64u: 'scope',
    pairRole: 'client',
    keyEpoch: 'key-epoch',
    activationEpoch: rootShareEpoch,
    protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1',
  },
};
void ecdsaPresignInitRequest;

const linkedHolderEcdsaPresignInitRequest: EcdsaPresignClientSessionInitRequest = {
  ...ecdsaPresignInitRequest,
  authority: {
    kind: 'linked_holder_signing_material',
    holderHandleId: 'linked-holder-handle',
  },
};
void linkedHolderEcdsaPresignInitRequest;

const invalidLinkedHolderPresignAuthorityWithRoleLocalMaterial: EcdsaPresignClientSessionInitRequest =
  {
    ...ecdsaPresignInitRequest,
    // @ts-expect-error Linked holder authority cannot carry owner role-local material.
    authority: {
      kind: 'linked_holder_signing_material',
      holderHandleId: 'linked-holder-handle',
      materialHandle: 'ecdsa-material-handle',
    },
  };
void invalidLinkedHolderPresignAuthorityWithRoleLocalMaterial;

// @ts-expect-error presign persistence requires an explicit material expiry.
const ecdsaPresignInitWithoutMaterialExpiry: EcdsaPresignClientSessionInitRequest = {
  authority: {
    kind: 'role_local_derivation_handle',
    materialHandle: 'ecdsa-material-handle',
    material: {
      kind: 'persisted',
      materialRef: roleLocalMaterialRef,
    },
  },
  sessionId: 'presign-session',
  groupPublicKey33: incomingMessage,
};
void ecdsaPresignInitWithoutMaterialExpiry;

type InvalidEcdsaDerivationPresignAsMaterial = EcdsaDerivationRoleLocalMaterialOperationRequest<
  // @ts-expect-error Presign operations cannot use the derivation material domain.
  typeof EcdsaPresignClientRequestType.SessionStep
>;
declare const invalidEcdsaDerivationPresignAsMaterial: InvalidEcdsaDerivationPresignAsMaterial;
void invalidEcdsaDerivationPresignAsMaterial;

// @ts-expect-error presign session step requires incomingMessages; pass [] when empty.
const presignStepWithoutIncomingMessages: PresignStepPayload = {
  sessionId: 'presign-session',
  stage: 'triples',
};
void presignStepWithoutIncomingMessages;

declare const emailOtpWalletUnlockRoutePlan: EmailOtpWalletUnlockPayload['routePlan'];
declare const emailOtpEcdsaWalletUnlockMaterial: EmailOtpEcdsaWalletUnlockMaterial;

const emailOtpWalletUnlockPayload: EmailOtpWalletUnlockPayload = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  userId: 'wallet.testnet',
  verification: {
    kind: 'otp',
    challengeId: 'challenge-1',
    otpCode: '123456',
  },
  groupId: 'prime',
  routePlan: emailOtpWalletUnlockRoutePlan,
  material: emailOtpEcdsaWalletUnlockMaterial,
};
void emailOtpWalletUnlockPayload;

const emailOtpWalletUnlockPayloadWithoutRuntimeScope = {
  relayUrl: 'https://relay.example',
  walletId: 'wallet.testnet',
  otpCode: '123456',
  groupId: 'prime',
  routePlan: emailOtpWalletUnlockRoutePlan,
};
// @ts-expect-error Email OTP wallet unlock must carry one exact material branch.
emailOtpWalletUnlockPayloadWithoutRuntimeScope satisfies EmailOtpWalletUnlockPayload;

const emailOtpEd25519YaoExportPayload: EmailOtpEd25519YaoExportPayload = {
  relayUrl: 'https://relay.example',
  challengeId: 'challenge-ed25519-export',
  otpCode: '123456',
  groupId: 'prime',
  lane: {
    walletId: 'wallet.testnet',
    providerSubjectId: 'google:subject',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'near-key-1',
    signerSlot: 1,
  },
  material: {
    kind: 'active_capability',
    materialActivation,
    capability: emailOtpEd25519YaoActiveCapability,
  },
};
void emailOtpEd25519YaoExportPayload;

const emailOtpEd25519YaoExportPayloadWithPasskey = {
  ...emailOtpEd25519YaoExportPayload,
  // @ts-expect-error Email OTP Ed25519 export rejects passkey credentials.
  webauthnAuthentication: {},
} satisfies EmailOtpEd25519YaoExportPayload;
void emailOtpEd25519YaoExportPayloadWithPasskey;

/**
 * The wallet custody ceremony worker's operation map.
 *
 * These pin the properties the boundary exists for: a run carries no custody
 * material out, its steps are addressed by ceremony id rather than by a handle
 * a caller could hold, and a run says where its seed comes from — establishing
 * custody or joining it — rather than leaving that to be inferred.
 */
const walletCustodyCeremonyEstablish: SignerWorkerOperationRequest<
  'walletCustodyCeremony',
  'beginWalletCustodyKeySetRun'
> = {
  type: 'beginWalletCustodyKeySetRun',
  payload: {
    ceremonyId: 'ceremony-1',
    keySet: 'evm_family_ecdsa_v1',
    custody: {
      origin: 'establish',
      walletId: 'alice.testnet',
      factorJson: '{}',
      factorSecret: new ArrayBuffer(32),
      recoveryCodesJson: '[]',
    },
    protocolInputsJson: '{}',
    evmFamilySigningKeySlotId: 'evm-slot-1',
  },
};
void walletCustodyCeremonyEstablish;

// A later key set reaches the same seed by opening the existing envelope.
const walletCustodyCeremonyJoinRun: SignerWorkerOperationRequest<
  'walletCustodyCeremony',
  'beginWalletCustodyKeySetRun'
> = {
  type: 'beginWalletCustodyKeySetRun',
  payload: {
    ceremonyId: 'ceremony-1',
    keySet: 'near_ed25519_v1',
    custody: { origin: 'join', custodyJson: '{}', factorSecret: new ArrayBuffer(32) },
    protocolInputsJson: '{}',
  },
};
void walletCustodyCeremonyJoinRun;

const walletCustodyCeremonyBeginWithSeed: SignerWorkerOperationRequest<
  'walletCustodyCeremony',
  'beginWalletCustodyKeySetRun'
> = {
  type: 'beginWalletCustodyKeySetRun',
  payload: {
    ceremonyId: 'ceremony-1',
    keySet: 'evm_family_ecdsa_v1',
    custody: {
      origin: 'establish',
      walletId: 'alice.testnet',
      factorJson: '{}',
      factorSecret: new ArrayBuffer(32),
      recoveryCodesJson: '[]',
    },
    protocolInputsJson: '{}',
    evmFamilySigningKeySlotId: 'evm-slot-1',
    // @ts-expect-error a caller cannot supply the wallet custody seed.
    walletCustodySeed: new ArrayBuffer(32),
  },
};
void walletCustodyCeremonyBeginWithSeed;

const walletCustodyCeremonyJoinWithoutFactor: SignerWorkerOperationRequest<
  'walletCustodyCeremony',
  'beginWalletCustodyKeySetRun'
> = {
  type: 'beginWalletCustodyKeySetRun',
  payload: {
    ceremonyId: 'ceremony-1',
    keySet: 'near_ed25519_v1',
    // @ts-expect-error joining custody means opening its envelope, which needs
    // the factor secret. There is no other way in.
    custody: { origin: 'join', custodyJson: '{}' },
    protocolInputsJson: '{}',
  },
};
void walletCustodyCeremonyJoinWithoutFactor;

const walletCustodyCeremonyEstablished: SignerWorkerOperationResult<
  'walletCustodyCeremony',
  'finishWalletCustodyKeySetRun'
> = {
  walletId: 'alice.testnet',
  keySet: 'evm_family_ecdsa_v1',
  keyManifestDigestB64u: 'digest',
  establishedCustody: {
    envelopeId: 'envelope-1',
    envelopeBindingJson: '{}',
    envelopeNonceB64u: 'nonce',
    sealedCustodySecretB64u: 'ciphertext',
    envelopeAadHashB64u: 'aad',
    envelopeCiphertextDigestB64u: 'digest',
    recoveryManifestKekWraps: [],
    recoveryEntryNonceB64u: 'nonce',
    recoveryEntryCiphertextB64u: 'ciphertext',
    recoveryEntryAadHashB64u: 'aad',
  },
  clientRootPublicKey33B64u: 'key',
  ecdsaReadyStateBlobB64u: 'blob',
};
void walletCustodyCeremonyEstablished;

// A run that joined existing custody writes no envelope and issues no codes.
const walletCustodyCeremonyJoined: SignerWorkerOperationResult<
  'walletCustodyCeremony',
  'finishWalletCustodyKeySetRun'
> = {
  walletId: 'alice.testnet',
  keySet: 'near_ed25519_v1',
  keyManifestDigestB64u: 'digest',
  registeredPublicKeyB64u: 'registered',
};
void walletCustodyCeremonyJoined;

// The finish result carries ciphertext and public facts only. Nothing that
// could open an envelope may appear on it.
// @ts-expect-error the ceremony never returns the custody seed.
void walletCustodyCeremonyEstablished.walletCustodySeedB64u;
// @ts-expect-error the ceremony never returns the recovery manifest KEK.
void walletCustodyCeremonyEstablished.manifestKekB64u;

export {};
